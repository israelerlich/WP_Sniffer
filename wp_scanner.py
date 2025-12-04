import requests
from bs4 import BeautifulSoup
import re
import argparse
import json
from colorama import init, Fore

init(autoreset=True)

class WPScanner:
    def __init__(self, url: str, api_token: str = None, local_db: str = 'vulnerabilities.json'):
        self.url = url.rstrip('/')
        self.api_token = api_token
        self.local_db_file = local_db
        self.plugins = {}
        self.local_vulnerabilities = self.load_local_vulnerabilities()
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': 'en-US,en;q=0.9',
            'Upgrade-Insecure-Requests': '1'
        }

    def load_local_vulnerabilities(self) -> dict:
        try:
            with open(self.local_db_file, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def detect_wordpress(self, soup: BeautifulSoup) -> bool:
        generator = soup.find('meta', attrs={'name': 'generator'})
        if generator and 'WordPress' in generator.get('content', ''):
            return True
        
        if soup.find(href=re.compile(r'wp-content')):
            return True
            
        if soup.find(src=re.compile(r'wp-content')):
            return True
            
        return False

    def scan_plugins(self, soup: BeautifulSoup):
        print(f"{Fore.CYAN}[*] Scanning for plugins...")
        
        plugin_pattern = re.compile(r'wp-content/plugins/([^/]+)/')
        tags = soup.find_all(['script', 'link', 'img'], src=True) + soup.find_all(['link', 'a'], href=True)
        
        found_plugins = set()
        
        for tag in tags:
            url = tag.get('src') or tag.get('href')
            if not url:
                continue
                
            match = plugin_pattern.search(url)
            if match:
                plugin_name = match.group(1)
                if plugin_name not in found_plugins:
                    found_plugins.add(plugin_name)
                    version = 'Unknown'
                    version_match = re.search(r'ver=([\d\.]+)', url)
                    if version_match:
                        version = version_match.group(1)
                    
                    self.plugins[plugin_name] = version
                    print(f"{Fore.GREEN}[+] Found plugin: {plugin_name} (Version: {version})")

    def check_vulnerabilities(self):
        print(f"\n{Fore.CYAN}[*] Checking for known vulnerabilities...")
        
        if not self.plugins:
            print(f"{Fore.YELLOW}[-] No plugins found to check.")
            return

        use_api = True
        if not self.api_token:
            print(f"{Fore.YELLOW}[!] No API Token provided. Switching to local database.")
            use_api = False

        found_vuln = False
        
        for plugin, version in self.plugins.items():
            if use_api:
                if self._check_api(plugin, version):
                    found_vuln = True
                else:
                    # If API check failed (e.g. rate limit), try local
                    if self._check_local(plugin, version):
                         found_vuln = True
            else:
                if self._check_local(plugin, version):
                    found_vuln = True

        if not found_vuln:
            print(f"{Fore.GREEN}[+] No known vulnerabilities found in detected plugins.")

    def _check_api(self, plugin: str, version: str) -> bool:
        print(f"{Fore.BLUE}[*] Checking {plugin} via API...")
        api_url = f"https://wpscan.com/api/v3/plugins/{plugin}"
        headers = {'Authorization': f'Token token={self.api_token}'}
        
        try:
            response = requests.get(api_url, headers=headers, timeout=10)
            
            if response.status_code == 429:
                print(f"{Fore.RED}[!] API Rate Limit Exceeded. Switching to local DB for this plugin.")
                return False # Signal to try local
            
            if response.status_code != 200:
                return False

            data = response.json()
            vulnerabilities = data.get(plugin, {}).get('vulnerabilities', [])

            if not vulnerabilities:
                return False

            found = False
            for vuln in vulnerabilities:
                fixed_in = vuln.get('fixed_in')
                is_vulnerable = False
                
                if version == 'Unknown':
                    is_vulnerable = True
                elif fixed_in:
                    if version < fixed_in: 
                        is_vulnerable = True
                else:
                    is_vulnerable = True

                if is_vulnerable:
                    print(f"{Fore.RED}[!] VULNERABILITY FOUND (API): {plugin} {version}")
                    print(f"    {Fore.RED}Title: {vuln.get('title')}")
                    print(f"    {Fore.RED}Fixed in: {fixed_in or 'Not fixed'}")
                    found = True
            return found

        except requests.exceptions.RequestException:
            return False

    def _check_local(self, plugin: str, version: str) -> bool:
        if plugin not in self.local_vulnerabilities:
            return False
            
        vuln_info = self.local_vulnerabilities[plugin]
        found = False
        
        if version == 'Unknown':
             print(f"{Fore.YELLOW}[!] Potential vulnerability in {plugin}: {vuln_info['description']}")
             print(f"    {Fore.YELLOW}Severity: {vuln_info['severity']}")
             found = True
        elif version in vuln_info['versions']:
            print(f"{Fore.RED}[!] VULNERABILITY FOUND (Local DB): {plugin} {version}")
            print(f"    {Fore.RED}Description: {vuln_info['description']}")
            print(f"    {Fore.RED}Severity: {vuln_info['severity']}")
            found = True
            
        return found

    def run(self):
        print(f"{Fore.BLUE}[*] Starting scan for {self.url}")
        try:
            response = requests.get(self.url, headers=self.headers, timeout=10)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}[!] Error connecting to {self.url}: {e}")
            return

        soup = BeautifulSoup(response.text, 'html.parser')
        
        if self.detect_wordpress(soup):
            print(f"{Fore.GREEN}[+] WordPress detected!")
        else:
            print(f"{Fore.YELLOW}[!] WordPress not detected. Continuing scan anyway...")

        self.scan_plugins(soup)
        self.check_vulnerabilities()

def main():
    parser = argparse.ArgumentParser(description="WordPress Plugin Vulnerability Scanner")
    parser.add_argument("url", help="Target URL")
    parser.add_argument("--api-token", help="WPScan API Token", default=None)
    args = parser.parse_args()

    scanner = WPScanner(args.url, args.api_token)
    scanner.run()

if __name__ == "__main__":
    main()
