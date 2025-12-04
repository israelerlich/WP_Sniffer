import requests
from bs4 import BeautifulSoup
import re
import argparse
import json
from colorama import init, Fore
from typing import Dict, Set, Tuple

init(autoreset=True)

class WPScanner:
    HEADERS = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
    }
    
    def __init__(self, url: str, api_token: str = None, local_db: str = 'vulnerabilities.json'):
        self.url = url.rstrip('/')
        self.api_token = api_token
        self.plugins: Dict[str, str] = {}
        self.local_vulnerabilities = self._load_json(local_db)

    @staticmethod
    def _load_json(filepath: str) -> dict:
        try:
            with open(filepath, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def detect_wordpress(self, soup: BeautifulSoup) -> bool:
        generator = soup.find('meta', attrs={'name': 'generator'})
        return (generator and 'WordPress' in generator.get('content', '')) or \
               bool(soup.find(href=re.compile(r'wp-content')) or soup.find(src=re.compile(r'wp-content')))

    def scan_plugins(self, soup: BeautifulSoup):
        print(f"{Fore.CYAN}[*] Scanning for plugins...")
        plugin_pattern = re.compile(r'wp-content/plugins/([^/]+)/')
        tags = soup.find_all(['script', 'link', 'img', 'a'], src=True) + soup.find_all(['link', 'a'], href=True)
        
        found: Set[str] = set()
        for tag in tags:
            url = tag.get('src') or tag.get('href')
            if url and (match := plugin_pattern.search(url)) and match.group(1) not in found:
                plugin_name = match.group(1)
                found.add(plugin_name)
                version = re.search(r'ver=([\d\.]+)', url)
                self.plugins[plugin_name] = version.group(1) if version else 'Unknown'
                print(f"{Fore.GREEN}[+] Found: {plugin_name} (v{self.plugins[plugin_name]})")

    def check_vulnerabilities(self):
        print(f"\n{Fore.CYAN}[*] Checking vulnerabilities...")
        if not self.plugins:
            return print(f"{Fore.YELLOW}[-] No plugins found.")

        use_api = bool(self.api_token)
        if not use_api:
            print(f"{Fore.YELLOW}[!] No API token. Using local database.")

        found_vuln = any(
            self._check_api(p, v) or self._check_local(p, v) if use_api else self._check_local(p, v)
            for p, v in self.plugins.items()
        )
        
        if not found_vuln:
            print(f"{Fore.GREEN}[+] No vulnerabilities found.")

    def _check_api(self, plugin: str, version: str) -> bool:
        print(f"{Fore.BLUE}[*] Checking {plugin} via API...")
        try:
            response = requests.get(
                f"https://wpscan.com/api/v3/plugins/{plugin}",
                headers={'Authorization': f'Token token={self.api_token}'},
                timeout=10
            )
            
            if response.status_code == 429:
                print(f"{Fore.RED}[!] API rate limit. Trying local DB...")
                return False
            
            if response.status_code != 200:
                return False

            vulnerabilities = response.json().get(plugin, {}).get('vulnerabilities', [])
            return self._print_vulnerabilities(plugin, version, vulnerabilities, "API")
        except requests.exceptions.RequestException:
            return False

    def _check_local(self, plugin: str, version: str) -> bool:
        if plugin not in self.local_vulnerabilities:
            return False
        
        vuln_info = self.local_vulnerabilities[plugin]
        if version == 'Unknown' or version in vuln_info.get('versions', []):
            color = Fore.YELLOW if version == 'Unknown' else Fore.RED
            status = "Potential" if version == 'Unknown' else "FOUND"
            print(f"{color}[!] {status} vulnerability in {plugin}: {vuln_info['description']}")
            print(f"    {color}Severity: {vuln_info['severity']}")
            return True
        return False

    def _print_vulnerabilities(self, plugin: str, version: str, vulns: list, source: str) -> bool:
        found = False
        for vuln in vulns:
            fixed_in = vuln.get('fixed_in')
            is_vulnerable = version == 'Unknown' or not fixed_in or version < fixed_in
            
            if is_vulnerable:
                print(f"{Fore.RED}[!] VULNERABILITY ({source}): {plugin} {version}")
                print(f"    {Fore.RED}Title: {vuln.get('title')}")
                print(f"    {Fore.RED}Fixed in: {fixed_in or 'Not fixed'}")
                found = True
        return found

    def run(self):
        print(f"{Fore.BLUE}[*] Starting scan: {self.url}")
        try:
            response = requests.get(self.url, headers=self.HEADERS, timeout=10)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            return print(f"{Fore.RED}[!] Connection error: {e}")

        soup = BeautifulSoup(response.text, 'html.parser')
        print(f"{Fore.GREEN}[+] WordPress detected!" if self.detect_wordpress(soup) 
              else f"{Fore.YELLOW}[!] WordPress not detected. Continuing...")
        
        self.scan_plugins(soup)
        self.check_vulnerabilities()

def main():
    parser = argparse.ArgumentParser(description="WordPress Plugin Vulnerability Scanner")
    parser.add_argument("url", help="Target URL")
    parser.add_argument("--api-token", help="WPScan API Token", default=None)
    args = parser.parse_args()
    WPScanner(args.url, args.api_token).run()

if __name__ == "__main__":
    main()
