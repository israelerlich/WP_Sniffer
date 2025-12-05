import requests
from bs4 import BeautifulSoup
import re
import argparse
import json
from colorama import init, Fore

init(autoreset=True)

class WPScanner:
    def __init__(self, url, api_token=None):
        self.url = url.rstrip('/')
        self.api_token = api_token
        self.plugins = {}
        self.vulnerabilities = self.carregar_vulnerabilidades()
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        }

    def carregar_vulnerabilidades(self):
        try:
            with open('vulnerabilities.json', 'r') as arquivo:
                return json.load(arquivo)
        except:
            return {}

    def detectar_wordpress(self, soup):
        # Procura pela tag meta generator
        generator = soup.find('meta', attrs={'name': 'generator'})
        if generator and 'WordPress' in generator.get('content', ''):
            return True
        
        # Procura por links do wp-content
        if soup.find(href=re.compile(r'wp-content')) or soup.find(src=re.compile(r'wp-content')):
            return True
        
        return False

    def buscar_plugins(self, soup):
        print(f"{Fore.CYAN}[*] Procurando plugins...")
        encontrados = set()
        
        # Busca todas as tags que podem ter plugins
        tags = soup.find_all(['script', 'link', 'img', 'a'])
        
        for tag in tags:
            url = tag.get('src') or tag.get('href')
            if url:
                # Procura padrão wp-content/plugins/nome-do-plugin/
                match = re.search(r'wp-content/plugins/([^/]+)/', url)
                if match:
                    plugin_nome = match.group(1)
                    if plugin_nome not in encontrados:
                        encontrados.add(plugin_nome)
                        
                        # Tenta pegar a versão
                        versao_match = re.search(r'ver=([\d\.]+)', url)
                        versao = versao_match.group(1) if versao_match else 'Desconhecida'
                        
                        self.plugins[plugin_nome] = versao
                        print(f"{Fore.GREEN}[+] Encontrado: {plugin_nome} (v{versao})")

    def verificar_vulnerabilidades(self):
        print(f"\n{Fore.CYAN}[*] Verificando vulnerabilidades...")
        
        if not self.plugins:
            print(f"{Fore.YELLOW}[-] Nenhum plugin encontrado.")
            return
        
        encontrou_vuln = False
        
        for plugin, versao in self.plugins.items():
            # Tenta API primeiro se tiver token
            if self.api_token:
                if self.verificar_api(plugin, versao):
                    encontrou_vuln = True
                    continue
            
            # Usa banco local
            if self.verificar_local(plugin, versao):
                encontrou_vuln = True
        
        if not encontrou_vuln:
            print(f"{Fore.GREEN}[+] Nenhuma vulnerabilidade encontrada.")

    def verificar_api(self, plugin, versao):
        print(f"{Fore.BLUE}[*] Consultando API para {plugin}...")
        try:
            url = f"https://wpscan.com/api/v3/plugins/{plugin}"
            headers = {'Authorization': f'Token token={self.api_token}'}
            resposta = requests.get(url, headers=headers, timeout=10)
            
            if resposta.status_code == 429:
                print(f"{Fore.RED}[!] Limite de requisições atingido.")
                return False
            
            if resposta.status_code != 200:
                return False
            
            dados = resposta.json()
            vulns = dados.get(plugin, {}).get('vulnerabilities', [])
            
            for vuln in vulns:
                print(f"{Fore.RED}[!] VULNERABILIDADE (API): {plugin} {versao}")
                print(f"    {Fore.RED}Título: {vuln.get('title')}")
                print(f"    {Fore.RED}Corrigido em: {vuln.get('fixed_in', 'Não corrigido')}")
            
            return len(vulns) > 0
        except:
            return False

    def verificar_local(self, plugin, versao):
        if plugin not in self.vulnerabilities:
            return False
        
        info = self.vulnerabilities[plugin]
        versoes_vuln = info.get('versions', [])
        
        if versao == 'Desconhecida' or versao in versoes_vuln:
            cor = Fore.YELLOW if versao == 'Desconhecida' else Fore.RED
            status = "Possível" if versao == 'Desconhecida' else "ENCONTRADA"
            print(f"{cor}[!] {status} vulnerabilidade em {plugin}: {info['description']}")
            print(f"    {cor}Severidade: {info['severity']}")
            return True
        
        return False

    def executar(self):
        print(f"{Fore.BLUE}[*] Iniciando scan: {self.url}")
        
        try:
            resposta = requests.get(self.url, headers=self.headers, timeout=10)
            resposta.raise_for_status()
        except Exception as e:
            print(f"{Fore.RED}[!] Erro de conexão: {e}")
            return
        
        soup = BeautifulSoup(resposta.text, 'html.parser')
        
        if self.detectar_wordpress(soup):
            print(f"{Fore.GREEN}[+] WordPress detectado!")
        else:
            print(f"{Fore.YELLOW}[!] WordPress não detectado. Continuando...")
        
        self.buscar_plugins(soup)
        self.verificar_vulnerabilidades()

def main():
    parser = argparse.ArgumentParser(description="Scanner de Vulnerabilidades WordPress")
    parser.add_argument("url", help="URL do site alvo")
    parser.add_argument("--api-token", help="Token da API WPScan", default=None)
    args = parser.parse_args()
    
    scanner = WPScanner(args.url, args.api_token)
    scanner.executar()

if __name__ == "__main__":
    main()
