# 🔍 WP_Sniffer

![Python](https://img.shields.io/badge/Python-3.6%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Security](https://img.shields.io/badge/Security-Tool-red?style=for-the-badge)
![License](https://img.shields.io/badge/License-Educational-green?style=for-the-badge)

**WP_Sniffer** é um scanner leve para enumeração de plugins WordPress e detecção de vulnerabilidades. Ele opera cruzando versões instaladas contra a API do **WPScan** ou uma base de dados local (`json`).

## ✨ O que ele faz
* ✅ **Reconhecimento:** Identifica instalação WordPress e lista plugins ativos.
* ✅ **Verificação Dupla:** Checa falhas via API (online) ou arquivo local (offline).
* ✅ **Relatórios:** Classifica riscos por severidade (Low até Critical).

## 🚀 Instalação Rápida

```bash
# 1. Clone o repositório
git clone [https://github.com/seu-usuario/WP_Sniffer.git](https://github.com/seu-usuario/WP_Sniffer.git)
cd WP_Sniffer

# 2. Instale as dependências
pip install -r requirements.txt
```

💻 Como Usar
1. Scan Básico (Base Local)
Utiliza apenas o arquivo vulnerabilities.json para checar falhas.
```bash
python wp_scanner.py [https://alvo.com](https://alvo.com)
```

. Scan Completo (API WPScan)
Utilizando uma base de dados oficial como wpscan.com (Recomendo pagar pelo token)
```bash
python wp_scanner.py [https://alvo.com](https://alvo.com) --api-token TOKEN_AQUI
```

⚙️ Customização da Base Local
Você pode adicionar vulnerabilidades manualmente no arquivo vulnerabilities.json:
```bash
{
    "contact-form-7": {
        "versions": ["5.3.1", "5.3.0"],
        "description": "Upload de arquivos sem restrição",
        "severity": "High"
    }
}
```

⚠️ Aviso Legal (Disclaimer)
ESTRITAMENTE EDUCACIONAL. O uso desta ferramenta em sites sem consentimento prévio e explícito é ilegal. O autor não se responsabiliza por danos ou uso indevido. Utilize apenas em ambientes de teste (CTF, Labs) ou infraestrutura própria.
