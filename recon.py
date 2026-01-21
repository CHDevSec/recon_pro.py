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
import webbrowser
import platform

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
MODE = "strict"
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
    # Cores ANSI
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    
    print(f"{BLUE}")
    print(r"""
 ██▀███  ▓█████  ▄████▄   ▒█████   ███▄    █     ██▓███   ██▀███   ▒█████  
▓██ ▒ ██▒▓█   ▀ ▒██▀ ▀█  ▒██▒  ██▒ ██ ▀█   █    ▓██░  ██▒▓██ ▒ ██▒▒██▒  ██▒
▓██ ░▄█ ▒▒███   ▒▓█    ▄ ▒██░  ██▒▓██  ▀█ ██▒   ▓██░ ██▓▒▓██ ░▄█ ▒▒██░  ██▒
▒██▀▀█▄  ▒▓█  ▄ ▒▓▓▄ ▄██▒▒██   ██░▓██▒  ▐▌██▒   ▒██▄█▓▒ ▒▒██▀▀█▄  ▒██   ██░
░██▓ ▒██▒░▒████▒▒ ▓███▀ ░░ ████▓▒░▒██░   ▓██░   ▒██▒ ░  ░░██▓ ▒██▒░ ████▓▒░
░ ▒▓ ░▒▓░░░ ▒░ ░░ ░▒ ▒  ░░ ▒░▒░▒░ ░ ▒░   ▒ ▒    ▒▓▒░ ░  ░░ ▒▓ ░▒▓░░ ▒░▒░▒░ 
  ░▒ ░ ▒░ ░ ░  ░  ░  ▒     ░ ▒ ▒░ ░ ░░   ░ ▒░   ░▒ ░       ░▒ ░ ▒░  ░ ▒ ▒░ 
  ░░   ░    ░   ░        ░ ░ ░ ▒     ░   ░ ░    ░░         ░░   ░ ░ ░ ░ ▒  
   ░        ░  ░░ ░          ░ ░           ░                ░         ░ ░  
                ░                                                          
    """)
    print(f"{CYAN}   🔍 RECON WEB PROFISSIONAL - SUBDOMÍNIOS + FUZZING + VULN CHECKS{RESET}")
    print(f"{YELLOW}   💀 By Pentester Caio | CHDEVSEC | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}")
    print(f"{BLUE}" + "=" * 74 + f"{RESET}")


def open_report(report_path):
    """Abre o relatório HTML no navegador padrão"""
    try:
        # Converte para caminho absoluto
        abs_path = os.path.abspath(report_path)
        
        # Abre no navegador
        if platform.system() == "Windows":
            os.startfile(abs_path)
        elif platform.system() == "Darwin":  # macOS
            subprocess.run(["open", abs_path], check=True)
        else:  # Linux
            subprocess.run(["xdg-open", abs_path], check=True)
        
        return True
    except Exception as e:
        print(f"  ⚠️ Não foi possível abrir automaticamente: {e}")
        return False


def print_final_summary(domain, tech_type, subdomains, classification, report_path):
    """Imprime resumo final estilizado com opção de abrir dashboard"""
    
    # Cores ANSI
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'
    
    # Caminho absoluto para o relatório
    abs_report_path = os.path.abspath(report_path)
    
    # Contagem dos resultados
    total_subs = len(subdomains)
    web_active = len(classification['web_active'])
    dns_only = len(classification['dns_only'])
    timeouts = len(classification['timeout'])
    filtered = len(classification['filtered'])
    
    # Linha decorativa
    border_top = f"{BLUE}╔{'═' * 72}╗{RESET}"
    border_mid = f"{BLUE}╠{'═' * 72}╣{RESET}"
    border_bot = f"{BLUE}╚{'═' * 72}╝{RESET}"
    line_empty = f"{BLUE}║{RESET}"
    
    def center_text(text, width=72, color=""):
        """Centraliza texto dentro da borda"""
        clean_text = text
        # Remove códigos ANSI para calcular tamanho real
        import re
        text_len = len(re.sub(r'\033\[[0-9;]*m', '', clean_text))
        padding = (width - text_len) // 2
        return f"{BLUE}║{RESET}{' ' * padding}{text}{' ' * (width - text_len - padding)}{BLUE}║{RESET}"
    
    def left_text(text, width=72, indent=4):
        """Alinha texto à esquerda dentro da borda"""
        import re
        text_len = len(re.sub(r'\033\[[0-9;]*m', '', text))
        padding = width - text_len - indent
        return f"{BLUE}║{RESET}{' ' * indent}{text}{' ' * max(0, padding)}{BLUE}║{RESET}"
    
    # ASCII Art de conclusão (menor, no mesmo estilo)
    print(f"\n{BLUE}")
    print(r"""
     ██████╗ ██████╗ ███╗   ███╗██████╗ ██╗     ███████╗████████╗███████╗
    ██╔════╝██╔═══██╗████╗ ████║██╔══██╗██║     ██╔════╝╚══██╔══╝██╔════╝
    ██║     ██║   ██║██╔████╔██║██████╔╝██║     █████╗     ██║   █████╗  
    ██║     ██║   ██║██║╚██╔╝██║██╔═══╝ ██║     ██╔══╝     ██║   ██╔══╝  
    ╚██████╗╚██████╔╝██║ ╚═╝ ██║██║     ███████╗███████╗   ██║   ███████╗
     ╚═════╝ ╚═════╝ ╚═╝     ╚═╝╚═╝     ╚══════╝╚══════╝   ╚═╝   ╚══════╝
    """)
    print(f"{RESET}")
    
    # Box do resumo
    print(border_top)
    print(center_text(f"{BOLD}{CYAN}🎯 RECON PROFISSIONAL FINALIZADO [V2.0]{RESET}"))
    print(center_text(f"{DIM}{WHITE}─────────────────────────────────{RESET}"))
    print(f"{BLUE}║{' ' * 72}║{RESET}")
    
    # Info do domínio
    print(left_text(f"{YELLOW}◆ ALVO:{RESET}       {WHITE}{BOLD}{domain}{RESET}"))
    print(left_text(f"{YELLOW}◆ TECNOLOGIA:{RESET} {WHITE}{tech_type.upper()}{RESET}"))
    print(left_text(f"{YELLOW}◆ DATA:{RESET}       {WHITE}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}"))
    print(f"{BLUE}║{' ' * 72}║{RESET}")
    
    # Separador
    print(border_mid)
    print(center_text(f"{BOLD}{MAGENTA}📊 RESULTADOS DO RECON{RESET}"))
    print(f"{BLUE}║{' ' * 72}║{RESET}")
    
    # Estatísticas com cores
    print(left_text(f"{GREEN}✔{RESET}  Subdomínios Descobertos (DNS)  {DIM}......................{RESET} {BOLD}{WHITE}{total_subs}{RESET}"))
    print(left_text(f"{GREEN}✔{RESET}  Web Ativos (HTTP/HTTPS)        {DIM}......................{RESET} {BOLD}{GREEN}{web_active}{RESET}"))
    print(left_text(f"{YELLOW}⚠{RESET}  DNS Ativos sem HTTP            {DIM}......................{RESET} {BOLD}{YELLOW}{dns_only}{RESET}"))
    print(left_text(f"{RED}⏳{RESET} Timeouts                        {DIM}......................{RESET} {BOLD}{DIM}{timeouts}{RESET}"))
    print(left_text(f"{RED}🚫{RESET} Filtrados/Bloqueados            {DIM}......................{RESET} {BOLD}{DIM}{filtered}{RESET}"))
    print(f"{BLUE}║{' ' * 72}║{RESET}")
    
    # Separador
    print(border_mid)
    print(center_text(f"{BOLD}{GREEN}📁 DASHBOARD / RELATÓRIO{RESET}"))
    print(f"{BLUE}║{' ' * 72}║{RESET}")
    
    # Caminho do relatório (destacado)
    print(left_text(f"{DIM}Arquivo:{RESET}"))
    print(left_text(f"{CYAN}{BOLD}{abs_report_path}{RESET}"))
    print(f"{BLUE}║{' ' * 72}║{RESET}")
    
    # Link clicável (para terminais que suportam)
    file_url = f"file:///{abs_report_path.replace(os.sep, '/')}"
    print(left_text(f"{DIM}URL:{RESET} {CYAN}\033]8;;{file_url}\033\\{file_url}\033]8;;\033\\{RESET}"))
    print(f"{BLUE}║{' ' * 72}║{RESET}")
    
    # Borda inferior
    print(border_bot)
    
    # Créditos
    print(f"\n{BLUE}{'─' * 74}{RESET}")
    print(f"{DIM}    💀 Desenvolvido por {RESET}{BOLD}{CYAN}Pentester Caio{RESET} {DIM}|{RESET} {BOLD}{MAGENTA}CHDEVSEC{RESET}")
    print(f"{DIM}    🔗 github.com/chdevsec{RESET}")
    print(f"{BLUE}{'─' * 74}{RESET}")
    
    # Prompt para abrir o dashboard
    print(f"\n{YELLOW}{'─' * 74}{RESET}")
    print(f"{BOLD}{WHITE}    📂 ABRIR DASHBOARD?{RESET}")
    print(f"{DIM}    Visualize os resultados no navegador para uma análise completa.{RESET}")
    print(f"{YELLOW}{'─' * 74}{RESET}")
    
    try:
        choice = input(f"\n    {CYAN}[ENTER]{RESET} Abrir agora  |  {DIM}[n]{RESET} Não abrir  |  {DIM}[c]{RESET} Copiar caminho\n\n    > ").strip().lower()
        
        if choice == 'n':
            print(f"\n    {DIM}Dashboard não aberto. Acesse manualmente:{RESET}")
            print(f"    {CYAN}{abs_report_path}{RESET}\n")
        elif choice == 'c':
            # Tenta copiar para clipboard
            try:
                if platform.system() == "Windows":
                    subprocess.run(["clip"], input=abs_report_path.encode(), check=True)
                elif platform.system() == "Darwin":
                    subprocess.run(["pbcopy"], input=abs_report_path.encode(), check=True)
                else:
                    subprocess.run(["xclip", "-selection", "clipboard"], input=abs_report_path.encode(), check=True)
                print(f"\n    {GREEN}✔{RESET} Caminho copiado para a área de transferência!\n")
            except:
                print(f"\n    {YELLOW}⚠{RESET} Não foi possível copiar. Caminho:")
                print(f"    {CYAN}{abs_report_path}{RESET}\n")
        else:
            # Abrir o dashboard
            print(f"\n    {CYAN}⏳ Abrindo dashboard no navegador...{RESET}")
            if open_report(report_path):
                print(f"    {GREEN}✔{RESET} Dashboard aberto com sucesso!\n")
            else:
                print(f"\n    {YELLOW}⚠{RESET} Abra manualmente:")
                print(f"    {CYAN}{abs_report_path}{RESET}\n")
                
    except KeyboardInterrupt:
        print(f"\n\n    {DIM}Operação cancelada.{RESET}\n")

def get_random_agent():
    """Retorna um User-Agent aleatório"""
    return random.choice(USER_AGENTS)

def resolve_tool_path(tool_name):
    """
    Tenta encontrar o executável de forma resiliente e "Coringa":
    1. PATH do sistema
    2. Diretórios comuns (Hardcoded ampliado)
    3. Busca via 'locate' (Database do sistema)
    4. Busca com 'find' na HOME e ROOT (Modo agressivo)
    """
    # 1. Verifica no PATH padrão
    path = shutil.which(tool_name)
    if path:
        return path
    
    # 2. Verifica em diretórios comuns (Lista Expandida)
    home = os.path.expanduser("~")
    # Tenta adivinhar subdiretórios comuns de usuários em sistemas Linux
    user_dirs = [home]
    if os.path.exists("/home/kali"): user_dirs.append("/home/kali")
    if os.path.exists("/root"): user_dirs.append("/root")
    
    common_paths = [
        os.path.join(home, "go", "bin", tool_name),
        os.path.join(home, ".local", "bin", tool_name),
        os.path.join(home, "bin", tool_name),
        os.path.join("/usr/local/bin", tool_name),
        os.path.join("/usr/local/go/bin", tool_name),
        os.path.join("/usr/bin", tool_name),
        os.path.join("/bin", tool_name),
        os.path.join("/usr/sbin", tool_name),
        os.path.join("/sbin", tool_name),
        os.path.join("/opt", tool_name),
        os.path.join("/opt", tool_name, tool_name), # ex: /opt/tool/tool
    ]
    
    # Adiciona caminhos do Go para outros usuários comuns
    for u_dir in user_dirs:
        common_paths.append(os.path.join(u_dir, "go", "bin", tool_name))
        common_paths.append(os.path.join(u_dir, ".local", "bin", tool_name))

    for p in common_paths:
        if os.path.isfile(p) and os.access(p, os.X_OK):
            # print(f"  [DEBUG] Ferramenta encontrada em lista comum: {p}")
            return p
            
    # 3. Busca rápida via 'locate' (se instalado)
    try:
        cmd = ["locate", "-b", f"\\{tool_name}"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
        paths = result.stdout.strip().splitlines()
        for p in paths:
            # Filtra apenas o que é binário exato e executável
            if os.path.basename(p) == tool_name and os.access(p, os.X_OK):
                return p
    except:
        pass

    # 4. Busca recursiva (Modo Coringa / Agressivo)
    print(f"  🔍 Modo Coringa: Buscando binário '{tool_name}' em todo o sistema (aguarde)...")
    
    # Define diretórios base para busca, evitando loops e locais irrelevantes
    search_roots = [home, "/opt", "/usr", "/var/www"]
    
    # Comando find otimizado: busca type file, executable, maxdepth razoável
    # Exclui /proc, /sys, /dev, /run, /tmp, /mnt para evitar erros e lentidão
    for root_dir in search_roots:
        if not os.path.exists(root_dir): continue
        try:
            cmd = ["find", root_dir, "-name", tool_name, "-type", "f", "-executable", "-print", "-quit"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            found_path = result.stdout.strip()
            if found_path:
                return found_path
        except:
            continue
            
    # Última tentativa: Busca na raiz '/' excluindo diretórios virtuais (Lento)
    try:
        # find / -path /proc -prune -o -path /sys -prune -o -path /dev -prune -o -type f -name tool_name -executable -print -quit
        cmd = [
            "find", "/", 
            "-path", "/proc", "-prune", "-o", 
            "-path", "/sys", "-prune", "-o", 
            "-path", "/dev", "-prune", "-o", 
            "-path", "/run", "-prune", "-o",
            "-type", "f", "-name", tool_name, "-executable", "-print", "-quit"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        found_path = result.stdout.strip()
        if found_path:
            return found_path
    except:
        pass
        
    return None

def run_recon_tools(domain):
    """Executa ferramentas de descoberta de subdomínios"""
    print(f"\n[+] Coletando subdomínios...")
    subdomains = set()
    tools_ran = 0
    
    # Definição das ferramentas
    # Definição das ferramentas com timeouts específicos (em segundos)
    # Formato: "nome": {"cmd": [args], "timeout": segundos, "ignore_result": bool}
    tools = {
        "subfinder": {
            "cmd": ["subfinder", "-d", domain, "-silent"],
            "timeout": 120
        },
        "assetfinder": {
            "cmd": ["assetfinder", "--subs-only", domain],
            "timeout": 60
        },
        "findomain": {
            "cmd": ["findomain", "-t", domain, "--quiet"],
            "timeout": 60
        },
        # Amass configurado para ser mais rápido mas ainda efetivo
        # Timeout interno do amass (-timeout 3) é em minutos.
        # Damos uma folga no Python (240s > 180s) para ele fechar graciosamente.
        "amass": {
            "cmd": ["amass", "enum", "-passive", "-d", domain, "-timeout", "3", "-noalts", "-norecursive"],
            "timeout": 240
        }
    }

    for tool_name, config in tools.items():
        command_args = config["cmd"]
        tool_timeout = config.get("timeout", 120)
        
        # Busca o executável de forma inteligente
        binary_name = command_args[0]
        full_path = resolve_tool_path(binary_name)
        
        if not full_path:
            print(f"  ⚠️ {tool_name} não encontrado (nem no PATH nem em ~/go/bin). Pulando...")
            continue
            
        # Atualiza o comando com o caminho completo encontrado
        command_args[0] = full_path
            
        try:
            print(f"  🔍 Executando {tool_name} (via {full_path})...")
            # print(f"    ⏳ Timeout definido para: {tool_timeout}s")
            
            result = subprocess.run(
                command_args,
                capture_output=True,
                text=True,
                timeout=tool_timeout
            )
            if result.stdout:
                new_subs = {s.strip() for s in result.stdout.splitlines() if s.strip() and domain in s}
                subdomains.update(new_subs)
                print(f"    ✅ {len(new_subs)} subdomínios encontrados")
                tools_ran += 1
        except subprocess.TimeoutExpired:
            print(f"    ⚠️ {tool_name} demorou demais e foi interrompido (Timeout: {tool_timeout}s).")
            # Tenta recuperar output parcial se possível (difícil com capture_output=True, mas mantemos o fluxo)
        except Exception as e:
            print(f"    ⚠️ Erro com {tool_name}: {str(e)}")
    
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
    """Verifica status do subdomínio: web_active, dns_only, timeout, filtered"""
    # 1. Validação de DNS (Pré-requisito para qualquer verificação)
    ip = resolve_ip(subdomain)
    
    # Se não resolver DNS, classifica como dns_only (mas com status de falha)
    # Isso garante que a contagem bata: Total = Web + DNS + Timeout + Filtered
    if not ip or ip == "N/A":
        return {
            "category": "dns_only",
            "url": f"http://{subdomain}",
            "status": "DNS Resolution Failed",
            "tech": "N/A",
            "title": "N/A",
            "ip": "N/A", # Não tem IP
            "ssl": "N/A",
            "login_detected": False
        }

    protocols = ["https://", "http://"]
    
    # Flags de diagnóstico
    has_timeout = False
    has_connection_error = False

    for protocol in protocols:
        url = f"{protocol}{subdomain}"
        try:
            # Configura headers e timeout
            headers = CUSTOM_HEADERS.copy()
            headers["User-Agent"] = get_random_agent()
            
            # Request com verify=False para ignorar erros de SSL na primeira tentativa HTTPS
            response = requests.get(
                url,
                headers=headers,
                timeout=TIMEOUT,
                allow_redirects=True,
                verify=False
            )
            
            # Critério de sucesso para WEB ACTIVE
            if response.status_code < 500:
                tech = detect_technology(response)
                title = extract_title(response)
                has_login = detect_login_page(response)
                
                print(f"  ✅ [WEB ACTIVE] {url} ({response.status_code}) | {tech}")
                return {
                    "category": "web_active",
                    "url": url,
                    "status": response.status_code,
                    "tech": tech,
                    "title": title,
                    "ip": ip,
                    "ssl": get_ssl_info(subdomain) if protocol == "https://" else "N/A",
                    "login_detected": has_login
                }
        
        except requests.exceptions.Timeout:
            has_timeout = True
        except requests.exceptions.ConnectionError:
            has_connection_error = True
        except requests.exceptions.SSLError:
            # SSLError tenta o próximo protocolo (HTTP)
            pass
        except Exception:
            pass

    # Se chegou aqui, não é WEB ACTIVE. Classificar o erro.
    category = "dns_only"
    status_msg = "DNS Only"

    if has_timeout:
        category = "timeout"
        status_msg = "Timeout"
    elif has_connection_error:
        category = "filtered"
        status_msg = "Connection Error/Filtered"

    # Exibe no console apenas se não for strict (ou se desejar logar tudo)
    # No modo strict original, isso seria silenciado, mas como classificamos, vamos mostrar.
    print(f"  ⚠️ [{category.upper()}] {subdomain} | IP: {ip}")

    return {
        "category": category,
        "url": f"http://{subdomain}",
        "status": status_msg,
        "tech": "N/A",
        "title": "N/A",
        "ip": ip,
        "ssl": "N/A",
        "login_detected": False
    }

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
                
                if response.status_code == 429:
                    print(f"    [!] Google bloqueou requisições (HTTP 429)")
                    print(f"    [!] Dorks pulados. Sugestão: usar proxy ou execução manual.")
                    return results # Para a execução dos dorks
                
                if response.status_code != 200:
                    print(f"    [-] Erro na requisição: Status {response.status_code}")
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

def generate_html_report(domain, live_subs, findings, dork_results, classification=None):
    """Gera relatório HTML profissional usando o template externo"""
    report_path = os.path.join(OUTPUT_DIR, f"recon_report_{domain}.html")
    
    # Carregar template
    template_path = os.path.join(os.path.dirname(__file__), "templates", "dashboard_template.html")
    
    try:
        with open(template_path, "r", encoding="utf-8") as f:
            html_template = f.read()
    except FileNotFoundError:
        print(f"  [!] Template não encontrado em {template_path}. Gerando relatório básico.")
        return generate_basic_html_report(domain, live_subs, findings, dork_results)
    
    # Calcular estatísticas
    if classification is None:
        classification = {
            "web_active": live_subs,
            "dns_only": [],
            "timeout": [],
            "filtered": []
        }
    
    total_subs = sum(len(v) for v in classification.values())
    web_active = len(classification.get("web_active", []))
    dns_only = len(classification.get("dns_only", []))
    timeouts = len(classification.get("timeout", []))
    filtered = len(classification.get("filtered", []))
    
    # Calcular porcentagens (evitar divisão por zero)
    def calc_percent(value, total):
        return round((value / total) * 100, 1) if total > 0 else 0
    
    web_active_percent = calc_percent(web_active, total_subs)
    dns_only_percent = calc_percent(dns_only, total_subs)
    timeouts_percent = calc_percent(timeouts, total_subs)
    filtered_percent = calc_percent(filtered, total_subs)
    
    # Classificar subdomínios por tipo
    critical_subs = []
    api_subs = []
    service_subs = []
    infra_subs = []
    
    critical_keywords = ["admin", "login", "auth", "signin", "portal", "backoffice", "panel", "dashboard"]
    api_keywords = ["api", "rest", "graphql", "ws", "websocket", "v1", "v2", "v3"]
    infra_keywords = ["ns", "dns", "smtp", "mail", "mx", "cdn", "ftp", "vpn", "proxy"]
    
    for sub in classification.get("web_active", []):
        url_lower = sub.get("url", "").lower()
        subdomain = url_lower.replace("https://", "").replace("http://", "").split("/")[0]
        
        if any(kw in subdomain for kw in critical_keywords) or sub.get("login_detected", False):
            critical_subs.append(subdomain)
        elif any(kw in subdomain for kw in api_keywords):
            api_subs.append(subdomain)
        elif any(kw in subdomain for kw in infra_keywords):
            infra_subs.append(subdomain)
        else:
            service_subs.append(subdomain)
    
    # Gerar HTML para tabela de subdomínios
    subs_rows = ""
    for sub in live_subs:
        # Determinar classe do status
        status = sub.get("status", "N/A")
        status_class = "status-2xx"
        if isinstance(status, int):
            if 300 <= status < 400:
                status_class = "status-3xx"
            elif 400 <= status < 500:
                status_class = "status-4xx"
            elif status >= 500:
                status_class = "status-5xx"
        
        # Gerar badges
        badges = []
        if sub.get("login_detected", False):
            badges.append('<span class="badge badge-danger">LOGIN PAGE</span>')
        
        url_lower = sub.get("url", "").lower()
        if "admin" in url_lower:
            badges.append('<span class="badge badge-danger">ADMIN</span>')
        elif "api" in url_lower:
            badges.append('<span class="badge badge-info">API</span>')
        
        if isinstance(status, int) and 300 <= status < 400:
            badges.append('<span class="badge badge-warning">REDIRECT</span>')
        
        badges_html = " ".join(badges)
        
        subs_rows += f'''
        <tr>
            <td><a href="{sub.get('url', '#')}" target="_blank">{sub.get('url', 'N/A')}</a></td>
            <td><span class="status-code {status_class}">{status}</span></td>
            <td>{sub.get('ip', 'N/A')}</td>
            <td>{sub.get('tech', 'Unknown')}</td>
            <td>{sub.get('title', '—')}</td>
            <td>{badges_html}</td>
        </tr>'''
    
    # Gerar HTML para paths sensíveis
    paths_rows = ""
    for finding in findings:
        status = finding.get("status", "N/A")
        status_class = "status-2xx" if isinstance(status, int) and status < 300 else "status-4xx"
        
        # Determinar tipo e risco
        path_url = finding.get("url", "")
        path_type = "Unknown"
        risk_badge = '<span class="badge badge-warning">MÉDIO</span>'
        
        if ".env" in path_url or "config" in path_url.lower():
            path_type = "Config File"
            risk_badge = '<span class="badge badge-danger">CRÍTICO</span>'
        elif ".sql" in path_url or "backup" in path_url.lower():
            path_type = "Database Backup"
            risk_badge = '<span class="badge badge-danger">CRÍTICO</span>'
        elif "phpinfo" in path_url.lower():
            path_type = "Info Disclosure"
            risk_badge = '<span class="badge badge-warning">ALTO</span>'
        elif ".git" in path_url:
            path_type = "Source Code"
            risk_badge = '<span class="badge badge-danger">CRÍTICO</span>'
        elif finding.get("is_login", False):
            path_type = "Login Page"
            risk_badge = '<span class="badge badge-warning">ALTO</span>'
        
        size_bytes = finding.get("length", 0)
        if size_bytes > 1024 * 1024:
            size_str = f"{size_bytes / (1024*1024):.1f} MB"
        elif size_bytes > 1024:
            size_str = f"{size_bytes / 1024:.1f} KB"
        else:
            size_str = f"{size_bytes} B"
        
        paths_rows += f'''
        <tr>
            <td><a href="{path_url}" target="_blank">{path_url}</a></td>
            <td><span class="status-code {status_class}">{status}</span></td>
            <td>{path_type}</td>
            <td>{size_str}</td>
            <td>{risk_badge}</td>
        </tr>'''
    
    # Gerar HTML para dorks
    dorks_content = ""
    for result in dork_results:
        links_html = ""
        for link in result.get("links", []):
            links_html += f'<li><a href="{link}" target="_blank">{link}</a></li>'
        
        dorks_content += f'''
        <div class="dork-item">
            <div class="dork-query">{result.get('dork', '')}</div>
            <ul class="dork-links">{links_html}</ul>
        </div>'''
    
    if not dorks_content:
        dorks_content = '''
        <div class="empty-state">
            <div class="empty-state-icon">🔍</div>
            <p class="empty-state-text">Nenhum resultado de dorks encontrado.</p>
        </div>'''
    
    # Gerar listas de classificação
    critical_list = "".join([f'<li class="classification-item">{s}</li>' for s in critical_subs[:10]])
    api_list = "".join([f'<li class="classification-item">{s}</li>' for s in api_subs[:10]])
    services_list = "".join([f'<li class="classification-item">{s}</li>' for s in service_subs[:10]])
    infra_list = "".join([f'<li class="classification-item">{s}</li>' for s in infra_subs[:10]])
    
    # Calcular larguras das barras (máximo 100%, relativo ao maior valor)
    max_bar = max(total_subs, len(findings), len(dork_results), 1)
    paths_bar_width = min(100, calc_percent(len(findings), max_bar) * 2)
    dorks_bar_width = min(100, calc_percent(len(dork_results), max_bar) * 2)
    
    # Substituições no template
    replacements = {
        "{{TARGET}}": domain,
        "{{DATE}}": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "{{TOTAL_SUBDOMAINS}}": str(total_subs),
        "{{WEB_ACTIVE}}": str(web_active),
        "{{DNS_ONLY}}": str(dns_only),
        "{{TIMEOUTS}}": str(timeouts),
        "{{FILTERED}}": str(filtered),
        "{{SENSITIVE_PATHS}}": str(len(findings)),
        "{{DORKS_RESULTS}}": str(len(dork_results)),
        "{{WEB_ACTIVE_PERCENT}}": str(web_active_percent),
        "{{DNS_ONLY_PERCENT}}": str(dns_only_percent),
        "{{TIMEOUTS_PERCENT}}": str(timeouts_percent),
        "{{FILTERED_PERCENT}}": str(filtered_percent),
        "{{PATHS_BAR_WIDTH}}": str(paths_bar_width),
        "{{DORKS_BAR_WIDTH}}": str(dorks_bar_width),
        "{{CRITICAL_COUNT}}": str(len(critical_subs)),
        "{{API_COUNT}}": str(len(api_subs)),
        "{{SERVICES_COUNT}}": str(len(service_subs)),
        "{{INFRA_COUNT}}": str(len(infra_subs)),
        "<!-- {{SUBDOMAINS_ROWS}} -->": subs_rows,
        "<!-- {{PATHS_ROWS}} -->": paths_rows,
        "<!-- {{DORKS_CONTENT}} -->": dorks_content,
        "<!-- {{CRITICAL_LIST}} -->": critical_list,
        "<!-- {{API_LIST}} -->": api_list,
        "<!-- {{SERVICES_LIST}} -->": services_list,
        "<!-- {{INFRA_LIST}} -->": infra_list,
    }
    
    html_output = html_template
    for placeholder, value in replacements.items():
        html_output = html_output.replace(placeholder, value)
    
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html_output)
    
    print(f"  ✅ Relatório HTML gerado: {report_path}")
    return report_path


def generate_basic_html_report(domain, live_subs, findings, dork_results):
    """Fallback: Gera relatório HTML básico quando template não está disponível"""
    report_path = os.path.join(OUTPUT_DIR, f"recon_report_{domain}.html")
    
    subs_html = ""
    for sub in live_subs:
        login_badge = '<span style="color:red">[LOGIN]</span>' if sub.get("login_detected") else ""
        subs_html += f'<tr><td><a href="{sub["url"]}">{sub["url"]}</a> {login_badge}</td><td>{sub["status"]}</td><td>{sub["ip"]}</td><td>{sub["tech"]}</td></tr>'
    
    findings_html = ""
    for f in findings:
        findings_html += f'<tr><td><a href="{f["url"]}">{f["url"]}</a></td><td>{f["status"]}</td><td>{f.get("length", 0)} bytes</td></tr>'
    
    html = f'''<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Recon - {domain}</title>
<style>body{{font-family:monospace;background:#1a1a2e;color:#eee;padding:20px}}
table{{width:100%;border-collapse:collapse}}th,td{{padding:8px;border:1px solid #333;text-align:left}}
a{{color:#00f5ff}}</style></head>
<body><h1>Recon Report: {domain}</h1><p>Data: {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
<h2>Subdomínios ({len(live_subs)})</h2><table><tr><th>URL</th><th>Status</th><th>IP</th><th>Tech</th></tr>{subs_html}</table>
<h2>Paths Sensíveis ({len(findings)})</h2><table><tr><th>URL</th><th>Status</th><th>Size</th></tr>{findings_html}</table>
<h2>Dorks ({len(dork_results)})</h2><p>{len(dork_results)} resultados encontrados</p>
<footer><p>CHDEVSEC - Recon Pro</p></footer></body></html>'''
    
    with open(report_path, "w", encoding="utf-8") as f:
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
    parser.add_argument('--mode', choices=['strict', 'soft'], default='strict', help='Modo de verificação (strict: apenas HTTP ativo, soft: considera DNS/Timeout)')
    args = parser.parse_args()
    
    domain = args.domain.lower().replace("https://", "").replace("http://", "").split("/")[0]
    dork_type = args.dork_type
    
    # Configuração do Modo
    global TIMEOUT, MODE
    MODE = args.mode
    if MODE == "soft":
        TIMEOUT = 20
        print(f"\n[!] MODO SOFT ATIVADO: Timeout {TIMEOUT}s | DNS Only = Classificado")
    else:
        TIMEOUT = 10
    
    banner()
    
    # Seleção de tecnologia
    tech_type = select_technology()
    print(f"\n[+] Tecnologia selecionada: {tech_type}")
    
    # Etapa 1: Descoberta de subdomínios
    subdomains = run_recon_tools(domain)
    
    # Etapa 2: Verificação de hosts ativos
    # Etapa 2: Classificação de subdomínios
    print(f"\n[+] Verificando e classificando subdomínios com {THREADS} threads...")
    
    classification = {
        "web_active": [],
        "dns_only": [],
        "timeout": [],
        "filtered": []
    }
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = {executor.submit(check_subdomain_alive, sub): sub for sub in subdomains}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                cat = result.get("category", "dns_only")
                if cat in classification:
                    classification[cat].append(result)
    
    live_subs = classification["web_active"]
    
    # Exibe resumo parcial
    print(f"\n[+] Resumo da Classificação:")
    print(f"  ✅ Web Active: {len(classification['web_active'])}")
    print(f"  ⚠️ DNS Only:   {len(classification['dns_only'])}")
    print(f"  ⏳ Timeout:    {len(classification['timeout'])}")
    print(f"  🚫 Filtered:   {len(classification['filtered'])}")

    # Fallback para domínio principal (apenas se nenhum web active encontrado)
    if not live_subs:
        print("  ⚠️ Nenhum subdomínio web ativo encontrado. Testando domínio base...")
        base_test = check_subdomain_alive(domain)
        if base_test and base_test["category"] == "web_active":
             live_subs.append(base_test)
             classification["web_active"].append(base_test)
    
    # Etapa 3: Fuzzing com payloads específicos (Apenas em Web Active)
    all_findings = []
    if live_subs:
        print(f"\n[*] Iniciando fuzzing em {len(live_subs)} hosts Web Ativos com payloads para {tech_type}...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as executor:
            # live_subs já contém apenas web_active
            futures = [executor.submit(fuzz_url, sub['url'], tech_type) for sub in live_subs]
            for i, future in enumerate(concurrent.futures.as_completed(futures), 1):
                findings = future.result()
                if findings:
                    print(f"  [+] [{i}/{len(live_subs)}] Encontrados {len(findings)} paths em {live_subs[i-1]['url']}")
                    all_findings.extend(findings)
    
    # Etapa 4: Google Dorks
    dork_results = google_dork_search(domain, dork_type)
    
    # Etapa 5: Geração de relatório
    report_path = generate_html_report(domain, live_subs, all_findings, dork_results, classification)
    
    # Resumo final estilizado (Forçado)
    print_final_summary(domain, tech_type, subdomains, classification, report_path)

if __name__ == "__main__":
    main()
