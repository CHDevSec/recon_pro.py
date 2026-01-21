#!/bin/bash

# ==========================================
# INSTALADOR ROBUSTO - RECON PRO
# ==========================================

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Banner
echo -e "${BLUE}"
echo '██╗███╗   ██╗███████╗████████╗ █████╗ ██╗     ██╗         ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗    ██████╗ ██████╗  ██████╗ '
echo '██║████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██║     ██║         ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║    ██╔══██╗██╔══██╗██╔═══██╗'
echo '██║██╔██╗ ██║███████╗   ██║   ███████║██║     ██║         ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║    ██████╔╝██████╔╝██║   ██║'
echo '██║██║╚██╗██║╚════██║   ██║   ██╔══██║██║     ██║         ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║    ██╔═══╝ ██╔══██╗██║   ██║'
echo '██║██║ ╚████║███████║   ██║   ██║  ██║███████╗███████╗    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║    ██║     ██║  ██║╚██████╔╝'
echo '╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝    ╚═╝     ╚═╝  ╚═╝ ╚═════╝ '
echo -e "${NC}"

# Função de verificação de sucesso
check_success() {
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[✓] Sucesso!${NC}"
    else
        echo -e "${RED}[X] Falha!${NC}"
        # Não sai do script, tenta continuar
    fi
}

# 1. Atualizar repositórios e instalar dependências do sistema
echo -e "\n${YELLOW}[*] Atualizando sistema e instalando dependências base...${NC}"
sudo apt-get update -y
sudo apt-get install -y git curl wget unzip python3 python3-pip python3-venv libpcap-dev plocate

# Atualiza DB do locate para facilitar a busca do recon.py
echo -e "${YELLOW}[*] Atualizando base de dados do 'locate'...${NC}"
sudo updatedb

# 2. Configuração do Python
echo -e "\n${YELLOW}[*] Verificando dependências Python...${NC}"
if [ -f "requirements.txt" ]; then
    # Tenta instalar system-wide ou user, dependendo da configuração. 
    # Adicionando --break-system-packages para sistemas novos que exigem venv, 
    # mas mantendo compatibilidade.
    pip3 install -r requirements.txt --break-system-packages 2>/dev/null || pip3 install -r requirements.txt
    check_success
else
    echo -e "${RED}[!] requirements.txt não encontrado!${NC}"
fi

# 3. Instalação Robusta do Go
echo -e "\n${YELLOW}[*] Configurando Go (Golang)...${NC}"

# Verifica se o go existe e a versão
INSTALL_GO=false
if command -v go &> /dev/null; then
    GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
    echo -e "${GREEN}[✓] Go detectado detectada: $GO_VERSION${NC}"
    # Opcional: Checar se a versão é muito antiga (ex: < 1.20)
else
    echo -e "${RED}[!] Go não encontrado.${NC}"
    INSTALL_GO=true
fi

if [ "$INSTALL_GO" = true ]; then
    echo -e "${YELLOW}[*] Instalando Go mais recente...${NC}"
    # Baixa e instala a última versão estável do Go manualmente para garantir compatibilidade
    wget https://go.dev/dl/go1.21.6.linux-amd64.tar.gz -O go_setup.tar.gz
    sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go_setup.tar.gz
    rm go_setup.tar.gz
    
    # Configura variáveis temporárias para este script agora mesmo
    export PATH=$PATH:/usr/local/go/bin
    echo -e "${GREEN}[✓] Go instalado manualmente em /usr/local/go${NC}"
fi

# Configurar Ambiente Go (GOPATH/GOBIN)
export GOPATH=$HOME/go
export GOBIN=$HOME/go/bin
export PATH=$PATH:/usr/local/go/bin:$GOBIN

# Adicionar ao PATH permanentemente
echo -e "\n${YELLOW}[*] Configurando PATH no .bashrc e .zshrc...${NC}"

add_path_if_missing() {
    RC_FILE="$1"
    if [ -f "$RC_FILE" ]; then
        if ! grep -q "export PATH=\$PATH:/usr/local/go/bin:\$HOME/go/bin" "$RC_FILE"; then
            echo >> "$RC_FILE"
            echo '# Configuração Go - Recon Pro' >> "$RC_FILE"
            echo 'export GOPATH=$HOME/go' >> "$RC_FILE"
            echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> "$RC_FILE"
            echo -e "${GREEN}[+] PATH adicionado ao $RC_FILE${NC}"
        else
            echo -e "${GREEN}[✓] PATH já configurado no $RC_FILE${NC}"
        fi
    fi
}

add_path_if_missing "$HOME/.bashrc"
add_path_if_missing "$HOME/.zshrc"
add_path_if_missing "$HOME/.profile"

# 4. Instalar Ferramentas
echo -e "\n${YELLOW}[*] Instalando ferramentas de Recon (Isso pode demorar)...${NC}"

# Função auxiliar para instalar tool Go
install_go_tool() {
    PKG=$1
    NAME=$2
    echo -e "${BLUE} > Instalando/Atualizando $NAME...${NC}"
    go install -v "$PKG"
    
    if [ -f "$GOBIN/$NAME" ]; then
        echo -e "${GREEN}[✓] $NAME instalado em $GOBIN/$NAME${NC}"
        # Copia para /usr/local/bin para 'Modo Coringa' do script não ser necessário
        sudo cp "$GOBIN/$NAME" /usr/local/bin/ 2>/dev/null
        sudo chmod +x /usr/local/bin/$NAME
    else
        echo -e "${RED}[X] Erro ao instalar $NAME${NC}"
    fi
}

# Subfinder
if ! command -v subfinder &> /dev/null; then
    install_go_tool "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" "subfinder"
else
    echo -e "${GREEN}[✓] Subfinder já instalado.${NC}"
fi

# Assetfinder
if ! command -v assetfinder &> /dev/null; then
    install_go_tool "github.com/tomnomnom/assetfinder@latest" "assetfinder"
else
    echo -e "${GREEN}[✓] Assetfinder já instalado.${NC}"
fi

# Amass (Mais demorado e complexo)
if ! command -v amass &> /dev/null; then
    echo -e "${YELLOW}[!] Amass não encontrado. Instalando versão v4...${NC}"
    install_go_tool "github.com/owasp-amass/amass/v4/...@latest" "amass"
else
     echo -e "${GREEN}[✓] Amass já instalado.${NC}"
fi

# Findomain (Binário direto para evitar problemas de compilação rust)
if ! command -v findomain &> /dev/null; then
    echo -e "${BLUE} > Baixando Findomain...${NC}"
    wget https://github.com/findomain/findomain/releases/latest/download/findomain-linux.zip -O findomain.zip
    unzip -o findomain.zip
    chmod +x findomain
    sudo mv findomain /usr/local/bin/findomain
    rm findomain.zip
    check_success
else
    echo -e "${GREEN}[✓] Findomain já instalado.${NC}"
fi

# httprobe & waybackurls (Utilitários extras recomendados para recon)
if ! command -v httprobe &> /dev/null; then
    install_go_tool "github.com/tomnomnom/httprobe@latest" "httprobe"
fi
if ! command -v waybackurls &> /dev/null; then
    install_go_tool "github.com/tomnomnom/waybackurls@latest" "waybackurls"
fi

# 5. Verificação Final (Checklist)
echo -e "\n${BLUE}"
echo '  ___ ___ _      _ _____  __ ___ ___ ___    ___  ___   ___ _  _ ___ _____ _   _      _   ___  /\/|___  '
echo ' | _ \ __| |    /_\_   _|/_/| _ \_ _/ _ \  |   \| __| |_ _| \| / __|_   _/_\ | |    /_\ / __||/\// _ \ '
echo ' |   / _|| |__ / _ \| |/ __ \   /| | (_) | | |) | _|   | || .` \__ \ | |/ _ \| |__ / _ \ (__ /--\ (_) |'
echo ' |_|_\___|____/_/ \_\_|\____/_|_\___\___/  |___/|___| |___|_|\_|___/ |_/_/ \_\____/_/ \_\___/_/\_\___/ '
echo '                                                                                         )_)           '
echo -e "${NC}"

check_tool_status() {
    TOOL=$1
    if command -v "$TOOL" &> /dev/null; then
        LOC=$(which "$TOOL")
        echo -e "${GREEN}[✓] $TOOL ......... OK ($LOC)${NC}"
    else
        echo -e "${RED}[X] $TOOL ......... NÃO ENCONTRADO${NC}"
    fi
}

check_tool_status "python3"
check_tool_status "go"
check_tool_status "subfinder"
check_tool_status "assetfinder"
check_tool_status "amass"
check_tool_status "findomain"
check_tool_status "httprobe"

# 6. Ajuste de Permissões (Caso tenha rodado com sudo)
if [ -n "$SUDO_USER" ]; then
    echo -e "\n${YELLOW}[*] Ajustando permissões do diretório para o usuário $SUDO_USER...${NC}"
    chown -R $SUDO_USER:$SUDO_USER .
    echo -e "${GREEN}[✓] Permissões corrigidas.${NC}"
fi

echo -e "${YELLOW}[!] IMPORTANTE: Se alguma ferramenta falhou, tente rodar este script novamente ou verifique sua conexão.${NC}"
echo -e "${YELLOW}[!] Pode ser necessário reiniciar seu terminal para carregar o novo PATH.${NC}"
echo -e "${YELLOW}[!] Execute: source ~/.bashrc (ou ~/.zshrc)${NC}"
