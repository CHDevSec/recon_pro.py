# 🔍 Recon Web Profissional

Uma ferramenta completa de reconhecimento web automatizado para descoberta de subdomínios, fuzzing de diretórios e detecção de vulnerabilidades.

## 📋 Índice

- [Sobre](#sobre)
- [Características](#características)
- [Pré-requisitos](#pré-requisitos)
- [Instalação](#instalação)
- [Uso](#uso)
- [APIs Suportadas](#apis-suportadas)
- [Configuração](#configuração)
- [Exemplos](#exemplos)
- [Resultados](#resultados)
- [Disclaimer](#disclaimer)
- [Contribuições](#contribuições)
- [Licença](#licença)

## 🎯 Sobre

O **Recon Web Profissional** é uma ferramenta de linha de comando desenvolvida para profissionais de segurança cibernética que precisam realizar reconhecimento automatizado de aplicações web. A ferramenta combina múltiplas técnicas de descoberta de subdomínios, fuzzing inteligente e detecção de vulnerabilidades básicas.

### Desenvolvido por
**Pentester Caio | CHDEVSEC**

## ✨ Características

### 🔍 Descoberta de Subdomínios
- **Ferramentas Externas**: Integração com Subfinder, Assetfinder, Amass e Findomain
- **APIs**: SecurityTrails, Shodan, crt.sh
- **DNS Brute Force**: Lista personalizada de subdomínios comuns
- **Verificação de Status**: Teste automático de disponibilidade

### 🌐 Análise de Tecnologias
- Detecção automática de tecnologias web (WordPress, Laravel, React, etc.)
- Análise de headers HTTP e cookies
- Extração de títulos de páginas
- Informações de certificados SSL/TLS

### 🔎 Fuzzing Inteligente
- **Paths Administrativos**: Descoberta de painéis admin
- **Arquivos Sensíveis**: Busca por .env, backups, logs
- **Páginas de Login**: Detecção automática de formulários
- **Payloads Específicos**: XSS e SQLi baseados na tecnologia detectada

### 🕵️ Google Dorks
- Busca automatizada por:
  - Páginas de login expostas
  - Arquivos sensíveis indexados
  - Painéis administrativos
  - Credenciais vazadas

### 📊 Relatórios Profissionais
- **HTML Interativo**: Relatório visual completo
- **Categorização**: Organização por tipo de descoberta
- **Links Diretos**: Acesso rápido aos recursos encontrados
- **Recomendações**: Sugestões de segurança

## 🛠 Pré-requisitos

### Obrigatórios
- Python 3.6+
- pip (gerenciador de pacotes Python)

### Opcionais (para máxima eficiência)
```bash
# Ferramentas de descoberta de subdomínios
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/assetfinder@latest
snap install amass
wget https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux
```

## 📦 Instalação

1. **Clone o repositório:**
```bash
git clone https://github.com/seu-usuario/recon-web-profissional.git
cd recon-web-profissional
```

2. **Instale as dependências Python:**
```bash
pip install -r requirements.txt
```

3. **Torne o script executável:**
```bash
chmod +x recon.py
```

### Dependências Python (requirements.txt)
```
requests>=2.25.0
dnspython>=2.1.0
```

## 🚀 Uso

### Uso Básico
```bash
python3 recon.py exemplo.com
```

### Uso Avançado
```bash
# Especificar tipo de Google Dorks
python3 recon.py exemplo.com --dork-type login
python3 recon.py exemplo.com --dork-type files
python3 recon.py exemplo.com --dork-type admin
```

### Seleção de Tecnologia
Durante a execução, você pode selecionar a tecnologia alvo:
1. PHP
2. Node.js
3. Next.js
4. Angular
5. Django (Python)
6. Flask (Python)
7. Ruby on Rails
8. Outra/Genérico

## 🔑 APIs Suportadas

Configure as seguintes variáveis de ambiente para máxima eficiência:

```bash
# SecurityTrails API
export SECURITYTRAILS_API_KEY="sua_api_key_aqui"

# Shodan API
export SHODAN_API_KEY="sua_api_key_aqui"

# Google Custom Search (para Dorks)
export GOOGLE_API_KEY="sua_api_key_aqui"
export GOOGLE_CSE_ID="seu_cse_id_aqui"
```

### Como obter as APIs:
- **SecurityTrails**: [securitytrails.com](https://securitytrails.com)
- **Shodan**: [shodan.io](https://shodan.io)
- **Google CSE**: [developers.google.com](https://developers.google.com/custom-search)

## ⚙️ Configuração

O script possui configurações avançadas que podem ser ajustadas:

```python
# Número de threads para processamento paralelo
THREADS = 20

# Timeout para requisições HTTP
TIMEOUT = 10

# Diretório de saída
OUTPUT_DIR = "recon_results"
```

## 📝 Exemplos

### Exemplo 1: Recon Completo
```bash
python3 recon.py target.com
```
**Saída:**
- Lista de subdomínios ativos
- Tecnologias detectadas
- Paths sensíveis encontrados
- Relatório HTML completo

### Exemplo 2: Foco em Login Pages
```bash
python3 recon.py target.com --dork-type login
```

### Exemplo 3: Busca por Arquivos Sensíveis
```bash
python3 recon.py target.com --dork-type files
```

## 📈 Resultados

### Estrutura de Saída
```
recon_results/
├── recon_report_target.com.html
└── screenshots/
```

### Informações Coletadas
- **Subdomínios**: URLs, status, IPs, tecnologias
- **Vulnerabilidades**: XSS, SQLi, LFI, RCE básicos
- **Login Pages**: Formulários de autenticação
- **Arquivos Sensíveis**: Backups, logs, configurações
- **Certificados SSL**: Informações de emissor e validade

## ⚠️ Disclaimer

### AVISO LEGAL E ÉTICO

**ESTA FERRAMENTA É DESTINADA EXCLUSIVAMENTE PARA FINS EDUCACIONAIS E TESTES DE SEGURANÇA AUTORIZADOS.**

#### ✅ USO PERMITIDO:
- Testes em seus próprios sistemas e aplicações
- Pentest autorizado com permissão por escrito
- Pesquisa educacional em ambientes controlados
- Bug bounty programs com escopo definido
- Red team exercises autorizados

#### ❌ USO PROIBIDO:
- Testes não autorizados em sistemas de terceiros
- Acesso não autorizado a dados ou sistemas
- Violação de termos de serviço
- Atividades maliciosas ou ilegais
- Coleta de dados sem permissão

#### 📋 RESPONSABILIDADES:
- **O usuário** é totalmente responsável pelo uso desta ferramenta
- **O desenvolvedor** não se responsabiliza por mau uso ou danos
- Sempre obtenha **autorização explícita** antes de usar
- Respeite as **leis locais** e **termos de serviço**
- Use apenas em **ambientes controlados** ou **sistemas próprios**

#### 🛡️ ÉTICA EM SEGURANÇA:
- Reporte vulnerabilidades de forma responsável
- Não cause danos aos sistemas testados
- Mantenha confidencialidade dos dados encontrados
- Siga as melhores práticas de disclosure

**AO USAR ESTA FERRAMENTA, VOCÊ CONCORDA EM ASSUMIR TOTAL RESPONSABILIDADE POR SUAS AÇÕES E ACEITA QUE O USO INADEQUADO PODE RESULTAR EM CONSEQUÊNCIAS LEGAIS.**

## 🤝 Contribuições

Contribuições são bem-vindas! Por favor:

1. Faça um fork do projeto
2. Crie uma branch para sua feature (`git checkout -b feature/AmazingFeature`)
3. Commit suas mudanças (`git commit -m 'Add some AmazingFeature'`)
4. Push para a branch (`git push origin feature/AmazingFeature`)
5. Abra um Pull Request

### Áreas para Contribuição:
- Novos módulos de descoberta
- Detecção de vulnerabilidades
- Melhoria nos relatórios
- Otimizações de performance
- Documentação

## 📧 Contato

**Pentester Caio | CHDEVSEC**

- GitHub: [@seu-github](https://github.com/seu-usuario)
- LinkedIn: [Seu LinkedIn](https://linkedin.com/in/seu-perfil)

## 📄 Licença

Este projeto está licenciado sob a Licença MIT - veja o arquivo [LICENSE](LICENSE) para detalhes.

---

## 🛠️ Roadmap

### Próximas Funcionalidades:
- [ ] Integração com mais APIs (VirusTotal, Censys)
- [ ] Módulo de screenshot automático
- [ ] Detecção de WAF
- [ ] Export para JSON/CSV
- [ ] Interface web opcional
- [ ] Integração com Metasploit
- [ ] Análise de JavaScript
- [ ] Detecção de CMS específicos

---

**⭐ Se esta ferramenta foi útil para você, considere dar uma estrela no repositório!**

*Desenvolvido com ❤️ para a comunidade de segurança cibernética*
