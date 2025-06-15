# 🔍 Professional Web Recon - Advanced Subdomain Discovery & Vulnerability Scanner

[![Python Version](https://img.shields.io/badge/python-3.7%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![GitHub Issues](https://img.shields.io/github/issues/chdevsec/professional-web-recon.svg)](https://github.com/chdevsec/professional-web-recon/issues)
[![GitHub Stars](https://img.shields.io/github/stars/chdevsec/professional-web-recon.svg)](https://github.com/chdevsec/professional-web-recon/stargazers)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/chdevsec/professional-web-recon/graphs/commit-activity)

> **Advanced web reconnaissance tool for penetration testing and bug bounty hunting**

A comprehensive web reconnaissance tool that combines subdomain discovery, directory fuzzing, vulnerability detection, and Google Dorking in a single automated solution.

## 📋 Table of Contents

- [Features](#-features)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Basic Usage](#-basic-usage)
- [Advanced Features](#-advanced-features)
- [Reports](#-reports)
- [Supported APIs](#-supported-apis)
- [Integrated Tools](#-integrated-tools)
- [Usage Examples](#-usage-examples)
- [Contributing](#-contributing)
- [License](#-license)

## 🚀 Features

### Subdomain Discovery
- **Multiple sources**: Integration with Subfinder, Assetfinder, Amass, Findomain
- **External APIs**: SecurityTrails, Shodan, crt.sh
- **DNS Brute Force**: Custom wordlist with common subdomains
- **Status verification**: HTTP/HTTPS connectivity testing

### Technology Detection
- **Fingerprinting**: Automatic web technology identification
- **Headers analysis**: HTTP headers analysis
- **Content detection**: Content-based detection
- **Framework detection**: WordPress, Drupal, Laravel, React, Angular, etc.

### Fuzzing and Path Discovery
- **Directory fuzzing**: Administrative directory search
- **Sensitive files**: Detection of sensitive files (.env, .git, backups)
- **Login pages**: Automatic login page identification
- **Specific payloads**: XSS and SQLi by technology

### Vulnerability Detection
- **XSS Detection**: Automated Cross-Site Scripting tests
- **SQL Injection**: Basic SQLi detection
- **Information Disclosure**: Sensitive information leakage
- **Misconfigurations**: Incorrect configuration detection

### Google Dorking
- **Automated dorks**: Automatic Google Dorks execution
- **Categorized search**: Search for login pages, sensitive files, admin panels
- **API integration**: Google Custom Search API support

### Reports
- **HTML Report**: Professional HTML report
- **Detailed findings**: Detailed information about discoveries
- **Vulnerability classification**: Classification of found vulnerabilities
- **Actionable recommendations**: Security recommendations

## 🛠️ Installation

### Prerequisites

```bash
# Python 3.7 or higher
python3 --version

# Pip package manager
pip3 --version
```

### Dependencies Installation

```bash
# Clone the repository
git clone https://github.com/chdevsec/professional-web-recon.git
cd professional-web-recon

# Install Python dependencies
pip3 install -r requirements.txt
```

### Requirements.txt
```txt
requests>=2.25.1
dnspython>=2.1.0
urllib3>=1.26.0
```

### External Tools (Optional)

For maximum effectiveness, install the following tools:

```bash
# Subfinder
GO111MODULE=on go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Assetfinder
go install github.com/tomnomnom/assetfinder@latest

# Amass
go install -v github.com/OWASP/Amass/v3/...@master

# Findomain
wget https://github.com/findomain/findomain/releases/latest/download/findomain-linux
chmod +x findomain-linux
sudo mv findomain-linux /usr/local/bin/findomain
```

## ⚙️ Configuration

### Environment Variables

Configure your API keys as environment variables:

```bash
# SecurityTrails
export SECURITYTRAILS_API_KEY="your_key_here"

# Shodan
export SHODAN_API_KEY="your_key_here"

# Google Custom Search
export GOOGLE_API_KEY="your_key_here"
export GOOGLE_CSE_ID="your_cse_id_here"
```

### Script Configuration

Alternatively, edit the script directly:

```python
API_KEYS = {
    "SECURITYTRAILS": "your_securitytrails_key",
    "SHODAN": "your_shodan_key", 
    "GOOGLE_API_KEY": "your_google_key",
    "GOOGLE_CSE_ID": "your_google_cse_id"
}
```

## 🎯 Basic Usage

### Basic Syntax

```bash
python3 web_recon.py <domain> [options]
```

### Simple Examples

```bash
# Basic reconnaissance
python3 web_recon.py example.com

# With specific Google Dorks type
python3 web_recon.py example.com --dork-type login

# Sensitive files only
python3 web_recon.py example.com --dork-type files
```

## 🔧 Advanced Features

### Technology Selection

The script offers specific payloads for different technologies:

1. **PHP** - Optimized payloads for PHP applications
2. **Node.js** - Specific tests for Node.js
3. **Next.js** - Payloads for Next.js applications
4. **Angular** - Specific tests for Angular
5. **Django** - Payloads for Django (Python)
6. **Flask** - Tests for Flask (Python)
7. **Ruby on Rails** - Payloads for Rails
8. **Generic** - Universal payloads

### Google Dorks Types

- `all`: Executes all types of dorks
- `login`: Focuses on login pages
- `files`: Searches for sensitive files
- `admin`: Looks for administrative panels

### Advanced Settings

```python
# Number of threads
THREADS = 20

# Request timeout
TIMEOUT = 10

# Output directory
OUTPUT_DIR = "recon_results"
```

## 📊 Reports

### HTML Report Structure

The generated report includes:

- **Executive summary**: General reconnaissance statistics
- **Active subdomains**: Complete list with status and technologies
- **Sensitive paths**: Discovered sensitive URLs
- **Vulnerabilities**: Identified potential vulnerabilities
- **Google Dorks**: Google search results
- **Recommendations**: Correction suggestions

### File Locations

```
recon_results/
├── recon_report_example.com.html
└── screenshots/
```

## 🔌 Supported APIs

### SecurityTrails
- **Functionality**: Subdomain discovery
- **Limit**: Varies by plan
- **Registration**: [securitytrails.com](https://securitytrails.com)

### Shodan
- **Functionality**: Host and subdomain information
- **Limit**: 100 queries/month (free)
- **Registration**: [shodan.io](https://shodan.io)

### Google Custom Search
- **Functionality**: Automated Google Dorking
- **Limit**: 100 queries/day (free)
- **Registration**: [developers.google.com](https://developers.google.com/custom-search)

### crt.sh
- **Functionality**: SSL/TLS certificates
- **Limit**: No limit
- **Registration**: Not required

## 🛡️ Integrated Tools

| Tool | Function | Status |
|------|----------|--------|
| Subfinder | Subdomain discovery | ✅ Integrated |
| Assetfinder | Asset enumeration | ✅ Integrated |
| Amass | Passive reconnaissance | ✅ Integrated |
| Findomain | Domain search | ✅ Integrated |
| DNSPython | DNS resolution | ✅ Integrated |

## 💡 Usage Examples

### Scenario 1: Bug Bounty Hunting

```bash
# Complete reconnaissance for bug bounty
python3 web_recon.py target.com

# Focus on login pages
python3 web_recon.py target.com --dork-type login
```

### Scenario 2: Web Application Pentest

```bash
# Reconnaissance focused on PHP application
python3 web_recon.py webapp.com
# Select option "1" for PHP when prompted
```

### Scenario 3: Security Audit

```bash
# Search for exposed sensitive files
python3 web_recon.py company.com --dork-type files
```

## 🔍 Vulnerability Detection

### Supported Types

- **XSS (Cross-Site Scripting)**
  - Reflected XSS
  - Technology-specific payloads
  
- **SQL Injection**
  - Error-based detection
  - Time-based detection
  
- **Information Disclosure**
  - Configuration files
  - Application logs
  - Exposed credentials
  
- **Misconfigurations**
  - CORS misconfiguration
  - Debug mode enabled
  - Directory listing

## 🎨 Customization

### Adding New Payloads

```python
PAYLOADS = {
    "XSS": {
        "your_technology": [
            "payload1",
            "payload2"
        ]
    }
}
```

### Customizing Wordlists

```python
COMMON_SUBDOMAINS = [
    "api", "admin", "test", "dev",
    # Add your custom subdomains
]
```

## 🤝 Contributing

Contributions are welcome! To contribute:

1. Fork the project
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Types of Contributions

- 🐛 Bug fixes
- ✨ New features
- 📚 Documentation improvements
- 🔧 Performance optimizations
- 🛡️ Security improvements

## ⚠️ Legal Disclaimer

This tool was developed for educational purposes and authorized security testing. The use of this tool is entirely the user's responsibility. Make sure you have explicit authorization before testing any system.

### Responsible Use

- ✅ Test only on your own systems or with explicit authorization
- ✅ Respect the terms of service of the APIs used
- ✅ Use rate limiting to avoid server overload
- ❌ Do not use for malicious or illegal activities

## 🏆 Acknowledgments

- **ProjectDiscovery** for excellent reconnaissance tools
- **OWASP** for the Amass project
- **Shodan** for the intelligence API
- **SecurityTrails** for DNS data

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<div align="center">

### 🔒 Developed by [CHDEVSEC](https://github.com/chdevsec) | Pentester Caio

**⭐ If this project was useful to you, consider giving it a star!**

[![GitHub followers](https://img.shields.io/github/followers/chdevsec.svg?style=social&label=Follow)](https://github.com/chdevsec)

</div>

---

## 📚 Tags and Keywords

`pentest` `reconnaissance` `subdomain-enumeration` `vulnerability-scanner` `bug-bounty` `cybersecurity` `web-security` `ethical-hacking` `security-testing` `python` `automation` `google-dorking` `dns-enumeration` `web-fuzzing` `security-audit` `information-gathering` `osint` `red-team` `penetration-testing` `security-tools` `recon` `subdomain-discovery` `web-reconnaissance` `pentesting-tools` `security-scanner` `vulnerability-assessment` `web-application-security` `subdomain-takeover` `directory-bruteforce` `sensitive-file-detection`
