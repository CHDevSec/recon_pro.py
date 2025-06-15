# 🔍 Professional Web Reconnaissance & Security Assessment Tool

[![Python Version](https://img.shields.io/badge/python-3.6%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-Educational%20Use%20Only-red.svg)](#legal-disclaimer)
[![Penetration Testing](https://img.shields.io/badge/pentest-reconnaissance-green.svg)](https://github.com)
[![Web Security](https://img.shields.io/badge/web%20security-vulnerability%20assessment-orange.svg)](https://github.com)

> **Advanced Web Reconnaissance Framework for Cybersecurity Professionals, Penetration Testers, and Bug Bounty Hunters**

## 📋 Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Installation](#installation)
- [Usage](#usage)
- [API Configuration](#api-configuration)
- [Advanced Features](#advanced-features)
- [Output & Reporting](#output--reporting)
- [SEO Keywords](#seo-keywords)
- [Legal Disclaimer](#legal-disclaimer)
- [Educational Purpose](#educational-purpose)
- [Contributing](#contributing)
- [Author](#author)

## 🎯 Overview

This **Professional Web Reconnaissance Tool** is a comprehensive Python-based framework designed for **cybersecurity professionals**, **penetration testers**, **bug bounty hunters**, and **security researchers**. The tool performs automated **subdomain enumeration**, **web fuzzing**, **vulnerability detection**, **technology fingerprinting**, and **Google dorking** to provide detailed security assessments of web applications and domains.

Perfect for **OSINT (Open Source Intelligence)**, **web application security testing**, **penetration testing**, **bug bounty hunting**, and **cybersecurity research**.

## ✨ Key Features

### 🔍 Subdomain Discovery & Enumeration
- **Multi-tool integration**: Subfinder, Assetfinder, Amass, Findomain
- **Certificate transparency**: crt.sh integration
- **DNS brute forcing** with custom wordlists
- **API-powered discovery**: SecurityTrails, Shodan integration
- **Advanced DNS resolution** with timeout handling

### 🌐 Web Application Reconnaissance
- **Technology fingerprinting**: WordPress, Drupal, Laravel, React, Angular, etc.
- **SSL/TLS certificate analysis**
- **HTTP header analysis** and security header detection
- **Login page detection** and authentication endpoint discovery
- **Content Management System (CMS) detection**

### 🎯 Advanced Web Fuzzing
- **Directory and file fuzzing** with custom wordlists
- **Admin panel discovery**: /admin, /wp-admin, /administrator, etc.
- **Sensitive file detection**: .env, .git, backup files, configuration files
- **Technology-specific payload testing**
- **Multi-threaded fuzzing** for improved performance

### 🚨 Vulnerability Detection
- **XSS (Cross-Site Scripting)** payload testing
- **SQL Injection** signature detection
- **Remote Code Execution (RCE)** indicators
- **Local File Inclusion (LFI)** testing
- **CORS misconfiguration** detection
- **Debug mode and credential leak** detection

### 🔎 Google Dorking & OSINT
- **Automated Google dorking** for sensitive information
- **Login page discovery** through search engines
- **Sensitive file exposure** detection
- **Admin panel identification** via search queries
- **API integration** with Google Custom Search

### 📊 Professional Reporting
- **HTML report generation** with professional styling
- **Vulnerability categorization** and risk assessment
- **Technology stack visualization**
- **Actionable security recommendations**
- **Export-ready documentation**

## 🛠️ Installation

### Prerequisites
- **Python 3.6+**
- **pip package manager**
- **Git** (for cloning repository)

### Required Python Packages
```bash
pip install requests dnspython concurrent-futures
```

### Optional External Tools (Recommended)
```bash
# Install Go (required for some tools)
# Ubuntu/Debian
sudo apt update && sudo apt install golang-go

# Install reconnaissance tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/OWASP/Amass/v3/...@latest
go install -v github.com/findomain/findomain@latest
```

### Clone Repository
```bash
git clone https://github.com/yourusername/professional-web-recon.git
cd professional-web-recon
chmod +x recon_tool.py
```

## 🚀 Usage

### Basic Usage
```bash
python3 recon_tool.py example.com
```

### Advanced Usage with Specific Dork Types
```bash
# All reconnaissance techniques
python3 recon_tool.py target-domain.com --dork-type all

# Focus on login pages
python3 recon_tool.py target-domain.com --dork-type login

# Sensitive files discovery
python3 recon_tool.py target-domain.com --dork-type files

# Admin panel discovery
python3 recon_tool.py target-domain.com --dork-type admin
```

### Technology-Specific Testing
The tool prompts for target technology selection:
1. **PHP** - WordPress, Laravel, custom PHP applications
2. **Node.js** - Express.js, custom Node applications
3. **Next.js** - React-based applications
4. **Angular** - Angular applications
5. **Django** - Python Django applications
6. **Flask** - Python Flask applications
7. **Ruby on Rails** - Ruby applications
8. **Generic** - Technology-agnostic testing

## 🔑 API Configuration

### Environment Variables Setup
Create a `.env` file or set environment variables:

```bash
export SECURITYTRAILS_API_KEY="your_securitytrails_api_key"
export SHODAN_API_KEY="your_shodan_api_key"
export GOOGLE_API_KEY="your_google_api_key"
export GOOGLE_CSE_ID="your_google_custom_search_engine_id"
```

### API Providers
- **SecurityTrails**: Advanced subdomain discovery
- **Shodan**: Host information and additional subdomains
- **Google Custom Search**: Automated dorking with official API

## 🔧 Advanced Features

### Custom Wordlists
The tool includes comprehensive wordlists for:
- **Common subdomains**: www, mail, api, admin, test, dev, staging
- **Admin paths**: /admin, /wp-admin, /administrator, /manager
- **Sensitive files**: .env, .git/config, backup files, configuration files

### Multi-threading Configuration
- **Default threads**: 20 concurrent connections
- **Timeout settings**: 10 seconds per request
- **Rate limiting**: Built-in delays to avoid blocking
- **User-Agent rotation**: Multiple browser signatures

### Vulnerability Signatures
Advanced pattern matching for:
- **SQL Injection**: MySQL, MSSQL, PostgreSQL error patterns
- **XSS vulnerabilities**: Script injection and DOM manipulation
- **File inclusion**: Path traversal and local file access
- **Debug information**: Development mode exposure
- **Credential leakage**: API keys, database credentials

## 📈 Output & Reporting

### Generated Files
- **HTML Report**: `recon_results/recon_report_domain.html`
- **Screenshots**: `recon_results/screenshots/` (if enabled)
- **Raw Data**: JSON format for further analysis

### Report Sections
1. **Executive Summary**: High-level findings and statistics
2. **Active Subdomains**: Live hosts with technology fingerprinting
3. **Sensitive Paths**: Discovered endpoints and potential vulnerabilities
4. **Google Dorks**: OSINT findings and exposed information
5. **Security Recommendations**: Actionable remediation steps

## 🏷️ SEO Keywords

**Primary Keywords**: web reconnaissance, subdomain enumeration, penetration testing, vulnerability scanner, web security assessment, bug bounty tools, OSINT tools, cybersecurity reconnaissance

**Secondary Keywords**: directory fuzzing, technology fingerprinting, Google dorking, SSL certificate analysis, web application security, ethical hacking tools, security testing automation, penetration testing framework

**Long-tail Keywords**: automated web reconnaissance tool python, professional subdomain discovery script, advanced web fuzzing framework, cybersecurity assessment automation, bug bounty reconnaissance toolkit, web application vulnerability detection

**Technical Keywords**: DNS enumeration, HTTP header analysis, XSS detection, SQL injection testing, CORS misconfiguration, certificate transparency, web scraping security, API-based reconnaissance

## ⚖️ Legal Disclaimer

### 🚨 IMPORTANT LEGAL NOTICE

**This tool is provided for educational and authorized testing purposes only.**

### Authorized Use Only
- ✅ **Authorized penetration testing** with proper written consent
- ✅ **Educational purposes** in controlled environments
- ✅ **Security research** on owned systems
- ✅ **Bug bounty programs** with explicit scope authorization
- ✅ **Cybersecurity training** and certification preparation

### Prohibited Activities
- ❌ **Unauthorized scanning** of systems you do not own
- ❌ **Malicious activities** or attacks against third parties
- ❌ **Violation of terms of service** of target applications
- ❌ **Any illegal activities** under local, state, or federal law
- ❌ **Commercial use** without proper licensing and authorization

### User Responsibilities
By using this tool, you acknowledge and agree that:

1. **You have explicit written authorization** to test the target systems
2. **You will comply with all applicable laws** and regulations
3. **You understand the ethical implications** of security testing
4. **You will not use this tool for malicious purposes**
5. **You accept full responsibility** for your actions and their consequences

### Legal Compliance
- Ensure compliance with **Computer Fraud and Abuse Act (CFAA)** in the US
- Follow **GDPR** and privacy regulations in Europe
- Respect **local cybersecurity laws** in your jurisdiction
- Obtain **proper authorization** before conducting any security testing
- Maintain **professional ethics** in cybersecurity practices

## 🎓 Educational Purpose

This tool is designed for:
- **Cybersecurity education** and skill development
- **Penetration testing certification** preparation (CEH, OSCP, CISSP)
- **University coursework** in cybersecurity and ethical hacking
- **Professional development** for security practitioners
- **Research purposes** in academic and corporate environments

### Learning Objectives
- Understanding **web application reconnaissance** methodologies
- Learning **automated security testing** techniques
- Practicing **OSINT (Open Source Intelligence)** gathering
- Developing **vulnerability assessment** skills
- Mastering **professional reporting** for security findings

## 🤝 Contributing

We welcome contributions from the cybersecurity community:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/AmazingFeature`)
3. **Commit** your changes (`git commit -m 'Add some AmazingFeature'`)
4. **Push** to the branch (`git push origin feature/AmazingFeature`)
5. **Open** a Pull Request

### Contribution Guidelines
- Follow **PEP 8** Python coding standards
- Add **comprehensive documentation** for new features
- Include **error handling** and **input validation**
- Test on **multiple target types** and environments
- Maintain **ethical standards** and **legal compliance**

## 👨‍💻 Author

**Pentester Caio | CHDEVSEC**

- **Professional Penetration Tester**
- **Cybersecurity Researcher**  
- **Web Application Security Specialist**
- **Bug Bounty Hunter**

---

### 🔗 Professional Links
- **LinkedIn**: [Connect with Caio](https://linkedin.com/in/pentester-caio)
- **GitHub**: [CHDEVSEC](https://github.com/chdevsec)
- **Blog**: [Cybersecurity Insights](https://chdevsec.blog)

---

### 📞 Contact & Support
- **Email**: contact@chdevsec.com
- **Twitter**: [@CHDEVSEC](https://twitter.com/chdevsec)
- **Telegram**: [@PentesterCaio](https://t.me/pentestercaio)

---

## 🏆 Recognition

*"Advanced reconnaissance is the foundation of effective penetration testing. This tool embodies professional-grade automation for cybersecurity professionals."*

---

**⭐ If this tool helped you in your cybersecurity journey, please consider starring the repository!**

---

*© 2024 CHDEVSEC - Professional Cybersecurity Tools. All rights reserved.*

*This project is licensed under Educational Use License - see the [LICENSE](LICENSE) file for details.*
