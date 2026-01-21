# <img src="assets/icons/fc12.png" width="40" style="vertical-align: middle;"> RECON PRO - Ultimate Web Reconnaissance

<div align="center">
  <!-- PLACEHOLDER FOR TOOL GIF -->
  <br>
  <img src="assets/img/tool_demo.gif" alt="Recon Pro Demo GIF (Add your GIF here)" width="100%">
  <br>
  <em>(Replace this line with your tool demonstration GIF)</em>
  <br><br>
</div>

<div align="center">

  <img src="assets/icons/fc2119.png" width="20"> **Active Development** &nbsp;&nbsp;
  <img src="assets/icons/fc2117.png" width="20"> **Python 3.x** &nbsp;&nbsp;
  <img src="assets/icons/fc2120.png" width="20"> **Linux/Kali** &nbsp;&nbsp;
  <img src="assets/icons/fc2118.png" width="20"> **MIT License**

</div>

---

## <img src="assets/icons/fc124.png" width="30" style="vertical-align: middle;"> Overview

**Recon Pro** is an advanced automated reconnaissance framework designed for **Bug Bounty Hunters** and **Pentesters**. It combines multiple open-source intelligence (OSINT) tools with custom Python scripting to deliver a comprehensive security analysis of target domains.

> <img src="assets/icons/fc950.png" width="20" style="vertical-align: middle;"> **Why Recon Pro?**  
> Unlike simple wrapper scripts, Recon Pro performs **intelligent technology detection**, **context-aware fuzzing**, and **smart vulnerability checks** (XSS, SQLi, Sensitive Files) tailored to the target's stack (Node.js, PHP, Python, etc.).

---

## <img src="assets/icons/fc5.png" width="30" style="vertical-align: middle;"> Key Features

### <img src="assets/icons/fc2.png" width="25" style="vertical-align: middle;"> 1. Automated Subdomain Discovery
*   **Multi-Source Intelligence**: Integrates powerful tools like `Subfinder`, `Assetfinder`, `Amass`, and `Findomain`.
*   **API Leverage**: Uses **Shodan**, **SecurityTrails**, and **crt.sh** for maximum coverage.
*   **Smart Fallback**: Automatically switches to brute-force DNS if passive sources yield low results.
*   **Live Classification**: Automatically categorizes subdomains into:
    *   <img src="assets/icons/fc855.png" width="15"> **Web Active** (HTTP/HTTPS)
    *   <img src="assets/icons/fc856.png" width="15"> **DNS Only**
    *   <img src="assets/icons/fc859.png" width="15"> **Filtered/Timeouts**

### <img src="assets/icons/fc913.png" width="25" style="vertical-align: middle;"> 2. Intelligent Fuzzing & Exploitation
*   **Tech-Aware Payloads**: Detects technologies (e.g., Laravel, React, Wordpress) and adjusts payloads accordingly.
*   **Vulnerability Scanner**: Checks for:
    *   Reflected XSS (Context-aware)
    *   SQL Injection (Error-based)
    *   Sensitive Files (`.env`, `.git`, backups)
    *   Admin Panels & Login Interfaces
*   **Google Dorking**: Automates search queries to find sensitive exposed data.

### <img src="assets/icons/fc15.png" width="25" style="vertical-align: middle;"> 3. Professional Reporting
*   Generates a **beautiful HTML Dashboard** for analyzing results.
*   **Interactive Summary**: view live hosts, technologies, and critical findings in a clean interface.
*   **Auto-Open**: Option to automatically open the report upon completion.

---

## <img src="assets/icons/fc6.png" width="30" style="vertical-align: middle;"> Gallery

<div align="center">
  
  <!-- Dashboard Main View -->
  <img src="assets/public/Dashboard_1.png" alt="Dashboard Overview" width="85%" style="border-radius: 6px;">
  <br><br>

  <!-- Scan Details -->
  <img src="assets/public/Dashboard_2.png" alt="Scan Details" width="85%" style="border-radius: 6px;">
  <br><br>

  <!-- Vulnerability Report -->
  <img src="assets/public/Dashboard_3.png" alt="Vulnerability Report" width="85%" style="border-radius: 6px;">
  
  <br><br>
  <em><img src="assets/icons/fc13.png" width="15"> Recon Pro HTML Dashboard Preview</em>

</div>

<br>

<div align="center">
  <!-- Placeholder for CLI if needed later -->
  <img src="assets/img/cli_output.png" alt="CLI Output Placeholder" width="85%" style="opacity: 0.5;">
  <br>
  <em><img src="assets/icons/fc13.png" width="15"> CLI Output (Run the tool to see it live!)</em>
</div>

---

## <img src="assets/icons/fc11.png" width="30" style="vertical-align: middle;"> Installation

We provide a **robust installer** (`install.sh`) that sets up your environment automatically.

### Prerequisites
*   **OS**: Linux (Kali, Ubuntu, or Debian)
*   **Python**: 3.7+
*   **Sudo Access**: Required for system packages.

### <img src="assets/icons/fc910.png" width="20" style="vertical-align: middle;"> Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/chdevsec/recon_pro.git
cd recon_pro

# 2. Give execution permissions
chmod +x install.sh

# 3. Run the installer
./install.sh
```

---

## <img src="assets/icons/fc910.png" width="30" style="vertical-align: middle;"> Usage

### Basic Scan
Simply run the python script with your target domain.

```bash
python3 recon.py target.com
```

### Interactive Mode
The tool will prompt you to select the target technology for specialized attacks:

```text
[+] Select target technology for specific tests:
  1. PHP
  2. Node.js
  3. Next.js
  4. Angular
  ...
```

---

## <img src="assets/icons/fc9.png" width="30" style="vertical-align: middle;"> Configuration

To enable **API-based** recon (Shodan, SecurityTrails, etc.), edit the `recon.py` file and add your keys:

```python
# API Configuration in recon.py
API_KEYS = {
    "SECURITYTRAILS": "YOUR_KEY_HERE", 
    "SHODAN": "YOUR_KEY_HERE", 
    "GOOGLE_API_KEY": "YOUR_KEY_HERE", 
    "GOOGLE_CSE_ID": "YOUR_CX_ID_HERE" 
}
```

---

## <img src="assets/icons/fc870.png" width="30" style="vertical-align: middle;"> Legal Disclaimer

**Recon Pro** is intended for **educational and authorized security testing purposes only**.

*   <img src="assets/icons/fc859.png" width="15"> **Do not** use this tool against systems you do not have explicit permission to test.
*   The developers (**CHDEVSEC**) assume no liability and are not responsible for any misuse or damage caused by this program.
*   Always follow responsible disclosure policies.

---

<div align="center">

  ### <img src="assets/icons/fc15.png" width="25"> Developed by [CHDEVSEC](https://github.com/chdevsec) | Pentester Caio

  <img src="assets/icons/fc2119.png" width="15"> **Happy Hacking!** <img src="assets/icons/fc2119.png" width="15">

</div>
