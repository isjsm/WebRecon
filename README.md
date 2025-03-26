# # WebRecon - Advanced Web Reconnaissance Tool [![License](https://img.shields.io/badge/License-MIT-green)](LICENSE) [![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue)](https://www.python.org/)

<p align="center">
  <img src="https://i.imgur.com/9X6QbDd.png" width="600"/>
</p>

**WebRecon** is a powerful web reconnaissance tool designed for ethical hackers and security professionals. It combines multiple scanning techniques to gather comprehensive information about web targets while maintaining a professional workflow.

---

## Features 🚀

✅ **Core Capabilities**:
- **HTTP Header Analysis**: Extract security headers and server information
- **DNS Enumeration**: Retrieve A, AAAA, MX, NS, TXT, and CNAME records
- **SSL/TLS Inspection**: Validate certificate details and expiration
- **CMS Detection**: Identify WordPress, Joomla, and other CMS platforms

✅ **Advanced Scanning**:
- **Vulnerability Detection**: 
  - XSS payload testing with severity classification (Critical/Medium/Low)
  - SQLi vulnerability checks with error-based detection
- **Directory Bruteforce**: Multithreaded scanning with custom wordlists
- **Internal Link Analysis**: Check status codes and content size

✅ **Professional Features**:
- **Proxy Support**: Route traffic through Burp Suite or other proxies
- **Multithreading**: Adjustable thread count for directory scans
- **Reporting**: Export results to JSON/TXT with vulnerability ratings
- **Color-Coded Output**: Clear visual hierarchy for scan results

---

## Installation 💻

**Requirements**:
- Python 3.8+
- Linux/Unix environment (Tested on Kali Linux)

```bash
# Install dependencies
pip3 install -r requirements.txt

# Make executable
chmod +x webrecon.py

** Usage 🛠️**

Basic Scans  :

# Full scan with default settings
python3 webrecon.py -u https://example.com --full

# Check HTTP headers only
python3 webrecon.py -u https://example.com --headers

Advanced Scans  :

# Vulnerability scan with proxy
python3 webrecon.py -u https://example.com --vuln-scan --proxy http://127.0.0.1:8080

# Directory scan with 50 threads
python3 webrecon.py -u https://example.com --dir-scan /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --threads 50

# Export results to JSON
python3 webrecon.py -u https://example.com --full --output json

**Output Example**

[+] Vulnerability Report:
+-------+----------+-----------------------------+--------------------------------+
| Type  | Severity |             URL             |            Payload             |
+-------+----------+-----------------------------+--------------------------------+
| XSS   | Critical | https://example.com/test     | <script>alert('XSS')</script>  |
| SQLi  | Critical | https://example.com/?id=1    | ' OR 1=1--                     |
+-------+----------+-----------------------------+--------------------------------+
