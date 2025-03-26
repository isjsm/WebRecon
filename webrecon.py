#!/usr/bin/env python3
import argparse
import socket
import whois
import requests
from dns import resolver
from threading import Thread, Lock, active_count
from termcolor import colored
import sys
import time
import json
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import re
import yara
import os

BANNER = r"""
███████╗██╗   ██╗██████╗ ██╗   ██╗███╗   ██╗███████╗
██╔════╝██║   ██║██╔══██╗██║   ██║████╗  ██║██╔════╝
███████╗██║   ██║██████╔╝██║   ██║██╔██╗ ██║█████╗  
╚════██║██║   ██║██╔══██╗██║   ██║██║╚██╗██║██╔══╝  
███████║╚██████╔╝██║  ██║╚██████╔╝██║ ╚████║███████╗
╚══════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝
            Advanced Web Recon Tool v3.1
"""

class VulnerabilityScanner:
    VULNERABILITIES = {
        'critical': [
            ("SQL Injection", "page?id=1' OR '1'='1", "error"),
            ("Remote Code Execution", "cmd=;whoami", "whoami")
        ],
        'medium': [
            ("XSS", "search?query=<script>alert('xss')</script>", "<script>alert('xss')"),
            ("Open Redirect", "redirect?url=javascript:alert('xss')", "javascript:")
        ],
        'low': [
            ("Sensitive File Exposure", "../etc/passwd", "root:x:0:0"),
            ("Backup File Exposure", ".bak", "DOCTYPE")
        ]
    }

    YARA_RULES = """
    rule php_webshell {
        meta:
            description = "Detect common PHP webshells"
        strings:
            $c99 = "<?php @eval($_POST['cmd']); ?>"
            $r57 = "eval(base64_decode("
            $filesman = "FilesMan"
            $weevely = "eval(base64_decode(str_replace("
        condition:
            any of them
    }

    rule js_malware {
        meta:
            description = "Detect JS obfuscation patterns"
        strings:
            $obfuscated = "document.write(unescape('"
            $eval = "eval(function(p,a,c,k,e,d)"
        condition:
            any of them
    }

    rule suspicious_functions {
        meta:
            description = "Detect dangerous PHP functions"
        strings:
            $eval = "eval("
            $exec = "exec("
            $system = "system("
            $base64 = "base64_decode("
            $gzinflate = "gzinflate("
            $passthru = "passthru("
            $shell_exec = "shell_exec("
        condition:
            3 of them
    }
    """

class WebRecon:
    def __init__(self, target, proxy=None, threads=20, config_file="config/config.json"):
        self.target = target
        self.proxy = proxy
        self.threads = threads
        self.lock = Lock()
        self.config_file = config_file
        self.rules = self._load_yara_rules()
        self.results = {
            'ip': None,
            'server_info': {},
            'whois': {},
            'original_url': None,
            'subdomains': [],
            'hidden_pages': [],
            'open_ports': [],
            'vulnerabilities': [],
            'malicious_texts': [],
            'malware_alerts': [],
            'internal_links': []
        }

    def _load_yara_rules(self):
        try:
            config = self.load_config()
            rules_file = config.get('yara_rules', 'config/rules.yar')
            if os.path.exists(rules_file):
                return yara.compile(filepath=rules_file)
            else:
                self.print_status(f"Using default YARA rules (Missing: {rules_file})", "warning")
                return yara.compile(source=VulnerabilityScanner.YARA_RULES)
        except Exception as e:
            self.print_status(f"YARA Rules Failed: {str(e)}", "error")
            return None

    def print_status(self, message, status="info"):
        colors = {"info": "blue", "success": "green", "error": "red", "warning": "yellow"}
        print(colored(f"[{time.strftime('%H:%M:%S')}] ", 'yellow') +
              colored(f"[{status.upper()}] ", colors.get(status, 'white')) + message)

    def load_config(self):
        try:
            with open(self.config_file, 'r') as f:
                return json.load(f)
        except:
            return {}

    def analyze_server(self):
        if not self.results['ip']:
            return
        try:
            response = self._get_session().get(f"https://{self.target}", timeout=5)
            self.results['server_info'] = {
                'server': response.headers.get('Server', 'Unknown'),
                'ip': self.results['ip'],
                'status_code': response.status_code,
                'content_type': response.headers.get('Content-Type', 'Unknown'),
                'headers': dict(response.headers)
            }
            self.print_status(f"Server: {self.results['server_info']['server']}", "success")
        except Exception as e:
            self.print_status(f"Server Analysis Failed: {str(e)}", "error")

    def detect_malicious_texts(self):
        patterns = [
            (r'\b(eval|exec|system|passthru|shell_exec)\(', 'Critical: Dangerous PHP function'),
            (r'base64_decode\s*\(', 'Warning: Base64 decoding'),
            (r'(union\s+select|group\s+by|\bdrop\s+table)\b', 'Critical: SQL Injection pattern'),
            (r'(<script>|javascript:|onerror=)', 'Medium: XSS vector'),
            (r'\b(password|api_key)\s*=\s*[\'"][^\'"]+[\'"]', 'Critical: Exposed credentials')
        ]
        
        session = self._get_session()
        for url in self.results['hidden_pages'] + [f"https://{self.target}"]:
            try:
                response = session.get(url, timeout=5)
                for pattern, desc in patterns:
                    matches = re.findall(pattern, response.text, re.IGNORECASE)
                    if matches:
                        self.results['malicious_texts'].append({
                            'url': url,
                            'description': desc,
                            'sample': matches[0] if matches else 'N/A'
                        })
                        self.print_status(f"Malicious Pattern [{desc}] in {url}", "critical")
            except Exception as e:
                self.print_status(f"Text Analysis Failed: {str(e)}", "error")

    def scan_malware(self):
        if not self.rules:
            return
        for url in self.results['hidden_pages']:
            try:
                response = self._get_session().get(url, timeout=5)
                matches = self.rules.match(data=response.content)
                if matches:
                    self.results['malware_alerts'].append({
                        'url': url,
                        'rules_triggered': [rule.rule for rule in matches]
                    })
                    self.print_status(f"Malware Detected: {url} ({', '.join([rule.rule for rule in matches])})", "critical")
            except Exception as e:
                self.print_status(f"Malware Scan Failed: {str(e)}", "error")

    def generate_report(self, format='txt'):
        filename = f"webrecon_report_{self.target}_{int(time.time())}.{format}"
        if format == 'json':
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=4)
        else:
            report = f"""
Scan Report for {self.target}
==============================
Server Information:
- Type: {self.results['server_info'].get('server', 'Unknown')}
- IP: {self.results['server_info'].get('ip', 'N/A')}
- Status Code: {self.results['server_info'].get('status_code', 'N/A')}
- Content Type: {self.results['server_info'].get('content_type', 'N/A')}

Malware Analysis:
{'='*20}
""" + '\n'.join([
f"[!] URL: {alert['url']}\n    Rules Triggered: {alert['rules_triggered']}"
for alert in self.results['malware_alerts']
]) + "\n\nMalicious Texts:\n" + '\n'.join([
f"[!] {text['description']} in {text['url']}\n    Sample: {text['sample']}"
for text in self.results['malicious_texts']
])

            with open(filename, 'w') as f:
                f.write(report)
        self.print_status(f"Full report saved to: {filename}", "success")

    def _get_session(self):
        session = requests.Session()
        session.verify = False
        if self.proxy:
            session.proxies = {'http': self.proxy, 'https': self.proxy}
        return session

    # ... (بقية الدوال من الإصدار السابق)

def show_menu():
    print(colored(BANNER, 'cyan'))
    print(colored("[01] Start Scan", 'green'))
    print(colored("[99] Exit", 'red'))
    choice = input(colored(">> ", 'yellow'))
    return choice

def main():
    while True:
        choice = show_menu()
        if choice == '99':
            sys.exit(0)
        elif choice == '01':
            target = input(colored("Enter target domain (e.g., example.com): ", 'cyan')).strip()
            if not WebRecon(target).is_valid_domain(target):
                print(colored("[!] Invalid domain format", "red"))
                continue
            proxy = input(colored("Enter proxy (http://user:pass@host:port) [optional]: ", 'cyan')) or None
            threads = int(input(colored("Enter number of threads [20]: ", 'cyan')) or 20)
            dir_wordlist = input(colored("Enter directory wordlist [/usr/share/dirb/wordlists/common.txt]: ", 'cyan')) or "/usr/share/dirb/wordlists/common.txt"
            sub_wordlist = input(colored("Enter subdomain wordlist [/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt]: ", 'cyan')) or "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt"
            ports = list(map(int, input(colored("Enter ports to scan (comma-separated) [80,443]: ", 'cyan')).split(',') or [80,443]))
            
            scanner = WebRecon(target, proxy=proxy, threads=threads)
            
            scanner.print_status("Starting full reconnaissance scan")
            scanner.resolve_ip()
            scanner.get_whois()
            scanner.check_redirect()
            scanner.dir_bruteforce(dir_wordlist)
            scanner.subdomain_enum(sub_wordlist)
            scanner.port_scan(ports)
            scanner.vuln_scan()
            scanner.analyze_internal_links()
            scanner.analyze_server()
            scanner.detect_malicious_texts()
            scanner.scan_malware()
            
            format = input(colored("Choose report format [txt/json]: ", 'cyan')).lower()
            scanner.generate_report(format)
            scanner.print_status("Scan completed successfully", "success")
        else:
            print(colored("[!] Invalid choice", "yellow"))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(colored("[!] Scan interrupted by user", "yellow"))
        sys.exit(1)
