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
import subprocess

BANNER = r"""
███████╗██╗   ██╗██████╗ ██╗   ██╗███╗   ██╗███████╗
██╔════╝██║   ██║██╔══██╗██║   ██║████╗  ██║██╔════╝
███████╗██║   ██║██████╔╝██║   ██║██╔██╗ ██║█████╗  
╚════██║██║   ██║██╔══██╗██║   ██║██║╚██╗██║██╔══╝  
███████║╚██████╔╝██║  ██║╚██████╔╝██║ ╚████║███████╗
╚══════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝
            Advanced Web Recon Tool v4.0
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
            'internal_links': [],
            'admin_pages': []  # إضافة قائمة صفحات الإدارة
        }

    def is_valid_domain(self, domain):
        """التحقق من صحة النطاق باستخدام تعبير منتظم"""
        regex = r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
        return re.match(regex, domain) is not None

    def _load_yara_rules(self):
        try:
            config = self.load_config()
            rules_file = config.get('yara_rules', 'config/rules.yar')
            if os.path.exists(rules_file):
                return yara.compile(filepath=rules_file)
            else:
                print(colored(f"[!] Using default YARA rules (Missing: {rules_file})", "yellow"))
                return yara.compile(source=VulnerabilityScanner.YARA_RULES)
        except Exception as e:
            print(colored(f"[!] YARA Rules Failed: {str(e)}", "red"))
            return None

    def load_config(self):
        try:
            with open(self.config_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(colored(f"[!] Config Load Failed: {str(e)}", "yellow"))
            return {}

    def resolve_ip(self):
        try:
            self.results['ip'] = socket.gethostbyname(self.target)
            print(colored(f"[+] IP Address: {self.results['ip']}", "green"))
        except Exception as e:
            print(colored(f"[!] IP Resolution Failed: {str(e)}", "red"))

    def get_whois(self):
        try:
            self.results['whois'] = whois.whois(self.target).__dict__
            print(colored("[+] WHOIS Information Retrieved", "green"))
        except Exception as e:
            print(colored(f"[!] WHOIS Lookup Failed: {str(e)}", "red"))

    def check_redirect(self):
        session = self._get_session()
        try:
            response = session.get(f"https://{self.target}", allow_redirects=False, timeout=10)
            self.results['original_url'] = response.headers.get('Location', f"https://{self.target}")
            print(colored(f"[+] Original URL: {self.results['original_url']}", "green"))
        except Exception as e:
            print(colored(f"[!] Redirect Check Failed: {str(e)}", "red"))

    def dir_bruteforce(self, wordlist):
        def scan_dir(directory):
            url = urljoin(f"https://{self.target}", directory)
            try:
                response = session.get(url, timeout=5)
                if response.status_code == 200:
                    with self.lock:
                        self.results['hidden_pages'].append(url)
                        print(colored(f"[+] Hidden Page Found: {url}", "green"))
            except:
                pass

        session = self._get_session()
        try:
            with open(wordlist, 'r') as f:
                directories = [line.strip() for line in f if line.strip()]
                print(colored(f"[+] Starting Directory Scan with {len(directories)} entries", "cyan"))
                
                for dir in directories:
                    while active_count() > self.threads:
                        time.sleep(0.1)
                    Thread(target=scan_dir, args=(dir,)).start()
        except FileNotFoundError:
            print(colored(f"[!] Wordlist {wordlist} Not Found", "red"))

    def subdomain_enum(self, wordlist):
        dns_resolver = resolver.Resolver()
        dns_resolver.timeout = 1
        dns_resolver.lifetime = 1

        def check_sub(sub):
            try:
                subdomain = f"{sub}.{self.target}"
                answers = dns_resolver.resolve(subdomain, 'A')
                if answers:
                    with self.lock:
                        self.results['subdomains'].append(subdomain)
                        print(colored(f"[+] Subdomain Found: {subdomain}", "green"))
            except:
                pass

        try:
            with open(wordlist, 'r') as f:
                subdomains = [line.strip() for line in f if line.strip()]
                print(colored(f"[+] Starting Subdomain Scan with {len(subdomains)} entries", "cyan"))
                
                for sub in subdomains:
                    while active_count() > self.threads:
                        time.sleep(0.1)
                    Thread(target=check_sub, args=(sub,)).start()
        except FileNotFoundError:
            print(colored(f"[!] Wordlist {wordlist} Not Found", "red"))

    def port_scan(self, ports):
        if not self.results['ip']:
            print(colored("[!] IP Address not resolved. Skipping port scan.", "yellow"))
            return
        def scan_port(port):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.results['ip'], port))
            if result == 0:
                with self.lock:
                    self.results['open_ports'].append(port)
                    print(colored(f"[+] Open Port Found: {port}", "green"))
            sock.close()

        print(colored(f"[+] Starting Port Scan on {len(ports)} ports", "cyan"))
        for port in ports:
            while active_count() > self.threads:
                time.sleep(0.1)
            Thread(target=scan_port, args=(port,)).start()

    def find_admin_pages(self, admin_wordlist):
        def check_admin_page(path):
            url = urljoin(f"https://{self.target}", path)
            try:
                response = session.get(url, timeout=5)
                if response.status_code == 200 and "login" in response.text.lower():
                    with self.lock:
                        self.results['admin_pages'].append(url)
                        print(colored(f"[+] Admin Page Found: {url}", "green"))
            except:
                pass

        session = self._get_session()
        try:
            with open(admin_wordlist, 'r') as f:
                paths = [line.strip() for line in f if line.strip()]
                print(colored(f"[+] Starting Admin Page Scan with {len(paths)} entries", "cyan"))
                
                for path in paths:
                    while active_count() > self.threads:
                        time.sleep(0.1)
                    Thread(target=check_admin_page, args=(path,)).start()
        except FileNotFoundError:
            print(colored(f"[!] Admin Wordlist {admin_wordlist} Not Found", "red"))

    def vuln_scan(self):
        session = self._get_session()
        
        for severity, tests in VulnerabilityScanner.VULNERABILITIES.items():
            for name, payload, indicator in tests:
                url = urljoin(f"https://{self.target}", payload.split('?')[0])
                try:
                    response = session.get(f"https://{self.target}/{payload}", timeout=5)
                    if indicator in response.text:
                        with self.lock:
                            self.results['vulnerabilities'].append({
                                'name': name,
                                'severity': severity,
                                'url': url,
                                'payload': payload
                            })
                            print(colored(f"[+] [{severity.upper()}] Potential {name} Vulnerability", "yellow"))
                except Exception as e:
                    print(colored(f"[!] Vuln Check Failed: {str(e)}", "red"))

    def analyze_internal_links(self):
        session = self._get_session()
        try:
            response = session.get(f"https://{self.target}", timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for link in soup.find_all('a', href=True):
                full_url = urljoin(f"https://{self.target}", link['href'])
                if self.target in full_url and full_url not in self.results['internal_links']:
                    self.results['internal_links'].append(full_url)
                    print(colored(f"[+] Internal Link Found: {full_url}", "cyan"))
        except Exception as e:
            print(colored(f"[!] Internal Link Analysis Failed: {str(e)}", "red"))

    def generate_report(self, format='txt'):
        filename = f"webrecon_report_{self.target}_{int(time.time())}.{format}"
        if format == 'json':
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=4)
        else:
            report = f"""
Scan Report for {self.target}
==============================
IP Address: {self.results['ip']}
Open Ports: {', '.join(map(str, self.results['open_ports']))}
Subdomains Found: {len(self.results['subdomains'])}
Hidden Pages: {len(self.results['hidden_pages'])}
Admin Pages: {len(self.results['admin_pages'])}
Vulnerabilities Detected: {len(self.results['vulnerabilities'])}

Vulnerability Details:
{'='*20}
""" + '\n'.join([
f"[{vuln['severity'].upper()}] {vuln['name']} at {vuln['url']} (Payload: {vuln['payload']})"
for vuln in
