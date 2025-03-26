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
            'admin_pages': []
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

    def _get_session(self):
        session = requests.Session()
        if self.proxy:
            session.proxies = {
                'http': self.proxy,
                'https': self.proxy
            }
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        return session

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
                response = session.get(url, timeout=5, allow_redirects=False, stream=False)
                if response.status_code == 200:
                    with self.lock:
                        self.results['hidden_pages'].append(url)
                        print(colored(f"[+] Hidden Page Found: {url}", "green"))
            except requests.RequestException:
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
            except (resolver.NoAnswer, resolver.NXDOMAIN, resolver.Timeout):
                pass
            except Exception as e:
                print(colored(f"[!] DNS Error: {str(e)}", "red"))

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
            try:
                result = sock.connect_ex((self.results['ip'], port))
                if result == 0:
                    with self.lock:
                        self.results['open_ports'].append(port)
                        print(colored(f"[+] Open Port Found: {port}", "green"))
            finally:
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
                response = session.get(url, timeout=5, allow_redirects=False)
                if response.status_code == 200 and "login" in response.text.lower():
                    with self.lock:
                        self.results['admin_pages'].append(url)
                        print(colored(f"[+] Admin Page Found: {url}", "green"))
            except requests.RequestException:
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
            print(colored(f"[!] Wordlist {admin_wordlist} Not Found", "red"))

    def scan_vulnerabilities(self):
        for severity, checks in VulnerabilityScanner.VULNERABILITIES.items():
            for name, payload, pattern in checks:
                url = f"https://{self.target}/{payload}"
                try:
                    response = requests.get(url, timeout=5)
                    if pattern in response.text:
                        with self.lock:
                            self.results['vulnerabilities'].append({
                                'severity': severity,
                                'name': name,
                                'url': url
                            })
                            print(colored(f"[!] {severity.upper()} Vulnerability Found: {name} at {url}", "red"))
                except requests.RequestException:
                    continue

    def scan_malware(self):
        if not self.rules:
            return

        def scan_content(content, url):
            matches = self.rules.match(data=content)
            if matches:
                for match in matches:
                    with self.lock:
                        self.results['malware_alerts'].append({
                            'url': url,
                            'rule': match.rule,
                            'description': match.meta.get('description', 'No description')
                        })
                        print(colored(f"[!] Malware Detected: {match.rule} at {url}", "red"))

        session = self._get_session()
        try:
            response = session.get(f"https://{self.target}", timeout=10)
            scan_content(response.text, f"https://{self.target}")
        except Exception as e:
            print(colored(f"[!] Malware Scan Failed: {str(e)}", "red"))

    def run_all_scans(self, wordlist_dir, wordlist_sub, wordlist_admin, ports):
        self.resolve_ip()
        self.get_whois()
        self.check_redirect()
        self.dir_bruteforce(wordlist_dir)
        self.subdomain_enum(wordlist_sub)
        self.port_scan(ports)
        self.find_admin_pages(wordlist_admin)
        self.scan_vulnerabilities()
        self.scan_malware()

if __name__ == "__main__":
    print(colored(BANNER, "cyan"))
    parser = argparse.ArgumentParser(description="Advanced Web Recon Tool v4.0")
    parser.add_argument("target", help="Target domain (e.g., example.com)")
    parser.add_argument("--proxy", help="Proxy (e.g., http://127.0.0.1:8080)", default=None)
    parser.add_argument("--threads", type=int, default=20, help="Number of threads (default: 20)")
    parser.add_argument("--wordlist-dir", default="wordlists/directories.txt", help="Directory wordlist")
    parser.add_argument("--wordlist-sub", default="wordlists/subdomains.txt", help="Subdomain wordlist")
    parser.add_argument("--wordlist-admin", default="wordlists/admin_paths.txt", help="Admin paths wordlist")
    parser.add_argument("--ports", nargs="+", type=int, default=[80, 443, 21, 22, 3306], help="Ports to scan")
    args = parser.parse_args()

    if not WebRecon(args.target).is_valid_domain(args.target):
        print(colored("[!] Invalid domain format", "red"))
        sys.exit(1)

    scanner = WebRecon(
        target=args.target,
        proxy=args.proxy,
        threads=args.threads
    )

    scanner.run_all_scans(
        wordlist_dir=args.wordlist_dir,
        wordlist_sub=args.wordlist_sub,
        wordlist_admin=args.wordlist_admin,
        ports=args.ports
    )

    print(colored("\n[+] Scan Completed. Results:", "cyan"))
    print(json.dumps(scanner.results, indent=4))
