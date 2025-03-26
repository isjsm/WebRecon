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

BANNER = r"""
███████╗██╗   ██╗██████╗ ██╗   ██╗███╗   ██╗███████╗
██╔════╝██║   ██║██╔══██╗██║   ██║████╗  ██║██╔════╝
███████╗██║   ██║██████╔╝██║   ██║██╔██╗ ██║█████╗  
╚════██║██║   ██║██╔══██╗██║   ██║██║╚██╗██║██╔══╝  
███████║╚██████╔╝██║  ██║╚██████╔╝██║ ╚████║███████╗
╚══════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝
            Advanced Web Recon Tool v2.0
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

class WebRecon:
    def __init__(self, target, proxy=None, threads=20):
        self.target = target
        self.proxy = proxy
        self.threads = threads
        self.lock = Lock()
        self.results = {
            'ip': None,
            'whois': {},
            'original_url': None,
            'subdomains': [],
            'hidden_pages': [],
            'open_ports': [],
            'vulnerabilities': [],
            'internal_links': []
        }

    def print_status(self, message, status="info"):
        colors = {"info": "blue", "success": "green", "error": "red", "warning": "yellow"}
        print(colored(f"[{time.strftime('%H:%M:%S')}] ", 'yellow') +
              colored(f"[{status.upper()}] ", colors.get(status, 'white')) + message)

    def resolve_ip(self):
        try:
            self.results['ip'] = socket.gethostbyname(self.target)
            self.print_status(f"IP Address: {self.results['ip']}", "success")
        except Exception as e:
            self.print_status(f"IP Resolution Failed: {str(e)}", "error")

    def get_whois(self):
        try:
            self.results['whois'] = whois.whois(self.target).__dict__
            self.print_status("WHOIS Information Retrieved", "success")
        except Exception as e:
            self.print_status(f"WHOIS Lookup Failed: {str(e)}", "error")

    def check_redirect(self):
        try:
            session = self._get_session()
            response = session.get(f"http://{self.target}", allow_redirects=False, timeout=5)
            self.results['original_url'] = response.headers.get('Location', f"http://{self.target}")
            self.print_status(f"Original URL: {self.results['original_url']}", "success")
        except Exception as e:
            self.print_status(f"Redirect Check Failed: {str(e)}", "error")

    def dir_bruteforce(self, wordlist):
        def scan_dir(directory):
            url = urljoin(f"http://{self.target}", directory)
            try:
                response = self._get_session().get(url, timeout=3)
                if response.status_code == 200:
                    with self.lock:
                        self.results['hidden_pages'].append(url)
                        self.print_status(f"Hidden Page Found: {url}", "success")
            except:
                pass

        try:
            with open(wordlist, 'r') as f:
                directories = [line.strip() for line in f if line.strip()]
                self.print_status(f"Starting Directory Scan with {len(directories)} entries")
                
                for dir in directories:
                    while active_count() > self.threads:
                        time.sleep(0.1)
                    Thread(target=scan_dir, args=(dir,)).start()
        except FileNotFoundError:
            self.print_status(f"Wordlist {wordlist} Not Found", "error")

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
                        self.print_status(f"Subdomain Found: {subdomain}", "success")
            except:
                pass

        try:
            with open(wordlist, 'r') as f:
                subdomains = [line.strip() for line in f if line.strip()]
                self.print_status(f"Starting Subdomain Scan with {len(subdomains)} entries")
                
                for sub in subdomains:
                    while active_count() > self.threads:
                        time.sleep(0.1)
                    Thread(target=check_sub, args=(sub,)).start()
        except FileNotFoundError:
            self.print_status(f"Wordlist {wordlist} Not Found", "error")

    def port_scan(self, ports):
        def scan_port(port):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.results['ip'], port))
            if result == 0:
                with self.lock:
                    self.results['open_ports'].append(port)
                    self.print_status(f"Open Port Found: {port}", "success")
            sock.close()

        self.print_status(f"Starting Port Scan on {len(ports)} ports")
        for port in ports:
            while active_count() > self.threads:
                time.sleep(0.1)
            Thread(target=scan_port, args=(port,)).start()

    def vuln_scan(self):
        session = self._get_session()
        
        for severity, tests in VulnerabilityScanner.VULNERABILITIES.items():
            for name, payload, indicator in tests:
                url = urljoin(f"http://{self.target}", payload.split('?')[0])
                try:
                    response = session.get(f"http://{self.target}/{payload}", timeout=3)
                    if indicator in response.text:
                        with self.lock:
                            self.results['vulnerabilities'].append({
                                'name': name,
                                'severity': severity,
                                'url': url,
                                'payload': payload
                            })
                            self.print_status(f"[{severity.upper()}] Potential {name} Vulnerability", "success")
                except Exception as e:
                    self.print_status(f"Vuln Check Failed: {str(e)}", "error")

    def analyze_internal_links(self):
        try:
            session = self._get_session()
            response = session.get(f"http://{self.target}", timeout=5)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for link in soup.find_all('a', href=True):
                full_url = urljoin(f"http://{self.target}", link['href'])
                if self.target in full_url and full_url not in self.results['internal_links']:
                    self.results['internal_links'].append(full_url)
                    self.print_status(f"Internal Link Found: {full_url}", "success")
        except Exception as e:
            self.print_status(f"Internal Link Analysis Failed: {str(e)}", "error")

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
Original URL: {self.results['original_url']}
Open Ports: {', '.join(map(str, self.results['open_ports']))}
Subdomains Found: {len(self.results['subdomains'])}
Hidden Pages: {len(self.results['hidden_pages'])}
Vulnerabilities Detected: {len(self.results['vulnerabilities'])}

Vulnerability Details:
{'='*20}
""" + '\n'.join([
f"[{vuln['severity'].upper()}] {vuln['name']} at {vuln['url']} (Payload: {vuln['payload']})"
for vuln in self.results['vulnerabilities']
])

            with open(filename, 'w') as f:
                f.write(report)
        self.print_status(f"Full report saved to: {filename}", "success")

    def _get_session(self):
        session = requests.Session()
        if self.proxy:
            session.proxies = {'http': self.proxy, 'https': self.proxy}
        return session

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
            target = input(colored("Enter target domain (e.g., example.com): ", 'cyan'))
            proxy = input(colored("Enter proxy (http://user:pass@host:port) [optional]: ", 'cyan')) or None
            threads = int(input(colored("Enter number of threads [20]: ", 'cyan')) or 20)
            dir_wordlist = input(colored("Enter directory wordlist [common_dirs.txt]: ", 'cyan')) or "common_dirs.txt"
            sub_wordlist = input(colored("Enter subdomain wordlist [subdomains.txt]: ", 'cyan')) or "subdomains.txt"
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
