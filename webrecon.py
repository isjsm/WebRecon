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

init(autoreset=True)

BANNER = f"""
{Fore.RED} ______   {Fore.GREEN} _____     {Fore.BLUE} _____ 
{Fore.RED}|  ____| {Fore.GREEN}|  __ \    {Fore.BLUE}/ ____|
{Fore.RED}| |__    {Fore.GREEN}| |__) |   {Fore.BLUE}( (___  
{Fore.RED}|  __|   {Fore.GREEN}|  _  /     {Fore.BLUE}\___ \ 
{Fore.RED}| |____ {Fore.GREEN}| | \ \ _  {Fore.BLUE}____) |
{Fore.RED}|______|{Fore.GREEN}|_|  \_(_) {Fore.BLUE}|_____/ 
"""

class WebRecon:
    def __init__(self, target):
        self.target = target
        self.results = {}
        
    def check_http_headers(self):
        try:
            response = requests.get(self.target, timeout=10)
            headers = response.headers
            print(f"{Fore.CYAN}[+] HTTP Headers:")
            for key, value in headers.items():
                print(f"    {Fore.YELLOW}{key}: {Fore.WHITE}{value}")
            self.results['headers'] = headers
        except Exception as e:
            print(f"{Fore.RED}[-] Error checking headers: {e}")

    def dns_lookup(self):
        try:
            print(f"\n{Fore.CYAN}[+] Performing DNS lookup...")
            res = dns.resolver.Resolver()
            res.nameservers = ['8.8.8.8', '1.1.1.1']
            
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
            dns_results = {}
            
            for rtype in record_types:
                try:
                    answers = res.resolve(self.target, rtype)
                    dns_results[rtype] = [str(rdata) for rdata in answers]
                except Exception:
                    dns_results[rtype] = []
            
            for rtype, records in dns_results.items():
                if records:
                    print(f"    {Fore.YELLOW}{rtype} Records:")
                    for rec in records:
                        print(f"        {Fore.WHITE}{rec}")
            self.results['dns'] = dns_results
        except Exception as e:
            print(f"{Fore.RED}[-] DNS Lookup Error: {e}")

    def check_ssl_tls(self):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.target, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()
                    print(f"\n{Fore.CYAN}[+] SSL/TLS Certificate Info:")
                    print(f"    {Fore.YELLOW}Issuer: {Fore.WHITE}{cert['issuer'][0][0][1]}")
                    print(f"    {Fore.YELLOW}Valid From: {Fore.WHITE}{cert['notBefore']}")
                    print(f"    {Fore.YELLOW}Valid Until: {Fore.WHITE}{cert['notAfter']}")
                    print(f"    {Fore.YELLOW}Subject: {Fore.WHITE}{cert['subject'][0][0][1]}")
                    self.results['ssl'] = cert
        except Exception as e:
            print(f"{Fore.RED}[-] SSL Check Error: {e}")

    def detect_cms(self):
        try:
            response = requests.get(self.target, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Check meta tags
            generator = soup.find("meta", attrs={'name': 'generator'})
            if generator:
                print(f"\n{Fore.CYAN}[+] CMS Detection:")
                print(f"    {Fore.YELLOW}Possible CMS: {Fore.WHITE}{generator['content']}")
                self.results['cms'] = generator['content']
                return
            
            # Check common CMS paths
            cms_paths = ['/wp-content/', '/wp-login.php', '/administrator/']
            for path in cms_paths:
                test_url = self.target + path
                resp = requests.get(test_url, timeout=5)
                if resp.status_code == 200:
                    print(f"\n{Fore.CYAN}[+] CMS Detection:")
                    print(f"    {Fore.YELLOW}Possible CMS: {Fore.WHITE}WordPress" if 'wp-' in path else "")
                    self.results['cms'] = "WordPress" if 'wp-' in path else "Joomla"
                    return
        except Exception as e:
            print(f"{Fore.RED}[-] CMS Detection Error: {e}")

def main():
    print(BANNER)
    parser = ArgumentParser(description="WebRecon - Advanced Web Reconnaissance Tool")
    parser.add_argument("-u", "--url", required=True, help="Target URL (e.g., https://example.com)")
    parser.add_argument("--headers", action="store_true", help="Check HTTP Headers")
    parser.add_argument("--dns", action="store_true", help="Perform DNS Lookup")
    parser.add_argument("--ssl", action="store_true", help="Check SSL/TLS Certificate")
    parser.add_argument("--cms", action="store_true", help="Detect CMS")
    parser.add_argument("--full", action="store_true", help="Run Full Scan")

    args = parser.parse_args()

    target = args.url
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target

    scanner = WebRecon(target)

    try:
        if args.full:
            scanner.check_http_headers()
            scanner.dns_lookup()
            scanner.check_ssl_tls()
            scanner.detect_cms()
        else:
            if args.headers:
                scanner.check_http_headers()
            if args.dns:
                scanner.dns_lookup()
            if args.ssl:
                scanner.check_ssl_tls()
            if args.cms:
                scanner.detect_cms()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[-] Scan interrupted by user")
        sys.exit(1)

if __name__ == "__main__":
    main()
