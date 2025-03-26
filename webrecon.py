#!/usr/bin/env python3
import argparse
import socket
import whois
import requests
from dns import resolver
from threading import Thread, Lock
from termcolor import colored
import sys
import time

BANNER = r"""
███████╗██╗   ██╗██████╗ ██╗   ██╗███╗   ██╗███████╗
██╔════╝██║   ██║██╔══██╗██║   ██║████╗  ██║██╔════╝
███████╗██║   ██║██████╔╝██║   ██║██╔██╗ ██║█████╗  
╚════██║██║   ██║██╔══██╗██║   ██║██║╚██╗██║██╔══╝  
███████║╚██████╔╝██║  ██║╚██████╔╝██║ ╚████║███████╗
╚══════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝
            Web Reconnaissance Tool v1.0
"""

class WebRecon:
    def __init__(self, target):
        self.target = target
        self.ip = None
        self.whois_info = None
        self.original_url = None
        self.hidden_pages = []
        self.subdomains = []
        self.open_ports = []
        self.vulnerabilities = []
        self.lock = Lock()

    def print_status(self, message, status="info"):
        colors = {"info": "blue", "success": "green", "error": "red"}
        print(colored(f"[{time.strftime('%H:%M:%S')}] ", 'yellow') +
              colored(f"[{status.upper()}] ", colors[status]) + message)

    def resolve_ip(self):
        try:
            self.ip = socket.gethostbyname(self.target)
            self.print_status(f"IP Address: {self.ip}", "success")
        except Exception as e:
            self.print_status(f"IP Resolution Failed: {str(e)}", "error")

    def get_whois(self):
        try:
            self.whois_info = whois.whois(self.target)
            self.print_status("WHOIS Information Retrieved", "success")
        except Exception as e:
            self.print_status(f"WHOIS Lookup Failed: {str(e)}", "error")

    def check_redirect(self):
        try:
            response = requests.get(f"http://{self.target}", allow_redirects=False, timeout=5)
            self.original_url = response.headers.get('Location', f"http://{self.target}")
            self.print_status(f"Original URL: {self.original_url}", "success")
        except Exception as e:
            self.print_status(f"Redirect Check Failed: {str(e)}", "error")

    def dir_bruteforce(self, wordlist):
        def scan_dir(directory):
            url = f"http://{self.target}/{directory}"
            try:
                response = requests.get(url, timeout=3)
                if response.status_code == 200:
                    with self.lock:
                        self.hidden_pages.append(url)
                        self.print_status(f"Hidden Page Found: {url}", "success")
            except:
                pass

        try:
            with open(wordlist, 'r') as f:
                directories = [line.strip() for line in f if line.strip()]
                self.print_status(f"Starting Directory Scan with {len(directories)} entries")
                
                threads = [Thread(target=scan_dir, args=(d,)) for d in directories]
                for t in threads: t.start()
                for t in threads: t.join()
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
                        self.subdomains.append(subdomain)
                        self.print_status(f"Subdomain Found: {subdomain}", "success")
            except:
                pass

        try:
            with open(wordlist, 'r') as f:
                subdomains = [line.strip() for line in f if line.strip()]
                self.print_status(f"Starting Subdomain Scan with {len(subdomains)} entries")
                
                threads = [Thread(target=check_sub, args=(s,)) for s in subdomains]
                for t in threads: t.start()
                for t in threads: t.join()
        except FileNotFoundError:
            self.print_status(f"Wordlist {wordlist} Not Found", "error")

    def port_scan(self, ports):
        def scan_port(port):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.ip, port))
            if result == 0:
                with self.lock:
                    self.open_ports.append(port)
                    self.print_status(f"Open Port Found: {port}", "success")
            sock.close()

        self.print_status(f"Starting Port Scan on {len(ports)} ports")
        threads = [Thread(target=scan_port, args=(p,)) for p in ports]
        for t in threads: t.start()
        for t in threads: t.join()

    def vuln_scan(self):
        tests = [
            ("SQL Injection", "page?id=1' OR '1'='1", "error"),
            ("XSS", "search?query=<script>alert('xss')</script>", "<script>alert('xss')")
        ]
        
        for name, payload, indicator in tests:
            url = f"http://{self.target}/{payload.split('?')[0]}"
            try:
                response = requests.get(f"http://{self.target}/{payload}", timeout=3)
                if indicator in response.text:
                    with self.lock:
                        self.vulnerabilities.append(name)
                        self.print_status(f"Potential {name} Vulnerability", "success")
            except:
                continue

    def generate_report(self):
        report = f"""
        Scan Report for {self.target}
        ==============================
        IP Address: {self.ip}
        Original URL: {self.original_url}
        Open Ports: {', '.join(map(str, self.open_ports))}
        Subdomains Found: {len(self.subdomains)}
        Hidden Pages: {len(self.hidden_pages)}
        Vulnerabilities Detected: {', '.join(self.vulnerabilities) or 'None'}

        Detailed Results:
        ----------------
        WHOIS Information:
        {self.whois_info}
        
        Hidden Pages:
        {chr(10).join(self.hidden_pages) if self.hidden_pages else 'None'}
        
        Subdomains:
        {chr(10).join(self.subdomains) if self.subdomains else 'None'}
        """
        
        filename = f"webrecon_report_{self.target}_{int(time.time())}.txt"
        with open(filename, 'w') as f:
            f.write(report)
        self.print_status(f"Full report saved to: {filename}", "success")

def main():
    print(colored(BANNER, 'cyan'))
    
    parser = argparse.ArgumentParser(description="WebRecon - Website Reconnaissance Tool")
    parser.add_argument("target", help="Target domain (e.g., example.com)")
    parser.add_argument("-d", "--dir", help="Directory wordlist", default="common_dirs.txt")
    parser.add_argument("-s", "--sub", help="Subdomain wordlist", default="subdomains.txt")
    parser.add_argument("-p", "--ports", help="Ports to scan (comma-separated)", default="80,443,22,21,3306")
    args = parser.parse_args()

    scanner = WebRecon(args.target)
    
    scanner.print_status("Starting full reconnaissance scan")
    scanner.resolve_ip()
    scanner.get_whois()
    scanner.check_redirect()
    scanner.dir_bruteforce(args.dir)
    scanner.subdomain_enum(args.sub)
    scanner.port_scan([int(p) for p in args.ports.split(',')])
    scanner.vuln_scan()
    scanner.generate_report()
    scanner.print_status("Scan completed successfully", "success")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(colored("[!] Scan interrupted by user", "yellow"))
        sys.exit(1)
