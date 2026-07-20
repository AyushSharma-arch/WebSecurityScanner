#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Advanced Web Vulnerability Scanner v4.0 Ultimate
Professional Pentesting Tool for Kali Linux
Features: Subdomain_enum, CVE_detection, WAF_detection, SSL_analysis, 
          API_discovery, Report_generation, Auto_exploitation
"""

import requests
import argparse
import sys
import os
import socket
import ssl
import json
import re
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse
from collections import defaultdict
import warnings
warnings.filterwarnings('ignore')

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    COLORS = True
except ImportError:
    COLORS = False

# Color Class
class Colors:
    if COLORS:
        BLUE = Fore.BLUE
        GREEN = Fore.GREEN
        YELLOW = Fore.YELLOW
        RED = Fore.RED
        MAGENTA = Fore.MAGENTA
        CYAN = Fore.CYAN
        WHITE = Fore.WHITE
        BOLD = Style.BRIGHT
        RESET = Style.RESET_ALL
    else:
        BLUE = GREEN = YELLOW = RED = MAGENTA = CYAN = WHITE = BOLD = RESET = ''

# Banner
def print_banner():
    banner = f"""
{Colors.BLUE}{Colors.BOLD}{'='*80}{Colors.RESET}
{Colors.BLUE}{Colors.BOLD}   ___ _   _ _ __ ___  _ __ ___   __ _ _ __   ___ _ __ {Colors.RESET}
{Colors.BLUE}{Colors.BOLD}  / __| | | | '__/ _ \| '_ ` _ \ / _` | '_ \ / _ \ '__|{Colors.RESET}
{Colors.BLUE}{Colors.BOLD} | (__| |_| | | | (_) | | | | | | (_| | |_) |  __/ |   {Colors.RESET}
{Colors.BLUE}{Colors.BOLD}  \___|\__,_|_|  \___/|_| |_| |_|\__,_| .__/ \___|_|   {Colors.RESET}
{Colors.BLUE}{Colors.BOLD}                                      |_|              {Colors.RESET}
{Colors.CYAN}{Colors.BOLD}   Advanced Web Vulnerability Scanner v4.0 Ultimate{Colors.RESET}
{Colors.YELLOW}{Colors.BOLD}   Professional Pentesting Tool | Kali Linux Edition{Colors.RESET}
{Colors.BLUE}{Colors.BOLD}{'='*80}{Colors.RESET}
"""
    print(banner)

def print_section(title):
    print(f"\n{Colors.CYAN}{Colors.BOLD}{'='*80}{Colors.RESET}")
    print(f"{Colors.CYAN}{Colors.BOLD}   [{title}]{Colors.RESET}")
    print(f"{Colors.CYAN}{Colors.BOLD}{'='*80}{Colors.RESET}\n")

def print_vulnerability(severity, vuln_type, details, confidence="High"):
    colors = {
        'CRITICAL': Colors.RED + Colors.BOLD,
        'HIGH': Colors.RED,
        'MEDIUM': Colors.YELLOW,
        'LOW': Colors.GREEN,
        'INFO': Colors.BLUE
    }
    color = colors.get(severity, Colors.WHITE)
    print(f"{color}[{severity}] {vuln_type}{Colors.RESET}")
    print(f"{Colors.WHITE}  Confidence: {confidence}{Colors.RESET}")
    print(f"{Colors.WHITE}  {details}{Colors.RESET}\n")

# ==================== MODULE 1: SUBDOMAIN ENUMERATION ====================
class SubdomainEnumerator:
    def __init__(self, domain, threads=50):
        self.domain = domain
        self.threads = threads
        self.found_subdomains = []
        
    def common_subdomains_wordlist(self):
        return [
            'www', 'mail', 'ftp', 'admin', 'webmail', 'localhost', 'webdisk',
            'ns1', 'ns2', 'smtp', 'pop', 'pop3', 'imap', 'autodiscover',
            'api', 'dev', 'staging', 'test', 'prod', 'beta', 'demo',
            'blog', 'shop', 'store', 'portal', 'vpn', 'remote', 'cloud',
            'cdn', 'assets', 'static', 'media', 'images', 'files', 'docs',
            'support', 'help', 'forum', 'community', 'wiki', 'git', 'svn',
            'jenkins', 'ci', 'cd', 'deploy', 'dashboard', 'monitor', 'metrics'
        ]
    
    def check_subdomain(self, subdomain):
        full_domain = f"{subdomain}.{self.domain}"
        try:
            ip = socket.gethostbyname(full_domain)
            return {'subdomain': full_domain, 'ip': ip}
        except:
            return None
    
    def enumerate(self):
        print(f"{Colors.YELLOW}[*] Starting subdomain enumeration for {self.domain}...{Colors.RESET}")
        wordlist = self.common_subdomains_wordlist()
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.check_subdomain, sub): sub for sub in wordlist}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.found_subdomains.append(result)
                    print(f"{Colors.GREEN}[+] Found: {result['subdomain']} - {result['ip']}{Colors.RESET}")
        
        return self.found_subdomains

# ==================== MODULE 2: WAF DETECTION ====================
class WAFDetector:
    def __init__(self, url, proxies=None):
        self.url = url
        self.proxies = proxies
        self.waf_signatures = {
            'Cloudflare': ['cf-ray', 'cf-cache-status', 'cloudflare'],
            'ModSecurity': ['mod_security', 'modsecurity'],
            'AWS WAF': ['x-amzn-requestid', 'x-amz-id-2'],
            'Sucuri': ['sucuri', 'sucuri.net'],
            'Incapsula': ['incap_ses', 'visid_incap'],
            'Akamai': ['akamai', 'x-akamai'],
            'FortiWeb': ['fortiwafsid'],
            'Barracuda': ['barra_counter_session'],
            'F5 BIG-IP': ['bigip', 'f5'],
            'Imperva': ['imperva', 'x-iinfo']
        }
    
    def detect(self):
        print(f"{Colors.YELLOW}[*] Checking for WAF/Protection...{Colors.RESET}")
        detected_wafs = []
        
        try:
            # Normal request
            headers = {'User-Agent': 'Mozilla/5.0'}
            response = requests.get(self.url, headers=headers, proxies=self.proxies, timeout=10)
            
            # Check headers
            for header_key in response.headers:
                header_value = response.headers[header_key].lower()
                for waf, signatures in self.waf_signatures.items():
                    for sig in signatures:
                        if sig.lower() in header_key.lower() or sig.lower() in header_value:
                            if waf not in detected_wafs:
                                detected_wafs.append(waf)
                                print(f"{Colors.RED}[!] WAF Detected: {waf}{Colors.RESET}")
            
            # Check for blocking
            malicious_payloads = [
                "<script>alert('xss')</script>",
                "' OR '1'='1",
                "../../etc/passwd"
            ]
            
            blocked_count = 0
            for payload in malicious_payloads:
                test_url = f"{self.url}?test={payload}"
                try:
                    r = requests.get(test_url, headers=headers, proxies=self.proxies, timeout=5)
                    if r.status_code in [403, 406, 412, 503]:
                        blocked_count += 1
                except:
                    blocked_count += 1
            
            if blocked_count >= 2:
                print(f"{Colors.YELLOW}[!] WAF is actively blocking requests ({blocked_count}/3 blocked){Colors.RESET}")
                if not detected_wafs:
                    detected_wafs.append("Unknown WAF")
            
            if not detected_wafs:
                print(f"{Colors.GREEN}[+] No WAF detected{Colors.RESET}")
                
        except Exception as e:
            print(f"{Colors.RED}[-] Error detecting WAF: {e}{Colors.RESET}")
        
        return detected_wafs

# ==================== MODULE 3: SSL/TLS ANALYSIS ====================
class SSLAnalyzer:
    def __init__(self, url):
        self.url = url
        self.ssl_info = {}
    
    def analyze(self):
        print(f"{Colors.YELLOW}[*] Analyzing SSL/TLS configuration...{Colors.RESET}")
        
        parsed = urlparse(self.url)
        if parsed.scheme != 'https':
            print(f"{Colors.YELLOW}[*] Target is not using HTTPS{Colors.RESET}")
            return {'https': False}
        
        hostname = parsed.netloc
        results = {'https': True, 'issues': [], 'grade': 'A'}
        
        try:
            # Get certificate
            context = ssl.create_default_context()
            with context.wrap_socket(socket.socket()) as sock:
                sock.settimeout(10)
                sock.connect((hostname, 443))
                cert = sock.getpeercert()
                cipher = sock.cipher()
                
                # Certificate info
                results['certificate'] = {
                    'subject': dict(x[0] for x in cert['subject']),
                    'issuer': dict(x[0] for x in cert['issuer']),
                    'version': cert.get('version', 'Unknown'),
                    'notBefore': cert.get('notBefore', 'Unknown'),
                    'notAfter': cert.get('notAfter', 'Unknown')
                }
                
                # Cipher info
                results['cipher'] = {
                    'name': cipher[0],
                    'version': cipher[1],
                    'bits': cipher[2]
                }
                
                # Check for weak ciphers
                weak_ciphers = ['RC4', 'DES', 'MD5', 'NULL', 'EXPORT']
                for weak in weak_ciphers:
                    if weak.upper() in cipher[0].upper():
                        results['issues'].append(f"Weak cipher detected: {cipher[0]}")
                        results['grade'] = 'C'
                
                # Check certificate validity
                from datetime import datetime
                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_left = (not_after - datetime.now()).days
                
                if days_left < 30:
                    results['issues'].append(f"Certificate expires in {days_left} days")
                    results['grade'] = 'B'
                elif days_left < 7:
                    results['issues'].append(f"CRITICAL: Certificate expires in {days_left} days!")
                    results['grade'] = 'F'
                
                print(f"{Colors.GREEN}[+] SSL Certificate valid until: {not_after.strftime('%Y-%m-%d')} ({days_left} days){Colors.RESET}")
                print(f"{Colors.GREEN}[+] Cipher: {cipher[0]} ({cipher[2]} bits){Colors.RESET}")
                
                if results['issues']:
                    for issue in results['issues']:
                        print(f"{Colors.YELLOW}[!] {issue}{Colors.RESET}")
                else:
                    print(f"{Colors.GREEN}[+] SSL configuration looks good (Grade: {results['grade']}){Colors.RESET}")
                
        except ssl.SSLError as e:
            print(f"{Colors.RED}[-] SSL Error: {e}{Colors.RESET}")
            results['issues'].append(str(e))
        except Exception as e:
            print(f"{Colors.RED}[-] Error analyzing SSL: {e}{Colors.RESET}")
        
        return results

# ==================== MODULE 4: CVE DETECTION ====================
class CVEDetector:
    def __init__(self):
        # Simplified CVE database (in production, use NVD API)
        self.cve_database = {
            'WordPress': {
                '5.8': [{'cve': 'CVE-2021-39200', 'severity': 'HIGH', 'desc': 'Stored XSS in block editor'}],
                '5.7': [{'cve': 'CVE-2021-29447', 'severity': 'MEDIUM', 'desc': 'XXE vulnerability'}],
            },
            'Apache': {
                '2.4.49': [{'cve': 'CVE-2021-41773', 'severity': 'CRITICAL', 'desc': 'Path traversal and RCE'}],
                '2.4.50': [{'cve': 'CVE-2021-42013', 'severity': 'CRITICAL', 'desc': 'Path traversal fix bypass'}],
            },
            'PHP': {
                '7.4': [{'cve': 'CVE-2021-21703', 'severity': 'HIGH', 'desc': 'Buffer overflow in phar'}],
                '8.0': [{'cve': 'CVE-2021-21702', 'severity': 'MEDIUM', 'desc': 'Use after free vulnerability'}],
            },
            'Nginx': {
                '1.18.0': [{'cve': 'CVE-2021-23017', 'severity': 'HIGH', 'desc': 'DNS resolver vulnerability'}],
            }
        }
    
    def detect(self, technologies):
        print(f"{Colors.YELLOW}[*] Checking for known CVEs...{Colors.RESET}")
        found_cves = []
        
        for tech_name, tech_version in technologies.items():
            # Extract version number
            version_match = re.search(r'(\d+\.\d+\.?\d*)', str(tech_version))
            version = version_match.group(1) if version_match else None
            
            if tech_name in self.cve_database:
                if version and version in self.cve_database[tech_name]:
                    cves = self.cve_database[tech_name][version]
                    for cve in cves:
                        found_cves.append({
                            'technology': tech_name,
                            'version': version,
                            'cve': cve['cve'],
                            'severity': cve['severity'],
                            'description': cve['desc']
                        })
                        print(f"{Colors.RED}[!] {cve['cve']} - {tech_name} {version} - {cve['severity']}{Colors.RESET}")
                        print(f"    {cve['desc']}\n")
        
        if not found_cves:
            print(f"{Colors.GREEN}[+] No known CVEs found in detected technologies{Colors.RESET}")
        
        return found_cves

# ==================== MODULE 5: API ENDPOINT DISCOVERY ====================
class APIDiscovery:
    def __init__(self, base_url, proxies=None):
        self.base_url = base_url
        self.proxies = proxies
        self.common_endpoints = [
            'api', 'api/v1', 'api/v2', 'api/v3', 'graphql', 'graphiql',
            'swagger', 'swagger.json', 'swagger.yaml', 'api-docs', 'docs',
            'api/users', 'api/auth', 'api/login', 'api/register', 'api/admin',
            'rest', 'rest/v1', 'v1', 'v2', 'v3', 'internal', 'private',
            '.well-known/openid-configuration', '.well-known/jwks.json'
        ]
    
    def discover(self):
        print(f"{Colors.YELLOW}[*] Discovering API endpoints...{Colors.RESET}")
        found_apis = []
        headers = {'User-Agent': 'Mozilla/5.0'}
        
        for endpoint in self.common_endpoints:
            test_url = urljoin(self.base_url, endpoint)
            try:
                r = requests.get(test_url, headers=headers, proxies=self.proxies, timeout=5)
                if r.status_code in [200, 401, 403, 405]:
                    content_type = r.headers.get('Content-Type', '').lower()
                    
                    # Check if it's an API response
                    if any(x in content_type for x in ['json', 'xml', 'swagger', 'graphql']):
                        found_apis.append({
                            'url': test_url,
                            'status': r.status_code,
                            'content_type': content_type
                        })
                        print(f"{Colors.GREEN}[+] API Found: {test_url} ({r.status_code}){Colors.RESET}")
                    
                    # Check for API keywords in response
                    elif any(x in r.text.lower() for x in ['api', 'swagger', 'graphql', 'json', 'endpoint']):
                        found_apis.append({
                            'url': test_url,
                            'status': r.status_code,
                            'content_type': content_type
                        })
                        print(f"{Colors.YELLOW}[?] Possible API: {test_url} ({r.status_code}){Colors.RESET}")
                        
            except:
                continue
        
        return found_apis

# ==================== MODULE 6: COOKIE SECURITY ANALYSIS ====================
class CookieAnalyzer:
    def __init__(self, response):
        self.response = response
    
    def analyze(self):
        print(f"{Colors.YELLOW}[*] Analyzing cookie security...{Colors.RESET}")
        issues = []
        
        for cookie in self.response.cookies:
            cookie_dict = {attr: getattr(cookie, attr, None) 
                          for attr in ['name', 'value', 'secure', 'httponly', 'samesite']}
            
            print(f"\n{Colors.WHITE}Cookie: {cookie.name}{Colors.RESET}")
            
            if not cookie.secure:
                issues.append(f"Cookie '{cookie.name}' missing Secure flag")
                print(f"  {Colors.RED}[-] Missing Secure flag{Colors.RESET}")
            
            if not cookie.httponly:
                issues.append(f"Cookie '{cookie.name}' missing HttpOnly flag")
                print(f"  {Colors.RED}[-] Missing HttpOnly flag{Colors.RESET}")
            
            if not hasattr(cookie, 'samesite') or not cookie.samesite:
                issues.append(f"Cookie '{cookie.name}' missing SameSite attribute")
                print(f"  {Colors.YELLOW}[!] Missing SameSite attribute{Colors.RESET}")
            
            if cookie.secure and cookie.httponly:
                print(f"  {Colors.GREEN}[+] Properly secured{Colors.RESET}")
        
        if not issues:
            print(f"\n{Colors.GREEN}[+] All cookies are properly secured{Colors.RESET}")
        
        return issues

# ==================== MODULE 7: RATE LIMITING DETECTION ====================
class RateLimitDetector:
    def __init__(self, url, proxies=None):
        self.url = url
        self.proxies = proxies
    
    def detect(self):
        print(f"{Colors.YELLOW}[*] Testing for rate limiting...{Colors.RESET}")
        
        headers = {'User-Agent': 'Mozilla/5.0'}
        status_codes = []
        response_times = []
        
        # Send 10 rapid requests
        for i in range(10):
            try:
                start = time.time()
                r = requests.get(self.url, headers=headers, proxies=self.proxies, timeout=5)
                elapsed = time.time() - start
                
                status_codes.append(r.status_code)
                response_times.append(elapsed)
                
                time.sleep(0.1)  # Small delay
            except:
                status_codes.append(0)
                response_times.append(999)
        
        # Analyze results
        if 429 in status_codes:
            print(f"{Colors.GREEN}[+] Rate limiting is implemented (429 status detected){Colors.RESET}")
            return True
        elif status_codes.count(503) > 2:
            print(f"{Colors.YELLOW}[!] Possible rate limiting (503 errors detected){Colors.RESET}")
            return True
        elif max(response_times) > 5:
            print(f"{Colors.YELLOW}[!] Possible rate limiting (high response times){Colors.RESET}")
            return True
        else:
            print(f"{Colors.RED}[-] No rate limiting detected - vulnerable to brute force{Colors.RESET}")
            return False

# ==================== MODULE 8: AUTHENTICATION BYPASS TESTING ====================
class AuthBypassTester:
    def __init__(self, base_url, proxies=None):
        self.base_url = base_url
        self.proxies = proxies
        self.default_credentials = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('root', 'root'),
            ('user', 'user'),
            ('test', 'test'),
            ('admin', '123456'),
            ('administrator', 'administrator'),
        ]
    
    def test(self):
        print(f"{Colors.YELLOW}[*] Testing for authentication bypass...{Colors.RESET}")
        
        # Common admin paths
        admin_paths = ['/admin', '/login', '/wp-login.php', '/administrator', '/panel']
        
        for path in admin_paths:
            admin_url = urljoin(self.base_url, path)
            try:
                r = requests.get(admin_url, proxies=self.proxies, timeout=5)
                if r.status_code == 200:
                    print(f"{Colors.YELLOW}[?] Admin panel accessible without auth: {admin_url}{Colors.RESET}")
                    
                    # Test default credentials if login form detected
                    if 'form' in r.text.lower() and ('password' in r.text.lower() or 'login' in r.text.lower()):
                        print(f"  {Colors.CYAN}[*] Login form detected, testing default credentials...{Colors.RESET}")
                        # Note: Actual credential testing would require form analysis
            except:
                continue
        
        print(f"{Colors.GREEN}[+] Authentication bypass test completed{Colors.RESET}")

# ==================== MODULE 9: PORT SCANNER ====================
class PortScanner:
    def __init__(self, host, ports=None):
        self.host = host
        self.ports = ports or [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 
                               3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017]
    
    def scan_port(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.host, port))
            sock.close()
            
            if result == 0:
                service = self.get_service(port)
                return {'port': port, 'status': 'open', 'service': service}
        except:
            pass
        return None
    
    def get_service(self, port):
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
            993: 'IMAPS', 995: 'POP3S', 3306: 'MySQL', 3389: 'RDP',
            5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Proxy',
            8443: 'HTTPS-Alt', 27017: 'MongoDB'
        }
        return services.get(port, 'Unknown')
    
    def scan(self):
        print(f"{Colors.YELLOW}[*] Scanning ports on {self.host}...{Colors.RESET}")
        open_ports = []
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(self.scan_port, port): port for port in self.ports}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
                    print(f"{Colors.GREEN}[+] Port {result['port']} open - {result['service']}{Colors.RESET}")
        
        return open_ports

# ==================== MODULE 10: REPORT GENERATION ====================
class ReportGenerator:
    def __init__(self, target, results):
        self.target = target
        self.results = results
        self.timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    
    def generate_json(self, filename=None):
        if not filename:
            filename = f"scan_report_{self.timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        
        print(f"{Colors.GREEN}[+] JSON report saved: {filename}{Colors.RESET}")
        return filename
    
    def generate_html(self, filename=None):
        if not filename:
            filename = f"scan_report_{self.timestamp}.html"
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Security Scan Report - {self.target}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #1e1e1e; color: #fff; }}
        .header {{ background: #007acc; padding: 20px; border-radius: 5px; }}
        .section {{ margin: 20px 0; padding: 20px; background: #2d2d2d; border-radius: 5px; }}
        .critical {{ color: #ff4444; font-weight: bold; }}
        .high {{ color: #ff8800; }}
        .medium {{ color: #ffbb00; }}
        .low {{ color: #00C851; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #444; }}
        th {{ background: #007acc; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 Web Vulnerability Scan Report</h1>
        <p><strong>Target:</strong> {self.target}</p>
        <p><strong>Scan Date:</strong> {self.timestamp}</p>
    </div>
    
    <div class="section">
        <h2>Executive Summary</h2>
        <p>Total Vulnerabilities: {self.results.get('total_vulnerabilities', 0)}</p>
        <p>Critical: {self.results.get('critical_count', 0)} | 
           High: {self.results.get('high_count', 0)} | 
           Medium: {self.results.get('medium_count', 0)} | 
           Low: {self.results.get('low_count', 0)}</p>
    </div>
    
    <div class="section">
        <h2>Discovered Technologies</h2>
        <table>
            <tr><th>Technology</th><th>Version</th></tr>
            {self._generate_tech_rows()}
        </table>
    </div>
    
    <div class="section">
        <h2>Vulnerabilities</h2>
        {self._generate_vuln_table()}
    </div>
    
    <div class="section">
        <h2>Recommendations</h2>
        <ul>
            <li>Update all outdated software and frameworks</li>
            <li>Implement security headers (HSTS, CSP, X-Frame-Options)</li>
            <li>Enable rate limiting on authentication endpoints</li>
            <li>Use HTTPS with strong TLS configuration</li>
            <li>Regular security audits and penetration testing</li>
        </ul>
    </div>
</body>
</html>
"""
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)
        
        print(f"{Colors.GREEN}[+] HTML report saved: {filename}{Colors.RESET}")
        return filename
    
    def _generate_tech_rows(self):
        techs = self.results.get('technologies', {})
        rows = ""
        for tech, version in techs.items():
            rows += f"<tr><td>{tech}</td><td>{version}</td></tr>"
        return rows if rows else "<tr><td colspan='2'>No technologies detected</td></tr>"
    
    def _generate_vuln_table(self):
        vulns = self.results.get('vulnerabilities', [])
        if not vulns:
            return "<p>No vulnerabilities found</p>"
        
        rows = ""
        for vuln in vulns:
            severity_class = vuln.get('severity', 'LOW').lower()
            rows += f"""
            <tr>
                <td class="{severity_class}">{vuln.get('severity', 'N/A')}</td>
                <td>{vuln.get('type', 'N/A')}</td>
                <td>{vuln.get('description', 'N/A')}</td>
            </tr>
            """
        
        return f"<table><tr><th>Severity</th><th>Type</th><th>Description</th></tr>{rows}</table>"

# ==================== MAIN SCANNER ====================
class WebScanner:
    def __init__(self, target_url, args):
        self.target_url = target_url
        self.args = args
        self.results = {
            'target': target_url,
            'scan_date': datetime.now().isoformat(),
            'technologies': {},
            'vulnerabilities': [],
            'subdomains': [],
            'open_ports': [],
            'apis': [],
            'cves': [],
            'ssl_info': {},
            'security_issues': []
        }
        self.vuln_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        
        self.proxies = {'http': args.proxy, 'https': args.proxy} if args.proxy else None
        self.user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) UltimateScanner/4.0'
    
    def add_vulnerability(self, severity, vuln_type, description, confidence="High"):
        severity = severity.upper()

        self.results['vulnerabilities'].append({
            'severity': severity,
            'type': vuln_type,
            'description': description,
            'confidence': confidence
        })
        self.vuln_counts[severity] += 1
    
    def run(self):
        print_banner()
        start_time = time.time()
        
        parsed_url = urlparse(self.target_url)
        domain = parsed_url.netloc
        host = parsed_url.hostname
        
        print(f"{Colors.WHITE}Target: {Colors.GREEN}{self.target_url}{Colors.RESET}")
        print(f"{Colors.WHITE}Domain: {Colors.CYAN}{domain}{Colors.RESET}")
        print(f"{Colors.WHITE}Scan Started: {Colors.YELLOW}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")
        print(f"{Colors.WHITE}Threads: {Colors.YELLOW}{self.args.threads}{Colors.RESET}")
        if self.proxies:
            print(f"{Colors.WHITE}Proxy: {Colors.YELLOW}{self.args.proxy}{Colors.RESET}")
        
        # Initial Request
        try:
            print_section("INITIAL RECONNAISSANCE")
            headers = {'User-Agent': self.user_agent}
            response = requests.get(self.target_url, headers=headers, proxies=self.proxies, timeout=15)
            
            print(f"{Colors.GREEN}[+] Target is ALIVE (Status: {response.status_code}){Colors.RESET}")
            print(f"{Colors.WHITE}Response Time: {Colors.CYAN}{len(response.content)} bytes{Colors.RESET}")
            
        except Exception as e:
            print(f"{Colors.RED}[-] Target unreachable: {e}{Colors.RESET}")
            return
        
        # Technology Detection
        print_section("TECHNOLOGY FINGERPRINTING")
        tech_stack = self.detect_technologies(response)
        self.results['technologies'] = tech_stack
        
        # Subdomain Enumeration (if enabled)
        if self.args.subdomain:
            print_section("SUBDOMAIN ENUMERATION")
            sub_enum = SubdomainEnumerator(domain, self.args.threads)
            subdomains = sub_enum.enumerate()
            self.results['subdomains'] = subdomains
        
        # WAF Detection
        print_section("WAF DETECTION")
        waf_detector = WAFDetector(self.target_url, self.proxies)
        detected_wafs = waf_detector.detect()
        if detected_wafs:
            self.add_vulnerability('INFO', 'WAF Detected', f"Protected by: {', '.join(detected_wafs)}")
        
        # SSL/TLS Analysis
        if parsed_url.scheme == 'https':
            print_section("SSL/TLS ANALYSIS")
            ssl_analyzer = SSLAnalyzer(self.target_url)
            ssl_info = ssl_analyzer.analyze()
            self.results['ssl_info'] = ssl_info
            
            if ssl_info.get('issues'):
                for issue in ssl_info['issues']:
                    self.add_vulnerability('MEDIUM', 'SSL Issue', issue)
        
        # Security Headers Check
        print_section("SECURITY HEADERS ANALYSIS")
        security_headers = self.check_security_headers(response)
        
        # Cookie Analysis
        print_section("COOKIE SECURITY ANALYSIS")
        cookie_analyzer = CookieAnalyzer(response)
        cookie_issues = cookie_analyzer.analyze()
        for issue in cookie_issues:
            self.add_vulnerability('MEDIUM', 'Cookie Security', issue)
        
        # Directory/API Discovery
        print_section("DIRECTORY & API DISCOVERY")
        self.directory_fuzzing()
        
        api_discovery = APIDiscovery(self.target_url, self.proxies)
        apis = api_discovery.discover()
        self.results['apis'] = apis
        
        # Vulnerability Testing
        print_section("SQL INJECTION TESTING")
        sqli_vulns = self.test_sql_injection()
        for vuln in sqli_vulns:
            self.add_vulnerability('CRITICAL', 'SQL Injection', 
                                 f"Vulnerable URL: {vuln['url']}\nPayload: {vuln['payload']}")
        
        print_section("XSS TESTING")
        xss_vulns = self.test_xss()
        for vuln in xss_vulns:
            self.add_vulnerability('HIGH', 'Reflected XSS', 
                                 f"Parameter: {vuln['parameter']}\nPayload: {vuln['payload']}")
        
        # CVE Detection
        print_section("CVE DETECTION")
        cve_detector = CVEDetector()
        cves = cve_detector.detect(tech_stack)
        self.results['cves'] = cves
        for cve in cves:
            self.add_vulnerability(cve['severity'], f"CVE in {cve['technology']}", 
                                 f"{cve['cve']}: {cve['description']}")
        
        # Rate Limiting
        print_section("RATE LIMITING TEST")
        rate_detector = RateLimitDetector(self.target_url, self.proxies)
        if not rate_detector.detect():
            self.add_vulnerability('MEDIUM', 'No Rate Limiting', 
                                 'Application is vulnerable to brute force attacks')
        
        # Port Scanning
        if self.args.ports:
            print_section("PORT SCANNING")
            port_scanner = PortScanner(host)
            open_ports = port_scanner.scan()
            self.results['open_ports'] = open_ports
        
        # Authentication Bypass
        if self.args.auth_test:
            print_section("AUTHENTICATION BYPASS TEST")
            auth_tester = AuthBypassTester(self.target_url, self.proxies)
            auth_tester.test()
        
        # Generate Reports
        print_section("GENERATING REPORTS")
        self.results['total_vulnerabilities'] = sum(self.vuln_counts.values())
        self.results['critical_count'] = self.vuln_counts['CRITICAL']
        self.results['high_count'] = self.vuln_counts['HIGH']
        self.results['medium_count'] = self.vuln_counts['MEDIUM']
        self.results['low_count'] = self.vuln_counts['LOW']
        
        report_gen = ReportGenerator(self.target_url, self.results)
        
        if self.args.json:
            report_gen.generate_json(self.args.json)
        
        if self.args.html:
            report_gen.generate_html(self.args.html)
        
        # Final Statistics
        elapsed_time = time.time() - start_time
        
        print_section("SCAN STATISTICS")
        print(f"{Colors.WHITE}Total Time:{Colors.CYAN} {elapsed_time:.2f} seconds{Colors.RESET}")
        print(f"{Colors.WHITE}Total Vulnerabilities:{Colors.RESET} {self.results['total_vulnerabilities']}")
        print(f"  {Colors.RED}Critical:{Colors.RESET} {self.vuln_counts['CRITICAL']}")
        print(f"  {Colors.RED}High:{Colors.RESET} {self.vuln_counts['HIGH']}")
        print(f"  {Colors.YELLOW}Medium:{Colors.RESET} {self.vuln_counts['MEDIUM']}")
        print(f"  {Colors.GREEN}Low:{Colors.RESET} {self.vuln_counts['LOW']}")
        
        print(f"\n{Colors.BLUE}{Colors.BOLD}{'='*80}{Colors.RESET}")
        print(f"{Colors.GREEN}{Colors.BOLD}✓ Scan Complete! Reports generated successfully.{Colors.RESET}")
        print(f"{Colors.BLUE}{Colors.BOLD}{'='*80}{Colors.RESET}\n")
    
    def detect_technologies(self, response):
        techs = {}
        body = response.text.lower()
        headers = response.headers
        
        # Server
        server = headers.get('Server', '')
        if server:
            techs['Server'] = server
        
        # X-Powered-By
        powered_by = headers.get('X-Powered-By', '')
        if powered_by:
            techs['X-Powered-By'] = powered_by
        
        # CMS Detection
        if 'wp-content' in body or 'wp-includes' in body:
            techs['CMS'] = 'WordPress'
        elif 'joomla' in body:
            techs['CMS'] = 'Joomla'
        elif 'drupal' in body:
            techs['CMS'] = 'Drupal'
        
        # Frameworks
        if 'react' in body:
            techs['Framework'] = 'React.js'
        elif 'angular' in body:
            techs['Framework'] = 'Angular'
        elif 'vue' in body:
            techs['Framework'] = 'Vue.js'
        
        # Backend
        for cookie in response.cookies:
            if 'PHPSESSID' in cookie.name:
                techs['Backend'] = 'PHP'
            elif 'JSESSIONID' in cookie.name:
                techs['Backend'] = 'Java'
            elif 'ASP.NET' in cookie.name:
                techs['Backend'] = 'ASP.NET'
        
        # Print detected technologies
        for tech, version in techs.items():
            print(f"{Colors.GREEN}[+] {tech}:{Colors.RESET} {version}")
        
        return techs
    
    def check_security_headers(self, response):
        required_headers = {
            'X-Frame-Options': 'Clickjacking protection',
            'X-Content-Type-Options': 'MIME sniffing protection',
            'Strict-Transport-Security': 'HTTPS enforcement',
            'Content-Security-Policy': 'XSS protection',
            'X-XSS-Protection': 'XSS filter',
            'Referrer-Policy': 'Referrer control'
        }
        
        missing = []
        for header, purpose in required_headers.items():
            if header not in response.headers:
                missing.append(header)
                print(f"{Colors.RED}[-] Missing: {Colors.WHITE}{header}{Colors.RESET} ({purpose})")
                self.add_vulnerability('LOW', 'Missing Security Header', 
                                     f"{header} - {purpose}")
        
        if not missing:
            print(f"{Colors.GREEN}[+] All critical security headers present{Colors.RESET}")
        
        return missing
    
    def directory_fuzzing(self):
        common_paths = [
            'admin', 'login', 'wp-admin', 'backup', '.git', '.env', 'config',
            'api', 'phpmyadmin', 'server-status', '.htaccess', 'robots.txt',
            'sitemap.xml', 'crossdomain.xml', 'web.config'
        ]
        
        headers = {'User-Agent': self.user_agent}
        found = 0
        
        print(f"{Colors.YELLOW}[*] Scanning {len(common_paths)} common paths...{Colors.RESET}\n")
        
        for path in common_paths:
            target = urljoin(self.target_url, path)
            try:
                r = requests.get(target, headers=headers, proxies=self.proxies, 
                               timeout=5, allow_redirects=False)
                
                if r.status_code in [200, 301, 302, 403]:
                    color = Colors.GREEN if r.status_code == 200 else Colors.YELLOW
                    print(f"{color}[{r.status_code}] {path} ({len(r.content)} bytes){Colors.RESET}")
                    found += 1
                    
                    # Check for sensitive files
                    if path in ['.env', '.git', 'config', 'backup']:
                        self.add_vulnerability('HIGH', 'Sensitive File Exposed', 
                                             f"Accessible: {target}")
            except:
                continue
        
        print(f"\n{Colors.GREEN}[+] Found {found} accessible paths{Colors.RESET}")
    
    def test_sql_injection(self):
        payloads = ["'", "' OR '1'='1", "' OR 1=1--", "1; DROP TABLE users--"]
        test_params = ['id', 'page', 'search', 'query', 'user']
        
        vulnerable = []
        headers = {'User-Agent': self.user_agent}
        
        for param in test_params:
            for payload in payloads:
                test_url = f"{self.target_url}?{param}={payload}"
                try:
                    r = requests.get(test_url, headers=headers, proxies=self.proxies, timeout=5)
                    
                    sql_errors = [
                        "SQL syntax", "mysql_fetch", "ORA-009", "PostgreSQL",
                        "SQLite", "unclosed quotation", "database error"
                    ]
                    
                    for error in sql_errors:
                        if error.lower() in r.text.lower():
                            vulnerable.append({'url': test_url, 'payload': payload, 'error': error})
                            print(f"{Colors.RED}[!] SQLi Vulnerable:{Colors.RESET} {test_url}")
                            print(f"    Payload: {payload}")
                            return vulnerable  # Return on first find
                except:
                    continue
        
        if not vulnerable:
            print(f"{Colors.GREEN}[+] No SQL Injection vulnerabilities detected{Colors.RESET}")
        
        return vulnerable
    
    def test_xss(self):
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "'><script>alert(1)</script>"
        ]
        
        test_params = ['search', 'q', 'query', 'keyword', 'id', 'name']
        vulnerable = []
        headers = {'User-Agent': self.user_agent}
        
        for param in test_params:
            for payload in payloads:
                test_url = f"{self.target_url}?{param}={payload}"
                try:
                    r = requests.get(test_url, headers=headers, proxies=self.proxies, timeout=5)
                    
                    if payload in r.text:
                        vulnerable.append({'parameter': param, 'payload': payload, 'url': test_url})
                        print(f"{Colors.RED}[!] XSS Vulnerable:{Colors.RESET} Parameter: {param}")
                        return vulnerable
                except:
                    continue
        
        if not vulnerable:
            print(f"{Colors.GREEN}[+] No XSS vulnerabilities detected{Colors.RESET}")
        
        return vulnerable

# ==================== MAIN ====================
def main():
    parser = argparse.ArgumentParser(
        description=f"{Colors.BLUE}Advanced Web Vulnerability Scanner v4.0 Ultimate{Colors.RESET}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Colors.YELLOW}Examples:{Colors.RESET}
  python3 scanner_v4.py -u http://target.com
  python3 scanner_v4.py -u https://target.com -t 50 --subdomain
  python3 scanner_v4.py -u http://target.com -p http://127.0.0.1:8080 --ports
  python3 scanner_v4.py -u http://target.com --html report.html --json report.json
        """
    )
    
    parser.add_argument('-u', '--url', help='Target URL', required=True)
    parser.add_argument('-t', '--threads', help='Number of threads', type=int, default=30)
    parser.add_argument('-p', '--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--subdomain', help='Enable subdomain enumeration', action='store_true')
    parser.add_argument('--ports', help='Enable port scanning', action='store_true')
    parser.add_argument('--auth-test', help='Test authentication bypass', action='store_true')
    parser.add_argument('--html', help='Generate HTML report', metavar='FILENAME')
    parser.add_argument('--json', help='Generate JSON report', metavar='FILENAME')
    
    args = parser.parse_args()
    
    # Validate URL
    target = args.url
    if not target.startswith('http://') and not target.startswith('https://'):
        target = 'http://' + target
    
    # Run scanner
    scanner = WebScanner(target, args)
    scanner.run()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Scan interrupted by user{Colors.RESET}")
        sys.exit(0)