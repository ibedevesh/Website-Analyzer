import socket
import ssl
import dns.resolver
import requests
import concurrent.futures
import whois
from bs4 import BeautifulSoup
import re

class EnhancedWebsiteAnalyzer:
    def __init__(self, domain):
        self.domain = domain
        self.ip = None
        self.results = {}

    def analyze(self):
        self.resolve_ip()
        self.check_dns_records()
        self.get_http_headers()
        self.check_ssl_cert()
        self.scan_common_ports()
        self.get_whois_info()
        self.check_robots_txt()
        self.check_sitemap()
        self.detect_technologies()

    def resolve_ip(self):
        try:
            self.ip = socket.gethostbyname(self.domain)
            self.results['ip'] = self.ip
        except socket.gaierror:
            self.results['ip'] = "Could not resolve IP"

    def check_dns_records(self):
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT']
        dns_results = {}
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.domain, record_type)
                dns_results[record_type] = [str(rdata) for rdata in answers]
            except dns.resolver.NoAnswer:
                dns_results[record_type] = []
            except dns.resolver.NXDOMAIN:
                dns_results[record_type] = "Domain does not exist"
            except Exception as e:
                dns_results[record_type] = f"Error: {str(e)}"
        self.results['dns_records'] = dns_results

    def get_http_headers(self):
        try:
            response = requests.head(f"http://{self.domain}", allow_redirects=True)
            self.results['http_headers'] = dict(response.headers)
        except requests.RequestException as e:
            self.results['http_headers'] = f"Error: {str(e)}"

    def check_ssl_cert(self):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as secure_sock:
                    cert = secure_sock.getpeercert()
                    self.results['ssl_cert'] = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serialNumber': cert['serialNumber'],
                        'notBefore': cert['notBefore'],
                        'notAfter': cert['notAfter']
                    }
        except Exception as e:
            self.results['ssl_cert'] = f"Error: {str(e)}"

    def scan_port(self, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((self.ip, port))
        sock.close()
        return port if result == 0 else None

    def scan_common_ports(self):
        common_ports = [80, 443, 22, 21, 25, 3306, 8080, 8443]
        open_ports = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_port = {executor.submit(self.scan_port, port): port for port in common_ports}
            for future in concurrent.futures.as_completed(future_to_port):
                result = future.result()
                if result:
                    open_ports.append(result)
        self.results['open_ports'] = open_ports

    def get_whois_info(self):
        try:
            w = whois.whois(self.domain)
            self.results['whois'] = {
                'registrar': w.registrar,
                'creation_date': w.creation_date,
                'expiration_date': w.expiration_date,
                'name_servers': w.name_servers
            }
        except Exception as e:
            self.results['whois'] = f"Error: {str(e)}"

    def check_robots_txt(self):
        try:
            response = requests.get(f"http://{self.domain}/robots.txt")
            if response.status_code == 200:
                self.results['robots_txt'] = response.text[:500] + "..." if len(response.text) > 500 else response.text
            else:
                self.results['robots_txt'] = f"No robots.txt found (Status code: {response.status_code})"
        except requests.RequestException as e:
            self.results['robots_txt'] = f"Error: {str(e)}"

    def check_sitemap(self):
        try:
            response = requests.get(f"http://{self.domain}/sitemap.xml")
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'xml')
                urls = soup.find_all('loc')
                self.results['sitemap'] = f"Found sitemap with {len(urls)} URLs"
            else:
                self.results['sitemap'] = f"No sitemap.xml found (Status code: {response.status_code})"
        except requests.RequestException as e:
            self.results['sitemap'] = f"Error: {str(e)}"

    def detect_technologies(self):
        try:
            response = requests.get(f"http://{self.domain}")
            technologies = []
            if 'WordPress' in response.text:
                technologies.append('WordPress')
            if 'Joomla' in response.text:
                technologies.append('Joomla')
            if 'Drupal' in response.text:
                technologies.append('Drupal')
            if re.search(r'<script[^>]*react\.js', response.text):
                technologies.append('React')
            if re.search(r'<script[^>]*vue\.js', response.text):
                technologies.append('Vue.js')
            self.results['technologies'] = technologies if technologies else "No common technologies detected"
        except requests.RequestException as e:
            self.results['technologies'] = f"Error: {str(e)}"

    def print_results(self):
        print(f"\nAnalysis results for {self.domain}:")
        print(f"IP Address: {self.results['ip']}")
        
        print("\nDNS Records:")
        for record_type, records in self.results['dns_records'].items():
            print(f"  {record_type}: {records}")
        
        print("\nHTTP Headers:")
        for header, value in self.results['http_headers'].items():
            print(f"  {header}: {value}")
        
        print("\nSSL Certificate:")
        if isinstance(self.results['ssl_cert'], dict):
            for key, value in self.results['ssl_cert'].items():
                print(f"  {key}: {value}")
        else:
            print(f"  {self.results['ssl_cert']}")
        
        print("\nOpen Ports:")
        print(f"  {', '.join(map(str, self.results['open_ports']))}")
        
        print("\nWHOIS Information:")
        if isinstance(self.results['whois'], dict):
            for key, value in self.results['whois'].items():
                print(f"  {key}: {value}")
        else:
            print(f"  {self.results['whois']}")
        
        print("\nRobots.txt:")
        print(f"  {self.results['robots_txt']}")
        
        print("\nSitemap:")
        print(f"  {self.results['sitemap']}")
        
        print("\nDetected Technologies:")
        print(f"  {self.results['technologies']}")

if __name__ == "__main__":
    domain = input("Enter the domain name to analyze: ")
    analyzer = EnhancedWebsiteAnalyzer(domain)
    analyzer.analyze()
    analyzer.print_results()
