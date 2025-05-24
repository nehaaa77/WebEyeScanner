import socket
import requests
import nmap
import whois
from bs4 import BeautifulSoup
import re
import argparse

def banner():
    print("""
    ____    __    ____  _______  __        ______   ______   .___  ___.  _______ 
    \   \  /  \  /   / |   ____||  |      /      | /  __  \  |   \/   | |   ____|
     \   \/    \/   /  |  |__   |  |     |  ,----'|  |  |  | |  \  /  | |  |__   
      \            /   |   __|  |  |     |  |     |  |  |  | |  |\/|  | |   __|  
       \    /\    /    |  |____ |  `----.|  `----.|  `--'  | |  |  |  | |  |____ 
        \__/  \__/     |_______||_______| \______| \______/  |__|  |__| |_______|
                                                                                 
    Simple Web App Scanner - Basic Enumeration Tool
    """)

def get_ip_address(domain):
    """Resolve domain name to IP address"""
    try:
        ip_address = socket.gethostbyname(domain)
        print(f"\n[+] IP Address for {domain}: {ip_address}")
        return ip_address
    except socket.gaierror:
        print(f"[-] Unable to resolve {domain}")
        return None

def port_scan(target, ports='1-1024'):
    """Scan for open ports using nmap"""
    print(f"\n[+] Scanning ports {ports} on {target}...")
    
    scanner = nmap.PortScanner()
    scanner.scan(target, ports)
    
    for host in scanner.all_hosts():
        print(f"\n[+] Scan results for {host}:")
        print(f"State: {scanner[host].state()}")
        
        for proto in scanner[host].all_protocols():
            print(f"\nProtocol: {proto}")
            ports = scanner[host][proto].keys()
            
            for port in sorted(ports):
                port_info = scanner[host][proto][port]
                print(f"Port: {port}\tState: {port_info['state']}\tService: {port_info['name']}")

def service_scan(target):
    """Perform service version detection"""
    print(f"\n[+] Performing service detection on {target}...")
    
    scanner = nmap.PortScanner()
    scanner.scan(target, arguments='-sV')
    
    for host in scanner.all_hosts():
        print(f"\n[+] Service detection results for {host}:")
        
        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()
            
            for port in sorted(ports):
                port_info = scanner[host][proto][port]
                print(f"\nPort: {port}/{proto}")
                print(f"Service: {port_info['name']}")
                print(f"Version: {port_info['product']} {port_info['version']}")
                print(f"Extra Info: {port_info['extrainfo']}")

def os_detection(target):
    """Attempt OS detection"""
    print(f"\n[+] Attempting OS detection for {target}...")
    
    scanner = nmap.PortScanner()
    scanner.scan(target, arguments='-O')
    
    for host in scanner.all_hosts():
        print(f"\n[+] OS detection results for {host}:")
        if 'osmatch' in scanner[host]:
            for osmatch in scanner[host]['osmatch']:
                print(f"OS Match: {osmatch['name']}")
                print(f"Accuracy: {osmatch['accuracy']}%")
                print(f"OS Class: {osmatch['osclass'][0]['osfamily']}")

def whois_lookup(domain):
    """Perform WHOIS lookup"""
    print(f"\n[+] Performing WHOIS lookup for {domain}...")
    
    try:
        w = whois.whois(domain)
        
        print("\nWHOIS Information:")
        print(f"Domain Name: {w.domain_name}")
        print(f"Registrar: {w.registrar}")
        print(f"Creation Date: {w.creation_date}")
        print(f"Expiration Date: {w.expiration_date}")
        print(f"Name Servers: {', '.join(w.name_servers) if w.name_servers else 'N/A'}")
    except Exception as e:
        print(f"[-] Error in WHOIS lookup: {e}")

def web_tech_detection(url):
    """Detect web technologies using headers and content"""
    print(f"\n[+] Detecting web technologies for {url}...")
    
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
        }
        response = requests.get(url, headers=headers, timeout=10, verify=False)
        
        # Server header
        server = response.headers.get('Server', 'Not Found')
        print(f"\nServer: {server}")
        
        # X-Powered-By header
        powered_by = response.headers.get('X-Powered-By', 'Not Found')
        print(f"Powered By: {powered_by}")
        
        # Check for common frameworks
        if 'wp-content' in response.text:
            print("Detected: WordPress")
        if 'Joomla' in response.text:
            print("Detected: Joomla")
        if 'Drupal' in response.text:
            print("Detected: Drupal")
            
        # Check for common JavaScript libraries
        soup = BeautifulSoup(response.text, 'html.parser')
        scripts = soup.find_all('script', src=True)
        
        js_libs = set()
        for script in scripts:
            src = script['src'].lower()
            if 'jquery' in src:
                js_libs.add('jQuery')
            if 'bootstrap' in src:
                js_libs.add('Bootstrap')
            if 'react' in src:
                js_libs.add('React')
            if 'angular' in src:
                js_libs.add('Angular')
                
        if js_libs:
            print(f"JavaScript Libraries: {', '.join(js_libs)}")
            
    except requests.RequestException as e:
        print(f"[-] Error accessing {url}: {e}")

def directory_enumeration(url, wordlist=None):
    """Basic directory enumeration"""
    print(f"\n[+] Attempting basic directory enumeration for {url}...")
    
    common_dirs = [
        'admin', 'login', 'wp-admin', 'administrator', 
        'backup', 'config', 'phpmyadmin', 'test', 'tmp'
    ]
    
    try:
        for directory in common_dirs:
            target_url = f"{url}/{directory}"
            response = requests.get(target_url, timeout=5, verify=False)
            
            if response.status_code == 200:
                print(f"[+] Found directory: {target_url} (Status: {response.status_code})")
            elif response.status_code == 403:
                print(f"[!] Directory exists but forbidden: {target_url} (Status: {response.status_code})")
                
    except requests.RequestException:
        pass

def main():
    banner()
    
    parser = argparse.ArgumentParser(description='Simple Web App Scanner')
    parser.add_argument('target', help='Target domain or IP address')
    args = parser.parse_args()
    
    target = args.target
    
    # Basic checks
    if not re.match(r'^https?://', target):
        target = f"http://{target}"
    
    domain = target.split('//')[1].split('/')[0]
    
    # Perform scans
    ip_address = get_ip_address(domain)
    if ip_address:
        port_scan(ip_address)
        service_scan(ip_address)
        os_detection(ip_address)
    
    whois_lookup(domain)
    web_tech_detection(target)
    directory_enumeration(target)
    
    print("\n[+] Basic scan completed!")

if __name__ == "__main__":
    main()
