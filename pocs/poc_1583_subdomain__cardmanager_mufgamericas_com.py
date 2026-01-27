#!/usr/bin/env python3

"""
ETHICAL DISCLAIMER: This script is for educational and authorized testing purposes only.
Only use this on systems you own or have explicit written permission to test.
Unauthorized access to computer systems is illegal and unethical.

Subdomain Discovery Proof-of-Concept
====================================
This script demonstrates passive subdomain enumeration techniques to discover
subdomains like cardmanager.mufgamericas.com. It showcases how attackers might
identify additional attack surfaces through subdomain discovery.

Vulnerability: Information Disclosure via Subdomain Discovery
The existence of subdomains can reveal additional services, applications, or
infrastructure that may not be intended for public access or may have different
security controls than the main domain.
"""

import requests
import socket
import sys
import time
from urllib.parse import urlparse

# TODO: Modify target domain for your authorized testing
TARGET_DOMAIN = "mufgamericas.com"
DISCOVERED_SUBDOMAIN = "cardmanager.mufgamericas.com"

# TODO: Add more common subdomain prefixes for comprehensive testing
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "test", "dev", "staging", "api",
    "portal", "login", "secure", "vpn", "remote", "support", "help",
    "cardmanager", "manager", "dashboard", "panel", "control"
]

# TODO: Customize headers to match your testing requirements
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Security Research) AppleWebKit/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
    'Connection': 'keep-alive'
}

def print_banner():
    """Display script banner and information"""
    print("=" * 70)
    print("SUBDOMAIN DISCOVERY PROOF-OF-CONCEPT")
    print("Educational Security Research Tool")
    print("=" * 70)
    print(f"Target Domain: {TARGET_DOMAIN}")
    print(f"Known Subdomain: {DISCOVERED_SUBDOMAIN}")
    print("=" * 70)

def check_dns_resolution(hostname):
    """
    Check if a hostname resolves to an IP address
    
    Args:
        hostname (str): The hostname to check
        
    Returns:
        tuple: (bool, str) - (resolution_success, ip_address_or_error)
    """
    try:
        # Attempt DNS resolution
        ip_address = socket.gethostbyname(hostname)
        return True, ip_address
    except socket.gaierror as e:
        return False, str(e)
    except Exception as e:
        return False, f"Unexpected error: {str(e)}"

def check_http_response(url, timeout=5):
    """
    Check HTTP response for a given URL
    
    Args:
        url (str): URL to check
        timeout (int): Request timeout in seconds
        
    Returns:
        dict: Response information including status, headers, etc.
    """
    response_info = {
        'accessible': False,
        'status_code': None,
        'server': None,
        'title': None,
        'redirect_url': None,
        'error': None
    }
    
    try:
        # TODO: Modify timeout and other request parameters as needed
        response = requests.get(url, headers=HEADERS, timeout=timeout, 
                              allow_redirects=True, verify=False)
        
        response_info['accessible'] = True
        response_info['status_code'] = response.status_code
        response_info['server'] = response.headers.get('Server', 'Unknown')
        
        # Check for redirects
        if response.history:
            response_info['redirect_url'] = response.url
            
        # Extract title from HTML (basic extraction)
        if 'text/html' in response.headers.get('Content-Type', ''):
            try:
                title_start = response.text.lower().find('<title>')
                if title_start != -1:
                    title_end = response.text.lower().find('</title>', title_start)
                    if title_end != -1:
                        title = response.text[title_start + 7:title_end].strip()
                        response_info['title'] = title[:100]  # Limit title length
            except:
                pass  # Title extraction is optional
                
    except requests.exceptions.RequestException as e:
        response_info['error'] = str(e)
    except Exception as e:
        response_info['error'] = f"Unexpected error: {str(e)}"
    
    return response_info

def verify_discovered_subdomain():
    """
    Verify the discovered subdomain from the security finding
    """
    print(f"\n[INFO] Verifying discovered subdomain: {DISCOVERED_SUBDOMAIN}")
    print("-" * 50)
    
    # Check DNS resolution
    dns_resolves, dns_result = check_dns_resolution(DISCOVERED_SUBDOMAIN)
    
    if dns_resolves:
        print(f"[+] DNS Resolution: SUCCESS - {dns_result}")
        
        # Check HTTP accessibility
        for protocol in ['http', 'https']:
            url = f"{protocol}://{DISCOVERED_SUBDOMAIN}"
            print(f"\n[INFO] Checking {protocol.upper()} accessibility...")
            
            http_info = check_http_response(url)
            
            if http_info['accessible']:
                print(f"[+] {protocol.upper()} Access: SUCCESS")
                print(f"    Status Code: {http_info['status_code']}")
                print(f"    Server: {http_info['server']}")
                
                if http_info['title']:
                    print(f"    Page Title: {http_info['title']}")
                    
                if http_info['redirect_url'] and http_info['redirect_url'] != url:
                    print(f"    Redirects to: {http_info['redirect_url']}")
            else:
                print(f"[-] {protocol.upper()} Access: FAILED")
                if http_info['error']:
                    print(f"    Error: {http_info['error']}")
            
            # TODO: Add delay between requests to be respectful
            time.sleep(1)
    else:
        print(f"[-] DNS Resolution: FAILED - {dns_result}")

def demonstrate_subdomain_enumeration():
    """
    Demonstrate how subdomains might be discovered through enumeration
    """
    print(f"\n[INFO] Demonstrating subdomain enumeration on {TARGET_DOMAIN}")
    print("-" * 50)
    print("[WARNING] This is for educational purposes - showing how discovery works")
    
    discovered_subdomains = []
    
    # TODO: Implement rate limiting to avoid overwhelming the target
    for subdomain in COMMON_SUBDOMAINS[:10]:  # Limit to first 10 for demonstration
        hostname = f"{subdomain}.{TARGET_DOMAIN}"
        
        print(f"[INFO] Checking: {hostname}")
        
        dns_resolves, dns_result = check_dns_resolution(hostname)
        
        if dns_resolves:
            print(f"[+] Found: {hostname} -> {dns_result}")
            discovered_subdomains.append((hostname, dns_result))
        else:
            print(f"[-] Not found: {hostname}")
        
        # TODO: Adjust delay between requests as appropriate
        time.sleep(2)  # Be respectful with timing
    
    return discovered_subdomains

def analyze_security_implications():
    """
    Analyze and explain the security implications of subdomain discovery
    """
    print("\n" + "=" * 70)
    print("SECURITY IMPLICATIONS ANALYSIS")
    print("=" * 70)
    
    print("\n[RISK] Information Disclosure:")
    print("- Subdomains reveal additional services and infrastructure")
    print("- May expose development, staging, or administrative interfaces")
    print("- Could indicate technology stack and architecture")
    
    print("\n[RISK] Expanded Attack Surface:")
    print("- Each subdomain represents a potential entry point")
    print("- Different subdomains may have different security controls")
    print("- Administrative interfaces may have weaker security")
    
    print("\n[MITIGATION] Recommendations:")
    print("- Implement proper DNS security practices")
    print("- Use internal DNS for non-public services")
    print("- Apply consistent security controls across all subdomains")
    print("- Regular security assessments of all discovered services")
    print("- Consider using wildcard certificates carefully")

def main():
    """Main execution function"""
    try:
        print_banner()
        
        # Verify the specific subdomain from the finding
        verify_discovered_subdomain()
        
        # TODO: Uncomment the following line only for authorized testing
        # discovered = demonstrate_subdomain_enumeration()
        
        # Provide security analysis
        analyze_security_implications()
        
        print("\n" + "=" * 70)
        print("PROOF-OF-CONCEPT COMPLETED")
        print("Remember: Use this knowledge responsibly and ethically!")
        print("=" * 70)
        
    except KeyboardInterrupt:
        print("\n[INFO] Script interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] Unexpected error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()