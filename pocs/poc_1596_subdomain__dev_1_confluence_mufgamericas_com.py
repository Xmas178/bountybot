#!/usr/bin/env python3

"""
ETHICAL DISCLAIMER: This script is for educational and authorized security testing purposes only.
Only use this script on systems you own or have explicit written permission to test.
Unauthorized access to computer systems is illegal and unethical.

Subdomain Discovery Proof-of-Concept Script

This script demonstrates passive subdomain enumeration techniques to identify
subdomains that may expose sensitive development or staging environments.
The finding shows a development Confluence instance that was discovered
through passive enumeration techniques.

Vulnerability: Information Disclosure through Subdomain Discovery
- Development/staging subdomains may expose sensitive information
- These environments often have weaker security controls
- Can reveal technology stack, internal naming conventions, and attack surface
"""

import requests
import socket
import sys
from urllib.parse import urlparse
import time

# Configuration - TODO: Customize these values for your authorized testing
TARGET_SUBDOMAIN = "dev-1-confluence.mufgamericas.com"  # TODO: Replace with your target
TARGET_URL = f"http://{TARGET_SUBDOMAIN}"
TIMEOUT = 10
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"


def print_banner():
    """Print script banner and information"""
    print("=" * 70)
    print("SUBDOMAIN DISCOVERY PROOF-OF-CONCEPT")
    print("=" * 70)
    print(f"Target: {TARGET_SUBDOMAIN}")
    print(f"URL: {TARGET_URL}")
    print("=" * 70)


def check_dns_resolution():
    """
    Step 1: Verify the subdomain resolves to an IP address
    This confirms the subdomain exists in DNS
    """
    print("[1] Checking DNS resolution...")

    try:
        # Attempt to resolve the subdomain to an IP address
        ip_address = socket.gethostbyname(TARGET_SUBDOMAIN)
        print(f"✓ DNS Resolution: {TARGET_SUBDOMAIN} -> {ip_address}")
        return True, ip_address

    except socket.gaierror as e:
        print(f"✗ DNS Resolution failed: {e}")
        return False, None

    except Exception as e:
        print(f"✗ Unexpected DNS error: {e}")
        return False, None


def check_http_response():
    """
    Step 2: Attempt to connect to the subdomain via HTTP
    This verifies if a web service is running on the subdomain
    """
    print("\n[2] Checking HTTP response...")

    # Configure session with headers to appear like a normal browser
    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }
    )

    try:
        # Send HTTP GET request to the target subdomain
        print(f"Connecting to {TARGET_URL}...")
        response = session.get(TARGET_URL, timeout=TIMEOUT, allow_redirects=True)

        print(f"✓ HTTP Response received:")
        print(f"  Status Code: {response.status_code}")
        print(f"  Content Length: {len(response.content)} bytes")
        print(f"  Final URL: {response.url}")

        return True, response

    except requests.exceptions.ConnectionError:
        print("✗ Connection failed - Service may not be running")
        return False, None

    except requests.exceptions.Timeout:
        print(f"✗ Request timeout after {TIMEOUT} seconds")
        return False, None

    except requests.exceptions.RequestException as e:
        print(f"✗ HTTP request failed: {e}")
        return False, None

    except Exception as e:
        print(f"✗ Unexpected HTTP error: {e}")
        return False, None


def analyze_response_headers(response):
    """
    Step 3: Analyze HTTP response headers for information disclosure
    Headers can reveal server technology, security configurations, etc.
    """
    print("\n[3] Analyzing response headers...")

    interesting_headers = [
        "Server",
        "X-Powered-By",
        "X-AspNet-Version",
        "X-Generator",
        "X-Confluence-User",
        "X-AUSERNAME",
        "X-Seraph-LoginReason",
        "Set-Cookie",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Strict-Transport-Security",
        "Content-Security-Policy",
    ]

    found_headers = {}

    for header in interesting_headers:
        if header in response.headers:
            found_headers[header] = response.headers[header]

    if found_headers:
        print("✓ Interesting headers found:")
        for header, value in found_headers.items():
            print(f"  {header}: {value}")
    else:
        print("- No particularly interesting headers found")

    return found_headers


def analyze_response_content(response):
    """
    Step 4: Analyze response content for technology identification
    Look for indicators that confirm this is a Confluence instance
    """
    print("\n[4] Analyzing response content...")

    content = response.text.lower()

    # TODO: Add more signatures for different technologies you want to detect
    confluence_indicators = [
        "confluence",
        "atlassian",
        "com.atlassian.confluence",
        "confluence-base-url",
        "/confluence/",
        "ajs-context-path",
    ]

    found_indicators = []

    for indicator in confluence_indicators:
        if indicator in content:
            found_indicators.append(indicator)

    if found_indicators:
        print("✓ Confluence indicators found in response:")
        for indicator in found_indicators:
            print(f"  - {indicator}")
        return True
    else:
        print("- No Confluence-specific indicators found in response")
        return False


def check_common_endpoints():
    """
    Step 5: DISABLED for VDP compliance

    MUFG VDP does not allow endpoint enumeration or fuzzing.
    This step is disabled to comply with program rules.
    """
    print("\n[5] Endpoint enumeration: SKIPPED (VDP compliance)")
    print("  ⚠ MUFG VDP does not allow active endpoint testing")
    print("  ℹ This would require authentication or constitute fuzzing")
    print("  ℹ Only passive reconnaissance is permitted")

    return []


def generate_report(
    dns_resolved,
    ip_address,
    http_success,
    response,
    headers,
    confluence_confirmed,
    endpoints,
):
    """
    Generate a summary report of findings
    """
    print("\n" + "=" * 70)
    print("PROOF-OF-CONCEPT RESULTS SUMMARY")
    print("=" * 70)

    print(f"Target: {TARGET_SUBDOMAIN}")
    if ip_address:
        print(f"IP Address: {ip_address}")

    print(f"DNS Resolution: {'SUCCESS' if dns_resolved else 'FAILED'}")
    print(f"HTTP Response: {'SUCCESS' if http_success else 'FAILED'}")

    if http_success:
        print(f"HTTP Status: {response.status_code}")
        print(f"Response Size: {len(response.content)} bytes")

    print(f"Confluence Confirmed: {'YES' if confluence_confirmed else 'NO'}")
    print(f"Accessible Endpoints: {len(endpoints) if endpoints else 0}")

    print("\n[SECURITY IMPLICATIONS]")
    if dns_resolved and http_success:
        print("✓ Subdomain is accessible and responding to HTTP requests")

        if confluence_confirmed:
            print("✓ Confirmed as Confluence application")
            print("⚠ Development/staging Confluence instances may contain:")
            print("  - Sensitive development data")
            print("  - Weaker authentication controls")
            print("  - Debug information disclosure")
            print("  - Default or weak credentials")

        if endpoints:
            print("⚠ Multiple endpoints are accessible")
            print("  - May indicate insufficient access controls")
            print("  - Could provide attack surface for further enumeration")

    print("\n[RECOMMENDATIONS]")
    print("• Implement proper access controls for development environments")
    print("• Consider IP whitelisting for internal development systems")
    print("• Ensure development instances don't contain production data")
    print("• Regular security assessments of all subdomains")
    print("• Monitor DNS records and subdomain creation processes")


def main():
    """Main execution function"""
    print_banner()

    # Step 1: DNS Resolution Check
    dns_resolved, ip_address = check_dns_resolution()
    if not dns_resolved:
        print("\n[ERROR] Cannot proceed without DNS resolution")
        sys.exit(1)

    # Step 2: HTTP Response Check
    http_success, response = check_http_response()
    if not http_success:
        print("\n[WARNING] HTTP connection failed, but subdomain exists in DNS")
        generate_report(dns_resolved, ip_address, False, None, {}, False, [])
        return

    # Step 3: Header Analysis
    headers = analyze_response_headers(response)

    # Step 4: Content Analysis
    confluence_confirmed = analyze_response_content(response)

    # Step 5: Endpoint Enumeration - DISABLED for VDP
    endpoints = check_common_endpoints()

    # Generate final report
    generate_report(
        dns_resolved,
        ip_address,
        http_success,
        response,
        headers,
        confluence_confirmed,
        endpoints,
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[INFO] Script interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[ERROR] Unexpected error: {e}")
        sys.exit(1)
