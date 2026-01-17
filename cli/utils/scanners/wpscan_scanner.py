"""
WPScan WordPress security scanner integration.

WPScan is the industry-standard WordPress vulnerability scanner that detects:
- WordPress core vulnerabilities (version-specific CVEs)
- Plugin vulnerabilities (30,000+ known issues)
- Theme vulnerabilities
- Configuration issues (debug mode, directory listing)
- User enumeration
- Weak passwords (optional)

WordPress is used by 43% of all websites, making it a prime target
for attackers. WPScan helps identify common WordPress security issues.
"""

import subprocess
import json
from pathlib import Path
from typing import List, Dict, Optional


def scan_wordpress(
    target: str, scan_id: int, enumerate: str = "vp,vt,u", timeout: int = 600
) -> List[Dict]:
    """
    Scan WordPress installation for vulnerabilities using WPScan.

    WPScan enumerates:
    - vp = Vulnerable plugins
    - vt = Vulnerable themes
    - u = Users
    - ap = All plugins
    - at = All themes

    For bug bounty, we use 'vp,vt,u' (vulnerable only + users) to save time.

    Args:
        target: Target WordPress URL (e.g., "https://example.com")
        scan_id: Database ID of the parent scan
        enumerate: What to enumerate (default: "vp,vt,u")
        timeout: Maximum scan duration in seconds (default: 10 minutes)

    Returns:
        List of WordPress vulnerability findings

    Example:
        findings = scan_wordpress(
            target="https://example.com",
            scan_id=1
        )
    """

    # Create output directory
    output_dir = Path(f"/tmp/bountybot/wpscan/scan_{scan_id}")
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / "wpscan_results.json"

    # Build WPScan command
    cmd = [
        "wpscan",
        "--url",
        target,  # Target WordPress URL
        "--enumerate",
        enumerate,  # What to enumerate
        "--format",
        "json",  # JSON output
        "--output",
        str(output_file),  # Output file
        "--random-user-agent",  # Random UA to avoid blocking
        "--disable-tls-checks",  # Skip SSL cert validation
        "--max-threads",
        "5",  # Parallel requests
    ]

    print(f"[*] Running WPScan on {target}")
    print(f"[*] Enumerating: {enumerate}")
    print(f"[*] This may take 5-10 minutes...")

    try:
        # Execute WPScan
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )

        # WPScan returns various exit codes
        # 0 = No vulnerabilities found
        # 4 = Vulnerabilities found (what we want to detect)

        if output_file.exists() and output_file.stat().st_size > 0:
            findings = parse_wpscan_output(output_file, target, scan_id)

            if findings:
                print(f"[+] Found {len(findings)} WordPress vulnerabilities!")
            else:
                print(f"[*] No WordPress vulnerabilities detected")

            return findings
        else:
            print(f"[!] No WPScan output file generated")
            return []

    except subprocess.TimeoutExpired:
        print(f"[!] WPScan timed out after {timeout} seconds")
        return []
    except Exception as e:
        print(f"[!] Error running WPScan: {e}")
        return []


def parse_wpscan_output(output_file: Path, target: str, scan_id: int) -> List[Dict]:
    """
    Parse WPScan JSON output to extract WordPress vulnerabilities.

    WPScan JSON structure:
    {
      "version": {...},
      "main_theme": {...},
      "plugins": {
        "plugin-name": {
          "vulnerabilities": [...]
        }
      },
      "users": [...],
      "interesting_findings": [...]
    }

    Args:
        output_file: Path to WPScan JSON output
        target: Target WordPress URL
        scan_id: Scan ID

    Returns:
        List of WordPress vulnerability findings
    """

    findings = []

    try:
        with open(output_file, "r") as f:
            data = json.load(f)

        # Extract WordPress version vulnerabilities
        version_data = data.get("version", {})
        version_vulns = version_data.get("vulnerabilities", [])

        for vuln in version_vulns:
            finding = create_wordpress_finding(
                vuln_type="WordPress Core",
                component="WordPress " + version_data.get("number", "Unknown"),
                vuln_data=vuln,
                target=target,
                scan_id=scan_id,
            )
            findings.append(finding)
            print(f"[+] WordPress Core vulnerability: {vuln.get('title', 'Unknown')}")

        # Extract plugin vulnerabilities
        plugins = data.get("plugins", {})

        for plugin_slug, plugin_data in plugins.items():
            plugin_vulns = plugin_data.get("vulnerabilities", [])

            for vuln in plugin_vulns:
                finding = create_wordpress_finding(
                    vuln_type="Plugin",
                    component=plugin_slug,
                    vuln_data=vuln,
                    target=target,
                    scan_id=scan_id,
                )
                findings.append(finding)
                print(
                    f"[+] Plugin vulnerability: {plugin_slug} - {vuln.get('title', 'Unknown')}"
                )

        # Extract theme vulnerabilities
        themes = data.get("themes", {})

        for theme_slug, theme_data in themes.items():
            theme_vulns = theme_data.get("vulnerabilities", [])

            for vuln in theme_vulns:
                finding = create_wordpress_finding(
                    vuln_type="Theme",
                    component=theme_slug,
                    vuln_data=vuln,
                    target=target,
                    scan_id=scan_id,
                )
                findings.append(finding)
                print(
                    f"[+] Theme vulnerability: {theme_slug} - {vuln.get('title', 'Unknown')}"
                )

        # Extract interesting findings (config exposure, etc.)
        interesting = data.get("interesting_findings", [])

        for finding_data in interesting:
            # Only include high-value findings
            interesting_types = finding_data.get("interesting_entries", [])

            if interesting_types:
                finding = create_interesting_finding(
                    finding_data=finding_data, target=target, scan_id=scan_id
                )
                if finding:
                    findings.append(finding)
                    print(
                        f"[+] Interesting finding: {finding_data.get('to_s', 'Unknown')}"
                    )

        print(f"[*] Parsed {len(findings)} findings from WPScan output")
        return findings

    except json.JSONDecodeError as e:
        print(f"[!] Failed to parse WPScan JSON: {e}")
        return []
    except Exception as e:
        print(f"[!] Error parsing WPScan output: {e}")
        return []


def create_wordpress_finding(
    vuln_type: str, component: str, vuln_data: Dict, target: str, scan_id: int
) -> Dict:
    """Create a finding from WordPress vulnerability data."""

    title_text = vuln_data.get("title", "Unknown Vulnerability")
    fixed_in = vuln_data.get("fixed_in", "Not fixed")

    # Determine severity (WPScan doesn't provide CVSS, we estimate)
    severity = "high"  # Default for WordPress vulns

    # Build description
    description = f"""
**WordPress {vuln_type} Vulnerability**

**Component:** {component}
**Vulnerability:** {title_text}
**Fixed In Version:** {fixed_in}
**Target:** {target}

**Vulnerability Details:**
This vulnerability affects the {vuln_type.lower()} component "{component}".

**Impact:**
WordPress vulnerabilities can lead to:
- Remote Code Execution (RCE)
- SQL Injection
- Cross-Site Scripting (XSS)
- Authentication Bypass
- Privilege Escalation
- Information Disclosure

**CVSS Score:** Estimated 7.0-9.0 (High/Critical)
"""

    # Build proof of concept
    references = vuln_data.get("references", {})
    ref_urls = []

    for ref_type, urls in references.items():
        if isinstance(urls, list):
            ref_urls.extend(urls)
        else:
            ref_urls.append(str(urls))

    poc = f"""
**Affected Component:**
{component}

**Vulnerability Title:**
{title_text}

**Fixed in Version:**
{fixed_in}

**Remediation:**
1. Update {component} to version {fixed_in} or later
2. If update not available, consider disabling the component
3. Implement Web Application Firewall (WAF) rules
4. Monitor WordPress security advisories

**References:**
"""

    for url in ref_urls[:5]:  # Limit to 5 references
        poc += f"- {url}\n"

    return {
        "scan_id": scan_id,
        "title": f"[WPScan] {vuln_type}: {title_text}",
        "severity": severity,
        "description": description.strip(),
        "proof_of_concept": poc.strip(),
        "tool": "wpscan",
        "raw_output": json.dumps(vuln_data, indent=2),
    }


def create_interesting_finding(
    finding_data: Dict, target: str, scan_id: int
) -> Optional[Dict]:
    """Create a finding from WPScan interesting findings."""

    finding_type = finding_data.get("type", "Unknown")
    to_string = finding_data.get("to_s", "")

    # Skip low-value findings
    skip_types = ["headers", "robots_txt"]
    if finding_type in skip_types:
        return None

    title = f"[WPScan] WordPress {finding_type}: {to_string}"

    description = f"""
**WordPress Configuration Issue**

**Finding Type:** {finding_type}
**Details:** {to_string}
**Target:** {target}

**Security Implications:**
This finding may indicate a security misconfiguration or information disclosure.
"""

    poc = f"""
**Finding:**
{to_string}

**Type:**
{finding_type}

**Recommended Actions:**
1. Review the WordPress configuration
2. Disable debug mode in production
3. Restrict access to sensitive files
4. Keep WordPress and all components updated
"""

    return {
        "scan_id": scan_id,
        "title": title,
        "severity": "medium",
        "description": description.strip(),
        "proof_of_concept": poc.strip(),
        "tool": "wpscan",
        "raw_output": json.dumps(finding_data, indent=2),
    }


def get_wpscan_stats() -> Dict:
    """Get WPScan installation statistics."""

    try:
        result = subprocess.run(
            ["wpscan", "--version"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )

        # Extract version from output
        # Look for "Current Version: X.X.X"
        for line in result.stdout.split("\n"):
            if "Current Version:" in line:
                version = line.split(":")[-1].strip()
                return {"version": version, "status": "installed"}

        return {"version": "unknown", "status": "installed"}

    except Exception as e:
        return {"version": "unknown", "status": f"error: {e}"}
