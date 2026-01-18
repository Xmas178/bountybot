"""
Nikto web server vulnerability scanner integration.

Nikto performs comprehensive web server testing including:
- Server configuration issues
- Default/dangerous files and programs
- Outdated server software
- Server and software specific problems
- Security headers analysis

With over 6,700 tests, Nikto can identify:
- Information disclosure
- Injection flaws
- Misconfigurations
- Authentication bypasses
- Default credentials
"""

import subprocess
import re
from pathlib import Path
from typing import List, Dict, Optional
from cli.utils.config import get_output_dir


def scan_web_vulnerabilities(
    target: str, scan_id: int, port: int = 80, ssl: bool = False, timeout: int = 600
) -> List[Dict]:
    """
    Scan web server for vulnerabilities using Nikto.

    Nikto performs over 6,700 tests to identify:
    - Server misconfigurations
    - Default files and directories
    - Outdated software versions
    - Dangerous files/programs
    - Missing security headers

    Args:
        target: Target hostname or IP
        scan_id: Database ID of the parent scan
        port: Port to scan (default: 80)
        ssl: Use SSL/TLS (default: False, auto-detected)
        timeout: Maximum scan duration in seconds (default: 10 minutes)

    Returns:
        List of vulnerability findings

    Example:
        findings = scan_web_vulnerabilities(
            target="example.com",
            scan_id=1,
            port=443,
            ssl=True
        )
    """

    # Create output directory
    output_dir = get_output_dir() / "nikto" / f"scan_{scan_id}"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / "nikto_results.txt"

    # Build Nikto command
    cmd = [
        "nikto",
        "-h",
        target,  # Target host
        "-p",
        str(port),  # Port to scan
        "-output",
        str(output_file),  # Output file
        "-Format",
        "txt",  # Text format (easier to parse)
        "-Tuning",
        "x",  # All tests except DoS
        "-timeout",
        "10",  # Request timeout (seconds)
        "-maxtime",
        str(timeout // 60),  # Max scan time (minutes)
    ]

    # Add SSL flag if needed
    if ssl or port == 443:
        cmd.append("-ssl")

    # Disable update check (faster)
    cmd.extend(["-nointeractive"])

    print(f"[*] Running Nikto web server scan on {target}:{port}")
    print(f"[*] Testing 6,700+ vulnerabilities...")
    print(f"[*] This may take 5-10 minutes...")

    try:
        # Execute Nikto
        # Nikto is verbose, so we capture output
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )

        # Nikto returns 0 even when vulnerabilities are found
        if output_file.exists():
            findings = parse_nikto_output(output_file, target, port, scan_id)

            if findings:
                print(f"[+] Found {len(findings)} vulnerabilities/misconfigurations!")
            else:
                print(f"[*] No significant vulnerabilities detected")

            return findings
        else:
            print(f"[!] No Nikto output file generated")
            return []

    except subprocess.TimeoutExpired:
        print(f"[!] Nikto scan timed out after {timeout} seconds")
        return []
    except Exception as e:
        print(f"[!] Error running Nikto: {e}")
        return []


def parse_nikto_output(
    output_file: Path, target: str, port: int, scan_id: int
) -> List[Dict]:
    """
    Parse Nikto text output to extract vulnerability findings.

    Nikto output format:
    + Target IP: 1.2.3.4
    + Target Hostname: example.com
    + Target Port: 80
    + OSVDB-3092: /admin/: This might be interesting...
    + OSVDB-3233: /icons/README: Apache default file found.

    Args:
        output_file: Path to Nikto text output
        target: Target hostname
        port: Port number
        scan_id: Scan ID

    Returns:
        List of vulnerability findings
    """

    findings = []

    try:
        with open(output_file, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        # Extract findings (lines starting with +)
        # Format: + OSVDB-ID: /path/: Description
        finding_pattern = r"\+\s+(OSVDB-\d+|[A-Z-]+):\s+(.+?):\s+(.+?)(?:\n|$)"
        matches = re.findall(finding_pattern, content, re.MULTILINE)

        if not matches:
            print(f"[*] No Nikto findings in output file")
            return []

        for vuln_id, path, description in matches:
            # Skip informational messages
            if any(
                skip in description.lower()
                for skip in [
                    "target ip",
                    "target hostname",
                    "target port",
                    "start time",
                    "server:",
                    "retrieved x-powered-by",
                ]
            ):
                continue

            # Determine severity based on finding type
            severity = determine_nikto_severity(vuln_id, description)

            # Build finding title
            title = f"[Nikto] {vuln_id}: {path}"

            # Build description
            finding_description = f"""
**Web Server Vulnerability Detected**

**Vulnerability ID:** {vuln_id}
**Affected Path:** {path}
**Target:** {target}:{port}

**Description:**
{description}

**Finding Details:**
Nikto identified this issue during automated web server testing. This may indicate:
- Server misconfiguration
- Presence of default/dangerous files
- Information disclosure
- Outdated software
- Missing security controls

**Potential Impact:**
{get_impact_description(description)}

**CVSS Score:** {get_estimated_cvss(severity)}
"""

            # Build proof of concept
            poc = f"""
**Vulnerable URL:**
http{"s" if port == 443 else ""}://{target}:{port}{path}

**Nikto Finding:**
```
{vuln_id}: {path}: {description}
```

**Verification Steps:**
1. Navigate to: http{"s" if port == 443 else ""}://{target}:{port}{path}
2. Observe the response
3. Verify if sensitive information is exposed or functionality is accessible

**Remediation:**
{get_remediation_advice(description)}

**References:**
- Nikto Documentation: https://cirt.net/Nikto2
{f"- OSVDB Reference: https://vulners.com/osvdb/{vuln_id.replace('OSVDB-', '')}" if vuln_id.startswith("OSVDB") else ""}
"""

            finding = {
                "scan_id": scan_id,
                "title": title[:200],  # Limit title length
                "severity": severity,
                "description": finding_description.strip(),
                "proof_of_concept": poc.strip(),
                "tool": "nikto",
                "raw_output": f"{vuln_id}: {path}: {description}",
            }

            findings.append(finding)
            print(f"[+] Nikto Finding: {vuln_id} - {path[:50]}... ({severity.upper()})")

        print(f"[*] Parsed {len(findings)} findings from Nikto output")
        return findings

    except Exception as e:
        print(f"[!] Error parsing Nikto output: {e}")
        return []


def determine_nikto_severity(vuln_id: str, description: str) -> str:
    """
    Determine severity level based on Nikto finding.

    Args:
        vuln_id: Vulnerability identifier (OSVDB-XXXX)
        description: Finding description

    Returns:
        Severity level: critical, high, medium, low, info
    """

    desc_lower = description.lower()

    # Critical - Direct exploitation or sensitive data exposure
    if any(
        keyword in desc_lower
        for keyword in [
            "sql injection",
            "remote code execution",
            "rce",
            "arbitrary file",
            "password",
            "credentials",
            "authentication bypass",
        ]
    ):
        return "critical"

    # High - Significant security issues
    if any(
        keyword in desc_lower
        for keyword in [
            "admin",
            "backup",
            ".git",
            ".svn",
            "phpinfo",
            "database",
            "config",
            "shell",
        ]
    ):
        return "high"

    # Medium - Misconfigurations and information disclosure
    if any(
        keyword in desc_lower
        for keyword in [
            "directory listing",
            "exposed",
            "accessible",
            "information disclosure",
            "missing header",
        ]
    ):
        return "medium"

    # Low - Minor issues
    if any(
        keyword in desc_lower
        for keyword in ["outdated", "deprecated", "uncommon header"]
    ):
        return "low"

    # Default to info
    return "info"


def get_impact_description(description: str) -> str:
    """Get impact description based on finding."""

    desc_lower = description.lower()

    if "admin" in desc_lower:
        return "Exposed admin interface may allow unauthorized access to administrative functions."
    elif ".git" in desc_lower or "backup" in desc_lower:
        return "Source code exposure can reveal sensitive logic, credentials, and attack surface."
    elif "directory listing" in desc_lower or "directory indexing" in desc_lower:
        return "Directory listing allows attackers to enumerate files and discover sensitive resources."
    elif "header" in desc_lower:
        return "Missing security headers may leave the application vulnerable to common web attacks."
    else:
        return "This finding may expose sensitive information or indicate misconfiguration."


def get_remediation_advice(description: str) -> str:
    """Get remediation advice based on finding."""

    desc_lower = description.lower()

    if "admin" in desc_lower:
        return "1. Restrict access to admin interfaces using IP whitelisting\n2. Implement strong authentication\n3. Use non-standard paths"
    elif ".git" in desc_lower:
        return "1. Remove .git directory from production servers\n2. Configure web server to deny access to hidden files"
    elif "backup" in desc_lower:
        return "1. Remove backup files from web-accessible directories\n2. Store backups securely outside webroot"
    elif "directory listing" in desc_lower or "directory indexing" in desc_lower:
        return "1. Disable directory listing in web server configuration\n2. Add index.html to directories"
    elif "header" in desc_lower:
        return "1. Configure security headers (HSTS, CSP, X-Frame-Options)\n2. Update web server configuration"
    else:
        return "1. Review and address the specific finding\n2. Follow security best practices\n3. Keep software updated"


def get_estimated_cvss(severity: str) -> str:
    """Get estimated CVSS score based on severity."""

    cvss_map = {
        "critical": "9.0-10.0 (Critical)",
        "high": "7.0-8.9 (High)",
        "medium": "4.0-6.9 (Medium)",
        "low": "0.1-3.9 (Low)",
        "info": "0.0 (Informational)",
    }

    return cvss_map.get(severity, "Unknown")


def get_nikto_stats() -> Dict:
    """
    Get Nikto installation statistics.

    Returns:
        Dictionary with Nikto version and status
    """

    try:
        result = subprocess.run(
            ["nikto", "-Version"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )

        # Extract version from first line
        version_line = result.stdout.split("\n")[0] if result.stdout else "Unknown"

        return {"version": version_line.strip(), "status": "installed"}

    except Exception as e:
        return {"version": "unknown", "status": f"error: {e}"}
