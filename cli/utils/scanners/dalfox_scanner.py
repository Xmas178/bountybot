"""
Dalfox XSS (Cross-Site Scripting) scanner integration.

Dalfox is a powerful XSS scanner that can detect:
- Reflected XSS (input reflected in response)
- Stored XSS (input saved and displayed later)
- DOM-based XSS (JavaScript manipulates DOM)

It tests 1000+ payloads across GET, POST, Cookie, and other injection points.
XSS vulnerabilities can allow attackers to:
- Steal session cookies and hijack accounts
- Redirect users to malicious sites
- Modify page content
- Execute arbitrary JavaScript in victim's browser
"""

import subprocess
import json
from pathlib import Path
from typing import List, Dict, Optional


def test_xss_vulnerabilities(
    target: str, scan_id: int, mode: str = "url", timeout: int = 300
) -> List[Dict]:
    """
    Test target for XSS vulnerabilities using Dalfox.

    Dalfox can operate in different modes:
    - url: Test a single URL with parameters
    - pipe: Test URLs from stdin (for bulk scanning)
    - file: Test URLs from a file
    - sxss: Stored XSS mode (slower but more thorough)

    For bug bounty, we use 'url' mode for targeted testing.

    Args:
        target: Target URL to test (e.g., "https://example.com/search?q=test")
        scan_id: Database ID of the parent scan
        mode: Scanning mode (default: "url")
        timeout: Maximum scan duration in seconds

    Returns:
        List of XSS findings with details

    Example:
        findings = test_xss_vulnerabilities(
            target="https://example.com/search?q=test",
            scan_id=1
        )
    """

    # Create output directory
    output_dir = Path(f"/tmp/bountybot/dalfox/scan_{scan_id}")
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / "dalfox_results.json"

    # Build Dalfox command
    cmd = [
        "dalfox",
        "url",  # URL mode
        target,  # Target URL
        "--output",
        str(output_file),  # JSON output file
        "--format",
        "json",  # Output format
        "--silence",  # Suppress banner/progress
        "--no-color",  # No ANSI colors in output
        "--no-spinner",  # No loading spinner
        "--worker",
        "10",  # Parallel workers (faster)
        "--delay",
        "100",  # Delay between requests (ms)
        "--timeout",
        "10",  # Request timeout (seconds)
    ]

    # Add common XSS testing options
    cmd.extend(
        [
            "--skip-bav",  # Skip BAV (Blind XSS) - faster for basic testing
            "--follow-redirects",  # Follow HTTP redirects
            "--mining-dict",  # Use mining dictionary for parameter discovery
        ]
    )

    print(f"[*] Running Dalfox XSS scan on {target}")
    print(f"[*] Testing for Reflected, DOM, and Stored XSS...")

    try:
        # Execute Dalfox
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )

        # Dalfox returns exit code 0 even when XSS is found
        # We check the output file for results
        if output_file.exists() and output_file.stat().st_size > 0:
            findings = parse_dalfox_output(output_file, target, scan_id)

            if findings:
                print(f"[+] Found {len(findings)} XSS vulnerabilities!")
            else:
                print(f"[*] No XSS vulnerabilities detected")

            return findings
        else:
            print(f"[*] No XSS vulnerabilities detected (no output file)")
            return []

    except subprocess.TimeoutExpired:
        print(f"[!] Dalfox scan timed out after {timeout} seconds")
        return []
    except Exception as e:
        print(f"[!] Error running Dalfox: {e}")
        return []


def parse_dalfox_output(output_file: Path, target: str, scan_id: int) -> List[Dict]:
    """
    Parse Dalfox JSON output to extract XSS findings.

    Dalfox outputs JSONL format (one JSON object per line).
    Each finding contains:
    - type: XSS type (reflected, stored, dom)
    - poc: Proof of concept payload
    - param: Vulnerable parameter name
    - evidence: HTML snippet showing XSS

    Args:
        output_file: Path to Dalfox JSON output
        target: Original target URL
        scan_id: Scan ID

    Returns:
        List of XSS findings
    """

    findings = []

    try:
        with open(output_file, "r") as f:
            for line in f:
                if not line.strip():
                    continue

                try:
                    result = json.loads(line)

                    # Skip non-vulnerability entries (info messages, etc.)
                    if "type" not in result or "param" not in result:
                        continue

                    # Extract XSS information
                    xss_type = result.get("type", "unknown")
                    param = result.get("param", "unknown")
                    poc = result.get("poc", "")
                    evidence = result.get("evidence", "")
                    message = result.get("message", "")

                    # Determine severity
                    # Reflected XSS = High (immediate exploitation)
                    # Stored XSS = Critical (persistent)
                    # DOM XSS = Medium (requires user interaction)
                    severity_map = {
                        "stored": "critical",
                        "reflected": "high",
                        "dom": "medium",
                        "unknown": "medium",
                    }
                    severity = severity_map.get(xss_type.lower(), "medium")

                    # Build finding title
                    title = f"[Dalfox] {xss_type.upper()} XSS in '{param}' parameter"

                    # Build description
                    description = f"""
**Cross-Site Scripting (XSS) Detected**

**XSS Type:** {xss_type.upper()}
**Vulnerable Parameter:** {param}
**Target URL:** {target}

**Attack Description:**
{message if message else "XSS vulnerability allows injection of malicious JavaScript code."}

**Impact:**
- Steal user session cookies and authentication tokens
- Perform actions on behalf of the victim
- Redirect users to malicious websites
- Modify page content to phish credentials
- Execute keyloggers to capture sensitive data

**Exploitation Complexity:** Low
**Authentication Required:** No (typically)
**User Interaction Required:** {"Yes (victim must visit crafted URL)" if xss_type.lower() == "reflected" else "No (payload is stored)"}
"""

                    # Build proof of concept
                    poc_section = f"""
**Working Payload:**
```html
{poc}
```

**Evidence (HTML Response):**
```html
{evidence[:500]}...
```

**Steps to Reproduce:**
1. Navigate to the vulnerable URL: {target}
2. Inject the payload into parameter '{param}'
3. Submit the request
4. Observe JavaScript execution in the browser

**Expected Behavior:**
The payload should execute in the browser context, potentially showing an alert box or executing arbitrary JavaScript.

**Remediation:**
1. **Input Validation:** Sanitize all user inputs on the server side
2. **Output Encoding:** Encode all data before rendering in HTML context
   - HTML Entity Encoding: `&lt;` instead of `<`
   - JavaScript Encoding for JS contexts
   - URL Encoding for URLs
3. **Content Security Policy (CSP):** Implement strict CSP headers
```
   Content-Security-Policy: default-src 'self'; script-src 'self'
```
4. **HTTPOnly Cookies:** Prevent JavaScript access to session cookies
```
   Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Strict
```
5. **Modern Framework:** Use frameworks with built-in XSS protection (React, Vue, Angular)
"""

                    finding = {
                        "scan_id": scan_id,
                        "title": title,
                        "severity": severity,
                        "description": description.strip(),
                        "proof_of_concept": poc_section.strip(),
                        "tool": "dalfox",
                        "raw_output": json.dumps(result, indent=2),
                    }

                    findings.append(finding)
                    print(
                        f"[+] XSS Found: {xss_type.upper()} in '{param}' ({severity.upper()})"
                    )

                except json.JSONDecodeError:
                    # Skip non-JSON lines (progress messages, etc.)
                    continue

        print(f"[*] Parsed {len(findings)} XSS findings from Dalfox output")
        return findings

    except Exception as e:
        print(f"[!] Error parsing Dalfox output: {e}")
        return []


def get_dalfox_stats() -> Dict:
    """
    Get Dalfox installation statistics.

    Returns:
        Dictionary with Dalfox version and status
    """

    try:
        result = subprocess.run(
            ["dalfox", "version"], capture_output=True, text=True, check=False
        )

        # Extract version from output
        # Output format: "v2.12.0"
        version_line = result.stdout.strip().split("\n")[-1]

        return {"version": version_line, "status": "installed"}

    except Exception as e:
        return {"version": "unknown", "status": f"error: {e}"}
