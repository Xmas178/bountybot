"""
SQLMap SQL injection testing integration.

SQLMap is an automated SQL injection detection and exploitation tool.
It can detect and exploit SQL injection vulnerabilities in:
- GET parameters
- POST data
- HTTP headers (Cookie, User-Agent, Referer)
- REST/JSON APIs

This module runs SQLMap in safe mode (level 1, risk 1) to avoid
damaging production systems while still detecting vulnerabilities.
"""

import subprocess
import json
import re
from pathlib import Path
from typing import List, Dict, Optional
from cli.utils.config import get_output_dir


def test_sql_injection(
    target: str,
    scan_id: int,
    level: int = 1,
    risk: int = 1,
    dbms: Optional[str] = None,
    timeout: int = 300,
) -> List[Dict]:
    """
    Test target for SQL injection vulnerabilities using SQLMap.

    SQLMap testing levels:
    - Level 1: Basic tests (fastest)
    - Level 2: Cookie injection tests
    - Level 3: User-Agent header tests
    - Level 4: Referer header tests
    - Level 5: Comprehensive (slowest)

    Risk levels:
    - Risk 1: Safe (default, no OR-based queries)
    - Risk 2: Add heavy query time-based tests
    - Risk 3: Add OR-based SQL injection tests (can modify data!)

    For bug bounty, we use level=1 risk=1 to stay safe.

    Args:
        target: Target URL to test (e.g., "https://example.com/login?id=1")
        scan_id: Database ID of the parent scan
        level: Detection level (1-5, default: 1)
        risk: Risk level (1-3, default: 1)
        timeout: Maximum scan duration in seconds

    Returns:
        List of findings with SQL injection details

    Example:
        findings = test_sql_injection(
            target="https://example.com/product?id=1",
            scan_id=1
        )
    """

    # Create output directory
    output_dir = get_output_dir() / "sqlmap" / f"scan_{scan_id}"
    output_dir.mkdir(parents=True, exist_ok=True)

    # SQLMap output files
    output_file = output_dir / "sqlmap_output.txt"
    log_file = output_dir / "sqlmap.log"

    # Build SQLMap command
    cmd = [
        "sqlmap",
        "-u",
        target,  # Target URL
        "--batch",  # Never ask for user input (automated)
        "--random-agent",  # Use random User-Agent
        "--level",
        str(level),  # Detection thoroughness
        "--risk",
        str(risk),  # Risk level
        "--output-dir",
        str(output_dir),  # Save results
        "--flush-session",  # Don't reuse previous session data
        "--threads",
        "5",  # Parallel requests (faster)
        "--technique=BEUSTQ",  # All SQL injection techniques
        # B = Boolean-based blind
        # E = Error-based
        # U = Union query-based
        # S = Stacked queries
        # T = Time-based blind
        # Q = Inline queries
    ]
    # Add DBMS if detected from WhatWeb
    if dbms:
        cmd.extend(["--dbms", dbms])

    # Add timeout handling
    cmd.extend(["--timeout", "30"])  # 30s per request timeout

    print(f"[*] Running SQLMap SQL injection test on {target}")
    print(f"[*] Level: {level}, Risk: {risk}")
    print(f"[*] This may take 2-5 minutes...")

    try:
        # Execute SQLMap
        # We redirect output to file because SQLMap output is very verbose
        with open(output_file, "w") as out_f:
            result = subprocess.run(
                cmd,
                stdout=out_f,
                stderr=subprocess.PIPE,
                timeout=timeout,
                check=False,
                text=True,
            )

        # Parse SQLMap output
        if output_file.exists():
            findings = parse_sqlmap_output(output_file, target, scan_id)

            if findings:
                print(f"[+] Found {len(findings)} SQL injection vulnerabilities!")
            else:
                print(f"[*] No SQL injection vulnerabilities detected")

            return findings
        else:
            print(f"[!] No SQLMap output file generated")
            return []

    except subprocess.TimeoutExpired:
        print(f"[!] SQLMap scan timed out after {timeout} seconds")
        return []
    except Exception as e:
        print(f"[!] Error running SQLMap: {e}")
        return []


def parse_sqlmap_output(output_file: Path, target: str, scan_id: int) -> List[Dict]:
    """
    Parse SQLMap text output to extract SQL injection findings.

    SQLMap output contains sections like:
    - Parameter: id (GET)
    - Type: boolean-based blind
    - Title: AND boolean-based blind - WHERE or HAVING clause
    - Payload: id=1 AND 1234=1234
    - Backend DBMS: MySQL
    - OS: Linux Ubuntu

    Args:
        output_file: Path to SQLMap output text file
        target: Original target URL
        scan_id: Scan ID

    Returns:
        List of SQL injection findings
    """

    findings = []

    try:
        with open(output_file, "r") as f:
            output = f.read()

        # Check if any parameter is injectable
        if "Parameter:" not in output or "is not injectable" in output.lower():
            print(f"[*] No injectable parameters found in {target}")
            return []

        # Extract vulnerable parameters
        # Pattern: "Parameter: id (GET)" or "Parameter: username (POST)"
        param_pattern = r"Parameter:\s+([^\(]+)\s+\(([^\)]+)\)"
        param_matches = re.findall(param_pattern, output)

        # Extract injection types
        # Pattern: "Type: boolean-based blind"
        type_pattern = r"Type:\s+(.+?)(?:\n|$)"
        type_matches = re.findall(type_pattern, output)

        # Extract titles (technique description)
        title_pattern = r"Title:\s+(.+?)(?:\n|$)"
        title_matches = re.findall(title_pattern, output)

        # Extract payloads
        payload_pattern = r"Payload:\s+(.+?)(?:\n|$)"
        payload_matches = re.findall(payload_pattern, output)

        # Extract backend DBMS
        dbms_pattern = r"back-end DBMS:\s+(.+?)(?:\n|$)"
        dbms_match = re.search(dbms_pattern, output, re.IGNORECASE)
        dbms = dbms_match.group(1).strip() if dbms_match else "Unknown"

        # Extract OS if available
        os_pattern = r"(?:web server operating system|OS):\s+(.+?)(?:\n|$)"
        os_match = re.search(os_pattern, output, re.IGNORECASE)
        os_info = os_match.group(1).strip() if os_match else "Unknown"

        # Build findings from extracted data
        for i, (param_name, param_type) in enumerate(param_matches):
            param_name = param_name.strip()
            param_type = param_type.strip()

            # Get corresponding injection details
            injection_type = type_matches[i] if i < len(type_matches) else "Unknown"
            title = title_matches[i] if i < len(title_matches) else "SQL Injection"
            payload = payload_matches[i] if i < len(payload_matches) else "N/A"

            # Determine severity based on injection type
            # Time-based and boolean-based are typically exploitable
            if "union" in injection_type.lower() or "error" in injection_type.lower():
                severity = "high"  # Direct data extraction possible
            elif "time-based" in injection_type.lower():
                severity = "medium"  # Slower exploitation
            elif "boolean" in injection_type.lower():
                severity = "medium"  # Slower exploitation
            else:
                severity = "low"

            # Build finding description
            description = f"""
**SQL Injection Detected**

**Vulnerable Parameter:** {param_name} ({param_type})
**Injection Type:** {injection_type}
**Technique:** {title}

**Backend Database:** {dbms}
**Operating System:** {os_info}

**Impact:**
This SQL injection vulnerability allows an attacker to:
- Extract sensitive data from the database
- Bypass authentication
- Modify or delete database records
- Potentially gain remote code execution

**Exploitation Complexity:** Medium
**Authentication Required:** No
"""

            # Build proof of concept
            poc = f"""
**Vulnerable URL:**
{target}

**Vulnerable Parameter:** {param_name} ({param_type})

**Working Payload:**
```
{payload}
```

**SQLMap Command for Verification:**
```bash
sqlmap -u "{target}" --batch --level 1 --risk 1
```

**Expected Behavior:**
SQLMap should detect {injection_type} SQL injection and confirm backend is {dbms}.

**Remediation:**
1. Use parameterized queries / prepared statements
2. Input validation and sanitization
3. Principle of least privilege for database users
4. Web Application Firewall (WAF) as additional layer
"""

            finding = {
                "scan_id": scan_id,
                "title": f"[SQLMap] SQL Injection in '{param_name}' parameter",
                "severity": severity,
                "description": description.strip(),
                "proof_of_concept": poc.strip(),
                "tool": "sqlmap",
                "raw_output": output[:5000],  # First 5000 chars only
            }

            findings.append(finding)
            print(f"[+] SQL Injection: {param_name} ({param_type}) - {injection_type}")

        return findings

    except Exception as e:
        print(f"[!] Error parsing SQLMap output: {e}")
        return []


def get_sqlmap_stats() -> Dict:
    """
    Get SQLMap installation statistics.

    Returns:
        Dictionary with SQLMap version and status
    """

    try:
        result = subprocess.run(
            ["sqlmap", "--version"], capture_output=True, text=True, check=False
        )

        # Extract version from output
        version_line = result.stdout.strip().split("\n")[0]

        return {"version": version_line, "status": "installed"}

    except Exception as e:
        return {"version": "unknown", "status": f"error: {e}"}
