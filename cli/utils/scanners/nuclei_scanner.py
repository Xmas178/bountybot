"""
Nuclei vulnerability scanner integration.

Nuclei is a fast, template-based vulnerability scanner that can detect:
- CVEs (Common Vulnerabilities and Exposures)
- Misconfigurations
- Exposed panels and debugging endpoints
- Security weaknesses using YAML templates

This module runs nuclei scans and parses JSON output into Finding objects.
"""

import subprocess
import json
import os
from pathlib import Path
from typing import List, Dict, Optional
from django.utils import timezone
from cli.utils.config import get_output_dir


def run_nuclei_scan(
    target: str,
    scan_id: int,
    severity: Optional[List[str]] = None,
    tags: Optional[List[str]] = None,
    templates: Optional[List[str]] = None,
    timeout: int = 300,
) -> List[Dict]:
    """
    Run nuclei vulnerability scan against a target.

    Nuclei uses YAML templates to detect vulnerabilities. By default, it runs
    all templates unless filtered by severity, tags, or specific templates.

    Args:
        target: Target URL or IP (e.g., "https://example.com" or "192.168.1.1")
        scan_id: Database ID of the parent scan
        severity: Filter by severity levels (e.g., ["critical", "high"])
        tags: Filter by tags (e.g., ["cve", "xss"])
        templates: Specific template files to run
        timeout: Maximum scan duration in seconds (default: 5 minutes)

    Returns:
        List of findings as dictionaries with vulnerability details

    Example:
        findings = run_nuclei_scan(
            target="https://example.com",
            scan_id=1,
            severity=["critical", "high"]
        )
    """

    # Create output directory for scan results
    output_dir = get_output_dir() / "nuclei" / f"scan_{scan_id}"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / "nuclei_results.json"

    # Build nuclei command with JSON output
    cmd = [
        "nuclei",
        "-u",
        target,  # Target URL
        "-json",  # Output in JSON format for parsing
        "-o",
        str(output_file),  # Save results to file
        "-silent",  # Suppress unnecessary output
        "-rate-limit",
        "150",  # Requests per second (default: 150)
    ]

    # Add severity filter if specified
    # Example: -severity critical,high
    if severity:
        cmd.extend(["-severity", ",".join(severity)])

    # Add tag filter if specified
    # Example: -tags cve,xss,sqli
    if tags:
        cmd.extend(["-tags", ",".join(tags)])

    # Add specific templates if specified
    # Example: -templates /path/to/template.yaml
    if templates:
        for template in templates:
            cmd.extend(["-templates", template])

    print(f"[*] Running nuclei scan on {target}")
    print(f"[*] Command: {' '.join(cmd)}")

    try:
        # Execute nuclei scan
        # timeout ensures scan doesn't run forever
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,  # Don't raise exception on non-zero exit
        )

        # Nuclei exit codes:
        # 0 = Success, no vulnerabilities found
        # 1 = Vulnerabilities found (expected)
        # 2 = No templates run / no matches (not an error)
        if result.returncode not in [0, 1, 2]:
            print(f"[!] Nuclei scan failed with exit code {result.returncode}")
            print(f"[!] Error: {result.stderr}")
            return []

        # Exit code 2 means no templates matched - this is OK
        if result.returncode == 2:
            print(f"[*] No nuclei templates matched for this target (exit code 2)")

        # Parse JSON output file
        if output_file.exists():
            return parse_nuclei_output(output_file, scan_id)
        else:
            print(f"[!] No output file generated: {output_file}")
            return []

    except subprocess.TimeoutExpired:
        print(f"[!] Nuclei scan timed out after {timeout} seconds")
        return []
    except Exception as e:
        print(f"[!] Error running nuclei scan: {e}")
        return []


def parse_nuclei_output(output_file: Path, scan_id: int) -> List[Dict]:
    """
    Parse nuclei JSON output into Finding objects.

    Nuclei outputs one JSON object per line (JSONL format).
    Each object contains vulnerability details like:
    - template-id: Unique identifier for the template
    - info: Metadata (name, severity, description, tags)
    - matched-at: Where the vulnerability was found
    - curl-command: Exact request that triggered the finding

    Args:
        output_file: Path to nuclei JSON output file
        scan_id: Database ID of the parent scan

    Returns:
        List of findings as dictionaries ready for database insertion
    """

    findings = []

    try:
        with open(output_file, "r") as f:
            for line in f:
                # Skip empty lines
                if not line.strip():
                    continue

                try:
                    # Parse JSON line
                    result = json.loads(line)

                    # Extract vulnerability information
                    template_id = result.get("template-id", "unknown")
                    info = result.get("info", {})
                    matched_at = result.get("matched-at", result.get("host", ""))

                    # Get severity level (critical, high, medium, low, info)
                    severity = info.get("severity", "info").lower()

                    # Map nuclei severity to our database severity
                    severity_map = {
                        "critical": "critical",
                        "high": "high",
                        "medium": "medium",
                        "low": "low",
                        "info": "info",
                        "unknown": "info",
                    }
                    db_severity = severity_map.get(severity, "info")

                    # Build finding title
                    title = f"[Nuclei] {info.get('name', template_id)}"

                    # Build detailed description
                    description = f"""
**Template ID:** {template_id}
**Severity:** {severity.upper()}
**Matched At:** {matched_at}

**Description:**
{info.get('description', 'No description available')}

**Tags:** {', '.join(info.get('tags', []))}

**Reference:**
{info.get('reference', 'No reference available')}

**Classification:**
{json.dumps(info.get('classification', {}), indent=2)}
"""

                    # Get curl command for PoC (Proof of Concept)
                    curl_command = result.get("curl-command", "")

                    # Build PoC section
                    poc = ""
                    if curl_command:
                        poc = f"""
**Proof of Concept:**
```bash
{curl_command}
```

**Raw Request:**
{result.get('request', 'Not available')}

**Response:**
{result.get('response', 'Not available')}
"""

                    # Create finding dictionary
                    finding = {
                        "scan_id": scan_id,
                        "title": title,
                        "severity": db_severity,
                        "description": description.strip(),
                        "proof_of_concept": poc.strip() if poc else None,
                        "tool": "nuclei",
                        "raw_output": json.dumps(result, indent=2),
                        "discovered_at": timezone.now(),
                    }

                    findings.append(finding)

                    # Print finding summary
                    print(f"[+] Found: {title} ({db_severity.upper()})")

                except json.JSONDecodeError as e:
                    print(f"[!] Failed to parse JSON line: {e}")
                    continue

        print(f"[*] Parsed {len(findings)} findings from nuclei output")
        return findings

    except Exception as e:
        print(f"[!] Error parsing nuclei output: {e}")
        return []


def get_nuclei_stats() -> Dict:
    """
    Get nuclei installation statistics.

    Returns information about:
    - Nuclei version
    - Number of templates available
    - Template update status

    Returns:
        Dictionary with nuclei statistics
    """

    try:
        # Get nuclei version
        version_result = subprocess.run(
            ["nuclei", "-version"], capture_output=True, text=True, check=False
        )

        # Get template count
        template_result = subprocess.run(
            ["nuclei", "-tl"],  # Template list
            capture_output=True,
            text=True,
            check=False,
        )

        # Count templates (each line is a template)
        template_count = len(template_result.stdout.strip().split("\n"))

        return {
            "version": version_result.stdout.strip(),
            "template_count": template_count,
            "status": "installed",
        }

    except Exception as e:
        return {"version": "unknown", "template_count": 0, "status": f"error: {e}"}
