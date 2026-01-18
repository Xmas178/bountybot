"""
FFuf (Fuzz Faster U Fool) web fuzzer integration.

FFuf is a fast web fuzzer used to discover:
- Hidden directories and files
- Backup files (.bak, .old, .backup)
- Configuration files (.env, config.php)
- API endpoints and versions
- Admin panels and debugging interfaces
- Source code exposure (.git, .svn)

FFuf is extremely fast (1000+ req/s) making it ideal for
comprehensive directory and file enumeration.
"""

import subprocess
import json
from pathlib import Path
from typing import List, Dict, Optional
from cli.utils.config import get_output_dir


def fuzz_directories(
    target: str,
    scan_id: int,
    wordlist: str = "common",
    max_time: int = 300,
    threads: int = 40,
) -> List[Dict]:
    """
    Fuzz web directories and files using FFuf.

    FFuf tests thousands of paths to discover hidden resources.
    Common findings include:
    - /admin/, /backup/, /test/
    - config.php, .env, database.sql
    - .git/, .svn/, .DS_Store

    Args:
        target: Target URL (e.g., "https://example.com")
        scan_id: Database ID of the parent scan
        wordlist: Wordlist to use ("common", "medium", "large")
        max_time: Maximum scan duration in seconds (default: 5 minutes)
        threads: Number of parallel threads (default: 40)

    Returns:
        List of discovered paths/files

    Example:
        findings = fuzz_directories(
            target="https://example.com",
            scan_id=1,
            wordlist="common"
        )
    """

    # Create output directory
    output_dir = get_output_dir() / "ffuf" / f"scan_{scan_id}"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / "ffuf_results.json"

    # Select wordlist based on size
    # We'll use SecLists if available, otherwise skip
    wordlist_paths = {
        "common": "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "medium": "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
        "large": "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt",
    }

    wordlist_path = wordlist_paths.get(wordlist, wordlist_paths["common"])

    # Check if wordlist exists
    if not Path(wordlist_path).exists():
        print(f"[!] Wordlist not found: {wordlist_path}")
        print(f"[*] Install SecLists: sudo apt install seclists")
        return []

    # Build FFuf command
    # FUZZ keyword will be replaced with wordlist entries
    target_url = target.rstrip("/") + "/FUZZ"

    cmd = [
        "ffuf",
        "-u",
        target_url,  # Target URL with FUZZ placeholder
        "-w",
        wordlist_path,  # Wordlist file
        "-o",
        str(output_file),  # Output file
        "-of",
        "json",  # JSON format
        "-t",
        str(threads),  # Threads (parallel requests)
        "-maxtime",
        str(max_time),  # Max scan time
        "-ac",  # Auto-calibrate filtering
        "-mc",
        "200,204,301,302,307,401,403",  # Match HTTP codes
        "-fs",
        "0",  # Filter size 0 (empty responses)
        "-noninteractive",  # No interactive mode
        "-v",  # Verbose errors
    ]

    # Add rate limiting to avoid overwhelming server
    cmd.extend(["-rate", "100"])  # Max 100 requests/second

    print(f"[*] Running FFuf directory fuzzing on {target}")
    print(f"[*] Wordlist: {wordlist} ({Path(wordlist_path).name})")
    print(f"[*] This may take 2-5 minutes...")

    try:
        # Execute FFuf
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=max_time + 60,  # Add buffer to timeout
            check=False,
        )

        # FFuf returns 0 on success
        if output_file.exists() and output_file.stat().st_size > 0:
            findings = parse_ffuf_output(output_file, target, scan_id)

            if findings:
                print(f"[+] Found {len(findings)} hidden paths/files!")
            else:
                print(f"[*] No hidden directories or files discovered")

            return findings
        else:
            print(f"[*] No paths discovered (output file empty or missing)")
            return []

    except subprocess.TimeoutExpired:
        print(f"[!] FFuf scan timed out after {max_time} seconds")
        return []
    except Exception as e:
        print(f"[!] Error running FFuf: {e}")
        return []


def parse_ffuf_output(output_file: Path, target: str, scan_id: int) -> List[Dict]:
    """
    Parse FFuf JSON output to extract discovered paths.

    FFuf outputs JSON with structure:
    {
      "results": [
        {
          "input": {"FUZZ": "admin"},
          "position": 1,
          "status": 200,
          "length": 1234,
          "words": 45,
          "lines": 23,
          "url": "https://example.com/admin"
        }
      ]
    }

    Args:
        output_file: Path to FFuf JSON output
        target: Original target URL
        scan_id: Scan ID

    Returns:
        List of discovered path findings
    """

    findings = []

    try:
        with open(output_file, "r") as f:
            data = json.load(f)

        results = data.get("results", [])

        if not results:
            print(f"[*] No results in FFuf output")
            return []

        for result in results:
            url = result.get("url", "")
            status = result.get("status", 0)
            length = result.get("length", 0)
            words = result.get("words", 0)

            # Extract path from URL
            path = url.replace(target.rstrip("/"), "")

            # Determine severity based on path
            severity = determine_path_severity(path, status)

            # Build finding title
            title = f"[FFuf] Discovered: {path} (HTTP {status})"

            # Build description
            description = f"""
**Hidden Resource Discovered**

**Path:** {path}
**Full URL:** {url}
**HTTP Status:** {status}
**Content Length:** {length} bytes
**Word Count:** {words}

**Discovery Method:**
FFuf directory/file fuzzing discovered this resource that is not publicly linked
but accessible when the direct path is known.

**Security Implications:**
{get_path_implications(path, status)}

**Risk Level:** {severity.upper()}
"""

            # Build proof of concept
            poc = f"""
**Discovered URL:**
{url}

**Access:**
1. Navigate to: {url}
2. Observe the response (HTTP {status})
3. Analyze content for sensitive information

**HTTP Status Meaning:**
{get_status_meaning(status)}

**Recommended Actions:**
{get_path_recommendations(path, status)}

**References:**
- OWASP: Forced Browsing
- CWE-548: Directory Indexing
"""

            finding = {
                "scan_id": scan_id,
                "title": title,
                "severity": severity,
                "description": description.strip(),
                "proof_of_concept": poc.strip(),
                "tool": "ffuf",
                "raw_output": json.dumps(result, indent=2),
            }

            findings.append(finding)
            print(f"[+] Found: {path} (HTTP {status}) - {severity.upper()}")

        print(f"[*] Parsed {len(findings)} paths from FFuf output")
        return findings

    except json.JSONDecodeError as e:
        print(f"[!] Failed to parse FFuf JSON: {e}")
        return []
    except Exception as e:
        print(f"[!] Error parsing FFuf output: {e}")
        return []


def determine_path_severity(path: str, status: int) -> str:
    """Determine severity based on discovered path and status code."""

    path_lower = path.lower()

    # Critical - Sensitive file exposure
    if any(
        pattern in path_lower
        for pattern in [
            ".git/",
            ".env",
            "config.php",
            "database",
            "backup.sql",
            "wp-config",
            "credentials",
            "password",
            ".aws",
        ]
    ):
        return "high"

    # High - Admin/control panels
    if any(
        pattern in path_lower
        for pattern in [
            "admin",
            "phpmyadmin",
            "cpanel",
            "manager",
            "console",
            "dashboard",
            "panel",
        ]
    ):
        return "high" if status == 200 else "medium"

    # Medium - Potentially sensitive
    if any(
        pattern in path_lower
        for pattern in [
            "backup",
            "test",
            "dev",
            "staging",
            "old",
            "tmp",
            "temp",
            "debug",
            "api",
        ]
    ):
        return "medium"

    # Low - Directory listing or redirects
    if status in [301, 302, 307, 403]:
        return "low"

    # Info - Generic paths
    return "info"


def get_path_implications(path: str, status: int) -> str:
    """Get security implications based on discovered path."""

    path_lower = path.lower()

    if ".git" in path_lower:
        return "Exposed .git directory can leak entire source code, credentials, and development history."
    elif ".env" in path_lower:
        return "Environment file exposure reveals API keys, database credentials, and sensitive configuration."
    elif "admin" in path_lower:
        return "Admin interface exposure may allow unauthorized access to administrative functions."
    elif "backup" in path_lower:
        return "Backup files may contain sensitive data, old vulnerabilities, or credentials."
    elif status == 403:
        return "Path exists but access is forbidden. May be exploitable through authorization bypass."
    else:
        return "Hidden resource that is not meant to be publicly accessible."


def get_status_meaning(status: int) -> str:
    """Get HTTP status code meaning."""

    meanings = {
        200: "OK - Resource is accessible",
        204: "No Content - Resource exists but returns no content",
        301: "Moved Permanently - Resource has been relocated",
        302: "Found - Temporary redirect",
        307: "Temporary Redirect",
        401: "Unauthorized - Authentication required",
        403: "Forbidden - Access denied (resource exists)",
        404: "Not Found - Resource does not exist",
    }

    return meanings.get(status, f"HTTP {status}")


def get_path_recommendations(path: str, status: int) -> str:
    """Get recommendations based on discovered path."""

    path_lower = path.lower()

    if ".git" in path_lower:
        return "1. Remove .git directory from production\n2. Add .git to web server deny rules"
    elif ".env" in path_lower:
        return "1. Move .env outside webroot\n2. Deny access via .htaccess/nginx config"
    elif "admin" in path_lower:
        return "1. Implement IP whitelisting\n2. Require strong authentication\n3. Use non-standard paths"
    elif "backup" in path_lower:
        return "1. Remove backup files from web-accessible directories\n2. Store backups securely"
    else:
        return "1. Review if this resource should be publicly accessible\n2. Implement proper access controls"


def get_ffuf_stats() -> Dict:
    """Get FFuf installation statistics."""

    try:
        result = subprocess.run(
            ["ffuf", "-V"], capture_output=True, text=True, check=False, timeout=5
        )

        version = result.stdout.strip()

        return {"version": version, "status": "installed"}

    except Exception as e:
        return {"version": "unknown", "status": f"error: {e}"}
