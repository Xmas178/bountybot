"""
WhatWeb technology detection integration.

WhatWeb identifies web technologies including:
- Content Management Systems (WordPress, Joomla, Drupal)
- Programming languages (PHP, Python, Ruby, Java)
- Web servers (Apache, nginx, IIS)
- Frameworks (Django, Laravel, React, Vue)
- Analytics tools (Google Analytics, Matomo)
- And 1800+ other technologies

This is more comprehensive than httpx basic detection.
"""

import subprocess
import json
from typing import List, Dict, Optional
from pathlib import Path
from cli.utils.config import get_output_dir


def detect_technologies(
    target: str, scan_id: int, aggression: int = 1, timeout: int = 60
) -> Dict:
    """
    Run WhatWeb technology detection on a target.

    WhatWeb uses plugins to identify technologies. Each plugin can detect
    specific software versions, configurations, and characteristics.

    Args:
        target: Target URL (e.g., "https://example.com")
        scan_id: Database ID of the parent scan
        aggression: Detection level 1-4 (1=passive, 4=aggressive)
                   Level 1: Single GET request (fastest, least intrusive)
                   Level 2: Follow redirects
                   Level 3: Check common paths (/admin, /login)
                   Level 4: Brute force (slowest, most thorough)
        timeout: Maximum scan duration in seconds

    Returns:
        Dictionary with detected technologies and metadata

    Example:
        result = detect_technologies(
            target="https://example.com",
            scan_id=1,
            aggression=1
        )

        # result = {
        #     "target": "https://example.com",
        #     "technologies": {
        #         "WordPress": {"version": "5.2.1"},
        #         "Apache": {"version": "2.4.41"},
        #         "PHP": {"version": "7.4"}
        #     },
        #     "http_status": 200,
        #     "plugins_matched": 5
        # }
    """

    # Create output directory
    output_dir = get_output_dir() / "whatweb" / f"scan_{scan_id}"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / "whatweb_results.json"

    # Build WhatWeb command
    cmd = [
        "whatweb",
        target,
        "--aggression",
        str(aggression),  # Detection level
        "--log-json",
        str(output_file),  # JSON output
        "--color=never",  # No color codes in output
        "--no-errors",  # Suppress error messages
    ]

    print(f"[*] Running WhatWeb technology detection on {target}")
    print(f"[*] Aggression level: {aggression}/4")

    try:
        # Execute WhatWeb
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )

        # Parse JSON output
        if output_file.exists():
            return parse_whatweb_output(output_file, target)
        else:
            print(f"[!] No WhatWeb output file generated")
            return {"target": target, "technologies": {}, "error": "No output"}

    except subprocess.TimeoutExpired:
        print(f"[!] WhatWeb scan timed out after {timeout} seconds")
        return {"target": target, "technologies": {}, "error": "Timeout"}
    except Exception as e:
        print(f"[!] Error running WhatWeb: {e}")
        return {"target": target, "technologies": {}, "error": str(e)}


def parse_whatweb_output(output_file: Path, target: str) -> Dict:
    """
    Parse WhatWeb JSON output into structured technology data.

    WhatWeb outputs JSON array with one object per target.
    Each object contains:
    - target: URL that was scanned
    - http_status: Response status code
    - plugins: Dictionary of detected technologies

    Args:
        output_file: Path to WhatWeb JSON output
        target: Original target URL

    Returns:
        Dictionary with parsed technology information
    """

    try:
        # WhatWeb outputs JSONL format (one JSON object per line)
        # Read all lines and parse each separately
        results = []
        with open(output_file, "r") as f:
            for line in f:
                if line.strip():
                    try:
                        results.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

        # Get first valid result
        if not results or len(results) == 0:
            return {"target": target, "technologies": {}}

        result = results[0]

        # Extract detected plugins (technologies)
        plugins = result.get("plugins", {})
        technologies = {}

        # Process each detected plugin
        for plugin_name, plugin_data in plugins.items():
            # Skip generic plugins
            if plugin_name in ["IP", "Country", "HTTPServer"]:
                continue

            tech_info = {}

            # Extract version if available
            if "version" in plugin_data:
                versions = plugin_data["version"]
                if isinstance(versions, list) and len(versions) > 0:
                    tech_info["version"] = versions[0]
                elif isinstance(versions, str):
                    tech_info["version"] = versions

            # Extract other metadata
            if "string" in plugin_data:
                strings = plugin_data["string"]
                if isinstance(strings, list) and len(strings) > 0:
                    tech_info["details"] = strings
                elif isinstance(strings, str):
                    tech_info["details"] = [strings]

            # Extract categories/accounts
            if "account" in plugin_data:
                tech_info["accounts"] = plugin_data["account"]

            if "module" in plugin_data:
                tech_info["modules"] = plugin_data["module"]

            # Only add if we found useful info
            if tech_info or plugin_name:
                technologies[plugin_name] = (
                    tech_info if tech_info else {"detected": True}
                )

        # Build summary
        summary = {
            "target": result.get("target", target),
            "http_status": result.get("http_status"),
            "request_config": result.get("request_config", {}),
            "technologies": technologies,
            "plugins_matched": len(technologies),
            "raw_plugins": plugins,  # Keep raw data for reference
        }

        # Print summary
        print(f"[+] Detected {len(technologies)} technologies on {target}")
        for tech_name, tech_info in technologies.items():
            version = tech_info.get("version", "")
            version_str = f" v{version}" if version else ""
            print(f"    - {tech_name}{version_str}")

        return summary

    except json.JSONDecodeError as e:
        print(f"[!] Failed to parse WhatWeb JSON: {e}")
        return {"target": target, "technologies": {}, "error": "JSON parse error"}
    except Exception as e:
        print(f"[!] Error parsing WhatWeb output: {e}")
        return {"target": target, "technologies": {}, "error": str(e)}


def format_technologies_for_finding(tech_data: Dict) -> str:
    """
    Format detected technologies into a human-readable finding description.

    Args:
        tech_data: Technology data from parse_whatweb_output()

    Returns:
        Formatted markdown string for Finding description
    """

    technologies = tech_data.get("technologies", {})

    if not technologies:
        return "No specific technologies detected."

    description = f"**Target:** {tech_data.get('target')}\n"
    description += f"**HTTP Status:** {tech_data.get('http_status')}\n"
    description += (
        f"**Technologies Detected:** {tech_data.get('plugins_matched', 0)}\n\n"
    )

    # Categorize technologies
    cms_list = []
    server_list = []
    framework_list = []
    other_list = []

    for tech_name, tech_info in technologies.items():
        version = tech_info.get("version", "")
        version_str = f" v{version}" if version else ""
        tech_entry = f"{tech_name}{version_str}"

        # Categorize based on common tech types
        tech_lower = tech_name.lower()

        if any(cms in tech_lower for cms in ["wordpress", "joomla", "drupal", "typo3"]):
            cms_list.append(tech_entry)
        elif any(
            server in tech_lower for server in ["apache", "nginx", "iis", "lighttpd"]
        ):
            server_list.append(tech_entry)
        elif any(
            fw in tech_lower
            for fw in ["django", "laravel", "rails", "express", "flask"]
        ):
            framework_list.append(tech_entry)
        else:
            other_list.append(tech_entry)

    # Build categorized list
    if cms_list:
        description += "**Content Management System:**\n"
        for cms in cms_list:
            description += f"  - {cms}\n"

    if server_list:
        description += "\n**Web Server:**\n"
        for server in server_list:
            description += f"  - {server}\n"

    if framework_list:
        description += "\n**Framework:**\n"
        for fw in framework_list:
            description += f"  - {fw}\n"

    if other_list:
        description += "\n**Other Technologies:**\n"
        for tech in other_list:
            description += f"  - {tech}\n"

    return description.strip()


def get_whatweb_stats() -> Dict:
    """
    Get WhatWeb installation statistics.

    Returns:
        Dictionary with WhatWeb version and plugin count
    """

    try:
        # Get version
        version_result = subprocess.run(
            ["whatweb", "--version"], capture_output=True, text=True, check=False
        )

        # Get plugin list
        plugin_result = subprocess.run(
            ["whatweb", "--list-plugins"], capture_output=True, text=True, check=False
        )

        # Count plugins (each line is a plugin)
        plugin_count = len(
            [
                line
                for line in plugin_result.stdout.split("\n")
                if line.strip() and not line.startswith("[")
            ]
        )

        return {
            "version": version_result.stdout.strip(),
            "plugin_count": plugin_count,
            "status": "installed",
        }

    except Exception as e:
        return {"version": "unknown", "plugin_count": 0, "status": f"error: {e}"}
