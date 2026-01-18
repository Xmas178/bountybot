"""
HTTPx Integration Module

Probes HTTP/HTTPS endpoints to verify they are alive and gather metadata.
Uses ProjectDiscovery's httpx tool for fast HTTP probing.
"""

import subprocess
import json
from typing import List, Dict, Optional
from dataclasses import dataclass


@dataclass
class HttpxResult:
    """Represents the result of an httpx probe."""

    url: str
    status_code: Optional[int]
    title: Optional[str]
    webserver: Optional[str]
    content_length: Optional[int]
    tech_stack: List[str]
    is_alive: bool


class HttpxProber:
    """
    HTTPx prober wrapper for HTTP endpoint verification.

    Probes URLs to check if they respond and extracts metadata
    like status codes, titles, web servers, and technologies.
    """

    def __init__(self):
        """Initialize httpx prober."""
        self.httpx_path = self._find_httpx()

    def _find_httpx(self) -> str:
        """
        Find httpx executable path.

        Returns:
            Path to httpx binary

        Raises:
            RuntimeError: If httpx is not installed
        """
        import os

        # Try multiple locations in order of preference
        possible_paths = [
            "/home/crake178/go/bin/httpx",  # Hardcoded user path (works with sudo)
            os.path.join(os.environ.get("HOME", ""), "go/bin/httpx"),  # $HOME/go/bin
            os.path.expanduser("~/go/bin/httpx"),  # ~/go/bin (may fail with sudo)
        ]

        # Check each possible location
        for path in possible_paths:
            if path and os.path.exists(path) and os.access(path, os.X_OK):
                # Verify it's the Go version
                try:
                    version_check = subprocess.run(
                        [path, "-version"], capture_output=True, text=True, timeout=5
                    )
                    output = version_check.stdout + version_check.stderr

                    if "projectdiscovery" in output:
                        return path
                except:
                    continue

        # Check system PATH as last resort
        try:
            result = subprocess.run(
                ["which", "httpx"], capture_output=True, text=True, check=True
            )
            path = result.stdout.strip()

            # Make sure it's the Go version, not Python httpx
            version_check = subprocess.run(
                [path, "-version"], capture_output=True, text=True
            )

            if "projectdiscovery" in version_check.stdout:
                return path
            else:
                raise RuntimeError(
                    "Found httpx but it's not ProjectDiscovery version. "
                    "Install with: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
                )

        except subprocess.CalledProcessError:
            raise RuntimeError(
                "httpx not found. Install it with: "
                "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
            )

    def probe_url(self, url: str) -> HttpxResult:
        """
        Probe a single URL.

        Args:
            url: URL to probe (with or without scheme)

        Returns:
            HttpxResult with endpoint information
        """
        results = self.probe_urls([url])
        return (
            results[0]
            if results
            else HttpxResult(
                url=url,
                status_code=None,
                title=None,
                webserver=None,
                content_length=None,
                tech_stack=[],
                is_alive=False,
            )
        )

    def probe_urls(self, urls: List[str]) -> List[HttpxResult]:
        """
        Probe multiple URLs.

        Args:
            urls: List of URLs to probe

        Returns:
            List of HttpxResult objects
        """
        args = [
            self.httpx_path,
            "-silent",  # No banner
            "-json",  # JSON output
            "-status-code",  # Include status code
            "-title",  # Extract page title
            "-web-server",  # Detect web server
            "-content-length",  # Get content length
            "-tech-detect",  # Detect technologies
            "-timeout",
            "10",  # 10 second timeout
        ]

        # Feed URLs via stdin (not as arguments)
        urls_input = "\n".join(urls)

        try:
            result = subprocess.run(
                args,
                input=urls_input,
                capture_output=True,
                text=True,
                timeout=60,  # 1 minute total timeout
            )

            return self._parse_output(result.stdout)

        except subprocess.TimeoutExpired:
            raise RuntimeError("HTTPx probe timed out after 60 seconds")
        except Exception as e:
            raise RuntimeError(f"HTTPx probe error: {str(e)}")

    def probe_from_ports(self, host: str, ports: List[int]) -> List[HttpxResult]:
        """
        Probe HTTP/HTTPS on specific ports.

        Useful after nmap scan to check which ports actually serve HTTP.

        Args:
            host: Hostname or IP
            ports: List of ports to check

        Returns:
            List of HttpxResult for responding endpoints
        """
        urls = []

        for port in ports:
            # Try both HTTP and HTTPS
            if port == 443:
                urls.append(f"https://{host}:{port}")
            elif port == 80:
                urls.append(f"http://{host}")
            else:
                urls.append(f"http://{host}:{port}")
                urls.append(f"https://{host}:{port}")

        return self.probe_urls(urls)

    def _parse_output(self, json_output: str) -> List[HttpxResult]:
        """
        Parse httpx JSON output.

        Args:
            json_output: JSON output from httpx

        Returns:
            List of HttpxResult objects
        """
        results = []

        for line in json_output.strip().split("\n"):
            if not line:
                continue

            try:
                data = json.loads(line)

                # Extract technologies
                tech_stack = []
                if "tech" in data:
                    tech_stack = data["tech"]

                result = HttpxResult(
                    url=data.get("url", ""),
                    status_code=data.get("status_code"),
                    title=data.get("title"),
                    webserver=data.get("webserver"),
                    content_length=data.get("content_length"),
                    tech_stack=tech_stack,
                    is_alive=True,
                )

                results.append(result)

            except json.JSONDecodeError:
                continue

        return results


# Example usage
if __name__ == "__main__":
    prober = HttpxProber()

    # Probe single URL
    print("Probing scanme.nmap.org...")
    result = prober.probe_url("scanme.nmap.org")

    print(f"URL: {result.url}")
    print(f"Status: {result.status_code}")
    print(f"Title: {result.title}")
    print(f"Server: {result.webserver}")
    print(f"Technologies: {result.tech_stack}")
