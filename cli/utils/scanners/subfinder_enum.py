"""
Subfinder Integration Module

Enumerates subdomains using multiple sources.
Uses ProjectDiscovery's subfinder for comprehensive subdomain discovery.
"""

import subprocess
from typing import List, Set
from dataclasses import dataclass


@dataclass
class SubfinderResult:
    """Represents the result of subdomain enumeration."""

    domain: str
    subdomains: List[str]
    total_found: int


class SubfinderEnumerator:
    """
    Subfinder wrapper for subdomain enumeration.

    Discovers subdomains using multiple sources including:
    - Certificate Transparency logs (crt.sh)
    - Search engines
    - DNS databases
    - Third-party APIs
    """

    def __init__(self):
        """Initialize subfinder enumerator."""
        self.subfinder_path = self._find_subfinder()

    def _find_subfinder(self) -> str:
        """
        Find subfinder executable path.

        Returns:
            Path to subfinder binary

        Raises:
            RuntimeError: If subfinder is not installed
        """
        import os

        # Try multiple locations in order of preference
        possible_paths = [
            "/home/crake178/go/bin/subfinder",  # Hardcoded user path (works with sudo)
            os.path.join(
                os.environ.get("HOME", ""), "go/bin/subfinder"
            ),  # $HOME/go/bin
            os.path.expanduser("~/go/bin/subfinder"),  # ~/go/bin (may fail with sudo)
        ]

        # Check each possible location
        for path in possible_paths:
            if path and os.path.exists(path) and os.access(path, os.X_OK):
                return path

        # Check system PATH as last resort
        try:
            result = subprocess.run(
                ["which", "subfinder"], capture_output=True, text=True, check=True
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError:
            raise RuntimeError(
                "subfinder not found. Install with: "
                "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
            )

    def enumerate(
        self, domain: str, timeout: int = 300, max_results: int = 1000
    ) -> SubfinderResult:
        """
        Enumerate subdomains for a domain.

        Args:
            domain: Root domain to enumerate
            timeout: Maximum time in seconds (default 5 minutes)
            max_results: Stop after finding this many subdomains

        Returns:
            SubfinderResult with discovered subdomains
        """
        args = [
            self.subfinder_path,
            "-d",
            domain,
            "-silent",
            "-all",
            "-timeout",
            str(timeout),
        ]

        try:
            result = subprocess.run(
                args, capture_output=True, text=True, timeout=timeout + 10
            )

            subdomains = self._parse_output(result.stdout, max_results)

            return SubfinderResult(
                domain=domain, subdomains=subdomains, total_found=len(subdomains)
            )

        except subprocess.TimeoutExpired:
            raise RuntimeError(f"Subfinder timed out after {timeout} seconds")
        except Exception as e:
            raise RuntimeError(f"Subfinder error: {str(e)}")

    def _parse_output(self, output: str, max_results: int) -> List[str]:
        """
        Parse subfinder output.

        Args:
            output: Raw output from subfinder
            max_results: Maximum number of results to return

        Returns:
            List of unique subdomains
        """
        subdomains = set()

        for line in output.strip().split("\n"):
            line = line.strip()
            if line and "." in line:
                subdomains.add(line)

                if len(subdomains) >= max_results:
                    break

        return sorted(list(subdomains))


if __name__ == "__main__":
    enumerator = SubfinderEnumerator()

    print("Enumerating subdomains for scanme.nmap.org...")
    result = enumerator.enumerate("scanme.nmap.org", timeout=30)

    print(f"\nDomain: {result.domain}")
    print(f"Subdomains found: {result.total_found}")

    if result.subdomains:
        print("\nSubdomains:")
        for subdomain in result.subdomains[:10]:
            print(f"  - {subdomain}")

        if result.total_found > 10:
            print(f"  ... and {result.total_found - 10} more")
    else:
        print("No subdomains found")
