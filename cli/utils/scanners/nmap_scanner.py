"""
Nmap Integration Module

Provides port scanning capabilities using nmap.
Supports different scan profiles and result parsing.
"""

import subprocess
import json
from typing import Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime


@dataclass
class NmapResult:
    """Represents the result of an nmap scan."""

    host: str
    open_ports: List[Dict[str, str]]
    os_detection: Optional[str]
    scan_time: str
    raw_output: str


class NmapScanner:
    """
    Nmap scanner wrapper for security testing.

    Provides different scan profiles for various use cases:
    - Quick: Fast SYN scan of common ports
    - Standard: Full TCP scan with service detection
    - Deep: Comprehensive scan with OS detection and scripts
    """

    def __init__(self):
        """Initialize nmap scanner."""
        self.nmap_path = self._find_nmap()

    def _find_nmap(self) -> str:
        """
        Find nmap executable path.

        Returns:
            Path to nmap binary

        Raises:
            RuntimeError: If nmap is not installed
        """
        try:
            result = subprocess.run(
                ["which", "nmap"], capture_output=True, text=True, check=True
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError:
            raise RuntimeError("nmap not found. Install it with: sudo apt install nmap")

    def scan_quick(self, target: str) -> NmapResult:
        """
        Quick TCP connect scan of top 1000 ports.

        Fast reconnaissance scan for initial target assessment.
        Does not require root privileges.

        Args:
            target: IP address or domain to scan

        Returns:
            NmapResult with open ports and services
        """

        args = [
            self.nmap_path,
            "-sT",  # TCP connect scan (no root needed)
            "-T4",  # Timing template (faster)
            "--top-ports",
            "100",  # Top 100 ports (faster for testing)
            "-oX",
            "-",  # XML output to stdout
            target,
        ]

        return self._run_scan(target, args)

    def scan_standard(self, target: str) -> NmapResult:
        """
        Standard TCP scan with service version detection.

        Scans all 65535 ports and detects service versions.

        Args:
            target: IP address or domain to scan

        Returns:
            NmapResult with ports, services, and versions
        """
        args = [
            self.nmap_path,
            "-sT",  # TCP connect scan
            "-sV",  # Service version detection
            "-p-",  # All ports (1-65535)
            "-T3",  # Normal timing
            "-oX",
            "-",  # XML output
            target,
        ]

        return self._run_scan(target, args)

    def scan_deep(self, target: str) -> NmapResult:
        """
        Comprehensive scan with OS detection and NSE scripts.

        Full port scan with:
        - Service version detection (-sV)
        - OS detection (-O)
        - Default NSE scripts (-sC)
        - Aggressive timing (-T4)

        Args:
            target: IP address or domain to scan

        Returns:
            NmapResult with detailed information
        """
        args = [
            self.nmap_path,
            "-sS",  # SYN scan
            "-sV",  # Service version detection
            "-O",  # OS detection
            "-sC",  # Default NSE scripts
            "-p-",  # All ports
            "-T4",  # Aggressive timing
            "-oX",
            "-",  # XML output
            target,
        ]

        return self._run_scan(target, args)

    def _run_scan(self, target: str, args: List[str]) -> NmapResult:
        """
        Execute nmap scan with given arguments.

        Args:
            target: Target being scanned
            args: Command line arguments for nmap

        Returns:
            Parsed NmapResult

        Raises:
            RuntimeError: If scan fails
        """
        try:
            # Run nmap scan
            result = subprocess.run(
                args, capture_output=True, text=True, timeout=300  # 5 minute timeout
            )

            if result.returncode != 0:
                raise RuntimeError(f"Nmap scan failed: {result.stderr}")

            # Parse XML output
            return self._parse_output(target, result.stdout)

        except subprocess.TimeoutExpired:
            raise RuntimeError("Nmap scan timed out after 5 minutes")
        except Exception as e:
            raise RuntimeError(f"Scan error: {str(e)}")

    def _parse_output(self, target: str, xml_output: str) -> NmapResult:
        """
        Parse nmap XML output into NmapResult.

        Args:
            target: Target that was scanned
            xml_output: XML output from nmap

        Returns:
            Structured NmapResult object
        """
        import xml.etree.ElementTree as ET

        open_ports = []

        try:
            # Parse XML
            root = ET.fromstring(xml_output)

            # Find all open ports
            for host in root.findall(".//host"):
                for port in host.findall(".//port"):
                    state = port.find("state")
                    if state is not None and state.get("state") == "open":
                        port_id = port.get("portid")
                        protocol = port.get("protocol", "tcp")

                        # Get service info
                        service = port.find("service")
                        service_name = "unknown"
                        if service is not None:
                            service_name = service.get("name", "unknown")

                        open_ports.append(
                            {
                                "port": port_id,
                                "protocol": protocol,
                                "service": service_name,
                            }
                        )

        except Exception as e:
            # If XML parsing fails, return empty result
            print(f"Warning: Could not parse XML output: {e}")

        return NmapResult(
            host=target,
            open_ports=open_ports,
            os_detection=None,
            scan_time=datetime.now().isoformat(),
            raw_output=xml_output,
        )

    def get_scan_profile(self, profile: str) -> callable:
        """
        Get scan method for given profile name.

        Args:
            profile: Profile name (quick, standard, deep)

        Returns:
            Scan method callable

        Raises:
            ValueError: If profile is unknown
        """
        profiles = {
            "quick": self.scan_quick,
            "standard": self.scan_standard,
            "deep": self.scan_deep,
        }

        if profile not in profiles:
            raise ValueError(
                f"Unknown scan profile: {profile}. "
                f"Choose from: {', '.join(profiles.keys())}"
            )

        return profiles[profile]


# Example usage
if __name__ == "__main__":
    scanner = NmapScanner()

    # Quick scan
    print("Running quick scan...")
    result = scanner.scan_quick("scanme.nmap.org")
    print(f"Found {len(result.open_ports)} open ports")
