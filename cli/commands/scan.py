"""
Scan Management Commands

CLI commands for managing security scans.
Integrates with Django Scan model for database operations.
"""

import typer
from rich.console import Console
from rich.table import Table
from typing import Optional
from scans.models import Scan
from targets.models import Target
from findings.models import Finding
from datetime import datetime
from cli.utils.scanners.nmap_scanner import NmapScanner
from cli.utils.scanners.httpx_prober import HttpxProber
from cli.utils.scanners.nuclei_scanner import run_nuclei_scan
from cli.utils.scanners.whatweb_detector import (
    detect_technologies,
    format_technologies_for_finding,
)
from cli.utils.scanners.sqlmap_tester import test_sql_injection
from cli.utils.scanners.dalfox_scanner import test_xss_vulnerabilities
from cli.utils.scanners.nikto_scanner import scan_web_vulnerabilities
from cli.utils.scanners.ffuf_fuzzer import fuzz_directories
from cli.utils.scanners.wpscan_scanner import scan_wordpress
from django.utils import timezone
from cli.utils.scanners.subfinder_enum import SubfinderEnumerator

# Initialize Typer app for scan commands
app = typer.Typer(help="Manage security scans")
console = Console()


@app.command("start")
def start_scan(
    target_id: int = typer.Argument(..., help="Target ID to scan"),
    profile: str = typer.Option(
        "standard",
        "--profile",
        "-p",
        help="Scan profile: quick, standard, deep, custom",
    ),
    execute: bool = typer.Option(
        False,
        "--execute",
        "-e",
        help="Execute scan immediately (otherwise just creates it)",
    ),
):
    """
    Start a new security scan for a target.

    Example:
        bountybot scan start 1                    # Create scan (pending)
        bountybot scan start 1 --execute          # Create and run immediately
        bountybot scan start 1 -p deep --execute  # Deep scan, run now
    """
    try:
        # Get target from database
        target = Target.objects.get(id=target_id)

        console.print(f"[cyan]Starting scan for:[/cyan] {target.name} ({target.value})")

        # Create new scan in database
        scan = Scan.objects.create(target=target, profile=profile, status="pending")

        console.print(f"[bold green]✓[/bold green] Scan created successfully!")
        console.print(f"  Scan ID: [cyan]{scan.id}[/cyan]")
        console.print(f"  Target: {target.name}")
        console.print(f"  Profile: {scan.profile}")
        console.print(f"  Status: [yellow]{scan.status}[/yellow]")

        # Execute scan immediately if --execute flag is set
        if execute:
            console.print(f"\n[cyan]Executing {profile} scan...[/cyan]")

            # Update scan status to running
            scan.status = "running"
            scan.started_at = timezone.now()
            scan.save()

            try:
                # Initialize scanners
                nmap_scanner = NmapScanner()
                httpx_prober = HttpxProber()
                subfinder_enum = SubfinderEnumerator()

                # PHASE 0: Subdomain enumeration (only for domains)
                subdomains = []
                if target.target_type == "domain":
                    console.print(f"[cyan]Phase 0: Subdomain enumeration...[/cyan]")

                    try:
                        subfinder_result = subfinder_enum.enumerate(
                            target.value, timeout=60
                        )
                        subdomains = subfinder_result.subdomains
                        console.print(f"  Found {len(subdomains)} subdomains")

                        # Create findings for subdomains
                        for subdomain in subdomains:
                            Finding.objects.create(
                                scan=scan,
                                title=f"Subdomain: {subdomain}",
                                severity="info",
                                description=f"Subdomain discovered via passive enumeration",
                                proof_of_concept=f"Domain: {subdomain}\nParent: {target.value}",
                                status="new",
                                affected_url=f"http://{subdomain}",
                            )
                    except Exception as e:
                        console.print(
                            f"  [yellow]Subdomain enumeration skipped: {str(e)}[/yellow]"
                        )
                else:
                    console.print(
                        f"[dim]Skipping subdomain enumeration (target is not a domain)[/dim]"
                    )
                # PHASE 1: Nmap port scan
                console.print(f"[cyan]Phase 1: Port scanning with nmap...[/cyan]")

                if profile == "quick":
                    nmap_result = nmap_scanner.scan_quick(target.value)
                elif profile == "standard":
                    nmap_result = nmap_scanner.scan_standard(target.value)
                elif profile == "deep":
                    nmap_result = nmap_scanner.scan_deep(target.value)
                else:
                    raise ValueError(f"Unknown profile: {profile}")

                console.print(f"  Found {len(nmap_result.open_ports)} open ports")

                # Create findings for each open port
                for port_info in nmap_result.open_ports:
                    Finding.objects.create(
                        scan=scan,
                        title=f"Open Port: {port_info.get('port', 'unknown')} ({port_info.get('service', 'unknown')})",
                        severity="info",
                        description=f"Port {port_info.get('port')} is open and running {port_info.get('service', 'unknown service')}",
                        proof_of_concept=f"Service: {port_info.get('service', 'N/A')}\nProtocol: {port_info.get('protocol', 'tcp')}",
                        status="new",
                    )

                # PHASE 2: HTTP probing
                console.print(f"\n[cyan]Phase 2: Probing HTTP endpoints...[/cyan]")

                # Extract ports that might serve HTTP
                http_ports = [int(p["port"]) for p in nmap_result.open_ports]

                if http_ports:
                    httpx_results = httpx_prober.probe_from_ports(
                        target.value, http_ports
                    )
                    console.print(f"  Found {len(httpx_results)} active HTTP endpoints")

                    # Create findings for HTTP endpoints
                    for http_result in httpx_results:
                        # Determine severity based on findings
                        severity = "info"

                        # Build description
                        description = f"HTTP endpoint is alive and responding.\n"
                        description += f"Status Code: {http_result.status_code}\n"
                        if http_result.title:
                            description += f"Page Title: {http_result.title}\n"
                        if http_result.webserver:
                            description += f"Web Server: {http_result.webserver}\n"
                        if http_result.tech_stack:
                            description += (
                                f"Technologies: {', '.join(http_result.tech_stack)}\n"
                            )

                        # Build proof of concept
                        poc = f"URL: {http_result.url}\n"
                        poc += f"Status: {http_result.status_code}\n"
                        if http_result.content_length:
                            poc += (
                                f"Content Length: {http_result.content_length} bytes\n"
                            )
                        if http_result.tech_stack:
                            poc += f"Tech Stack:\n"
                            for tech in http_result.tech_stack:
                                poc += f"  - {tech}\n"

                        Finding.objects.create(
                            scan=scan,
                            title=f"HTTP Endpoint: {http_result.url}",
                            severity=severity,
                            description=description.strip(),
                            proof_of_concept=poc.strip(),
                            status="new",
                            affected_url=http_result.url,
                        )
                else:
                    console.print(f"  No HTTP ports to probe")

                # PHASE 3: Technology detection with WhatWeb
                console.print(
                    f"\n[cyan]Phase 3: Technology detection with WhatWeb...[/cyan]"
                )
                # Collect URLs for technology detection
                whatweb_targets = []
                if http_ports and httpx_results:
                    for http_result in httpx_results:
                        whatweb_targets.append(http_result.url)

                # Run WhatWeb on each HTTP endpoint
                all_technologies = {}
                for whatweb_target in whatweb_targets:
                    console.print(f"  Detecting technologies: {whatweb_target}")

                    try:
                        tech_data = detect_technologies(
                            target=whatweb_target,
                            scan_id=scan.id,
                            aggression=1,  # Passive detection (fast and safe)
                            timeout=30,
                        )

                        # Store technologies for this URL
                        all_technologies[whatweb_target] = tech_data

                        # Create Finding for technology detection
                        if tech_data.get("technologies"):
                            description = format_technologies_for_finding(tech_data)

                            Finding.objects.create(
                                scan=scan,
                                title=f"Technology Stack: {whatweb_target}",
                                severity="info",
                                description=description,
                                status="new",
                                affected_url=whatweb_target,
                            )

                            console.print(
                                f"    Found {tech_data.get('plugins_matched', 0)} technologies"
                            )

                    except Exception as e:
                        console.print(
                            f"    [yellow]Warning: WhatWeb failed for {whatweb_target}: {str(e)}[/yellow]"
                        )
                        continue

                # PHASE 4: Nuclei vulnerability scanning
                console.print(
                    f"\n[cyan]Phase 4: Vulnerability scanning with nuclei...[/cyan]"
                )
                # Collect all discovered URLs for nuclei scanning
                scan_targets = []

                # Add main target
                if target.target_type == "url":
                    scan_targets.append(target.value)
                elif target.target_type == "domain":
                    scan_targets.append(f"http://{target.value}")
                    scan_targets.append(f"https://{target.value}")
                elif target.target_type == "ip":
                    # Add IP with common HTTP ports
                    for port_info in nmap_result.open_ports:
                        port = port_info.get("port")
                        if port in [80, 443, 8000, 8080, 8443]:
                            protocol = "https" if port in [443, 8443] else "http"
                            scan_targets.append(f"{protocol}://{target.value}:{port}")

                # Add discovered HTTP endpoints from Phase 2
                if http_ports and httpx_results:
                    for http_result in httpx_results:
                        if http_result.url not in scan_targets:
                            scan_targets.append(http_result.url)

                # Run nuclei on each target
                nuclei_findings_count = 0
                severity_counts = {
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "info": 0,
                }

                for scan_target in scan_targets:
                    console.print(f"  Scanning: {scan_target}")

                    try:
                        # Run nuclei with all severity levels
                        nuclei_findings = run_nuclei_scan(
                            target=scan_target,
                            scan_id=scan.id,
                            timeout=300,  # 5 minutes per target
                        )

                        # Create Finding objects in database
                        for finding_data in nuclei_findings:
                            Finding.objects.create(
                                scan=scan,
                                title=finding_data["title"],
                                severity=finding_data["severity"],
                                description=finding_data["description"],
                                proof_of_concept=finding_data.get("proof_of_concept"),
                                status="new",
                                affected_url=scan_target,
                            )

                            # Count by severity
                            severity_counts[finding_data["severity"]] += 1
                            nuclei_findings_count += 1

                    except Exception as e:
                        console.print(
                            f"    [yellow]Warning: Nuclei scan failed for {scan_target}: {str(e)}[/yellow]"
                        )
                        continue

                console.print(f"  Found {nuclei_findings_count} vulnerabilities")
                if nuclei_findings_count > 0:
                    console.print(
                        f"    Critical: [red]{severity_counts['critical']}[/red]"
                    )
                    console.print(
                        f"    High: [yellow]{severity_counts['high']}[/yellow]"
                    )
                    console.print(
                        f"    Medium: [blue]{severity_counts['medium']}[/blue]"
                    )
                    console.print(f"    Low: [dim]{severity_counts['low']}[/dim]")
                    console.print(f"    Info: [dim]{severity_counts['info']}[/dim]")

                # PHASE 5: SQL Injection testing with SQLMap
                console.print(
                    f"\n[cyan]Phase 5: SQL injection testing with SQLMap...[/cyan]"
                )

                # Only test URLs with parameters (potential injection points)
                sqlmap_targets = []

                # Check if HTTP endpoints have parameters
                if http_ports and httpx_results:
                    for http_result in httpx_results:
                        url = http_result.url
                        # SQLMap needs parameters to test (e.g., ?id=1)
                        # For now, we'll test base URLs and let SQLMap crawl
                        sqlmap_targets.append(url)

                # Run SQLMap on each target
                sqlmap_findings_count = 0

                # Determine SQLMap level based on scan profile
                sqlmap_level = 1  # Default
                if profile == "standard":
                    sqlmap_level = 2  # Test cookies too
                elif profile == "deep":
                    sqlmap_level = 3  # Test cookies + User-Agent

                for sqlmap_target in sqlmap_targets:
                    console.print(f"  Testing: {sqlmap_target} (level {sqlmap_level})")

                    try:
                        # Run SQLMap with safe settings (risk=1 always)
                        sqlmap_findings = test_sql_injection(
                            target=sqlmap_target,
                            scan_id=scan.id,
                            level=sqlmap_level,
                            risk=1,  # Always risk=1 for bug bounty safety
                            timeout=300,  # 5 minutes per target
                        )

                        # Create Finding objects in database
                        for finding_data in sqlmap_findings:
                            Finding.objects.create(
                                scan=scan,
                                title=finding_data["title"],
                                severity=finding_data["severity"],
                                description=finding_data["description"],
                                proof_of_concept=finding_data.get("proof_of_concept"),
                                status="new",
                                affected_url=sqlmap_target,
                            )

                            # Count by severity
                            severity_counts[finding_data["severity"]] += 1
                            sqlmap_findings_count += 1

                        if sqlmap_findings:
                            console.print(
                                f"    [red]⚠️  Found {len(sqlmap_findings)} SQL injection vulnerabilities![/red]"
                            )
                        else:
                            console.print(
                                f"    [green]✓ No SQL injection found[/green]"
                            )

                    except Exception as e:
                        console.print(
                            f"    [yellow]Warning: SQLMap failed for {sqlmap_target}: {str(e)}[/yellow]"
                        )
                        continue

                if sqlmap_findings_count > 0:
                    console.print(
                        f"\n[bold red]🚨 CRITICAL: {sqlmap_findings_count} SQL injection vulnerabilities detected![/bold red]"
                    )
                # PHASE 6: XSS detection with Dalfox
                console.print(f"\n[cyan]Phase 6: XSS detection with Dalfox...[/cyan]")

                # Test URLs with parameters for XSS
                dalfox_targets = []

                # Dalfox needs URLs with parameters to test
                # For now, test base URLs (Dalfox will try to find parameters)
                if http_ports and httpx_results:
                    for http_result in httpx_results:
                        dalfox_targets.append(http_result.url)

                # Run Dalfox on each target
                dalfox_findings_count = 0

                for dalfox_target in dalfox_targets:
                    console.print(f"  Testing: {dalfox_target}")

                    try:
                        # Run Dalfox XSS detection
                        dalfox_findings = test_xss_vulnerabilities(
                            target=dalfox_target,
                            scan_id=scan.id,
                            mode="url",
                            timeout=300,  # 5 minutes per target
                        )

                        # Create Finding objects in database
                        for finding_data in dalfox_findings:
                            Finding.objects.create(
                                scan=scan,
                                title=finding_data["title"],
                                severity=finding_data["severity"],
                                description=finding_data["description"],
                                proof_of_concept=finding_data.get("proof_of_concept"),
                                status="new",
                                affected_url=dalfox_target,
                            )

                            # Count by severity
                            severity_counts[finding_data["severity"]] += 1
                            dalfox_findings_count += 1

                        if dalfox_findings:
                            console.print(
                                f"    [red]⚠️  Found {len(dalfox_findings)} XSS vulnerabilities![/red]"
                            )
                        else:
                            console.print(
                                f"    [green]✓ No XSS vulnerabilities found[/green]"
                            )

                    except Exception as e:
                        console.print(
                            f"    [yellow]Warning: Dalfox failed for {dalfox_target}: {str(e)}[/yellow]"
                        )
                        continue

                if dalfox_findings_count > 0:
                    console.print(
                        f"\n[bold red]🚨 CRITICAL: {dalfox_findings_count} XSS vulnerabilities detected![/bold red]"
                    )
                # PHASE 7: Nikto web server scanning (conditional based on profile)
                nikto_findings_count = 0

                if profile == "quick":
                    console.print(
                        f"\n[dim]Skipping Nikto scan in quick profile (use --profile standard for web server testing)[/dim]"
                    )

                elif profile in ["standard", "deep"] and http_ports and httpx_results:
                    console.print(
                        f"\n[cyan]Phase 7: Web server scanning with Nikto...[/cyan]"
                    )

                    # Estimate scan time
                    if profile == "standard":
                        time_per_endpoint = "5-10 minutes"
                        tuning = "1"  # Important tests only
                        max_time = 10
                    else:  # deep
                        time_per_endpoint = "15-30 minutes"
                        tuning = "123456789abc"  # All tests
                        max_time = 30

                    total_endpoints = len(httpx_results)

                    console.print(
                        f"  [yellow]⚠️  Nikto scan takes {time_per_endpoint} per endpoint.[/yellow]"
                    )
                    console.print(
                        f"  [yellow]Found {total_endpoints} HTTP endpoint(s) to scan.[/yellow]"
                    )

                    # Ask user for confirmation
                    run_nikto = typer.confirm(
                        "  Run Nikto web server scan?", default=False
                    )

                    if run_nikto:
                        console.print(
                            f"  [cyan]Starting Nikto scan (this will take a while)...[/cyan]"
                        )

                        for http_result in httpx_results:
                            # Parse URL to get host and port
                            from urllib.parse import urlparse

                            parsed = urlparse(http_result.url)
                            host = parsed.hostname
                            port = parsed.port or (
                                443 if parsed.scheme == "https" else 80
                            )
                            use_ssl = parsed.scheme == "https"

                            console.print(f"  Testing: {http_result.url}")

                            try:
                                # Run Nikto scan
                                nikto_findings = scan_web_vulnerabilities(
                                    target=host,
                                    scan_id=scan.id,
                                    port=port,
                                    ssl=use_ssl,
                                    timeout=max_time * 60,  # Convert to seconds
                                )

                                # Create Finding objects in database
                                for finding_data in nikto_findings:
                                    Finding.objects.create(
                                        scan=scan,
                                        title=finding_data["title"],
                                        severity=finding_data["severity"],
                                        description=finding_data["description"],
                                        proof_of_concept=finding_data.get(
                                            "proof_of_concept"
                                        ),
                                        status="new",
                                        affected_url=http_result.url,
                                    )

                                    # Count by severity
                                    severity_counts[finding_data["severity"]] += 1
                                    nikto_findings_count += 1

                                if nikto_findings:
                                    console.print(
                                        f"    [yellow]⚠️  Found {len(nikto_findings)} issues![/yellow]"
                                    )
                                else:
                                    console.print(
                                        f"    [green]✓ No significant issues found[/green]"
                                    )

                            except Exception as e:
                                console.print(
                                    f"    [yellow]Warning: Nikto failed for {http_result.url}: {str(e)}[/yellow]"
                                )
                                continue

                        if nikto_findings_count > 0:
                            console.print(
                                f"\n[bold yellow]⚠️  Nikto found {nikto_findings_count} web server issues![/bold yellow]"
                            )
                    else:
                        console.print(f"  [dim]Nikto scan skipped by user[/dim]")

                # PHASE 8: FFuf directory/file fuzzing (conditional based on profile)
                ffuf_findings_count = 0

                if profile == "quick":
                    console.print(
                        f"\n[dim]Skipping FFuf fuzzing in quick profile (use --profile standard for directory discovery)[/dim]"
                    )

                elif profile in ["standard", "deep"] and http_ports and httpx_results:
                    console.print(
                        f"\n[cyan]Phase 8: Directory/file fuzzing with FFuf...[/cyan]"
                    )

                    # Select wordlist and estimate time based on profile
                    if profile == "standard":
                        wordlist = "common"
                        wordlist_size = "~4,700 entries"
                        time_estimate = "2-5 minutes"
                        max_time = 300  # 5 minutes
                    else:  # deep
                        wordlist = "medium"
                        wordlist_size = "~220,000 entries"
                        time_estimate = "10-30 minutes"
                        max_time = 1800  # 30 minutes

                    total_endpoints = len(httpx_results)

                    console.print(
                        f"  [yellow]⚠️  FFuf fuzzing takes {time_estimate} per endpoint.[/yellow]"
                    )
                    console.print(
                        f"  [yellow]Wordlist: {wordlist} ({wordlist_size})[/yellow]"
                    )
                    console.print(
                        f"  [yellow]Found {total_endpoints} HTTP endpoint(s) to fuzz.[/yellow]"
                    )

                    # Ask user for confirmation
                    run_ffuf = typer.confirm(
                        "  Run FFuf directory fuzzing?", default=False
                    )

                    if run_ffuf:
                        console.print(f"  [cyan]Starting FFuf fuzzing...[/cyan]")

                        for http_result in httpx_results:
                            console.print(f"  Fuzzing: {http_result.url}")

                            try:
                                # Run FFuf fuzzing
                                ffuf_findings = fuzz_directories(
                                    target=http_result.url,
                                    scan_id=scan.id,
                                    wordlist=wordlist,
                                    max_time=max_time,
                                    threads=40,
                                )

                                # Create Finding objects in database
                                for finding_data in ffuf_findings:
                                    Finding.objects.create(
                                        scan=scan,
                                        title=finding_data["title"],
                                        severity=finding_data["severity"],
                                        description=finding_data["description"],
                                        proof_of_concept=finding_data.get(
                                            "proof_of_concept"
                                        ),
                                        status="new",
                                        affected_url=http_result.url,
                                    )

                                    # Count by severity
                                    severity_counts[finding_data["severity"]] += 1
                                    ffuf_findings_count += 1

                                if ffuf_findings:
                                    console.print(
                                        f"    [yellow]⚠️  Found {len(ffuf_findings)} hidden paths![/yellow]"
                                    )
                                else:
                                    console.print(
                                        f"    [green]✓ No hidden paths discovered[/green]"
                                    )

                            except Exception as e:
                                console.print(
                                    f"    [yellow]Warning: FFuf failed for {http_result.url}: {str(e)}[/yellow]"
                                )
                                continue

                        if ffuf_findings_count > 0:
                            console.print(
                                f"\n[bold yellow]⚠️  FFuf discovered {ffuf_findings_count} hidden resources![/bold yellow]"
                            )
                    else:
                        console.print(f"  [dim]FFuf fuzzing skipped by user[/dim]")

                # PHASE 9: WordPress scanning with WPScan (conditional - only if WordPress detected)
                wpscan_findings_count = 0

                # Check if WordPress was detected in Phase 3 (WhatWeb)
                wordpress_detected = False
                wordpress_urls = []

                for url, tech_data in all_technologies.items():
                    technologies = tech_data.get("technologies", {})
                    for tech_name in technologies.keys():
                        if "wordpress" in tech_name.lower():
                            wordpress_detected = True
                            wordpress_urls.append(url)
                            break

                if wordpress_detected and profile in ["standard", "deep"]:
                    console.print(
                        f"\n[cyan]Phase 9: WordPress scanning with WPScan...[/cyan]"
                    )
                    console.print(
                        f"  [green]✓ WordPress detected on {len(wordpress_urls)} endpoint(s)[/green]"
                    )

                    console.print(
                        f"  [yellow]⚠️  WPScan takes 5-10 minutes per WordPress site.[/yellow]"
                    )

                    # Ask user for confirmation
                    run_wpscan = typer.confirm(
                        "  Run WPScan WordPress security scan?", default=False
                    )

                    if run_wpscan:
                        console.print(
                            f"  [cyan]Starting WPScan (scanning plugins, themes, core)...[/cyan]"
                        )

                        for wp_url in wordpress_urls:
                            console.print(f"  Scanning: {wp_url}")

                            try:
                                # Run WPScan
                                wpscan_findings = scan_wordpress(
                                    target=wp_url,
                                    scan_id=scan.id,
                                    enumerate="vp,vt,u",  # Vulnerable plugins, themes, users
                                    timeout=600,  # 10 minutes
                                )

                                # Create Finding objects in database
                                for finding_data in wpscan_findings:
                                    Finding.objects.create(
                                        scan=scan,
                                        title=finding_data["title"],
                                        severity=finding_data["severity"],
                                        description=finding_data["description"],
                                        proof_of_concept=finding_data.get(
                                            "proof_of_concept"
                                        ),
                                        status="new",
                                        affected_url=wp_url,
                                    )

                                    # Count by severity
                                    severity_counts[finding_data["severity"]] += 1
                                    wpscan_findings_count += 1

                                if wpscan_findings:
                                    console.print(
                                        f"    [red]⚠️  Found {len(wpscan_findings)} WordPress vulnerabilities![/red]"
                                    )
                                else:
                                    console.print(
                                        f"    [green]✓ No WordPress vulnerabilities found[/green]"
                                    )

                            except Exception as e:
                                console.print(
                                    f"    [yellow]Warning: WPScan failed for {wp_url}: {str(e)}[/yellow]"
                                )
                                continue

                        if wpscan_findings_count > 0:
                            console.print(
                                f"\n[bold red]🚨 CRITICAL: {wpscan_findings_count} WordPress vulnerabilities detected![/bold red]"
                            )
                    else:
                        console.print(f"  [dim]WPScan skipped by user[/dim]")

                elif wordpress_detected and profile == "quick":
                    console.print(
                        f"\n[dim]WordPress detected but WPScan skipped in quick profile (use --profile standard)[/dim]"
                    )

                else:
                    console.print(
                        f"\n[dim]No WordPress detected - skipping WPScan[/dim]"
                    )
                # Update scan summary counts
                total_findings = Finding.objects.filter(scan=scan).count()

                # Count findings by severity
                critical_count = Finding.objects.filter(
                    scan=scan, severity="critical"
                ).count()
                high_count = Finding.objects.filter(scan=scan, severity="high").count()
                medium_count = Finding.objects.filter(
                    scan=scan, severity="medium"
                ).count()
                low_count = Finding.objects.filter(scan=scan, severity="low").count()
                info_count = Finding.objects.filter(scan=scan, severity="info").count()

                # Update scan model
                scan.findings_count = total_findings
                scan.critical_count = critical_count
                scan.high_count = high_count
                scan.medium_count = medium_count
                scan.low_count = low_count
                scan.info_count = info_count

                # Update scan as completed
                scan.status = "completed"
                scan.completed_at = timezone.now()
                scan.notes = f"Phases: Subdomain ({len(subdomains)}), Ports ({len(nmap_result.open_ports)}), HTTP ({len(httpx_results) if http_ports else 0}), Tech ({len(all_technologies)}), CVE ({nuclei_findings_count}), SQLi ({sqlmap_findings_count}), XSS ({dalfox_findings_count}), Nikto ({nikto_findings_count}), FFuf ({ffuf_findings_count}), WPScan ({wpscan_findings_count})"
                scan.save()

                console.print(f"\n[bold]Phase Results:[/bold]")
                console.print(f"  Subdomains: [cyan]{len(subdomains)}[/cyan]")
                console.print(
                    f"  Open Ports: [cyan]{len(nmap_result.open_ports)}[/cyan]"
                )
                console.print(
                    f"  HTTP Endpoints: [cyan]{len(httpx_results) if http_ports else 0}[/cyan]"
                )
                console.print(
                    f"  Technologies Detected: [cyan]{len(all_technologies)}[/cyan]"
                )
                console.print(
                    f"  CVE Vulnerabilities: [cyan]{nuclei_findings_count}[/cyan]"
                )
                console.print(f"  SQL Injections: [cyan]{sqlmap_findings_count}[/cyan]")
                console.print(
                    f"  XSS Vulnerabilities: [cyan]{dalfox_findings_count}[/cyan]"
                )
                console.print(
                    f"  Web Server Issues: [cyan]{nikto_findings_count}[/cyan]"
                )
                console.print(
                    f"  Hidden Paths/Files: [cyan]{ffuf_findings_count}[/cyan]"
                )
                console.print(
                    f"  WordPress Vulnerabilities: [cyan]{wpscan_findings_count}[/cyan]"
                )
                console.print(f"\n[bold]Severity Breakdown:[/bold]")
                if critical_count > 0:
                    console.print(
                        f"  🔴 Critical: [bold red]{critical_count}[/bold red]"
                    )
                if high_count > 0:
                    console.print(f"  🟠 High: [bold yellow]{high_count}[/bold yellow]")
                if medium_count > 0:
                    console.print(f"  🟡 Medium: [bold blue]{medium_count}[/bold blue]")
                if low_count > 0:
                    console.print(f"  🟢 Low: [dim]{low_count}[/dim]")
                console.print(f"  ℹ️  Info: [dim]{info_count}[/dim]")

                console.print(f"\n[bold]Scan Summary:[/bold]")
                console.print(f"  Total Findings: [cyan]{total_findings}[/cyan]")
                console.print(f"  Duration: {scan.completed_at - scan.started_at}")

            except Exception as e:
                # Mark scan as failed
                scan.status = "failed"
                scan.completed_at = timezone.now()
                scan.notes = f"Error: {str(e)}"
                scan.save()

                console.print(f"[bold red]✗[/bold red] Scan failed: {str(e)}")
                raise typer.Exit(code=1)
        else:
            console.print(f"\n[dim]Scan created but not executed.[/dim]")
            console.print(
                f"[dim]Run with --execute flag to start scan immediately[/dim]"
            )
            console.print(f"[dim]Or use: bountybot scan status {scan.id}[/dim]")

    except Target.DoesNotExist:
        console.print(f"[bold red]✗[/bold red] Target with ID {target_id} not found.")
        console.print("[dim]Use 'bountybot target list' to see available targets[/dim]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[bold red]✗[/bold red] Error starting scan: {str(e)}")
        raise typer.Exit(code=1)


# (list_scans ja scan_status funktiot tulevat tähän - säilytä ne!)


@app.command("list")
def list_scans(
    target_id: Optional[int] = typer.Option(
        None, "--target", "-t", help="Filter by target ID"
    ),
    status: Optional[str] = typer.Option(
        None, "--status", "-s", help="Filter by status"
    ),
):
    """
    List all scans in the database.

    Example:
        bountybot scan list
        bountybot scan list --target 1
        bountybot scan list --status running
    """
    # Query scans from database
    scans = Scan.objects.select_related("target").all()

    if target_id:
        scans = scans.filter(target_id=target_id)

    if status:
        scans = scans.filter(status=status)

    if not scans.exists():
        console.print("[yellow]No scans found.[/yellow]")
        console.print(
            "Start a scan with: [cyan]bountybot scan start <target_id>[/cyan]"
        )
        return

    # Create Rich table for pretty output
    table = Table(title="Security Scans", show_header=True, header_style="bold cyan")
    table.add_column("ID", style="dim", width=6)
    table.add_column("Target", style="cyan")
    table.add_column("Profile", style="yellow")
    table.add_column("Status", justify="center")
    table.add_column("Started", style="dim", width=16)
    table.add_column("Duration", style="dim")

    # Add rows to table
    for scan in scans:
        # Color-code status
        status_colors = {
            "queued": "yellow",
            "running": "blue",
            "completed": "green",
            "failed": "red",
            "cancelled": "dim",
        }
        status_color = status_colors.get(scan.status, "white")
        status_display = f"[{status_color}]{scan.status.upper()}[/{status_color}]"

        # Calculate duration
        if scan.completed_at and scan.started_at:
            duration = scan.completed_at - scan.started_at
            duration_str = str(duration).split(".")[0]  # Remove microseconds
        elif scan.started_at:
            duration = datetime.now(scan.started_at.tzinfo) - scan.started_at
            duration_str = str(duration).split(".")[0] + " (ongoing)"
        else:
            duration_str = "-"

        table.add_row(
            str(scan.id),
            f"{scan.target.name} ({scan.target.value})",
            scan.profile,
            status_display,
            (
                scan.started_at.strftime("%Y-%m-%d %H:%M")
                if scan.started_at
                else "Not started"
            ),
            duration_str,
        )

    console.print(table)
    console.print(f"\n[dim]Total scans: {scans.count()}[/dim]")


@app.command("status")
def scan_status(
    scan_id: int = typer.Argument(..., help="Scan ID to check"),
):
    """
    Show detailed status of a specific scan.

    Example:
        bountybot scan status 1
    """
    try:
        # Get scan from database
        scan = Scan.objects.select_related("target").get(id=scan_id)

        console.print(f"\n[bold cyan]Scan #{scan.id} - Status Report[/bold cyan]")
        console.print("─" * 50)

        console.print(f"Target: [cyan]{scan.target.name}[/cyan] ({scan.target.value})")
        console.print(f"Profile: {scan.profile}")

        # Status with color
        status_colors = {
            "pending": "yellow",
            "running": "blue",
            "completed": "green",
            "failed": "red",
            "cancelled": "dim",
        }
        status_color = status_colors.get(scan.status, "white")
        console.print(f"Status: [{status_color}]{scan.status.upper()}[/{status_color}]")

        # Timestamps
        if scan.started_at:
            console.print(f"Started: {scan.started_at.strftime('%Y-%m-%d %H:%M:%S')}")

        if scan.completed_at:
            console.print(
                f"Completed: {scan.completed_at.strftime('%Y-%m-%d %H:%M:%S')}"
            )
            duration = scan.completed_at - scan.started_at
            console.print(f"Duration: {str(duration).split('.')[0]}")

        # Results
        if hasattr(scan, "results") and scan.results:
            console.print(f"\n[bold]Results:[/bold]")
            # This will be populated when we add actual scanning
            console.print(
                "[dim]Results data will appear here after scan completes[/dim]"
            )

        console.print("─" * 50 + "\n")

    except Scan.DoesNotExist:
        console.print(f"[bold red]✗[/bold red] Scan with ID {scan_id} not found.")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[bold red]✗[/bold red] Error checking scan status: {str(e)}")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
