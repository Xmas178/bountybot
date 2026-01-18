"""
Scan Execution Engine

Orchestrates multi-phase security scanning with different tools.
Each phase is a separate function for better maintainability.
"""

from typing import Optional, Dict, List
from rich.console import Console
from django.utils import timezone

console = Console()


def execute_scan(
    scan,
    target,
    profile: str,
    yes: bool = False,
    sqlmap_level: Optional[int] = None,
    sqlmap_risk: Optional[int] = None,
    nuclei_severity: Optional[str] = None,
    ffuf_wordlist: Optional[str] = None,
    nmap_timing: Optional[str] = None,
):
    """
    Execute complete security scan across all phases.
    """
    from findings.models import Finding

    console.print(f"\n[cyan]Executing {profile} scan...[/cyan]")

    # Update scan status to running
    scan.status = "running"
    scan.started_at = timezone.now()
    scan.save()

    try:
        # PHASE 0: Subdomain Enumeration
        subdomains = execute_phase_0_subdomain_enum(scan, target, profile)

        # PHASE 1: Port Scanning
        nmap_result = execute_phase_1_port_scan(scan, target, profile)

        # PHASE 2: HTTP Probing
        httpx_results = execute_phase_2_http_probing(scan, target, nmap_result)

        # PHASE 3: Technology Detection
        all_technologies = execute_phase_3_tech_detection(
            scan, target, httpx_results, profile
        )

        # PHASE 4: Nuclei Vulnerability Scanning
        nuclei_count, severity_counts = execute_phase_4_nuclei_scan(
            scan, target, nmap_result, httpx_results, profile, nuclei_severity
        )

        # PHASE 5: SQL Injection Testing
        sqlmap_count = execute_phase_5_sqlmap_test(
            scan, httpx_results, all_technologies, profile, sqlmap_level, sqlmap_risk
        )

        # PHASE 6: XSS Detection
        dalfox_count = execute_phase_6_xss_detection(scan, httpx_results)

        # PHASE 7: Nikto Web Server Scanning
        nikto_count = execute_phase_7_nikto_scan(scan, httpx_results, profile, yes)

        # PHASE 8: FFuf Directory Fuzzing
        ffuf_count = execute_phase_8_ffuf_fuzzing(
            scan, httpx_results, profile, yes, ffuf_wordlist
        )

        # PHASE 9: WordPress Scanning
        wpscan_count = execute_phase_9_wpscan(
            scan, httpx_results, all_technologies, profile, yes
        )

        # Update scan summary
        total_findings = Finding.objects.filter(scan=scan).count()

        critical_count = Finding.objects.filter(scan=scan, severity="critical").count()
        high_count = Finding.objects.filter(scan=scan, severity="high").count()
        medium_count = Finding.objects.filter(scan=scan, severity="medium").count()
        low_count = Finding.objects.filter(scan=scan, severity="low").count()
        info_count = Finding.objects.filter(scan=scan, severity="info").count()

        scan.findings_count = total_findings
        scan.critical_count = critical_count
        scan.high_count = high_count
        scan.medium_count = medium_count
        scan.low_count = low_count
        scan.info_count = info_count
        scan.status = "completed"
        scan.completed_at = timezone.now()
        scan.notes = f"Phases: Subdomain ({len(subdomains)}), Ports ({len(nmap_result.open_ports)}), HTTP ({len(httpx_results)}), Tech ({len(all_technologies)}), CVE ({nuclei_count}), SQLi ({sqlmap_count}), XSS ({dalfox_count}), Nikto ({nikto_count}), FFuf ({ffuf_count}), WPScan ({wpscan_count})"
        scan.save()

        # Print summary
        console.print(f"\n[bold]Phase Results:[/bold]")
        console.print(f"  Subdomains: [cyan]{len(subdomains)}[/cyan]")
        console.print(f"  Open Ports: [cyan]{len(nmap_result.open_ports)}[/cyan]")
        console.print(f"  HTTP Endpoints: [cyan]{len(httpx_results)}[/cyan]")
        console.print(f"  Technologies: [cyan]{len(all_technologies)}[/cyan]")
        console.print(f"  CVE Vulnerabilities: [cyan]{nuclei_count}[/cyan]")
        console.print(f"  SQL Injections: [cyan]{sqlmap_count}[/cyan]")
        console.print(f"  XSS Vulnerabilities: [cyan]{dalfox_count}[/cyan]")
        console.print(f"  Web Server Issues: [cyan]{nikto_count}[/cyan]")
        console.print(f"  Hidden Paths: [cyan]{ffuf_count}[/cyan]")
        console.print(f"  WordPress Vulns: [cyan]{wpscan_count}[/cyan]")

        console.print(f"\n[bold]Severity Breakdown:[/bold]")
        if critical_count > 0:
            console.print(f"  🔴 Critical: [bold red]{critical_count}[/bold red]")
        if high_count > 0:
            console.print(f"  🟠 High: [bold yellow]{high_count}[/bold yellow]")
        if medium_count > 0:
            console.print(f"  🟡 Medium: [bold blue]{medium_count}[/bold blue]")
        if low_count > 0:
            console.print(f"  🟢 Low: [dim]{low_count}[/dim]")
        console.print(f"  ℹ️  Info: [dim]{info_count}[/dim]")

        console.print(f"\n[bold green]✓ Scan completed![/bold green]")
        console.print(f"  Total Findings: [cyan]{total_findings}[/cyan]")
        console.print(f"  Duration: {scan.completed_at - scan.started_at}")

    except Exception as e:
        scan.status = "failed"
        scan.completed_at = timezone.now()
        scan.notes = f"Error: {str(e)}"
        scan.save()

        console.print(f"[bold red]✗ Scan failed: {str(e)}[/bold red]")
        raise
    """
    Execute complete security scan across all phases.

    Args:
        scan: Django Scan model instance
        target: Django Target model instance
        profile: Scan profile (quick, standard, deep)
        yes: Auto-accept all prompts
        sqlmap_level: Custom SQLMap level (1-5)
        sqlmap_risk: Custom SQLMap risk (1-3)
        nuclei_severity: Custom Nuclei severity filter
        ffuf_wordlist: Custom FFuf wordlist
        nmap_timing: Custom Nmap timing
    """
    console.print(f"\n[cyan]Executing {profile} scan...[/cyan]")

    # Update scan status to running
    scan.status = "running"
    scan.started_at = timezone.now()
    scan.save()

    try:
        # PHASE 0: Subdomain Enumeration
        subdomains = execute_phase_0_subdomain_enum(scan, target, profile)

        # PHASE 1: Port Scanning
        nmap_result = execute_phase_1_port_scan(scan, target, profile)

        # PHASE 2: HTTP Probing
        http_results = execute_phase_2_http_probing(scan, target, nmap_result)

        # PHASE 3: Technology Detection
        all_technologies = execute_phase_3_tech_detection(
            scan, target, http_results, profile
        )

        # TODO: Phases 4-9...

        # Mark scan as completed
        scan.status = "completed"
        scan.completed_at = timezone.now()
        scan.save()

        console.print(f"\n[bold green]✓ Scan completed![/bold green]")

    except Exception as e:
        scan.status = "failed"
        scan.completed_at = timezone.now()
        scan.notes = f"Error: {str(e)}"
        scan.save()

        console.print(f"[bold red]✗ Scan failed: {str(e)}[/bold red]")
        raise


def execute_phase_0_subdomain_enum(scan, target, profile):
    """
    Phase 0: Subdomain Enumeration

    Uses Subfinder to discover subdomains for domain targets.
    Skipped for IP and URL targets.
    """
    from cli.utils.scanners.subfinder_enum import SubfinderEnumerator
    from findings.models import Finding

    subdomains = []

    if target.target_type == "domain":
        console.print(f"[cyan]Phase 0: Subdomain enumeration...[/cyan]")

        try:
            subfinder_enum = SubfinderEnumerator()
            subfinder_result = subfinder_enum.enumerate(target.value, timeout=60)
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
            console.print(f"  [yellow]Subdomain enumeration skipped: {str(e)}[/yellow]")
    else:
        console.print(
            f"[dim]Skipping subdomain enumeration (target is not a domain)[/dim]"
        )

    return subdomains


def execute_phase_1_port_scan(scan, target, profile):
    """
    Phase 1: Port Scanning with Nmap

    Scans for open ports and running services.
    Profile determines scan depth and timing.
    """
    from cli.utils.scanners.nmap_scanner import NmapScanner
    from findings.models import Finding

    console.print(f"[cyan]Phase 1: Port scanning with nmap...[/cyan]")

    nmap_scanner = NmapScanner()

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

    return nmap_result


def execute_phase_2_http_probing(scan, target, nmap_result):
    """
    Phase 2: HTTP Endpoint Probing

    Uses HTTPx to probe discovered ports for HTTP/HTTPS services.
    Extracts metadata like titles, web servers, and technologies.
    """
    from cli.utils.scanners.httpx_prober import HttpxProber
    from findings.models import Finding

    console.print(f"\n[cyan]Phase 2: Probing HTTP endpoints...[/cyan]")

    # Extract ports that might serve HTTP
    http_ports = [int(p["port"]) for p in nmap_result.open_ports]
    httpx_results = []

    if http_ports:
        httpx_prober = HttpxProber()
        httpx_results = httpx_prober.probe_from_ports(target.value, http_ports)
        console.print(f"  Found {len(httpx_results)} active HTTP endpoints")

        # Create findings for HTTP endpoints
        for http_result in httpx_results:
            # Build description
            description = f"HTTP endpoint is alive and responding.\n"
            description += f"Status Code: {http_result.status_code}\n"
            if http_result.title:
                description += f"Page Title: {http_result.title}\n"
            if http_result.webserver:
                description += f"Web Server: {http_result.webserver}\n"
            if http_result.tech_stack:
                description += f"Technologies: {', '.join(http_result.tech_stack)}\n"

            # Build proof of concept
            poc = f"URL: {http_result.url}\n"
            poc += f"Status: {http_result.status_code}\n"
            if http_result.content_length:
                poc += f"Content Length: {http_result.content_length} bytes\n"
            if http_result.tech_stack:
                poc += f"Tech Stack:\n"
                for tech in http_result.tech_stack:
                    poc += f"  - {tech}\n"

            Finding.objects.create(
                scan=scan,
                title=f"HTTP Endpoint: {http_result.url}",
                severity="info",
                description=description.strip(),
                proof_of_concept=poc.strip(),
                status="new",
                affected_url=http_result.url,
            )
    else:
        console.print(f"  No HTTP ports to probe")

    return httpx_results


def execute_phase_3_tech_detection(scan, target, httpx_results, profile):
    """
    Phase 3: Technology Detection with WhatWeb

    Identifies web technologies, CMS, frameworks, and server software.
    Results are used by later phases (e.g., SQLMap DBMS detection).
    """
    from cli.utils.scanners.whatweb_detector import (
        detect_technologies,
        format_technologies_for_finding,
    )
    from findings.models import Finding

    console.print(f"\n[cyan]Phase 3: Technology detection with WhatWeb...[/cyan]")

    all_technologies = {}

    if httpx_results:
        for http_result in httpx_results:
            whatweb_target = http_result.url
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

    return all_technologies


def execute_phase_4_nuclei_scan(
    scan, target, nmap_result, httpx_results, profile, nuclei_severity=None
):
    """
    Phase 4: Nuclei CVE and Vulnerability Scanning

    Scans for known vulnerabilities using 10,000+ templates.
    Supports severity filtering and profile-based timeouts.
    """
    from cli.utils.scanners.nuclei_scanner import run_nuclei_scan
    from findings.models import Finding
    from urllib.parse import urlparse

    console.print(f"\n[cyan]Phase 4: Vulnerability scanning with nuclei...[/cyan]")

    # Collect all discovered URLs for nuclei scanning
    scan_targets = []

    # Add main target
    if target.target_type == "url":
        scan_targets.append(target.value)
    elif target.target_type == "domain":
        # Don't add defaults - let HTTPx discover actual endpoints
        pass
    elif target.target_type == "ip":
        # Add IP with common HTTP ports (only if not discovered by HTTPx)
        for port_info in nmap_result.open_ports:
            port = port_info.get("port")
            if port in [80, 443, 8000, 8080, 8443]:
                protocol = "https" if port in [443, 8443] else "http"
                scan_targets.append(f"{protocol}://{target.value}:{port}")

    # Add discovered HTTP endpoints from Phase 2 (primary source)
    if httpx_results:
        for http_result in httpx_results:
            scan_targets.append(http_result.url)

    # Remove duplicates and normalize URLs
    seen = set()
    unique_targets = []

    for url in scan_targets:
        # Normalize URL (remove default ports)
        parsed = urlparse(url)

        # Normalize: https://example.com:443 → https://example.com
        if (parsed.scheme == "https" and parsed.port == 443) or (
            parsed.scheme == "http" and parsed.port == 80
        ):
            normalized = f"{parsed.scheme}://{parsed.hostname}{parsed.path or ''}"
        else:
            normalized = url

        if normalized not in seen:
            seen.add(normalized)
            unique_targets.append(url)

    scan_targets = unique_targets
    console.print(f"  [dim]Scanning {len(scan_targets)} unique endpoint(s)[/dim]")

    # Run nuclei on each target
    nuclei_findings_count = 0
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    # Increase timeout for deep profile
    nuclei_timeout = 600 if profile == "deep" else 300  # 10 min vs 5 min

    for scan_target in scan_targets:
        console.print(f"  Scanning: {scan_target}")

        try:
            # Run nuclei with severity filter (if provided)
            nuclei_findings = run_nuclei_scan(
                target=scan_target,
                scan_id=scan.id,
                severity=nuclei_severity.split(",") if nuclei_severity else None,
                timeout=nuclei_timeout,
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
        console.print(f"    Critical: [red]{severity_counts['critical']}[/red]")
        console.print(f"    High: [yellow]{severity_counts['high']}[/yellow]")
        console.print(f"    Medium: [blue]{severity_counts['medium']}[/blue]")
        console.print(f"    Low: [dim]{severity_counts['low']}[/dim]")
        console.print(f"    Info: [dim]{severity_counts['info']}[/dim]")

    return nuclei_findings_count, severity_counts


def execute_phase_5_sqlmap_test(
    scan, httpx_results, all_technologies, profile, sqlmap_level=None, sqlmap_risk=None
):
    """
    Phase 5: SQL Injection Testing with SQLMap

    Tests for SQL injection vulnerabilities.
    Uses WhatWeb data to detect DBMS for faster testing.
    """
    from cli.utils.scanners.sqlmap_tester import test_sql_injection
    from findings.models import Finding

    console.print(f"\n[cyan]Phase 5: SQL injection testing with SQLMap...[/cyan]")

    sqlmap_targets = []

    # Collect HTTP endpoints
    if httpx_results:
        for http_result in httpx_results:
            sqlmap_targets.append(http_result.url)

    sqlmap_findings_count = 0

    # Determine SQLMap level based on scan profile or custom parameter
    if sqlmap_level is None:
        sqlmap_level = 1  # Default
        if profile == "standard":
            sqlmap_level = 2  # Test cookies too
        elif profile == "deep":
            sqlmap_level = 3  # Test cookies + User-Agent

    # Determine SQLMap risk (default 1, or use custom parameter)
    if sqlmap_risk is None:
        sqlmap_risk = 1  # Always safe by default

    for sqlmap_target in sqlmap_targets:
        console.print(f"  Testing: {sqlmap_target} (level {sqlmap_level})")

        try:
            # Detect DBMS from WhatWeb data if available
            detected_dbms = None
            if sqlmap_target in all_technologies:
                tech_data = all_technologies[sqlmap_target]
                technologies = tech_data.get("technologies", {})

                # Check for database technologies
                for tech_name in technologies.keys():
                    tech_lower = tech_name.lower()
                    if "mysql" in tech_lower:
                        detected_dbms = "MySQL"
                    elif "postgresql" in tech_lower or "postgres" in tech_lower:
                        detected_dbms = "PostgreSQL"
                    elif "microsoft sql" in tech_lower or "mssql" in tech_lower:
                        detected_dbms = "Microsoft SQL Server"
                    elif "oracle" in tech_lower:
                        detected_dbms = "Oracle"
                    elif "sqlite" in tech_lower:
                        detected_dbms = "SQLite"

            if detected_dbms:
                console.print(f"    [dim]Detected DBMS: {detected_dbms}[/dim]")

            # Run SQLMap
            sqlmap_findings = test_sql_injection(
                target=sqlmap_target,
                scan_id=scan.id,
                level=sqlmap_level,
                risk=sqlmap_risk,
                dbms=detected_dbms,
                timeout=600,  # 10 minutes
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
                sqlmap_findings_count += 1

            if sqlmap_findings:
                console.print(
                    f"    [red]⚠️  Found {len(sqlmap_findings)} SQL injection vulnerabilities![/red]"
                )
            else:
                console.print(f"    [green]✓ No SQL injection found[/green]")

        except Exception as e:
            console.print(
                f"    [yellow]Warning: SQLMap failed for {sqlmap_target}: {str(e)}[/yellow]"
            )
            continue

    if sqlmap_findings_count > 0:
        console.print(
            f"\n[bold red]🚨 CRITICAL: {sqlmap_findings_count} SQL injection vulnerabilities detected![/bold red]"
        )

    return sqlmap_findings_count


def execute_phase_6_xss_detection(scan, httpx_results):
    """
    Phase 6: XSS Detection with Dalfox

    Tests for Cross-Site Scripting vulnerabilities.
    """
    from cli.utils.scanners.dalfox_scanner import test_xss_vulnerabilities
    from findings.models import Finding

    console.print(f"\n[cyan]Phase 6: XSS detection with Dalfox...[/cyan]")

    dalfox_targets = []

    if httpx_results:
        for http_result in httpx_results:
            dalfox_targets.append(http_result.url)

    dalfox_findings_count = 0

    for dalfox_target in dalfox_targets:
        console.print(f"  Testing: {dalfox_target}")

        try:
            # Run Dalfox XSS detection
            dalfox_findings = test_xss_vulnerabilities(
                target=dalfox_target,
                scan_id=scan.id,
                mode="url",
                timeout=600,  # 10 minutes
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
                dalfox_findings_count += 1

            if dalfox_findings:
                console.print(
                    f"    [red]⚠️  Found {len(dalfox_findings)} XSS vulnerabilities![/red]"
                )
            else:
                console.print(f"    [green]✓ No XSS vulnerabilities found[/green]")

        except Exception as e:
            console.print(
                f"    [yellow]Warning: Dalfox failed for {dalfox_target}: {str(e)}[/yellow]"
            )
            continue

    if dalfox_findings_count > 0:
        console.print(
            f"\n[bold red]🚨 CRITICAL: {dalfox_findings_count} XSS vulnerabilities detected![/bold red]"
        )

    return dalfox_findings_count


def execute_phase_7_nikto_scan(scan, httpx_results, profile, yes=False):
    """
    Phase 7: Nikto Web Server Scanning

    Scans for web server vulnerabilities and misconfigurations.
    Optional - asks user confirmation unless --yes flag is used.
    """
    import typer
    from cli.utils.scanners.nikto_scanner import scan_web_vulnerabilities
    from findings.models import Finding
    from urllib.parse import urlparse

    nikto_findings_count = 0

    if profile == "quick":
        console.print(
            f"\n[dim]Skipping Nikto scan in quick profile (use --profile standard for web server testing)[/dim]"
        )
        return nikto_findings_count

    if not httpx_results:
        return nikto_findings_count

    console.print(f"\n[cyan]Phase 7: Web server scanning with Nikto...[/cyan]")

    # Estimate scan time
    if profile == "standard":
        time_per_endpoint = "5-10 minutes"
        max_time = 10
    else:  # deep
        time_per_endpoint = "15-30 minutes"
        max_time = 30

    total_endpoints = len(httpx_results)

    console.print(
        f"  [yellow]⚠️  Nikto scan takes {time_per_endpoint} per endpoint.[/yellow]"
    )
    console.print(
        f"  [yellow]Found {total_endpoints} HTTP endpoint(s) to scan.[/yellow]"
    )

    # Ask user for confirmation (or auto-accept with --yes)
    if yes:
        run_nikto = True
        console.print("  [dim]Auto-accepting Nikto scan (--yes flag)[/dim]")
    else:
        run_nikto = typer.confirm("  Run Nikto web server scan?", default=False)

    if run_nikto:
        console.print(f"  [cyan]Starting Nikto scan (this will take a while)...[/cyan]")

        for http_result in httpx_results:
            # Parse URL to get host and port
            parsed = urlparse(http_result.url)
            host = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
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
                        proof_of_concept=finding_data.get("proof_of_concept"),
                        status="new",
                        affected_url=http_result.url,
                    )
                    nikto_findings_count += 1

                if nikto_findings:
                    console.print(
                        f"    [yellow]⚠️  Found {len(nikto_findings)} issues![/yellow]"
                    )
                else:
                    console.print(f"    [green]✓ No significant issues found[/green]")

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

    return nikto_findings_count


def execute_phase_8_ffuf_fuzzing(
    scan, httpx_results, profile, yes=False, ffuf_wordlist=None
):
    """
    Phase 8: FFuf Directory/File Fuzzing

    Discovers hidden directories and files.
    Optional - asks user confirmation unless --yes flag is used.
    """
    import typer
    from cli.utils.scanners.ffuf_fuzzer import fuzz_directories
    from findings.models import Finding

    ffuf_findings_count = 0

    if profile == "quick":
        console.print(
            f"\n[dim]Skipping FFuf fuzzing in quick profile (use --profile standard for directory discovery)[/dim]"
        )
        return ffuf_findings_count

    if not httpx_results:
        return ffuf_findings_count

    console.print(f"\n[cyan]Phase 8: Directory/file fuzzing with FFuf...[/cyan]")

    # Select wordlist based on custom parameter or profile
    if ffuf_wordlist is not None:
        wordlist = ffuf_wordlist
    elif profile == "standard":
        wordlist = "common"
    else:  # deep
        wordlist = "medium"

    # Set time estimates based on wordlist
    if wordlist == "common":
        wordlist_size = "~4,700 entries"
        time_estimate = "2-5 minutes"
        max_time = 300
    elif wordlist == "medium":
        wordlist_size = "~220,000 entries"
        time_estimate = "10-30 minutes"
        max_time = 1800
    elif wordlist == "large":
        wordlist_size = "~1,000,000 entries"
        time_estimate = "30-60 minutes"
        max_time = 3600
    else:
        wordlist_size = "custom"
        time_estimate = "varies"
        max_time = 1800

    total_endpoints = len(httpx_results)

    console.print(
        f"  [yellow]⚠️  FFuf fuzzing takes {time_estimate} per endpoint.[/yellow]"
    )
    console.print(f"  [yellow]Wordlist: {wordlist} ({wordlist_size})[/yellow]")
    console.print(
        f"  [yellow]Found {total_endpoints} HTTP endpoint(s) to fuzz.[/yellow]"
    )

    # Ask user for confirmation (or auto-accept with --yes)
    if yes:
        run_ffuf = True
        console.print("  [dim]Auto-accepting FFuf fuzzing (--yes flag)[/dim]")
    else:
        run_ffuf = typer.confirm("  Run FFuf directory fuzzing?", default=False)

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
                    threads=20 if profile == "standard" else 40,
                )

                # Create Finding objects in database
                for finding_data in ffuf_findings:
                    Finding.objects.create(
                        scan=scan,
                        title=finding_data["title"],
                        severity=finding_data["severity"],
                        description=finding_data["description"],
                        proof_of_concept=finding_data.get("proof_of_concept"),
                        status="new",
                        affected_url=http_result.url,
                    )
                    ffuf_findings_count += 1

                if ffuf_findings:
                    console.print(
                        f"    [yellow]⚠️  Found {len(ffuf_findings)} hidden paths![/yellow]"
                    )
                else:
                    console.print(f"    [green]✓ No hidden paths discovered[/green]")

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

    return ffuf_findings_count


def execute_phase_9_wpscan(scan, httpx_results, all_technologies, profile, yes=False):
    """
    Phase 9: WordPress Scanning with WPScan

    Scans WordPress sites for vulnerable plugins, themes, and core.
    Only runs if WordPress is detected in Phase 3.
    """
    import typer
    from cli.utils.scanners.wpscan_scanner import scan_wordpress
    from findings.models import Finding

    wpscan_findings_count = 0

    # Check if WordPress was detected in Phase 3
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
        console.print(f"\n[cyan]Phase 9: WordPress scanning with WPScan...[/cyan]")
        console.print(
            f"  [green]✓ WordPress detected on {len(wordpress_urls)} endpoint(s)[/green]"
        )

        console.print(
            f"  [yellow]⚠️  WPScan takes 5-10 minutes per WordPress site.[/yellow]"
        )

        # Ask user for confirmation (or auto-accept with --yes)
        if yes:
            run_wpscan = True
            console.print("  [dim]Auto-accepting WPScan (--yes flag)[/dim]")
        else:
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
                            proof_of_concept=finding_data.get("proof_of_concept"),
                            status="new",
                            affected_url=wp_url,
                        )
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
        console.print(f"\n[dim]No WordPress detected - skipping WPScan[/dim]")

    return wpscan_findings_count
