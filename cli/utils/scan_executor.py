"""
Scan Execution Engine

Orchestrates multi-phase security scanning with different tools.
Each phase is a separate function for better maintainability.
"""

from typing import Optional, Dict, List
from rich.console import Console
from django.utils import timezone
from cli.utils.logger import (
    setup_logger,
    log_phase_start,
    log_phase_complete,
    log_tool_execution,
    log_tool_success,
    log_tool_error,
)
from cli.utils.error_handler import safe_tool_execution, validate_scan_requirements

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
    # Setup logger for this scan
    logger = setup_logger(scan_id=scan.id, log_level="INFO")
    logger.info(f"Starting {profile} scan for target: {target.value}")

    # Validate required tools
    logger.info("Validating security tools...")
    tool_status = validate_scan_requirements(logger=logger)

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


def execute_phase_0_subdomain_enum(scan, target, profile):
    """
    Phase 0: Subdomain Enumeration (domain targets only).
    """
    from cli.utils.scanners.subfinder_enum import enumerate_subdomains
    from findings.models import Finding

    log_phase_start(logger, 0, "Subdomain Enumeration")

    # Skip if target is not a domain
    if target.target_type != "domain":
        logger.info("Skipping subdomain enumeration - target is not a domain")
        console.print("[dim]Skipping subdomain enumeration (not a domain target)[/dim]")
        log_phase_complete(logger, 0)
        return []

    # Execute subfinder with error handling
    def run_subfinder():
        log_tool_execution(logger, "subfinder", f"subfinder -d {target.value}")
        return enumerate_subdomains(target.value, scan.id)

    success, subdomains = safe_tool_execution(
        func=run_subfinder,
        tool_name="subfinder",
        logger=logger,
        max_retries=2,
        continue_on_error=True,
    )

    if not success:
        logger.warning("Subfinder failed - continuing without subdomain enumeration")
        log_phase_complete(logger, 0)
        return []

    # Save subdomains as findings
    for subdomain in subdomains:
        Finding.objects.create(
            scan=scan,
            title=f"Subdomain discovered: {subdomain}",
            severity="info",
            description=f"Subdomain enumeration found: {subdomain}",
            tool="subfinder",
            affected_url=subdomain,
        )

    log_tool_success(logger, "subfinder", len(subdomains))
    console.print(
        f"[bold]Phase 0 Results:[/bold] {len(subdomains)} subdomains discovered"
    )

    log_phase_complete(logger, 0)
    return subdomains


def execute_phase_1_port_scan(scan, target, profile):
    """
    Phase 1: Port Scanning.
    """
    from cli.utils.scanners.nmap_scanner import NmapScanner, NmapResult
    from findings.models import Finding

    log_phase_start(logger, 1, "Port Scanning")

    # Initialize scanner
    scanner = NmapScanner()

    # Execute nmap with error handling
    def run_nmap():
        log_tool_execution(logger, "nmap", f"nmap {target.value}")
        return scanner.scan(target.value, profile=profile)

    success, nmap_result = safe_tool_execution(
        func=run_nmap,
        tool_name="nmap",
        logger=logger,
        max_retries=2,
        continue_on_error=True,
    )

    if not success:
        logger.warning("Nmap failed - returning empty result")
        log_phase_complete(logger, 1)
        return NmapResult(host=target.value, open_ports=[], scan_output="Scan failed")

    # Save port findings
    for port_info in nmap_result.open_ports:
        port = port_info["port"]
        service = port_info.get("service", "unknown")
        version = port_info.get("version", "")

        description = f"Port {port}/{service}"
        if version:
            description += f" - {version}"

        Finding.objects.create(
            scan=scan,
            title=f"Open port: {port}/{service}",
            severity="info",
            description=description,
            tool="nmap",
            affected_url=f"{target.value}:{port}",
        )

    log_tool_success(logger, "nmap", len(nmap_result.open_ports))
    console.print(
        f"[bold]Phase 1 Results:[/bold] {len(nmap_result.open_ports)} open ports"
    )

    log_phase_complete(logger, 1)
    return nmap_result


def execute_phase_2_http_probing(scan, target, nmap_result):
    """
    Phase 2: HTTP Probing.
    """
    from cli.utils.scanners.httpx_prober import HttpxProber, HttpxResult
    from findings.models import Finding

    log_phase_start(logger, 2, "HTTP Probing")

    # Build list of URLs to probe
    urls_to_probe = []

    # Add target itself
    urls_to_probe.append(target.value)

    # Add URLs from open ports (if nmap found web ports)
    for port_info in nmap_result.open_ports:
        port = port_info["port"]
        # Common web ports
        if port in [80, 443, 8000, 8080, 8443, 3000, 5000]:
            protocol = "https" if port in [443, 8443] else "http"
            urls_to_probe.append(f"{protocol}://{target.value}:{port}")

    # Initialize prober
    prober = HttpxProber()

    # Execute httpx with error handling
    def run_httpx():
        log_tool_execution(logger, "httpx", f"httpx -l {len(urls_to_probe)} URLs")
        return prober.probe_urls(urls_to_probe)

    success, httpx_results = safe_tool_execution(
        func=run_httpx,
        tool_name="httpx",
        logger=logger,
        max_retries=2,
        continue_on_error=True,
    )

    if not success:
        logger.warning("HTTPx failed - returning empty results")
        log_phase_complete(logger, 2)
        return []

    # Save HTTP findings
    for result in httpx_results:
        Finding.objects.create(
            scan=scan,
            title=f"Live HTTP endpoint: {result.url}",
            severity="info",
            description=f"Status: {result.status_code}, Title: {result.title}",
            tool="httpx",
            affected_url=result.url,
        )

    log_tool_success(logger, "httpx", len(httpx_results))
    console.print(
        f"[bold]Phase 2 Results:[/bold] {len(httpx_results)} live HTTP endpoints"
    )

    log_phase_complete(logger, 2)
    return httpx_results


def execute_phase_3_tech_detection(scan, target, httpx_results, profile):
    """
    Phase 3: Technology Detection with WhatWeb.
    """
    from cli.utils.scanners.whatweb_detector import WhatWebDetector
    from findings.models import Finding

    log_phase_start(logger, 3, "Technology Detection")

    if not httpx_results:
        logger.info("No HTTP endpoints to scan - skipping technology detection")
        console.print("[dim]No HTTP endpoints found - skipping WhatWeb[/dim]")
        log_phase_complete(logger, 3)
        return {}

    # Initialize detector
    detector = WhatWebDetector()

    # Build list of URLs
    urls = [result.url for result in httpx_results]

    # Execute WhatWeb with error handling
    def run_whatweb():
        log_tool_execution(logger, "whatweb", f"whatweb {len(urls)} URLs")
        return detector.detect_technologies(urls, aggression=1)

    success, all_technologies = safe_tool_execution(
        func=run_whatweb,
        tool_name="whatweb",
        logger=logger,
        max_retries=2,
        continue_on_error=True,
    )

    if not success:
        logger.warning("WhatWeb failed - returning empty results")
        log_phase_complete(logger, 3)
        return {}

    # Save technology findings
    for url, technologies in all_technologies.items():
        if technologies:
            tech_list = ", ".join(technologies)
            Finding.objects.create(
                scan=scan,
                title=f"Technologies detected: {url}",
                severity="info",
                description=f"Detected: {tech_list}",
                tool="whatweb",
                affected_url=url,
            )

    total_techs = sum(len(techs) for techs in all_technologies.values())
    log_tool_success(logger, "whatweb", total_techs)
    console.print(f"[bold]Phase 3 Results:[/bold] {total_techs} technologies detected")

    log_phase_complete(logger, 3)
    return all_technologies


def execute_phase_4_nuclei_scan(
    scan, target, nmap_result, httpx_results, profile, nuclei_severity
):
    """
    Phase 4: Nuclei CVE Scanning.
    """
    from cli.utils.scanners.nuclei_scanner import NucleiScanner
    from findings.models import Finding

    log_phase_start(logger, 4, "Nuclei CVE Scanning")

    # Build target list (HTTP URLs)
    if not httpx_results:
        logger.info("No HTTP endpoints to scan - skipping Nuclei")
        console.print("[dim]No HTTP endpoints found - skipping Nuclei[/dim]")
        log_phase_complete(logger, 4)
        return 0, {}

    urls = [result.url for result in httpx_results]

    # Initialize scanner
    scanner = NucleiScanner()

    # Execute Nuclei with error handling
    def run_nuclei():
        log_tool_execution(logger, "nuclei", f"nuclei -l {len(urls)} URLs")
        return scanner.scan(urls=urls, profile=profile, severity_filter=nuclei_severity)

    success, nuclei_findings = safe_tool_execution(
        func=run_nuclei,
        tool_name="nuclei",
        logger=logger,
        max_retries=1,  # Nuclei takes long, only 1 retry
        continue_on_error=True,
    )

    if not success:
        logger.warning("Nuclei failed - returning empty results")
        log_phase_complete(logger, 4)
        return 0, {}

    # Count by severity
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    # Save Nuclei findings
    for finding in nuclei_findings:
        Finding.objects.create(
            scan=scan,
            title=finding["name"],
            severity=finding["severity"],
            description=finding["description"],
            tool="nuclei",
            affected_url=finding["matched_at"],
            cvss_score=finding.get("cvss_score"),
        )
        severity_counts[finding["severity"]] += 1

    log_tool_success(logger, "nuclei", len(nuclei_findings))
    console.print(
        f"[bold]Phase 4 Results:[/bold] {len(nuclei_findings)} CVE findings "
        f"(C:{severity_counts['critical']} H:{severity_counts['high']} "
        f"M:{severity_counts['medium']} L:{severity_counts['low']} I:{severity_counts['info']})"
    )

    log_phase_complete(logger, 4)
    return len(nuclei_findings), severity_counts


def execute_phase_5_sqlmap_test(
    scan, httpx_results, all_technologies, profile, sqlmap_level, sqlmap_risk
):
    """
    Phase 5: SQL Injection Testing with SQLMap.
    """
    from cli.utils.scanners.sqlmap_tester import SqlmapTester
    from findings.models import Finding

    log_phase_start(logger, 5, "SQL Injection Testing")

    if not httpx_results:
        logger.info("No HTTP endpoints to test - skipping SQLMap")
        console.print("[dim]No HTTP endpoints found - skipping SQLMap[/dim]")
        log_phase_complete(logger, 5)
        return 0

    # Build URL list
    urls = [result.url for result in httpx_results]

    # Auto-detect DBMS from WhatWeb results
    dbms_hint = None
    for url, technologies in all_technologies.items():
        for tech in technologies:
            tech_lower = tech.lower()
            if "mysql" in tech_lower:
                dbms_hint = "MySQL"
                break
            elif "postgres" in tech_lower:
                dbms_hint = "PostgreSQL"
                break
            elif "mssql" in tech_lower or "sql server" in tech_lower:
                dbms_hint = "Microsoft SQL Server"
                break
            elif "oracle" in tech_lower:
                dbms_hint = "Oracle"
                break
        if dbms_hint:
            break

    if dbms_hint:
        logger.info(f"Auto-detected DBMS: {dbms_hint}")
        console.print(f"[cyan]Auto-detected DBMS: {dbms_hint}[/cyan]")

    # Initialize tester
    tester = SqlmapTester()

    # Execute SQLMap with error handling
    def run_sqlmap():
        log_tool_execution(logger, "sqlmap", f"sqlmap {len(urls)} URLs")
        return tester.test_urls(
            urls=urls,
            profile=profile,
            dbms=dbms_hint,
            level=sqlmap_level,
            risk=sqlmap_risk,
        )

    success, sqlmap_findings = safe_tool_execution(
        func=run_sqlmap,
        tool_name="sqlmap",
        logger=logger,
        max_retries=1,  # SQLMap takes long, only 1 retry
        continue_on_error=True,
    )

    if not success:
        logger.warning("SQLMap failed - returning empty results")
        log_phase_complete(logger, 5)
        return 0

    # Save SQLMap findings
    for finding in sqlmap_findings:
        Finding.objects.create(
            scan=scan,
            title=finding["title"],
            severity=finding["severity"],
            description=finding["description"],
            tool="sqlmap",
            affected_url=finding["url"],
        )

    log_tool_success(logger, "sqlmap", len(sqlmap_findings))
    console.print(
        f"[bold]Phase 5 Results:[/bold] {len(sqlmap_findings)} SQL injection vulnerabilities"
    )

    log_phase_complete(logger, 5)
    return len(sqlmap_findings)


def execute_phase_6_xss_detection(scan, httpx_results):
    """
    Phase 6: XSS Detection with Dalfox.
    """
    from cli.utils.scanners.dalfox_scanner import DalfoxScanner
    from findings.models import Finding

    log_phase_start(logger, 6, "XSS Detection")

    if not httpx_results:
        logger.info("No HTTP endpoints to test - skipping Dalfox")
        console.print("[dim]No HTTP endpoints found - skipping Dalfox[/dim]")
        log_phase_complete(logger, 6)
        return 0

    # Build URL list
    urls = [result.url for result in httpx_results]

    # Initialize scanner
    scanner = DalfoxScanner()

    # Execute Dalfox with error handling
    def run_dalfox():
        log_tool_execution(logger, "dalfox", f"dalfox {len(urls)} URLs")
        return scanner.scan_urls(urls)

    success, dalfox_findings = safe_tool_execution(
        func=run_dalfox,
        tool_name="dalfox",
        logger=logger,
        max_retries=2,
        continue_on_error=True,
    )

    if not success:
        logger.warning("Dalfox failed - returning empty results")
        log_phase_complete(logger, 6)
        return 0

    # Save Dalfox findings
    for finding in dalfox_findings:
        Finding.objects.create(
            scan=scan,
            title=finding["title"],
            severity=finding["severity"],
            description=finding["description"],
            tool="dalfox",
            affected_url=finding["url"],
        )

    log_tool_success(logger, "dalfox", len(dalfox_findings))
    console.print(
        f"[bold]Phase 6 Results:[/bold] {len(dalfox_findings)} XSS vulnerabilities"
    )

    log_phase_complete(logger, 6)
    return len(dalfox_findings)


def execute_phase_7_nikto_scan(scan, httpx_results, profile, yes):
    """
    Phase 7: Nikto Web Server Scanning.
    """
    from cli.utils.scanners.nikto_scanner import NiktoScanner
    from findings.models import Finding

    log_phase_start(logger, 7, "Nikto Web Server Scanning")

    if not httpx_results:
        logger.info("No HTTP endpoints to scan - skipping Nikto")
        console.print("[dim]No HTTP endpoints found - skipping Nikto[/dim]")
        log_phase_complete(logger, 7)
        return 0

    # Skip Nikto for quick profile
    if profile == "quick":
        logger.info("Quick profile - skipping Nikto")
        console.print("[dim]Quick profile - skipping Nikto[/dim]")
        log_phase_complete(logger, 7)
        return 0

    # Ask user confirmation (unless --yes flag)
    if not yes:
        console.print(
            f"\n[yellow]Nikto scans can take 5-30 minutes per endpoint ({len(httpx_results)} endpoints found)[/yellow]"
        )
        response = input("Run Nikto web server scan? [y/N]: ").strip().lower()
        if response not in ["y", "yes"]:
            logger.info("User skipped Nikto scan")
            console.print("[dim]Skipping Nikto scan[/dim]")
            log_phase_complete(logger, 7)
            return 0

    # Build URL list
    urls = [result.url for result in httpx_results]

    # Initialize scanner
    scanner = NiktoScanner()

    # Execute Nikto with error handling
    def run_nikto():
        log_tool_execution(logger, "nikto", f"nikto {len(urls)} URLs")
        return scanner.scan_urls(urls, profile=profile)

    success, nikto_findings = safe_tool_execution(
        func=run_nikto,
        tool_name="nikto",
        logger=logger,
        max_retries=1,  # Nikto takes very long, only 1 retry
        continue_on_error=True,
    )

    if not success:
        logger.warning("Nikto failed - returning empty results")
        log_phase_complete(logger, 7)
        return 0

    # Save Nikto findings
    for finding in nikto_findings:
        Finding.objects.create(
            scan=scan,
            title=finding["title"],
            severity=finding["severity"],
            description=finding["description"],
            tool="nikto",
            affected_url=finding["url"],
        )

    log_tool_success(logger, "nikto", len(nikto_findings))
    console.print(
        f"[bold]Phase 7 Results:[/bold] {len(nikto_findings)} web server vulnerabilities"
    )

    log_phase_complete(logger, 7)
    return len(nikto_findings)


def execute_phase_8_ffuf_fuzzing(scan, httpx_results, profile, yes, ffuf_wordlist):
    """
    Phase 8: FFuf Directory/File Fuzzing.
    """
    from cli.utils.scanners.ffuf_fuzzer import FfufFuzzer
    from findings.models import Finding

    log_phase_start(logger, 8, "FFuf Directory Fuzzing")

    if not httpx_results:
        logger.info("No HTTP endpoints to fuzz - skipping FFuf")
        console.print("[dim]No HTTP endpoints found - skipping FFuf[/dim]")
        log_phase_complete(logger, 8)
        return 0

    # Skip FFuf for quick profile
    if profile == "quick":
        logger.info("Quick profile - skipping FFuf")
        console.print("[dim]Quick profile - skipping FFuf[/dim]")
        log_phase_complete(logger, 8)
        return 0

    # Ask user confirmation (unless --yes flag)
    if not yes:
        wordlist_size = "~4,700" if profile == "standard" else "~220,000"
        console.print(
            f"\n[yellow]FFuf fuzzing with {wordlist_size} wordlist can take 2-30 minutes per endpoint ({len(httpx_results)} endpoints found)[/yellow]"
        )
        response = input("Run FFuf directory fuzzing? [y/N]: ").strip().lower()
        if response not in ["y", "yes"]:
            logger.info("User skipped FFuf scan")
            console.print("[dim]Skipping FFuf scan[/dim]")
            log_phase_complete(logger, 8)
            return 0

    # Build URL list
    urls = [result.url for result in httpx_results]

    # Initialize fuzzer
    fuzzer = FfufFuzzer()

    # Execute FFuf with error handling
    def run_ffuf():
        log_tool_execution(logger, "ffuf", f"ffuf {len(urls)} URLs")
        return fuzzer.fuzz_urls(urls, profile=profile, wordlist=ffuf_wordlist)

    success, ffuf_findings = safe_tool_execution(
        func=run_ffuf,
        tool_name="ffuf",
        logger=logger,
        max_retries=1,  # FFuf takes long, only 1 retry
        continue_on_error=True,
    )

    if not success:
        logger.warning("FFuf failed - returning empty results")
        log_phase_complete(logger, 8)
        return 0

    # Save FFuf findings
    for finding in ffuf_findings:
        Finding.objects.create(
            scan=scan,
            title=finding["title"],
            severity=finding["severity"],
            description=finding["description"],
            tool="ffuf",
            affected_url=finding["url"],
        )

    log_tool_success(logger, "ffuf", len(ffuf_findings))
    console.print(
        f"[bold]Phase 8 Results:[/bold] {len(ffuf_findings)} hidden paths discovered"
    )

    log_phase_complete(logger, 8)
    return len(ffuf_findings)


def execute_phase_9_wpscan(scan, httpx_results, all_technologies, profile, yes):
    """
    Phase 9: WordPress Scanning (conditional).
    """
    from cli.utils.scanners.wpscan_scanner import WPScanScanner
    from findings.models import Finding

    log_phase_start(logger, 9, "WordPress Scanning")

    if not httpx_results:
        logger.info("No HTTP endpoints to scan - skipping WPScan")
        console.print("[dim]No HTTP endpoints found - skipping WPScan[/dim]")
        log_phase_complete(logger, 9)
        return 0

    # Check if WordPress was detected
    wordpress_urls = []
    for url, technologies in all_technologies.items():
        for tech in technologies:
            if "wordpress" in tech.lower():
                wordpress_urls.append(url)
                break

    if not wordpress_urls:
        logger.info("No WordPress sites detected - skipping WPScan")
        console.print("[dim]No WordPress detected - skipping WPScan[/dim]")
        log_phase_complete(logger, 9)
        return 0

    console.print(f"[cyan]WordPress detected on {len(wordpress_urls)} site(s)[/cyan]")

    # Ask user confirmation (unless --yes flag)
    if not yes:
        console.print(
            f"\n[yellow]WPScan can take 5-20 minutes per WordPress site ({len(wordpress_urls)} found)[/yellow]"
        )
        response = input("Run WPScan WordPress security scan? [y/N]: ").strip().lower()
        if response not in ["y", "yes"]:
            logger.info("User skipped WPScan")
            console.print("[dim]Skipping WPScan[/dim]")
            log_phase_complete(logger, 9)
            return 0

    # Initialize scanner
    scanner = WPScanScanner()

    # Execute WPScan with error handling
    def run_wpscan():
        log_tool_execution(
            logger, "wpscan", f"wpscan {len(wordpress_urls)} WordPress sites"
        )
        return scanner.scan_wordpress_sites(wordpress_urls, profile=profile)

    success, wpscan_findings = safe_tool_execution(
        func=run_wpscan,
        tool_name="wpscan",
        logger=logger,
        max_retries=1,  # WPScan takes long, only 1 retry
        continue_on_error=True,
    )

    if not success:
        logger.warning("WPScan failed - returning empty results")
        log_phase_complete(logger, 9)
        return 0

    # Save WPScan findings
    for finding in wpscan_findings:
        Finding.objects.create(
            scan=scan,
            title=finding["title"],
            severity=finding["severity"],
            description=finding["description"],
            tool="wpscan",
            affected_url=finding["url"],
        )

    log_tool_success(logger, "wpscan", len(wpscan_findings))
    console.print(
        f"[bold]Phase 9 Results:[/bold] {len(wpscan_findings)} WordPress vulnerabilities"
    )

    log_phase_complete(logger, 9)
    return len(wpscan_findings)
