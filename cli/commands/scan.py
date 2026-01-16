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

                # Update scan summary counts
                total_findings = Finding.objects.filter(scan=scan).count()
                scan.findings_count = total_findings
                scan.info_count = total_findings

                # Update scan as completed
                scan.status = "completed"
                scan.completed_at = timezone.now()
                scan.notes = f"Found {len(nmap_result.open_ports)} open ports, {len(httpx_results) if http_ports else 0} HTTP endpoints"
                scan.save()

                console.print(f"\n[bold green]✓[/bold green] Scan completed!")
                console.print(
                    f"  Open Ports: [cyan]{len(nmap_result.open_ports)}[/cyan]"
                )
                console.print(
                    f"  HTTP Endpoints: [cyan]{len(httpx_results) if http_ports else 0}[/cyan]"
                )
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
    table.add_column("Started", style="dim")
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
