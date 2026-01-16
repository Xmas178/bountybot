"""
Finding Management Commands

CLI commands for managing security findings and vulnerabilities.
Integrates with Django Finding model for database operations.
"""

import typer
from rich.console import Console
from rich.table import Table
from typing import Optional
from findings.models import Finding
from scans.models import Scan

# Initialize Typer app for finding commands
app = typer.Typer(help="Manage security findings")
console = Console()


@app.command("add")
def add_finding(
    scan_id: int = typer.Argument(..., help="Scan ID this finding belongs to"),
    title: str = typer.Option(..., "--title", "-t", help="Finding title"),
    severity: str = typer.Option(
        ..., "--severity", "-s", help="Severity: critical, high, medium, low, info"
    ),
    description: str = typer.Option(
        "", "--description", "-d", help="Detailed description"
    ),
):
    """
    Add a new finding to a scan.

    Example:
        bountybot finding add 1 --title "XSS Vulnerability" --severity high --description "Found in login form"
    """
    try:
        # Get scan from database
        scan = Scan.objects.get(id=scan_id)

        # Create new finding
        finding = Finding.objects.create(
            scan=scan,
            title=title,
            severity=severity,
            description=description,
            status="new",
        )

        console.print(f"[bold green]✓[/bold green] Finding added successfully!")
        console.print(f"  ID: [cyan]{finding.id}[/cyan]")
        console.print(f"  Title: {finding.title}")
        console.print(
            f"  Severity: [{get_severity_color(severity)}]{severity.upper()}[/{get_severity_color(severity)}]"
        )
        console.print(f"  Scan: #{scan.id}")

    except Scan.DoesNotExist:
        console.print(f"[bold red]✗[/bold red] Scan with ID {scan_id} not found.")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[bold red]✗[/bold red] Error adding finding: {str(e)}")
        raise typer.Exit(code=1)


@app.command("list")
def list_findings(
    scan_id: Optional[int] = typer.Option(
        None, "--scan", "-s", help="Filter by scan ID"
    ),
    severity: Optional[str] = typer.Option(
        None, "--severity", help="Filter by severity"
    ),
    status: Optional[str] = typer.Option(None, "--status", help="Filter by status"),
):
    """
    List all findings.

    Example:
        bountybot finding list
        bountybot finding list --scan 1
        bountybot finding list --severity critical
        bountybot finding list --status new
    """
    # Query findings from database
    findings = Finding.objects.select_related("scan", "scan__target").all()

    if scan_id:
        findings = findings.filter(scan_id=scan_id)

    if severity:
        findings = findings.filter(severity=severity)

    if status:
        findings = findings.filter(status=status)

    if not findings.exists():
        console.print("[yellow]No findings found.[/yellow]")
        console.print(
            'Add a finding with: [cyan]bountybot finding add <scan_id> --title "..." --severity <level>[/cyan]'
        )
        return

    # Create Rich table
    table = Table(title="Security Findings", show_header=True, header_style="bold cyan")
    table.add_column("ID", style="dim", width=6)
    table.add_column("Title", style="cyan")
    table.add_column("Severity", justify="center")
    table.add_column("Status", justify="center")
    table.add_column("Scan", style="dim")
    table.add_column("Target", style="green")
    table.add_column("Found", style="dim")

    # Add rows
    for finding in findings:
        # Color-code severity
        severity_color = get_severity_color(finding.severity)
        severity_display = (
            f"[{severity_color}]{finding.severity.upper()}[/{severity_color}]"
        )

        # Color-code status
        status_colors = {
            "new": "yellow",
            "confirmed": "red",
            "false_positive": "dim",
            "fixed": "green",
        }
        status_color = status_colors.get(finding.status, "white")
        status_display = f"[{status_color}]{finding.status}[/{status_color}]"

        table.add_row(
            str(finding.id),
            finding.title[:40] + "..." if len(finding.title) > 40 else finding.title,
            severity_display,
            status_display,
            f"#{finding.scan.id}",
            finding.scan.target.name,
            finding.discovered_at.strftime("%Y-%m-%d"),
        )

    console.print(table)
    console.print(f"\n[dim]Total findings: {findings.count()}[/dim]")

    # Show severity breakdown
    if findings.exists():
        console.print("\n[bold]Severity Breakdown:[/bold]")
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = findings.filter(severity=sev).count()
            if count > 0:
                color = get_severity_color(sev)
                console.print(f"  [{color}]{sev.upper()}:[/{color}] {count}")


@app.command("show")
def show_finding(
    finding_id: int = typer.Argument(..., help="Finding ID to display"),
):
    """
    Show detailed information about a specific finding.

    Example:
        bountybot finding show 1
    """
    try:
        finding = Finding.objects.select_related("scan", "scan__target").get(
            id=finding_id
        )

        console.print(f"\n[bold cyan]Finding #{finding.id}[/bold cyan]")
        console.print("─" * 60)

        # Severity with color
        severity_color = get_severity_color(finding.severity)
        console.print(f"Title: [bold]{finding.title}[/bold]")
        console.print(
            f"Severity: [{severity_color}]{finding.severity.upper()}[/{severity_color}]"
        )

        if finding.cvss_score:
            console.print(f"CVSS Score: {finding.cvss_score}")

        console.print(f"Status: {finding.status}")
        console.print(
            f"\nTarget: {finding.scan.target.name} ({finding.scan.target.value})"
        )
        console.print(f"Scan: #{finding.scan.id}")
        console.print(
            f"Discovered: {finding.discovered_at.strftime('%Y-%m-%d %H:%M:%S')}"
        )

        if finding.description:
            console.print(f"\n[bold]Description:[/bold]")
            console.print(finding.description)

        if finding.proof_of_concept:
            console.print(f"\n[bold]Proof of Concept:[/bold]")
            console.print(finding.proof_of_concept)

        console.print("─" * 60 + "\n")

    except Finding.DoesNotExist:
        console.print(f"[bold red]✗[/bold red] Finding with ID {finding_id} not found.")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[bold red]✗[/bold red] Error: {str(e)}")
        raise typer.Exit(code=1)


def get_severity_color(severity: str) -> str:
    """Get Rich color for severity level."""
    colors = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "info": "dim",
    }
    return colors.get(severity.lower(), "white")


if __name__ == "__main__":
    app()
