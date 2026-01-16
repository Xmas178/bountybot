"""
Scan Management Commands

CLI commands for managing security scans.
Integrates with Django Scan model for database operations.
"""

import typer
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from typing import Optional
from scans.models import Scan
from targets.models import Target
from datetime import datetime

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
):
    """
    Start a new security scan for a target.

    Example:
        bountybot scan start 1
        bountybot scan start 1 --profile deep
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
        console.print(
            f"\n[dim]Use 'bountybot scan status {scan.id}' to check progress[/dim]"
        )

    except Target.DoesNotExist:
        console.print(f"[bold red]✗[/bold red] Target with ID {target_id} not found.")
        console.print("[dim]Use 'bountybot target list' to see available targets[/dim]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[bold red]✗[/bold red] Error starting scan: {str(e)}")
        raise typer.Exit(code=1)


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
