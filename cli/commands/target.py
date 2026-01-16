"""
Target Management Commands

CLI commands for managing bug bounty targets.
Integrates with Django Target model for database operations.
"""

import typer
from rich.console import Console
from rich.table import Table
from typing import Optional
from targets.models import Target

# Initialize Typer app for target commands
app = typer.Typer(help="Manage bug bounty targets")
console = Console()


@app.command("add")
def add_target(
    value: str = typer.Argument(..., help="Target value (domain, IP, or URL)"),
    name: Optional[str] = typer.Option(
        None, "--name", "-n", help="Target name/identifier"
    ),
    target_type: str = typer.Option(
        "domain", "--type", "-t", help="Type: domain, ip, url, subnet"
    ),
    description: Optional[str] = typer.Option(
        None, "--description", "-d", help="Optional description"
    ),
):
    """
    Add a new target to the database.

    Example:
        bountybot target add example.com --name "Example Inc" --type domain
        bountybot target add 192.168.1.1 --name "Internal Server" --type ip
    """
    try:
        # Use value as name if name not provided
        target_name = name or value

        # Create new target in database
        target = Target.objects.create(
            name=target_name,
            value=value,
            target_type=target_type,
            description=description or "",
            status="active",
        )

        console.print(f"[bold green]✓[/bold green] Target added successfully!")
        console.print(f"  Name: [cyan]{target.name}[/cyan]")
        console.print(f"  Value: {target.value}")
        console.print(f"  Type: {target.target_type}")
        console.print(f"  ID: {target.id}")

    except Exception as e:
        console.print(f"[bold red]✗[/bold red] Error adding target: {str(e)}")
        raise typer.Exit(code=1)


@app.command("list")
def list_targets(
    active_only: bool = typer.Option(
        False, "--active", "-a", help="Show only active targets"
    )
):
    """
    List all targets in the database.

    Example:
        bountybot target list
        bountybot target list --active
    """
    # Query targets from database
    targets = Target.objects.all()

    if active_only:
        targets = targets.filter(status="active")

    if not targets.exists():
        console.print("[yellow]No targets found.[/yellow]")
        console.print("Add a target with: [cyan]bountybot target add <value>[/cyan]")
        return

    # Create Rich table for pretty output
    table = Table(
        title="Bug Bounty Targets", show_header=True, header_style="bold cyan"
    )
    table.add_column("ID", style="dim", width=6)
    table.add_column("Name", style="cyan")
    table.add_column("Value", style="green")
    table.add_column("Type", style="yellow")
    table.add_column("Status", justify="center")
    table.add_column("Added", style="dim")

    # Add rows to table
    for target in targets:
        # Color-code status
        if target.status == "active":
            status_display = "[green]✓ Active[/green]"
        elif target.status == "inactive":
            status_display = "[red]✗ Inactive[/red]"
        else:
            status_display = "[dim]◆ Archived[/dim]"

        table.add_row(
            str(target.id),
            target.name,
            target.value,
            target.target_type,
            status_display,
            target.created_at.strftime("%Y-%m-%d"),
        )

    console.print(table)
    console.print(f"\n[dim]Total targets: {targets.count()}[/dim]")


@app.command("delete")
def delete_target(
    target_id: int = typer.Argument(..., help="Target ID to delete"),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation"),
):
    """
    Delete a target from the database.

    Example:
        bountybot target delete 1
        bountybot target delete 1 --force
    """
    try:
        # Get target from database
        target = Target.objects.get(id=target_id)

        # Confirm deletion unless --force flag is used
        if not force:
            confirm = typer.confirm(
                f"Delete target '{target.name}' ({target.value}) (ID: {target_id})?"
            )
            if not confirm:
                console.print("[yellow]Deletion cancelled.[/yellow]")
                raise typer.Exit(0)

        # Delete target
        name = target.name
        value = target.value
        target.delete()

        console.print(
            f"[bold green]✓[/bold green] Target '{name}' ({value}) deleted successfully!"
        )

    except Target.DoesNotExist:
        console.print(f"[bold red]✗[/bold red] Target with ID {target_id} not found.")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[bold red]✗[/bold red] Error deleting target: {str(e)}")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
