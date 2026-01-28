"""
Delete command - Remove targets, scans, or findings from database.

Provides safe deletion with confirmation prompts.
"""

import typer
from rich.console import Console
from rich.table import Table

console = Console()


def delete_target(target_id: int) -> None:
    """
    Delete a specific target and all associated scans/findings.

    Args:
        target_id: ID of the target to delete
    """
    # Import here to avoid Django setup issues
    from targets.models import Target
    from findings.models import Finding

    try:
        target = Target.objects.get(id=target_id)

        # Show what will be deleted
        scan_count = target.scans.count()
        finding_count = Finding.objects.filter(scan__target=target).count()

        console.print(f"\n[yellow]⚠️  About to delete:[/yellow]")
        console.print(f"  Target: {target.name} ({target.value})")
        console.print(f"  {scan_count} scans")
        console.print(f"  {finding_count} findings")

        # Confirm deletion
        confirm = typer.confirm("\nAre you sure you want to delete this target?")

        if confirm:
            target.delete()
            console.print(
                f"\n[green]✓[/green] Target #{target_id} deleted successfully"
            )
        else:
            console.print("\n[yellow]Deletion cancelled[/yellow]")

    except Target.DoesNotExist:
        console.print(f"[red]✗[/red] Target #{target_id} not found")


def delete_scan(scan_id: int) -> None:
    """
    Delete a specific scan and all associated findings.

    Args:
        scan_id: ID of the scan to delete
    """
    # Import here to avoid Django setup issues
    from scans.models import Scan

    try:
        scan = Scan.objects.get(id=scan_id)

        # Show what will be deleted
        finding_count = scan.findings.count()

        console.print(f"\n[yellow]⚠️  About to delete:[/yellow]")
        console.print(f"  Scan #{scan_id} on {scan.target.name}")
        console.print(f"  {finding_count} findings")

        # Confirm deletion
        confirm = typer.confirm("\nAre you sure you want to delete this scan?")

        if confirm:
            scan.delete()
            console.print(f"\n[green]✓[/green] Scan #{scan_id} deleted successfully")
        else:
            console.print("\n[yellow]Deletion cancelled[/yellow]")

    except Scan.DoesNotExist:
        console.print(f"[red]✗[/red] Scan #{scan_id} not found")


def delete_finding(finding_id: int) -> None:
    """
    Delete a specific finding.

    Args:
        finding_id: ID of the finding to delete
    """
    # Import here to avoid Django setup issues
    from findings.models import Finding

    try:
        finding = Finding.objects.get(id=finding_id)

        # Show what will be deleted
        console.print(f"\n[yellow]⚠️  About to delete:[/yellow]")
        console.print(f"  Finding #{finding_id}: {finding.title}")
        console.print(f"  Severity: {finding.severity.upper()}")

        # Confirm deletion
        confirm = typer.confirm("\nAre you sure you want to delete this finding?")

        if confirm:
            finding.delete()
            console.print(
                f"\n[green]✓[/green] Finding #{finding_id} deleted successfully"
            )
        else:
            console.print("\n[yellow]Deletion cancelled[/yellow]")

    except Finding.DoesNotExist:
        console.print(f"[red]✗[/red] Finding #{finding_id} not found")


def delete_all() -> None:
    """
    Delete ALL data from database (targets, scans, findings).

    This is a destructive operation with multiple confirmations.
    """
    # Import here to avoid Django setup issues
    from targets.models import Target
    from scans.models import Scan
    from findings.models import Finding

    # Count current data
    target_count = Target.objects.count()
    scan_count = Scan.objects.count()
    finding_count = Finding.objects.count()

    console.print("\n[red]⚠️  WARNING: This will delete EVERYTHING![/red]")
    console.print(f"\n  Targets: {target_count}")
    console.print(f"  Scans: {scan_count}")
    console.print(f"  Findings: {finding_count}")

    # First confirmation
    confirm1 = typer.confirm("\nAre you absolutely sure?", abort=False)
    if not confirm1:
        console.print("\n[yellow]Deletion cancelled[/yellow]")
        return

    # Second confirmation
    console.print("\n[red]This action CANNOT be undone![/red]")
    confirm2 = typer.confirm("Type 'yes' one more time to confirm", abort=False)

    if confirm2:
        # Delete in order: findings -> scans -> targets
        Target.objects.all().delete()
        Scan.objects.all().delete()
        Finding.objects.all().delete()

        console.print("\n[green]✓[/green] Database cleared successfully")
        console.print(f"  Deleted {target_count} targets")
        console.print(f"  Deleted {scan_count} scans")
        console.print(f"  Deleted {finding_count} findings")
    else:
        console.print("\n[yellow]Deletion cancelled[/yellow]")


def main(
    target: int = typer.Option(None, "--target", "-t", help="Delete target by ID"),
    scan: int = typer.Option(None, "--scan", "-s", help="Delete scan by ID"),
    finding: int = typer.Option(None, "--finding", "-f", help="Delete finding by ID"),
    all: bool = typer.Option(False, "--all", "-a", help="Delete ALL data (dangerous!)"),
):
    """
    Delete targets, scans, or findings from database.

    Examples:
        bountybot delete --target 5
        bountybot delete --scan 10
        bountybot delete --finding 123
        bountybot delete --all
    """

    if all:
        delete_all()
    elif target:
        delete_target(target)
    elif scan:
        delete_scan(scan)
    elif finding:
        delete_find(finding)
    else:
        console.print("[yellow]Please specify what to delete:[/yellow]")
        console.print("  bountybot delete --target ID")
        console.print("  bountybot delete --scan ID")
        console.print("  bountybot delete --finding ID")
        console.print("  bountybot delete --all")


if __name__ == "__main__":
    typer.run(main)
