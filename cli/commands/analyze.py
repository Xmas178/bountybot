"""
AI-powered analysis commands for intelligent finding prioritization.

Uses Claude API to analyze scan results and suggest the most promising
targets for manual testing.
"""

import typer
from rich.console import Console
from rich.table import Table
from typing import Optional

app = typer.Typer(help="AI-powered finding analysis")
console = Console()


@app.command("prioritize")
def prioritize_findings(
    scan_id: int = typer.Option(..., "--scan", help="Scan ID to analyze"),
    top_n: int = typer.Option(10, "--top", "-n", help="Number of top findings (1-20)"),
    min_severity: Optional[str] = typer.Option(
        None, "--min-severity", help="Minimum severity (info/low/medium/high/critical)"
    ),
):
    """
    AI-powered prioritization of findings for manual testing.

    Analyzes scan results and suggests the most promising targets
    with actionable next steps.

    Example:
        bountybot analyze prioritize --scan 1
        bountybot analyze prioritize --scan 1 --top 5
        bountybot analyze prioritize --scan 1 --min-severity high
    """
    from scans.models import Scan
    from cli.utils.ai_analyzer import AIAnalyzer

    try:
        # Get scan
        scan = Scan.objects.get(id=scan_id)

        console.print(f"\n[cyan]🧠 Analyzing scan results with AI...[/cyan]")
        console.print(f"Target: {scan.target.name}")
        console.print(f"Findings: {scan.findings_count}\n")

        # Initialize AI analyzer
        analyzer = AIAnalyzer()

        # Get prioritized findings
        prioritized = analyzer.prioritize_findings(
            scan=scan, top_n=top_n, min_severity=min_severity
        )

        if not prioritized:
            console.print("[yellow]No findings to prioritize.[/yellow]")
            return

        # Display results
        _display_prioritized_findings(prioritized, scan)

    except Scan.DoesNotExist:
        console.print(f"[red]Error: Scan {scan_id} not found[/red]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Error during analysis: {e}[/red]")
        raise typer.Exit(1)


def _display_prioritized_findings(prioritized_list, scan):
    """Display prioritized findings in rich format."""

    console.print(
        f"[bold]🎯 TOP {len(prioritized_list)} MANUAL TESTING TARGETS[/bold]\n"
    )

    console.print(f"Scan: {scan.target.name} ({scan.findings_count} findings)")
    console.print(f"Profile: {scan.profile}")

    if scan.completed_at and scan.started_at:
        duration = scan.completed_at - scan.started_at
        minutes = int(duration.total_seconds() / 60)
        console.print(f"Duration: {minutes} minutes\n")

    console.print("━" * 80)

    # Severity colors
    severity_colors = {
        "critical": "red",
        "high": "yellow",
        "medium": "blue",
        "low": "green",
        "info": "white",
    }

    for item in prioritized_list:
        rank = item["rank"]
        finding = item["finding"]
        reasoning = item["reasoning"]
        action = item["action"]
        time_estimate = item["time_estimate"]
        bounty_range = item["bounty_range"]

        color = severity_colors.get(finding.severity, "white")

        console.print(
            f"\n[bold] #{rank}  [{color}][{finding.severity.upper()}] {finding.title}[/{color}][/bold]"
        )
        console.print(f"     [dim]Why:[/dim] {reasoning}")
        console.print(f"     [dim]Action:[/dim] {action}")
        console.print(
            f"     [dim]Time:[/dim] {time_estimate} | [dim]Bounty:[/dim] {bounty_range}"
        )

    console.print("\n" + "━" * 80)

    # Summary
    console.print(f"\n[bold]📊 SUMMARY[/bold]")
    console.print(f"   Recommended order: #1 → #2 → #3 (highest impact first)")

    console.print(f"\n[bold]💡 TIP[/bold]")
    if prioritized_list:
        console.print(
            f"   Start with #{prioritized_list[0]['rank']} - highest priority target"
        )

    console.print(f"\n[bold]📝 NEXT STEPS[/bold]")
    if prioritized_list:
        first_id = prioritized_list[0]["finding"].id
        console.print(f"   bountybot finding show {first_id}  # View full details")
        console.print(f"   bountybot poc generate {first_id}   # Generate PoC (future)")
