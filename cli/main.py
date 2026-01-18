"""
BountyBot CLI - Main Entry Point

Command-line interface for BountyBot security testing platform.
Integrates with Django models for target and scan management.
"""

import os
import sys
import django
import typer
from rich.console import Console
from pathlib import Path

# Initialize Rich console for pretty output
console = Console()


# Setup Django environment
# This allows CLI to use Django models and database
def setup_django():
    """
    Configure Django settings for CLI usage.

    Sets DJANGO_SETTINGS_MODULE and calls django.setup() to initialize
    Django's ORM and make models available to CLI commands.
    """
    # Get project root directory
    project_root = Path(__file__).parent.parent
    sys.path.insert(0, str(project_root))

    # Set Django settings module
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "bountybot.settings")

    # Initialize Django
    django.setup()


# Setup Django before creating Typer app
setup_django()

# Import command modules
from cli.commands import target, scan, finding

# Create main Typer application
app = typer.Typer(
    name="bountybot",
    help="BountyBot - Automated Security Testing Platform",
    add_completion=False,  # Disable shell completion for now
)

app.add_typer(target.app, name="target")
app.add_typer(scan.app, name="scan")
app.add_typer(finding.app, name="finding")


@app.command()
def version():
    """Show BountyBot version information."""
    console.print("[bold cyan]BountyBot[/bold cyan] v0.1.0")
    app = typer.Typer(
        help="BountyBot - Comprehensive Bug Bounty Reconnaissance & Vulnerability Discovery Platform"
    )
    console.print("\nDeveloped by: Sami T")


@app.callback()
def callback():
    """
    BountyBot CLI - Automated Bug Bounty Toolkit

    Use 'bountybot COMMAND --help' for command-specific help.
    """
    pass


def main():
    """Main entry point for CLI."""
    try:
        app()
    except KeyboardInterrupt:
        console.print("\n[yellow]Operation cancelled by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
