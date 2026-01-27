"""
Centralized logging utility for BountyBot.

Provides unified logging to both console and file.
Each scan gets its own log file for debugging.
"""

import logging
import os
from pathlib import Path
from datetime import datetime
from typing import Optional
from rich.console import Console

console = Console()


def setup_logger(
    scan_id: Optional[int] = None, log_level: str = "INFO"
) -> logging.Logger:
    """
    Setup logger for scan execution.

    Creates a logger that writes to both console and file.
    Each scan gets its own log file: logs/scan_{id}.log

    Args:
        scan_id: Scan ID for log file naming (optional)
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR)

    Returns:
        Configured logger instance
    """
    # Create logs directory if it doesn't exist
    logs_dir = Path.home() / "Työpöytä" / "projects" / "bountybot" / "logs"
    logs_dir.mkdir(exist_ok=True)

    # Create logger
    logger_name = f"bountybot.scan_{scan_id}" if scan_id else "bountybot"
    logger = logging.getLogger(logger_name)

    # Clear existing handlers (avoid duplicates)
    logger.handlers = []

    # Set log level
    level = getattr(logging, log_level.upper(), logging.INFO)
    logger.setLevel(level)

    # Create formatters
    file_formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    console_formatter = logging.Formatter("%(levelname)s - %(message)s")

    # File handler (always logs everything)
    if scan_id:
        log_file = logs_dir / f"scan_{scan_id}.log"
    else:
        # General log file with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = logs_dir / f"bountybot_{timestamp}.log"

    file_handler = logging.FileHandler(log_file, mode="a", encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)  # Always log everything to file
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)

    # Console handler (only INFO and above by default)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    # Initial log entry
    logger.info(f"Logger initialized - Log file: {log_file}")

    return logger


def log_tool_execution(logger, tool_name: str, command: str):
    """
    Log tool execution start.

    Args:
        logger: Logger instance
        tool_name: Name of the security tool (e.g., "nmap")
        command: Command being executed
    """
    logger.info(f"Executing {tool_name}")
    logger.debug(f"Command: {command}")
    console.print(f"[cyan]Running {tool_name}...[/cyan]")


def log_tool_success(logger, tool_name: str, findings_count: int = 0):
    """
    Log successful tool execution.

    Args:
        logger: Logger instance
        tool_name: Name of the security tool
        findings_count: Number of findings discovered
    """
    logger.info(f"{tool_name} completed successfully - {findings_count} findings")
    console.print(f"[green]✓[/green] {tool_name} complete - {findings_count} findings")


def log_tool_error(logger, tool_name: str, error: Exception):
    """
    Log tool execution error.

    Args:
        logger: Logger instance
        tool_name: Name of the security tool
        error: Exception that occurred
    """
    logger.error(f"{tool_name} failed: {str(error)}")
    console.print(f"[red]✗[/red] {tool_name} failed: {str(error)}")


def log_tool_warning(logger, tool_name: str, message: str):
    """
    Log tool execution warning.

    Args:
        logger: Logger instance
        tool_name: Name of the security tool
        message: Warning message
    """
    logger.warning(f"{tool_name}: {message}")
    console.print(f"[yellow]⚠[/yellow] {tool_name}: {message}")


def log_phase_start(logger, phase_number: int, phase_name: str):
    """
    Log scan phase start.

    Args:
        logger: Logger instance
        phase_number: Phase number (0-9)
        phase_name: Human-readable phase name
    """
    logger.info(f"=== PHASE {phase_number}: {phase_name} ===")
    console.print(
        f"\n[bold cyan]=== PHASE {phase_number}: {phase_name} ===[/bold cyan]"
    )


def log_phase_complete(logger, phase_number: int, duration: Optional[float] = None):
    """
    Log scan phase completion.

    Args:
        logger: Logger instance
        phase_number: Phase number (0-9)
        duration: Optional phase duration in seconds
    """
    if duration:
        logger.info(f"Phase {phase_number} complete - Duration: {duration:.1f}s")
        console.print(f"[green]Phase {phase_number} complete[/green] ({duration:.1f}s)")
    else:
        logger.info(f"Phase {phase_number} complete")
        console.print(f"[green]Phase {phase_number} complete[/green]")
