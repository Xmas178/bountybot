"""
Error handling utilities for BountyBot.

Provides retry logic, graceful error handling, and user-friendly error messages.
"""

import time
import subprocess
from typing import Callable, Any, Optional, Tuple
from rich.console import Console

console = Console()


class ScannerError(Exception):
    """Base exception for scanner errors."""

    pass


class ToolNotFoundError(ScannerError):
    """Raised when a security tool is not installed."""

    pass


class ToolExecutionError(ScannerError):
    """Raised when a tool execution fails."""

    pass


class ToolTimeoutError(ScannerError):
    """Raised when a tool execution times out."""

    pass


def retry_on_failure(
    func: Callable,
    max_retries: int = 3,
    delay: float = 2.0,
    logger=None,
    tool_name: str = "Tool",
) -> Any:
    """
    Retry a function if it fails.

    Args:
        func: Function to execute
        max_retries: Maximum number of retry attempts
        delay: Delay between retries in seconds
        logger: Logger instance for logging attempts
        tool_name: Name of the tool for error messages

    Returns:
        Function result if successful

    Raises:
        Exception: Original exception if all retries fail
    """
    last_exception: Optional[Exception] = None

    for attempt in range(1, max_retries + 1):
        try:
            if logger and attempt > 1:
                logger.info(f"Retry attempt {attempt}/{max_retries} for {tool_name}")

            result = func()

            if logger and attempt > 1:
                logger.info(f"{tool_name} succeeded on attempt {attempt}")
                console.print(
                    f"[green]✓[/green] {tool_name} succeeded on retry {attempt}"
                )

            return result

        except Exception as e:
            last_exception = e

            if logger:
                logger.warning(
                    f"{tool_name} failed on attempt {attempt}/{max_retries}: {str(e)}"
                )

            if attempt < max_retries:
                console.print(
                    f"[yellow]⚠[/yellow] {tool_name} failed, retrying in {delay}s... (attempt {attempt}/{max_retries})"
                )
                time.sleep(delay)
            else:
                if logger:
                    logger.error(f"{tool_name} failed after {max_retries} attempts")
                console.print(
                    f"[red]✗[/red] {tool_name} failed after {max_retries} attempts"
                )

    # All retries failed
    raise last_exception if last_exception else Exception(f"{tool_name} failed")


def handle_tool_error(
    error: Exception, tool_name: str, logger=None, continue_on_error: bool = True
) -> bool:
    """
    Handle tool execution error gracefully.

    Args:
        error: Exception that occurred
        tool_name: Name of the security tool
        logger: Logger instance
        continue_on_error: Whether to continue scan after error

    Returns:
        True if scan should continue, False if should abort
    """
    error_type = type(error).__name__
    error_message = str(error)

    # Log the error
    if logger:
        logger.error(f"{tool_name} error: {error_type} - {error_message}")

    # User-friendly console message
    console.print(f"\n[red]━━━ {tool_name} Error ━━━[/red]")
    console.print(f"[red]Type:[/red] {error_type}")
    console.print(f"[red]Message:[/red] {error_message}")

    # Specific error handling
    if isinstance(error, ToolNotFoundError):
        console.print(f"\n[yellow]💡 Solution:[/yellow]")
        console.print(f"   Install {tool_name} before running scans")
        console.print(f"   See README.md for installation instructions")

    elif isinstance(error, ToolTimeoutError):
        console.print(f"\n[yellow]💡 Tip:[/yellow]")
        console.print(f"   {tool_name} timed out - target may be slow or unresponsive")
        console.print(f"   Consider using a faster scan profile (--profile quick)")

    elif isinstance(error, subprocess.TimeoutExpired):
        console.print(f"\n[yellow]💡 Tip:[/yellow]")
        console.print(f"   {tool_name} exceeded timeout limit")
        console.print(f"   This is normal for large targets - continuing scan...")

    elif isinstance(error, FileNotFoundError):
        console.print(f"\n[yellow]💡 Solution:[/yellow]")
        console.print(f"   {tool_name} not found in PATH")
        console.print(f"   Make sure it's installed and accessible")

    # Decide whether to continue
    if continue_on_error:
        console.print(f"\n[cyan]→ Continuing scan with remaining tools...[/cyan]\n")
        return True
    else:
        console.print(f"\n[red]→ Aborting scan due to critical error[/red]\n")
        return False


def check_tool_installed(tool_name: str, command: Optional[str] = None) -> bool:
    """
    Check if a security tool is installed.

    Args:
        tool_name: Name of the tool (e.g., "nmap")
        command: Optional command to check (defaults to tool_name)

    Returns:
        True if tool is installed, False otherwise
    """
    if command is None:
        command = tool_name

    try:
        # Try running tool with --version or -h
        result = subprocess.run(
            [command, "--version"], capture_output=True, timeout=5, text=True
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        try:
            # Some tools use -h instead of --version
            result = subprocess.run(
                [command, "-h"], capture_output=True, timeout=5, text=True
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False


def validate_scan_requirements(logger=None) -> dict:
    """
    Validate that all required security tools are installed.

    Returns:
        Dict with tool names as keys and installation status as values

    Example:
        {
            'subfinder': True,
            'nmap': True,
            'nuclei': False  # Not installed
        }
    """
    required_tools = {
        "subfinder": "subfinder",
        "nmap": "nmap",
        "httpx": "httpx",
        "nuclei": "nuclei",
        "whatweb": "whatweb",
        "sqlmap": "sqlmap",
        "dalfox": "dalfox",
        "nikto": "nikto",
        "ffuf": "ffuf",
        "wpscan": "wpscan",
    }

    results = {}
    missing_tools = []

    for tool_name, command in required_tools.items():
        is_installed = check_tool_installed(tool_name, command)
        results[tool_name] = is_installed

        if not is_installed:
            missing_tools.append(tool_name)
            if logger:
                logger.warning(f"Tool not found: {tool_name}")

    # Display results
    if missing_tools:
        console.print(f"\n[yellow]⚠ Missing tools:[/yellow]")
        for tool in missing_tools:
            console.print(f"   - {tool}")
        console.print(f"\n[yellow]These tools will be skipped during scans.[/yellow]")
        console.print(
            f"[yellow]See README.md for installation instructions.[/yellow]\n"
        )

    return results


def safe_tool_execution(
    func: Callable,
    tool_name: str,
    logger=None,
    max_retries: int = 3,
    continue_on_error: bool = True,
) -> Tuple[bool, Any]:
    """
    Execute a tool function with error handling and retry logic.

    Args:
        func: Function to execute
        tool_name: Name of the security tool
        logger: Logger instance
        max_retries: Maximum retry attempts
        continue_on_error: Whether to continue on error

    Returns:
        Tuple of (success: bool, result: Any)
        - success: True if execution succeeded
        - result: Function result if successful, None if failed
    """
    try:
        # Try executing with retry logic
        result = retry_on_failure(
            func=func,
            max_retries=max_retries,
            delay=2.0,
            logger=logger,
            tool_name=tool_name,
        )
        return (True, result)

    except Exception as e:
        # Handle the error
        should_continue = handle_tool_error(
            error=e,
            tool_name=tool_name,
            logger=logger,
            continue_on_error=continue_on_error,
        )

        if should_continue:
            return (False, None)  # Failed but continue
        else:
            raise  # Re-raise to abort scan
