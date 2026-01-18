"""
Configuration utilities for BountyBot.
"""

import os
from pathlib import Path


def get_output_dir() -> Path:
    """
    Get the base output directory for scan results.

    Returns from environment variable BOUNTYBOT_OUTPUT_DIR if set,
    otherwise defaults to ~/bountybot_scans
    """
    output_dir = os.getenv("BOUNTYBOT_OUTPUT_DIR")

    if output_dir:
        return Path(output_dir)
    else:
        return Path.home() / "bountybot_scans"
