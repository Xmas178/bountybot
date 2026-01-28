"""
Parsers for security tool outputs.

This package contains parsers that extract structured data
from various security tool outputs (JSON, XML, text).
"""

from .sqlmap_parser import SQLMapParser

__all__ = ["SQLMapParser"]
