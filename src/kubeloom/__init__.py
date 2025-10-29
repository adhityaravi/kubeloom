"""kubeloom - Service mesh policy discovery and management for Kubernetes."""

from kubeloom.cli import cli
from kubeloom.tui import run as run_tui

__version__ = "0.1.0"
__all__ = ["cli", "run_tui"]
