"""kubeloom - Service mesh policy discovery and management for Kubernetes."""

from kubeloom.cli import cli
from kubeloom.tui import run as run_tui

from kubeloom._version import __version__
__all__ = ["cli", "run_tui"]
