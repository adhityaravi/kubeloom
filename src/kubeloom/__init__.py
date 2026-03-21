"""kubeloom - Service mesh policy discovery and management for Kubernetes."""

from kubeloom._version import __version__
from kubeloom.cli import cli
from kubeloom.tui import run as run_tui

__all__ = ["cli", "run_tui"]
