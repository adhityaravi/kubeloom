"""Dracula theme for the TUI.

Uses the Dracula color palette: https://draculatheme.com/
"""

from __future__ import annotations

from enum import Enum

from textual.theme import Theme


class Colors(str, Enum):
    """Kubeloom color palette for Dracula theme."""

    # Core colors
    BACKGROUND = "#000000"
    FOREGROUND = "#f8f8f2"
    SURFACE = "#44475a"  # Borders, elevated surfaces
    MUTED = "#6272a4"  # Dim text, hints, paths

    # Semantic accent colors
    PRIMARY = "#bd93f9"  # Main accent (Dracula purple)
    SECONDARY = "#ff79c6"  # Secondary accent (Dracula pink)
    ACCENT = "#8be9fd"  # Tertiary accent (Dracula cyan)

    # Status colors
    SUCCESS = "#50fa7b"  # Success, online (Dracula green)
    WARNING = "#ffb86c"  # Warning, caution (Dracula orange)
    ERROR = "#ff5555"  # Error, danger (Dracula red)
    INFO = "#f1fa8c"  # Info, neutral (Dracula yellow)

    # Named colors for convenience
    CYAN = "#8be9fd"
    GREEN = "#50fa7b"
    ORANGE = "#ffb86c"
    PINK = "#ff79c6"
    PURPLE = "#bd93f9"
    RED = "#ff5555"
    YELLOW = "#f1fa8c"

    # Detail pane
    LABEL = "#ffb86c"  # Orange for labels
    MANIFEST_BG = "#1a1a2e"  # Subtle background for manifests


class Labels:
    """Formatted labels for list items."""

    # Policy action labels
    ALLOW = f"[{Colors.GREEN.value}]ALLOW[/]"
    DENY = f"[{Colors.RED.value}]DENY[/]"
    CUSTOM = f"[{Colors.YELLOW.value}]CUSTOM[/]"

    # Resource type labels
    SVC = "[magenta]SVC[/]"
    POD = "[cyan]POD[/]"

    @staticmethod
    def resource_type(rtype: str) -> str:
        """Get label for resource type."""
        if rtype == "service":
            return Labels.SVC
        if rtype == "pod":
            return Labels.POD
        return f"[dim]{rtype.upper()[:3]}[/]"

    @staticmethod
    def policy_action(action_type: str | None) -> str:
        """Get label for policy action type."""
        if action_type == "ALLOW":
            return Labels.ALLOW
        if action_type == "DENY":
            return Labels.DENY
        return Labels.CUSTOM


# Textual Theme
THEME = Theme(
    name="dracula",
    dark=True,
    primary=Colors.PRIMARY.value,
    secondary=Colors.SECONDARY.value,
    accent=Colors.ACCENT.value,
    foreground=Colors.FOREGROUND.value,
    background=Colors.BACKGROUND.value,
    surface=Colors.SURFACE.value,
    panel=Colors.SURFACE.value,
    success=Colors.SUCCESS.value,
    warning=Colors.WARNING.value,
    error=Colors.ERROR.value,
    variables={
        "muted": Colors.MUTED.value,
        "info": Colors.INFO.value,
    },
)
