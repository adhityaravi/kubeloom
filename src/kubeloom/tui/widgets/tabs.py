"""Tab widgets for TUI."""

from textual.widgets import Tabs as TextualTabs


class MainTabs(TextualTabs):
    """Main application tabs."""

    def __init__(self) -> None:
        super().__init__("policies", "namespaces", "conflicts", "help", id="main-tabs")

    def on_mount(self) -> None:
        """Set initial active tab."""
        self.active = "policies"
