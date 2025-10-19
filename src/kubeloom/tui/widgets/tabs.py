"""Tab widgets for TUI."""

from textual.widgets import Tabs as TextualTabs
from textual.reactive import reactive


class MainTabs(TextualTabs):
    """Main application tabs."""

    active_tab = reactive("policies")

    def __init__(self):
        super().__init__(
            "policies",
            "namespaces",
            "conflicts",
            "help",
            id="main-tabs"
        )

    def on_mount(self) -> None:
        """Set initial active tab."""
        self.active = "policies"