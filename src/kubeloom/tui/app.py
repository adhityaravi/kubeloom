"""Main TUI application."""

from textual.app import App

from kubeloom.tui.screens import MainScreen
from kubeloom.tui.theme import THEME


class KubeloomApp(App[None]):
    """kubeloom TUI application."""

    CSS_PATH = "app.tcss"

    def on_mount(self) -> None:
        """Set up the application."""
        self.register_theme(THEME)
        self.theme = THEME.name
        self.title = "kubeloom"
        self.push_screen(MainScreen())


def run() -> None:
    """Run the TUI application."""
    app = KubeloomApp()
    # Disable mouse support to allow terminal text selection
    app.run(mouse=False)
