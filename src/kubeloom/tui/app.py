"""Main TUI application."""

from textual.app import App
from .screens import MainScreen


class KubeloomApp(App):
    """kubeloom TUI application."""

    CSS = """
    /* Hide scrollbars globally */
    * {
        scrollbar-size: 0 0;
    }

    /* Main container */
    #main-container {
        height: 100%;
        width: 100%;
    }

    /* App title */
    #app-title {
        height: 1;
        background: $primary;
        color: $text-primary;
        text-align: center;
        content-align: center middle;
        text-style: bold;
    }

    /* Dashboard content */
    #dashboard-content {
        padding: 1;
        background: $surface;
        color: $text;
        height: 1fr;
        width: 100%;
    }

    /* Namespace selector */
    #namespace-selector {
        height: 1;
        background: $surface;
        border-bottom: solid $primary;
    }

    .namespace-label {
        width: 12;
        text-style: bold;
        color: $text;
    }

    .namespace-value {
        color: $accent;
        text-style: bold;
        width: 20;
    }

    .namespace-counter {
        color: $text-muted;
        width: 10;
    }

    /* Tabs */
    #main-tabs {
        height: 1fr;
    }

    TabbedContent > TabPane {
        padding: 1;
    }

    #policies-table {
        height: 1fr;
        background: $surface;
        color: $text;
        border: solid $primary;
    }

    #policies-table > .datatable--header {
        background: $primary;
        color: $text-primary;
        text-style: bold;
    }

    #policies-table > .datatable--cursor {
        background: $accent;
        color: $text-accent;
    }

    #policies-table > .datatable--hover {
        background: $primary-lighten-2;
        color: $text;
    }

    #policies-table .datatable--even-row {
        background: $surface;
        color: $text;
    }

    #policies-table .datatable--odd-row {
        background: $panel;
        color: $text;
    }

    #resources-table {
        height: 1fr;
        background: $surface;
        color: $text;
        border: solid $primary;
    }

    #resources-table > .datatable--header {
        background: $primary;
        color: $text-primary;
        text-style: bold;
    }

    #resources-table > .datatable--cursor {
        background: $accent;
        color: $text-accent;
    }

    #resources-table > .datatable--hover {
        background: $primary-lighten-2;
        color: $text;
    }

    #resources-table .datatable--even-row {
        background: $surface;
        color: $text;
    }

    #resources-table .datatable--odd-row {
        background: $panel;
        color: $text;
    }

    #resources-footer {
        height: 1;
        background: $surface;
        color: $text-muted;
        padding: 0 1;
    }

    #mispicks-table {
        height: 1fr;
        background: $surface;
        color: $text;
        border: solid $primary;
    }

    #mispicks-table > .datatable--header {
        background: $primary;
        color: $text-primary;
        text-style: bold;
    }

    #mispicks-table > .datatable--cursor {
        background: $accent;
        color: $text-accent;
    }

    #mispicks-table > .datatable--hover {
        background: $primary-lighten-2;
        color: $text;
    }

    #mispicks-table .datatable--even-row {
        background: $surface;
        color: $text;
    }

    #mispicks-table .datatable--odd-row {
        background: $panel;
        color: $text;
    }

    #mispicks-footer-container {
        height: 1;
        background: $surface;
        width: 100%;
    }

    #mispicks-keybindings {
        width: 1fr;
        color: $text-muted;
        padding: 0 1;
    }

    #tailing-status {
        width: auto;
        color: $text;
        padding: 0 1;
        text-align: right;
    }

    /* Namespace panel */
    #namespace-panel {
        width: 25%;
        min-width: 20;
        max-width: 35;
        background: $panel;
        border-left: solid $primary;
    }

    #namespace-title {
        height: 1;
        background: $primary;
        color: $text-primary;
        text-align: center;
        text-style: bold;
        padding: 0 1;
    }

    #namespace-tree {
        height: 1fr;
        background: $panel;
        color: $text;
        padding: 1;
    }

    Tabs {
        background: $surface;
        color: $text;
    }

    Tab {
        background: $surface;
        color: $text-muted;
        border: none;
        margin: 0 1;
        padding: 0 2;
    }

    Tab:hover {
        background: $primary;
        color: $text;
    }

    Tab.-active {
        background: $accent;
        color: $background;
        text-style: bold;
    }


    /* Status bar */
    #status-bar {
        height: 1;
        background: $surface;
        border-top: solid $primary;
        dock: bottom;
    }

    .key-binding {
        margin: 0 1;
        color: $text-muted;
    }

    .key-binding:first-child {
        margin-left: 2;
    }

    /* Help content */
    #help-content {
        padding: 2;
        background: $surface;
        color: $text;
    }

    /* Conflicts content */
    #conflicts-content {
        padding: 2;
        background: $surface;
        color: $text-muted;
        text-align: center;
        content-align: center middle;
    }

    /* Policy detail screen */
    #detail-container {
        height: 100%;
        width: 100%;
        padding: 1;
    }

    #policy-detail {
        height: auto;
        width: 100%;
    }
    """

    def on_mount(self) -> None:
        """Set up the application."""
        self.title = "kubeloom"
        self.push_screen(MainScreen())


def run() -> None:
    """Run the TUI application."""
    app = KubeloomApp()
    # Disable mouse support to allow terminal text selection
    app.run(mouse=False)
