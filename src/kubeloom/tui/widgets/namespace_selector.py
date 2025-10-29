"""Namespace selector widget."""

from collections.abc import Iterator

from textual.containers import Horizontal
from textual.widgets import Static


class NamespaceSelector(Horizontal):
    """Namespace selector widget."""

    def __init__(self) -> None:
        super().__init__(id="namespace-selector")
        self.namespaces: list[str] = []
        self.current_index = 0

    def compose(self) -> Iterator[Static]:
        yield Static("Namespace:", classes="namespace-label")
        yield Static("", id="current-namespace", classes="namespace-value")
        yield Static("", id="namespace-counter", classes="namespace-counter")

    def set_namespaces(self, namespaces: list[str]) -> None:
        """Set available namespaces."""
        self.namespaces = namespaces
        self.current_index = 0
        self.update_display()

    def next_namespace(self) -> str:
        """Move to next namespace."""
        if len(self.namespaces) > 1:
            self.current_index = (self.current_index + 1) % len(self.namespaces)
            self.update_display()
        return self.get_current_namespace()

    def prev_namespace(self) -> str:
        """Move to previous namespace."""
        if len(self.namespaces) > 1:
            self.current_index = (self.current_index - 1) % len(self.namespaces)
            self.update_display()
        return self.get_current_namespace()

    def get_current_namespace(self) -> str:
        """Get current namespace."""
        return self.namespaces[self.current_index] if self.namespaces else ""

    def update_display(self) -> None:
        """Update the display."""
        if self.namespaces:
            current_ns = self.namespaces[self.current_index]
            counter = f"({self.current_index + 1}/{len(self.namespaces)})"

            self.query_one("#current-namespace", Static).update(current_ns)
            self.query_one("#namespace-counter", Static).update(counter)
        else:
            self.query_one("#current-namespace", Static).update("No namespaces")
            self.query_one("#namespace-counter", Static).update("")
