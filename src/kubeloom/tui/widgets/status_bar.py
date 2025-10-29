"""Status bar widget."""

from collections.abc import Iterator

from textual.containers import Horizontal
from textual.widgets import Static


class StatusBar(Horizontal):
    """Bottom status bar with key bindings and info."""

    def __init__(self) -> None:
        super().__init__(id="status-bar")

    def compose(self) -> Iterator[Static]:
        yield Static("q:quit", classes="key-binding")
        yield Static("j/k:up/down", classes="key-binding")
        yield Static("n/p:next/prev ns", classes="key-binding")
        yield Static("enter:view", classes="key-binding")
        yield Static("r:refresh", classes="key-binding")
        yield Static("?:help", classes="key-binding")
