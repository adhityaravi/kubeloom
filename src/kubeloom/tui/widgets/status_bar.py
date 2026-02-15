"""Status bar widget."""

from collections.abc import Iterator
from typing import ClassVar

from textual.containers import Horizontal
from textual.widgets import Static


class StatusBar(Horizontal):
    """Bottom status bar with key bindings and status info."""

    # Tab-specific hints
    TAB_HINTS: ClassVar[dict[str, str]] = {
        "policies": "r: Refresh . n/p: Namespace . y: Copy",
        "resources": "r: Refresh . n/p: Namespace . e: Enroll . u: Unenroll",
        "mispicks": "s: Start . x: Stop . c: Clear . w: Weave . W: Unweave",
    }

    def __init__(self) -> None:
        super().__init__(id="status-bar")
        self._mesh_info: str = ""
        self._namespace_count: int = 0
        self._tailing_status: str = ""
        self._is_tailing: bool = False
        self._current_tab: str = "policies"

    def compose(self) -> Iterator[Static]:
        # Left side: key hints with "." separator
        yield Static(self.TAB_HINTS["policies"], id="status-hints")

        # Right side: status info
        yield Static("", id="status-info")

    def set_active_tab(self, tab_id: str) -> None:
        """Update hints based on active tab."""
        self._current_tab = tab_id
        try:
            hints_widget = self.query_one("#status-hints", Static)
            hints = self.TAB_HINTS.get(tab_id, self.TAB_HINTS["policies"])
            hints_widget.update(hints)
        except Exception:
            pass
        self._refresh_info()

    def update_info(self, mesh_type: str = "", mesh_version: str = "", namespace_count: int = 0) -> None:
        """Update the mesh info on the right side."""
        self._mesh_info = f"{mesh_type} v{mesh_version}" if mesh_type and mesh_version else ""
        self._namespace_count = namespace_count
        self._refresh_info()

    def update_tailing_status(self, is_running: bool, message: str = "") -> None:
        """Update tailing status with color coding."""
        self._is_tailing = is_running
        if is_running:
            self._tailing_status = f"[#50fa7b]{message or 'Tailing'}[/]"
        else:
            self._tailing_status = f"[#6272a4]{message or 'Stopped'}[/]"
        self._refresh_info()

    def _refresh_info(self) -> None:
        """Refresh the status info display."""
        try:
            info_widget = self.query_one("#status-info", Static)
            parts = []

            # Show tailing status when in mispicks tab
            if self._current_tab == "mispicks" and self._tailing_status:
                parts.append(self._tailing_status)

            if self._mesh_info:
                parts.append(self._mesh_info)
            if self._namespace_count > 0:
                parts.append(f"{self._namespace_count} ns")

            info_widget.update(" . ".join(parts))
        except Exception:
            pass
