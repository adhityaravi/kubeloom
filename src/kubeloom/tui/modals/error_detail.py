"""Access error detail screen."""

from typing import ClassVar

from rich.panel import Panel
from rich.text import Text
from textual import work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import VerticalScroll
from textual.screen import Screen
from textual.widgets import Footer, Header, LoadingIndicator, Static

from kubeloom.core.models.errors import AccessError


class ErrorDetailScreen(Screen[None]):
    """Screen for showing access error details."""

    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("escape", "app.pop_screen", "Back"),
    ]

    def __init__(self, error: AccessError):
        super().__init__()
        self.error = error

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        with VerticalScroll(id="detail-container"):
            yield LoadingIndicator(id="loading")
            yield Static("", id="error-detail")
        yield Footer()

    def on_mount(self) -> None:
        """Load error details when screen is mounted."""
        # Hide content initially, show only loading indicator
        self.query_one("#error-detail", Static).display = False
        # Use call_after_refresh to ensure screen renders before loading
        self.call_after_refresh(self.load_error_data)

    @work(exclusive=True)
    async def load_error_data(self) -> None:
        """Load error data in the background using worker."""
        content = self._render_error_detail()

        # Update UI from worker
        self.query_one("#loading", LoadingIndicator).display = False
        error_widget = self.query_one("#error-detail", Static)
        error_widget.update(content)
        error_widget.display = True

    def _render_error_detail(self) -> Panel:
        """Render detailed error information."""
        error_type_display = self.error.error_type.value.replace("_", " ").title()

        # Determine error type color
        error_color = "red"
        if "policy" in self.error.error_type.value:
            error_color = "yellow"
        elif "mtls" in self.error.error_type.value:
            error_color = "orange1"
        elif "connection" in self.error.error_type.value:
            error_color = "red"

        # Build content sections
        content_parts = []

        # Error Type and Timestamp
        content_parts.append(f"[bold]Error Type:[/bold] [{error_color}]{error_type_display}[/{error_color}]")
        if self.error.timestamp:
            timestamp_str = self.error.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            content_parts.append(f"[bold]Timestamp:[/bold] {timestamp_str}")

        # Source Information
        content_parts.append("\n[bold cyan]Source Information:[/bold cyan]")
        if self.error.source_workload or self.error.source_namespace:
            source = (
                f"{self.error.source_namespace}/{self.error.source_workload}"
                if self.error.source_namespace and self.error.source_workload
                else (self.error.source_workload or self.error.source_namespace)
            )
            content_parts.append(f"  Workload: {source}")
        if self.error.source_service_account:
            content_parts.append(f"  Service Account: {self.error.source_service_account}")
        if self.error.source_ip:
            content_parts.append(f"  IP Address: {self.error.source_ip}")
        if not any(
            [
                self.error.source_workload,
                self.error.source_namespace,
                self.error.source_service_account,
                self.error.source_ip,
            ]
        ):
            content_parts.append("  [dim]No source information available[/dim]")

        # Target Information
        content_parts.append("\n[bold cyan]Target Information:[/bold cyan]")
        if self.error.target_service:
            target = self.error.target_service
            if self.error.target_port:
                target = f"{target}:{self.error.target_port}"
            content_parts.append(f"  Service: {target}")
        if self.error.target_workload or self.error.target_namespace:
            target_str = (
                f"{self.error.target_namespace}/{self.error.target_workload}"
                if self.error.target_namespace and self.error.target_workload
                else (self.error.target_workload or self.error.target_namespace or "")
            )
            if self.error.target_port and not self.error.target_service:
                target_str = f"{target_str}:{self.error.target_port}"
            content_parts.append(f"  Workload: {target_str}")
        if self.error.target_ip:
            target_ip = self.error.target_ip
            if self.error.target_port and not self.error.target_service and not self.error.target_workload:
                target_ip = f"{target_ip}:{self.error.target_port}"
            content_parts.append(f"  IP Address: {target_ip}")
        # Show port separately if not already included above
        if self.error.target_port and not any(
            [self.error.target_service, self.error.target_workload, self.error.target_ip]
        ):
            content_parts.append(f"  Port: {self.error.target_port}")
        if not any(
            [
                self.error.target_service,
                self.error.target_workload,
                self.error.target_namespace,
                self.error.target_ip,
                self.error.target_port,
            ]
        ):
            content_parts.append("  [dim]No target information available[/dim]")

        # Request Details (L7)
        if self.error.http_method or self.error.http_path or self.error.http_version or self.error.http_status_code:
            content_parts.append("\n[bold cyan]HTTP Request:[/bold cyan]")
            if self.error.http_method:
                content_parts.append(f"  Method: {self.error.http_method}")
            if self.error.http_path:
                content_parts.append(f"  Path: {self.error.http_path}")
            if self.error.http_version:
                content_parts.append(f"  Protocol: {self.error.http_version}")
            if self.error.http_status_code:
                content_parts.append(f"  Status Code: {self.error.http_status_code}")

        # Error Reason
        if self.error.reason:
            content_parts.append("\n[bold cyan]Error Reason:[/bold cyan]")
            # Wrap long reasons
            reason_lines = self._wrap_text(self.error.reason, width=100)
            for line in reason_lines:
                content_parts.append(f"  {line}")

        # Metadata
        if self.error.pod_name or self.error.pod_namespace:
            content_parts.append("\n[bold cyan]Log Source:[/bold cyan]")
            if self.error.pod_name:
                pod_display = (
                    f"{self.error.pod_namespace}/{self.error.pod_name}"
                    if self.error.pod_namespace
                    else self.error.pod_name
                )
                content_parts.append(f"  Pod: {pod_display}")

        # Raw Message (if available and different from reason)
        if self.error.raw_message and self.error.raw_message != self.error.reason:
            content_parts.append("\n[bold cyan]Raw Log Message:[/bold cyan]")
            raw_lines = self._wrap_text(self.error.raw_message, width=100)
            for line in raw_lines:
                content_parts.append(f"  [dim]{line}[/dim]")

        content = "\n".join(content_parts)

        title_text = Text()
        title_text.append("Access Error: ", style="bold")
        title_text.append(error_type_display, style=f"bold {error_color}")

        return Panel(content, title=title_text, border_style="cyan")

    def _wrap_text(self, text: str, width: int = 100) -> list[str]:
        """Wrap text to specified width, breaking at word boundaries."""
        if not text:
            return []

        words = text.split()
        lines = []
        current_line: list[str] = []
        current_length = 0

        for word in words:
            word_length = len(word)
            # +1 for space
            if current_length + word_length + (1 if current_line else 0) <= width:
                current_line.append(word)
                current_length += word_length + (1 if len(current_line) > 1 else 0)
            else:
                if current_line:
                    lines.append(" ".join(current_line))
                current_line = [word]
                current_length = word_length

        if current_line:
            lines.append(" ".join(current_line))

        return lines if lines else [text]
