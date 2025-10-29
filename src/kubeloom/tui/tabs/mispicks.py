"""Mispicks (error tracking) tab component."""

import asyncio
from collections import deque
from collections.abc import Callable
from typing import Any

from textual.widgets import DataTable, Static

from kubeloom.core.interfaces import MeshAdapter
from kubeloom.core.models.errors import AccessError
from kubeloom.tui.widgets import NamespaceSelector


class MispicksTab:
    """Mispicks tab logic for tracking access errors from mesh logs."""

    def __init__(self) -> None:
        self.is_tailing_logs = False
        self.access_errors: deque[AccessError] = deque(maxlen=1000)  # Max 1000 errors in memory
        self.access_error_hashes: set[int] = set()  # For deduplication
        self.log_tailer_task: asyncio.Task[None] | None = None

    def init_table(self, table: DataTable[Any]) -> None:
        """Initialize the mispicks table columns."""
        # No width specified - let Textual auto-size based on content
        table.add_column("Time")
        table.add_column("Type")
        table.add_column("Source")
        table.add_column("Target")
        table.add_column("Reason")

    def update_table(self, table: DataTable[Any]) -> None:
        """Update the mispicks table with current errors."""
        table.clear()

        # Errors are already in deque, most recent appended last
        # Reverse to show most recent first
        sorted_errors = list(reversed(self.access_errors))

        for error in sorted_errors:
            # Format timestamp (already in local timezone from K8s logs)
            timestamp_str = error.timestamp.strftime("%Y-%m-%d %H:%M:%S") if error.timestamp else "-"

            # Format source
            if error.source_workload and error.source_namespace:
                source = f"{error.source_namespace}/{error.source_workload}"
            elif error.source_ip:
                source = error.source_ip
            else:
                source = "-"

            # Format target
            if error.target_service:
                target = error.target_service
                if error.target_port:
                    target = f"{target}:{error.target_port}"
            elif error.target_workload and error.target_namespace:
                target = f"{error.target_namespace}/{error.target_workload}"
                if error.target_port:
                    target = f"{target}:{error.target_port}"
            elif error.target_ip:
                target = error.target_ip
                if error.target_port:
                    target = f"{target}:{error.target_port}"
            else:
                target = "-"

            # Format HTTP details if present
            if error.http_method or error.http_path:
                http_details = f"{error.http_method or ''} {error.http_path or ''}".strip()
                target = f"{target} ({http_details})"

            table.add_row(
                timestamp_str,
                error.error_type.value,
                source,
                target,
                error.reason[:100] if error.reason else "-",  # Truncate long reasons
            )

    def get_error_at_row(self, row: int) -> AccessError | None:
        """Get the error at the specified row index."""
        if len(self.access_errors) == 0:
            return None
        sorted_errors: list[AccessError] = list(reversed(self.access_errors))
        if row < len(sorted_errors):
            return sorted_errors[row]
        return None

    def start_tailing(
        self,
        status_widget: Static,
        mesh_adapter: MeshAdapter | None,
        namespace_selector: NamespaceSelector | None,
        update_callback: Callable[[], None],
    ) -> None:
        """Start tailing access logs from mesh."""
        if self.is_tailing_logs or not mesh_adapter:
            return

        self.is_tailing_logs = True
        status_widget.update("Status: Running")

        # Start background worker
        self.log_tailer_task = asyncio.create_task(
            self._tail_logs_worker(mesh_adapter, namespace_selector, status_widget, update_callback)
        )

    def stop_tailing(self, status_widget: Static) -> None:
        """Stop tailing access logs."""
        if not self.is_tailing_logs:
            return

        self.is_tailing_logs = False

        # Cancel the worker task
        if self.log_tailer_task:
            self.log_tailer_task.cancel()
            self.log_tailer_task = None

        status_widget.update("Status: Stopped")

    def clear_errors(self) -> None:
        """Clear all collected errors."""
        self.access_errors.clear()
        self.access_error_hashes.clear()

    async def _tail_logs_worker(
        self,
        mesh_adapter: MeshAdapter,
        namespace_selector: NamespaceSelector | None,
        status_widget: Static,
        update_callback: Callable[[], None],
    ) -> None:
        """Background worker that tails logs and updates the error table."""
        try:
            # Get current namespace filter
            current_namespace = None
            if namespace_selector:
                current_namespace = namespace_selector.get_current_namespace()

            # Tail logs from mesh
            async for error in mesh_adapter.tail_access_logs(namespace=current_namespace):
                if not self.is_tailing_logs:
                    break

                # Check for duplicates using hash
                error_hash = hash(error)
                if error_hash not in self.access_error_hashes:
                    # Add to deque (automatically evicts oldest if at maxlen)
                    self.access_errors.append(error)
                    self.access_error_hashes.add(error_hash)

                    # If deque evicted an error, clean up its hash
                    if len(self.access_error_hashes) > 1000:
                        # Rebuild hash set from current deque
                        self.access_error_hashes = {hash(e) for e in self.access_errors}

                    # Update table (use call_after_refresh to avoid blocking)
                    update_callback()

        except asyncio.CancelledError:
            # Task was cancelled, clean exit
            pass
        except Exception as e:
            # Log error and stop tailing
            status_widget.update(f"Status: Error - {e!s}")
            self.is_tailing_logs = False
