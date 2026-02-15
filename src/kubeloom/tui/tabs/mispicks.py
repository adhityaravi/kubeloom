"""Mispicks (error tracking) tab component."""

import asyncio
from collections import deque
from collections.abc import Callable
from typing import Any

from textual.widgets import DataTable

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
        self._status_callback: Callable[[bool, str], None] | None = None
        self._filtered_errors: list[AccessError] = []  # Current filtered view

    def init_table(self, table: DataTable[Any]) -> None:
        """Initialize the mispicks table columns."""
        table.add_column("Time")
        table.add_column("Component")
        table.add_column("Namespace")

    def update_table(self, table: DataTable[Any], filter_text: str = "") -> None:
        """Update the mispicks table with current errors."""
        table.clear()

        # Errors are already in deque, most recent appended last
        # Reverse to show most recent first
        sorted_errors = list(reversed(self.access_errors))

        # Apply filter
        if filter_text:
            filter_lower = filter_text.lower()
            self._filtered_errors = [
                e for e in sorted_errors
                if (filter_lower in (e.pod_name or "").lower()
                    or filter_lower in (e.pod_namespace or "").lower()
                    or filter_lower in (e.source_workload or "").lower()
                    or filter_lower in (e.target_service or "").lower())
            ]
        else:
            self._filtered_errors = sorted_errors

        for error in self._filtered_errors:
            # Format timestamp (already in local timezone from K8s logs)
            timestamp_str = error.timestamp.strftime("%H:%M:%S") if error.timestamp else "-"

            # Component (pod name where error was logged, e.g. ztunnel)
            component = error.pod_name or "-"

            # Namespace (pod namespace where error was logged)
            namespace = error.pod_namespace or "-"

            table.add_row(
                timestamp_str,
                component,
                namespace,
            )

    def get_error_at_row(self, row: int) -> AccessError | None:
        """Get the error at the specified row index (from filtered list)."""
        if not self._filtered_errors:
            return None
        if row < len(self._filtered_errors):
            return self._filtered_errors[row]
        return None

    def start_tailing(
        self,
        mesh_adapter: MeshAdapter | None,
        namespace_selector: NamespaceSelector | None,
        update_callback: Callable[[], None],
        status_callback: Callable[[bool, str], None],
    ) -> None:
        """Start tailing access logs from mesh."""
        if self.is_tailing_logs or not mesh_adapter:
            return

        self.is_tailing_logs = True
        self._status_callback = status_callback
        status_callback(True, "Tailing")

        # Start background worker
        self.log_tailer_task = asyncio.create_task(
            self._tail_logs_worker(mesh_adapter, namespace_selector, update_callback, status_callback)
        )

    def stop_tailing(self) -> None:
        """Stop tailing access logs."""
        if not self.is_tailing_logs:
            return

        self.is_tailing_logs = False

        # Cancel the worker task
        if self.log_tailer_task:
            self.log_tailer_task.cancel()
            self.log_tailer_task = None

        if self._status_callback:
            self._status_callback(False, "Stopped")

    def clear_errors(self) -> None:
        """Clear all collected errors."""
        self.access_errors.clear()
        self.access_error_hashes.clear()

    async def _tail_logs_worker(
        self,
        mesh_adapter: MeshAdapter,
        namespace_selector: NamespaceSelector | None,
        update_callback: Callable[[], None],
        status_callback: Callable[[bool, str], None],
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
            status_callback(False, f"Error: {e!s}")
            self.is_tailing_logs = False
