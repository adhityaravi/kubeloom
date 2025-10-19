"""Mispicks (error tracking) tab component."""

import asyncio
from collections import deque
from typing import Optional, Set
from textual.widgets import DataTable, Static

from ...core.models.errors import AccessError
from ...core.interfaces import MeshAdapter
from ..widgets import NamespaceSelector


class MispicksTab:
    """Mispicks tab logic for tracking access errors from mesh logs."""

    def __init__(self):
        self.is_tailing_logs = False
        self.access_errors: deque = deque(maxlen=1000)  # Max 1000 errors in memory
        self.access_error_hashes: Set[int] = set()  # For deduplication
        self.log_tailer_task: Optional[asyncio.Task] = None

    def init_table(self, table: DataTable) -> None:
        """Initialize the mispicks table columns."""
        table.add_column("Time", width=20)
        table.add_column("Type", width=20)
        table.add_column("Source", width=30)
        table.add_column("Target", width=30)
        table.add_column("Reason", width=50)

    def update_table(self, table: DataTable) -> None:
        """Update the mispicks table with current errors."""
        table.clear()

        # Errors are already in deque, most recent appended last
        # Reverse to show most recent first
        sorted_errors = list(reversed(self.access_errors))

        for error in sorted_errors:
            # Format timestamp
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
                error.reason[:100] if error.reason else "-"  # Truncate long reasons
            )

    def get_error_at_row(self, row: int) -> Optional[AccessError]:
        """Get the error at the specified row index."""
        if len(self.access_errors) == 0:
            return None
        sorted_errors = list(reversed(self.access_errors))
        if row < len(sorted_errors):
            return sorted_errors[row]
        return None

    def start_tailing(
        self,
        status_widget: Static,
        mesh_adapter: Optional[MeshAdapter],
        namespace_selector: Optional[NamespaceSelector],
        update_callback
    ) -> None:
        """Start tailing access logs from mesh."""
        if self.is_tailing_logs or not mesh_adapter:
            return

        self.is_tailing_logs = True
        status_widget.update("Status: Running | s: Start | x: Stop | c: Clear")

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

        status_widget.update("Status: Stopped | s: Start | x: Stop | c: Clear")

    def clear_errors(self) -> None:
        """Clear all collected errors."""
        self.access_errors.clear()
        self.access_error_hashes.clear()

    async def _tail_logs_worker(
        self,
        mesh_adapter: MeshAdapter,
        namespace_selector: Optional[NamespaceSelector],
        status_widget: Static,
        update_callback
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
            status_widget.update(f"Status: Error - {str(e)} | s: Start | x: Stop | c: Clear")
            self.is_tailing_logs = False
