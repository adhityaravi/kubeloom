#!/usr/bin/env python3
"""Test script to verify DataTable rendering works."""

from textual.app import App, ComposeResult
from textual.widgets import DataTable
from textual.containers import Container


class TestTableApp(App):
    """Simple test app for DataTable."""

    CSS = """
    DataTable {
        background: white;
        color: black;
        height: 100%;
    }

    DataTable > .datatable--header {
        background: blue;
        color: white;
        text-style: bold;
    }

    DataTable > .datatable--cursor {
        background: yellow;
        color: black;
    }

    DataTable > .datatable--row {
        background: white;
        color: black;
    }

    DataTable .datatable--row {
        background: white;
        color: black;
    }
    """

    def compose(self) -> ComposeResult:
        with Container():
            yield DataTable(id="test-table")

    def on_mount(self) -> None:
        table = self.query_one("#test-table", DataTable)

        # Add columns
        table.add_column("Name")
        table.add_column("Type")
        table.add_column("Status")

        # Add test rows
        table.add_row("Policy-1", "AUTH", "ACTIVE")
        table.add_row("Policy-2", "PEER", "PENDING")
        table.add_row("Policy-3", "VIRTUAL", "ERROR")

        print(f"✓ Added {table.row_count} rows to table")
        print(f"✓ Table has {len(table.columns)} columns")


if __name__ == "__main__":
    print("Testing DataTable rendering...")
    app = TestTableApp()
    app.run()