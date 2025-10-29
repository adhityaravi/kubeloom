"""Policies tab component."""

from typing import Any

from rich.text import Text
from textual.widgets import DataTable, Tree

from kubeloom.core.interfaces import MeshAdapter
from kubeloom.core.models import Policy


class PoliciesTab:
    """Policies tab logic."""

    @staticmethod
    def update_table(table: DataTable[Any], policies: list[Policy]) -> None:
        """Update the policies table."""
        table.clear(columns=True)

        table.add_column("Name")
        table.add_column("Type")
        table.add_column("Status")
        table.add_column("Targets")
        table.add_column("Routes")

        for policy in policies:
            # Check if this is a kubeloom-managed (woven) policy
            is_woven = policy.labels.get("kubeloom.io/managed") == "true"

            # Style woven policies in cyan
            if is_woven:
                table.add_row(
                    Text(policy.name, style="cyan"),
                    Text(str(policy.type.value), style="cyan"),
                    Text(str(policy.status.value), style="cyan"),
                    Text(str(len(policy.targets)), style="cyan"),
                    Text(str(len(policy.allowed_routes)), style="cyan"),
                )
            else:
                table.add_row(
                    policy.name,
                    str(policy.type.value),
                    str(policy.status.value),
                    str(len(policy.targets)),
                    str(len(policy.allowed_routes)),
                )

    @staticmethod
    async def update_namespace_tree(
        tree: Tree[Any],
        namespaces_with_policies: list[str],
        current_namespace: str | None,
        mesh_adapter: MeshAdapter | None,
    ) -> None:
        """Update the namespace tree with namespaces that have policies."""
        tree.clear()

        for namespace in namespaces_with_policies:
            # Get policy count for this namespace
            try:
                if mesh_adapter:
                    policies = await mesh_adapter.get_policies(namespace)
                    policy_count = len(policies)
                else:
                    policy_count = 0
            except Exception:
                policy_count = 0

            # Make each namespace a leaf node with policy count in the label
            if namespace == current_namespace:
                node_label = f"[bold]{namespace}[/bold] ({policy_count})"
            else:
                node_label = f"{namespace} ({policy_count})"

            leaf = tree.root.add_leaf(node_label)
            leaf.data = namespace
