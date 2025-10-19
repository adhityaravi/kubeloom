"""Policies tab component."""

from typing import List, Optional
from textual.widgets import DataTable, Tree

from ...core.models import Policy
from ...core.interfaces import MeshAdapter


class PoliciesTab:
    """Policies tab logic."""

    @staticmethod
    def update_table(table: DataTable, policies: List[Policy]) -> None:
        """Update the policies table."""
        table.clear(columns=True)

        table.add_column("Name")
        table.add_column("Type")
        table.add_column("Status")
        table.add_column("Targets")
        table.add_column("Routes")

        for policy in policies:
            table.add_row(
                policy.name,
                str(policy.type.value),
                str(policy.status.value),
                str(len(policy.targets)),
                str(len(policy.allowed_routes))
            )

    @staticmethod
    async def update_namespace_tree(
        tree: Tree,
        namespaces_with_policies: List[str],
        current_namespace: Optional[str],
        mesh_adapter: Optional[MeshAdapter]
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
