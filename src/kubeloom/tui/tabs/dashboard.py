"""Dashboard tab component."""

from typing import List, Optional
from rich.panel import Panel
from rich.text import Text
from rich.table import Table as RichTable

from ...core.models import Policy, ServiceMesh
from ..widgets import NamespaceSelector


class DashboardTab:
    """Dashboard tab logic."""

    @staticmethod
    def render(
        service_mesh: Optional[ServiceMesh],
        namespaces_with_policies: List[str],
        policies: List[Policy],
        namespace_selector: Optional[NamespaceSelector]
    ) -> Panel:
        """Render dashboard content."""
        if not service_mesh:
            return Panel(
                "[red]No mesh connection available[/red]",
                title="[bold red]Connection Error[/bold red]",
                border_style="red"
            )

        current_ns = namespace_selector.get_current_namespace() if namespace_selector else "unknown"
        total_namespaces = len(namespaces_with_policies)
        total_policies = len(policies)

        # Policy type breakdown
        policy_types = {}
        for policy in policies:
            policy_type = policy.type.value
            policy_types[policy_type] = policy_types.get(policy_type, 0) + 1

        content = f"""[bold]Service Mesh[/bold]
{service_mesh.type.value} v{service_mesh.version}

[bold]Cluster Overview[/bold]
{total_namespaces} namespaces with policies

[bold]Policies ({total_policies})[/bold]"""

        for policy_type, count in sorted(policy_types.items()):
            content += f"\n{policy_type}: {count}"

        if not policy_types:
            content += "\nNo policies found"

        return Panel(content, border_style="white")
