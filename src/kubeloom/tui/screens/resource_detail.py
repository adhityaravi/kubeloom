"""Resource detail screen for viewing resource policy impacts."""

from typing import List, Optional
from textual import work
from textual.app import ComposeResult
from textual.containers import Container, VerticalScroll
from textual.widgets import Header, Footer, Static, LoadingIndicator
from textual.screen import Screen
from textual.binding import Binding
from rich.console import RenderableType
from rich.panel import Panel

from ...core.models import Policy
from ...core.services import PolicyAnalyzer, ResourceInfo, ResourcePolicyAnalysis
from ...core.interfaces import ClusterClient


class ResourceDetailScreen(Screen):
    """Screen for viewing detailed information about a resource and its policy impacts."""

    BINDINGS = [
        Binding("escape", "app.pop_screen", "Back"),
    ]

    def __init__(self, resource: ResourceInfo, policies: List[Policy], policy_analyzer: PolicyAnalyzer, k8s_client: ClusterClient):
        super().__init__()
        self.resource = resource
        self.policies = policies
        self.policy_analyzer = policy_analyzer
        self.k8s_client = k8s_client
        self.analysis: Optional[ResourcePolicyAnalysis] = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        with VerticalScroll(id="detail-container"):
            yield LoadingIndicator(id="loading")
            yield Static("", id="resource-detail")
        yield Footer()

    def on_mount(self) -> None:
        """Initialize the resource detail view."""
        # Hide content initially, show only loading indicator
        self.query_one("#resource-detail", Static).display = False
        # Use call_after_refresh to ensure screen renders before loading
        self.call_after_refresh(self.load_resource_data)

    @work(exclusive=True)
    async def load_resource_data(self) -> None:
        """Load resource analysis in the background using worker."""
        try:
            self.analysis = await self.policy_analyzer.analyze_resource_policies(self.resource, self.policies)
            content = self._format_resource_detail()

            # Update UI from worker
            self.query_one("#loading", LoadingIndicator).display = False
            detail_widget = self.query_one("#resource-detail", Static)
            detail_widget.update(content)
            detail_widget.display = True
        except Exception as e:
            # Show error and hide loading indicator
            self.query_one("#loading", LoadingIndicator).display = False
            detail_widget = self.query_one("#resource-detail", Static)
            detail_widget.update(f"Error loading resource analysis: {str(e)}")
            detail_widget.display = True

    def _format_resource_detail(self) -> RenderableType:
        """Format the complete resource detail."""
        if not self.analysis:
            return "No analysis available"

        content_sections = []

        # Resource overview
        content_sections.append(self._format_resource_overview())

        # Inbound access (what can reach this resource)
        content_sections.append(self._format_inbound_access())

        # Outbound access (what this resource can reach)
        content_sections.append(self._format_outbound_access())

        return Panel(
            "\n\n".join(content_sections),
            title=f"[bold]{self.resource.type.title()}: {self.resource.name}[/bold]",
            border_style="blue"
        )

    def _format_resource_overview(self) -> str:
        """Format the resource overview section."""
        lines = ["[bold]Resource Overview[/bold]"]
        lines.append(f"Name: {self.resource.name}")
        lines.append(f"Namespace: {self.resource.namespace}")
        lines.append(f"Type: {self.resource.type}")

        if self.resource.service_account:
            lines.append(f"Service Account: {self.resource.service_account}")

        if self.resource.labels:
            lines.append("[bold]Labels:[/bold]")
            for key, value in self.resource.labels.items():
                lines.append(f"  {key}: {value}")

        return "\n".join(lines)


    def _format_inbound_access(self) -> str:
        """Format inbound access (what can reach this resource)."""
        lines = ["[bold green]Inbound Access[/bold green]"]

        if not self.analysis.inbound_access:
            lines.append("[dim]No explicit inbound access defined[/dim]")
            return "\n".join(lines)

        # Group by resource type for better organization
        grouped = {}
        for source_resource, routes in self.analysis.inbound_access:
            if source_resource.type not in grouped:
                grouped[source_resource.type] = []
            grouped[source_resource.type].append((source_resource, routes))

        # Sort types
        for resource_type in sorted(grouped.keys()):
            lines.append(f"\n[cyan]{resource_type.title()}s:[/cyan]")
            for source_resource, routes in sorted(grouped[resource_type], key=lambda x: x[0].name):
                # Show fully qualified name (namespace/name)
                qualified_name = f"{source_resource.namespace}/{source_resource.name}"
                lines.append(f"  • [yellow]{qualified_name}[/yellow]")
                lines.append(self._format_routes_inline(routes, indent="    "))

        return "\n".join(lines)

    def _format_outbound_access(self) -> str:
        """Format outbound access (what this resource can reach)."""
        lines = ["[bold blue]Outbound Access[/bold blue]"]

        if not self.analysis.outbound_access:
            lines.append("[dim]No explicit outbound access defined[/dim]")
            return "\n".join(lines)

        # Group by resource type for better organization
        grouped = {}
        for target_resource, routes in self.analysis.outbound_access:
            if target_resource.type not in grouped:
                grouped[target_resource.type] = []
            grouped[target_resource.type].append((target_resource, routes))

        # Sort types
        for resource_type in sorted(grouped.keys()):
            lines.append(f"\n[cyan]{resource_type.title()}s:[/cyan]")
            for target_resource, routes in sorted(grouped[resource_type], key=lambda x: x[0].name):
                # Show fully qualified name (namespace/name)
                qualified_name = f"{target_resource.namespace}/{target_resource.name}"
                lines.append(f"  • [green]{qualified_name}[/green]")
                lines.append(self._format_routes_inline(routes, indent="    "))

        return "\n".join(lines)

    def _format_routes_inline(self, routes: List, indent: str = "  ") -> str:
        """Format routes with each property on its own line."""
        if not routes:
            return f"{indent}Routes: All routes allowed"

        lines = [f"{indent}Routes:"]

        for route in routes:
            if hasattr(route, 'allow_all') and route.allow_all:
                return f"{indent}Routes: All routes allowed"
            elif hasattr(route, 'deny_all') and route.deny_all:
                return f"{indent}Routes: [red]No routes allowed[/red]"

            # Put each property on its own line
            if hasattr(route, 'methods') and route.methods:
                methods = [m.value for m in route.methods]
                lines.append(f"{indent}  Methods: {', '.join(methods)}")

            if hasattr(route, 'paths') and route.paths:
                lines.append(f"{indent}  Paths: {', '.join(route.paths)}")

            if hasattr(route, 'ports') and route.ports:
                lines.append(f"{indent}  Ports: {', '.join(map(str, route.ports))}")

        # If we only added the header, no actual routes were found
        if len(lines) == 1:
            return f"{indent}Routes: All routes allowed"

        return "\n".join(lines)

