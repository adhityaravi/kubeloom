"""Main screen for kubeloom TUI."""

from typing import List, Optional, Set
import asyncio
from datetime import datetime
from collections import deque
from textual import work
from textual.app import ComposeResult
from textual.containers import Container, Vertical, Horizontal
from textual.widgets import Static, DataTable, TabbedContent, TabPane, Tree
from textual.screen import Screen
from textual.binding import Binding
from rich.console import RenderableType
from rich.panel import Panel
from rich.columns import Columns
from rich.text import Text
from rich.table import Table as RichTable

from ...core.models import Policy, ServiceMesh, AccessError
from ...core.interfaces import MeshAdapter
from ...core.services import PolicyAnalyzer, ResourceInfo
from ...k8s.client import K8sClient
from ...mesh.istio.adapter import IstioAdapter
from ..widgets import StatusBar, NamespaceSelector
from .policy_detail import PolicyDetailScreen
from .resource_detail import ResourceDetailScreen
from .error_detail import ErrorDetailScreen


class MainScreen(Screen):
    """Main screen for service mesh policy management."""

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("r", "refresh", "Refresh"),
        Binding("enter", "view_item", "View"),
        Binding("h", "focus_left", "Focus Left", show=False),
        Binding("l", "focus_right", "Focus Right", show=False),
        Binding("j", "cursor_down", "Down", show=False),
        Binding("k", "cursor_up", "Up", show=False),
        Binding("n", "next_namespace", "Next NS"),
        Binding("p", "prev_namespace", "Prev NS"),
        Binding("1", "tab_dashboard", "Dashboard", show=False),
        Binding("2", "tab_policies", "Policies", show=False),
        Binding("3", "tab_resources", "Resources", show=False),
        Binding("4", "tab_mispicks", "Mispicks", show=False),
        Binding("5", "tab_conflicts", "Conflicts", show=False),
        Binding("6", "tab_help", "Help", show=False),
        Binding("s", "start_tailing", "Start Tailing", show=False),
        Binding("x", "stop_tailing", "Stop Tailing", show=False),
        Binding("c", "clear_mispicks", "Clear Errors", show=False),
    ]

    def __init__(self):
        super().__init__()
        self.k8s_client: Optional[K8sClient] = None
        self.mesh_adapter: Optional[MeshAdapter] = None
        self.service_mesh: Optional[ServiceMesh] = None
        self.namespaces_with_policies: List[str] = []
        self.policies: List[Policy] = []
        self.resources: List[ResourceInfo] = []
        self.policy_analyzer: Optional[PolicyAnalyzer] = None
        self.namespace_selector: Optional[NamespaceSelector] = None
        self.focused_section = "table"  # "table" or "tree"

        # Mispicks (error tracking) state
        self.is_tailing_logs = False
        self.access_errors: deque = deque(maxlen=1000)  # Max 1000 errors in memory
        self.access_error_hashes: Set[int] = set()  # For deduplication
        self.log_tailer_task: Optional[asyncio.Task] = None

    def compose(self) -> ComposeResult:
        with Container(id="main-container"):
            yield Static("kubeloom", id="app-title")
            yield NamespaceSelector()

            with TabbedContent(initial="dashboard", id="main-tabs"):
                with TabPane("Dashboard", id="dashboard"):
                    yield Static("Loading dashboard...", id="dashboard-content")
                with TabPane("Policies", id="policies"):
                    with Horizontal():
                        yield DataTable(id="policies-table", zebra_stripes=True)
                        with Container(id="namespace-panel"):
                            yield Static("Namespaces", id="namespace-title")
                            yield Tree("Namespaces", id="namespace-tree")

                with TabPane("Resources", id="resources"):
                    with Horizontal():
                        yield DataTable(id="resources-table", zebra_stripes=True)
                        with Container(id="namespace-panel"):
                            yield Static("Namespaces", id="namespace-title")
                            yield Tree("Namespaces", id="namespace-tree-resources")

                with TabPane("Mispicks", id="mispicks"):
                    with Vertical():
                        yield Static("Status: Not running | s: Start | x: Stop | c: Clear", id="tailing-status")
                        yield DataTable(id="mispicks-table", zebra_stripes=True)

                with TabPane("Conflicts", id="conflicts"):
                    yield Static("Conflict detection not implemented", id="conflicts-content")

                with TabPane("Help", id="help"):
                    yield Static(self._get_help_content(), id="help-content")

            yield StatusBar()

    def _get_help_content(self) -> str:
        """Get help content."""
        return """kubeloom

NAVIGATION:
  h/j/k/l      Move cursor
  1/2/3/4      Switch tabs (Dashboard/Policies/Resources/Conflicts)

ACTIONS:
  r            Refresh data
  q            Quit
"""

    async def on_mount(self) -> None:
        """Initialize the application on mount."""
        self.namespace_selector = self.query_one(NamespaceSelector)

        # Initialize mispicks table
        self._init_mispicks_table()

        # Force show something in dashboard immediately
        dashboard = self.query_one("#dashboard-content", Static)
        dashboard.update("TEST - Dashboard content is working")

        await self._initialize()

    async def _initialize(self) -> None:
        """Initialize Kubernetes client and detect service mesh."""
        try:
            self.k8s_client = K8sClient()
            self.mesh_adapter = IstioAdapter(self.k8s_client)
            self.policy_analyzer = PolicyAnalyzer(self.k8s_client)
            self.service_mesh = await self.mesh_adapter.detect()

            if not self.service_mesh:
                return

            await self._load_namespaces_with_policies()
            await self._refresh_policies()
            self._update_dashboard()

        except Exception as e:
            dashboard = self.query_one("#dashboard-content", Static)
            dashboard.update(f"Error: {str(e)}")

    async def _load_namespaces_with_policies(self) -> None:
        """Load namespaces that contain policies."""
        if not self.mesh_adapter:
            return

        try:
            namespaces = await self.k8s_client.get_namespaces()
            self.namespaces_with_policies = []

            for namespace in namespaces:
                policies = await self.mesh_adapter.get_policies(namespace.name)
                if policies:
                    self.namespaces_with_policies.append(namespace.name)

            if self.namespace_selector:
                self.namespace_selector.set_namespaces(self.namespaces_with_policies)

        except Exception:
            pass

    async def _refresh_policies(self) -> None:
        """Refresh policies for current namespace."""
        if not self.mesh_adapter or not self.namespace_selector:
            return

        try:
            current_namespace = self.namespace_selector.get_current_namespace()
            if current_namespace:
                self.policies = await self.mesh_adapter.get_policies(current_namespace)
                self._update_policies_table()
                await self._refresh_resources()
                self._update_dashboard()
                await self._update_namespace_tree()

        except Exception as e:
            dashboard = self.query_one("#dashboard-content", Static)
            dashboard.update(f"Error loading policies: {str(e)}")

    def _update_policies_table(self) -> None:
        """Update the policies table."""
        table = self.query_one("#policies-table", DataTable)
        table.clear(columns=True)

        table.add_column("Name")
        table.add_column("Type")
        table.add_column("Status")
        table.add_column("Targets")
        table.add_column("Routes")
        for policy in self.policies:
            table.add_row(
                policy.name,
                str(policy.type.value),
                str(policy.status.value),
                str(len(policy.targets)),
                str(len(policy.allowed_routes))
            )

    async def _refresh_resources(self) -> None:
        """Refresh resources affected by policies in current namespace."""
        if not self.policy_analyzer or not self.policies:
            self.resources = []
            self._update_resources_table()
            return

        try:
            self.resources = await self.policy_analyzer.get_all_affected_resources(self.policies)
            self._update_resources_table()
        except Exception as e:
            self.resources = []
            self._update_resources_table()

    def _update_resources_table(self) -> None:
        """Update the resources table."""
        table = self.query_one("#resources-table", DataTable)
        table.clear(columns=True)

        table.add_column("Name")
        table.add_column("Type")
        table.add_column("Service Account")
        table.add_column("Policies")
        table.add_column("Labels")

        # Group resources by type
        grouped_resources = {}
        for resource in self.resources:
            if resource.type not in grouped_resources:
                grouped_resources[resource.type] = []
            grouped_resources[resource.type].append(resource)

        # Sort resource types for consistent display
        type_order = ["service", "pod", "statefulset", "deployment", "daemonset"]
        sorted_types = []

        # Add known types in order
        for resource_type in type_order:
            if resource_type in grouped_resources:
                sorted_types.append(resource_type)

        # Add any unknown types at the end
        for resource_type in sorted(grouped_resources.keys()):
            if resource_type not in sorted_types:
                sorted_types.append(resource_type)

        # Add resources to table grouped by type
        for resource_type in sorted_types:
            resources_of_type = grouped_resources[resource_type]

            # Sort resources within type by name
            resources_of_type.sort(key=lambda r: r.name)

            for resource in resources_of_type:
                # Count policies affecting this resource
                affecting_policies = sum(1 for policy in self.policies
                                       if self._resource_affected_by_policy(resource, policy))

                # Format labels (show first few key=value pairs)
                labels_str = ", ".join([f"{k}={v}" for k, v in list(resource.labels.items())[:2]])
                if len(resource.labels) > 2:
                    labels_str += f"... (+{len(resource.labels) - 2})"

                table.add_row(
                    resource.name,
                    resource.type,
                    resource.service_account or "-",
                    str(affecting_policies),
                    labels_str or "-"
                )

    def _resource_affected_by_policy(self, resource: ResourceInfo, policy: Policy) -> bool:
        """Check if a resource is affected by a policy (as source or target)."""
        # Check if resource is a target
        for target in policy.targets:
            if resource.type == "service" and resource.name in target.services:
                return True
            if resource.type == "pod" and resource.name in target.pods:
                return True
            if target.workload_labels:
                if all(resource.labels.get(k) == v for k, v in target.workload_labels.items()):
                    return True

        # Check if resource is a source
        if policy.source:
            if (resource.service_account and
                resource.service_account in policy.source.service_accounts):
                return True
            if policy.source.workload_labels:
                if all(resource.labels.get(k) == v for k, v in policy.source.workload_labels.items()):
                    return True

        return False

    async def _update_namespace_tree(self) -> None:
        """Update the namespace tree with namespaces that have policies."""
        # Update both namespace trees
        try:
            tree = self.query_one("#namespace-tree", Tree)
            await self._populate_namespace_tree(tree)
        except Exception:
            pass

        try:
            tree_resources = self.query_one("#namespace-tree-resources", Tree)
            await self._populate_namespace_tree(tree_resources)
        except Exception:
            pass

    async def _populate_namespace_tree(self, tree: Tree) -> None:
        """Populate a namespace tree with namespaces that have policies."""
        tree.clear()

        current_ns = self.namespace_selector.get_current_namespace() if self.namespace_selector else None

        for namespace in self.namespaces_with_policies:
            # Get policy count for this namespace
            try:
                if self.mesh_adapter:
                    policies = await self.mesh_adapter.get_policies(namespace)
                    policy_count = len(policies)
                else:
                    policy_count = 0
            except Exception:
                policy_count = 0

            # Make each namespace a leaf node with policy count in the label
            if namespace == current_ns:
                node_label = f"[bold]{namespace}[/bold] ({policy_count})"
            else:
                node_label = f"{namespace} ({policy_count})"

            leaf = tree.root.add_leaf(node_label)
            leaf.data = namespace

    def _update_dashboard(self) -> None:
        """Update dashboard with cluster and mesh statistics."""
        dashboard = self.query_one("#dashboard-content", Static)

        if not self.service_mesh or not self.k8s_client:
            error_panel = Panel(
                "[red]No mesh connection available[/red]",
                title="[bold red]Connection Error[/bold red]",
                border_style="red"
            )
            dashboard.update(error_panel)
            return

        current_ns = self.namespace_selector.get_current_namespace() if self.namespace_selector else "unknown"
        total_namespaces = len(self.namespaces_with_policies)
        total_policies = len(self.policies)

        # Policy type breakdown
        policy_types = {}
        for policy in self.policies:
            policy_type = policy.type.value
            policy_types[policy_type] = policy_types.get(policy_type, 0) + 1

        # Create mesh info
        mesh_info = Text()
        mesh_info.append(f"{self.service_mesh.type.value}", style="bold cyan")
        mesh_info.append(f" v{self.service_mesh.version}", style="dim cyan")

        # Create namespace info
        ns_info = Text()
        ns_info.append(f"{current_ns}", style="bold green")
        ns_info.append(f"\n{total_namespaces} namespaces with policies", style="dim")

        # Create policy stats table
        policy_table = RichTable(show_header=True, header_style="bold magenta")
        policy_table.add_column("Policy Type", style="cyan")
        policy_table.add_column("Count", justify="right", style="green")

        for policy_type, count in sorted(policy_types.items()):
            policy_table.add_row(policy_type, str(count))

        if not policy_types:
            policy_table.add_row("[dim]No policies found[/dim]", "[dim]-[/dim]")

        content = f"""[bold]Service Mesh[/bold]
{self.service_mesh.type.value} v{self.service_mesh.version}

[bold]Cluster Overview[/bold]
{total_namespaces} namespaces with policies

[bold]Policies ({total_policies})[/bold]"""

        for policy_type, count in sorted(policy_types.items()):
            content += f"\n{policy_type}: {count}"

        if not policy_types:
            content += "\nNo policies found"

        # Create simple panel without title
        main_panel = Panel(
            content,
            border_style="white"
        )

        dashboard.update(main_panel)

    # Mispicks (Error Tracking) Methods
    def _init_mispicks_table(self) -> None:
        """Initialize the mispicks table columns."""
        table = self.query_one("#mispicks-table", DataTable)
        table.add_column("Time", width=20)
        table.add_column("Type", width=20)
        table.add_column("Source", width=30)
        table.add_column("Target", width=30)
        table.add_column("Reason", width=50)

    def _update_mispicks_table(self) -> None:
        """Update the mispicks table with current errors."""
        table = self.query_one("#mispicks-table", DataTable)
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

    def _start_log_tailing(self) -> None:
        """Start tailing access logs from mesh."""
        if self.is_tailing_logs or not self.mesh_adapter:
            return

        self.is_tailing_logs = True

        # Update UI
        self.query_one("#tailing-status", Static).update("Status: Running | s: Start | x: Stop | c: Clear")

        # Start background worker
        self.log_tailer_task = asyncio.create_task(self._tail_logs_worker())

    def _stop_log_tailing(self) -> None:
        """Stop tailing access logs."""
        if not self.is_tailing_logs:
            return

        self.is_tailing_logs = False

        # Cancel the worker task
        if self.log_tailer_task:
            self.log_tailer_task.cancel()
            self.log_tailer_task = None

        # Update UI
        self.query_one("#tailing-status", Static).update("Status: Stopped | s: Start | x: Stop | c: Clear")

    def _clear_errors(self) -> None:
        """Clear all collected errors."""
        self.access_errors.clear()
        self.access_error_hashes.clear()
        self._update_mispicks_table()

    async def _tail_logs_worker(self) -> None:
        """Background worker that tails logs and updates the error table."""
        if not self.mesh_adapter:
            return

        try:
            # Get current namespace filter
            current_namespace = None
            if self.namespace_selector:
                current_namespace = self.namespace_selector.get_current_namespace()

            # Tail logs from mesh
            async for error in self.mesh_adapter.tail_access_logs(namespace=current_namespace):
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
                    self.call_after_refresh(self._update_mispicks_table)

        except asyncio.CancelledError:
            # Task was cancelled, clean exit
            pass
        except Exception as e:
            # Log error and stop tailing
            self.query_one("#tailing-status", Static).update(f"Status: Error - {str(e)} | s: Start | x: Stop | c: Clear")
            self.is_tailing_logs = False

    # Actions
    async def action_refresh(self) -> None:
        """Refresh action."""
        await self._load_namespaces_with_policies()
        await self._refresh_policies()

    async def action_next_namespace(self) -> None:
        """Switch to next namespace."""
        if self.namespace_selector:
            self.namespace_selector.next_namespace()
            await self._refresh_policies()

    async def action_prev_namespace(self) -> None:
        """Switch to previous namespace."""
        if self.namespace_selector:
            self.namespace_selector.prev_namespace()
            await self._refresh_policies()

    def action_tab_dashboard(self) -> None:
        """Switch to dashboard tab."""
        tabs = self.query_one("#main-tabs", TabbedContent)
        tabs.active = "dashboard"

    def action_view_item(self) -> None:
        """View selected item details (policy or resource)."""
        tabs = self.query_one("#main-tabs", TabbedContent)

        if tabs.active == "policies":
            table = self.query_one("#policies-table", DataTable)
            if table.cursor_row is not None:
                policy_name = table.get_row_at(table.cursor_row)[0]
                policy = next((p for p in self.policies if p.name == policy_name), None)
                if policy:
                    self.app.push_screen(PolicyDetailScreen(policy, self.k8s_client))

        elif tabs.active == "resources":
            table = self.query_one("#resources-table", DataTable)
            if table.cursor_row is not None:
                resource_name = table.get_row_at(table.cursor_row)[0]
                resource = next((r for r in self.resources if r.name == resource_name), None)
                if resource and self.policy_analyzer:
                    self.app.push_screen(ResourceDetailScreen(resource, self.policies, self.policy_analyzer, self.k8s_client))

        elif tabs.active == "mispicks":
            table = self.query_one("#mispicks-table", DataTable)
            if table.cursor_row is not None and len(self.access_errors) > 0:
                # Get the error from the reversed list (since table shows most recent first)
                sorted_errors = list(reversed(self.access_errors))
                if table.cursor_row < len(sorted_errors):
                    error = sorted_errors[table.cursor_row]
                    self.app.push_screen(ErrorDetailScreen(error))

    def on_data_table_cell_selected(self, event: DataTable.CellSelected) -> None:
        """Handle cell selection in DataTable (triggered by Enter key)."""
        if event.data_table.id == "policies-table":
            policy_name = event.data_table.get_row_at(event.coordinate.row)[0]
            policy = next((p for p in self.policies if p.name == policy_name), None)
            if policy:
                self.app.push_screen(PolicyDetailScreen(policy, self.k8s_client))
        elif event.data_table.id == "resources-table":
            resource_name = event.data_table.get_row_at(event.coordinate.row)[0]
            resource = next((r for r in self.resources if r.name == resource_name), None)
            if resource and self.policy_analyzer:
                self.app.push_screen(ResourceDetailScreen(resource, self.policies, self.policy_analyzer, self.k8s_client))
        elif event.data_table.id == "mispicks-table":
            if len(self.access_errors) > 0:
                # Get the error from the reversed list (since table shows most recent first)
                sorted_errors = list(reversed(self.access_errors))
                if event.coordinate.row < len(sorted_errors):
                    error = sorted_errors[event.coordinate.row]
                    self.app.push_screen(ErrorDetailScreen(error))

    def action_cursor_up(self) -> None:
        """Move cursor up in focused section."""
        if self.focused_section == "table":
            tabs = self.query_one("#main-tabs", TabbedContent)
            if tabs.active == "policies":
                table = self.query_one("#policies-table", DataTable)
                table.action_cursor_up()
            elif tabs.active == "resources":
                table = self.query_one("#resources-table", DataTable)
                table.action_cursor_up()
            elif tabs.active == "mispicks":
                table = self.query_one("#mispicks-table", DataTable)
                table.action_cursor_up()
        elif self.focused_section == "tree":
            tabs = self.query_one("#main-tabs", TabbedContent)
            if tabs.active == "policies":
                tree = self.query_one("#namespace-tree", Tree)
                tree.action_cursor_up()
            elif tabs.active == "resources":
                tree = self.query_one("#namespace-tree-resources", Tree)
                tree.action_cursor_up()

    def action_cursor_down(self) -> None:
        """Move cursor down in focused section."""
        if self.focused_section == "table":
            tabs = self.query_one("#main-tabs", TabbedContent)
            if tabs.active == "policies":
                table = self.query_one("#policies-table", DataTable)
                table.action_cursor_down()
            elif tabs.active == "resources":
                table = self.query_one("#resources-table", DataTable)
                table.action_cursor_down()
            elif tabs.active == "mispicks":
                table = self.query_one("#mispicks-table", DataTable)
                table.action_cursor_down()
        elif self.focused_section == "tree":
            tabs = self.query_one("#main-tabs", TabbedContent)
            if tabs.active == "policies":
                tree = self.query_one("#namespace-tree", Tree)
                tree.action_cursor_down()
            elif tabs.active == "resources":
                tree = self.query_one("#namespace-tree-resources", Tree)
                tree.action_cursor_down()

    def action_focus_left(self) -> None:
        """Focus the left section (table)."""
        if self.focused_section != "table":
            self.focused_section = "table"
            tabs = self.query_one("#main-tabs", TabbedContent)
            if tabs.active == "policies":
                table = self.query_one("#policies-table", DataTable)
                table.focus()
            elif tabs.active == "resources":
                table = self.query_one("#resources-table", DataTable)
                table.focus()

    def action_focus_right(self) -> None:
        """Focus the right section (namespace tree)."""
        if self.focused_section != "tree":
            self.focused_section = "tree"
            tabs = self.query_one("#main-tabs", TabbedContent)
            if tabs.active == "policies":
                tree = self.query_one("#namespace-tree", Tree)
                tree.focus()
            elif tabs.active == "resources":
                tree = self.query_one("#namespace-tree-resources", Tree)
                tree.focus()

    def action_tab_policies(self) -> None:
        """Switch to policies tab."""
        tabs = self.query_one("#main-tabs", TabbedContent)
        tabs.active = "policies"
        # Ensure table is focused by default
        self.focused_section = "table"
        table = self.query_one("#policies-table", DataTable)
        table.focus()

    def action_tab_resources(self) -> None:
        """Switch to resources tab."""
        tabs = self.query_one("#main-tabs", TabbedContent)
        tabs.active = "resources"
        # Ensure table is focused by default
        self.focused_section = "table"
        table = self.query_one("#resources-table", DataTable)
        table.focus()

    def action_tab_mispicks(self) -> None:
        """Switch to mispicks tab."""
        tabs = self.query_one("#main-tabs", TabbedContent)
        tabs.active = "mispicks"

    def action_start_tailing(self) -> None:
        """Start tailing logs (only in Mispicks tab)."""
        tabs = self.query_one("#main-tabs", TabbedContent)
        if tabs.active == "mispicks":
            self._start_log_tailing()

    def action_stop_tailing(self) -> None:
        """Stop tailing logs (only in Mispicks tab)."""
        tabs = self.query_one("#main-tabs", TabbedContent)
        if tabs.active == "mispicks":
            self._stop_log_tailing()

    def action_clear_mispicks(self) -> None:
        """Clear errors (only in Mispicks tab)."""
        tabs = self.query_one("#main-tabs", TabbedContent)
        if tabs.active == "mispicks":
            self._clear_errors()

    def action_tab_conflicts(self) -> None:
        """Switch to conflicts tab."""
        tabs = self.query_one("#main-tabs", TabbedContent)
        tabs.active = "conflicts"

    def action_tab_help(self) -> None:
        """Switch to help tab."""
        tabs = self.query_one("#main-tabs", TabbedContent)
        tabs.active = "help"

    def action_quit(self) -> None:
        """Quit action."""
        self.app.exit()

    async def on_tree_node_selected(self, event) -> None:
        """Handle namespace selection from tree."""
        if event.node.data and self.namespace_selector:
            # Check if the event came from either namespace tree
            if (hasattr(event.node, 'tree') and
                (event.node.tree.id in ["namespace-tree", "namespace-tree-resources"])):
                # Find the index of the selected namespace
                try:
                    target_namespace = event.node.data
                    current_index = self.namespaces_with_policies.index(target_namespace)
                    self.namespace_selector.current_index = current_index
                    self.namespace_selector.update_display()
                    await self._refresh_policies()
                except ValueError:
                    pass  # Namespace not found in list

    async def _switch_to_namespace(self, target_namespace: str) -> None:
        """Switch to a specific namespace."""
        if self.namespace_selector:
            try:
                current_index = self.namespaces_with_policies.index(target_namespace)
                self.namespace_selector.current_index = current_index
                self.namespace_selector.update_display()
                await self._refresh_policies()
            except ValueError:
                pass  # Namespace not found in list
