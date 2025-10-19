"""Main screen for kubeloom TUI."""

from typing import List, Optional
import asyncio
from textual import work
from textual.app import ComposeResult
from textual.containers import Container, Vertical, Horizontal
from textual.widgets import Static, DataTable, TabbedContent, TabPane, Tree
from textual.screen import Screen
from textual.binding import Binding

from ...core.models import Policy, ServiceMesh
from ...core.interfaces import MeshAdapter
from ...core.services import PolicyAnalyzer, ResourceInfo
from ...k8s.client import K8sClient
from ...mesh.istio.adapter import IstioAdapter
from ..widgets import StatusBar, NamespaceSelector
from ..modals import PolicyDetailScreen, ResourceDetailScreen, ErrorDetailScreen
from ..tabs import DashboardTab, PoliciesTab, ResourcesTab, MispicksTab


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
        Binding("e", "enroll_pod", "Enroll Pod", show=False),
        Binding("u", "unenroll_pod", "Unenroll Pod", show=False),
        Binding("w", "weave_policy", "Weave Policy", show=False),
        Binding("W", "unweave_policies", "Unweave All", show=False),
    ]

    def __init__(self):
        super().__init__()
        self.k8s_client: Optional[K8sClient] = None
        self.mesh_adapter: Optional[MeshAdapter] = None
        self.service_mesh: Optional[ServiceMesh] = None
        self.namespaces_with_policies: List[str] = []
        self.namespaces: List = []  # Full namespace objects
        self.policies: List[Policy] = []
        self.resources: List[ResourceInfo] = []
        self.policy_analyzer: Optional[PolicyAnalyzer] = None
        self.namespace_selector: Optional[NamespaceSelector] = None
        self.focused_section = "table"  # "table" or "tree"

        # Tab components
        self.dashboard_tab = DashboardTab()
        self.policies_tab = PoliciesTab()
        self.resources_tab = ResourcesTab()
        self.mispicks_tab = MispicksTab()

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
                    with Vertical():
                        with Horizontal():
                            yield DataTable(id="resources-table", zebra_stripes=True)
                            with Container(id="namespace-panel"):
                                yield Static("Namespaces", id="namespace-title")
                                yield Tree("Namespaces", id="namespace-tree-resources")
                        yield Static("e: Enroll Pod | u: Unenroll Pod", id="resources-footer")

                with TabPane("Mispicks", id="mispicks"):
                    with Vertical():
                        yield DataTable(id="mispicks-table", zebra_stripes=True)
                        with Horizontal(id="mispicks-footer-container"):
                            yield Static("s: Start | x: Stop | c: Clear | w: Weave | W: Unweave All", id="mispicks-keybindings")
                            yield Static("Status: Not running", id="tailing-status")

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
  1/2/3/4      Switch tabs (Dashboard/Policies/Resources/Mispicks)

ACTIONS:
  r            Refresh data
  q            Quit
"""

    async def on_mount(self) -> None:
        """Initialize the application on mount."""
        self.namespace_selector = self.query_one(NamespaceSelector)

        # Initialize mispicks table
        table = self.query_one("#mispicks-table", DataTable)
        self.mispicks_tab.init_table(table)

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
            self.namespaces = namespaces  # Store full namespace objects
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
        self.policies_tab.update_table(table, self.policies)

    async def _refresh_resources(self) -> None:
        """Refresh resources affected by policies in current namespace."""
        if not self.policy_analyzer or not self.policies:
            self.resources = []
            await self._update_resources_table()
            return

        try:
            self.resources = await self.policy_analyzer.get_all_affected_resources(self.policies)
            await self._update_resources_table()
        except Exception:
            self.resources = []
            await self._update_resources_table()

    async def _update_resources_table(self) -> None:
        """Update the resources table."""
        table = self.query_one("#resources-table", DataTable)

        # Get current namespace object
        current_namespace = None
        if self.namespace_selector:
            current_ns_name = self.namespace_selector.get_current_namespace()
            current_namespace = next((ns for ns in self.namespaces if ns.name == current_ns_name), None)

        await self.resources_tab.update_table(
            table,
            self.resources,
            self.policies,
            self.mesh_adapter,
            self.k8s_client,
            current_namespace
        )

    async def _update_namespace_tree(self) -> None:
        """Update the namespace tree with namespaces that have policies."""
        current_ns = self.namespace_selector.get_current_namespace() if self.namespace_selector else None

        # Update both namespace trees
        try:
            tree = self.query_one("#namespace-tree", Tree)
            await self.policies_tab.update_namespace_tree(
                tree, self.namespaces_with_policies, current_ns, self.mesh_adapter
            )
        except Exception:
            pass

        try:
            tree_resources = self.query_one("#namespace-tree-resources", Tree)
            await self.policies_tab.update_namespace_tree(
                tree_resources, self.namespaces_with_policies, current_ns, self.mesh_adapter
            )
        except Exception:
            pass

    def _update_dashboard(self) -> None:
        """Update dashboard with cluster and mesh statistics."""
        dashboard = self.query_one("#dashboard-content", Static)
        panel = self.dashboard_tab.render(
            self.service_mesh,
            self.namespaces_with_policies,
            self.policies,
            self.namespace_selector
        )
        dashboard.update(panel)

    def _update_mispicks_table(self) -> None:
        """Update the mispicks table."""
        table = self.query_one("#mispicks-table", DataTable)
        self.mispicks_tab.update_table(table)

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
        """View selected item details (policy, resource, or error)."""
        tabs = self.query_one("#main-tabs", TabbedContent)

        if tabs.active == "policies":
            table = self.query_one("#policies-table", DataTable)
            if table.cursor_row is not None:
                policy_name = table.get_row_at(table.cursor_row)[0]
                # Handle Rich Text objects (used for cyan-colored woven policies)
                if hasattr(policy_name, "plain"):
                    policy_name = policy_name.plain
                policy = next((p for p in self.policies if p.name == policy_name), None)
                if policy:
                    self.app.push_screen(PolicyDetailScreen(policy, self.k8s_client))

        elif tabs.active == "resources":
            table = self.query_one("#resources-table", DataTable)
            if table.cursor_row is not None:
                resource_name = table.get_row_at(table.cursor_row)[0]
                # Handle Rich Text objects
                if hasattr(resource_name, "plain"):
                    resource_name = resource_name.plain
                resource = next((r for r in self.resources if r.name == resource_name), None)
                if resource and self.policy_analyzer:
                    self.app.push_screen(ResourceDetailScreen(resource, self.policies, self.policy_analyzer, self.k8s_client))

        elif tabs.active == "mispicks":
            table = self.query_one("#mispicks-table", DataTable)
            if table.cursor_row is not None:
                error = self.mispicks_tab.get_error_at_row(table.cursor_row)
                if error:
                    self.app.push_screen(ErrorDetailScreen(error))

    def on_data_table_cell_selected(self, event: DataTable.CellSelected) -> None:
        """Handle cell selection in DataTable (triggered by Enter key)."""
        if event.data_table.id == "policies-table":
            policy_name = event.data_table.get_row_at(event.coordinate.row)[0]
            # Handle Rich Text objects (used for cyan-colored woven policies)
            if hasattr(policy_name, "plain"):
                policy_name = policy_name.plain
            policy = next((p for p in self.policies if p.name == policy_name), None)
            if policy:
                self.app.push_screen(PolicyDetailScreen(policy, self.k8s_client))
        elif event.data_table.id == "resources-table":
            resource_name = event.data_table.get_row_at(event.coordinate.row)[0]
            # Handle Rich Text objects
            if hasattr(resource_name, "plain"):
                resource_name = resource_name.plain
            resource = next((r for r in self.resources if r.name == resource_name), None)
            if resource and self.policy_analyzer:
                self.app.push_screen(ResourceDetailScreen(resource, self.policies, self.policy_analyzer, self.k8s_client))
        elif event.data_table.id == "mispicks-table":
            error = self.mispicks_tab.get_error_at_row(event.coordinate.row)
            if error:
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
            status_widget = self.query_one("#tailing-status", Static)
            self.mispicks_tab.start_tailing(
                status_widget,
                self.mesh_adapter,
                self.namespace_selector,
                lambda: self.call_after_refresh(self._update_mispicks_table)
            )

    def action_stop_tailing(self) -> None:
        """Stop tailing logs (only in Mispicks tab)."""
        tabs = self.query_one("#main-tabs", TabbedContent)
        if tabs.active == "mispicks":
            status_widget = self.query_one("#tailing-status", Static)
            self.mispicks_tab.stop_tailing(status_widget)

    def action_clear_mispicks(self) -> None:
        """Clear errors (only in Mispicks tab)."""
        tabs = self.query_one("#main-tabs", TabbedContent)
        if tabs.active == "mispicks":
            self.mispicks_tab.clear_errors()
            self._update_mispicks_table()

    def action_tab_conflicts(self) -> None:
        """Switch to conflicts tab."""
        tabs = self.query_one("#main-tabs", TabbedContent)
        tabs.active = "conflicts"

    def action_tab_help(self) -> None:
        """Switch to help tab."""
        tabs = self.query_one("#main-tabs", TabbedContent)
        tabs.active = "help"

    async def action_enroll_pod(self) -> None:
        """Enroll selected pod in mesh (only in Resources tab)."""
        tabs = self.query_one("#main-tabs", TabbedContent)
        if tabs.active != "resources":
            # Show feedback that we're not in the right tab
            dashboard = self.query_one("#dashboard-content", Static)
            dashboard.update("Enroll only works in Resources tab")
            return

        table = self.query_one("#resources-table", DataTable)
        if table.cursor_row is None:
            return

        # Get the selected resource
        resource_name = table.get_row_at(table.cursor_row)[0]
        # Handle Rich Text objects
        if hasattr(resource_name, "plain"):
            resource_name = resource_name.plain

        resource = next((r for r in self.resources if r.name == resource_name), None)
        if not resource or resource.type != "pod":
            # Show feedback
            dashboard = self.query_one("#dashboard-content", Static)
            dashboard.update(f"Cannot enroll {resource.type if resource else 'unknown'} - only pods can be enrolled")
            return

        # Show we're enrolling
        dashboard = self.query_one("#dashboard-content", Static)
        dashboard.update(f"Enrolling pod {resource.name}...")

        # Enroll the pod
        if self.mesh_adapter:
            try:
                success = await self.mesh_adapter.enroll_pod(resource.name, resource.namespace)
                if success:
                    self.app.notify(f"Pod {resource.name} enrolled in mesh", severity="information", timeout=3)
                    dashboard.update(f"Pod enrolled! Refreshing...")
                    # Small delay to let Kubernetes process the update
                    await asyncio.sleep(0.5)
                    # Refresh resources to show updated enrollment status
                    await self._refresh_resources()
                    dashboard.update(f"Pod {resource.name} enrolled in mesh")
                else:
                    self.app.notify(f"Failed to enroll pod {resource.name}", severity="warning", timeout=5)
                    dashboard.update(f"Failed to enroll pod {resource.name}")
            except Exception as e:
                self.app.notify(f"Error: {str(e)}", severity="error", timeout=5)
                dashboard.update(f"Error enrolling: {str(e)}")

    async def action_unenroll_pod(self) -> None:
        """Unenroll selected pod from mesh (only in Resources tab)."""
        tabs = self.query_one("#main-tabs", TabbedContent)
        if tabs.active != "resources":
            return

        table = self.query_one("#resources-table", DataTable)
        if table.cursor_row is None:
            return

        # Get the selected resource
        resource_name = table.get_row_at(table.cursor_row)[0]
        # Handle Rich Text objects
        if hasattr(resource_name, "plain"):
            resource_name = resource_name.plain

        resource = next((r for r in self.resources if r.name == resource_name), None)
        if not resource or resource.type != "pod":
            # Show feedback
            dashboard = self.query_one("#dashboard-content", Static)
            dashboard.update(f"Cannot unenroll {resource.type if resource else 'unknown'} - only pods can be unenrolled")
            return

        # Check if namespace is mesh-enabled
        if self.mesh_adapter and self.namespace_selector:
            current_ns_name = self.namespace_selector.get_current_namespace()
            current_namespace = next((ns for ns in self.namespaces if ns.name == current_ns_name), None)

            if current_namespace and self.mesh_adapter.is_namespace_mesh_enabled(current_namespace):
                # Namespace is mesh-enabled, cannot unenroll individual pod
                dashboard = self.query_one("#dashboard-content", Static)
                dashboard.update(f"Pod cannot be removed from mesh - entire namespace '{current_ns_name}' is enrolled")
                self.app.notify(
                    f"Pod cannot be removed from mesh as the entire namespace is enrolled",
                    severity="warning",
                    timeout=5
                )
                return

        # Show we're unenrolling
        dashboard = self.query_one("#dashboard-content", Static)
        dashboard.update(f"Unenrolling pod {resource.name}...")

        # Unenroll the pod
        if self.mesh_adapter:
            try:
                success = await self.mesh_adapter.unenroll_pod(resource.name, resource.namespace)
                if success:
                    self.app.notify(f"Pod {resource.name} unenrolled from mesh", severity="information", timeout=3)
                    dashboard.update(f"Pod unenrolled! Refreshing...")
                    # Small delay to let Kubernetes process the update
                    await asyncio.sleep(0.5)
                    # Refresh resources to show updated enrollment status
                    await self._refresh_resources()
                    dashboard.update(f"Pod {resource.name} unenrolled from mesh")
                else:
                    self.app.notify(f"Failed to unenroll pod {resource.name}", severity="warning", timeout=5)
                    dashboard.update(f"Failed to unenroll pod {resource.name}")
            except Exception as e:
                self.app.notify(f"Error: {str(e)}", severity="error", timeout=5)
                dashboard.update(f"Error unenrolling: {str(e)}")

    async def action_weave_policy(self) -> None:
        """Weave policy from selected error (only in Mispicks tab)."""
        tabs = self.query_one("#main-tabs", TabbedContent)
        if tabs.active != "mispicks":
            return

        table = self.query_one("#mispicks-table", DataTable)
        if table.cursor_row is None:
            return

        # Get the selected error
        error = self.mispicks_tab.get_error_at_row(table.cursor_row)
        if not error:
            return

        # Check error type - only ACCESS_DENIED can be woven
        if error.error_type.value == "source_not_on_mesh":
            self.app.notify(
                "Source pod is not enrolled in mesh - enroll the source pod first before creating policies",
                severity="warning",
                timeout=5
            )
            return
        elif error.error_type.value != "access_denied":
            self.app.notify(
                f"Can only weave policies for access_denied errors, not {error.error_type.value}",
                severity="warning",
                timeout=5
            )
            return

        # Weave the policy
        if self.mesh_adapter:
            try:
                self.app.notify("Weaving policy...", severity="information", timeout=2)

                policy = await self.mesh_adapter.weave_policy(error)

                if policy:
                    policy_type = policy.labels.get("kubeloom.io/policy-type", "unknown")
                    self.app.notify(
                        f"Policy {policy.name} ({policy_type}) woven successfully!",
                        severity="information",
                        timeout=5
                    )

                    # Refresh policies to show the new woven policy
                    await self._refresh_policies()
                else:
                    self.app.notify("Failed to weave policy", severity="warning", timeout=5)

            except Exception as e:
                self.app.notify(f"Error weaving policy: {str(e)}", severity="error", timeout=5)

    async def action_unweave_policies(self) -> None:
        """Unweave all kubeloom-managed policies."""
        if not self.mesh_adapter:
            return

        try:
            self.app.notify("Unweaving all kubeloom policies...", severity="information", timeout=2)

            # Unweave policies from all namespaces
            removed_count = await self.mesh_adapter.unweave_policies()

            if removed_count > 0:
                self.app.notify(
                    f"Successfully removed {removed_count} woven {'policy' if removed_count == 1 else 'policies'}",
                    severity="information",
                    timeout=5
                )

                # Refresh policies to reflect the changes
                await self._refresh_policies()
            else:
                self.app.notify("No woven policies found to remove", severity="information", timeout=3)

        except Exception as e:
            self.app.notify(f"Error unweaving policies: {str(e)}", severity="error", timeout=5)

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
