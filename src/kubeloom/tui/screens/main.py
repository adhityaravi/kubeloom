"""Main screen for kubeloom TUI."""

import asyncio
import contextlib
from typing import Any, ClassVar

import yaml
from rich.console import Group
from rich.syntax import Syntax
from rich.text import Text as RichText
from rich.tree import Tree as RichTree
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import DataTable, Input, Static, TabbedContent, TabPane

from kubeloom.core.interfaces import MeshAdapter
from kubeloom.core.models import Policy, ServiceMesh
from kubeloom.core.services import PolicyAnalyzer, ResourceInfo
from kubeloom.k8s.client import K8sClient
from kubeloom.mesh.istio.adapter import IstioAdapter
from kubeloom.tui.tabs import MispicksTab
from kubeloom.tui.theme import Colors, Labels
from kubeloom.tui.widgets import NamespaceSelector, StatusBar

# Tab IDs
TAB_POLICIES = "policies"
TAB_RESOURCES = "resources"
TAB_MISPICKS = "mispicks"


class MainScreen(Screen[None]):
    """Main screen for service mesh policy management."""

    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("q", "quit", "Quit"),
        Binding("r", "refresh", "Refresh"),
        Binding("j", "cursor_down", "Down", show=False),
        Binding("k", "cursor_up", "Up", show=False),
        Binding("h", "scroll_up", "Scroll Up", show=False),
        Binding("l", "scroll_down", "Scroll Down", show=False),
        Binding("n", "next_namespace", "Next NS"),
        Binding("p", "prev_namespace", "Prev NS"),
        Binding("1", "tab_policies", "Policies", show=False),
        Binding("2", "tab_resources", "Resources", show=False),
        Binding("3", "tab_mispicks", "Mispicks", show=False),
        Binding("s", "start_tailing", "Start Tailing", show=False),
        Binding("x", "stop_tailing", "Stop Tailing", show=False),
        Binding("c", "clear_mispicks", "Clear Errors", show=False),
        Binding("e", "enroll_pod", "Enroll Pod", show=False),
        Binding("u", "unenroll_pod", "Unenroll Pod", show=False),
        Binding("w", "weave_policy", "Weave Policy", show=False),
        Binding("W", "unweave_policies", "Unweave All", show=False),
        Binding("y", "copy_manifest", "Copy Manifest", show=False),
        Binding("slash", "focus_filter", "Filter", show=False),
        Binding("escape", "clear_filter", "Clear Filter", show=False),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.k8s_client: K8sClient | None = None
        self.mesh_adapter: MeshAdapter | None = None
        self.service_mesh: ServiceMesh | None = None
        self.namespaces_with_policies: list[str] = []
        self.namespaces: list[Any] = []
        self.policies: list[Policy] = []
        self.resources: list[ResourceInfo] = []
        self.policy_analyzer: PolicyAnalyzer | None = None
        self.namespace_selector: NamespaceSelector | None = None
        self.status_bar: StatusBar | None = None

        self.mispicks_tab = MispicksTab()

        # Background tasks (stored to prevent garbage collection)
        self._background_tasks: set[asyncio.Task[None]] = set()

        # List selection and filter state
        self._policy_cursor: int = 0
        self._resource_cursor: int = 0
        self._policy_filter: str = ""
        self._resource_filter: str = ""
        self._mispicks_filter: str = ""
        self._filtered_policies: list[Policy] = []
        self._filtered_resources: list[ResourceInfo] = []

        # Cache for namespace policy counts (avoids redundant API calls)
        self._namespace_policy_counts: dict[str, int] = {}

    def compose(self) -> ComposeResult:
        with Container(id="main-container"):
            yield Static(f"[{Colors.PURPLE.value} bold]ｋｕｂｅｌｏｏｍ[/]", id="app-title")
            yield NamespaceSelector()

            with TabbedContent(initial=TAB_POLICIES, id="main-tabs"):
                with TabPane("Policies", id=TAB_POLICIES):
                    with Horizontal(id="policies-layout"):
                        with Vertical(id="policies-list-pane"):
                            yield Input(placeholder="/filter...", id="policies-filter")
                            with VerticalScroll(id="policies-list-scroll"):
                                yield Static("", id="policies-list")
                        with Vertical(id="policies-detail-pane"):
                            with VerticalScroll(id="policies-detail-scroll"):
                                yield Static("", id="policies-detail-content")
                        with Vertical(id="policies-ns-pane"):
                            with VerticalScroll(id="policies-ns-scroll"):
                                yield Static("", id="namespace-list")

                with TabPane("Resources", id=TAB_RESOURCES):
                    with Horizontal(id="resources-layout"):
                        with Vertical(id="resources-list-pane"):
                            yield Input(placeholder="/filter...", id="resources-filter")
                            with VerticalScroll(id="resources-list-scroll"):
                                yield Static("", id="resources-list")
                        with Vertical(id="resources-detail-pane"):
                            with VerticalScroll(id="resources-detail-scroll"):
                                yield Static("", id="resources-detail-content")
                        with Vertical(id="resources-ns-pane"):
                            with VerticalScroll(id="resources-ns-scroll"):
                                yield Static("", id="namespace-list-resources")

                with TabPane("Mispicks", id=TAB_MISPICKS):
                    with Horizontal(id="mispicks-layout"):
                        with Vertical(id="mispicks-list-pane"):
                            yield Input(placeholder="/filter...", id="mispicks-filter")
                            yield DataTable(id="mispicks-table", zebra_stripes=True, header_height=2)
                        with Vertical(id="mispicks-detail-pane"):
                            with VerticalScroll(id="mispicks-detail-scroll"):
                                yield Static("", id="mispicks-detail-content")

            yield StatusBar()

    # ─── Lifecycle ────────────────────────────────────────────────────────────

    async def on_mount(self) -> None:
        """Initialize the application on mount."""
        self.namespace_selector = self.query_one(NamespaceSelector)
        self.status_bar = self.query_one(StatusBar)
        self.status_bar.set_active_tab(TAB_POLICIES)

        table = self.query_one("#mispicks-table", DataTable)
        self.mispicks_tab.init_table(table)

        # Show loading state
        self.query_one("#policies-list", Static).update("[dim]Loading...[/]")

        # Initialize in background so UI renders immediately
        self._run_background(self._initialize())

    async def _initialize(self) -> None:
        """Initialize Kubernetes client and detect service mesh."""
        try:
            self.k8s_client = K8sClient()
            self.mesh_adapter = IstioAdapter(self.k8s_client)
            self.policy_analyzer = PolicyAnalyzer(self.k8s_client)
            self.service_mesh = await self.mesh_adapter.detect()

            if not self.service_mesh:
                self.app.notify("No service mesh detected", severity="warning", timeout=5)
                self._update_status_bar()
                return

            await self._load_namespaces_with_policies()
            await self._refresh_policies()
            self._update_status_bar()

        except Exception as e:
            self.app.notify(f"Error: {e!s}", severity="error", timeout=5)

    # ─── Data Loading ─────────────────────────────────────────────────────────

    async def _load_namespaces_with_policies(self) -> None:
        """Load namespaces that contain policies."""
        if not self.mesh_adapter or not self.k8s_client:
            return

        try:
            namespaces = await self.k8s_client.get_namespaces()
            self.namespaces = namespaces
            self.namespaces_with_policies = []
            self._namespace_policy_counts = {}

            # Fetch AuthorizationPolicies for all namespaces in parallel
            async def get_ns_policies(ns_name: str) -> tuple[str, int]:
                policies = await self.mesh_adapter.get_authorization_policies(ns_name)
                return (ns_name, len(policies))

            results = await asyncio.gather(
                *[get_ns_policies(ns.name) for ns in namespaces],
                return_exceptions=True
            )

            for result in results:
                if isinstance(result, tuple):
                    ns_name, count = result
                    if count > 0:
                        self.namespaces_with_policies.append(ns_name)
                        self._namespace_policy_counts[ns_name] = count

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
                self._policy_cursor = self._clamp_cursor(self._policy_cursor, len(self.policies))
                self._update_policies_list()
                await self._refresh_resources()
                self._update_status_bar()
                self._update_namespace_tree()
                self._update_current_detail()

        except Exception as e:
            self.app.notify(f"Error loading policies: {e!s}", severity="error", timeout=5)

    async def _refresh_resources(self) -> None:
        """Refresh resources affected by policies in current namespace."""
        if not self.policy_analyzer or not self.policies:
            self.resources = []
            self._resource_cursor = 0
            await self._update_resources_list()
            return

        try:
            self.resources = await self.policy_analyzer.get_all_affected_resources(self.policies)
            self._resource_cursor = self._clamp_cursor(self._resource_cursor, len(self.resources))
            await self._update_resources_list()
        except Exception:
            self.resources = []
            self._resource_cursor = 0
            await self._update_resources_list()

    # ─── List Rendering ───────────────────────────────────────────────────────

    def _clamp_cursor(self, cursor: int, length: int) -> int:
        """Clamp cursor to valid range."""
        return min(cursor, max(0, length - 1)) if length > 0 else 0

    def _run_background(self, coro: Any) -> None:
        """Run a coroutine as a background task with proper cleanup."""
        task = asyncio.create_task(coro)
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

    def _apply_filter(self, items: list[Any], filter_text: str, key: str = "name") -> list[Any]:
        """Filter items by name (case-insensitive)."""
        if not filter_text:
            return list(items)
        filter_lower = filter_text.lower()
        return [item for item in items if filter_lower in getattr(item, key, "").lower()]

    def _update_policies_list(self) -> None:
        """Update the policies list display."""
        self._filtered_policies = self._apply_filter(self.policies, self._policy_filter)
        self._policy_cursor = self._clamp_cursor(self._policy_cursor, len(self._filtered_policies))
        self._render_policies_list()

    def _render_policies_list(self) -> None:
        """Render the policies list widget."""
        policies_list = self.query_one("#policies-list", Static)
        lines = []

        for i, policy in enumerate(self._filtered_policies):
            is_woven = policy.labels.get("kubeloom.io/managed") == "true"
            action_type = policy.action.type.value if policy.action else None
            label = Labels.policy_action(action_type)
            selected = i == self._policy_cursor

            if selected:
                lines.append(f"[bold {Colors.CYAN.value}]{label} {policy.name}[/]")
            elif is_woven:
                lines.append(f"[{Colors.CYAN.value}]{label} {policy.name}[/]")
            else:
                lines.append(f"{label} {policy.name}")

        policies_list.update("\n".join(lines) if lines else "[dim]No policies[/dim]")

    async def _update_resources_list(self) -> None:
        """Update the resources list display."""
        self._filtered_resources = self._apply_filter(self.resources, self._resource_filter)
        self._resource_cursor = self._clamp_cursor(self._resource_cursor, len(self._filtered_resources))
        await self._render_resources_list()

    async def _render_resources_list(self) -> None:
        """Render the resources list widget."""
        resources_list = self.query_one("#resources-list", Static)
        current_namespace = self._get_current_namespace_obj()
        lines = []

        for i, resource in enumerate(self._filtered_resources):
            is_enrolled = await self._check_pod_enrollment(resource, current_namespace)
            label = Labels.resource_type(resource.type)
            selected = i == self._resource_cursor

            if selected:
                color = Colors.RED.value if not is_enrolled else Colors.CYAN.value
                lines.append(f"[bold {color}]{label} {resource.name}[/]")
            elif not is_enrolled:
                lines.append(f"[{Colors.RED.value}]{label} {resource.name}[/]")
            else:
                lines.append(f"{label} {resource.name}")

        resources_list.update("\n".join(lines) if lines else "[dim]No resources[/dim]")

    async def _check_pod_enrollment(self, resource: ResourceInfo, namespace: Any) -> bool:
        """Check if a pod is enrolled in the mesh."""
        if resource.type != "pod" or not self.mesh_adapter or not self.k8s_client or not namespace:
            return True
        try:
            pods = await self.k8s_client.get_resources("v1", "Pod", resource.namespace)
            pod = next((p for p in pods if p.get("metadata", {}).get("name") == resource.name), None)
            return self.mesh_adapter.is_pod_enrolled(pod, namespace) if pod else True
        except Exception:
            return True

    def _get_current_namespace_obj(self) -> Any:
        """Get the current namespace object."""
        if not self.namespace_selector:
            return None
        ns_name = self.namespace_selector.get_current_namespace()
        return next((ns for ns in self.namespaces if ns.name == ns_name), None)

    def _update_mispicks_table(self) -> None:
        """Update the mispicks table."""
        table = self.query_one("#mispicks-table", DataTable)
        self.mispicks_tab.update_table(table, self._mispicks_filter)

    def _update_namespace_tree(self) -> None:
        """Update the namespace list with namespaces that have policies."""
        current_ns = self.namespace_selector.get_current_namespace() if self.namespace_selector else None

        tree = RichTree("[bold]All[/bold]", guide_style=Colors.SURFACE.value)
        for namespace in self.namespaces_with_policies:
            # Use cached count instead of making API calls
            policy_count = self._namespace_policy_counts.get(namespace, 0)

            if namespace == current_ns:
                label = f"[bold {Colors.CYAN.value}]{namespace}[/] ({policy_count})"
            else:
                label = f"{namespace} ({policy_count})"
            tree.add(label)

        # Update both namespace lists
        for widget_id in ("#namespace-list", "#namespace-list-resources"):
            with contextlib.suppress(Exception):
                self.query_one(widget_id, Static).update(tree)

    def _update_status_bar(self) -> None:
        """Update status bar with mesh and namespace info."""
        if self.status_bar:
            mesh_type = self.service_mesh.type.value if self.service_mesh else ""
            mesh_version = self.service_mesh.version if self.service_mesh else ""
            self.status_bar.update_info(mesh_type, mesh_version, len(self.namespaces_with_policies))

    # ─── Detail Pane Rendering ────────────────────────────────────────────────

    def _get_active_tab(self) -> str:
        """Get the currently active tab ID."""
        return self.query_one("#main-tabs", TabbedContent).active or TAB_POLICIES

    def _update_current_detail(self) -> None:
        """Update the detail pane based on current tab and selection."""
        tab = self._get_active_tab()
        if tab == TAB_POLICIES:
            self._update_policy_detail()
        elif tab == TAB_RESOURCES:
            self._update_resource_detail()
        elif tab == TAB_MISPICKS:
            self._update_mispicks_detail()

    def _update_policy_detail(self) -> None:
        """Update policy detail pane."""
        detail = self.query_one("#policies-detail-content", Static)

        if not self._filtered_policies or self._policy_cursor >= len(self._filtered_policies):
            detail.update("[dim]Select a policy to view details[/dim]")
            return

        policy = self._filtered_policies[self._policy_cursor]
        detail.update(self._render_policy_detail(policy))

    def _update_resource_detail(self) -> None:
        """Update resource detail pane."""
        detail = self.query_one("#resources-detail-content", Static)

        if not self._filtered_resources or self._resource_cursor >= len(self._filtered_resources):
            detail.update("[dim]Select a resource to view details[/dim]")
            return

        resource = self._filtered_resources[self._resource_cursor]
        detail.update(self._render_resource_detail(resource))

    def _update_mispicks_detail(self) -> None:
        """Update mispicks detail pane."""
        table = self.query_one("#mispicks-table", DataTable)
        detail = self.query_one("#mispicks-detail-content", Static)

        if table.cursor_row is None:
            detail.update("[dim]Select an error to view details[/dim]")
            return

        error = self.mispicks_tab.get_error_at_row(table.cursor_row)
        if not error:
            detail.update("[dim]Error not found[/dim]")
            return

        detail.update(self._render_error_detail(error))

    def _label(self, text: str) -> str:
        """Format a label with theme color."""
        return f"[{Colors.LABEL.value} bold]{text}:[/]"

    def _render_policy_detail(self, policy: Policy) -> Group:
        """Render policy detail content with syntax highlighting."""
        action_str = self._format_action(policy.action)
        source_str = self._format_source(policy.source)
        target_str = self._format_targets(policy.targets)
        routes_str = self._format_routes(policy.allowed_routes)
        labels_str = self._format_labels(policy.labels)

        text_content = f"""{self._label("Name")} {policy.name}
{self._label("Namespace")} {policy.namespace}
{self._label("Type")} {policy.type.value}
{self._label("Status")} {policy.status.value}
{self._label("Action")} {action_str}

{self._label("Source")} {source_str}
{self._label("Targets")} {target_str}
{self._label("Routes")} {routes_str}

{self._label("Labels")}
{labels_str}

{self._label("Manifest")}
"""
        return Group(
            RichText.from_markup(text_content),
            self._format_yaml(policy.raw_manifest or policy.spec),
        )

    def _render_resource_detail(self, resource: ResourceInfo) -> str:
        """Render resource detail content."""
        labels_str = self._format_labels(resource.labels)
        sa_str = resource.service_account or "default"

        return f"""{self._label("Name")} {resource.name}
{self._label("Namespace")} {resource.namespace}
{self._label("Type")} {resource.type}
{self._label("Service Account")} {sa_str}

{self._label("Labels")}
{labels_str}"""

    def _render_error_detail(self, error: Any) -> Group:
        """Render error detail content."""
        source_str = self._format_error_source(error)
        target_str = self._format_error_target(error)
        http_str = f"{error.http_method or ''} {error.http_path or ''}".strip() or "-"
        timestamp_str = error.timestamp.strftime("%Y-%m-%d %H:%M:%S") if error.timestamp else "-"

        text_content = f"""{self._label("Error Type")} {error.error_type.value}
{self._label("Timestamp")} {timestamp_str}

{self._label("Source")} {source_str}
{self._label("Target")} {target_str}
{self._label("HTTP")} {http_str}

{self._label("Reason")} {error.reason or "-"}

{self._label("Raw Message")}"""

        return Group(
            RichText.from_markup(text_content),
            RichText(error.raw_message or "-", style="dim"),
        )

    # ─── Formatting Helpers ───────────────────────────────────────────────────

    def _format_action(self, action: Any) -> str:
        """Format policy action for display."""
        if not action:
            return "Unknown"
        action_type = action.type.value
        color = "green" if action_type == "ALLOW" else "red" if action_type == "DENY" else "yellow"
        return f"[{color}]{action_type}[/{color}]"

    def _format_source(self, source: Any) -> str:
        """Format policy source for display."""
        if not source or source.is_empty():
            return "All sources"
        parts = []
        if source.service_accounts:
            parts.append(f"SAs: {', '.join(source.service_accounts)}")
        if source.namespaces:
            parts.append(f"NS: {', '.join(source.namespaces)}")
        if source.workload_labels:
            labels = [f"{k}={v}" for k, v in source.workload_labels.items()]
            parts.append(f"Labels: {', '.join(labels)}")
        return " | ".join(parts) if parts else "All sources"

    def _format_targets(self, targets: list[Any]) -> str:
        """Format policy targets for display."""
        if not targets:
            return "All workloads"
        parts = []
        for target in targets:
            if target.services:
                parts.extend(target.services)
            if target.workload_labels:
                labels = [f"{k}={v}" for k, v in target.workload_labels.items()]
                parts.append(f"Labels: {', '.join(labels)}")
        return ", ".join(parts) if parts else "All workloads"

    def _format_routes(self, routes: list[Any]) -> str:
        """Format policy routes for display."""
        if not routes:
            return "All routes"
        parts = []
        for route in routes:
            if route.deny_all:
                return f"[{Colors.RED.value}]No routes allowed[/]"
            if route.allow_all:
                return "All routes"
            if route.ports and route.paths:
                for port in route.ports:
                    for path in route.paths:
                        parts.append(f":{port}{path}")
            elif route.ports:
                parts.extend(f":{port}/*" for port in route.ports)
            elif route.paths:
                parts.extend(f":*{path}" for path in route.paths)
        return ", ".join(parts) if parts else "All routes"

    def _format_labels(self, labels: dict[str, str] | None) -> str:
        """Format labels for display."""
        if not labels:
            return "None"
        return "\n".join(f"  {k}: {v}" for k, v in labels.items())

    def _format_error_source(self, error: Any) -> str:
        """Format error source for display."""
        if error.source_workload and error.source_namespace:
            return f"{error.source_namespace}/{error.source_workload}"
        return error.source_ip or "-"

    def _format_error_target(self, error: Any) -> str:
        """Format error target for display."""
        if error.target_service:
            base = error.target_service
        elif error.target_workload and error.target_namespace:
            base = f"{error.target_namespace}/{error.target_workload}"
        elif error.target_ip:
            base = error.target_ip
        else:
            return "-"
        return f"{base}:{error.target_port}" if error.target_port else base

    def _format_yaml(self, obj: Any) -> Syntax:
        """Format object as syntax-highlighted YAML."""
        try:
            formatted = yaml.dump(obj, default_flow_style=False, indent=2, sort_keys=False)
        except (yaml.YAMLError, TypeError):
            formatted = str(obj)
        return Syntax(formatted, "yaml", theme="dracula", background_color=Colors.MANIFEST_BG.value)

    # ─── Actions ──────────────────────────────────────────────────────────────

    async def action_refresh(self) -> None:
        """Refresh all data."""
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

    def action_scroll_up(self) -> None:
        """Scroll up in detail pane."""
        scroll_id = f"#{self._get_active_tab()}-detail-scroll"
        self.query_one(scroll_id, VerticalScroll).scroll_up()

    def action_scroll_down(self) -> None:
        """Scroll down in detail pane."""
        scroll_id = f"#{self._get_active_tab()}-detail-scroll"
        self.query_one(scroll_id, VerticalScroll).scroll_down()

    def action_cursor_up(self) -> None:
        """Move cursor up in list/table."""
        tab = self._get_active_tab()
        if tab == TAB_POLICIES and self._policy_cursor > 0:
            self._policy_cursor -= 1
            self._render_policies_list()
        elif tab == TAB_RESOURCES and self._resource_cursor > 0:
            self._resource_cursor -= 1
            self._run_background(self._render_resources_list())
        elif tab == TAB_MISPICKS:
            self.query_one("#mispicks-table", DataTable).action_cursor_up()
        self._update_current_detail()

    def action_cursor_down(self) -> None:
        """Move cursor down in list/table."""
        tab = self._get_active_tab()
        if tab == TAB_POLICIES and self._policy_cursor < len(self._filtered_policies) - 1:
            self._policy_cursor += 1
            self._render_policies_list()
        elif tab == TAB_RESOURCES and self._resource_cursor < len(self._filtered_resources) - 1:
            self._resource_cursor += 1
            self._run_background(self._render_resources_list())
        elif tab == TAB_MISPICKS:
            self.query_one("#mispicks-table", DataTable).action_cursor_down()
        self._update_current_detail()

    def _switch_tab(self, tab_id: str) -> None:
        """Switch to a specific tab."""
        self.query_one("#main-tabs", TabbedContent).active = tab_id
        if self.status_bar:
            self.status_bar.set_active_tab(tab_id)
        self._update_current_detail()

    def action_tab_policies(self) -> None:
        """Switch to policies tab."""
        self._switch_tab(TAB_POLICIES)

    def action_tab_resources(self) -> None:
        """Switch to resources tab."""
        self._switch_tab(TAB_RESOURCES)

    def action_tab_mispicks(self) -> None:
        """Switch to mispicks tab."""
        self._switch_tab(TAB_MISPICKS)

    def action_start_tailing(self) -> None:
        """Start tailing logs (only in Mispicks tab)."""
        if self._get_active_tab() != TAB_MISPICKS:
            return

        def update_callback() -> None:
            self.call_after_refresh(self._update_mispicks_table)

        def status_callback(is_running: bool, message: str) -> None:
            if self.status_bar:
                self.status_bar.update_tailing_status(is_running, message)

        self.mispicks_tab.start_tailing(
            self.mesh_adapter, self.namespace_selector, update_callback, status_callback
        )

    def action_stop_tailing(self) -> None:
        """Stop tailing logs (only in Mispicks tab)."""
        if self._get_active_tab() == TAB_MISPICKS:
            self.mispicks_tab.stop_tailing()

    def action_clear_mispicks(self) -> None:
        """Clear errors (only in Mispicks tab)."""
        if self._get_active_tab() == TAB_MISPICKS:
            self.mispicks_tab.clear_errors()
            self._update_mispicks_table()

    async def action_enroll_pod(self) -> None:
        """Enroll selected pod in mesh (only in Resources tab)."""
        if self._get_active_tab() != TAB_RESOURCES:
            return

        resource = self._get_selected_resource()
        if not resource:
            return

        if resource.type != "pod":
            self.app.notify(f"Cannot enroll {resource.type} - only pods can be enrolled", severity="warning", timeout=3)
            return

        if self.mesh_adapter:
            try:
                self.app.notify(f"Enrolling pod {resource.name}...", severity="information", timeout=2)
                success = await self.mesh_adapter.enroll_pod(resource.name, resource.namespace)
                if success:
                    await asyncio.sleep(0.5)
                    await self._refresh_resources()
                    self.app.notify(f"Pod {resource.name} enrolled in mesh", severity="information", timeout=3)
                else:
                    self.app.notify(f"Failed to enroll pod {resource.name}", severity="warning", timeout=5)
            except Exception as e:
                self.app.notify(f"Error: {e!s}", severity="error", timeout=5)

    async def action_unenroll_pod(self) -> None:
        """Unenroll selected pod from mesh (only in Resources tab)."""
        if self._get_active_tab() != TAB_RESOURCES:
            return

        resource = self._get_selected_resource()
        if not resource:
            return

        if resource.type != "pod":
            self.app.notify(f"Cannot unenroll {resource.type} - only pods can be unenrolled", severity="warning", timeout=3)
            return

        # Check if namespace is mesh-enabled
        current_namespace = self._get_current_namespace_obj()
        if current_namespace and self.mesh_adapter and self.mesh_adapter.is_namespace_mesh_enabled(current_namespace):
            self.app.notify("Pod cannot be removed from mesh - entire namespace is enrolled", severity="warning", timeout=5)
            return

        if self.mesh_adapter:
            try:
                self.app.notify(f"Unenrolling pod {resource.name}...", severity="information", timeout=2)
                success = await self.mesh_adapter.unenroll_pod(resource.name, resource.namespace)
                if success:
                    await asyncio.sleep(0.5)
                    await self._refresh_resources()
                    self.app.notify(f"Pod {resource.name} unenrolled from mesh", severity="information", timeout=3)
                else:
                    self.app.notify(f"Failed to unenroll pod {resource.name}", severity="warning", timeout=5)
            except Exception as e:
                self.app.notify(f"Error: {e!s}", severity="error", timeout=5)

    def _get_selected_resource(self) -> ResourceInfo | None:
        """Get currently selected resource."""
        if not self._filtered_resources or self._resource_cursor >= len(self._filtered_resources):
            return None
        return self._filtered_resources[self._resource_cursor]

    async def action_weave_policy(self) -> None:
        """Weave policy from selected error (only in Mispicks tab)."""
        if self._get_active_tab() != TAB_MISPICKS:
            return

        table = self.query_one("#mispicks-table", DataTable)
        if table.cursor_row is None:
            return

        error = self.mispicks_tab.get_error_at_row(table.cursor_row)
        if not error:
            return

        if error.error_type.value == "source_not_on_mesh":
            self.app.notify("Source pod is not enrolled - enroll it first", severity="warning", timeout=5)
            return
        if error.error_type.value != "access_denied":
            self.app.notify(f"Can only weave for access_denied errors, not {error.error_type.value}", severity="warning", timeout=5)
            return

        if self.mesh_adapter:
            try:
                self.app.notify("Weaving policy...", severity="information", timeout=2)
                policy = await self.mesh_adapter.weave_policy(error)
                if policy:
                    policy_type = policy.labels.get("kubeloom.io/policy-type", "unknown")
                    self.app.notify(f"Policy {policy.name} ({policy_type}) woven!", severity="information", timeout=5)
                    await self._refresh_policies()
                else:
                    self.app.notify("Failed to weave policy", severity="warning", timeout=5)
            except Exception as e:
                self.app.notify(f"Error weaving policy: {e!s}", severity="error", timeout=5)

    async def action_unweave_policies(self) -> None:
        """Unweave all kubeloom-managed policies."""
        if not self.mesh_adapter:
            return

        try:
            self.app.notify("Unweaving all kubeloom policies...", severity="information", timeout=2)
            removed_count = await self.mesh_adapter.unweave_policies()

            if removed_count > 0:
                word = "policy" if removed_count == 1 else "policies"
                self.app.notify(f"Removed {removed_count} woven {word}", severity="information", timeout=5)
                await self._refresh_policies()
            else:
                self.app.notify("No woven policies found", severity="information", timeout=3)

        except Exception as e:
            self.app.notify(f"Error unweaving policies: {e!s}", severity="error", timeout=5)

    def action_quit(self) -> None:
        """Quit the application."""
        self.app.exit()

    def action_copy_manifest(self) -> None:
        """Copy manifest to clipboard (only in Policies tab)."""
        if self._get_active_tab() != TAB_POLICIES:
            return

        if not self._filtered_policies or self._policy_cursor >= len(self._filtered_policies):
            return

        policy = self._filtered_policies[self._policy_cursor]
        manifest = policy.raw_manifest or policy.spec

        try:
            manifest_yaml = yaml.dump(manifest, default_flow_style=False, indent=2, sort_keys=False)
            self.app.copy_to_clipboard(manifest_yaml)
            self.app.notify("Manifest copied to clipboard", severity="information", timeout=2)
        except Exception as e:
            self.app.notify(f"Failed to copy: {e!s}", severity="error", timeout=3)

    def action_focus_filter(self) -> None:
        """Focus the filter input for current tab."""
        filter_id = f"#{self._get_active_tab()}-filter"
        self.query_one(filter_id, Input).focus()

    def action_clear_filter(self) -> None:
        """Clear filter and blur input."""
        tab = self._get_active_tab()
        filter_input = self.query_one(f"#{tab}-filter", Input)
        filter_input.value = ""
        filter_input.blur()

        if tab == TAB_POLICIES:
            self._policy_filter = ""
            self._update_policies_list()
        elif tab == TAB_RESOURCES:
            self._resource_filter = ""
            self._run_background(self._update_resources_list())
        elif tab == TAB_MISPICKS:
            self._mispicks_filter = ""
            self._update_mispicks_table()

        self._update_current_detail()

    # ─── Event Handlers ───────────────────────────────────────────────────────

    def on_tabbed_content_tab_activated(self, event: TabbedContent.TabActivated) -> None:
        """Handle tab activation."""
        if self.status_bar:
            self.status_bar.set_active_tab(event.pane.id or TAB_POLICIES)
        self._update_current_detail()

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        """Update detail pane when row is highlighted."""
        self._update_current_detail()

    def on_input_changed(self, event: Input.Changed) -> None:
        """Handle filter input changes."""
        input_id = event.input.id
        if input_id == "policies-filter":
            self._policy_filter = event.value
            self._policy_cursor = 0
            self._update_policies_list()
            self._update_current_detail()
        elif input_id == "resources-filter":
            self._resource_filter = event.value
            self._resource_cursor = 0
            self._run_background(self._update_resources_list())
            self._update_current_detail()
        elif input_id == "mispicks-filter":
            self._mispicks_filter = event.value
            self._update_mispicks_table()
            self._update_current_detail()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle Enter in filter - blur and keep filter active."""
        if event.input.id in ("policies-filter", "resources-filter", "mispicks-filter"):
            event.input.blur()
