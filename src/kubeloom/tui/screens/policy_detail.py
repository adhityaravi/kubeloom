"""Policy detail screen."""

import yaml
from textual import work
from textual.app import ComposeResult
from textual.containers import Container, VerticalScroll
from textual.widgets import Header, Footer, Static, LoadingIndicator
from textual.screen import Screen
from textual.binding import Binding
from rich.panel import Panel
from rich.syntax import Syntax

from ...core.models import Policy
from ...k8s.client import K8sClient


class PolicyDetailScreen(Screen):
    """Screen for showing policy details."""

    BINDINGS = [
        Binding("escape", "app.pop_screen", "Back"),
    ]

    def __init__(self, policy: Policy, k8s_client: K8sClient = None):
        super().__init__()
        self.policy = policy
        self.k8s_client = k8s_client

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        with VerticalScroll(id="detail-container"):
            yield LoadingIndicator(id="loading")
            yield Static("", id="policy-detail")
        yield Footer()

    def on_mount(self) -> None:
        """Load policy details when screen is mounted."""
        # Hide content initially, show only loading indicator
        self.query_one("#policy-detail", Static).display = False
        # Use call_after_refresh to ensure screen renders before loading
        self.call_after_refresh(self.load_policy_data)

    @work(exclusive=True)
    async def load_policy_data(self) -> None:
        """Load policy data in the background using worker."""
        content = await self._render_policy_detail()

        # Update UI from worker
        self.query_one("#loading", LoadingIndicator).display = False
        policy_widget = self.query_one("#policy-detail", Static)
        policy_widget.update(content)
        policy_widget.display = True

    async def _render_policy_detail(self) -> Panel:
        """Render detailed policy information."""
        source_info = await self._format_source()
        targets_info = await self._format_targets()

        content = f"""[bold]Name:[/bold] {self.policy.name}
[bold]Namespace:[/bold] {self.policy.namespace}
[bold]Type:[/bold] {self.policy.type.value}
[bold]Mesh:[/bold] {self.policy.mesh_type.value}
[bold]Status:[/bold] {self.policy.status.value}
[bold]Created:[/bold] {self.policy.created_at or 'Unknown'}

{self._format_action()}

{source_info}

{targets_info}

{self._format_routes()}

[bold]Labels:[/bold]
{self._format_dict(self.policy.labels)}

[bold]Kubernetes Manifest:[/bold]
[dim]{self._format_yaml(self.policy.raw_manifest or self.policy.spec)}[/dim]
"""
        return Panel(content, title=f"Policy: {self.policy.name}", border_style="cyan")

    def _format_dict(self, d: dict) -> str:
        """Format dictionary for display."""
        if not d:
            return "  None"
        return "\n".join(f"  {k}: {v}" for k, v in d.items())

    def _format_yaml(self, obj) -> str:
        """Format object as YAML."""
        try:
            formatted = yaml.dump(obj, default_flow_style=False, indent=2, sort_keys=False)
            # Add some indentation to align with other content
            lines = formatted.split('\n')
            return '\n'.join(f"  {line}" for line in lines if line.strip())
        except (yaml.YAMLError, TypeError):
            # Fallback if object is not YAML serializable
            return f"  {str(obj)}"

    def _format_action(self) -> str:
        """Format policy action (allow/deny/audit)."""
        if not self.policy.action:
            return "[bold]Action:[/bold] Unknown"

        action_type = self.policy.action.type.value
        color = "green" if action_type == "ALLOW" else "red" if action_type == "DENY" else "yellow"
        return f"[bold]Action:[/bold] [{color}]{action_type}[/{color}]"

    async def _format_source(self) -> str:
        """Format source information as a tree with workload controllers and pods."""
        if not self.policy.source or self.policy.source.is_empty():
            return "[bold]Sources:[/bold] All sources (no restrictions)"

        tree_lines = ["[bold]Sources:[/bold]"]

        # Service Accounts - show tree: SA → Controllers → Pods
        if self.policy.source.service_accounts:
            tree_lines.append("├── Service Accounts")
            for i, sa in enumerate(self.policy.source.service_accounts):
                is_last_sa = i == len(self.policy.source.service_accounts) - 1
                sa_prefix = "└──" if is_last_sa and not any([
                    self.policy.source.workload_labels,
                    self.policy.source.namespaces,
                    self.policy.source.ip_blocks
                ]) else "├──"

                # Extract namespace from principals for this SA
                sa_namespace = self.policy.namespace
                if self.policy.source and self.policy.source.principals:
                    for principal in self.policy.source.principals:
                        if "/sa/" in principal and principal.endswith(f"/sa/{sa}"):
                            parts = principal.split("/")
                            for i, part in enumerate(parts):
                                if part == "ns" and i + 1 < len(parts):
                                    sa_namespace = parts[i + 1]
                                    break
                            break

                tree_lines.append(f"│   {sa_prefix} {sa_namespace}/{sa}")

                # Get controllers and pods for this service account
                controllers_tree = await self._build_service_account_tree(sa, self.policy.namespace)
                for line in controllers_tree:
                    indent = "│       " if not is_last_sa or any([
                        self.policy.source.workload_labels,
                        self.policy.source.namespaces,
                        self.policy.source.ip_blocks
                    ]) else "        "
                    tree_lines.append(f"{indent}{line}")

        # Workload Labels - show tree: Labels → Pods
        if self.policy.source.workload_labels:
            has_more_sections = bool(self.policy.source.namespaces or self.policy.source.ip_blocks)
            tree_lines.append("├── Workload Labels" if has_more_sections else "└── Workload Labels")

            labels_str = ", ".join([f"{k}={v}" for k, v in self.policy.source.workload_labels.items()])
            tree_lines.append(f"│   └── {labels_str}")

            pods = await self._resolve_label_selector_pods(self.policy.source.workload_labels, self.policy.namespace)
            for j, pod in enumerate(pods[:10]):  # Limit to 10 pods
                is_last_pod = j == len(pods) - 1 or j == 9
                pod_prefix = "└──" if is_last_pod else "├──"
                indent = "       " if not has_more_sections else "│       "
                tree_lines.append(f"{indent}{pod_prefix} [green]{self.policy.namespace}/{pod}[/green]")

            if len(pods) > 10:
                indent = "       " if not has_more_sections else "│       "
                tree_lines.append(f"{indent}└── [dim]... and {len(pods) - 10} more pods[/dim]")

        # Other source types
        remaining_sections = []
        if self.policy.source.namespaces:
            remaining_sections.append(("Namespaces", self.policy.source.namespaces))
        if self.policy.source.ip_blocks:
            remaining_sections.append(("IP Blocks", self.policy.source.ip_blocks))

        for i, (section_name, items) in enumerate(remaining_sections):
            is_last_section = i == len(remaining_sections) - 1
            section_prefix = "└──" if is_last_section else "├──"
            tree_lines.append(f"{section_prefix} {section_name}")

            for j, item in enumerate(items):
                is_last_item = j == len(items) - 1
                item_prefix = "└──" if is_last_item else "├──"
                indent = "    " if is_last_section else "│   "
                tree_lines.append(f"{indent}{item_prefix} {item}")

        return "\n".join(tree_lines)

    async def _format_targets(self) -> str:
        """Format target information as a tree with services and pods."""
        if not self.policy.targets:
            return "[bold]Targets:[/bold] All workloads (no restrictions)"

        tree_lines = ["[bold]Targets:[/bold]"]

        for target in self.policy.targets:
            # Count sections in this target
            has_services = bool(target.services)
            has_workload_labels = bool(target.workload_labels)
            has_direct_pods = bool(target.pods)

            sections_count = sum([has_services, has_workload_labels, has_direct_pods])

            # Services - show as endpoints, not pods
            if target.services:
                remaining_sections = sections_count - 1
                service_prefix = "├──" if remaining_sections > 0 else "└──"
                tree_lines.append(f"{service_prefix} Services")

                for i, service in enumerate(target.services):
                    is_last_service = i == len(target.services) - 1
                    service_item_prefix = "└──" if is_last_service else "├──"
                    indent = "│   " if remaining_sections > 0 else "    "
                    tree_lines.append(f"{indent}{service_item_prefix} [blue]{self.policy.namespace}/{service}[/blue]")

                sections_count -= 1

            # Workload Labels - show tree: Labels → Pods
            if target.workload_labels:
                remaining_sections = sections_count - 1
                labels_prefix = "├──" if remaining_sections > 0 else "└──"
                tree_lines.append(f"{labels_prefix} Workload Labels")

                labels_str = ", ".join([f"{k}={v}" for k, v in target.workload_labels.items()])
                indent = "│   " if remaining_sections > 0 else "    "
                tree_lines.append(f"{indent}└── {labels_str}")

                pods = await self._resolve_label_selector_pods(target.workload_labels, self.policy.namespace)
                if pods:
                    for j, pod in enumerate(pods[:10]):  # Limit to 10 pods
                        is_last_pod = j == len(pods) - 1 or j == 9
                        pod_prefix = "└──" if is_last_pod else "├──"
                        pod_indent = f"{indent}    "
                        tree_lines.append(f"{pod_indent}{pod_prefix} [green]{self.policy.namespace}/{pod}[/green]")

                    if len(pods) > 10:
                        pod_indent = f"{indent}    "
                        tree_lines.append(f"{pod_indent}└── [dim]... and {len(pods) - 10} more pods[/dim]")
                else:
                    pod_indent = f"{indent}    "
                    tree_lines.append(f"{pod_indent}└── [red]No pods found[/red]")

                sections_count -= 1

            # Direct Pods
            if target.pods:
                tree_lines.append("└── Direct Pods")
                for i, pod in enumerate(target.pods):
                    is_last_pod = i == len(target.pods) - 1
                    pod_prefix = "└──" if is_last_pod else "├──"
                    tree_lines.append(f"    {pod_prefix} [green]{self.policy.namespace}/{pod}[/green]")

        return "\n".join(tree_lines)

    def _format_routes(self) -> str:
        """Format routes in :port/path format."""
        if not self.policy.allowed_routes:
            # No routes means "allow nothing" for ALLOW policies
            from ...core.models import ActionType
            if self.policy.action and self.policy.action.type == ActionType.ALLOW:
                return "[bold]Routes:[/bold] [red]No routes allowed[/red]"
            else:
                return "[bold]Routes:[/bold] All routes allowed"

        route_parts = []
        for route in self.policy.allowed_routes:
            # Handle special cases first
            if route.deny_all:
                return "[bold]Routes:[/bold] [red]No routes allowed[/red]"
            elif route.allow_all:
                return "[bold]Routes:[/bold] All routes allowed"

            route_strs = []

            # Format as :port/path
            if route.ports and route.paths:
                for port in route.ports:
                    for path in route.paths:
                        route_strs.append(f":{port}{path}")
            elif route.ports:
                for port in route.ports:
                    route_strs.append(f":{port}/*")
            elif route.paths:
                for path in route.paths:
                    route_strs.append(f":*{path}")

            # Add methods if specified
            if route.methods:
                methods = [m.value for m in route.methods if m.value != "*"]
                if methods:
                    method_str = f"Methods: {', '.join(methods)}"
                    route_strs = [f"{r} ({method_str})" for r in route_strs]

            if route_strs:
                route_parts.extend(route_strs)
            else:
                route_parts.append("All routes")

        if route_parts:
            routes_lines = ["[bold]Routes:[/bold]"]
            for route in route_parts:
                routes_lines.append(f"  • {route}")
            return "\n".join(routes_lines)
        else:
            return "[bold]Routes:[/bold] All routes allowed"

    async def _resolve_service_account_pods(self, service_account: str, namespace: str) -> list:
        """Resolve service account to actual pods using it."""
        if not self.k8s_client:
            return []

        try:
            # Extract namespace and service account name from principals if needed
            # Format: cluster.local/ns/namespace/sa/service-account-name
            target_namespace = namespace
            target_sa = service_account

            # Check if we need to extract namespace from principals
            if self.policy.source and self.policy.source.principals:
                for principal in self.policy.source.principals:
                    if "/sa/" in principal and principal.endswith(f"/sa/{service_account}"):
                        # Extract namespace from principal: cluster.local/ns/namespace/sa/service-account-name
                        parts = principal.split("/")

                        # Find the ns and sa positions
                        ns_index = -1
                        sa_index = -1
                        for i, part in enumerate(parts):
                            if part == "ns":
                                ns_index = i
                            elif part == "sa":
                                sa_index = i

                        # Extract namespace if valid format
                        if ns_index >= 0 and sa_index >= 0 and ns_index < sa_index:
                            if ns_index + 1 < len(parts):
                                target_namespace = parts[ns_index + 1]
                                break

            # Get all pods in the target namespace
            pods = await self.k8s_client.get_resources(
                api_version="v1",
                kind="Pod",
                namespace=target_namespace
            )

            matching_pods = []
            for pod in pods:
                pod_sa = pod.get("spec", {}).get("serviceAccountName", "default")
                if pod_sa == target_sa:
                    pod_name = pod.get("metadata", {}).get("name", "")
                    if pod_name:
                        matching_pods.append(pod_name)

            return matching_pods
        except Exception:
            return []

    async def _resolve_label_selector_pods(self, labels: dict, namespace: str) -> list:
        """Resolve label selector to actual pods matching it."""
        if not self.k8s_client:
            return []

        try:
            # Get all pods in the namespace
            pods = await self.k8s_client.get_resources(
                api_version="v1",
                kind="Pod",
                namespace=namespace
            )

            matching_pods = []
            for pod in pods:
                pod_labels = pod.get("metadata", {}).get("labels", {})
                pod_name = pod.get("metadata", {}).get("name", "")

                # Check if all selector labels match
                if all(pod_labels.get(k) == v for k, v in labels.items()):
                    if pod_name:
                        matching_pods.append(pod_name)
            return matching_pods
        except Exception:
            return []

    async def _resolve_service_pods(self, service: str, namespace: str) -> list:
        """Resolve service to actual pods behind it."""
        if not self.k8s_client:
            return []

        try:
            # Get the service
            services = await self.k8s_client.get_resources(
                api_version="v1",
                kind="Service",
                namespace=namespace
            )

            service_selector = None
            for svc in services:
                if svc.get("metadata", {}).get("name") == service:
                    service_selector = svc.get("spec", {}).get("selector", {})
                    break

            if service_selector:
                return await self._resolve_label_selector_pods(service_selector, namespace)

            return []
        except Exception:
            return []

    async def _build_service_account_tree(self, service_account: str, namespace: str) -> list[str]:
        """Build a tree showing controllers and pods for a service account."""
        if not self.k8s_client:
            return ["└── ❌ No Kubernetes client available"]

        try:
            tree_lines = []

            # Extract namespace and service account name from principals if needed
            target_namespace = namespace
            target_sa = service_account

            # Check if we need to extract namespace from principals
            if self.policy.source and self.policy.source.principals:
                for principal in self.policy.source.principals:
                    if "/sa/" in principal and principal.endswith(f"/sa/{service_account}"):
                        parts = principal.split("/")
                        ns_index = -1
                        sa_index = -1
                        for i, part in enumerate(parts):
                            if part == "ns":
                                ns_index = i
                            elif part == "sa":
                                sa_index = i

                        if ns_index >= 0 and sa_index >= 0 and ns_index < sa_index:
                            if ns_index + 1 < len(parts):
                                target_namespace = parts[ns_index + 1]
                                break

            # Get workload controllers in the target namespace
            controllers = await self._get_workload_controllers(target_namespace)

            # Group controllers by those that use this service account
            controllers_using_sa = []
            for controller in controllers:
                controller_sa = controller.get("serviceAccountName", "default")
                if controller_sa == target_sa:
                    controllers_using_sa.append(controller)

            # Get all pods in the target namespace
            pods = await self.k8s_client.get_resources(
                api_version="v1",
                kind="Pod",
                namespace=target_namespace
            )

            # Build the tree
            if controllers_using_sa:
                for i, controller in enumerate(controllers_using_sa):
                    is_last_controller = i == len(controllers_using_sa) - 1
                    controller_prefix = "└──" if is_last_controller else "├──"

                    controller_name = controller["name"]
                    controller_type = controller["type"]

                    tree_lines.append(f"{controller_prefix} {controller_type}: {target_namespace}/{controller_name}")

                    # Find pods managed by this controller
                    managed_pods = self._find_pods_for_controller(pods, controller)

                    if managed_pods:
                        for j, pod_info in enumerate(managed_pods):
                            is_last_pod = j == len(managed_pods) - 1
                            pod_prefix = "└──" if is_last_pod else "├──"
                            controller_indent = "    " if is_last_controller else "│   "

                            pod_name, actual_sa, matches = pod_info
                            if matches:
                                status_text = f"[green]{target_namespace}/{pod_name}[/green]"
                            else:
                                status_text = f"[red]{target_namespace}/{pod_name}[/red]"

                            tree_lines.append(f"{controller_indent}{pod_prefix} {status_text}")
                    else:
                        controller_indent = "    " if is_last_controller else "│   "
                        tree_lines.append(f"{controller_indent}└── [red]No pods found[/red]")

            else:
                # Check if any pods directly use this service account (not managed by controllers)
                direct_pods = []
                for pod in pods:
                    pod_sa = pod.get("spec", {}).get("serviceAccountName", "default")
                    if pod_sa == target_sa:
                        pod_name = pod.get("metadata", {}).get("name", "")
                        if pod_name:
                            # Check if this pod is managed by a controller we didn't find
                            owner_refs = pod.get("metadata", {}).get("ownerReferences", [])
                            if not owner_refs:
                                direct_pods.append(pod_name)

                if direct_pods:
                    tree_lines.append("└── Direct Pods:")
                    for i, pod_name in enumerate(direct_pods):
                        is_last = i == len(direct_pods) - 1
                        pod_prefix = "└──" if is_last else "├──"
                        tree_lines.append(f"    {pod_prefix} [green]{target_namespace}/{pod_name}[/green]")
                else:
                    tree_lines.append("└── [red]No controllers or pods use this service account[/red]")

            return tree_lines

        except Exception as e:
            return [f"└── [red]Error resolving service account: {str(e)}[/red]"]

    async def _get_workload_controllers(self, namespace: str) -> list[dict]:
        """Get all workload controllers (StatefulSets, Deployments, etc.) in a namespace."""
        if not self.k8s_client:
            return []

        controllers = []

        try:
            # Get StatefulSets
            statefulsets = await self.k8s_client.get_resources(
                api_version="apps/v1",
                kind="StatefulSet",
                namespace=namespace
            )
            for ss in statefulsets:
                name = ss.get("metadata", {}).get("name", "unknown")
                sa = ss.get("spec", {}).get("template", {}).get("spec", {}).get("serviceAccountName", "default")
                controllers.append({
                    "name": name,
                    "type": "StatefulSet",
                    "serviceAccountName": sa,
                    "selector": ss.get("spec", {}).get("selector", {}).get("matchLabels", {}),
                    "kind": "StatefulSet"
                })

            # Get Deployments
            deployments = await self.k8s_client.get_resources(
                api_version="apps/v1",
                kind="Deployment",
                namespace=namespace
            )
            for deploy in deployments:
                name = deploy.get("metadata", {}).get("name", "unknown")
                sa = deploy.get("spec", {}).get("template", {}).get("spec", {}).get("serviceAccountName", "default")
                controllers.append({
                    "name": name,
                    "type": "Deployment",
                    "serviceAccountName": sa,
                    "selector": deploy.get("spec", {}).get("selector", {}).get("matchLabels", {}),
                    "kind": "Deployment"
                })

            # Get DaemonSets
            daemonsets = await self.k8s_client.get_resources(
                api_version="apps/v1",
                kind="DaemonSet",
                namespace=namespace
            )
            for ds in daemonsets:
                name = ds.get("metadata", {}).get("name", "unknown")
                sa = ds.get("spec", {}).get("template", {}).get("spec", {}).get("serviceAccountName", "default")
                controllers.append({
                    "name": name,
                    "type": "DaemonSet",
                    "serviceAccountName": sa,
                    "selector": ds.get("spec", {}).get("selector", {}).get("matchLabels", {}),
                    "kind": "DaemonSet"
                })

        except Exception:
            pass

        return controllers

    def _find_pods_for_controller(self, pods: list, controller: dict) -> list[tuple[str, str, bool]]:
        """Find pods managed by a controller and check if they use the expected service account."""
        managed_pods = []
        controller_name = controller["name"]
        controller_type = controller["kind"]
        expected_sa = controller["serviceAccountName"]

        for pod in pods:
            pod_name = pod.get("metadata", {}).get("name", "")

            # Check if pod is managed by this controller
            is_managed = False

            if controller_type == "StatefulSet":
                # StatefulSet pods follow pattern: <name>-<ordinal>
                if pod_name.startswith(f"{controller_name}-") and pod_name[len(controller_name)+1:].isdigit():
                    is_managed = True
            else:
                # For Deployments and DaemonSets, check owner references or labels
                owner_refs = pod.get("metadata", {}).get("ownerReferences", [])
                for owner in owner_refs:
                    if owner.get("name") == controller_name and owner.get("kind") in ["ReplicaSet", "DaemonSet"]:
                        is_managed = True
                        break

                # Also check labels if owner reference doesn't match directly
                if not is_managed:
                    pod_labels = pod.get("metadata", {}).get("labels", {})
                    controller_selector = controller.get("selector", {})
                    if controller_selector and all(pod_labels.get(k) == v for k, v in controller_selector.items()):
                        is_managed = True

            if is_managed:
                actual_sa = pod.get("spec", {}).get("serviceAccountName", "default")
                matches = actual_sa == expected_sa
                managed_pods.append((pod_name, actual_sa, matches))

        return managed_pods