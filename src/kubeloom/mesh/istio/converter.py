"""Istio policy converter."""

import contextlib
from datetime import datetime
from typing import Any

from kubeloom.core.models import (
    ActionType,
    AllowedRoute,
    HTTPMethod,
    Policy,
    PolicyAction,
    PolicySource,
    PolicyStatus,
    PolicyTarget,
    PolicyType,
    ServiceMeshType,
)


class IstioConverter:
    """Convert Istio CRD objects to kubeloom Policy objects."""

    def convert_authorization_policy(self, k8s_object: dict[str, Any]) -> Policy:
        """Convert Istio AuthorizationPolicy to Policy."""
        metadata = k8s_object.get("metadata", {})
        spec = k8s_object.get("spec", {})

        policy = Policy(
            name=metadata.get("name", ""),
            namespace=metadata.get("namespace", ""),
            type=PolicyType.AUTHORIZATION_POLICY,
            mesh_type=ServiceMeshType.ISTIO,
            uid=metadata.get("uid"),
            resource_version=metadata.get("resourceVersion"),
            generation=metadata.get("generation"),
            created_at=self._parse_timestamp(metadata.get("creationTimestamp")),
            labels=metadata.get("labels", {}),
            annotations=metadata.get("annotations", {}),
            spec=spec,
            raw_manifest=k8s_object,  # Store complete manifest
            status=PolicyStatus.ACTIVE,  # AuthzPolicies are active when applied
        )

        # Parse selector to targets
        if "selector" in spec:
            target = self._parse_selector(spec["selector"])
            if target:
                policy.targets = [target]

        # Parse targetRefs to targets
        if "targetRefs" in spec:
            targetref_targets = self._parse_target_refs(spec["targetRefs"])
            if targetref_targets:
                if policy.targets:
                    policy.targets.extend(targetref_targets)
                else:
                    policy.targets = targetref_targets

        # Parse rules
        if spec.get("rules"):
            policy.source, policy.allowed_routes = self._parse_authorization_rules(spec["rules"])
        else:
            # No rules means "allow nothing" for ALLOW policies, "deny nothing" for DENY policies
            action_type = ActionType.ALLOW
            if spec.get("action") == "DENY":
                action_type = ActionType.DENY
            elif spec.get("action") == "AUDIT":
                action_type = ActionType.AUDIT

            if action_type == ActionType.ALLOW:
                # Allow-nothing: no rules means no requests match, so all are denied
                policy.allowed_routes = []  # Empty routes means allow nothing
            else:
                # Deny-nothing or audit-nothing: no rules means nothing is denied/audited
                policy.allowed_routes = [AllowedRoute(allow_all=True)]

        # Set action
        action_type = ActionType.ALLOW
        if spec.get("action") == "DENY":
            action_type = ActionType.DENY
        elif spec.get("action") == "AUDIT":
            action_type = ActionType.AUDIT

        policy.action = PolicyAction(type=action_type)

        return policy

    def convert_peer_authentication(self, k8s_object: dict[str, Any]) -> Policy:
        """Convert Istio PeerAuthentication to Policy."""
        metadata = k8s_object.get("metadata", {})
        spec = k8s_object.get("spec", {})

        policy = Policy(
            name=metadata.get("name", ""),
            namespace=metadata.get("namespace", ""),
            type=PolicyType.PEER_AUTHENTICATION,
            mesh_type=ServiceMeshType.ISTIO,
            uid=metadata.get("uid"),
            resource_version=metadata.get("resourceVersion"),
            generation=metadata.get("generation"),
            created_at=self._parse_timestamp(metadata.get("creationTimestamp")),
            labels=metadata.get("labels", {}),
            annotations=metadata.get("annotations", {}),
            spec=spec,
            raw_manifest=k8s_object,  # Store complete manifest
            status=PolicyStatus.ACTIVE,
        )

        # Parse selector to targets
        if "selector" in spec:
            target = self._parse_selector(spec["selector"])
            if target:
                policy.targets = [target]

        # PeerAuth doesn't have traditional routes, but affects all traffic
        policy.action = PolicyAction(type=ActionType.ALLOW)

        return policy

    def convert_virtual_service(self, k8s_object: dict[str, Any]) -> Policy:
        """Convert Istio VirtualService to Policy."""
        metadata = k8s_object.get("metadata", {})
        spec = k8s_object.get("spec", {})

        policy = Policy(
            name=metadata.get("name", ""),
            namespace=metadata.get("namespace", ""),
            type=PolicyType.VIRTUAL_SERVICE,
            mesh_type=ServiceMeshType.ISTIO,
            uid=metadata.get("uid"),
            resource_version=metadata.get("resourceVersion"),
            generation=metadata.get("generation"),
            created_at=self._parse_timestamp(metadata.get("creationTimestamp")),
            labels=metadata.get("labels", {}),
            annotations=metadata.get("annotations", {}),
            spec=spec,
            raw_manifest=k8s_object,  # Store complete manifest
            status=PolicyStatus.ACTIVE,
        )

        # Parse hosts to targets
        if "hosts" in spec:
            target = PolicyTarget(hosts=spec["hosts"])
            policy.targets = [target]

        # Parse HTTP routes
        if "http" in spec:
            policy.allowed_routes = self._parse_http_routes(spec["http"])

        policy.action = PolicyAction(type=ActionType.ALLOW)

        return policy

    def convert_destination_rule(self, k8s_object: dict[str, Any]) -> Policy:
        """Convert Istio DestinationRule to Policy."""
        metadata = k8s_object.get("metadata", {})
        spec = k8s_object.get("spec", {})

        policy = Policy(
            name=metadata.get("name", ""),
            namespace=metadata.get("namespace", ""),
            type=PolicyType.DESTINATION_RULE,
            mesh_type=ServiceMeshType.ISTIO,
            uid=metadata.get("uid"),
            resource_version=metadata.get("resourceVersion"),
            generation=metadata.get("generation"),
            created_at=self._parse_timestamp(metadata.get("creationTimestamp")),
            labels=metadata.get("labels", {}),
            annotations=metadata.get("annotations", {}),
            spec=spec,
            raw_manifest=k8s_object,  # Store complete manifest
            status=PolicyStatus.ACTIVE,
        )

        # Parse host to target
        if "host" in spec:
            target = PolicyTarget(hosts=[spec["host"]])
            policy.targets = [target]

        policy.action = PolicyAction(type=ActionType.ALLOW)

        return policy

    def convert_gateway(self, k8s_object: dict[str, Any]) -> Policy:
        """Convert Istio Gateway to Policy."""
        metadata = k8s_object.get("metadata", {})
        spec = k8s_object.get("spec", {})

        policy = Policy(
            name=metadata.get("name", ""),
            namespace=metadata.get("namespace", ""),
            type=PolicyType.GATEWAY,
            mesh_type=ServiceMeshType.ISTIO,
            uid=metadata.get("uid"),
            resource_version=metadata.get("resourceVersion"),
            generation=metadata.get("generation"),
            created_at=self._parse_timestamp(metadata.get("creationTimestamp")),
            labels=metadata.get("labels", {}),
            annotations=metadata.get("annotations", {}),
            spec=spec,
            raw_manifest=k8s_object,  # Store complete manifest
            status=PolicyStatus.ACTIVE,
        )

        # Parse servers for hosts and ports
        if "servers" in spec:
            hosts = []
            ports = []
            for server in spec["servers"]:
                if "hosts" in server:
                    hosts.extend(server["hosts"])
                if "port" in server and "number" in server["port"]:
                    ports.append(server["port"]["number"])

            if hosts or ports:
                route = AllowedRoute(hosts=hosts, ports=ports)
                policy.allowed_routes = [route]

        policy.action = PolicyAction(type=ActionType.ALLOW)

        return policy

    def _parse_timestamp(self, timestamp_str: str | None) -> datetime | None:
        """Parse Kubernetes timestamp."""
        if not timestamp_str:
            return None
        try:
            return datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        except Exception:
            return None

    def _parse_selector(self, selector: dict[str, Any]) -> PolicyTarget | None:
        """Parse Istio selector to PolicyTarget."""
        if "matchLabels" in selector:
            return PolicyTarget(workload_labels=selector["matchLabels"])
        return None

    def _parse_authorization_rules(self, rules: list[dict[str, Any]]) -> tuple[PolicySource | None, list[AllowedRoute]]:
        """Parse authorization policy rules."""
        source = None
        routes = []

        for rule in rules:
            # Parse 'from' clause
            if "from" in rule and not source:  # Take first source for simplicity
                source = self._parse_authorization_from(rule["from"])

            # Check if this is an empty rule (matches everything)
            if not rule:  # Empty rule {}
                routes.append(AllowedRoute(allow_all=True))
                continue

            # Parse 'to' clause
            if "to" in rule:
                route = self._parse_authorization_to(rule["to"])
                if route:
                    routes.append(route)
                # If _parse_authorization_to returns None, the rule doesn't match anything
            else:
                # No 'to' clause means allow all operations for this rule
                routes.append(AllowedRoute(allow_all=True))

        return source, routes

    def _parse_authorization_from(self, from_list: list[dict[str, Any]]) -> PolicySource | None:
        """Parse authorization 'from' clause."""
        source = PolicySource()

        for from_item in from_list:
            if "source" in from_item:
                src = from_item["source"]

                # Parse principals and extract service accounts
                if "principals" in src:
                    source.principals.extend(src["principals"])
                    # Extract service accounts from principals
                    for principal in src["principals"]:
                        # Format: cluster.local/ns/namespace/sa/service-account-name
                        if "/sa/" in principal:
                            sa_name = principal.split("/sa/")[-1]
                            if sa_name not in source.service_accounts:
                                source.service_accounts.append(sa_name)

                if "namespaces" in src:
                    source.namespaces.extend(src["namespaces"])
                if "ipBlocks" in src:
                    source.ip_blocks.extend(src["ipBlocks"])

                # Parse workload selector (Istio specific)
                if "workloadSelector" in src:
                    workload_selector = src["workloadSelector"]
                    if "matchLabels" in workload_selector:
                        source.workload_labels.update(workload_selector["matchLabels"])

        return source if not source.is_empty() else None

    def _parse_authorization_to(self, to_list: list[dict[str, Any]]) -> AllowedRoute | None:
        """Parse authorization 'to' clause."""
        # Empty 'to' list means no operations specified = allow all operations
        if not to_list:
            return AllowedRoute(allow_all=True)

        # Check if it's an empty operation object (allow all operations)
        if len(to_list) == 1 and not to_list[0]:
            return AllowedRoute(allow_all=True)

        methods = set()
        paths = []
        ports = []
        has_empty_operation = False

        for to_item in to_list:
            if "operation" not in to_item:
                continue

            op = to_item["operation"]
            if not op:  # Empty operation object
                has_empty_operation = True
                continue

            # Parse methods
            methods_result = self._parse_operation_methods(op)
            if methods_result is None:  # Empty methods list means deny all
                return AllowedRoute(deny_all=True)
            methods.update(methods_result)

            # Parse paths
            paths_result = self._parse_operation_paths(op)
            if paths_result is None:  # Empty paths list means deny all
                return AllowedRoute(deny_all=True)
            paths.extend(paths_result)

            # Parse ports
            ports_result = self._parse_operation_ports(op)
            if ports_result is None:  # Empty ports list means deny all
                return AllowedRoute(deny_all=True)
            ports.extend(ports_result)

        # If we had an empty operation, allow all
        if has_empty_operation:
            return AllowedRoute(allow_all=True)

        # If we have specific methods/paths/ports, return them
        if methods or paths or ports:
            return AllowedRoute(methods=methods, paths=paths, ports=ports)

        # If we reach here, allow all
        return AllowedRoute(allow_all=True)

    def _parse_operation_methods(self, operation: dict[str, Any]) -> set[HTTPMethod] | None:
        """
        Parse HTTP methods from operation.

        Returns:
            Set of HTTPMethod objects, empty set if no methods, None if empty list (deny all)
        """
        if "methods" not in operation:
            return set()

        methods_list = operation["methods"]
        if not methods_list:  # Empty methods list means no methods allowed
            return None

        methods = set()
        for method in methods_list:
            with contextlib.suppress(ValueError):
                methods.add(HTTPMethod(method))
        return methods

    def _parse_operation_paths(self, operation: dict[str, Any]) -> list[str] | None:
        """
        Parse paths from operation.

        Returns:
            List of paths, empty list if no paths, None if empty list (deny all)
        """
        if "paths" not in operation:
            return []

        paths_list = operation["paths"]
        if not paths_list:  # Empty paths list means no paths allowed
            return None

        return list(paths_list)

    def _parse_operation_ports(self, operation: dict[str, Any]) -> list[int] | None:
        """
        Parse ports from operation.

        Returns:
            List of ports, empty list if no ports, None if empty list (deny all)
        """
        if "ports" not in operation:
            return []

        ports_list = operation["ports"]
        if not ports_list:  # Empty ports list means no ports allowed
            return None

        return [int(p) for p in ports_list if str(p).isdigit()]

    def _parse_http_routes(self, http_routes: list[dict[str, Any]]) -> list[AllowedRoute]:
        """Parse VirtualService HTTP routes."""
        routes = []

        for route in http_routes:
            if "match" in route:
                for match in route["match"]:
                    allowed_route = AllowedRoute()

                    if "uri" in match:
                        uri_match = match["uri"]
                        if "exact" in uri_match:
                            allowed_route.paths = [uri_match["exact"]]
                        elif "prefix" in uri_match:
                            allowed_route.paths = [uri_match["prefix"] + "*"]
                        elif "regex" in uri_match:
                            allowed_route.paths = [uri_match["regex"]]

                    if "method" in match:
                        method_match = match["method"]
                        if "exact" in method_match:
                            with contextlib.suppress(ValueError):
                                allowed_route.methods = {HTTPMethod(method_match["exact"])}

                    if "headers" in match:
                        allowed_route.headers = {}
                        for header_name, header_match in match["headers"].items():
                            if "exact" in header_match:
                                allowed_route.headers[header_name] = header_match["exact"]

                    routes.append(allowed_route)

        return routes

    def _parse_target_refs(self, target_refs: list[dict[str, Any]]) -> list[PolicyTarget]:
        """Parse Istio targetRefs to PolicyTarget objects."""
        targets = []

        for target_ref in target_refs:
            target = PolicyTarget()

            # Extract kind and name
            kind = target_ref.get("kind", "")
            name = target_ref.get("name", "")

            if kind == "Service" and name:
                target.services = [name]
            elif kind == "Pod" and name:
                target.pods = [name]
            # Add more kinds as needed (Deployment, StatefulSet, etc.)

            if not target.is_empty():
                targets.append(target)

        return targets

    def export_authorization_policy(self, policy: Policy) -> dict[str, Any]:
        """
        Export a Policy object to an Istio AuthorizationPolicy manifest.

        Handles both L4 (ztunnel) and L7 (waypoint) policies:
        - L4: Uses selector with matchLabels
        - L7: Uses targetRefs to target services

        Args:
            policy: Policy object to export

        Returns:
            Dictionary containing the AuthorizationPolicy manifest
        """
        manifest = {
            "apiVersion": "security.istio.io/v1",
            "kind": "AuthorizationPolicy",
            "metadata": {
                "name": policy.name,
                "namespace": policy.namespace,
                "labels": dict(policy.labels) if policy.labels else {},
                "annotations": dict(policy.annotations) if policy.annotations else {},
            },
            "spec": {},
        }

        # Add action
        self._add_action_to_manifest(manifest, policy)

        # Determine if this is L4 or L7 based on labels
        is_l7 = policy.labels.get("kubeloom.io/policy-type") == "l7"

        # Add target - use targetRefs for L7, selector for L4
        self._add_targets_to_manifest(manifest, policy, is_l7)

        # Add rules
        self._add_rules_to_manifest(manifest, policy, is_l7)

        return manifest

    def _add_action_to_manifest(self, manifest: dict[str, Any], policy: Policy) -> None:
        """Add action field to the manifest spec."""
        if not policy.action:
            return

        if policy.action.type == ActionType.DENY:
            manifest["spec"]["action"] = "DENY"
        elif policy.action.type == ActionType.AUDIT:
            manifest["spec"]["action"] = "AUDIT"
        else:
            manifest["spec"]["action"] = "ALLOW"

    def _add_targets_to_manifest(self, manifest: dict[str, Any], policy: Policy, is_l7: bool) -> None:
        """Add target (selector or targetRefs) to the manifest spec."""
        if not policy.targets:
            return

        if is_l7:
            # L7: Use targetRefs to target service
            target_refs = self._build_target_refs(policy.targets)
            if target_refs:
                manifest["spec"]["targetRefs"] = target_refs
        else:
            # L4: Use selector with matchLabels
            if policy.targets[0].workload_labels:
                manifest["spec"]["selector"] = {"matchLabels": dict(policy.targets[0].workload_labels)}

    def _build_target_refs(self, targets: list[PolicyTarget]) -> list[dict[str, Any]]:
        """Build targetRefs array from policy targets."""
        target_refs = []
        for target in targets:
            if target.services:
                for service in target.services:
                    target_refs.append({"kind": "Service", "group": "", "name": service})
        return target_refs

    def _add_rules_to_manifest(self, manifest: dict[str, Any], policy: Policy, is_l7: bool) -> None:
        """Add rules to the manifest spec."""
        rule = {}

        # Add 'from' section if source exists
        if policy.source and not policy.source.is_empty():
            rule["from"] = self._build_from_clause(policy.source)

        # Add 'to' section from allowed_routes
        if policy.allowed_routes:
            to_clause = self._build_to_clause(policy.allowed_routes, is_l7)
            if to_clause is not None:
                rule["to"] = to_clause

        if rule:
            manifest["spec"]["rules"] = [rule]

    def _build_from_clause(self, source: PolicySource) -> list[dict[str, Any]]:
        """Build 'from' clause from policy source."""
        source_item: dict[str, Any] = {"source": {}}

        if source.principals:
            source_item["source"]["principals"] = list(source.principals)
        if source.namespaces:
            source_item["source"]["namespaces"] = list(source.namespaces)
        if source.ip_blocks:
            source_item["source"]["ipBlocks"] = list(source.ip_blocks)

        return [source_item]

    def _build_to_clause(self, allowed_routes: list[AllowedRoute], is_l7: bool) -> list[dict[str, Any]] | None:
        """Build 'to' clause from allowed routes."""
        to_items = []
        has_any_constraints = False

        for route in allowed_routes:
            operation = {}

            # Only add HTTP methods/paths for L7 policies
            if is_l7:
                if route.methods:
                    operation["methods"] = [m.value for m in route.methods]
                    has_any_constraints = True
                if route.paths:
                    operation["paths"] = list(route.paths)
                    has_any_constraints = True

            # Ports can be used in both L4 and L7
            if route.ports:
                operation["ports"] = [str(p) for p in route.ports]
                has_any_constraints = True

            to_items.append({"operation": operation})

        # Only add 'to' clause if there are actual constraints
        # Empty operation {} should omit the 'to' clause entirely (allow all operations)
        if has_any_constraints:
            return to_items

        return None
