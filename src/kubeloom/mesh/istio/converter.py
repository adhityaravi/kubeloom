"""Istio policy converter."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from ...core.models import (
    Policy, PolicyType, ServiceMeshType, PolicyStatus,
    PolicySource, PolicyTarget, AllowedRoute, HTTPMethod, PolicyAction, ActionType
)


class IstioConverter:
    """Convert Istio CRD objects to kubeloom Policy objects."""

    def convert_authorization_policy(self, k8s_object: Dict[str, Any]) -> Policy:
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
        if "rules" in spec and spec["rules"]:
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

    def convert_peer_authentication(self, k8s_object: Dict[str, Any]) -> Policy:
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

    def convert_virtual_service(self, k8s_object: Dict[str, Any]) -> Policy:
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

    def convert_destination_rule(self, k8s_object: Dict[str, Any]) -> Policy:
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

    def convert_gateway(self, k8s_object: Dict[str, Any]) -> Policy:
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

    def _parse_timestamp(self, timestamp_str: Optional[str]) -> Optional[datetime]:
        """Parse Kubernetes timestamp."""
        if not timestamp_str:
            return None
        try:
            return datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        except Exception:
            return None

    def _parse_selector(self, selector: Dict[str, Any]) -> Optional[PolicyTarget]:
        """Parse Istio selector to PolicyTarget."""
        if "matchLabels" in selector:
            return PolicyTarget(workload_labels=selector["matchLabels"])
        return None

    def _parse_authorization_rules(self, rules: List[Dict[str, Any]]) -> tuple[Optional[PolicySource], List[AllowedRoute]]:
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

    def _parse_authorization_from(self, from_list: List[Dict[str, Any]]) -> Optional[PolicySource]:
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

    def _parse_authorization_to(self, to_list: List[Dict[str, Any]]) -> Optional[AllowedRoute]:
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
            if "operation" in to_item:
                op = to_item["operation"]
                if not op:  # Empty operation object
                    has_empty_operation = True
                    continue

                if "methods" in op:
                    methods_list = op["methods"]
                    if not methods_list:  # Empty methods list means no methods allowed
                        return AllowedRoute(deny_all=True)
                    for method in methods_list:
                        try:
                            methods.add(HTTPMethod(method))
                        except ValueError:
                            pass  # Skip unknown methods

                if "paths" in op:
                    paths_list = op["paths"]
                    if not paths_list:  # Empty paths list means no paths allowed
                        return AllowedRoute(deny_all=True)
                    paths.extend(paths_list)

                if "ports" in op:
                    ports_list = op["ports"]
                    if not ports_list:  # Empty ports list means no ports allowed
                        return AllowedRoute(deny_all=True)
                    ports.extend([int(p) for p in ports_list if str(p).isdigit()])

        # If we had an empty operation, allow all
        if has_empty_operation:
            return AllowedRoute(allow_all=True)

        # If we have specific methods/paths/ports, return them
        if methods or paths or ports:
            return AllowedRoute(methods=methods, paths=paths, ports=ports)

        # If we had operations but they were all empty lists, deny all was already returned above
        # If we reach here, allow all
        return AllowedRoute(allow_all=True)

    def _parse_http_routes(self, http_routes: List[Dict[str, Any]]) -> List[AllowedRoute]:
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
                            try:
                                allowed_route.methods = {HTTPMethod(method_match["exact"])}
                            except ValueError:
                                pass

                    if "headers" in match:
                        allowed_route.headers = {}
                        for header_name, header_match in match["headers"].items():
                            if "exact" in header_match:
                                allowed_route.headers[header_name] = header_match["exact"]

                    routes.append(allowed_route)

        return routes

    def _parse_target_refs(self, target_refs: List[Dict[str, Any]]) -> List[PolicyTarget]:
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