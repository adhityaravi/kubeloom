"""Policy analysis service for extracting insights from policies."""

from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass
from ..models import Policy, PolicyTarget, PolicySource, AllowedRoute
from ..interfaces import ClusterClient


@dataclass
class ResourceInfo:
    """Information about a resource that is affected by policies."""

    name: str
    namespace: str
    type: str  # service, pod, statefulset, deployment, etc.
    labels: Dict[str, str]
    service_account: Optional[str] = None

    def __hash__(self) -> int:
        """Make ResourceInfo hashable for use in sets."""
        return hash((self.name, self.namespace, self.type))


@dataclass
class PolicyImpact:
    """Impact of a policy on a resource."""

    policy: Policy
    impact_type: str  # "source", "target", "both"
    allowed_routes: List[AllowedRoute]


@dataclass
class ResourcePolicyAnalysis:
    """Analysis of all policies affecting a resource."""

    resource: ResourceInfo

    # Policies where this resource is a target
    target_policies: List[PolicyImpact]

    # Policies where this resource is a source
    source_policies: List[PolicyImpact]

    # What this resource can reach
    outbound_access: List[Tuple[ResourceInfo, List[AllowedRoute]]]

    # What can reach this resource
    inbound_access: List[Tuple[ResourceInfo, List[AllowedRoute]]]


class PolicyAnalyzer:
    """Service for analyzing policies and their impact on resources."""

    def __init__(self, cluster_client: ClusterClient):
        self.cluster_client = cluster_client

    async def get_all_affected_resources(self, policies: List[Policy]) -> List[ResourceInfo]:
        """Get all resources that are affected by at least one policy."""
        resources = set()

        for policy in policies:
            # Extract resources from targets
            for target in policy.targets:
                target_resources = await self._extract_resources_from_target(target, policy.namespace)
                resources.update(target_resources)

            # Extract resources from sources
            if policy.source:
                source_resources = await self._extract_resources_from_source(policy.source, policy.namespace)
                resources.update(source_resources)

        return list(resources)

    async def _extract_resources_from_target(self, target: PolicyTarget, namespace: str) -> List[ResourceInfo]:
        """Extract resource information from a policy target."""
        resources = []

        # Services - only when explicitly targeted
        for service_name in target.services:
            service_info = await self._get_service_info(service_name, namespace)
            if service_info:
                resources.append(service_info)

        # Pods - explicitly targeted
        for pod_name in target.pods:
            pod_info = await self._get_pod_info(pod_name, namespace)
            if pod_info:
                resources.append(pod_info)

        # Workload labels - only match workloads (pods, statefulsets, deployments), NOT services
        if target.workload_labels:
            labeled_resources = await self._get_workloads_by_labels(target.workload_labels, namespace)
            resources.extend(labeled_resources)

        return resources

    async def _extract_resources_from_source(self, source: PolicySource, namespace: str) -> List[ResourceInfo]:
        """Extract resource information from a policy source."""
        resources = []

        # Service accounts - extract namespace from principals if available
        # Principals format: cluster.local/ns/namespace/sa/service-account-name
        sa_namespaces = {}  # Map SA name to namespace

        if source.principals:
            for principal in source.principals:
                if "/sa/" in principal:
                    parts = principal.split("/")
                    ns_index = -1
                    sa_index = -1
                    for i, part in enumerate(parts):
                        if part == "ns":
                            ns_index = i
                        elif part == "sa":
                            sa_index = i

                    if ns_index >= 0 and sa_index >= 0 and ns_index < sa_index:
                        if ns_index + 1 < len(parts) and sa_index + 1 < len(parts):
                            sa_namespace = parts[ns_index + 1]
                            sa_name = parts[sa_index + 1]
                            sa_namespaces[sa_name] = sa_namespace

        # Get resources for each service account in the correct namespace
        for sa_name in source.service_accounts:
            # Use namespace from principal if available, otherwise use policy namespace
            sa_namespace = sa_namespaces.get(sa_name, namespace)
            sa_resources = await self._get_resources_by_service_account(sa_name, sa_namespace)
            resources.extend(sa_resources)

        # Workload labels - check in source.namespaces if specified, otherwise policy namespace
        if source.workload_labels:
            namespaces_to_check = source.namespaces if source.namespaces else [namespace]
            for ns in namespaces_to_check:
                labeled_resources = await self._get_workloads_by_labels(source.workload_labels, ns)
                resources.extend(labeled_resources)

        return resources

    async def _get_service_info(self, service_name: str, namespace: str) -> Optional[ResourceInfo]:
        """Get information about a service."""
        try:
            services = await self.cluster_client.get_resources("v1", "Service", namespace)
            for service in services:
                if service.get("metadata", {}).get("name") == service_name:
                    return ResourceInfo(
                        name=service_name,
                        namespace=namespace,
                        type="service",
                        labels=service.get("metadata", {}).get("labels", {})
                    )
        except Exception:
            pass
        return None

    async def _get_pod_info(self, pod_name: str, namespace: str) -> Optional[ResourceInfo]:
        """Get information about a pod."""
        try:
            pods = await self.cluster_client.get_resources("v1", "Pod", namespace)
            for pod in pods:
                if pod.get("metadata", {}).get("name") == pod_name:
                    # Get actual service account from spec (snake_case fields from K8s API)
                    sa_name = pod.get("spec", {}).get("service_account_name")
                    if not sa_name:
                        sa_name = pod.get("spec", {}).get("service_account", "default")

                    return ResourceInfo(
                        name=pod_name,
                        namespace=namespace,
                        type="pod",
                        labels=pod.get("metadata", {}).get("labels", {}),
                        service_account=sa_name
                    )
        except Exception:
            pass
        return None

    async def _get_workloads_by_labels(self, labels: Dict[str, str], namespace: str) -> List[ResourceInfo]:
        """Get workloads (pods, statefulsets, deployments) that match the given labels. NOT services."""
        resources = []

        try:
            # Check pods
            pods = await self.cluster_client.get_resources("v1", "Pod", namespace)
            for pod in pods:
                pod_labels = pod.get("metadata", {}).get("labels", {})
                if self._labels_match(labels, pod_labels):
                    pod_name = pod.get("metadata", {}).get("name", "")
                    if pod_name:
                        # Get actual service account from spec (snake_case fields from K8s API)
                        sa_name = pod.get("spec", {}).get("service_account_name")
                        if not sa_name:
                            sa_name = pod.get("spec", {}).get("service_account", "default")

                        resources.append(ResourceInfo(
                            name=pod_name,
                            namespace=namespace,
                            type="pod",
                            labels=pod_labels,
                            service_account=sa_name
                        ))

            # Note: We could also check StatefulSets/Deployments here if needed
            # But typically workload labels target pods directly

        except Exception:
            pass

        return resources

    async def _get_resources_by_labels(self, labels: Dict[str, str], namespace: str) -> List[ResourceInfo]:
        """Get resources that match the given labels."""
        resources = []

        try:
            # Check pods
            pods = await self.cluster_client.get_resources("v1", "Pod", namespace)
            for pod in pods:
                pod_labels = pod.get("metadata", {}).get("labels", {})
                if self._labels_match(labels, pod_labels):
                    pod_name = pod.get("metadata", {}).get("name", "")
                    if pod_name:
                        # Get actual service account from spec (snake_case fields from K8s API)
                        sa_name = pod.get("spec", {}).get("service_account_name")
                        if not sa_name:
                            sa_name = pod.get("spec", {}).get("service_account", "default")

                        resources.append(ResourceInfo(
                            name=pod_name,
                            namespace=namespace,
                            type="pod",
                            labels=pod_labels,
                            service_account=sa_name
                        ))

            # Check services
            services = await self.cluster_client.get_resources("v1", "Service", namespace)
            for service in services:
                service_labels = service.get("metadata", {}).get("labels", {})
                if self._labels_match(labels, service_labels):
                    service_name = service.get("metadata", {}).get("name", "")
                    if service_name:
                        resources.append(ResourceInfo(
                            name=service_name,
                            namespace=namespace,
                            type="service",
                            labels=service_labels
                        ))

        except Exception:
            pass

        return resources

    async def _get_resources_by_service_account(self, sa_name: str, namespace: str) -> List[ResourceInfo]:
        """Get all resources using a specific service account."""
        resources = []

        try:
            # Get pods using this service account
            pods = await self.cluster_client.get_resources("v1", "Pod", namespace)
            for pod in pods:
                # Get actual service account from spec (snake_case fields from K8s API)
                pod_sa = pod.get("spec", {}).get("service_account_name")
                if not pod_sa:
                    pod_sa = pod.get("spec", {}).get("service_account", "default")

                if pod_sa == sa_name:
                    pod_name = pod.get("metadata", {}).get("name", "")
                    if pod_name:
                        resources.append(ResourceInfo(
                            name=pod_name,
                            namespace=namespace,
                            type="pod",
                            labels=pod.get("metadata", {}).get("labels", {}),
                            service_account=sa_name
                        ))

            # Get workload controllers using this service account
            for controller_type in ["StatefulSet", "Deployment", "DaemonSet"]:
                try:
                    controllers = await self.cluster_client.get_resources("apps/v1", controller_type, namespace)
                    for controller in controllers:
                        controller_sa = (controller.get("spec", {})
                                       .get("template", {})
                                       .get("spec", {})
                                       .get("service_account_name", "default"))
                        if controller_sa == sa_name:
                            controller_name = controller.get("metadata", {}).get("name", "")
                            if controller_name:
                                resources.append(ResourceInfo(
                                    name=controller_name,
                                    namespace=namespace,
                                    type=controller_type.lower(),
                                    labels=controller.get("metadata", {}).get("labels", {}),
                                    service_account=sa_name
                                ))
                except Exception:
                    continue

        except Exception:
            pass

        return resources

    def _labels_match(self, required_labels: Dict[str, str], resource_labels: Dict[str, str]) -> bool:
        """Check if resource labels match the required labels."""
        for key, value in required_labels.items():
            if resource_labels.get(key) != value:
                return False
        return True

    async def analyze_resource_policies(self, resource: ResourceInfo, policies: List[Policy]) -> ResourcePolicyAnalysis:
        """Analyze all policies affecting a specific resource."""
        target_policies = []
        source_policies = []

        for policy in policies:
            impact_type = None

            # Check if resource is a target
            if self._is_resource_targeted(resource, policy):
                impact_type = "target"
                target_policies.append(PolicyImpact(
                    policy=policy,
                    impact_type="target",
                    allowed_routes=policy.allowed_routes
                ))

            # Check if resource is a source
            if self._is_resource_source(resource, policy):
                if impact_type == "target":
                    impact_type = "both"
                else:
                    impact_type = "source"
                source_policies.append(PolicyImpact(
                    policy=policy,
                    impact_type="source",
                    allowed_routes=policy.allowed_routes
                ))

        # Calculate outbound and inbound access
        outbound_access = await self._calculate_outbound_access(resource, policies)
        inbound_access = await self._calculate_inbound_access(resource, policies)

        return ResourcePolicyAnalysis(
            resource=resource,
            target_policies=target_policies,
            source_policies=source_policies,
            outbound_access=outbound_access,
            inbound_access=inbound_access
        )

    def _is_resource_targeted(self, resource: ResourceInfo, policy: Policy) -> bool:
        """Check if a resource is targeted by a policy."""
        for target in policy.targets:
            # Check services - only when explicitly in services list
            if resource.type == "service" and resource.name in target.services:
                return True

            # Check pods - explicitly named
            if resource.type == "pod" and resource.name in target.pods:
                return True

            # Check workload labels - only for workload resources, NOT services
            if (target.workload_labels and
                resource.type in ["pod", "statefulset", "deployment", "daemonset", "replicaset"] and
                self._labels_match(target.workload_labels, resource.labels)):
                return True

        return False

    def _is_resource_source(self, resource: ResourceInfo, policy: Policy) -> bool:
        """Check if a resource is a source in a policy."""
        if not policy.source:
            return False

        # Check service accounts (only for workloads that have service accounts)
        if (resource.service_account and
            resource.type in ["pod", "statefulset", "deployment", "daemonset"] and
            resource.service_account in policy.source.service_accounts):
            return True

        # Check workload labels - only for workload resources, NOT services
        if (policy.source.workload_labels and
            resource.type in ["pod", "statefulset", "deployment", "daemonset", "replicaset"] and
            self._labels_match(policy.source.workload_labels, resource.labels)):
            return True

        return False

    async def _calculate_outbound_access(self, resource: ResourceInfo, policies: List[Policy]) -> List[Tuple[ResourceInfo, List[AllowedRoute]]]:
        """Calculate what resources this resource can reach."""
        outbound = {}  # Use dict to aggregate routes per target resource

        for policy in policies:
            # Check if this resource (or its controller) is a source
            is_source = False

            # Direct source check
            if self._is_resource_source(resource, policy):
                is_source = True

            # If resource is a pod, check if its controller has the service account
            elif resource.type == "pod":
                controller_sa = await self._get_pod_controller_service_account(resource)
                if (controller_sa and policy.source and
                    controller_sa in policy.source.service_accounts):
                    is_source = True

            # If resource is a statefulset/deployment, it can act as source
            elif resource.type in ["statefulset", "deployment"] and policy.source:
                if resource.service_account in policy.source.service_accounts:
                    is_source = True

            if is_source:
                # This resource can reach policy targets
                for target in policy.targets:
                    target_resources = await self._extract_resources_from_target(target, policy.namespace)
                    for target_resource in target_resources:
                        key = (target_resource.name, target_resource.namespace, target_resource.type)
                        if key not in outbound:
                            outbound[key] = (target_resource, [])
                        outbound[key][1].extend(policy.allowed_routes)

        return list(outbound.values())

    async def _calculate_inbound_access(self, resource: ResourceInfo, policies: List[Policy]) -> List[Tuple[ResourceInfo, List[AllowedRoute]]]:
        """Calculate what resources can reach this resource."""
        inbound = {}  # Use dict to aggregate routes per source resource

        for policy in policies:
            is_targeted = False

            # Direct target check
            if self._is_resource_targeted(resource, policy):
                is_targeted = True

            # If resource is a pod controlled by StatefulSet/Deployment, check if controller is targeted
            elif resource.type == "pod":
                # Check if any StatefulSet/Deployment that controls this pod is targeted
                controller_targeted = await self._is_pod_controller_targeted(resource, policy)
                if controller_targeted:
                    is_targeted = True

            if is_targeted:
                # Sources can reach this resource
                if policy.source:
                    source_resources = await self._extract_resources_from_source(policy.source, policy.namespace)
                    for source_resource in source_resources:
                        key = (source_resource.name, source_resource.namespace, source_resource.type)
                        if key not in inbound:
                            inbound[key] = (source_resource, [])
                        inbound[key][1].extend(policy.allowed_routes)

        return list(inbound.values())

    async def _is_pod_controller_targeted(self, pod: ResourceInfo, policy: Policy) -> bool:
        """Check if the pod's controller (StatefulSet/Deployment) is targeted by the policy."""
        # Get the pod's controller
        try:
            pods = await self.cluster_client.get_resources("v1", "Pod", pod.namespace)
            for p in pods:
                if p.get("metadata", {}).get("name") == pod.name:
                    owner_refs = p.get("metadata", {}).get("ownerReferences", [])
                    for owner_ref in owner_refs:
                        owner_kind = owner_ref.get("kind", "").lower()
                        owner_name = owner_ref.get("name", "")

                        # Check if this owner is targeted
                        if owner_kind in ["statefulset", "replicaset"]:
                            # Create a temporary resource info for the controller
                            controller_resource = ResourceInfo(
                                name=owner_name,
                                namespace=pod.namespace,
                                type=owner_kind,
                                labels={},  # We could fetch these if needed
                            )
                            if self._is_resource_targeted(controller_resource, policy):
                                return True
        except Exception:
            pass

        return False

    async def _get_pod_controller_service_account(self, pod: ResourceInfo) -> Optional[str]:
        """Get the service account of the pod's controller (StatefulSet/Deployment)."""
        try:
            pods = await self.cluster_client.get_resources("v1", "Pod", pod.namespace)
            for p in pods:
                if p.get("metadata", {}).get("name") == pod.name:
                    owner_refs = p.get("metadata", {}).get("ownerReferences", [])
                    for owner_ref in owner_refs:
                        owner_kind = owner_ref.get("kind", "")
                        owner_name = owner_ref.get("name", "")

                        # Get the controller's service account
                        if owner_kind == "StatefulSet":
                            statefulsets = await self.cluster_client.get_resources(
                                "apps/v1", "StatefulSet", pod.namespace
                            )
                            for ss in statefulsets:
                                if ss.get("metadata", {}).get("name") == owner_name:
                                    return (ss.get("spec", {})
                                          .get("template", {})
                                          .get("spec", {})
                                          .get("service_account_name", "default"))

                        elif owner_kind == "ReplicaSet":
                            # ReplicaSets are usually owned by Deployments, get the deployment
                            replicasets = await self.cluster_client.get_resources(
                                "apps/v1", "ReplicaSet", pod.namespace
                            )
                            for rs in replicasets:
                                if rs.get("metadata", {}).get("name") == owner_name:
                                    # Check for deployment owner
                                    rs_owner_refs = rs.get("metadata", {}).get("ownerReferences", [])
                                    for rs_owner in rs_owner_refs:
                                        if rs_owner.get("kind") == "Deployment":
                                            deployment_name = rs_owner.get("name")
                                            deployments = await self.cluster_client.get_resources(
                                                "apps/v1", "Deployment", pod.namespace
                                            )
                                            for deployment in deployments:
                                                if deployment.get("metadata", {}).get("name") == deployment_name:
                                                    return (deployment.get("spec", {})
                                                          .get("template", {})
                                                          .get("spec", {})
                                                          .get("service_account_name", "default"))
        except Exception:
            pass

        return None