"""Cluster and namespace models."""

from dataclasses import dataclass, field

from kubeloom.core.models.base import Policy, PolicyStatus, PolicyType, ServiceMeshType


@dataclass
class ServiceMesh:
    """Represents a service mesh installation."""

    type: ServiceMeshType
    version: str
    namespace: str  # Control plane namespace
    revision: str | None = None  # For versioned deployments

    # Control plane status
    control_plane_ready: bool = False
    data_plane_ready: bool = False

    # Mesh configuration
    mtls_mode: str | None = None  # Implementation-specific values
    default_injection: bool = False
    telemetry_enabled: bool = False

    # Proxy statistics
    total_proxies: int = 0
    connected_proxies: int = 0

    # Observability addons
    prometheus_enabled: bool = False
    grafana_enabled: bool = False
    jaeger_enabled: bool = False
    kiali_enabled: bool = False

    def is_healthy(self) -> bool:
        """Check if mesh control plane is healthy."""
        return self.control_plane_ready and self.data_plane_ready


@dataclass
class Namespace:
    """Represents a Kubernetes namespace with service mesh policies."""

    name: str
    labels: dict[str, str] = field(default_factory=dict)
    annotations: dict[str, str] = field(default_factory=dict)

    # Service mesh configuration (populated by mesh adapters)
    mesh_injection_enabled: bool = False
    mesh_revision: str | None = None
    mesh_type: ServiceMeshType | None = None

    # Policies
    policies: list[Policy] = field(default_factory=list)
    policy_count_by_type: dict[PolicyType, int] = field(default_factory=dict)

    # Stats
    total_policies: int = 0
    active_policies: int = 0
    conflicting_policies: int = 0

    # Workloads
    deployments_count: int = 0
    services_count: int = 0
    pods_with_sidecar: int = 0
    pods_without_sidecar: int = 0

    def add_policy(self, policy: Policy) -> None:
        """Add a policy to the namespace."""
        self.policies.append(policy)
        self.total_policies += 1

        if policy.status == PolicyStatus.ACTIVE:
            self.active_policies += 1

        if policy.conflicts:
            self.conflicting_policies += 1

        # Update type count
        if policy.type not in self.policy_count_by_type:
            self.policy_count_by_type[policy.type] = 0
        self.policy_count_by_type[policy.type] += 1

    def get_policies_by_type(self, policy_type: PolicyType) -> list[Policy]:
        """Get all policies of a specific type."""
        return [p for p in self.policies if p.type == policy_type]

    def has_label(self, key: str, value: str | None = None) -> bool:
        """Check if namespace has a specific label."""
        if value is None:
            return key in self.labels
        return self.labels.get(key) == value

    def has_annotation(self, key: str, value: str | None = None) -> bool:
        """Check if namespace has a specific annotation."""
        if value is None:
            return key in self.annotations
        return self.annotations.get(key) == value


@dataclass
class Cluster:
    """Represents a Kubernetes cluster with service mesh capabilities."""

    name: str
    context: str
    api_server: str

    # Kubernetes info
    kubernetes_version: str = ""
    platform: str | None = None  # GKE, EKS, AKS, OpenShift, etc.

    # Cluster size
    nodes_count: int = 0
    namespaces_count: int = 0

    # Service mesh
    service_mesh: ServiceMesh | None = None

    # Namespaces
    namespaces: list[Namespace] = field(default_factory=list)

    # Global policy stats
    policy_counts: dict[PolicyType, int] = field(default_factory=dict)

    def get_namespace(self, name: str) -> Namespace | None:
        """Get a namespace by name."""
        for ns in self.namespaces:
            if ns.name == name:
                return ns
        return None

    def get_mesh_enabled_namespaces(self) -> list[Namespace]:
        """Get all namespaces with service mesh injection enabled."""
        return [ns for ns in self.namespaces if ns.mesh_injection_enabled]

    def get_all_policies(self) -> list[Policy]:
        """Get all policies across all namespaces."""
        policies = []
        for ns in self.namespaces:
            policies.extend(ns.policies)
        return policies

    def count_policies_by_type(self) -> dict[PolicyType, int]:
        """Count all policies by type across the cluster."""
        counts: dict[PolicyType, int] = {}
        for ns in self.namespaces:
            for policy_type, count in ns.policy_count_by_type.items():
                if policy_type not in counts:
                    counts[policy_type] = 0
                counts[policy_type] += count
        return counts

    def has_service_mesh(self) -> bool:
        """Check if cluster has a service mesh installed."""
        return self.service_mesh is not None and self.service_mesh.is_healthy()

    def get_total_policies(self) -> int:
        """Get total number of policies across all namespaces."""
        return sum(ns.total_policies for ns in self.namespaces)

    def get_namespaces_with_policies(self) -> list[Namespace]:
        """Get namespaces that have at least one policy."""
        return [ns for ns in self.namespaces if ns.total_policies > 0]
