"""Base policy models."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from kubeloom.core.models.actions import AllowedRoute, PolicyAction
from kubeloom.core.models.sources import PolicySource, PolicyTarget
from kubeloom.core.models.validation import PolicyConflict, PolicyValidation


class PolicyType(Enum):
    """Supported policy types for Istio and Kubernetes."""

    # Istio Security policies (security.istio.io/v1beta1)
    AUTHORIZATION_POLICY = "AuthorizationPolicy"
    PEER_AUTHENTICATION = "PeerAuthentication"
    REQUEST_AUTHENTICATION = "RequestAuthentication"

    # Istio Networking policies (networking.istio.io/v1beta1)
    VIRTUAL_SERVICE = "VirtualService"
    DESTINATION_RULE = "DestinationRule"
    GATEWAY = "Gateway"
    SERVICE_ENTRY = "ServiceEntry"
    SIDECAR = "Sidecar"
    WORKLOAD_ENTRY = "WorkloadEntry"
    WORKLOAD_GROUP = "WorkloadGroup"
    ENVOY_FILTER = "EnvoyFilter"
    PROXY_CONFIG = "ProxyConfig"

    # Istio Telemetry (telemetry.istio.io/v1alpha1)
    TELEMETRY = "Telemetry"

    # Kubernetes native
    # NETWORK_POLICY = "NetworkPolicy"


class ServiceMeshType(Enum):
    """Supported service mesh types."""

    ISTIO = "istio"
    KUBERNETES = "kubernetes"  # For native NetworkPolicy
    NONE = "none"


class PolicyStatus(Enum):
    """Policy status states."""

    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    ERROR = "ERROR"
    WARNING = "WARNING"
    PENDING = "PENDING"
    UNKNOWN = "UNKNOWN"


@dataclass
class Policy:
    """Core policy model representing a service mesh policy."""

    # Identity
    name: str
    namespace: str
    type: PolicyType
    mesh_type: ServiceMeshType

    # Kubernetes metadata
    uid: str | None = None
    resource_version: str | None = None
    generation: int | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None
    deletion_timestamp: datetime | None = None

    # Kubernetes labels and annotations
    labels: dict[str, str] = field(default_factory=dict)
    annotations: dict[str, str] = field(default_factory=dict)

    # Raw spec for mesh-specific data
    spec: dict[str, Any] = field(default_factory=dict)

    # Complete Kubernetes manifest
    raw_manifest: dict[str, Any] | None = None

    # Status
    status: PolicyStatus = PolicyStatus.UNKNOWN
    status_details: dict[str, Any] = field(default_factory=dict)

    # Traffic control
    source: PolicySource | None = None
    targets: list[PolicyTarget] = field(default_factory=list)
    action: PolicyAction | None = None
    allowed_routes: list[AllowedRoute] = field(default_factory=list)
    denied_routes: list[AllowedRoute] = field(default_factory=list)

    # Analysis results
    affected_workloads: list[str] = field(default_factory=list)
    affected_services: list[str] = field(default_factory=list)
    conflicts: list[PolicyConflict] = field(default_factory=list)
    validation: PolicyValidation | None = None

    # Relationships
    related_policies: list[str] = field(default_factory=list)  # namespace/name format
    depends_on: list[str] = field(default_factory=list)
    referenced_by: list[str] = field(default_factory=list)

    # Metrics
    last_applied_time: datetime | None = None
    apply_count: int = 0
    error_count: int = 0
    last_error_message: str | None = None

    def __hash__(self) -> int:
        """Make Policy hashable for use in sets."""
        return hash(f"{self.namespace}/{self.name}/{self.type.value}")

    def get_full_name(self) -> str:
        """Get fully qualified policy name."""
        return f"{self.namespace}/{self.name}"

    def get_allowed_methods(self) -> set[str]:
        """Get all allowed HTTP methods from all routes."""
        methods: set[str] = set()
        for route in self.allowed_routes:
            methods.update(m.value for m in route.methods)
        return methods

    def get_allowed_paths(self) -> set[str]:
        """Get all allowed paths from all routes."""
        paths = set()
        for route in self.allowed_routes:
            paths.update(route.paths)
        return paths

    def get_allowed_ports(self) -> set[int]:
        """Get all allowed ports from all routes."""
        ports = set()
        for route in self.allowed_routes:
            ports.update(route.ports)
        return ports

    def applies_to_namespace(self, namespace: str) -> bool:
        """Check if this policy applies to a given namespace."""
        if not self.targets:
            return True  # No targets means it applies to all

        return any(target.matches_namespace(namespace) for target in self.targets)

    def applies_to_service(self, service: str, namespace: str) -> bool:
        """Check if this policy applies to a given service."""
        if not self.targets:
            return True

        return any(target.matches_service(service, namespace) for target in self.targets)

    def is_permissive(self) -> bool:
        """Check if policy is overly permissive."""
        # No source restrictions and allows all routes
        no_source = not self.source or self.source.is_empty()
        no_target = not self.targets or all(t.is_empty() for t in self.targets)
        all_routes = not self.allowed_routes or any(r.allow_all for r in self.allowed_routes)

        return no_source and no_target and all_routes

    def has_conflicts(self) -> bool:
        """Check if policy has conflicts."""
        return bool(self.conflicts)

    def has_errors(self) -> bool:
        """Check if policy has validation errors."""
        return bool(self.status == PolicyStatus.ERROR or (self.validation and self.validation.has_errors()))
