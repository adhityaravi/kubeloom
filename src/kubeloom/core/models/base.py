"""Base policy models."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set

from .actions import AllowedRoute, PolicyAction
from .sources import PolicySource, PolicyTarget
from .validation import PolicyConflict, PolicyValidation


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
    uid: Optional[str] = None
    resource_version: Optional[str] = None
    generation: Optional[int] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    deletion_timestamp: Optional[datetime] = None

    # Kubernetes labels and annotations
    labels: Dict[str, str] = field(default_factory=dict)
    annotations: Dict[str, str] = field(default_factory=dict)

    # Raw spec for mesh-specific data
    spec: Dict[str, Any] = field(default_factory=dict)

    # Complete Kubernetes manifest
    raw_manifest: Optional[Dict[str, Any]] = None

    # Status
    status: PolicyStatus = PolicyStatus.UNKNOWN
    status_details: Dict[str, Any] = field(default_factory=dict)

    # Traffic control
    source: Optional[PolicySource] = None
    targets: List[PolicyTarget] = field(default_factory=list)
    action: Optional[PolicyAction] = None
    allowed_routes: List[AllowedRoute] = field(default_factory=list)
    denied_routes: List[AllowedRoute] = field(default_factory=list)

    # Analysis results
    affected_workloads: List[str] = field(default_factory=list)
    affected_services: List[str] = field(default_factory=list)
    conflicts: List[PolicyConflict] = field(default_factory=list)
    validation: Optional[PolicyValidation] = None

    # Relationships
    related_policies: List[str] = field(default_factory=list)  # namespace/name format
    depends_on: List[str] = field(default_factory=list)
    referenced_by: List[str] = field(default_factory=list)

    # Metrics
    last_applied_time: Optional[datetime] = None
    apply_count: int = 0
    error_count: int = 0
    last_error_message: Optional[str] = None

    def __hash__(self) -> int:
        """Make Policy hashable for use in sets."""
        return hash(f"{self.namespace}/{self.name}/{self.type.value}")

    def get_full_name(self) -> str:
        """Get fully qualified policy name."""
        return f"{self.namespace}/{self.name}"

    def get_allowed_methods(self) -> Set[str]:
        """Get all allowed HTTP methods from all routes."""
        methods = set()
        for route in self.allowed_routes:
            methods.update(m.value for m in route.methods)
        return methods

    def get_allowed_paths(self) -> Set[str]:
        """Get all allowed paths from all routes."""
        paths = set()
        for route in self.allowed_routes:
            paths.update(route.paths)
        return paths

    def get_allowed_ports(self) -> Set[int]:
        """Get all allowed ports from all routes."""
        ports = set()
        for route in self.allowed_routes:
            ports.update(route.ports)
        return ports

    def applies_to_namespace(self, namespace: str) -> bool:
        """Check if this policy applies to a given namespace."""
        if not self.targets:
            return True  # No targets means it applies to all

        for target in self.targets:
            if target.matches_namespace(namespace):
                return True
        return False

    def applies_to_service(self, service: str, namespace: str) -> bool:
        """Check if this policy applies to a given service."""
        if not self.targets:
            return True

        for target in self.targets:
            if target.matches_service(service, namespace):
                return True
        return False

    def is_permissive(self) -> bool:
        """Check if policy is overly permissive."""
        # No source restrictions and allows all routes
        no_source = not self.source or self.source.is_empty()
        no_target = not self.targets or all(t.is_empty() for t in self.targets)
        all_routes = not self.allowed_routes or any(r.matches_all() for r in self.allowed_routes)

        return no_source and no_target and all_routes

    def has_conflicts(self) -> bool:
        """Check if policy has conflicts."""
        return bool(self.conflicts)

    def has_errors(self) -> bool:
        """Check if policy has validation errors."""
        return (
            self.status == PolicyStatus.ERROR or
            (self.validation and self.validation.has_errors())
        )
