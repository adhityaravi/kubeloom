"""Core interfaces for kubeloom."""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, AsyncIterator

from .models import Policy, Cluster, Namespace, ServiceMesh, PolicyValidation, PolicyConflict, AccessError


class MeshAdapter(ABC):
    """Interface for service mesh adapters."""

    @abstractmethod
    async def detect(self) -> Optional[ServiceMesh]:
        """Detect if this service mesh is installed in the cluster."""
        pass

    @abstractmethod
    async def get_policies(self, namespace: str) -> List[Policy]:
        """Get all policies for a namespace."""
        pass

    @abstractmethod
    async def get_policy(self, name: str, namespace: str, policy_type: str) -> Optional[Policy]:
        """Get a specific policy by name and type."""
        pass

    @abstractmethod
    async def validate_policy(self, policy: Policy) -> PolicyValidation:
        """Validate a policy configuration."""
        pass

    @abstractmethod
    def is_namespace_mesh_enabled(self, namespace: Namespace) -> bool:
        """Check if namespace has this mesh enabled."""
        pass

    @abstractmethod
    def get_supported_policy_types(self) -> List[str]:
        """Get list of policy types supported by this mesh."""
        pass

    @abstractmethod
    async def tail_access_logs(self, namespace: Optional[str] = None) -> AsyncIterator[AccessError]:
        """
        Tail access logs from the mesh and yield parsed access errors.

        This method should:
        - Identify relevant mesh components (e.g., ztunnel, waypoint for Istio)
        - Tail their logs efficiently
        - Parse log entries for access errors
        - Yield AccessError objects as they are detected

        Args:
            namespace: Optional namespace to filter logs. If None, tail all namespaces.

        Yields:
            AccessError objects as they are parsed from logs.
        """
        pass

    @abstractmethod
    def is_pod_enrolled(self, pod: Dict[str, Any], namespace: Namespace) -> bool:
        """
        Check if a pod is enrolled in the service mesh.

        Important: If a namespace is mesh-enabled, it's very likely the pod is enrolled
        (unless the pod explicitly opts out). However, the reverse isn't always true -
        a pod can be enrolled without the namespace being mesh-enabled (pod-level enrollment).

        Args:
            pod: Pod resource as a dictionary
            namespace: Namespace object containing labels and metadata

        Returns:
            True if pod is enrolled in the mesh, False otherwise
        """
        pass

    @abstractmethod
    async def enroll_pod(self, pod_name: str, namespace: str) -> bool:
        """
        Enroll a pod in the service mesh.

        Implementation is mesh-specific. For example:
        - Istio Ambient: Add labels to namespace or pod
        - Istio Sidecar: Add injection annotation to namespace or pod

        Args:
            pod_name: Name of the pod to enroll
            namespace: Namespace containing the pod

        Returns:
            True if enrollment succeeded, False otherwise
        """
        pass

    @abstractmethod
    async def unenroll_pod(self, pod_name: str, namespace: str) -> bool:
        """
        Unenroll a pod from the service mesh.

        Implementation is mesh-specific. For example:
        - Istio Ambient: Remove ambient labels from pod
        - Istio Sidecar: Requires pod restart (not supported)

        Args:
            pod_name: Name of the pod to unenroll
            namespace: Namespace containing the pod

        Returns:
            True if unenrollment succeeded, False otherwise
        """
        pass


class PolicyAnalyzer(ABC):
    """Interface for policy analysis engines."""

    @abstractmethod
    def analyze_policy(self, policy: Policy, cluster: Cluster) -> Policy:
        """Analyze a single policy and populate analysis results."""
        pass

    @abstractmethod
    def find_conflicts(self, policies: List[Policy]) -> List[PolicyConflict]:
        """Find conflicts between policies."""
        pass

    @abstractmethod
    def suggest_improvements(self, policy: Policy) -> List[str]:
        """Suggest improvements for a policy."""
        pass

    @abstractmethod
    def check_security_issues(self, policy: Policy) -> List[str]:
        """Check for security issues in a policy."""
        pass


class PolicyExporter(ABC):
    """Interface for exporting policies to different formats."""

    @abstractmethod
    def export_policies(self, policies: List[Policy], output_path: str) -> None:
        """Export policies to a file."""
        pass

    @abstractmethod
    def get_supported_formats(self) -> List[str]:
        """Get list of supported export formats."""
        pass

    @abstractmethod
    def serialize_policy(self, policy: Policy) -> Dict[str, Any]:
        """Serialize a single policy to a dictionary."""
        pass


class ClusterClient(ABC):
    """Interface for Kubernetes cluster clients."""

    @abstractmethod
    async def get_namespaces(self) -> List[Namespace]:
        """Get all namespaces in the cluster."""
        pass

    @abstractmethod
    async def get_cluster_info(self) -> Cluster:
        """Get cluster information."""
        pass

    @abstractmethod
    async def get_resources(self, api_version: str, kind: str, namespace: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get Kubernetes resources of a specific type."""
        pass

    @abstractmethod
    def is_connected(self) -> bool:
        """Check if client is connected to cluster."""
        pass


class EventListener(ABC):
    """Interface for listening to policy events."""

    @abstractmethod
    async def start_watching(self, namespace: Optional[str] = None) -> None:
        """Start watching for policy changes."""
        pass

    @abstractmethod
    async def stop_watching(self) -> None:
        """Stop watching for policy changes."""
        pass

    @abstractmethod
    def on_policy_created(self, policy: Policy) -> None:
        """Handle policy creation event."""
        pass

    @abstractmethod
    def on_policy_updated(self, old_policy: Policy, new_policy: Policy) -> None:
        """Handle policy update event."""
        pass

    @abstractmethod
    def on_policy_deleted(self, policy: Policy) -> None:
        """Handle policy deletion event."""
        pass