"""Core interfaces for kubeloom."""

from abc import ABC, abstractmethod
from collections.abc import AsyncGenerator
from typing import Any

from kubeloom.core.models import AccessError, Cluster, Namespace, Policy, PolicyValidation, ServiceMesh


class MeshAdapter(ABC):
    """Interface for service mesh adapters."""

    @abstractmethod
    async def detect(self) -> ServiceMesh | None:
        """Detect if this service mesh is installed in the cluster."""
        pass

    @abstractmethod
    async def get_policies(self, namespace: str) -> list[Policy]:
        """Get all policies for a namespace."""
        pass

    async def get_authorization_policies(self, namespace: str) -> list[Policy]:
        """Get only authorization policies for a namespace (fast path).

        Default implementation falls back to get_policies().
        Mesh adapters can override for faster queries.
        """
        return await self.get_policies(namespace)

    @abstractmethod
    async def get_policy(self, name: str, namespace: str, policy_type: str) -> Policy | None:
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
    def get_supported_policy_types(self) -> list[str]:
        """Get list of policy types supported by this mesh."""
        pass

    @abstractmethod
    def tail_access_logs(self, namespace: str | None = None) -> AsyncGenerator[AccessError, None]:
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
        ...

    @abstractmethod
    def is_pod_enrolled(self, pod: dict[str, Any], namespace: Namespace) -> bool:
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

    def is_service_waypoint_enrolled(self, service: dict[str, Any]) -> bool:
        """
        Check if a service is enrolled in a waypoint proxy.

        Args:
            service: Service resource as a dictionary

        Returns:
            True if service has a waypoint proxy configured
        """
        return True

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

    @abstractmethod
    async def weave_policy(self, error: AccessError) -> Policy | None:
        """
        Auto-generate a minimal policy to resolve an access error.

        Strategy (mesh-specific):
        - Generate the most minimal policy that can resolve the error
        - For Istio: L7 policy if HTTP details available, L4 policy otherwise
        - Label policy with kubeloom.io/managed=true for tracking

        Args:
            error: AccessError to resolve

        Returns:
            Generated Policy object if successful, None otherwise
        """
        pass

    @abstractmethod
    async def unweave_policies(self, namespace: str | None = None) -> int:
        """
        Remove all kubeloom-managed policies.

        Args:
            namespace: Optional namespace to filter. If None, remove from all namespaces.

        Returns:
            Number of policies removed
        """
        pass

    @abstractmethod
    async def get_woven_policies(self, namespace: str) -> list[Policy]:
        """
        Get all kubeloom-managed (woven) policies in a namespace.

        Args:
            namespace: Namespace to query

        Returns:
            List of woven Policy objects
        """
        pass


class ClusterClient(ABC):
    """Interface for Kubernetes cluster clients."""

    @abstractmethod
    async def get_namespaces(self) -> list[Namespace]:
        """Get all namespaces in the cluster."""
        pass

    @abstractmethod
    async def get_cluster_info(self) -> Cluster:
        """Get cluster information."""
        pass

    @abstractmethod
    async def get_resources(self, api_version: str, kind: str, namespace: str | None = None) -> list[dict[str, Any]]:
        """Get Kubernetes resources of a specific type."""
        pass

    @abstractmethod
    def is_connected(self) -> bool:
        """Check if client is connected to cluster."""
        pass
