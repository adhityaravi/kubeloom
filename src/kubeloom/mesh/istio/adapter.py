"""Istio service mesh adapter."""

import asyncio
from typing import List, Optional, AsyncIterator

from ...core.interfaces import MeshAdapter
from ...core.models import Policy, ServiceMesh, ServiceMeshType, Namespace, PolicyValidation, PolicyType, AccessError
from ...k8s.client import K8sClient
from .detector import IstioDetector
from .converter import IstioConverter
from .log_parser import IstioLogParser
from .tailer import SmartLogTailer


class IstioAdapter(MeshAdapter):
    """Adapter for Istio service mesh."""

    # Istio policy types and their API details
    POLICY_TYPES = {
        PolicyType.AUTHORIZATION_POLICY: {
            "api_version": "security.istio.io/v1beta1",
            "kind": "AuthorizationPolicy",
        },
        PolicyType.PEER_AUTHENTICATION: {
            "api_version": "security.istio.io/v1beta1",
            "kind": "PeerAuthentication",
        },
        PolicyType.REQUEST_AUTHENTICATION: {
            "api_version": "security.istio.io/v1beta1",
            "kind": "RequestAuthentication",
        },
        PolicyType.VIRTUAL_SERVICE: {
            "api_version": "networking.istio.io/v1beta1",
            "kind": "VirtualService",
        },
        PolicyType.DESTINATION_RULE: {
            "api_version": "networking.istio.io/v1beta1",
            "kind": "DestinationRule",
        },
        PolicyType.GATEWAY: {
            "api_version": "networking.istio.io/v1beta1",
            "kind": "Gateway",
        },
        PolicyType.SERVICE_ENTRY: {
            "api_version": "networking.istio.io/v1beta1",
            "kind": "ServiceEntry",
        },
        PolicyType.SIDECAR: {
            "api_version": "networking.istio.io/v1beta1",
            "kind": "Sidecar",
        },
        PolicyType.WORKLOAD_ENTRY: {
            "api_version": "networking.istio.io/v1beta1",
            "kind": "WorkloadEntry",
        },
        PolicyType.WORKLOAD_GROUP: {
            "api_version": "networking.istio.io/v1beta1",
            "kind": "WorkloadGroup",
        },
        PolicyType.ENVOY_FILTER: {
            "api_version": "networking.istio.io/v1alpha3",
            "kind": "EnvoyFilter",
        },
        PolicyType.PROXY_CONFIG: {
            "api_version": "install.istio.io/v1alpha1",
            "kind": "ProxyConfig",
        },
        PolicyType.TELEMETRY: {
            "api_version": "telemetry.istio.io/v1alpha1",
            "kind": "Telemetry",
        },
    }

    def __init__(self, k8s_client: K8sClient):
        self.k8s_client = k8s_client
        self.detector = IstioDetector(k8s_client)
        self.converter = IstioConverter()
        self.log_parser = IstioLogParser()

    async def detect(self) -> Optional[ServiceMesh]:
        """Detect if Istio is installed in the cluster."""
        return await self.detector.detect()

    async def get_policies(self, namespace: str) -> List[Policy]:
        """Get all Istio policies for a namespace."""
        policies = []

        for policy_type, api_info in self.POLICY_TYPES.items():
            try:
                resources = await self.k8s_client.get_resources(
                    api_version=api_info["api_version"],
                    kind=api_info["kind"],
                    namespace=namespace
                )

                for resource in resources:
                    policy = self._convert_resource_to_policy(resource, policy_type)
                    if policy:
                        policies.append(policy)

            except Exception as e:
                # Log the error but continue with other policy types
                print(f"Failed to load {policy_type.value} policies: {e}")
                continue

        return policies

    async def get_policy(self, name: str, namespace: str, policy_type: str) -> Optional[Policy]:
        """Get a specific policy by name and type."""
        try:
            # Convert string policy type to enum
            policy_type_enum = None
            for pt in PolicyType:
                if pt.value == policy_type:
                    policy_type_enum = pt
                    break

            if not policy_type_enum or policy_type_enum not in self.POLICY_TYPES:
                return None

            api_info = self.POLICY_TYPES[policy_type_enum]
            resources = await self.k8s_client.get_resources(
                api_version=api_info["api_version"],
                kind=api_info["kind"],
                namespace=namespace
            )

            for resource in resources:
                if resource.get("metadata", {}).get("name") == name:
                    return self._convert_resource_to_policy(resource, policy_type_enum)

            return None

        except Exception:
            return None

    async def validate_policy(self, policy: Policy) -> PolicyValidation:
        """Validate a policy configuration."""
        # Basic validation for now
        validation = PolicyValidation(is_valid=True)

        # Check if policy has required fields
        if not policy.name:
            validation.is_valid = False
            validation.errors.append("Policy name is required")

        if not policy.namespace:
            validation.is_valid = False
            validation.errors.append("Policy namespace is required")

        return validation

    def is_namespace_mesh_enabled(self, namespace: Namespace) -> bool:
        """Check if namespace has Istio mesh enabled (sidecar or ambient mode)."""
        return (
            namespace.has_label("istio-injection", "enabled") or  # Sidecar mode
            namespace.has_label("istio.io/rev") or  # Revision-based sidecar mode
            namespace.has_label("istio.io/dataplane-mode", "ambient") or  # Ambient mode
            namespace.mesh_injection_enabled
        )

    def get_supported_policy_types(self) -> List[str]:
        """Get list of policy types supported by Istio."""
        return [pt.value for pt in self.POLICY_TYPES.keys()]

    def _convert_resource_to_policy(self, resource: dict, policy_type: PolicyType) -> Optional[Policy]:
        """Convert a Kubernetes resource to a Policy object."""
        try:
            if policy_type == PolicyType.AUTHORIZATION_POLICY:
                return self.converter.convert_authorization_policy(resource)
            elif policy_type == PolicyType.PEER_AUTHENTICATION:
                return self.converter.convert_peer_authentication(resource)
            elif policy_type == PolicyType.VIRTUAL_SERVICE:
                return self.converter.convert_virtual_service(resource)
            elif policy_type == PolicyType.DESTINATION_RULE:
                return self.converter.convert_destination_rule(resource)
            elif policy_type == PolicyType.GATEWAY:
                return self.converter.convert_gateway(resource)
            else:
                # For other types, create a basic policy with raw spec
                metadata = resource.get("metadata", {})
                return Policy(
                    name=metadata.get("name", ""),
                    namespace=metadata.get("namespace", ""),
                    type=policy_type,
                    mesh_type=ServiceMeshType.ISTIO,
                    spec=resource.get("spec", {}),
                    labels=metadata.get("labels", {}),
                    annotations=metadata.get("annotations", {}),
                    raw_manifest=resource,  # Store complete manifest
                )

        except Exception as e:
            # Log conversion errors with policy details
            metadata = resource.get("metadata", {})
            print(f"Failed to convert {policy_type.value} policy '{metadata.get('name', 'unknown')}': {e}")
            return None

    async def tail_access_logs(self, namespace: Optional[str] = None) -> AsyncIterator[AccessError]:
        """
        Tail access logs from Istio Ambient mesh using smart adaptive strategy.

        This uses SmartLogTailer which:
        - Discovers all ztunnel and waypoint pods across all namespaces
        - Uses adaptive tailing (1min all pods, 5min noisy pods, repeat)
        - Handles pod lifecycle and memory efficiently

        Args:
            namespace: Optional namespace filter (currently unused, always tails all)

        Yields:
            AccessError objects as they are parsed from logs.
        """
        # Create smart tailer
        tailer = SmartLogTailer(self.k8s_client, self.log_parser)

        # Tail with adaptive strategy
        async for error in tailer.tail_with_adaptive_strategy():
            yield error

    def is_pod_enrolled(self, pod: dict, namespace: Namespace) -> bool:
        """
        Check if a pod is enrolled in Istio mesh.

        Logic:
        1. If namespace has istio.io/dataplane-mode=ambient → pod is enrolled (unless pod opts out)
        2. If pod has istio.io/dataplane-mode=ambient → pod is enrolled
        3. If pod has istio-proxy sidecar → pod is enrolled
        4. Pod explicitly opts out with istio.io/dataplane-mode=none

        Args:
            pod: Pod resource dictionary
            namespace: Namespace object

        Returns:
            True if pod is enrolled in mesh
        """
        pod_labels = pod.get("metadata", {}).get("labels", {})
        pod_name = pod.get("metadata", {}).get("name", "")

        # Skip Istio system pods
        if pod_name.startswith("istio-") or pod_name.startswith("ztunnel-"):
            return False

        # Check if pod explicitly opts out
        pod_dataplane_mode = pod_labels.get("istio.io/dataplane-mode")
        if pod_dataplane_mode == "none":
            return False

        # Check namespace-level enrollment (Ambient mode)
        if namespace.has_label("istio.io/dataplane-mode", "ambient"):
            # Namespace is enrolled → pod is enrolled unless it opted out (already checked)
            return True

        # Check pod-level enrollment (Ambient mode)
        if pod_dataplane_mode == "ambient":
            return True

        # Check for sidecar injection (Sidecar mode)
        containers = pod.get("spec", {}).get("containers", [])
        for container in containers:
            if container.get("name") == "istio-proxy":
                return True

        return False

    async def enroll_pod(self, pod_name: str, namespace: str) -> bool:
        """
        Enroll a specific pod in Istio Ambient mesh by labeling it.

        Adds the label istio.io/dataplane-mode=ambient to the pod.
        Also checks if namespace has a waypoint and enrolls pod to use it.

        Args:
            pod_name: Name of the pod to enroll
            namespace: Namespace containing the pod

        Returns:
            True if enrollment succeeded
        """
        try:
            await self.k8s_client._ensure_connected()
            assert self.k8s_client._core_v1 is not None

            # Check if namespace has a waypoint
            waypoint_name = await self._get_namespace_waypoint(namespace)

            # Build labels patch
            labels = {
                "istio.io/dataplane-mode": "ambient"
            }

            # If waypoint exists, add use-waypoint labels
            if waypoint_name:
                labels["istio.io/use-waypoint"] = waypoint_name
                labels["istio.io/use-waypoint-namespace"] = namespace

            # Patch pod to add ambient label (and waypoint if exists)
            patch = {
                "metadata": {
                    "labels": labels
                }
            }

            # Run the synchronous k8s API call in executor
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                lambda: self.k8s_client._core_v1.patch_namespaced_pod(
                    name=pod_name,
                    namespace=namespace,
                    body=patch
                )
            )

            return True

        except Exception as e:
            print(f"Failed to enroll pod {namespace}/{pod_name}: {e}")
            return False

    async def unenroll_pod(self, pod_name: str, namespace: str) -> bool:
        """
        Unenroll a specific pod from Istio Ambient mesh by removing labels.

        Removes the following labels:
        - istio.io/dataplane-mode
        - istio.io/use-waypoint (if present)
        - istio.io/use-waypoint-namespace (if present)

        Args:
            pod_name: Name of the pod to unenroll
            namespace: Namespace containing the pod

        Returns:
            True if unenrollment succeeded
        """
        try:
            await self.k8s_client._ensure_connected()
            assert self.k8s_client._core_v1 is not None

            # Remove Istio labels using JSON Patch
            # Use null to remove labels
            patch = {
                "metadata": {
                    "labels": {
                        "istio.io/dataplane-mode": None,
                        "istio.io/use-waypoint": None,
                        "istio.io/use-waypoint-namespace": None
                    }
                }
            }

            # Run the synchronous k8s API call in executor
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                lambda: self.k8s_client._core_v1.patch_namespaced_pod(
                    name=pod_name,
                    namespace=namespace,
                    body=patch
                )
            )

            return True

        except Exception as e:
            print(f"Failed to unenroll pod {namespace}/{pod_name}: {e}")
            return False

    async def _get_namespace_waypoint(self, namespace: str) -> Optional[str]:
        """
        Check if a waypoint proxy is deployed in the namespace.

        Looks for Gateway resources with gatewayClassName: istio-waypoint.

        Returns:
            Waypoint Gateway name if one exists, None otherwise
        """
        try:
            # Check for Gateway resources with gatewayClassName: istio-waypoint in this namespace
            gateways = await self.k8s_client.get_resources(
                api_version="gateway.networking.k8s.io/v1",
                kind="Gateway",
                namespace=namespace
            )

            for gateway in gateways:
                spec = gateway.get("spec", {})
                if spec.get("gatewayClassName") == "istio-waypoint":
                    return gateway.get("metadata", {}).get("name")

            return None

        except Exception:
            return None