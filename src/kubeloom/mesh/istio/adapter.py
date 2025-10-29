"""Istio service mesh adapter."""

import logging
from collections.abc import AsyncGenerator
from typing import Any, ClassVar

from kubeloom.core.interfaces import MeshAdapter
from kubeloom.core.models import (
    AccessError,
    Namespace,
    Policy,
    PolicyType,
    PolicyValidation,
    ServiceMesh,
    ServiceMeshType,
)
from kubeloom.core.models.validation import ValidationError
from kubeloom.k8s.client import K8sClient
from kubeloom.mesh.istio.converter import IstioConverter
from kubeloom.mesh.istio.detector import IstioDetector
from kubeloom.mesh.istio.log_parser import IstioLogParser
from kubeloom.mesh.istio.tailer import SmartLogTailer
from kubeloom.mesh.istio.weaver import IstioPolicyWeaver

# Set up logging to file
logging.basicConfig(
    filename="/tmp/kubeloom-weave.log", level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s"
)


class IstioAdapter(MeshAdapter):
    """Adapter for Istio service mesh."""

    # Istio policy types and their API details
    POLICY_TYPES: ClassVar[dict[PolicyType, dict[str, str]]] = {
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
        self.weaver = IstioPolicyWeaver(k8s_client)

    async def detect(self) -> ServiceMesh | None:
        """Detect if Istio is installed in the cluster."""
        return await self.detector.detect()

    async def get_policies(self, namespace: str) -> list[Policy]:
        """Get all Istio policies for a namespace."""
        policies = []

        for policy_type, api_info in self.POLICY_TYPES.items():
            try:
                resources = await self.k8s_client.get_resources(
                    api_version=api_info["api_version"], kind=api_info["kind"], namespace=namespace
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

    async def get_policy(self, name: str, namespace: str, policy_type: str) -> Policy | None:
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
                api_version=api_info["api_version"], kind=api_info["kind"], namespace=namespace
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
            validation.errors.append(ValidationError(field="name", message="Policy name is required"))

        if not policy.namespace:
            validation.is_valid = False
            validation.errors.append(ValidationError(field="namespace", message="Policy namespace is required"))

        return validation

    def is_namespace_mesh_enabled(self, namespace: Namespace) -> bool:
        """Check if namespace has Istio mesh enabled (sidecar or ambient mode)."""
        return (
            namespace.has_label("istio-injection", "enabled")  # Sidecar mode
            or namespace.has_label("istio.io/rev")  # Revision-based sidecar mode
            or namespace.has_label("istio.io/dataplane-mode", "ambient")  # Ambient mode
            or namespace.mesh_injection_enabled
        )

    def get_supported_policy_types(self) -> list[str]:
        """Get list of policy types supported by Istio."""
        return [pt.value for pt in self.POLICY_TYPES]

    def _convert_resource_to_policy(self, resource: dict[str, Any], policy_type: PolicyType) -> Policy | None:
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

    async def tail_access_logs(self, namespace: str | None = None) -> AsyncGenerator[AccessError, None]:
        """
        Tail access logs from Istio Ambient mesh using smart adaptive strategy.

        This uses SmartLogTailer which:
        - Discovers all ztunnel and waypoint pods across all namespaces
        - Uses adaptive tailing (1min all pods, 5min noisy pods, repeat)
        - Handles pod lifecycle and memory efficiently
        - Enriches errors by resolving source IPs and checking mesh enrollment

        Args:
            namespace: Optional namespace filter (currently unused, always tails all)

        Yields:
            AccessError objects as they are parsed from logs.
        """
        # Create smart tailer with mesh adapter for enrollment checks
        tailer = SmartLogTailer(self.k8s_client, self.log_parser, mesh_adapter=self)

        # Tail with adaptive strategy
        async for error in tailer.tail_with_adaptive_strategy():
            yield error

    def is_pod_enrolled(self, pod: dict[str, Any], namespace: Namespace) -> bool:
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
        return any(container.get("name") == "istio-proxy" for container in containers)

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
            # Check if namespace has a waypoint
            waypoint_name = await self._get_namespace_waypoint(namespace)

            # Build labels patch
            labels = {"istio.io/dataplane-mode": "ambient"}

            # If waypoint exists, add use-waypoint labels
            if waypoint_name:
                labels["istio.io/use-waypoint"] = waypoint_name
                labels["istio.io/use-waypoint-namespace"] = namespace

            # Patch pod to add ambient label (and waypoint if exists)
            patch = {"metadata": {"labels": labels}}

            await self.k8s_client.patch_pod(name=pod_name, namespace=namespace, body=patch)

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
            # Remove Istio labels using JSON Patch
            # Use null to remove labels
            patch = {
                "metadata": {
                    "labels": {
                        "istio.io/dataplane-mode": None,
                        "istio.io/use-waypoint": None,
                        "istio.io/use-waypoint-namespace": None,
                    }
                }
            }

            await self.k8s_client.patch_pod(name=pod_name, namespace=namespace, body=patch)

            return True

        except Exception as e:
            print(f"Failed to unenroll pod {namespace}/{pod_name}: {e}")
            return False

    async def _get_namespace_waypoint(self, namespace: str) -> str | None:
        """
        Check if a waypoint proxy is deployed in the namespace.

        Looks for Gateway resources with gatewayClassName: istio-waypoint.

        Returns:
            Waypoint Gateway name if one exists, None otherwise
        """
        try:
            # Check for Gateway resources with gatewayClassName: istio-waypoint in this namespace
            gateways = await self.k8s_client.get_resources(
                api_version="gateway.networking.k8s.io/v1", kind="Gateway", namespace=namespace
            )

            for gateway in gateways:
                spec = gateway.get("spec", {})
                if spec.get("gatewayClassName") == "istio-waypoint":
                    name = gateway.get("metadata", {}).get("name")
                    return str(name) if name else None

            return None

        except Exception:
            return None

    async def weave_policy(self, error: AccessError) -> Policy | None:
        """
        Auto-generate a minimal policy to resolve an access error.

        Creates either an L4 (ztunnel) or L7 (waypoint) AuthorizationPolicy
        based on the error details and applies it to the cluster.

        Args:
            error: AccessError to resolve

        Returns:
            Generated Policy object if successful, None otherwise
        """
        try:
            # Generate policy using weaver
            logging.debug(
                f"Generating policy for error: {error.source_workload} -> {error.target_service or error.target_workload}"
            )
            logging.debug(
                f"Error details - source_namespace: {error.source_namespace}, target_namespace: {error.target_namespace}, target_port: {error.target_port}"
            )

            policy = await self.weaver.weave_policy(error)
            logging.debug(f"Generated policy: {policy.name} in namespace {policy.namespace}")

            # Convert Policy object to Istio AuthorizationPolicy manifest
            manifest = self.converter.export_authorization_policy(policy)
            logging.debug(f"Converted to manifest: {manifest.get('metadata', {}).get('name')}")
            logging.debug(f"Manifest: {manifest}")

            # Apply the manifest to the cluster
            logging.debug(f"Applying manifest to cluster in namespace {policy.namespace}...")
            result = await self.k8s_client.create_custom_object(
                group="security.istio.io",
                version="v1",
                namespace=policy.namespace,
                plural="authorizationpolicies",
                body=manifest,
            )

            logging.debug(f"Policy applied successfully, result: {result}")

            # Fetch the created policy to get full metadata
            created_policy = await self.get_policy(policy.name, policy.namespace, PolicyType.AUTHORIZATION_POLICY.value)

            return created_policy or policy

        except Exception as e:
            import traceback

            logging.error(f"Failed to weave policy: {e}")
            logging.error(f"Traceback: {traceback.format_exc()}")
            return None

    async def unweave_policies(self, namespace: str | None = None) -> int:
        """
        Remove all kubeloom-managed policies.

        Args:
            namespace: Optional namespace to filter. If None, remove from all namespaces.

        Returns:
            Number of policies removed
        """
        try:
            removed_count = 0

            # Get list of namespaces to process
            if namespace:
                namespaces_to_process = [namespace]
            else:
                # Get all namespaces
                ns_objects = await self.k8s_client.get_namespaces()
                namespaces_to_process = [ns.name for ns in ns_objects]

            # For each namespace, find and delete kubeloom-managed AuthorizationPolicies
            for ns in namespaces_to_process:
                try:
                    # Get all AuthorizationPolicies in namespace
                    policies_response = await self.k8s_client.list_custom_objects(
                        group="security.istio.io",
                        version="v1",
                        namespace=ns,
                        plural="authorizationpolicies",
                        label_selector=f"{IstioPolicyWeaver.MANAGED_LABEL}={IstioPolicyWeaver.MANAGED_LABEL_VALUE}",
                    )

                    # Delete each managed policy
                    for item in policies_response.get("items", []):
                        policy_name = item.get("metadata", {}).get("name")
                        if policy_name:
                            await self.k8s_client.delete_custom_object(
                                group="security.istio.io",
                                version="v1",
                                namespace=ns,
                                plural="authorizationpolicies",
                                name=policy_name,
                            )
                            removed_count += 1

                except Exception as e:
                    print(f"Failed to unweave policies in namespace {ns}: {e}")
                    continue

            return removed_count

        except Exception as e:
            print(f"Failed to unweave policies: {e}")
            return 0

    async def get_woven_policies(self, namespace: str) -> list[Policy]:
        """
        Get all kubeloom-managed (woven) policies in a namespace.

        Args:
            namespace: Namespace to query

        Returns:
            List of woven Policy objects
        """
        try:
            # Get all AuthorizationPolicies with kubeloom label
            policies_response = await self.k8s_client.list_custom_objects(
                group="security.istio.io",
                version="v1",
                namespace=namespace,
                plural="authorizationpolicies",
                label_selector=f"{IstioPolicyWeaver.MANAGED_LABEL}={IstioPolicyWeaver.MANAGED_LABEL_VALUE}",
            )

            # Convert to Policy objects
            woven_policies = []
            for item in policies_response.get("items", []):
                policy = self.converter.convert_authorization_policy(item)
                if policy:
                    woven_policies.append(policy)

            return woven_policies

        except Exception as e:
            print(f"Failed to get woven policies: {e}")
            return []
