"""Policy weaving - auto-generate minimal AuthorizationPolicies from access errors."""

from datetime import datetime
from typing import Set, Optional, Dict

from ...core.models import (
    Policy, PolicyType, ServiceMeshType, PolicyStatus,
    PolicySource, PolicyTarget, AllowedRoute, HTTPMethod, PolicyAction, ActionType
)
from ...core.models.errors import AccessError
from ...k8s.client import K8sClient


class IstioPolicyWeaver:
    """
    Auto-generates minimal Istio AuthorizationPolicies to resolve access errors.

    Strategy:
    - L7 policy (waypoint): If HTTP method/path detected in error - uses targetRefs
    - L4 policy (ztunnel): If only port detected in error - uses selector
    """

    MANAGED_LABEL = "kubeloom.io/managed"
    MANAGED_LABEL_VALUE = "true"
    ISTIO_HBONE_PORT = 15008  # Istio's internal HBONE tunnel port

    def __init__(self, k8s_client: K8sClient):
        """Initialize the policy weaver with a K8s client."""
        self.k8s_client = k8s_client

    async def weave_policy(self, error: AccessError) -> Policy:
        """
        Generate a minimal Policy object to resolve the access error.

        Args:
            error: The AccessError to resolve

        Returns:
            Policy object configured for the error
        """
        # Determine if this is L7 (HTTP) or L4 (TCP) based on available info
        is_l7 = bool(error.http_method or error.http_path)

        if is_l7:
            return await self._generate_l7_policy(error)
        else:
            return await self._generate_l4_policy(error)

    async def _generate_l7_policy(self, error: AccessError) -> Policy:
        """
        Generate an L7 (waypoint) AuthorizationPolicy.

        This policy:
        - Uses targetRefs to target the service
        - Allows specific HTTP methods and paths
        - Enforced at waypoint proxy
        """
        policy_name = self._generate_policy_name(error, "l7")

        # Build labels
        labels = {
            self.MANAGED_LABEL: self.MANAGED_LABEL_VALUE,
            "kubeloom.io/policy-type": "l7",
        }

        # Build annotations
        annotations = {
            "kubeloom.io/source": f"{error.source_namespace}/{error.source_workload}" if error.source_workload else error.source_ip or "unknown",
            "kubeloom.io/target": f"{error.target_namespace}/{error.target_workload}" if error.target_workload else error.target_service or "unknown",
            "kubeloom.io/description": f"Auto-generated to allow {error.http_method or 'HTTP'} {error.http_path or '/'}"
        }

        # Build source (from clause)
        source = None
        if error.source_workload and error.source_namespace:
            # Use service account principal format
            # Use actual service account, fallback to workload name if not available
            sa_name = error.source_service_account or error.source_workload
            principal = f"cluster.local/ns/{error.source_namespace}/sa/{sa_name}"
            source = PolicySource(
                principals=[principal],
                service_accounts=[sa_name]
            )

        # Build allowed route (to clause with operation)
        methods: Set[HTTPMethod] = set()
        if error.http_method:
            try:
                methods.add(HTTPMethod(error.http_method))
            except ValueError:
                pass  # Unknown HTTP method

        paths = [error.http_path] if error.http_path else []

        # Skip port filter for Istio's internal HBONE port (15008)
        # This port is used for tunneling - we should allow all ports
        ports = None
        if error.target_port and error.target_port != self.ISTIO_HBONE_PORT:
            ports = [error.target_port]

        allowed_routes = [AllowedRoute(
            methods=methods if methods else None,
            paths=paths if paths else None,
            ports=ports
        )]

        # Build target (targetRefs - for L7 we target the service)
        target = None
        if error.target_service:
            target = PolicyTarget(services=[error.target_service])
        elif error.target_workload:
            # If no service, use workload as service name (common pattern)
            target = PolicyTarget(services=[error.target_workload])

        # Create policy
        policy = Policy(
            name=policy_name,
            namespace=error.target_namespace or "default",
            type=PolicyType.AUTHORIZATION_POLICY,
            mesh_type=ServiceMeshType.ISTIO,
            labels=labels,
            annotations=annotations,
            spec={},  # Will be filled by converter
            status=PolicyStatus.PENDING,
            action=PolicyAction(type=ActionType.ALLOW),
            source=source,
            targets=[target] if target else [],
            allowed_routes=allowed_routes
        )

        return policy

    async def _generate_l4_policy(self, error: AccessError) -> Policy:
        """
        Generate an L4 (ztunnel) AuthorizationPolicy.

        This policy:
        - Uses selector with matchLabels to target pods
        - Allows connections on specific ports from specific principals
        - Enforced at ztunnel
        """
        policy_name = self._generate_policy_name(error, "l4")

        # Build labels
        labels = {
            self.MANAGED_LABEL: self.MANAGED_LABEL_VALUE,
            "kubeloom.io/policy-type": "l4",
        }

        # Build annotations
        annotations = {
            "kubeloom.io/source": f"{error.source_namespace}/{error.source_workload}" if error.source_workload else error.source_ip or "unknown",
            "kubeloom.io/target": f"{error.target_namespace}/{error.target_workload}" if error.target_workload else error.target_service or "unknown",
            "kubeloom.io/description": f"Auto-generated to allow port {error.target_port or 'any'}"
        }

        # Build source (from clause)
        source = None
        if error.source_workload and error.source_namespace:
            # Use service account principal format
            # Use actual service account, fallback to workload name if not available
            sa_name = error.source_service_account or error.source_workload
            principal = f"cluster.local/ns/{error.source_namespace}/sa/{sa_name}"
            source = PolicySource(
                principals=[principal],
                service_accounts=[sa_name]
            )

        # Skip port filter for Istio's internal HBONE port (15008)
        # This port is used for tunneling - we should allow all ports
        ports = None
        if error.target_port and error.target_port != self.ISTIO_HBONE_PORT:
            ports = [error.target_port]

        allowed_routes = [AllowedRoute(
            ports=ports
        )]

        # Build target (selector - for L4 we query actual pod labels)
        target = None
        target_labels = await self._get_target_pod_labels(error)
        if target_labels:
            target = PolicyTarget(workload_labels=target_labels)
        elif error.target_workload:
            # Fallback to app label if we couldn't get actual labels
            target = PolicyTarget(workload_labels={"app": error.target_workload})
        elif error.target_service:
            # Use service name as app label (common convention)
            target = PolicyTarget(workload_labels={"app": error.target_service})

        # Create policy
        policy = Policy(
            name=policy_name,
            namespace=error.target_namespace or "default",
            type=PolicyType.AUTHORIZATION_POLICY,
            mesh_type=ServiceMeshType.ISTIO,
            labels=labels,
            annotations=annotations,
            spec={},  # Will be filled by converter
            status=PolicyStatus.PENDING,
            action=PolicyAction(type=ActionType.ALLOW),
            source=source,
            targets=[target] if target else [],
            allowed_routes=allowed_routes
        )

        return policy

    async def _get_target_pod_labels(self, error: AccessError) -> Optional[Dict[str, str]]:
        """
        Query the target pod and extract unique identifying labels.

        Strategy:
        - Look for labels where the value contains the pod name
        - This gives us unique labels that identify this specific pod/workload
        - Falls back to None if we can't find the pod or extract labels

        Args:
            error: The access error with target pod info

        Returns:
            Dictionary of labels to use in selector, or None if unavailable
        """
        # Need target workload and namespace to query the pod
        if not error.target_workload or not error.target_namespace:
            return None

        try:
            # Query the target pod
            pod = await self.k8s_client.get_pod(
                name=error.target_workload,
                namespace=error.target_namespace
            )

            if not pod:
                return None

            # Extract labels from pod
            metadata = pod.get("metadata", {})
            pod_labels = metadata.get("labels", {})

            if not pod_labels:
                return None

            # Find labels that have the pod name in the value
            # This helps us uniquely identify the workload
            unique_labels = {}
            pod_base_name = error.target_workload

            # Remove trailing pod ordinal if it's a StatefulSet pod (e.g., "pod-0" -> "pod")
            if pod_base_name and pod_base_name[-2:].startswith("-") and pod_base_name[-1].isdigit():
                pod_base_name = pod_base_name.rsplit("-", 1)[0]

            for key, value in pod_labels.items():
                # Skip Istio-managed labels
                if key.startswith("istio.io/") or key.startswith("service.istio.io/"):
                    continue

                # Skip Kubernetes-managed labels (these can be unreliable for policy matching)
                if key.startswith("statefulset.kubernetes.io/") or \
                   key.startswith("controller-revision-hash") or \
                   key.startswith("pod-template-hash") or \
                   key.startswith("apps.kubernetes.io/pod-index"):
                    continue

                # Include labels where value matches the workload name
                if value == pod_base_name or value == error.target_workload:
                    unique_labels[key] = value

            # If we found unique labels, return them
            if unique_labels:
                return unique_labels

            # Otherwise, return common labels (app, version, etc.) if they exist
            common_label_keys = ["app", "app.kubernetes.io/name", "version"]
            for key in common_label_keys:
                if key in pod_labels:
                    return {key: pod_labels[key]}

            # Last resort: return all non-istio labels (limited to 3 for safety)
            non_istio_labels = {
                k: v for k, v in pod_labels.items()
                if not k.startswith("istio.io/") and not k.startswith("service.istio.io/")
            }
            if non_istio_labels:
                # Return up to 3 labels
                return dict(list(non_istio_labels.items())[:3])

            return None

        except Exception as e:
            print(f"Warning: Could not get labels for pod {error.target_namespace}/{error.target_workload}: {e}")
            return None

    def _generate_policy_name(self, error: AccessError, policy_type: str) -> str:
        """
        Generate a unique policy name based on the error details.

        Format: kubeloom-{type}-{source}-{target}-{hash}
        """
        source = error.source_workload or error.source_ip or "unknown"
        target = error.target_service or error.target_workload or "unknown"

        # Sanitize names (k8s resource names must be DNS-1123 compliant)
        source = source.replace(".", "-").replace("/", "-").replace(":", "-")[:20]
        target = target.replace(".", "-").replace("/", "-").replace(":", "-")[:20]

        # Add timestamp to ensure uniqueness
        timestamp = datetime.now().strftime("%H%M%S")

        return f"kubeloom-{policy_type}-{source}-to-{target}-{timestamp}".lower()
