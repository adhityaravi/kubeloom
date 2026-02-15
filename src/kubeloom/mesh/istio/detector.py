"""Istio service mesh detector."""

from typing import Any, ClassVar

from kubeloom.core.models import ServiceMesh, ServiceMeshType
from kubeloom.k8s.client import K8sClient


class IstioDetector:
    """Detect Istio service mesh installation using CRDs."""

    # Istio CRDs that indicate installation.
    # This only indicates a subset of all the Istio CRDs.
    ISTIO_CRDS: ClassVar[list[str]] = [
        "virtualservices.networking.istio.io",
        "destinationrules.networking.istio.io",
        "authorizationpolicies.security.istio.io",
        "peerauthentications.security.istio.io",
        "gateways.networking.istio.io",
    ]

    def __init__(self, k8s_client: K8sClient):
        self.k8s_client = k8s_client

    async def detect(self) -> ServiceMesh | None:
        """Detect if Istio is installed by checking for CRDs."""
        try:
            # Check for Istio CRDs
            if not await self._check_istio_crds():
                return None

            # Find Istio control plane namespace and deployment
            control_plane_info = await self._find_control_plane()
            if not control_plane_info:
                return None

            namespace, deployment, version, revision = control_plane_info

            # Check control plane status
            control_plane_ready = self._check_control_plane_status(deployment)

            service_mesh = ServiceMesh(
                type=ServiceMeshType.ISTIO,
                version=version,
                namespace=namespace,
                revision=revision,
                control_plane_ready=control_plane_ready,
                # FIXME: this should rather check for waypoint readiness.
                data_plane_ready=control_plane_ready,
                default_injection=False,
                telemetry_enabled=False,  # Check not implemented
            )

            return service_mesh

        except Exception:
            return None

    async def _check_istio_crds(self) -> bool:
        """Check if Istio CRDs are installed."""
        try:
            # Get all CRDs
            crds = await self.k8s_client.get_resources(
                api_version="apiextensions.k8s.io/v1", kind="CustomResourceDefinition"
            )

            crd_names = {crd.get("metadata", {}).get("name", "") for crd in crds}

            # Check if any Istio CRDs are present.
            # I am checking for "any". Must this be rather an "all"?
            return any(istio_crd in crd_names for istio_crd in self.ISTIO_CRDS)

        except Exception:
            return False

    async def _find_control_plane(self) -> tuple[str, dict[str, Any], str, str | None] | None:
        """Find Istio control plane deployment in any namespace."""
        try:
            # Check common Istio namespaces first (fast path)
            common_namespaces = ["istio-system", "istio", "default"]

            for ns_name in common_namespaces:
                result = await self._check_namespace_for_istiod(ns_name)
                if result:
                    return result

            # Fall back to checking all namespaces if not found
            namespaces = await self.k8s_client.get_namespaces()
            for namespace in namespaces:
                if namespace.name in common_namespaces:
                    continue  # Already checked
                result = await self._check_namespace_for_istiod(namespace.name)
                if result:
                    return result

            return None

        except Exception:
            return None

    async def _check_namespace_for_istiod(self, ns_name: str) -> tuple[str, dict[str, Any], str, str | None] | None:
        """Check a specific namespace for istiod deployment."""
        try:
            deployments = await self.k8s_client.get_resources(
                api_version="apps/v1", kind="Deployment", namespace=ns_name
            )

            for deployment in deployments:
                name = deployment.get("metadata", {}).get("name", "")
                labels = deployment.get("metadata", {}).get("labels", {})

                if (
                    name.startswith("istiod")
                    or "pilot" in name
                    or labels.get("app") == "istiod"
                    or "istio.io/rev" in labels
                ):
                    version = self._extract_version(deployment)
                    revision = self._extract_revision(deployment)
                    return ns_name, deployment, version, revision

            return None
        except Exception:
            return None

    def _extract_version(self, deployment: dict[str, Any]) -> str:
        """Extract Istio version from deployment."""
        try:
            # Check labels first
            labels = deployment.get("metadata", {}).get("labels", {})

            # Check common Istio version labels
            version_labels = ["version", "istio", "app.kubernetes.io/version", "istio.io/version"]
            for label in version_labels:
                if labels.get(label):
                    version = str(labels[label])
                    # Filter out non-version values like "pilot"
                    if version and version not in ["pilot", "istiod", "discovery"]:
                        return version

            # Check image tag
            containers = deployment.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
            for container in containers:
                image = str(container.get("image", ""))
                if ("pilot" in image or "istiod" in image) and ":" in image:
                    tag = image.split(":")[-1]
                    # Only return tag if it looks like a version (contains digits and dots)
                    if tag and tag != "latest" and any(c.isdigit() for c in tag) and "." in tag:
                        return str(tag)

            # Check annotations for version info
            annotations = deployment.get("metadata", {}).get("annotations", {})
            for key, value in annotations.items():
                if "version" in key.lower() and value and any(c.isdigit() for c in str(value)):
                    return str(value)

            return "unknown"

        except Exception:
            return "unknown"

    def _extract_revision(self, deployment: dict[str, Any]) -> str | None:
        """Extract Istio revision from deployment."""
        try:
            labels = deployment.get("metadata", {}).get("labels", {})
            rev = labels.get("istio.io/rev")
            return str(rev) if rev is not None else None
        except Exception:
            return None

    def _check_control_plane_status(self, deployment: dict[str, Any]) -> bool:
        """Check if control plane is ready."""
        try:
            status = deployment.get("status", {})
            ready_replicas = int(status.get("readyReplicas", 0))
            replicas = int(status.get("replicas", 0))

            return bool(ready_replicas > 0 and ready_replicas == replicas)

        except Exception:
            return False
