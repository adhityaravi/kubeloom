"""Kubernetes client implementation."""

import asyncio
from typing import Any, AsyncIterator

from kubernetes import client, config, watch
from kubernetes.client.exceptions import ApiException

from kubeloom.core.interfaces import ClusterClient
from kubeloom.core.models import Cluster, Namespace


class K8sClient(ClusterClient):
    """Kubernetes client implementation."""

    def __init__(self, kubeconfig_path: str | None = None):
        """Initialize Kubernetes client."""
        self.kubeconfig_path = kubeconfig_path
        self._api_client: client.ApiClient | None = None
        self._core_v1: client.CoreV1Api | None = None
        self._custom_objects: client.CustomObjectsApi | None = None
        self._apps_v1: client.AppsV1Api | None = None

    async def _ensure_connected(self) -> None:
        """Ensure client is connected."""
        if self._api_client is None:
            try:
                if self.kubeconfig_path:
                    config.load_kube_config(config_file=self.kubeconfig_path)
                else:
                    # Try in-cluster config first, then default kubeconfig
                    try:
                        config.load_incluster_config()
                    except config.ConfigException:
                        config.load_kube_config()

                self._api_client = client.ApiClient()
                self._core_v1 = client.CoreV1Api(self._api_client)
                self._custom_objects = client.CustomObjectsApi(self._api_client)
                self._apps_v1 = client.AppsV1Api(self._api_client)

            except Exception as e:
                raise ConnectionError(f"Failed to connect to Kubernetes cluster: {e}") from e

    def is_connected(self) -> bool:
        """Check if client is connected to cluster."""
        return self._api_client is not None

    async def get_namespaces(self) -> list[Namespace]:
        """Get all namespaces in the cluster."""
        await self._ensure_connected()

        try:
            assert self._core_v1 is not None
            response = self._core_v1.list_namespace()
            namespaces = []

            for ns in response.items:
                namespace = Namespace(
                    name=ns.metadata.name,
                    labels=ns.metadata.labels or {},
                    annotations=ns.metadata.annotations or {},
                )
                namespaces.append(namespace)

            return namespaces

        except ApiException as e:
            raise RuntimeError(f"Failed to get namespaces: {e}") from e

    async def get_cluster_info(self) -> Cluster:
        """Get cluster information."""
        await self._ensure_connected()

        try:
            # Get cluster version
            version_api = client.VersionApi(self._api_client)
            version_info = version_api.get_code()

            # Get current context
            _, active_context = config.list_kube_config_contexts()
            current_context = active_context['name'] if active_context else "unknown"

            # Get cluster name and server
            cluster_name = current_context
            api_server = active_context['context']['cluster'] if active_context else "unknown"

            # Count nodes
            assert self._core_v1 is not None
            nodes_response = self._core_v1.list_node()
            nodes_count = len(nodes_response.items)

            # Count namespaces
            namespaces = await self.get_namespaces()
            namespaces_count = len(namespaces)

            cluster = Cluster(
                name=cluster_name,
                context=current_context,
                api_server=api_server,
                kubernetes_version=version_info.git_version,
                nodes_count=nodes_count,
                namespaces_count=namespaces_count,
                namespaces=namespaces
            )

            return cluster

        except Exception as e:
            raise RuntimeError(f"Failed to get cluster info: {e}") from e

    async def get_resources(
        self,
        api_version: str,
        kind: str,
        namespace: str | None = None
    ) -> list[dict[str, Any]]:
        """Get Kubernetes resources of a specific type."""
        await self._ensure_connected()

        try:
            # Parse API version
            if "/" in api_version:
                group, version = api_version.split("/", 1)
            else:
                group = ""
                version = api_version

            # Handle core resources differently
            if group == "" and version == "v1":
                return await self._get_core_resources(kind, namespace)

            # Get custom resources
            if namespace:
                assert self._custom_objects is not None
                response = self._custom_objects.list_namespaced_custom_object(
                    group=group,
                    version=version,
                    namespace=namespace,
                    plural=self._get_plural_name(kind)
                )
            else:
                assert self._custom_objects is not None
                response = self._custom_objects.list_cluster_custom_object(
                    group=group,
                    version=version,
                    plural=self._get_plural_name(kind)
                )

            items = response.get("items", [])
            return items if isinstance(items, list) else []

        except ApiException as e:
            if e.status == 404:
                # Resource type doesn't exist
                return []
            raise RuntimeError(f"Failed to get {kind} resources: {e}") from e

    async def _get_core_resources(self, kind: str, namespace: str | None = None) -> list[dict[str, Any]]:
        """Get core Kubernetes resources."""
        kind_lower = kind.lower()

        try:
            assert self._core_v1 is not None
            if kind_lower == "namespace":
                response = self._core_v1.list_namespace()
            elif kind_lower == "pod":
                if namespace:
                    response = self._core_v1.list_namespaced_pod(namespace=namespace)
                else:
                    response = self._core_v1.list_pod_for_all_namespaces()
            elif kind_lower == "service":
                if namespace:
                    response = self._core_v1.list_namespaced_service(namespace=namespace)
                else:
                    response = self._core_v1.list_service_for_all_namespaces()
            elif kind_lower == "serviceaccount":
                if namespace:
                    response = self._core_v1.list_namespaced_service_account(namespace=namespace)
                else:
                    response = self._core_v1.list_service_account_for_all_namespaces()
            elif kind_lower == "configmap":
                if namespace:
                    response = self._core_v1.list_namespaced_config_map(namespace=namespace)
                else:
                    response = self._core_v1.list_config_map_for_all_namespaces()
            elif kind_lower == "secret":
                if namespace:
                    response = self._core_v1.list_namespaced_secret(namespace=namespace)
                else:
                    response = self._core_v1.list_secret_for_all_namespaces()
            else:
                raise ValueError(f"Unsupported core resource: {kind}")

            return [item.to_dict() for item in response.items]

        except ApiException as e:
            if e.status == 404:
                return []
            raise RuntimeError(f"Failed to get {kind} resources: {e}") from e

    def _get_plural_name(self, kind: str) -> str:
        """Get plural name for a Kubernetes kind."""
        # Simple pluralization - can be improved
        plural_map = {
            "AuthorizationPolicy": "authorizationpolicies",
            "PeerAuthentication": "peerauthentications",
            "RequestAuthentication": "requestauthentications",
            "VirtualService": "virtualservices",
            "DestinationRule": "destinationrules",
            "Gateway": "gateways",
            "ServiceEntry": "serviceentries",
            "Sidecar": "sidecars",
            "WorkloadEntry": "workloadentries",
            "WorkloadGroup": "workloadgroups",
            "EnvoyFilter": "envoyfilters",
            "ProxyConfig": "proxyconfigs",
            "Telemetry": "telemetries",
            "NetworkPolicy": "networkpolicies",
        }

        return plural_map.get(kind, kind.lower() + "s")

    async def stream_pod_logs(
        self,
        pod_name: str,
        namespace: str,
        container: str | None = None,
        follow: bool = True,
        tail_lines: int | None = 10
    ) -> AsyncIterator[str]:
        """
        Stream logs from a pod.

        Args:
            pod_name: Name of the pod
            namespace: Namespace of the pod
            container: Optional container name (if pod has multiple containers)
            follow: Whether to follow/tail the logs
            tail_lines: Number of lines to start with (None for all)

        Yields:
            Log lines as they arrive
        """
        await self._ensure_connected()

        try:
            assert self._core_v1 is not None

            # Use the watch module to stream logs
            w = watch.Watch()

            # Run the blocking stream in a thread pool to avoid blocking event loop
            loop = asyncio.get_event_loop()

            # Create iterator in thread
            def create_stream():
                return w.stream(
                    self._core_v1.read_namespaced_pod_log,
                    name=pod_name,
                    namespace=namespace,
                    container=container,
                    follow=follow,
                    tail_lines=tail_lines,
                    timestamps=True
                )

            stream_iter = await loop.run_in_executor(None, create_stream)

            # Iterate in thread pool
            while True:
                try:
                    line = await loop.run_in_executor(None, next, stream_iter, None)
                    if line is None:
                        break
                    yield line
                except StopIteration:
                    break

        except ApiException as e:
            if e.status != 404:  # Ignore pod not found, it might have terminated
                raise RuntimeError(f"Failed to stream logs from {namespace}/{pod_name}: {e}") from e
        except Exception as e:
            raise RuntimeError(f"Error streaming logs from {namespace}/{pod_name}: {e}") from e

    async def get_pods_by_label(
        self,
        namespace: str | None = None,
        label_selector: str | None = None
    ) -> list[dict[str, Any]]:
        """
        Get pods filtered by label selector.

        Args:
            namespace: Optional namespace to filter (None for all namespaces)
            label_selector: Label selector (e.g., "app=ztunnel")

        Returns:
            List of pod objects
        """
        await self._ensure_connected()

        try:
            assert self._core_v1 is not None

            # Run blocking k8s API call in thread pool
            loop = asyncio.get_event_loop()

            def get_pods():
                if namespace:
                    response = self._core_v1.list_namespaced_pod(
                        namespace=namespace,
                        label_selector=label_selector
                    )
                else:
                    response = self._core_v1.list_pod_for_all_namespaces(
                        label_selector=label_selector
                    )
                return [pod.to_dict() for pod in response.items]

            return await loop.run_in_executor(None, get_pods)

        except ApiException as e:
            raise RuntimeError(f"Failed to get pods: {e}") from e

    async def close(self) -> None:
        """Close the client connection."""
        if self._api_client and hasattr(self._api_client, 'close'):
            if asyncio.iscoroutinefunction(self._api_client.close):
                await self._api_client.close()
            else:
                self._api_client.close()
        self._api_client = None
        self._core_v1 = None
        self._custom_objects = None
        self._apps_v1 = None
