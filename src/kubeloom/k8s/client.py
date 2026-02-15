"""Kubernetes client implementation."""

import asyncio
from collections.abc import AsyncIterator
from queue import Queue
from typing import Any

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
            # Run blocking K8s API call in thread pool
            response = await asyncio.to_thread(self._core_v1.list_namespace)
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
            current_context = active_context["name"] if active_context else "unknown"

            # Get cluster name and server
            cluster_name = current_context
            api_server = active_context["context"]["cluster"] if active_context else "unknown"

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
                namespaces=namespaces,
            )

            return cluster

        except Exception as e:
            raise RuntimeError(f"Failed to get cluster info: {e}") from e

    async def get_resources(self, api_version: str, kind: str, namespace: str | None = None) -> list[dict[str, Any]]:
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

            # Get custom resources in thread pool
            assert self._custom_objects is not None
            custom_objects = self._custom_objects
            plural = self._get_plural_name(kind)

            def fetch() -> dict[str, Any]:
                if namespace:
                    return custom_objects.list_namespaced_custom_object(
                        group=group, version=version, namespace=namespace, plural=plural
                    )
                return custom_objects.list_cluster_custom_object(
                    group=group, version=version, plural=plural
                )

            response = await asyncio.to_thread(fetch)
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
        assert self._core_v1 is not None
        core_v1 = self._core_v1

        def fetch() -> Any:
            if kind_lower == "namespace":
                return core_v1.list_namespace()
            elif kind_lower == "pod":
                if namespace:
                    return core_v1.list_namespaced_pod(namespace=namespace)
                return core_v1.list_pod_for_all_namespaces()
            elif kind_lower == "service":
                if namespace:
                    return core_v1.list_namespaced_service(namespace=namespace)
                return core_v1.list_service_for_all_namespaces()
            elif kind_lower == "serviceaccount":
                if namespace:
                    return core_v1.list_namespaced_service_account(namespace=namespace)
                return core_v1.list_service_account_for_all_namespaces()
            elif kind_lower == "configmap":
                if namespace:
                    return core_v1.list_namespaced_config_map(namespace=namespace)
                return core_v1.list_config_map_for_all_namespaces()
            elif kind_lower == "secret":
                if namespace:
                    return core_v1.list_namespaced_secret(namespace=namespace)
                return core_v1.list_secret_for_all_namespaces()
            else:
                raise ValueError(f"Unsupported core resource: {kind}")

        try:
            response = await asyncio.to_thread(fetch)
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
        tail_lines: int | None = 10,
    ) -> AsyncIterator[str]:
        """
        Stream logs from a pod using daemon threads.

        Uses daemon threads that won't block process exit. When the app exits,
        any running log streams will be immediately terminated.

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

        assert self._core_v1 is not None
        core_v1 = self._core_v1  # Capture for lambda

        # Queue for receiving log lines from daemon thread
        log_queue: Queue[tuple[str, Any]] = Queue()
        stop_flag = {"stop": False}

        def stream_logs_in_thread() -> None:
            """Run log streaming in a daemon thread."""
            try:
                w = watch.Watch()
                stream = w.stream(
                    core_v1.read_namespaced_pod_log,
                    name=pod_name,
                    namespace=namespace,
                    container=container,
                    follow=follow,
                    tail_lines=tail_lines,
                    timestamps=True,
                )

                for line in stream:
                    if stop_flag["stop"]:
                        w.stop()
                        break
                    log_queue.put(("line", line))

                # Signal end of stream
                log_queue.put(("done", None))

            except ApiException as e:
                if e.status != 404:
                    log_queue.put(("error", e))
                else:
                    log_queue.put(("done", None))
            except Exception as e:
                log_queue.put(("error", e))

        # Start daemon thread for log streaming
        import threading

        thread = threading.Thread(
            target=stream_logs_in_thread, daemon=True, name=f"log-stream-{pod_name}"  # Won't block exit
        )
        thread.start()

        try:
            # Yield lines as they arrive
            while True:
                # Non-blocking check with timeout
                await asyncio.sleep(0.01)

                if not log_queue.empty():
                    msg_type, data = log_queue.get()

                    if msg_type == "line":
                        yield data
                    elif msg_type == "error":
                        raise RuntimeError(f"Error streaming logs from {namespace}/{pod_name}: {data}")
                    elif msg_type == "done":
                        break

        except asyncio.CancelledError:
            # Task cancelled - signal thread to stop
            stop_flag["stop"] = True
            raise
        finally:
            # Signal thread to stop
            stop_flag["stop"] = True

    async def get_pods_by_label(
        self, namespace: str | None = None, label_selector: str | None = None
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
            core_v1 = self._core_v1  # Capture for lambda

            # Run blocking k8s API call in default thread pool
            loop = asyncio.get_event_loop()

            def get_pods() -> list[dict[str, Any]]:
                if namespace:
                    response = core_v1.list_namespaced_pod(namespace=namespace, label_selector=label_selector)
                else:
                    response = core_v1.list_pod_for_all_namespaces(label_selector=label_selector)
                return [pod.to_dict() for pod in response.items]

            # Use default executor (None) for non-streaming operations
            return await loop.run_in_executor(None, get_pods)

        except ApiException as e:
            raise RuntimeError(f"Failed to get pods: {e}") from e

    async def create_custom_object(
        self, group: str, version: str, namespace: str, plural: str, body: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Create a custom Kubernetes object.

        Args:
            group: API group (e.g., "security.istio.io")
            version: API version (e.g., "v1")
            namespace: Namespace to create the object in
            plural: Plural form of the resource (e.g., "authorizationpolicies")
            body: Resource manifest as dictionary

        Returns:
            Created resource as dictionary

        Raises:
            RuntimeError: If creation fails
        """
        await self._ensure_connected()

        try:
            assert self._custom_objects is not None
            custom_objects = self._custom_objects  # Capture for lambda

            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: custom_objects.create_namespaced_custom_object(
                    group=group, version=version, namespace=namespace, plural=plural, body=body
                ),
            )
            return dict(result)

        except ApiException as e:
            raise RuntimeError(f"Failed to create {plural} in {namespace}: {e}") from e

    async def delete_custom_object(
        self, group: str, version: str, namespace: str, plural: str, name: str
    ) -> dict[str, Any]:
        """
        Delete a custom Kubernetes object.

        Args:
            group: API group (e.g., "security.istio.io")
            version: API version (e.g., "v1")
            namespace: Namespace containing the object
            plural: Plural form of the resource (e.g., "authorizationpolicies")
            name: Name of the resource to delete

        Returns:
            Deletion status as dictionary

        Raises:
            RuntimeError: If deletion fails
        """
        await self._ensure_connected()

        try:
            assert self._custom_objects is not None
            custom_objects = self._custom_objects  # Capture for lambda

            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: custom_objects.delete_namespaced_custom_object(
                    group=group, version=version, namespace=namespace, plural=plural, name=name
                ),
            )
            return dict(result)

        except ApiException as e:
            raise RuntimeError(f"Failed to delete {plural}/{name} in {namespace}: {e}") from e

    async def list_custom_objects(
        self, group: str, version: str, namespace: str, plural: str, label_selector: str | None = None
    ) -> dict[str, Any]:
        """
        List custom Kubernetes objects with optional label selector.

        Args:
            group: API group (e.g., "security.istio.io")
            version: API version (e.g., "v1")
            namespace: Namespace to list objects from
            plural: Plural form of the resource (e.g., "authorizationpolicies")
            label_selector: Optional label selector (e.g., "app=foo,env=prod")

        Returns:
            List response as dictionary with 'items' field

        Raises:
            RuntimeError: If listing fails
        """
        await self._ensure_connected()

        try:
            assert self._custom_objects is not None
            custom_objects = self._custom_objects  # Capture for lambda

            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: custom_objects.list_namespaced_custom_object(
                    group=group, version=version, namespace=namespace, plural=plural, label_selector=label_selector
                ),
            )
            return dict(result)

        except ApiException as e:
            raise RuntimeError(f"Failed to list {plural} in {namespace}: {e}") from e

    async def patch_pod(self, name: str, namespace: str, body: dict[str, Any]) -> dict[str, Any]:
        """
        Patch a pod (e.g., to update labels).

        Args:
            name: Pod name
            namespace: Pod namespace
            body: Patch body as dictionary

        Returns:
            Patched pod as dictionary

        Raises:
            RuntimeError: If patching fails
        """
        await self._ensure_connected()

        try:
            assert self._core_v1 is not None
            core_v1 = self._core_v1  # Capture for lambda

            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None, lambda: core_v1.patch_namespaced_pod(name=name, namespace=namespace, body=body)
            )
            return dict(result.to_dict())

        except ApiException as e:
            raise RuntimeError(f"Failed to patch pod {namespace}/{name}: {e}") from e

    async def find_pod_by_ip(self, ip: str) -> dict[str, Any] | None:
        """
        Find a pod by its IP address using field selector.

        Args:
            ip: Pod IP address to search for

        Returns:
            Pod dictionary if found, None otherwise
        """
        await self._ensure_connected()

        try:
            assert self._core_v1 is not None
            core_v1 = self._core_v1  # Capture for lambda

            # Use field selector to efficiently find pod by IP
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None, lambda: core_v1.list_pod_for_all_namespaces(field_selector=f"status.podIP={ip}")
            )

            # Return first matching pod (IPs are unique)
            if response.items:
                return dict(response.items[0].to_dict())

            return None

        except ApiException:
            # Field selector might not be supported in older K8s versions
            # Silently return None rather than error
            return None

    async def get_pod(self, name: str, namespace: str) -> dict[str, Any] | None:
        """
        Get a specific pod by name and namespace.

        Args:
            name: Pod name
            namespace: Pod namespace

        Returns:
            Pod dictionary if found, None otherwise
        """
        await self._ensure_connected()

        try:
            assert self._core_v1 is not None
            core_v1 = self._core_v1  # Capture for lambda

            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None, lambda: core_v1.read_namespaced_pod(name=name, namespace=namespace)
            )
            return dict(response.to_dict())

        except ApiException:
            # Pod not found or other error
            return None

    async def close(self) -> None:
        """Close the client connection and cleanup resources."""
        # Close API client
        if self._api_client and hasattr(self._api_client, "close"):
            if asyncio.iscoroutinefunction(self._api_client.close):
                await self._api_client.close()
            else:
                self._api_client.close()

        self._api_client = None
        self._core_v1 = None
        self._custom_objects = None
        self._apps_v1 = None
