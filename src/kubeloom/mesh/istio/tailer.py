"""Smart log tailing with adaptive backoff for quiet pods."""

import asyncio
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from kubeloom.core.models import AccessError
from kubeloom.core.models.errors import ErrorType
from kubeloom.k8s.client import K8sClient
from kubeloom.mesh.istio.log_parser import IstioLogParser


@dataclass
class PodTailState:
    """Track the state of a pod being tailed."""

    pod_name: str
    pod_namespace: str
    is_waypoint: bool
    last_error_time: datetime | None = None
    last_checked: datetime | None = None
    is_active: bool = False  # Currently being tailed
    error_count: int = 0  # Total errors seen from this pod

    def __post_init__(self) -> None:
        if self.last_checked is None:
            self.last_checked = datetime.now()

    @property
    def pod_key(self) -> str:
        """Unique key for this pod."""
        return f"{self.pod_namespace}/{self.pod_name}"

    @property
    def is_noisy(self) -> bool:
        """Check if this pod has shown errors recently."""
        if self.last_error_time is None:
            return False
        # Consider noisy if error in last 5 minutes
        return (datetime.now() - self.last_error_time) < timedelta(minutes=5)


class SmartLogTailer:
    """
    Smart log tailing with adaptive strategy.

    Strategy:
    1. Active phase (1 min): Tail all pods simultaneously
    2. Selective phase (5 min): Only tail pods that showed errors
    3. Re-check phase (1 min): Re-tail all pods to catch new errors
    4. Repeat

    This reduces overhead while ensuring we don't miss errors.
    """

    ACTIVE_PHASE_DURATION = 600  # Tail all pods for 10 minutes
    SELECTIVE_PHASE_DURATION = 0  # Disabled - immediately switch back to active
    MAX_CONCURRENT_TAILS = 100  # Limit concurrent tails

    def __init__(self, k8s_client: K8sClient, log_parser: IstioLogParser, mesh_adapter: Any = None) -> None:
        self.k8s_client = k8s_client
        self.log_parser = log_parser
        self.mesh_adapter = mesh_adapter  # Optional mesh adapter for enrollment checks
        self.pod_states: dict[str, PodTailState] = {}
        self.active_tasks: dict[str, asyncio.Task[None]] = {}
        self.error_queue: asyncio.Queue[AccessError | None] = asyncio.Queue()
        self.is_running = False
        self.phase = "active"  # "active" or "selective"
        self.phase_start_time = datetime.now()

    async def discover_pods(self) -> list[PodTailState]:
        """
        Discover all ztunnel and waypoint pods across all namespaces.

        Returns:
            List of PodTailState objects for discovered pods.
        """
        discovered = []

        # Find all ztunnel pods (search all namespaces)
        ztunnel_pods = await self.k8s_client.get_pods_by_label(
            namespace=None, label_selector="app=ztunnel"  # All namespaces
        )

        for pod in ztunnel_pods:
            pod_name = pod["metadata"]["name"]
            pod_namespace = pod["metadata"]["namespace"]
            pod_key = f"{pod_namespace}/{pod_name}"

            # Reuse existing state or create new
            if pod_key in self.pod_states:
                discovered.append(self.pod_states[pod_key])
            else:
                state = PodTailState(pod_name=pod_name, pod_namespace=pod_namespace, is_waypoint=False)
                self.pod_states[pod_key] = state
                discovered.append(state)

        # Find all waypoint pods (search all namespaces)
        waypoint_pods = await self.k8s_client.get_pods_by_label(
            namespace=None, label_selector="gateway.istio.io/managed=istio.io-mesh-controller"  # All namespaces
        )

        for pod in waypoint_pods:
            pod_name = pod["metadata"]["name"]
            pod_namespace = pod["metadata"]["namespace"]
            pod_key = f"{pod_namespace}/{pod_name}"

            # Reuse existing state or create new
            if pod_key in self.pod_states:
                discovered.append(self.pod_states[pod_key])
            else:
                state = PodTailState(pod_name=pod_name, pod_namespace=pod_namespace, is_waypoint=True)
                self.pod_states[pod_key] = state
                discovered.append(state)

        return discovered

    async def tail_with_adaptive_strategy(self) -> AsyncIterator[AccessError]:
        """
        Tail logs with adaptive strategy.

        Yields:
            AccessError objects as they are detected.
        """
        self.is_running = True

        # Start the phase manager
        phase_manager_task = asyncio.create_task(self._manage_phases())

        # Start error collector
        collector_task = asyncio.create_task(self._collect_errors())

        try:
            # Yield errors as they arrive
            while self.is_running:
                error = await self.error_queue.get()
                if error is None:
                    break
                yield error
        finally:
            # Cleanup
            self.is_running = False
            phase_manager_task.cancel()
            collector_task.cancel()
            await self._stop_all_tails()

    async def _manage_phases(self) -> None:
        """Manage tailing phases (active vs selective)."""
        while self.is_running:
            try:
                # Discover pods (handles pod additions/deletions)
                pods = await self.discover_pods()

                # Determine which pods to tail based on phase
                if self.phase == "active":
                    # Active phase: tail all pods
                    pods_to_tail = pods
                    phase_duration = self.ACTIVE_PHASE_DURATION
                else:
                    # Selective phase: only tail noisy pods
                    pods_to_tail = [p for p in pods if p.is_noisy]
                    phase_duration = self.SELECTIVE_PHASE_DURATION

                # Start tailing selected pods
                await self._start_tailing_pods(pods_to_tail)

                # Wait for phase to complete
                await asyncio.sleep(phase_duration)

                # Switch phase
                if self.phase == "active":
                    self.phase = "selective"
                else:
                    self.phase = "active"

                self.phase_start_time = datetime.now()

                # Stop all tails before switching phase
                await self._stop_all_tails()

            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"Error in phase manager: {e}")
                await asyncio.sleep(5)  # Wait before retrying

    async def _start_tailing_pods(self, pods: list[PodTailState]) -> None:
        """Start tailing a list of pods."""
        for pod_state in pods:
            if pod_state.is_active:
                continue  # Already tailing

            # Respect concurrent limit
            if len(self.active_tasks) >= self.MAX_CONCURRENT_TAILS:
                break

            # Start tailing this pod
            task = asyncio.create_task(self._tail_pod(pod_state))
            self.active_tasks[pod_state.pod_key] = task
            pod_state.is_active = True
            pod_state.last_checked = datetime.now()

    async def _tail_pod(self, pod_state: PodTailState) -> None:
        """Tail a single pod and push errors to queue."""
        try:
            async for log_line in self.k8s_client.stream_pod_logs(
                pod_name=pod_state.pod_name, namespace=pod_state.pod_namespace, follow=True, tail_lines=10
            ):
                if not self.is_running:
                    break

                # Parse log line
                error = self.log_parser.parse_log_line(
                    log_line=log_line,
                    pod_name=pod_state.pod_name,
                    pod_namespace=pod_state.pod_namespace,
                    is_waypoint=pod_state.is_waypoint,
                )

                if error:
                    # Enrich error with source pod info if only IP is available
                    enriched_error = await self._enrich_error(error)

                    # Update pod state
                    pod_state.last_error_time = enriched_error.timestamp or datetime.now()
                    pod_state.error_count += 1

                    # Push to queue
                    await self.error_queue.put(enriched_error)

        except asyncio.CancelledError:
            pass
        except Exception as e:
            print(f"Error tailing {pod_state.pod_key}: {e}")
        finally:
            # Cleanup
            pod_state.is_active = False
            if pod_state.pod_key in self.active_tasks:
                del self.active_tasks[pod_state.pod_key]

    async def _enrich_error(self, error: AccessError) -> AccessError:
        """
        Enrich error by resolving source IP to pod and checking mesh enrollment.

        For all ACCESS_DENIED errors with source_ip:
        - Resolve IP to pod (if not already known)
        - Check if pod is enrolled in mesh
        - Reclassify as SOURCE_NOT_ON_MESH if not enrolled
        - Enrich with workload info and SA if enrolled

        Args:
            error: The parsed error

        Returns:
            Enriched error with proper classification
        """
        # Only enrich ACCESS_DENIED errors that have source_ip
        if error.error_type != ErrorType.ACCESS_DENIED or not error.source_ip:
            return error

        # Skip if we don't have mesh adapter (can't check enrollment)
        if not self.mesh_adapter:
            return error

        try:
            # Resolve IP to pod if we don't have workload info
            pod = None
            if not error.source_workload:
                pod = await self.k8s_client.find_pod_by_ip(error.source_ip)

                if not pod:
                    # Could not resolve IP - reclassify as SOURCE_NOT_ON_MESH
                    error.error_type = ErrorType.SOURCE_NOT_ON_MESH
                    error.reason = f"Source pod with IP {error.source_ip} not found"
                    return error

                # Extract pod details
                metadata = pod.get("metadata", {})
                error.source_workload = metadata.get("name")
                error.source_namespace = metadata.get("namespace")
            else:
                # We have workload info from log, look up the pod to verify enrollment
                if error.source_namespace:
                    # Get pod by name and namespace
                    pod = await self.k8s_client.get_pod(name=error.source_workload, namespace=error.source_namespace)

                    if not pod:
                        # Pod not found - likely deleted or workload name is incorrect
                        error.error_type = ErrorType.SOURCE_NOT_ON_MESH
                        error.reason = f"Source pod {error.source_namespace}/{error.source_workload} not found"
                        return error

            # Check if pod is enrolled in mesh
            if pod:
                # Get namespace object
                namespaces = await self.k8s_client.get_namespaces()
                pod_ns_obj = next((ns for ns in namespaces if ns.name == error.source_namespace), None)

                if pod_ns_obj:
                    is_enrolled = self.mesh_adapter.is_pod_enrolled(pod, pod_ns_obj)

                    if not is_enrolled:
                        # Pod not enrolled - reclassify
                        error.error_type = ErrorType.SOURCE_NOT_ON_MESH
                        error.reason = (
                            f"Source pod {error.source_namespace}/{error.source_workload} is not enrolled in mesh"
                        )
                        return error

                    # Pod is enrolled - enrich with service account if we don't have it
                    if not error.source_service_account:
                        spec = pod.get("spec", {})
                        # Get SA from pod spec, default to "default" if not specified
                        # DO NOT use pod name as fallback - that's wrong!
                        # Note: Kubernetes Python client uses snake_case for field names
                        sa_name = spec.get("service_account_name")

                        if sa_name:
                            error.source_service_account = sa_name
                        else:
                            # Pod doesn't have SA specified, Kubernetes uses "default"
                            error.source_service_account = "default"
                            print(
                                f"Warning: Pod {error.source_namespace}/{error.source_workload} has no service_account_name in spec, using 'default'"
                            )

        except Exception as e:
            # On error, keep original classification but log
            print(f"Error enriching access error: {e}")

        return error

    async def _collect_errors(self) -> None:
        """Monitor active tasks and handle completions."""
        while self.is_running:
            await asyncio.sleep(1)

            # Remove completed tasks
            completed = [key for key, task in self.active_tasks.items() if task.done()]
            for key in completed:
                del self.active_tasks[key]

    async def _stop_all_tails(self) -> None:
        """Stop all active tailing tasks."""
        tasks = list(self.active_tasks.values())
        for task in tasks:
            task.cancel()

        # Wait for all to complete
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        self.active_tasks.clear()

        # Update pod states
        for pod_state in self.pod_states.values():
            pod_state.is_active = False

    async def stop(self) -> None:
        """Stop the smart tailer."""
        self.is_running = False
        await self._stop_all_tails()
        # Signal collector to stop
        await self.error_queue.put(None)
