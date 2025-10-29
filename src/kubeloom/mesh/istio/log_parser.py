"""Parser for Istio ztunnel and waypoint access logs."""

import contextlib
import re
from datetime import datetime
from typing import Any

from kubeloom.core.models.errors import AccessError, ErrorType


class IstioLogParser:
    """Parser for Istio ambient mesh access logs."""

    def __init__(self) -> None:
        """Initialize the log parser."""
        # Ztunnel error patterns in the error field
        self.ztunnel_error_patterns = {
            ErrorType.ACCESS_DENIED: [
                r"connection closed due to policy rejection",
                r"allow policies exist, but none allowed",
            ],
            ErrorType.MTLS_ERROR: [
                r"http status: 401 Unauthorized",
                r"tls|certificate|mtls",
            ],
            ErrorType.CONNECTION_ERROR: [
                r"http status: 503 Service Unavailable",
                r"http status: 502 Bad Gateway",
                r"http status: 504 Gateway Timeout",
                r"connection reset",
                r"connection refused",
            ],
        }

        # Waypoint response codes indicating errors
        self.waypoint_error_codes = {
            403: ErrorType.ACCESS_DENIED,
            401: ErrorType.MTLS_ERROR,
            502: ErrorType.CONNECTION_ERROR,  # Bad Gateway
            503: ErrorType.CONNECTION_ERROR,  # Service Unavailable
            504: ErrorType.CONNECTION_ERROR,  # Gateway Timeout
        }

    def parse_log_line(
        self, log_line: str, pod_name: str, pod_namespace: str, is_waypoint: bool = False
    ) -> AccessError | None:
        """
        Parse a single log line for access errors.

        Args:
            log_line: Raw log line from pod (may have k8s timestamp prefix)
            pod_name: Name of the pod that produced the log
            pod_namespace: Namespace of the pod
            is_waypoint: True if this is from a waypoint, False for ztunnel

        Returns:
            AccessError if an error was detected, None otherwise
        """
        # Extract k8s timestamp prefix if present (RFC3339 format from kubectl logs --timestamps)
        # Format: 2024-10-19T12:34:56.789012345Z <actual log line>
        # or:     2024-10-19T12:34:56.789012345+02:00 <actual log line>
        k8s_timestamp = None
        actual_log_line = log_line

        # Check if line starts with RFC3339 timestamp (matches both Z and +HH:MM timezone formats)
        timestamp_match = re.match(
            r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))\s+(.*)$", log_line
        )
        if timestamp_match:
            k8s_timestamp_str = timestamp_match.group(1)
            actual_log_line = timestamp_match.group(2)

            # Parse k8s timestamp (handles both Z and timezone offsets)
            with contextlib.suppress(ValueError, AttributeError):
                k8s_timestamp = datetime.fromisoformat(k8s_timestamp_str.replace("Z", "+00:00"))

        if is_waypoint:
            error = self._parse_waypoint_log(actual_log_line, pod_name, pod_namespace, k8s_timestamp)
        else:
            error = self._parse_ztunnel_log(actual_log_line, pod_name, pod_namespace, k8s_timestamp)

        return error

    def _parse_ztunnel_log(
        self, log_line: str, pod_name: str, pod_namespace: str, fallback_timestamp: datetime | None = None
    ) -> AccessError | None:
        """
        Parse ztunnel log line (structured key-value format).

        Format: TIMESTAMP LEVEL access connection complete src.addr=... dst.addr=... error="..."
        """
        # Split by tabs and spaces to get fields
        parts = log_line.split("\t")
        if len(parts) < 4:
            return None

        # Parse basic fields
        timestamp_str = parts[0].strip() if len(parts) > 0 else None
        level = parts[1].strip() if len(parts) > 1 else None

        # Only parse error-level logs
        if level != "error":
            return None

        # The rest is key-value pairs - parse them
        kv_text = "\t".join(parts[3:]) if len(parts) > 3 else ""
        fields = self._parse_kv_fields(kv_text)

        # Check for error field
        error_msg = fields.get("error", "")
        if not error_msg:
            return None

        # Determine error type and extract source/destination
        error_type = self._determine_ztunnel_error_type(error_msg, fields)
        source_info = self._extract_ztunnel_source_info(fields)
        dest_info = self._extract_ztunnel_dest_info(fields)

        # Prefer Kubernetes timestamp (has timezone info) over ztunnel's internal timestamp (always UTC)
        timestamp = self._parse_timestamp(timestamp_str, fallback_timestamp)

        return AccessError(
            error_type=error_type,
            source_workload=source_info["workload"],
            source_namespace=source_info["namespace"],
            source_ip=source_info["ip"],
            target_workload=dest_info["workload"],
            target_namespace=dest_info["namespace"],
            target_service=dest_info["service"],
            target_ip=dest_info["ip"],
            target_port=dest_info["port"],
            reason=self._unquote(error_msg),
            raw_message=log_line,
            timestamp=timestamp,
            pod_name=pod_name,
            pod_namespace=pod_namespace,
        )

    def _determine_ztunnel_error_type(self, error_msg: str, fields: dict[str, str]) -> ErrorType:
        """Determine error type from ztunnel error message."""
        error_type = ErrorType.UNKNOWN

        for etype, patterns in self.ztunnel_error_patterns.items():
            for pattern in patterns:
                if re.search(pattern, error_msg, re.IGNORECASE):
                    error_type = etype
                    break
            if error_type != ErrorType.UNKNOWN:
                break

        # If source has no workload identity, it's not enrolled in the mesh
        # Reclassify ACCESS_DENIED as SOURCE_NOT_ON_MESH
        src_workload = self._unquote(fields.get("src.workload", ""))
        if error_type == ErrorType.ACCESS_DENIED and not src_workload:
            error_type = ErrorType.SOURCE_NOT_ON_MESH

        return error_type

    def _extract_ztunnel_source_info(self, fields: dict[str, str]) -> dict[str, str | None]:
        """Extract source information from ztunnel log fields."""
        src_addr = fields.get("src.addr", "")
        src_ip, _ = self._split_addr(src_addr)
        src_workload = self._unquote(fields.get("src.workload", ""))
        src_namespace = self._unquote(fields.get("src.namespace", ""))

        return {
            "ip": src_ip or None,
            "workload": src_workload or None,
            "namespace": src_namespace or None,
        }

    def _extract_ztunnel_dest_info(self, fields: dict[str, str]) -> dict[str, Any | None]:
        """Extract destination information from ztunnel log fields."""
        dst_addr = fields.get("dst.addr", "")
        dst_ip, dst_port = self._split_addr(dst_addr)
        dst_workload = self._unquote(fields.get("dst.workload", ""))
        dst_namespace = self._unquote(fields.get("dst.namespace", ""))
        dst_service = self._unquote(fields.get("dst.service", ""))

        return {
            "ip": dst_ip or None,
            "port": dst_port,
            "workload": dst_workload or None,
            "namespace": dst_namespace or None,
            "service": dst_service or None,
        }

    def _parse_timestamp(self, timestamp_str: str | None, fallback: datetime | None) -> datetime | None:
        """Parse timestamp with fallback."""
        timestamp = fallback

        if not timestamp and timestamp_str:
            with contextlib.suppress(ValueError, AttributeError):
                timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))

        return timestamp

    def _parse_waypoint_log(
        self, log_line: str, pod_name: str, pod_namespace: str, fallback_timestamp: datetime | None = None
    ) -> AccessError | None:
        """
        Parse waypoint log line (Envoy access log format).

        Format: [TIMESTAMP] "METHOD /path HTTP/VERSION" CODE FLAGS ... "USER_AGENT" "REQ_ID" "HOST" "UPSTREAM" ...
        """
        # Parse timestamp
        timestamp = self._parse_waypoint_timestamp(log_line, fallback_timestamp)

        # Extract request information
        request_info = self._extract_waypoint_request_info(log_line)

        # Extract response code and check if it's an error
        response_code = self._extract_response_code(log_line)
        if response_code is None or response_code not in self.waypoint_error_codes:
            return None

        error_type = self.waypoint_error_codes[response_code]

        # Extract service and network information
        service_info = self._extract_waypoint_service_info(log_line)
        source_ip = self._extract_waypoint_source_ip(log_line)

        # Generate reason based on response code
        reason = self._get_error_reason(response_code)

        return AccessError(
            error_type=error_type,
            source_ip=source_ip,
            target_service=service_info["service"],
            target_namespace=service_info["namespace"],
            target_ip=service_info["ip"],
            target_port=service_info["port"],
            http_method=request_info["method"],
            http_path=request_info["path"],
            http_version=request_info["version"],
            http_status_code=response_code,
            reason=reason,
            raw_message=log_line,
            timestamp=timestamp,
            pod_name=pod_name,
            pod_namespace=pod_namespace,
        )

    def _parse_waypoint_timestamp(self, log_line: str, fallback: datetime | None) -> datetime | None:
        """Parse timestamp from waypoint log with fallback."""
        timestamp = fallback

        if not timestamp:
            timestamp_match = re.match(r"\[([^\]]+)\]", log_line)
            if timestamp_match:
                try:
                    timestamp_str = timestamp_match.group(1)
                    timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
                except (ValueError, AttributeError):
                    pass

        return timestamp

    def _extract_waypoint_request_info(self, log_line: str) -> dict[str, str | None]:
        """Extract HTTP request information from waypoint log."""
        request_match = re.search(r'"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+([^\s]+)\s+(HTTP/[^"]*)"', log_line)

        if request_match:
            return {
                "method": request_match.group(1),
                "path": request_match.group(2),
                "version": request_match.group(3) if request_match.group(3) else None,
            }

        return {"method": None, "path": None, "version": None}

    def _extract_response_code(self, log_line: str) -> int | None:
        """Extract HTTP response code from waypoint log."""
        code_match = re.search(r'"\s+(\d{3})\s+', log_line)
        if code_match:
            return int(code_match.group(1))
        return None

    def _extract_waypoint_service_info(self, log_line: str) -> dict[str, Any | None]:
        """Extract service and target information from waypoint log."""
        # Extract host (service): "host:port"
        host_match = re.search(r'"([a-z0-9.-]+\.svc\.cluster\.local:\d+)"', log_line)
        target_service = host_match.group(1) if host_match else None
        target_port = None
        target_namespace = None

        if target_service and ":" in target_service:
            parts = target_service.rsplit(":", 1)
            target_service = parts[0]
            with contextlib.suppress(ValueError, IndexError):
                target_port = int(parts[1])

        # Extract namespace from FQDN service name
        if target_service and ".svc.cluster.local" in target_service:
            service_parts = target_service.split(".")
            if len(service_parts) >= 2:
                target_namespace = service_parts[1]
                target_service = service_parts[0]

        # Extract upstream (target IP)
        target_ip = self._extract_waypoint_upstream_ip(log_line, target_port)

        return {
            "service": target_service,
            "namespace": target_namespace,
            "ip": target_ip["ip"],
            "port": target_ip["port"] if target_ip["port"] else target_port,
        }

    def _extract_waypoint_upstream_ip(self, log_line: str, fallback_port: int | None) -> dict[str, Any | None]:
        """Extract upstream IP and port from waypoint log."""
        upstream_match = re.search(r'"envoy://connect_originate/([^"]+)"', log_line)
        if upstream_match:
            upstream = upstream_match.group(1)
            ip, port = self._split_addr(upstream)
            return {"ip": ip, "port": port if port else fallback_port}

        return {"ip": None, "port": None}

    def _extract_waypoint_source_ip(self, log_line: str) -> str | None:
        """Extract source IP from waypoint log."""
        source_match = re.search(r"(\d+\.\d+\.\d+\.\d+:\d+)\s+-\s+\w+\s*$", log_line)
        if source_match:
            source_addr = source_match.group(1)
            source_ip, _ = self._split_addr(source_addr)
            return source_ip
        return None

    def _get_error_reason(self, response_code: int) -> str:
        """Get human-readable error reason from response code."""
        reason_map = {
            403: "Access denied by authorization policy",
            401: "Authentication failed (mTLS error)",
            502: "Bad gateway - connection issue",
            503: "Service unavailable - destination not ready",
            504: "Gateway timeout - destination not responding",
        }
        return reason_map.get(response_code, f"HTTP {response_code}")

    def _parse_kv_fields(self, text: str) -> dict[str, str]:
        """
        Parse key=value pairs from ztunnel log line.

        Handles both simple values and quoted values.
        Example: src.addr=10.1.2.3:4567 src.workload="my-pod" dst.service="my-svc.ns.svc.cluster.local"
        """
        fields = {}

        # Pattern to match key=value or key="quoted value"
        pattern = r'(\S+?)=(?:"([^"]*)"|(\S+))'

        for match in re.finditer(pattern, text):
            key = match.group(1)
            # Either quoted value (group 2) or unquoted value (group 3)
            value = match.group(2) if match.group(2) is not None else match.group(3)
            fields[key] = value

        return fields

    def _split_addr(self, addr: str) -> tuple[str | None, int | None]:
        """Split address into IP and port."""
        if not addr or ":" not in addr:
            return addr or None, None

        try:
            ip, port_str = addr.rsplit(":", 1)
            port = int(port_str)
            return ip, port
        except (ValueError, AttributeError):
            return addr, None

    def _unquote(self, value: str) -> str:
        """Remove surrounding quotes from a value."""
        if value and len(value) >= 2 and value[0] == '"' and value[-1] == '"':
            return value[1:-1]
        return value
