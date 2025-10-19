"""Parser for Istio ztunnel and waypoint access logs."""

import re
from datetime import datetime
from typing import Optional, Dict

from ...core.models.errors import AccessError, ErrorType


class IstioLogParser:
    """Parser for Istio ambient mesh access logs."""

    def __init__(self):
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
        }

        # Waypoint response codes indicating errors
        self.waypoint_error_codes = {
            403: ErrorType.ACCESS_DENIED,
            401: ErrorType.MTLS_ERROR,
            502: ErrorType.CONNECTION_ERROR,  # Often indicates policy/connection issues
        }

    def parse_log_line(
        self,
        log_line: str,
        pod_name: str,
        pod_namespace: str,
        is_waypoint: bool = False
    ) -> Optional[AccessError]:
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
        timestamp_match = re.match(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))\s+(.*)$', log_line)
        if timestamp_match:
            k8s_timestamp_str = timestamp_match.group(1)
            actual_log_line = timestamp_match.group(2)

            # Parse k8s timestamp (handles both Z and timezone offsets)
            try:
                k8s_timestamp = datetime.fromisoformat(k8s_timestamp_str.replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                pass

        if is_waypoint:
            error = self._parse_waypoint_log(actual_log_line, pod_name, pod_namespace, k8s_timestamp)
        else:
            error = self._parse_ztunnel_log(actual_log_line, pod_name, pod_namespace, k8s_timestamp)

        return error

    def _parse_ztunnel_log(
        self,
        log_line: str,
        pod_name: str,
        pod_namespace: str,
        fallback_timestamp: Optional[datetime] = None
    ) -> Optional[AccessError]:
        """
        Parse ztunnel log line (structured key-value format).

        Format: TIMESTAMP LEVEL access connection complete src.addr=... dst.addr=... error="..."
        """
        # Split by tabs and spaces to get fields
        parts = log_line.split('\t')
        if len(parts) < 4:
            return None

        # Parse basic fields
        timestamp_str = parts[0].strip() if len(parts) > 0 else None
        level = parts[1].strip() if len(parts) > 1 else None

        # Only parse error-level logs
        if level != "error":
            return None

        # The rest is key-value pairs - parse them
        kv_text = '\t'.join(parts[3:]) if len(parts) > 3 else ""
        fields = self._parse_kv_fields(kv_text)

        # Check for error field
        error_msg = fields.get("error", "")
        if not error_msg:
            return None

        # Determine error type from error message
        error_type = ErrorType.UNKNOWN
        for etype, patterns in self.ztunnel_error_patterns.items():
            for pattern in patterns:
                if re.search(pattern, error_msg, re.IGNORECASE):
                    error_type = etype
                    break
            if error_type != ErrorType.UNKNOWN:
                break

        # Extract source info
        src_addr = fields.get("src.addr", "")
        src_ip, src_port = self._split_addr(src_addr)
        src_workload = self._unquote(fields.get("src.workload", ""))
        src_namespace = self._unquote(fields.get("src.namespace", ""))

        # Extract destination info
        dst_addr = fields.get("dst.addr", "")
        dst_ip, dst_port = self._split_addr(dst_addr)
        dst_workload = self._unquote(fields.get("dst.workload", ""))
        dst_namespace = self._unquote(fields.get("dst.namespace", ""))
        dst_service = self._unquote(fields.get("dst.service", ""))

        # Prefer Kubernetes timestamp (has timezone info) over ztunnel's internal timestamp (always UTC)
        # Only parse ztunnel timestamp as fallback if K8s timestamp wasn't provided
        timestamp = fallback_timestamp

        if not timestamp and timestamp_str:
            try:
                timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                pass

        return AccessError(
            error_type=error_type,
            source_workload=src_workload or None,
            source_namespace=src_namespace or None,
            source_ip=src_ip or None,
            target_workload=dst_workload or None,
            target_namespace=dst_namespace or None,
            target_service=dst_service or None,
            target_ip=dst_ip or None,
            target_port=dst_port,
            reason=self._unquote(error_msg),
            raw_message=log_line,
            timestamp=timestamp,
            pod_name=pod_name,
            pod_namespace=pod_namespace
        )

    def _parse_waypoint_log(
        self,
        log_line: str,
        pod_name: str,
        pod_namespace: str,
        fallback_timestamp: Optional[datetime] = None
    ) -> Optional[AccessError]:
        """
        Parse waypoint log line (Envoy access log format).

        Format: [TIMESTAMP] "METHOD /path HTTP/VERSION" CODE FLAGS ... "USER_AGENT" "REQ_ID" "HOST" "UPSTREAM" ...
        """
        # Prefer Kubernetes timestamp (has timezone info) over Envoy's internal timestamp
        # Only parse Envoy timestamp as fallback if K8s timestamp wasn't provided
        timestamp = fallback_timestamp

        if not timestamp:
            # Try to extract timestamp from Envoy log
            timestamp_match = re.match(r'\[([^\]]+)\]', log_line)
            if timestamp_match:
                try:
                    timestamp_str = timestamp_match.group(1)
                    timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
                except (ValueError, AttributeError):
                    pass

        # Extract request line: "METHOD /path HTTP/VERSION"
        request_match = re.search(r'"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+([^\s]+)\s+(HTTP/[^"]*)"', log_line)
        method = None
        path = None
        http_version = None
        if request_match:
            method = request_match.group(1)
            path = request_match.group(2)
            http_version = request_match.group(3) if request_match.group(3) else None  # e.g., "HTTP/2", "HTTP/1.1"

        # Extract response code (comes after the quoted request line)
        code_match = re.search(r'"\s+(\d{3})\s+', log_line)
        if not code_match:
            return None

        response_code = int(code_match.group(1))

        # Check if this is an error response
        if response_code not in self.waypoint_error_codes:
            return None

        error_type = self.waypoint_error_codes[response_code]

        # Extract host (service): "host:port"
        host_match = re.search(r'"([^"]+:\d+)"\s+"envoy://', log_line)
        target_service = host_match.group(1) if host_match else None
        target_port = None
        if target_service and ":" in target_service:
            parts = target_service.rsplit(":", 1)
            target_service = parts[0]
            try:
                target_port = int(parts[1])
            except (ValueError, IndexError):
                pass

        # Extract upstream (target): "envoy://connect_originate/IP:PORT"
        upstream_match = re.search(r'"envoy://connect_originate/([^"]+)"', log_line)
        target_ip = None
        if upstream_match:
            upstream = upstream_match.group(1)
            ip, port = self._split_addr(upstream)
            target_ip = ip
            if not target_port and port:
                target_port = port

        # Extract source IP (last IP:PORT before the dash at the end)
        # Format: ... 10.152.183.60:4318 10.1.239.92:56156 - default
        source_match = re.search(r'(\d+\.\d+\.\d+\.\d+:\d+)\s+-\s+\w+\s*$', log_line)
        source_ip = None
        if source_match:
            source_addr = source_match.group(1)
            source_ip, _ = self._split_addr(source_addr)

        # Generate reason based on response code
        reason_map = {
            403: "Access denied by authorization policy",
            401: "Authentication failed (mTLS error)",
            502: "Bad gateway - possible policy or connection issue",
        }
        reason = reason_map.get(response_code, f"HTTP {response_code}")

        return AccessError(
            error_type=error_type,
            source_ip=source_ip,
            target_service=target_service,
            target_ip=target_ip,
            target_port=target_port,
            http_method=method,
            http_path=path,
            http_version=http_version,
            http_status_code=response_code,
            reason=reason,
            raw_message=log_line,
            timestamp=timestamp,
            pod_name=pod_name,
            pod_namespace=pod_namespace
        )

    def _parse_kv_fields(self, text: str) -> Dict[str, str]:
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

    def _split_addr(self, addr: str) -> tuple[Optional[str], Optional[int]]:
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
