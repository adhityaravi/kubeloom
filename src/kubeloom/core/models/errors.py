"""Models for access errors and log analysis."""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Optional


class ErrorType(Enum):
    """Type of access error."""
    ACCESS_DENIED = "access_denied"
    MTLS_ERROR = "mtls_error"
    CONNECTION_ERROR = "connection_error"
    UNKNOWN = "unknown"


@dataclass
class AccessError:
    """Represents a parsed access error from mesh logs."""

    # Error classification
    error_type: ErrorType

    # Source information
    source_workload: Optional[str] = None
    source_namespace: Optional[str] = None
    source_service_account: Optional[str] = None
    source_ip: Optional[str] = None

    # Target information
    target_workload: Optional[str] = None
    target_namespace: Optional[str] = None
    target_service: Optional[str] = None
    target_ip: Optional[str] = None
    target_port: Optional[int] = None

    # Request details (for L7)
    http_method: Optional[str] = None
    http_path: Optional[str] = None
    http_version: Optional[str] = None  # e.g., "HTTP/1.1", "HTTP/2"
    http_status_code: Optional[int] = None  # e.g., 502, 403, 401

    # Error details
    reason: str = ""
    raw_message: str = ""

    # Metadata
    timestamp: Optional[datetime] = None
    pod_name: Optional[str] = None
    pod_namespace: Optional[str] = None

    def __hash__(self):
        """Make error hashable for deduplication."""
        return hash((
            self.error_type,
            self.source_workload,
            self.source_namespace,
            self.target_workload,
            self.target_namespace,
            self.target_service,
            self.target_port,
            self.http_method,
            self.http_path,
            self.reason
        ))

    def __eq__(self, other):
        """Compare errors for deduplication."""
        if not isinstance(other, AccessError):
            return False
        return (
            self.error_type == other.error_type and
            self.source_workload == other.source_workload and
            self.source_namespace == other.source_namespace and
            self.target_workload == other.target_workload and
            self.target_namespace == other.target_namespace and
            self.target_service == other.target_service and
            self.target_port == other.target_port and
            self.http_method == other.http_method and
            self.http_path == other.http_path and
            self.reason == other.reason
        )

    def to_display_string(self) -> str:
        """Convert error to user-friendly display string."""
        parts = []

        # Source info
        if self.source_workload or self.source_namespace:
            source = f"{self.source_namespace}/{self.source_workload}" if self.source_namespace and self.source_workload else (self.source_workload or self.source_namespace)
            parts.append(f"Source: {source}")
        elif self.source_ip:
            parts.append(f"Source IP: {self.source_ip}")

        # Target info
        if self.target_service or self.target_workload:
            target = self.target_service or self.target_workload
            if self.target_namespace:
                target = f"{self.target_namespace}/{target}"
            if self.target_port:
                target = f"{target}:{self.target_port}"
            parts.append(f"Target: {target}")
        elif self.target_ip:
            target = self.target_ip
            if self.target_port:
                target = f"{target}:{self.target_port}"
            parts.append(f"Target: {target}")

        # Request details
        if self.http_method or self.http_path:
            request = ""
            if self.http_method:
                request = self.http_method
            if self.http_path:
                request = f"{request} {self.http_path}" if request else self.http_path
            parts.append(f"Request: {request}")

        # Error type and reason
        error_desc = self.error_type.value.replace("_", " ").title()
        if self.reason:
            parts.append(f"Reason: {self.reason}")
        else:
            parts.append(f"Type: {error_desc}")

        return " | ".join(parts)
