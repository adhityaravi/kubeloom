"""Policy action models."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Literal, Optional, Set


class ActionType(Enum):
    """Policy action types."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    AUDIT = "AUDIT"  # Log but don't block
    REDIRECT = "REDIRECT"
    RETRY = "RETRY"
    FAULT_INJECTION = "FAULT_INJECTION"
    RATE_LIMIT = "RATE_LIMIT"
    CUSTOM = "CUSTOM"


class HTTPMethod(Enum):
    """Standard HTTP methods."""

    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"
    CONNECT = "CONNECT"
    TRACE = "TRACE"

    # TODO: WEBDAV methods? Are they relevant?
    # PROPFIND = "PROPFIND"  # WebDAV
    # PROPPATCH = "PROPPATCH"  # WebDAV
    # MKCOL = "MKCOL"  # WebDAV
    # COPY = "COPY"  # WebDAV
    # MOVE = "MOVE"  # WebDAV
    # LOCK = "LOCK"  # WebDAV
    # UNLOCK = "UNLOCK"  # WebDAV

    # Wildcard
    ALL = "*"  # Match all methods

    @classmethod
    def read_methods(cls) -> Set["HTTPMethod"]:
        """Returns read-only HTTP methods."""
        return {cls.GET, cls.HEAD, cls.OPTIONS}

    @classmethod
    def write_methods(cls) -> Set["HTTPMethod"]:
        """Returns methods that modify resources."""
        return {cls.POST, cls.PUT, cls.DELETE, cls.PATCH}


@dataclass
class AllowedRoute:
    """Traffic route specification for policies."""

    methods: Set[HTTPMethod] = field(default_factory=set)
    paths: List[str] = field(default_factory=list)  # URL paths with wildcards: /api/*, /health
    ports: List[int] = field(default_factory=list)  # TCP/UDP ports

    # Protocol-specific fields
    hosts: List[str] = field(default_factory=list)  # DNS names: api.example.com, *.internal
    headers: Dict[str, str] = field(default_factory=dict)  # Required headers
    query_params: Dict[str, str] = field(default_factory=dict)
    protocol: Optional[Literal["HTTP", "HTTPS", "GRPC", "HTTP2", "TCP", "UDP", "TLS"]] = None

    # Special route flags
    allow_all: bool = False
    allow_nothing: bool = False  # Priority difference between deny all and allow nothing. 
    deny_all: bool = False
    deny_nothing: bool = False  # does this exist?

    
@dataclass
class RateLimitConfig:
    """Rate limiting configuration."""

    requests_per_second: Optional[int] = None
    burst_size: Optional[int] = None
    duration_seconds: int = 60
    by_header: Optional[str] = None  # Rate limit by specific header value
    by_remote_ip: bool = False
    by_path: bool = False
    response_status_code: Literal[429, 503] = 429  # Too Many Requests or Service Unavailable


@dataclass
class RetryConfig:
    """Retry policy configuration."""

    attempts: int = 3
    per_try_timeout_seconds: int = 30
    retry_on: Set[Literal["5xx", "4xx", "reset", "connect-failure", "refused-stream"]] = field(default_factory=set)
    retry_on_status_codes: Set[int] = field(default_factory=set)
    backoff_strategy: Literal["exponential", "linear", "fixed"] = "exponential"


@dataclass
class FaultInjectionConfig:
    """Fault injection for testing resilience."""

    delay_percentage: float = 0.0
    delay_seconds: float = 0.0
    abort_percentage: float = 0.0
    abort_status_code: int = 500


@dataclass
class PolicyAction:
    """
    Represents what action a policy takes when conditions match.
    Different from basic ALLOW/DENY - includes traffic management capabilities.
    """

    type: ActionType

    # Basic action modifiers
    enabled: bool = True
    priority: int = 0  # Higher priority actions execute first

    # Traffic management configs
    rate_limit: Optional[RateLimitConfig] = None
    retry: Optional[RetryConfig] = None
    fault_injection: Optional[FaultInjectionConfig] = None

    # Redirect configuration
    redirect_host: Optional[str] = None
    redirect_port: Optional[int] = None
    redirect_scheme: Optional[Literal["http", "https"]] = None
    redirect_path: Optional[str] = None

    # Custom action data for extensibility
    custom_config: Dict[str, any] = field(default_factory=dict)

    # Audit/logging configuration
    log_level: Literal["DEBUG", "INFO", "WARN", "ERROR", "NONE"] = "INFO"
    log_additional_headers: List[str] = field(default_factory=list)
    log_request_body: bool = False
    log_response_body: bool = False

    def is_blocking(self) -> bool:
        """Check if this action blocks traffic."""
        return self.type in [ActionType.DENY, ActionType.REDIRECT]

    def has_traffic_management(self) -> bool:
        """Check if action includes traffic management features."""
        return any([self.rate_limit, self.retry, self.fault_injection])
