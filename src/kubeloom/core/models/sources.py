"""Policy source and target models."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class PolicySource:
    """Defines where traffic/requests originate from in a policy."""

    # Kubernetes identity
    namespaces: List[str] = field(default_factory=list)
    service_accounts: List[str] = field(default_factory=list)
    workload_labels: Dict[str, str] = field(default_factory=dict)

    # Network sources
    ip_blocks: List[str] = field(default_factory=list)  # CIDR notation: 192.168.1.0/24
    not_ip_blocks: List[str] = field(default_factory=list)  # Exclude these CIDRs

    # Service mesh identity
    principals: List[str] = field(default_factory=list)  # cluster.local/ns/default/sa/my-sa
    not_principals: List[str] = field(default_factory=list)

    # JWT/OAuth sources
    jwt_issuers: List[str] = field(default_factory=list)
    request_principals: List[str] = field(default_factory=list)  # Authenticated user principals
    audiences: List[str] = field(default_factory=list)

    def is_empty(self) -> bool:
        """Check if no source is specified (matches all sources)."""
        return not any([
            self.namespaces,
            self.service_accounts,
            self.workload_labels,
            self.ip_blocks,
            self.principals,
            self.jwt_issuers,
            self.request_principals,
            self.audiences
        ])

    def has_exclusions(self) -> bool:
        """Check if this source has exclusion rules."""
        return bool(self.not_ip_blocks or self.not_principals)


@dataclass
class PolicyTarget:
    """Defines what resources/services a policy applies to."""

    # Kubernetes resources
    namespaces: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    workload_labels: Dict[str, str] = field(default_factory=dict)

    # Specific workload types
    deployments: List[str] = field(default_factory=list)
    statefulsets: List[str] = field(default_factory=list)
    daemonsets: List[str] = field(default_factory=list)
    pods: List[str] = field(default_factory=list)  # Direct pod names

    # Network targets
    hosts: List[str] = field(default_factory=list)  # Service DNS names
    not_hosts: List[str] = field(default_factory=list)  # Exclude these hosts

    # Port-specific targeting
    ports: List[int] = field(default_factory=list)  # Target specific ports only

    def is_empty(self) -> bool:
        """Check if no target is specified (applies to all resources)."""
        return not any([
            self.namespaces,
            self.services,
            self.workload_labels,
            self.deployments,
            self.statefulsets,
            self.daemonsets,
            self.pods,
            self.hosts,
            self.ports
        ])

    def matches_namespace(self, namespace: str) -> bool:
        """Check if this target includes the given namespace."""
        if not self.namespaces:
            return True  # No namespace restriction means all namespaces
        return namespace in self.namespaces

    def matches_service(self, service: str, namespace: str) -> bool:
        """Check if this target includes the given service."""
        if not self.matches_namespace(namespace):
            return False

        if not self.services:
            return True  # No service restriction means all services

        # Check both short name and FQDN
        return (
            service in self.services or
            f"{service}.{namespace}" in self.services or
            f"{service}.{namespace}.svc.cluster.local" in self.services
        )