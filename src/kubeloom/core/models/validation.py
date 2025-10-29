"""Policy validation and conflict models."""

from dataclasses import dataclass, field
from enum import Enum


class ConflictSeverity(Enum):
    """Severity levels for policy conflicts."""

    LOW = "LOW"  # Informational, unlikely to cause issues
    MEDIUM = "MEDIUM"  # May cause unexpected behavior
    HIGH = "HIGH"  # Will likely cause issues
    CRITICAL = "CRITICAL"  # Will definitely break functionality


@dataclass
class PolicyConflict:
    """Represents a conflict between policies."""

    severity: ConflictSeverity
    conflicting_policy: str  # namespace/name of conflicting policy
    conflict_type: str  # OVERLAP, CONTRADICTION, PRECEDENCE, etc.
    description: str

    # Specific conflict details
    conflicting_rules: list[str] = field(default_factory=list)
    affected_resources: list[str] = field(default_factory=list)

    # Resolution guidance
    resolution_hint: str | None = None
    recommended_action: str | None = None  # MERGE, DELETE, MODIFY_PRIORITY

    def is_blocking(self) -> bool:
        """Check if this conflict blocks policy application."""
        return self.severity in [ConflictSeverity.HIGH, ConflictSeverity.CRITICAL]


@dataclass
class ValidationError:
    """Represents a validation error in a policy."""

    field: str  # Field path that has the error
    message: str
    suggestion: str | None = None

    def __str__(self) -> str:
        base = f"{self.field}: {self.message}"
        return f"{base} ({self.suggestion})" if self.suggestion else base


@dataclass
class PolicyValidation:
    """Complete validation result for a policy."""

    is_valid: bool
    errors: list[ValidationError] = field(default_factory=list)
    warnings: list[ValidationError] = field(default_factory=list)

    # Best practice suggestions
    suggestions: list[str] = field(default_factory=list)

    # Security findings
    security_issues: list[str] = field(default_factory=list)
    overly_permissive_rules: list[str] = field(default_factory=list)

    # Performance implications
    performance_warnings: list[str] = field(default_factory=list)

    def has_errors(self) -> bool:
        """Check if validation has any errors."""
        return bool(self.errors)

    def has_security_issues(self) -> bool:
        """Check if validation found security issues."""
        return bool(self.security_issues or self.overly_permissive_rules)

    def get_all_issues(self) -> list[str]:
        """Get all issues as a flat list of strings."""
        issues: list[str] = []
        issues.extend(str(e) for e in self.errors)
        issues.extend(str(w) for w in self.warnings)
        issues.extend(self.security_issues)
        issues.extend(self.overly_permissive_rules)
        issues.extend(self.performance_warnings)
        return issues
