"""Policy validation and conflict models."""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


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
    conflicting_rules: List[str] = field(default_factory=list)
    affected_resources: List[str] = field(default_factory=list)

    # Resolution guidance
    resolution_hint: Optional[str] = None
    recommended_action: Optional[str] = None  # MERGE, DELETE, MODIFY_PRIORITY

    def is_blocking(self) -> bool:
        """Check if this conflict blocks policy application."""
        return self.severity in [ConflictSeverity.HIGH, ConflictSeverity.CRITICAL]


@dataclass
class ValidationError:
    """Represents a validation error in a policy."""

    field: str  # Field path that has the error
    message: str
    suggestion: Optional[str] = None

    def __str__(self) -> str:
        base = f"{self.field}: {self.message}"
        return f"{base} ({self.suggestion})" if self.suggestion else base


@dataclass
class PolicyValidation:
    """Complete validation result for a policy."""

    is_valid: bool
    errors: List[ValidationError] = field(default_factory=list)
    warnings: List[ValidationError] = field(default_factory=list)

    # Best practice suggestions
    suggestions: List[str] = field(default_factory=list)

    # Security findings
    security_issues: List[str] = field(default_factory=list)
    overly_permissive_rules: List[str] = field(default_factory=list)

    # Performance implications
    performance_warnings: List[str] = field(default_factory=list)

    def has_errors(self) -> bool:
        """Check if validation has any errors."""
        return bool(self.errors)

    def has_security_issues(self) -> bool:
        """Check if validation found security issues."""
        return bool(self.security_issues or self.overly_permissive_rules)

    def get_all_issues(self) -> List[str]:
        """Get all issues as a flat list of strings."""
        issues = []
        issues.extend(str(e) for e in self.errors)
        issues.extend(str(w) for w in self.warnings)
        issues.extend(self.security_issues)
        issues.extend(self.overly_permissive_rules)
        issues.extend(self.performance_warnings)
        return issues