"""Enum types shared across canonical Pydantic models.

Values mirror the strict `enum:` declarations in the YAML schemas.
Where the YAML uses `enum_hint:` (guidance, not constraint), no Enum is
defined here — the model uses `str`.

See core/schema/INTERFACE.md §5 for the enum contract.
"""

from enum import Enum


# --- canonical_alert.yaml ---------------------------------------------------

class AlertEventType(str, Enum):
    AUTH_FAILURE = "auth_failure"
    AUTH_SUCCESS = "auth_success"
    BRUTE_FORCE_DETECTED = "brute_force_detected"


class AlertSeverity(str, Enum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# --- canonical_case.yaml ----------------------------------------------------

class CaseStatus(str, Enum):
    OPEN = "open"
    TRIAGED = "triaged"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"


class CaseType(str, Enum):
    BRUTE_FORCE = "brute_force"
    CREDENTIAL_ACCESS = "credential_access"
    LATERAL_MOVEMENT = "lateral_movement"
    SUSPICIOUS_AUTHENTICATION = "suspicious_authentication"
    UNKNOWN = "unknown"


class CaseSeverity(str, Enum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CasePriority(str, Enum):
    P1 = "p1"
    P2 = "p2"
    P3 = "p3"
    P4 = "p4"


class GroupingOrigin(str, Enum):
    CORRELATION_POLICY = "correlation_policy"
    MANUAL = "manual"
    IMPORT = "import"


# --- canonical_entity.yaml --------------------------------------------------

class EntityType(str, Enum):
    USER = "user"
    HOST = "host"
    IP = "ip"
    DOMAIN = "domain"
    SERVICE = "service"
    APPLICATION = "application"
    UNKNOWN = "unknown"


# --- canonical_action.yaml --------------------------------------------------

class ActionState(str, Enum):
    PROPOSED = "proposed"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTED = "executed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ActionType(str, Enum):
    TRIAGE = "triage"
    CONTAINMENT = "containment"
    INVESTIGATION = "investigation"
    LIFECYCLE = "lifecycle"


class ActorType(str, Enum):
    ANALYST = "analyst"
    AUTOMATION = "automation"
    SYSTEM = "system"