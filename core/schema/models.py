"""Pydantic models for canonical schemas.

Mirrors the YAML contracts in schemas/ per core/schema/INTERFACE.md §5.
Field-level nullability and required/optional status follow the YAML
`required:` / `optional:` sections and `nullable:` flags.

Enum types live in core.schema.enums.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator

from core.schema.enums import (
    ActionState,
    ActionType,
    ActorType,
    AlertEventType,
    AlertSeverity,
    CasePriority,
    CaseSeverity,
    CaseStatus,
    CaseType,
    EntityType,
    GroupingOrigin,
)


# ---------------------------------------------------------------------------
# Nested models (used by the four top-level models)
# ---------------------------------------------------------------------------

class RawRef(BaseModel):
    """Structured pointer back to the source event."""

    adapter: str
    rule_id: str
    event_id: str
    index_hint: str | None = None


class NaturalKey(BaseModel):
    """Minimal fields identifying an entity within its tenant.

    Exactly one field is populated for non-unknown entity types;
    enforced at the validator layer, not here.
    """

    user_name: str | None = None
    host_name: str | None = None
    ip_address: str | None = None
    domain_name: str | None = None
    service_name: str | None = None
    app_name: str | None = None


class GroupingKeys(BaseModel):
    """Keys the correlation policy matched on. May be empty."""

    source_ip: str | None = None
    target_user: str | None = None
    target_system: str | None = None
    time_window_seconds: int | None = None


class ExecutionDetails(BaseModel):
    """Outcome summary when an action reached a terminal execution state."""

    success: bool | None = None
    error_message: str | None = None
    duration_ms: int | None = None
    external_ref: str | None = None


# ---------------------------------------------------------------------------
# CanonicalAlert
# ---------------------------------------------------------------------------

class CanonicalAlert(BaseModel):
    """Canonical alert — one normalized detection event."""

    # Required
    id: str
    tenant_id: str
    timestamp: datetime
    source_adapter: str
    event_type: AlertEventType
    source_ip: str
    severity: AlertSeverity
    target_system: str
    raw_ref: RawRef
    raw_payload: dict[str, Any]

    # Optional
    target_user: str | None = None
    actor_user: str | None = None
    source_port: int | None = None
    protocol: str | None = None
    enrichment: dict[str, Any] | None = None

    @field_validator("source_ip")
    @classmethod
    def _validate_source_ip(cls, v: str) -> str:
        ipaddress.ip_address(v)  # raises ValueError on invalid
        return v


# ---------------------------------------------------------------------------
# CanonicalCase
# ---------------------------------------------------------------------------

class CanonicalCase(BaseModel):
    """Canonical case — an investigation grouping one or more alerts."""

    # Required
    id: str
    tenant_id: str
    created_at: datetime
    updated_at: datetime
    status: CaseStatus
    case_type: CaseType | None
    severity: CaseSeverity
    priority: CasePriority
    alert_ids: list[str] = Field(..., min_length=1)
    grouping_keys: GroupingKeys
    grouping_origin: GroupingOrigin

    # Optional
    classification_override: dict[str, Any] | None = None
    assignee: str | None = None
    closed_at: datetime | None = None
    close_reason: str | None = None
    enrichment: dict[str, Any] | None = None
    raw_payload: dict[str, Any] | None = None


# ---------------------------------------------------------------------------
# CanonicalEntity
# ---------------------------------------------------------------------------

class CanonicalEntity(BaseModel):
    """Canonical entity — a user, host, IP, domain, service, or app."""

    # Required
    id: str
    tenant_id: str
    entity_type: EntityType
    natural_key: NaturalKey
    first_seen: datetime
    last_seen: datetime

    # Optional
    attributes: dict[str, Any] | None = None
    aliases: list[str] | None = None
    merged_from: list[str] | None = None
    enrichment: dict[str, Any] | None = None
    raw_payload: dict[str, Any] | None = None


# ---------------------------------------------------------------------------
# CanonicalAction
# ---------------------------------------------------------------------------

class CanonicalAction(BaseModel):
    """Canonical action — one state transition of a response action.

    Event-log model: each instance is a single transition, not the
    logical action. Transitions sharing `action_id` form the history.
    """

    # Required
    id: str
    action_id: str
    tenant_id: str
    occurred_at: datetime
    state: ActionState
    action_type: ActionType
    actor_type: ActorType
    actor_id: str | None

    # Optional
    case_id: str | None = None
    target_entity_ids: list[str] | None = None
    rationale: str | None = None
    approval_ref: str | None = None
    approver_id: str | None = None
    automation_id: str | None = None
    execution_details: ExecutionDetails | None = None
    enrichment: dict[str, Any] | None = None
    raw_payload: dict[str, Any] | None = None