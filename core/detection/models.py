"""Pydantic models for the detection engine (Day 7).

DetectionRule — a validated rule loaded from detections/canonical/*.yaml.
ThresholdConfig — {count, window_seconds} nested in DetectionRule.
MatchConfig — {event_type} nested in DetectionRule.
DetectionHit — one output of a rule firing (an "episode" of matching alerts).

These are NOT canonical schemas — they live under core/detection/ and
do not participate in the canonical model/YAML consistency tests.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field, field_validator

from core.schema.enums import AlertEventType


# Fields on CanonicalAlert that a rule may group by. tenant_id is NOT in
# this list because it is always implicit — every detection key is
# tenant-scoped by construction.
_GROUPABLE_FIELDS = frozenset({
    "source_ip",
    "target_system",
    "target_user",
    "actor_user",
    "protocol",
    "source_adapter",
})


class MatchConfig(BaseModel):
    """Predicates an alert must satisfy to enter a rule's window."""

    event_type: AlertEventType


class ThresholdConfig(BaseModel):
    """Fire when `count` alerts land in any `window_seconds`-wide window."""

    count: int = Field(ge=1)
    window_seconds: int = Field(ge=1)


class DetectionRule(BaseModel):
    """A validated detection rule."""

    id: str = Field(min_length=1, pattern=r"^[a-z][a-z0-9_]+$")
    name: str = Field(min_length=1)
    description: str = ""
    version: str = "0.1"

    match: MatchConfig
    threshold: ThresholdConfig
    group_by: list[str] = Field(min_length=1)

    emit_event_type: AlertEventType

    @field_validator("group_by")
    @classmethod
    def _validate_group_by(cls, value: list[str]) -> list[str]:
        if len(set(value)) != len(value):
            raise ValueError(f"group_by contains duplicates: {value!r}")
        for field in value:
            if field not in _GROUPABLE_FIELDS:
                raise ValueError(
                    f"group_by field {field!r} not allowed; "
                    f"allowed: {sorted(_GROUPABLE_FIELDS)}"
                )
        return value

    @property
    def event_type(self) -> AlertEventType:
        """Convenience accessor — flattened view of match.event_type."""
        return self.match.event_type


class DetectionHit(BaseModel):
    """One firing of a rule: an episode of matching alerts."""

    rule_id: str
    tenant_id: str
    alert_ids: list[str] = Field(min_length=1)
    window_start: datetime
    window_end: datetime
    grouping_keys: dict[str, str]
    event_type: AlertEventType