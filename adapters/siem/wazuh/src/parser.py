"""Wazuh → SOCForge canonical alert parser (Day 5).

Translates ONE Wazuh alert object into ONE canonical alert dictionary
conforming to schemas/canonical_alert.yaml v0.1.

Design contract:
  - tenant_id is supplied by trusted context (kwarg), never read from
    the untrusted Wazuh event.
  - Required source data missing/malformed → WazuhParseError.
  - Optional source data absent → field omitted from output.
  - The parser never invents values for required fields.
  - raw_payload preserves the complete source event as received
    (the test-only `_fixture` block is stripped by the caller, not here).
  - Canonical id is namespaced as "wazuh:{manager.name}:{native_id}" to
    guarantee uniqueness across Wazuh managers (Day 6 Decision #5).

See docs/integrations/wazuh.md for the full mapping table.
"""

from __future__ import annotations

import copy
import ipaddress
from datetime import datetime, timezone
from typing import Any

from core.schema.enums import AlertEventType, AlertSeverity


class WazuhParseError(ValueError):
    """Raised when a Wazuh event cannot be translated to a canonical alert."""


# ---------------------------------------------------------------------------
# Classification (rule-ID first, groups fallback)
# ---------------------------------------------------------------------------

_RULE_ID_TO_EVENT_TYPE: dict[str, AlertEventType] = {
    "5712": AlertEventType.BRUTE_FORCE_DETECTED,
    "5715": AlertEventType.AUTH_SUCCESS,
    "5710": AlertEventType.AUTH_FAILURE,
    "5760": AlertEventType.AUTH_FAILURE,
}

_GROUP_TO_EVENT_TYPE: dict[str, AlertEventType] = {
    "authentication_success": AlertEventType.AUTH_SUCCESS,
    "authentication_failed": AlertEventType.AUTH_FAILURE,
}


# ---------------------------------------------------------------------------
# Severity (Wazuh rule.level 0-15 -> canonical enum)
# ---------------------------------------------------------------------------

def _severity_from_level(level: int) -> AlertSeverity:
    if 0 <= level <= 3:
        return AlertSeverity.INFORMATIONAL
    if 4 <= level <= 6:
        return AlertSeverity.LOW
    if 7 <= level <= 9:
        return AlertSeverity.MEDIUM
    if 10 <= level <= 12:
        return AlertSeverity.HIGH
    if 13 <= level <= 15:
        return AlertSeverity.CRITICAL
    raise WazuhParseError(f"rule.level out of range [0,15]: {level!r}")


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _require(mapping: dict, key: str, where: str) -> Any:
    """Return mapping[key] or raise WazuhParseError."""
    if key not in mapping or mapping[key] is None:
        raise WazuhParseError(f"Missing required field: {where}.{key}")
    return mapping[key]


def _require_int_not_bool(value: Any, field: str) -> int:
    """Coerce value to int, rejecting bool (an int subclass) and floats."""
    if isinstance(value, bool):
        raise WazuhParseError(f"{field} must be an integer, got bool {value!r}")
    if isinstance(value, float):
        raise WazuhParseError(f"{field} must be an integer, got float {value!r}")
    try:
        return int(value)
    except (TypeError, ValueError):
        raise WazuhParseError(
            f"{field} must be an integer, got {value!r}"
        ) from None


def _optional_nonempty_str(value: Any, field: str) -> str:
    """Validate an optional scalar: if present, must be a non-empty string."""
    if not isinstance(value, str):
        raise WazuhParseError(
            f"{field} must be a string, got {type(value).__name__}"
        )
    if value == "":
        raise WazuhParseError(f"{field} must be non-empty when present")
    return value


def _normalize_timestamp(value: Any) -> str:
    """Parse ISO 8601, require tz-aware, return UTC-normalized string."""
    if not isinstance(value, str):
        raise WazuhParseError(
            f"timestamp must be a string, got {type(value).__name__}"
        )
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise WazuhParseError(
            f"timestamp is not valid ISO 8601: {value!r}"
        ) from None
    if parsed.tzinfo is None:
        raise WazuhParseError(
            f"timestamp must include a timezone offset: {value!r}"
        )
    return parsed.astimezone(timezone.utc).isoformat()


def _mitre_list(mitre: dict, key: str) -> list[str]:
    """Return mitre[key] as a validated list[str]."""
    value = mitre.get(key, [])
    if not isinstance(value, list):
        raise WazuhParseError(
            f"rule.mitre.{key} must be a list, got {type(value).__name__}"
        )
    for i, item in enumerate(value):
        if not isinstance(item, str):
            raise WazuhParseError(
                f"rule.mitre.{key}[{i}] must be a string, got {type(item).__name__}"
            )
    return list(value)


def _classify(rule: dict) -> AlertEventType:
    rule_id = str(rule.get("id", ""))
    if rule_id in _RULE_ID_TO_EVENT_TYPE:
        return _RULE_ID_TO_EVENT_TYPE[rule_id]
    groups = rule.get("groups") or []
    if isinstance(groups, list):
        for group in groups:
            if group in _GROUP_TO_EVENT_TYPE:
                return _GROUP_TO_EVENT_TYPE[group]
    raise WazuhParseError(
        f"Cannot classify Wazuh event: rule.id={rule_id!r}, groups={groups!r}"
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse(raw: dict, *, tenant_id: str) -> dict:
    """Translate one Wazuh alert into a canonical alert dictionary.

    Raises:
        WazuhParseError: when required source data is missing, a mapped
            value is malformed, the event cannot be classified, or
            tenant_id is invalid.
    """
    if not tenant_id or not isinstance(tenant_id, str):
        raise WazuhParseError(
            f"tenant_id must be a non-empty string, got {tenant_id!r}"
        )
    if not isinstance(raw, dict):
        raise WazuhParseError(f"raw must be a dict, got {type(raw).__name__}")

    # --- Required top-level fields ---
    event_id = _optional_nonempty_str(_require(raw, "id", "raw"), "id")
    timestamp_str = _require(raw, "timestamp", "raw")
    rule = _require(raw, "rule", "raw")
    if not isinstance(rule, dict):
        raise WazuhParseError("rule must be a JSON object")

    rule_id = _require(rule, "id", "raw.rule")
    level_raw = _require(rule, "level", "raw.rule")
    level = _require_int_not_bool(level_raw, "rule.level")
    if level < 0 or level > 15:
        raise WazuhParseError(f"rule.level out of range [0,15]: {level}")

    # --- agent / target_system ---
    agent = raw.get("agent") or {}
    if not isinstance(agent, dict):
        raise WazuhParseError("agent must be a JSON object")
    agent_name = agent.get("name")
    agent_id = agent.get("id")
    if agent_name is not None:
        target_system = _optional_nonempty_str(agent_name, "agent.name")
    elif agent_id is not None:
        target_system = _optional_nonempty_str(agent_id, "agent.id")
    else:
        raise WazuhParseError(
            "Neither agent.name nor agent.id is present — cannot determine target_system"
        )

    # --- manager (required for namespacing canonical id) ---
    manager = raw.get("manager") or {}
    if not isinstance(manager, dict):
        raise WazuhParseError("manager must be a JSON object")
    manager_name = manager.get("name")
    if not manager_name or not isinstance(manager_name, str) or manager_name.strip() == "":
        raise WazuhParseError(
            "manager.name is required to namespace the canonical id"
        )

    # --- data / source_ip ---
    data = raw.get("data") or {}
    if not isinstance(data, dict):
        raise WazuhParseError("data must be a JSON object")
    srcip = _require(data, "srcip", "raw.data")
    if not isinstance(srcip, str):
        raise WazuhParseError(f"data.srcip must be a string, got {type(srcip).__name__}")
    try:
        ipaddress.ip_address(srcip)
    except ValueError:
        raise WazuhParseError(f"data.srcip is not a valid IP literal: {srcip!r}") from None

    # --- timestamp ---
    canonical_timestamp = _normalize_timestamp(timestamp_str)

    # --- classification and severity ---
    event_type = _classify(rule)
    severity = _severity_from_level(level)

    # --- raw_ref ---
    raw_ref: dict[str, Any] = {
        "adapter": "wazuh",
        "rule_id": str(rule_id),
        "event_id": str(event_id),
    }
    location = raw.get("location")
    if location is not None:
        raw_ref["index_hint"] = _optional_nonempty_str(location, "location")

    # --- Assemble canonical dict ---
    namespaced_id = f"wazuh:{manager_name}:{event_id}"
    canonical: dict[str, Any] = {
        "id": namespaced_id,
        "tenant_id": tenant_id,
        "timestamp": canonical_timestamp,
        "source_adapter": "wazuh",
        "event_type": event_type.value,
        "source_ip": srcip,
        "severity": severity.value,
        "target_system": target_system,
        "raw_ref": raw_ref,
        "raw_payload": copy.deepcopy(raw),
    }

    # --- Optional fields: omit when absent, raise when malformed ---
    dstuser = data.get("dstuser")
    if dstuser is not None:
        canonical["target_user"] = _optional_nonempty_str(dstuser, "data.dstuser")

    srcport = data.get("srcport")
    if srcport is not None:
        port = _require_int_not_bool(srcport, "data.srcport")
        if port < 1 or port > 65535:
            raise WazuhParseError(
                f"data.srcport out of range [1,65535]: {port}"
            )
        canonical["source_port"] = port

    protocol = data.get("protocol")
    if protocol is not None:
        canonical["protocol"] = _optional_nonempty_str(protocol, "data.protocol")

    mitre = rule.get("mitre")
    if mitre is not None:
        if not isinstance(mitre, dict):
            raise WazuhParseError("rule.mitre must be a JSON object")
        canonical["enrichment"] = {
            "mitre": {
                "id": _mitre_list(mitre, "id"),
                "tactic": _mitre_list(mitre, "tactic"),
                "technique": _mitre_list(mitre, "technique"),
            }
        }

    return canonical