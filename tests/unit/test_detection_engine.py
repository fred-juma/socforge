"""Tests for core.detection.engine (Day 7 TDD).

Written before core/detection/engine.py.

The engine is a **batch pure function**:
    hits = run(alerts, rules)

Alerts are canonical dicts (validated shape). Engine sorts by timestamp
internally, so caller order is irrelevant.

Episode semantics (locked Day 7):
  - Fire once per episode when sliding count first reaches threshold.
  - Suppress while count stays ≥ threshold.
  - Re-fire only after count drops below threshold and later re-crosses.
  - window_start anchored to first alert of episode; does not shift.
  - Window is half-open [start, start + window_seconds).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
TENANT = "org_aa"
BASE = datetime(2026, 10, 14, 9, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _alert(
    *,
    offset_seconds: float,
    source_ip: str = "203.0.113.47",
    target_user: str | None = "deploy",
    event_type: str = "auth_failure",
    alert_id: str | None = None,
    tenant_id: str = TENANT,
) -> dict:
    """Minimal canonical alert dict for engine tests."""
    ts = (BASE + timedelta(seconds=offset_seconds)).isoformat()
    d = {
        "id": alert_id or f"alert-{offset_seconds}",
        "tenant_id": tenant_id,
        "timestamp": ts,
        "source_adapter": "wazuh",
        "event_type": event_type,
        "source_ip": source_ip,
        "severity": "low",
        "target_system": "web-server-01",
        "raw_ref": {
            "adapter": "wazuh",
            "rule_id": "5760",
            "event_id": alert_id or f"alert-{offset_seconds}",
        },
        "raw_payload": {},
    }
    if target_user is not None:
        d["target_user"] = target_user
    return d


def _brute_force_rule():
    from core.detection.models import DetectionRule, MatchConfig, ThresholdConfig
    from core.schema.enums import AlertEventType

    return DetectionRule(
        id="brute_force",
        name="SSH brute-force detected",
        description="test",
        version="0.1",
        match=MatchConfig(event_type=AlertEventType.AUTH_FAILURE),
        threshold=ThresholdConfig(count=5, window_seconds=300),
        group_by=["source_ip", "target_user"],
        emit_event_type=AlertEventType.BRUTE_FORCE_DETECTED,
    )


# ---------------------------------------------------------------------------
# Threshold behaviour
# ---------------------------------------------------------------------------

def test_six_within_window_fires_hit():
    from core.detection.engine import run

    alerts = [_alert(offset_seconds=i * 10) for i in range(6)]
    hits = run(alerts, [_brute_force_rule()])

    assert len(hits) == 1
    assert len(hits[0].alert_ids) == 5  # up to + including the one crossing threshold


def test_three_within_window_no_hit():
    from core.detection.engine import run

    alerts = [_alert(offset_seconds=i * 10) for i in range(3)]
    assert run(alerts, [_brute_force_rule()]) == []


def test_five_exactly_fires():
    """Boundary: exactly threshold fires."""
    from core.detection.engine import run

    alerts = [_alert(offset_seconds=i * 10) for i in range(5)]
    hits = run(alerts, [_brute_force_rule()])
    assert len(hits) == 1
    assert len(hits[0].alert_ids) == 5


def test_six_spread_outside_window_no_hit():
    """6 alerts 80s apart — never 5 within any 300s window."""
    from core.detection.engine import run

    alerts = [_alert(offset_seconds=i * 80) for i in range(6)]
    assert run(alerts, [_brute_force_rule()]) == []


def test_boundary_alert_at_exactly_300s_does_not_count():
    """Half-open window: alert at exactly start+window is OUT."""
    from core.detection.engine import run

    alerts = [_alert(offset_seconds=i * 10) for i in range(4)]  # 0..30
    alerts.append(_alert(offset_seconds=300, alert_id="boundary"))
    assert run(alerts, [_brute_force_rule()]) == []


def test_boundary_alert_at_299s_counts():
    """Alert at 299s is INSIDE the window."""
    from core.detection.engine import run

    alerts = [_alert(offset_seconds=i * 10) for i in range(4)]  # 0..30
    alerts.append(_alert(offset_seconds=299, alert_id="boundary"))
    hits = run(alerts, [_brute_force_rule()])
    assert len(hits) == 1
    assert len(hits[0].alert_ids) == 5


# ---------------------------------------------------------------------------
# Grouping
# ---------------------------------------------------------------------------

def test_different_source_ip_not_grouped():
    from core.detection.engine import run

    alerts = []
    for i in range(3):
        alerts.append(_alert(offset_seconds=i * 10, source_ip="203.0.113.47"))
    for i in range(3):
        alerts.append(_alert(offset_seconds=100 + i * 10, source_ip="198.51.100.22"))
    assert run(alerts, [_brute_force_rule()]) == []


def test_different_target_user_not_grouped():
    from core.detection.engine import run

    alerts = []
    for i in range(3):
        alerts.append(_alert(offset_seconds=i * 10, target_user="deploy"))
    for i in range(3):
        alerts.append(_alert(offset_seconds=100 + i * 10, target_user="root"))
    assert run(alerts, [_brute_force_rule()]) == []


def test_different_tenants_not_grouped():
    from core.detection.engine import run

    alerts = []
    for i in range(3):
        alerts.append(_alert(offset_seconds=i * 10, tenant_id="org_aa"))
    for i in range(3):
        alerts.append(
            _alert(offset_seconds=100 + i * 10, tenant_id="org_bb", alert_id=f"bb-{i}")
        )
    assert run(alerts, [_brute_force_rule()]) == []


def test_alert_without_target_user_excluded():
    """Group key requires target_user; missing → alert skipped."""
    from core.detection.engine import run

    alerts = [_alert(offset_seconds=i * 10, target_user=None) for i in range(10)]
    assert run(alerts, [_brute_force_rule()]) == []


def test_non_matching_event_type_no_hit():
    from core.detection.engine import run

    alerts = [_alert(offset_seconds=i * 10, event_type="auth_success") for i in range(10)]
    assert run(alerts, [_brute_force_rule()]) == []


# ---------------------------------------------------------------------------
# Hit shape
# ---------------------------------------------------------------------------

def test_hit_window_start_is_first_alert_timestamp():
    from core.detection.engine import run

    alerts = [_alert(offset_seconds=i * 10) for i in range(6)]
    hits = run(alerts, [_brute_force_rule()])
    assert hits[0].window_start == datetime.fromisoformat(alerts[0]["timestamp"])
    assert hits[0].window_end == hits[0].window_start + timedelta(seconds=300)


def test_hit_alert_ids_chronological():
    from core.detection.engine import run

    alerts = [_alert(offset_seconds=i * 10, alert_id=f"a{i}") for i in range(6)]
    hits = run(alerts, [_brute_force_rule()])
    assert hits[0].alert_ids == ["a0", "a1", "a2", "a3", "a4"]


def test_hit_grouping_keys():
    from core.detection.engine import run

    alerts = [_alert(offset_seconds=i * 10) for i in range(5)]
    hits = run(alerts, [_brute_force_rule()])
    assert hits[0].grouping_keys == {
        "source_ip": "203.0.113.47",
        "target_user": "deploy",
    }


def test_hit_event_type_is_rule_emit():
    from core.detection.engine import run

    alerts = [_alert(offset_seconds=i * 10) for i in range(5)]
    hits = run(alerts, [_brute_force_rule()])
    assert hits[0].event_type == "brute_force_detected"


def test_hit_return_is_empty_list_not_none():
    from core.detection.engine import run

    assert run([], [_brute_force_rule()]) == []


# ---------------------------------------------------------------------------
# Episode semantics
# ---------------------------------------------------------------------------

def test_single_hit_per_episode():
    """10 alerts within one window → exactly 1 hit, not 6."""
    from core.detection.engine import run

    alerts = [_alert(offset_seconds=i * 5) for i in range(10)]
    hits = run(alerts, [_brute_force_rule()])
    assert len(hits) == 1


def test_hit_window_does_not_shift_within_episode():
    """window_start anchored to first alert; later alerts don't shift it."""
    from core.detection.engine import run

    alerts = [_alert(offset_seconds=i * 5) for i in range(10)]  # 0..45
    hits = run(alerts, [_brute_force_rule()])
    assert hits[0].window_start == datetime.fromisoformat(alerts[0]["timestamp"])


def test_episode_ends_when_deque_drops_below_threshold():
    """After > 300s gap, next 5-alert cluster fires again."""
    from core.detection.engine import run

    alerts = [_alert(offset_seconds=i * 10) for i in range(5)]  # 0..40
    alerts.extend(
        _alert(offset_seconds=500 + i * 10, alert_id=f"b{i}") for i in range(5)
    )

    hits = run(alerts, [_brute_force_rule()])
    assert len(hits) == 2
    assert hits[0].window_start == datetime.fromisoformat(alerts[0]["timestamp"])
    assert hits[1].window_start == datetime.fromisoformat(alerts[5]["timestamp"])


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------

def test_input_order_does_not_change_hits():
    import random
    from core.detection.engine import run

    alerts = [_alert(offset_seconds=i * 10) for i in range(6)]
    hits_sorted = run(alerts, [_brute_force_rule()])

    shuffled = alerts[:]
    random.Random(42).shuffle(shuffled)
    hits_shuffled = run(shuffled, [_brute_force_rule()])

    assert len(hits_sorted) == len(hits_shuffled) == 1
    assert hits_sorted[0].alert_ids == hits_shuffled[0].alert_ids
    assert hits_sorted[0].window_start == hits_shuffled[0].window_start