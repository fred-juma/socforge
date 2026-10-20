"""Batch detection engine (Day 7).

Public API:
    run(alerts: list[dict], rules: list[DetectionRule]) -> list[DetectionHit]

The engine is a pure function over a batch:
  - Sorts alerts by timestamp internally (input order is irrelevant).
  - Evaluates each rule per alert, maintaining a per-group sliding window.
  - Emits one hit per active episode (see detections/canonical/brute_force.yaml
    for episode semantics).

Alerts are canonical dicts as produced by adapters and validated by
core.schema.loader. Timestamps are ISO 8601 UTC (Phase 4 normalization
guarantees fixed-width sortable order).
"""

from __future__ import annotations

from collections import deque
from datetime import datetime, timedelta

from core.detection.models import DetectionHit, DetectionRule


def _parse_ts(value: str) -> datetime:
    """Parse an ISO 8601 timestamp produced by the adapter."""
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _group_key(alert: dict, group_by: list[str]) -> tuple[str, ...] | None:
    """Build the grouping key. Returns None if any required field is missing."""
    values: list[str] = []
    for field in group_by:
        value = alert.get(field)
        if value is None:
            return None
        values.append(str(value))
    return tuple(values)


class _GroupState:
    """Per-(rule, tenant, group_key) state."""

    __slots__ = ("deque", "in_episode", "window_start")

    def __init__(self) -> None:
        self.deque: deque[tuple[datetime, str]] = deque()
        self.in_episode: bool = False
        self.window_start: datetime | None = None


def _evaluate_rule(
    alerts: list[dict],
    alert_ts: list[datetime],
    rule: DetectionRule,
) -> list[DetectionHit]:
    """Evaluate one rule over the (already timestamp-sorted) alerts."""
    state: dict[tuple[str, ...], _GroupState] = {}
    hits: list[DetectionHit] = []
    window = timedelta(seconds=rule.threshold.window_seconds)
    threshold = rule.threshold.count
    target_event_type = rule.match.event_type.value

    for alert, ts in zip(alerts, alert_ts):
        if alert.get("event_type") != target_event_type:
            continue

        group_values = _group_key(alert, rule.group_by)
        if group_values is None:
            continue

        # tenant_id is always implicit in the key
        tenant_id = alert.get("tenant_id")
        if not tenant_id:
            continue

        key = (tenant_id, *group_values)
        st = state.get(key)
        if st is None:
            st = _GroupState()
            state[key] = st

        # Evict alerts outside the half-open window [ts - window, ts)
        # i.e. keep iff (ts - old_ts) < window
        while st.deque and (ts - st.deque[0][0]) >= window:
            st.deque.popleft()

        st.deque.append((ts, alert["id"]))

        if st.in_episode:
            if len(st.deque) < threshold:
                st.in_episode = False
                st.window_start = None
            continue  # suppress while still in episode

        if len(st.deque) >= threshold:
            assert st.window_start is None  # invariant: pre-fire
            st.window_start = st.deque[0][0]
            hits.append(
                DetectionHit(
                    rule_id=rule.id,
                    tenant_id=tenant_id,
                    alert_ids=[alert_id for (_, alert_id) in st.deque],
                    window_start=st.window_start,
                    window_end=st.window_start + window,
                    grouping_keys=dict(zip(rule.group_by, group_values)),
                    event_type=rule.emit_event_type,
                )
            )
            st.in_episode = True

    return hits


def run(alerts: list[dict], rules: list[DetectionRule]) -> list[DetectionHit]:
    """Evaluate all rules against all alerts. Return deterministic hit list.

    Alerts are sorted by timestamp internally; caller order is irrelevant.
    Hits are ordered by (window_start, rule_id, sorted grouping key).
    """
    if not alerts or not rules:
        return []

    parsed: list[tuple[datetime, dict]] = [(_parse_ts(a["timestamp"]), a) for a in alerts]
    parsed.sort(key=lambda pair: pair[0])
    sorted_alerts = [a for (_, a) in parsed]
    sorted_ts = [ts for (ts, _) in parsed]

    all_hits: list[DetectionHit] = []
    for rule in rules:
        all_hits.extend(_evaluate_rule(sorted_alerts, sorted_ts, rule))

    all_hits.sort(
        key=lambda h: (h.window_start, h.rule_id, tuple(sorted(h.grouping_keys.items())))
    )
    return all_hits