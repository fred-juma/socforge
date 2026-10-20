"""Tests for core.detection.rule_loader.

Day 7 TDD — written before core/detection/rule_loader.py.

Covers:
  - Loading detections/canonical/brute_force.yaml into a DetectionRule
  - Missing/empty directory -> []
  - Ignoring non-YAML files
  - Missing required field -> ValueError
  - Unknown event_type (not in AlertEventType) -> ValueError
  - Unknown group_by field (not a canonical alert field) -> ValueError
  - Sorted by filename (deterministic)
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
DETECTIONS_DIR = REPO_ROOT / "detections" / "canonical"


def _rule_dict(rule_id: str) -> dict:
    """Build a minimal valid rule as a dict (matches DetectionRule schema)."""
    return {
        "id": rule_id,
        "name": rule_id,
        "version": "0.1",
        "match": {"event_type": "auth_failure"},
        "threshold": {"count": 5, "window_seconds": 300},
        "group_by": ["source_ip"],
        "emit_event_type": "brute_force_detected",
    }


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

def test_load_brute_force_rule_parses():
    from core.detection.rule_loader import load_rules
    from core.schema.enums import AlertEventType

    rules = load_rules(DETECTIONS_DIR)
    assert len(rules) == 1

    rule = rules[0]
    assert rule.id == "brute_force"
    assert rule.name == "SSH brute-force detected"
    assert rule.event_type == AlertEventType.AUTH_FAILURE
    assert rule.emit_event_type == AlertEventType.BRUTE_FORCE_DETECTED
    assert rule.threshold.count == 5
    assert rule.threshold.window_seconds == 300
    assert rule.group_by == ["source_ip", "target_user"]


# ---------------------------------------------------------------------------
# Directory edge cases
# ---------------------------------------------------------------------------

def test_load_rules_returns_empty_list_for_missing_dir(tmp_path):
    from core.detection.rule_loader import load_rules

    missing = tmp_path / "does-not-exist"
    assert not missing.exists()
    assert load_rules(missing) == []


def test_load_rules_ignores_non_yaml(tmp_path):
    from core.detection.rule_loader import load_rules

    (tmp_path / "README.md").write_text("# not a rule\n")
    (tmp_path / "notes.txt").write_text("ignore me\n")
    assert load_rules(tmp_path) == []


def test_load_rules_sorted_by_filename(tmp_path):
    from core.detection.rule_loader import load_rules

    for name, rid in [
        ("b_rule.yaml", "b_rule"),
        ("a_rule.yaml", "a_rule"),
        ("c_rule.yaml", "c_rule"),
    ]:
        (tmp_path / name).write_text(yaml.safe_dump(_rule_dict(rid)))

    rules = load_rules(tmp_path)
    assert [r.id for r in rules] == ["a_rule", "b_rule", "c_rule"]


# ---------------------------------------------------------------------------
# Validation failures
# ---------------------------------------------------------------------------

def test_load_rules_rejects_missing_required_field(tmp_path):
    from core.detection.rule_loader import load_rules

    rule = _rule_dict("bad_rule")
    del rule["match"]  # required field
    (tmp_path / "bad.yaml").write_text(yaml.safe_dump(rule))

    with pytest.raises(ValueError):
        load_rules(tmp_path)


def test_load_rules_rejects_unknown_event_type(tmp_path):
    from core.detection.rule_loader import load_rules

    rule = _rule_dict("bad_rule")
    rule["match"]["event_type"] = "not_a_real_event"
    (tmp_path / "bad.yaml").write_text(yaml.safe_dump(rule))

    with pytest.raises(ValueError):
        load_rules(tmp_path)


def test_load_rules_rejects_unknown_group_by_field(tmp_path):
    from core.detection.rule_loader import load_rules

    rule = _rule_dict("bad_rule")
    rule["group_by"] = ["source_ip", "geolocation"]  # not a canonical field
    (tmp_path / "bad.yaml").write_text(yaml.safe_dump(rule))

    with pytest.raises(ValueError):
        load_rules(tmp_path)