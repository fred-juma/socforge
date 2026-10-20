"""Adapter tests for the Wazuh → canonical alert parser (Day 5).

Written before parser.py per handover Step 4 (TDD).

Structure:
  - Fixtures live in adapters/siem/wazuh/fixtures/.
  - The _fixture metadata block is stripped before invoking parse().
    Per Decision 3, _fixture is test-only; the parser must never see it,
    and raw_payload must not carry it.
  - Every parsed dict is validated with core.schema.validate_alert.
  - Error-path tests pin the WazuhParseError policy from Decision 2 / 6.

These tests are RED until Task 37 implements the parser.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from core.schema.loader import validate_alert
from core.schema.enums import AlertEventType, AlertSeverity
from adapters.siem.wazuh.src import parse, WazuhParseError


REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES_DIR = (
    REPO_ROOT / "adapters" / "siem" / "wazuh" / "fixtures"
)

TENANT_ID = "org_test"


# (filename, rule_id, event_type, severity)
FIXTURE_CASES = [
    ("01-ssh-failed-password.json",         "5760", "auth_failure",         "low"),
    ("02-ssh-invalid-user.json",            "5710", "auth_failure",         "low"),
    ("03-ssh-failed-password-repeat.json",  "5760", "auth_failure",         "low"),
    ("04-ssh-brute-force.json",             "5712", "brute_force_detected", "high"),
    ("05-ssh-authentication-success.json",  "5715", "auth_success",         "informational"),
    ("06-ssh-invalid-user-bruteforce.json", "5712", "brute_force_detected", "high"),
    ("07-ssh-failure-no-source-port.json",  "5760", "auth_failure",         "low"),
    ("08-ssh-failure-no-user.json",         "5760", "auth_failure",         "low"),
    ("09-ssh-bruteforce-multi-source.json", "5760", "auth_failure",         "low"),
    ("10-ssh-alert-with-mitre.json",        "5712", "brute_force_detected", "high"),
]


def _load_raw(name: str) -> dict:
    """Load a fixture and strip the test-only _fixture block (Decision 3)."""
    with open(FIXTURES_DIR / name) as f:
        raw = json.load(f)
    raw.pop("_fixture", None)
    return raw


def _minimal_valid_raw() -> dict:
    """Smallest well-formed Wazuh event — baseline for mutation tests."""
    return {
        "id": "1730000999.000001",
        "timestamp": "2026-10-14T10:00:00.000Z",
        "rule": {"id": "5760", "level": 5, "groups": ["authentication_failed"]},
        "agent": {"id": "001", "name": "host-01"},
        "manager": {"name": "wazuh-manager"},
        "location": "/var/log/auth.log",
        "data": {"srcip": "203.0.113.47"},
    }

def _expect_parse_error(raw: dict, tenant_id: str = TENANT_ID) -> None:
    """Assert that parse(raw) raises WazuhParseError."""
    with pytest.raises(WazuhParseError):
        parse(raw, tenant_id=tenant_id)


def _assert_omitted(result: dict, field: str) -> None:
    """Assert an optional field is completely absent, not set to None."""
    assert field not in result, (
        f"Field {field!r} should be omitted entirely; "
        f"got key present with value {result.get(field)!r}"
    )


# ---------------------------------------------------------------------------
# Happy path — one test per fixture
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("filename,rule_id,event_type,severity", FIXTURE_CASES)
def test_fixture_parses_to_valid_canonical_alert(
    filename, rule_id, event_type, severity
):
    raw = _load_raw(filename)
    result = parse(raw, tenant_id=TENANT_ID)
    assert isinstance(result, dict)

    alert = validate_alert(result)  # raises ValidationError on failure

    assert alert.event_type == event_type
    assert alert.severity == severity
    assert alert.raw_ref.rule_id == rule_id
    assert alert.tenant_id == TENANT_ID
    assert alert.source_adapter == "wazuh"
    assert alert.raw_ref.adapter == "wazuh"
    #assert alert.id == raw["id"]
    assert alert.id == f"wazuh:{raw['manager']['name']}:{raw['id']}"
    assert alert.raw_ref.event_id == raw["id"]


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("rule_id,expected", [
    ("5760", "auth_failure"),
    ("5710", "auth_failure"),
    ("5715", "auth_success"),
    ("5712", "brute_force_detected"),
])
def test_classification_by_known_rule_id(rule_id, expected):
    raw = _minimal_valid_raw()
    raw["rule"]["id"] = rule_id
    result = parse(raw, tenant_id=TENANT_ID)
    assert result["event_type"] == expected


@pytest.mark.parametrize("groups,expected", [
    (["authentication_success"], "auth_success"),
    (["authentication_failed"], "auth_failure"),
])
def test_classification_by_groups_fallback(groups, expected):
    raw = _minimal_valid_raw()
    raw["rule"]["id"] = "9999"  # unrecognized id
    raw["rule"]["groups"] = groups
    result = parse(raw, tenant_id=TENANT_ID)
    assert result["event_type"] == expected


def test_unclassifiable_event_raises():
    raw = _minimal_valid_raw()
    raw["rule"]["id"] = "9999"
    raw["rule"]["groups"] = ["some_other_group"]
    with pytest.raises(WazuhParseError):
        parse(raw, tenant_id=TENANT_ID)


# ---------------------------------------------------------------------------
# Severity mapping boundaries
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("level,expected", [
    (0, "informational"), (3, "informational"),
    (4, "low"), (6, "low"),
    (7, "medium"), (9, "medium"),
    (10, "high"), (12, "high"),
    (13, "critical"), (15, "critical"),
])
def test_severity_boundaries(level, expected):
    raw = _minimal_valid_raw()
    raw["rule"]["level"] = level
    result = parse(raw, tenant_id=TENANT_ID)
    assert result["severity"] == expected


# ---------------------------------------------------------------------------
# Field transformations
# ---------------------------------------------------------------------------

def test_source_ip_preserved():
    raw = _minimal_valid_raw()
    raw["data"]["srcip"] = "198.51.100.22"
    result = parse(raw, tenant_id=TENANT_ID)
    assert result["source_ip"] == "198.51.100.22"


def test_source_port_cast_to_int():
    raw = _minimal_valid_raw()
    raw["data"]["srcport"] = "51422"
    result = parse(raw, tenant_id=TENANT_ID)
    assert result["source_port"] == 51422
    assert isinstance(result["source_port"], int)


def test_timestamp_preserved():
    raw = _minimal_valid_raw()
    raw["timestamp"] = "2026-10-14T09:15:22.481Z"
    result = parse(raw, tenant_id=TENANT_ID)
    alert = validate_alert(result)
    # Pydantic normalizes to tz-aware datetime; verify the wall-clock
    # instant is preserved at second granularity.
    assert alert.timestamp.isoformat().startswith("2026-10-14T09:15:22")


def test_target_system_from_agent_name():
    raw = _minimal_valid_raw()
    raw["agent"] = {"id": "001", "name": "web-server-01"}
    result = parse(raw, tenant_id=TENANT_ID)
    assert result["target_system"] == "web-server-01"


def test_target_system_falls_back_to_agent_id():
    raw = _minimal_valid_raw()
    raw["agent"] = {"id": "001"}  # no name
    result = parse(raw, tenant_id=TENANT_ID)
    assert result["target_system"] == "001"


# ---------------------------------------------------------------------------
# Optional field handling
# ---------------------------------------------------------------------------

def test_source_port_omitted_when_absent():
    raw = _load_raw("07-ssh-failure-no-source-port.json")
    result = parse(raw, tenant_id=TENANT_ID)
    _assert_omitted(result, "source_port")
    #assert result.get("source_port") is None


def test_target_user_omitted_when_absent():
    raw = _load_raw("08-ssh-failure-no-user.json")
    result = parse(raw, tenant_id=TENANT_ID)
    _assert_omitted(result, "target_user")
    #assert result.get("target_user") is None


def test_actor_user_never_populated_from_srcuser():
    # Fixtures 02, 06, 10 all carry data.srcuser == data.dstuser.
    # Per canonical_alert.yaml, srcuser is not a separate actor.
    for name in (
        "02-ssh-invalid-user.json",
        "06-ssh-invalid-user-bruteforce.json",
        "10-ssh-alert-with-mitre.json",
    ):
        raw = _load_raw(name)
        assert "srcuser" in raw["data"]  # sanity: fixture still has it
        result = parse(raw, tenant_id=TENANT_ID)
        #assert result.get("actor_user") is None, name
        _assert_omitted(result, "actor_user")
        


def test_enrichment_absent_when_no_mitre():
    raw = _load_raw("01-ssh-failed-password.json")
    result = parse(raw, tenant_id=TENANT_ID)
    #assert result.get("enrichment") is None
    _assert_omitted(result, "enrichment")


def test_enrichment_mitre_preserved():
    raw = _load_raw("10-ssh-alert-with-mitre.json")
    result = parse(raw, tenant_id=TENANT_ID)
    enrichment = result.get("enrichment")
    assert enrichment is not None
    mitre = enrichment["mitre"]
    assert mitre["id"] == ["T1110"]
    assert mitre["tactic"] == ["Credential Access"]
    assert mitre["technique"] == ["Brute Force"]


# ---------------------------------------------------------------------------
# Raw preservation
# ---------------------------------------------------------------------------

def test_raw_payload_preserves_full_event():
    raw = _load_raw("01-ssh-failed-password.json")
    snapshot = copy.deepcopy(raw)
    result = parse(raw, tenant_id=TENANT_ID)
    assert result["raw_payload"] == snapshot
    # Parser must not mutate the caller's dict.
    assert raw == snapshot


def test_raw_ref_fields_populated():
    raw = _load_raw("01-ssh-failed-password.json")
    result = parse(raw, tenant_id=TENANT_ID)
    raw_ref = result["raw_ref"]
    assert raw_ref["adapter"] == "wazuh"
    assert raw_ref["rule_id"] == "5760"
    assert raw_ref["event_id"] == raw["id"]
    assert raw_ref["index_hint"] == "/var/log/auth.log"


def test_index_hint_omitted_when_location_absent():
    raw = _minimal_valid_raw()
    raw.pop("location")
    result = parse(raw, tenant_id=TENANT_ID)
    #assert result["raw_ref"].get("index_hint") is None
    _assert_omitted(result["raw_ref"], "index_hint")


# ---------------------------------------------------------------------------
# Error policy
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("mutator,label", [
    (lambda r: r.pop("id"),                         "missing top-level id"),
    (lambda r: r.pop("timestamp"),                  "missing timestamp"),
    (lambda r: r.pop("rule"),                       "missing rule block"),
    (lambda r: r["rule"].pop("id"),                 "missing rule.id"),
    (lambda r: r["rule"].pop("level"),              "missing rule.level"),
    (lambda r: r["data"].pop("srcip"),              "missing data.srcip"),
    (lambda r: r["agent"].clear() or r.pop("agent"),"missing agent"),
    (lambda r: r["agent"].clear(),              "missing agent.name with no id"),
])
def test_missing_required_source_field_raises(mutator, label):
    raw = _minimal_valid_raw()
    # For the "missing agent.name" case, ensure agent.id is also absent so
    # the fallback cannot rescue the event.
    mutator(raw)
    with pytest.raises(WazuhParseError):
        parse(raw, tenant_id=TENANT_ID)


@pytest.mark.parametrize("mutator,label", [
    (lambda r: r.__setitem__("timestamp", "not-a-date"),
     "malformed timestamp"),
    (lambda r: r["data"].__setitem__("srcip", "999.999.999.999"),
     "malformed source_ip"),
    (lambda r: r["data"].__setitem__("srcport", "not-an-int"),
     "malformed source_port"),
    (lambda r: r["rule"].__setitem__("level", "high"),
     "non-integer rule.level"),
])
def test_malformed_mapped_value_raises(mutator, label):
    raw = _minimal_valid_raw()
    mutator(raw)
    with pytest.raises(WazuhParseError):
        parse(raw, tenant_id=TENANT_ID)


@pytest.mark.parametrize("tenant", ["", None])
def test_invalid_tenant_id_raises(tenant):
    raw = _minimal_valid_raw()
    with pytest.raises(WazuhParseError):
        parse(raw, tenant_id=tenant)