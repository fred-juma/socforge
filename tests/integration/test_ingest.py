"""Integration tests for the ingestion pipeline.

Flow: Wazuh fixture → parse() → ingest() → row in alerts.
Written before core/ingestion/ingest.py (Day 6 TDD).
"""

from __future__ import annotations

import json
from pathlib import Path

import psycopg
import pytest

from adapters.siem.wazuh.src import parse as wazuh_parse

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES_DIR = REPO_ROOT / "adapters" / "siem" / "wazuh" / "fixtures"
TENANT_ID = "org_aa"


def _load_raw(name: str) -> dict:
    with open(FIXTURES_DIR / name) as f:
        raw = json.load(f)
    raw.pop("_fixture", None)
    return raw


def _row_count(conn) -> int:
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM alerts")
    return cur.fetchone()[0]


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

def test_ingest_writes_one_row(ingest_conn):
    from core.ingestion.ingest import ingest

    raw = _load_raw("01-ssh-failed-password.json")
    alert_dict = wazuh_parse(raw, tenant_id=TENANT_ID)

    alert_id = ingest(alert_dict, tenant_id=TENANT_ID)
    assert alert_id == "wazuh:wazuh-manager:1730000122.482910"
    assert _row_count(ingest_conn) == 1

    cur = ingest_conn.cursor()
    cur.execute("""
        SELECT canonical_id, tenant_id, event_type, source_ip, severity,
               target_system, source
        FROM alerts WHERE canonical_id = %s
    """, (alert_id,))
    row = cur.fetchone()
    assert row == (
        "wazuh:wazuh-manager:1730000122.482910",
        TENANT_ID, "auth_failure", "203.0.113.47", "low",
        "web-server-01", "wazuh",
    )


def test_ingest_preserves_raw_payload_as_jsonb(ingest_conn):
    from core.ingestion.ingest import ingest

    raw = _load_raw("01-ssh-failed-password.json")
    alert_dict = wazuh_parse(raw, tenant_id=TENANT_ID)
    ingest(alert_dict, tenant_id=TENANT_ID)

    cur = ingest_conn.cursor()
    cur.execute(
        "SELECT raw_payload FROM alerts WHERE canonical_id = %s",
        (alert_dict["id"],),
    )
    stored = cur.fetchone()[0]
    assert stored["id"] == raw["id"]
    assert stored["rule"]["id"] == "5760"


def test_ingest_preserves_raw_ref(ingest_conn):
    from core.ingestion.ingest import ingest

    raw = _load_raw("01-ssh-failed-password.json")
    alert_dict = wazuh_parse(raw, tenant_id=TENANT_ID)
    ingest(alert_dict, tenant_id=TENANT_ID)

    cur = ingest_conn.cursor()
    cur.execute(
        "SELECT raw_ref FROM alerts WHERE canonical_id = %s",
        (alert_dict["id"],),
    )
    raw_ref = cur.fetchone()[0]
    assert raw_ref["adapter"] == "wazuh"
    assert raw_ref["rule_id"] == "5760"
    assert raw_ref["event_id"] == "1730000122.482910"


def test_ingest_optional_fields_null_when_absent(ingest_conn):
    from core.ingestion.ingest import ingest

    raw = _load_raw("07-ssh-failure-no-source-port.json")
    alert_dict = wazuh_parse(raw, tenant_id=TENANT_ID)
    ingest(alert_dict, tenant_id=TENANT_ID)

    cur = ingest_conn.cursor()
    cur.execute(
        "SELECT source_port FROM alerts WHERE canonical_id = %s",
        (alert_dict["id"],),
    )
    assert cur.fetchone()[0] is None


def test_ingest_mitre_enrichment_round_trips(ingest_conn):
    from core.ingestion.ingest import ingest

    raw = _load_raw("10-ssh-alert-with-mitre.json")
    alert_dict = wazuh_parse(raw, tenant_id=TENANT_ID)
    ingest(alert_dict, tenant_id=TENANT_ID)

    cur = ingest_conn.cursor()
    cur.execute(
        "SELECT enrichment FROM alerts WHERE canonical_id = %s",
        (alert_dict["id"],),
    )
    assert cur.fetchone()[0]["mitre"]["id"] == ["T1110"]


# ---------------------------------------------------------------------------
# Idempotency + conflict (Decision #6)
# ---------------------------------------------------------------------------

def test_ingest_same_content_twice_is_noop(ingest_conn):
    from core.ingestion.ingest import ingest

    raw = _load_raw("01-ssh-failed-password.json")
    alert_dict = wazuh_parse(raw, tenant_id=TENANT_ID)

    id1 = ingest(alert_dict, tenant_id=TENANT_ID)
    id2 = ingest(alert_dict, tenant_id=TENANT_ID)

    assert id1 == id2
    assert _row_count(ingest_conn) == 1


def test_ingest_conflicting_content_raises(ingest_conn):
    from core.ingestion.ingest import ingest, AlertConflictError

    raw = _load_raw("01-ssh-failed-password.json")
    alert_dict = wazuh_parse(raw, tenant_id=TENANT_ID)
    ingest(alert_dict, tenant_id=TENANT_ID)

    tampered = dict(alert_dict)
    tampered["source_ip"] = "198.51.100.99"

    with pytest.raises(AlertConflictError):
        ingest(tampered, tenant_id=TENANT_ID)

    assert _row_count(ingest_conn) == 1


def test_ingest_different_tenant_same_canonical_id_allowed(ingest_conn):
    from core.ingestion.ingest import ingest

    cur = ingest_conn.cursor()
    cur.execute(
        "INSERT INTO tenants (id, name) VALUES ('org_bb', 'Org BB') "
        "ON CONFLICT DO NOTHING"
    )

    raw = _load_raw("01-ssh-failed-password.json")
    alert_dict = wazuh_parse(raw, tenant_id="org_aa")

    ingest(alert_dict, tenant_id="org_aa")
    ingest(alert_dict, tenant_id="org_bb")

    cur.execute("SELECT tenant_id FROM alerts ORDER BY tenant_id")
    assert [r[0] for r in cur.fetchall()] == ["org_aa", "org_bb"]


# ---------------------------------------------------------------------------
# Failure paths
# ---------------------------------------------------------------------------

def test_ingest_rejects_invalid_dict(ingest_conn):
    from pydantic import ValidationError
    from core.ingestion.ingest import ingest

    with pytest.raises(ValidationError):
        ingest({"id": "x"}, tenant_id=TENANT_ID)

    assert _row_count(ingest_conn) == 0


def test_ingest_rejects_unknown_tenant(ingest_conn):
    from core.ingestion.ingest import ingest

    raw = _load_raw("01-ssh-failed-password.json")
    alert_dict = wazuh_parse(raw, tenant_id=TENANT_ID)

    with pytest.raises(psycopg.IntegrityError):
        ingest(alert_dict, tenant_id="org_zz")

    assert _row_count(ingest_conn) == 0


def test_ingest_rejects_empty_tenant_id(ingest_conn):
    from core.ingestion.ingest import ingest

    raw = _load_raw("01-ssh-failed-password.json")
    alert_dict = wazuh_parse(raw, tenant_id=TENANT_ID)

    with pytest.raises(ValueError):
        ingest(alert_dict, tenant_id="")


# ---------------------------------------------------------------------------
# Title derivation (Decision #8)
# ---------------------------------------------------------------------------

def test_ingest_derives_title(ingest_conn):
    from core.ingestion.ingest import ingest

    raw = _load_raw("04-ssh-brute-force.json")
    alert_dict = wazuh_parse(raw, tenant_id=TENANT_ID)
    ingest(alert_dict, tenant_id=TENANT_ID)

    cur = ingest_conn.cursor()
    cur.execute(
        "SELECT title FROM alerts WHERE canonical_id = %s",
        (alert_dict["id"],),
    )
    assert cur.fetchone()[0] == "brute_force_detected on web-server-01"


def test_ingest_caller_title_override(ingest_conn):
    from core.ingestion.ingest import ingest

    raw = _load_raw("01-ssh-failed-password.json")
    alert_dict = wazuh_parse(raw, tenant_id=TENANT_ID)
    ingest(alert_dict, tenant_id=TENANT_ID, title="Custom title")

    cur = ingest_conn.cursor()
    cur.execute(
        "SELECT title FROM alerts WHERE canonical_id = %s",
        (alert_dict["id"],),
    )
    assert cur.fetchone()[0] == "Custom title"