"""Verify the 001 migration produces the expected schema.

Uses socforge_test, initialized by the session fixture in conftest.py.
"""

import psycopg
import pytest

from tests.integration.conftest import TEST_DB_URL


def test_alerts_has_canonical_columns():
    with psycopg.connect(TEST_DB_URL) as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT column_name FROM information_schema.columns
            WHERE table_name = 'alerts' ORDER BY column_name
        """)
        cols = {r[0] for r in cur.fetchall()}
    required = {
        "id", "tenant_id", "canonical_id", "title", "severity", "status",
        "source", "raw_payload", "created_at", "updated_at",
        "event_type", "source_ip", "target_system", "raw_ref",
        "target_user", "actor_user", "source_port", "protocol", "enrichment",
    }
    assert required.issubset(cols), f"missing: {required - cols}"


def test_id_still_uuid_pk():
    with psycopg.connect(TEST_DB_URL) as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT data_type FROM information_schema.columns
            WHERE table_name='alerts' AND column_name='id'
        """)
        assert cur.fetchone()[0] == "uuid"


def test_canonical_id_unique_per_tenant_and_source():
    with psycopg.connect(TEST_DB_URL, autocommit=False) as conn:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO alerts (tenant_id, canonical_id, title, source,
                                event_type, source_ip, target_system,
                                raw_ref, raw_payload)
            VALUES ('org_aa', 'dup-test', 'x', 'wazuh', 'auth_failure',
                    '1.2.3.4', 'h', '{}'::jsonb, '{}'::jsonb)
        """)
        with pytest.raises(psycopg.IntegrityError):
            cur.execute("""
                INSERT INTO alerts (tenant_id, canonical_id, title, source,
                                    event_type, source_ip, target_system,
                                    raw_ref, raw_payload)
                VALUES ('org_aa', 'dup-test', 'x', 'wazuh', 'auth_failure',
                        '1.2.3.4', 'h', '{}'::jsonb, '{}'::jsonb)
            """)
        conn.rollback()


def test_canonical_id_same_across_adapters_allowed():
    with psycopg.connect(TEST_DB_URL, autocommit=False) as conn:
        cur = conn.cursor()
        for source in ("wazuh", "splunk"):
            cur.execute("""
                INSERT INTO alerts (tenant_id, canonical_id, title, source,
                                    event_type, source_ip, target_system,
                                    raw_ref, raw_payload)
                VALUES ('org_aa', 'shared-id', 'x', %s, 'auth_failure',
                        '1.2.3.4', 'h', '{}'::jsonb, '{}'::jsonb)
            """, (source,))
        cur.execute("SELECT COUNT(*) FROM alerts WHERE canonical_id='shared-id'")
        assert cur.fetchone()[0] == 2
        conn.rollback()