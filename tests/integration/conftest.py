"""Fixtures for integration tests.

Isolation model (Day 6 Decision #7):
  - Session-scoped: apply init.sql + migration 001 to socforge_test once.
  - Function-scoped: begin a transaction, yield connection, rollback.
  - ingest() is patched to use the test connection so writes roll back too.

The ingest_conn fixture deliberately patches the *module attribute*
`core.ingestion.db.connection_scope` (not the imported name in
`core.ingestion.ingest`). `ingest.py` imports the module as `_db` and
calls `_db.connection_scope()` at runtime, so this patch takes effect.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from pathlib import Path

import psycopg
import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

TEST_DB_URL = os.environ.get(
    "SOCFORGE_TEST_DB_URL",
    "postgresql://socforge:socforge@localhost:5432/socforge_test",
)


@pytest.fixture(scope="session", autouse=True)
def _ensure_test_schema():
    """Reset socforge_test and apply init.sql + migrations, once per session."""
    with psycopg.connect(TEST_DB_URL, autocommit=True) as conn:
        cur = conn.cursor()
        cur.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
        for sql_path in [
            REPO_ROOT / "deploy" / "shared" / "postgres" / "init.sql",
            REPO_ROOT / "deploy" / "shared" / "postgres" / "migrations"
            / "001_alert_canonical_columns.sql",
        ]:
            cur.execute(sql_path.read_text())


@pytest.fixture
def db_conn(monkeypatch):
    """Rollback-isolated connection to socforge_test.

    Also points Settings at the test DB for the duration of the test.
    """
    monkeypatch.setenv("SOCFORGE_DB_URL", TEST_DB_URL)
    monkeypatch.setenv("SOCFORGE_TENANT_ID", "org_aa")
    from core.platform.config import get_settings
    get_settings.cache_clear()

    conn = psycopg.connect(TEST_DB_URL, autocommit=False)
    try:
        yield conn
    finally:
        conn.rollback()
        conn.close()
        get_settings.cache_clear()


@pytest.fixture
def ingest_conn(db_conn, monkeypatch):
    """Make ingest() use the test connection; no commit — outer fixture rolls back.

    Patches `core.ingestion.db.connection_scope` at the module level so
    that `_db.connection_scope()` inside ingest.py resolves to the fake
    contextmanager. Do NOT patch `ingest.connection_scope` directly —
    ingest.py imports the module (`from core.ingestion import db as _db`),
    not the name.
    """
    import core.ingestion.db as db_module

    @contextmanager
    def _fake_scope():
        yield db_conn  # no commit; db_conn fixture rolls back at teardown

    monkeypatch.setattr(db_module, "connection_scope", _fake_scope)
    yield db_conn