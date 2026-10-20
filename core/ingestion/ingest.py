"""Ingest validated canonical alerts into the alerts table.

Public API:
    ingest(alert: dict, *, tenant_id: str, title: str | None = None) -> str

Decision #6 — duplicate-ingestion semantics:
  - Same (tenant, source, canonical_id) + identical content -> no-op.
  - Same key + different content -> AlertConflictError.
  - Same canonical_id across tenants -> separate rows (allowed).

Implementation notes:
  - `_db.connection_scope` is accessed via the module attribute so tests
    can monkeypatch it (from core.ingestion import db as _db).
  - Writes use a SAVEPOINT so an INSERT failure (e.g. FK violation)
    rolls back only this operation, leaving the outer transaction
    usable. This is required by test_ingest_rejects_unknown_tenant.
  - Content comparison is done against the validated canonical model,
    not against the Jsonb-wrapped insert dict, because psycopg's Jsonb
    wrapper is not dict-equal (required by
    test_ingest_same_content_twice_is_noop).
"""

from __future__ import annotations

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from core.ingestion import db as _db
from core.schema.loader import validate_alert


class AlertConflictError(Exception):
    """Raised when a canonical_id exists with different content."""


_INSERT_SQL = """
INSERT INTO alerts (
    tenant_id, canonical_id, title, severity, source,
    event_type, source_ip, target_system, raw_ref, raw_payload,
    target_user, actor_user, source_port, protocol, enrichment
) VALUES (
    %(tenant_id)s, %(canonical_id)s, %(title)s, %(severity)s, %(source)s,
    %(event_type)s, %(source_ip)s, %(target_system)s, %(raw_ref)s,
    %(raw_payload)s, %(target_user)s, %(actor_user)s, %(source_port)s,
    %(protocol)s, %(enrichment)s
)
ON CONFLICT (tenant_id, source, canonical_id) DO NOTHING
RETURNING canonical_id;
"""

_SELECT_EXISTING_SQL = """
SELECT event_type, source_ip, severity, target_system,
       raw_ref, raw_payload, target_user, actor_user, source_port,
       protocol, enrichment
FROM alerts
WHERE tenant_id = %(tenant_id)s
  AND source = %(source)s
  AND canonical_id = %(canonical_id)s;
"""


def _content_matches(existing: dict, validated) -> bool:
    """Compare an existing DB row against the validated canonical alert.

    Uses the validated model (plain Python types) rather than the
    Jsonb-wrapped insert dict, so equality is meaningful.
    """
    return (
        existing["event_type"] == validated.event_type.value
        and existing["source_ip"] == validated.source_ip
        and existing["severity"] == validated.severity.value
        and existing["target_system"] == validated.target_system
        and existing["raw_ref"] == validated.raw_ref.model_dump()
        and existing["raw_payload"] == validated.raw_payload
        and existing["target_user"] == validated.target_user
        and existing["actor_user"] == validated.actor_user
        and existing["source_port"] == validated.source_port
        and existing["protocol"] == validated.protocol
        and existing["enrichment"] == validated.enrichment
    )


def ingest(
    alert: dict,
    *,
    tenant_id: str,
    title: str | None = None,
) -> str:
    """Validate and write one canonical alert; return its canonical id.

    Raises:
        ValueError: tenant_id empty.
        pydantic.ValidationError: alert does not conform.
        AlertConflictError: same key, different content.
        psycopg.IntegrityError: FK violation or CHECK failure.
    """
    if not tenant_id or not tenant_id.strip():
        raise ValueError("tenant_id must be a non-empty string")

    validated = validate_alert(alert)

    if title is None:
        title = f"{validated.event_type.value} on {validated.target_system}"

    row = {
        "tenant_id": tenant_id,
        "canonical_id": validated.id,
        "title": title,
        "severity": validated.severity.value,
        "source": validated.source_adapter,
        "event_type": validated.event_type.value,
        "source_ip": validated.source_ip,
        "target_system": validated.target_system,
        "raw_ref": Jsonb(validated.raw_ref.model_dump()),
        "raw_payload": Jsonb(validated.raw_payload),
        "target_user": validated.target_user,
        "actor_user": validated.actor_user,
        "source_port": validated.source_port,
        "protocol": validated.protocol,
        "enrichment": (
            Jsonb(validated.enrichment)
            if validated.enrichment is not None
            else None
        ),
    }

    with _db.connection_scope() as conn:
        cur = conn.cursor(row_factory=dict_row)
        try:
            cur.execute("SAVEPOINT ingest_op")
            try:
                cur.execute(_INSERT_SQL, row)
            except psycopg.IntegrityError:
                cur.execute("ROLLBACK TO SAVEPOINT ingest_op")
                raise

            inserted = cur.fetchone()
            if inserted is not None:
                cur.execute("RELEASE SAVEPOINT ingest_op")
                return inserted["canonical_id"]

            cur.execute(_SELECT_EXISTING_SQL, {
                "tenant_id": tenant_id,
                "source": validated.source_adapter,
                "canonical_id": validated.id,
            })
            existing = cur.fetchone()
            if existing is None:
                raise RuntimeError(
                    "INSERT conflict reported but no existing row found"
                )

            if not _content_matches(existing, validated):
                raise AlertConflictError(
                    f"canonical_id {validated.id!r} exists with different "
                    f"content in tenant {tenant_id!r}"
                )
            cur.execute("RELEASE SAVEPOINT ingest_op")
            return validated.id
        finally:
            cur.close()