-- deploy/shared/postgres/migrations/001_alert_canonical_columns.sql
--
-- Extends alerts to store the full canonical alert shape.
-- Canonical ids are namespaced by adapters (e.g. "wazuh:{manager}:{native_id}").
-- Surrogate UUID PK is retained; canonical_id is a separate constrained column.
--
-- Idempotent: safe to re-run. Requires init.sql to have run first.

BEGIN;

ALTER TABLE alerts
    ADD COLUMN IF NOT EXISTS canonical_id   TEXT,
    ADD COLUMN IF NOT EXISTS event_type     TEXT,
    ADD COLUMN IF NOT EXISTS source_ip      TEXT,
    ADD COLUMN IF NOT EXISTS target_system  TEXT,
    ADD COLUMN IF NOT EXISTS raw_ref        JSONB,
    ADD COLUMN IF NOT EXISTS target_user    TEXT,
    ADD COLUMN IF NOT EXISTS actor_user     TEXT,
    ADD COLUMN IF NOT EXISTS source_port    INTEGER,
    ADD COLUMN IF NOT EXISTS protocol       TEXT,
    ADD COLUMN IF NOT EXISTS enrichment     JSONB;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'alerts' AND column_name = 'raw'
    ) AND NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'alerts' AND column_name = 'raw_payload'
    ) THEN
        ALTER TABLE alerts RENAME COLUMN raw TO raw_payload;
    END IF;
END $$;

UPDATE alerts SET canonical_id = 'legacy:' || id::text WHERE canonical_id IS NULL;
ALTER TABLE alerts ALTER COLUMN canonical_id SET NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'uq_alerts_tenant_source_canonical'
    ) THEN
        ALTER TABLE alerts
            ADD CONSTRAINT uq_alerts_tenant_source_canonical
            UNIQUE (tenant_id, source, canonical_id);
    END IF;
END $$;

ALTER TABLE alerts DROP CONSTRAINT IF EXISTS chk_alerts_severity;
ALTER TABLE alerts
    ADD CONSTRAINT chk_alerts_severity
    CHECK (severity IN ('informational', 'low', 'medium', 'high', 'critical'));

CREATE INDEX IF NOT EXISTS idx_alerts_canonical_id ON alerts (canonical_id);

COMMIT;