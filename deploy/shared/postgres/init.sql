-- SOCForge: Initial database schema
-- Database: socforge
-- Intended for PostgreSQL container initialization.
--
-- NOTE: tenant deletion cascades to all tenant-owned rows
-- (alerts, cases, entities, actions, notes). Acceptable for
-- local bootstrap; production requires a deactivation or
-- retention policy. See roadmap.
--
-- NOTE: CREATE TABLE IF NOT EXISTS does not migrate an
-- existing table to match a revised definition. Once this
-- schema is deployed, use versioned migrations for changes.
--
-- UUID generation: gen_random_uuid() is built-in on PostgreSQL 13+.


-- =========================================================
-- 1. TENANTS
-- =========================================================

CREATE TABLE IF NOT EXISTS tenants (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_tenants_id_not_empty
        CHECK (length(trim(id)) > 0)
);


-- =========================================================
-- 2. ALERTS
-- =========================================================

CREATE TABLE IF NOT EXISTS alerts (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   TEXT NOT NULL,
    title       TEXT NOT NULL,
    severity    TEXT NOT NULL DEFAULT 'low',
    status      TEXT NOT NULL DEFAULT 'open',
    source      TEXT,
    raw         JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT fk_alerts_tenant
        FOREIGN KEY (tenant_id)
        REFERENCES tenants(id)
        ON DELETE CASCADE,

    CONSTRAINT uq_alerts_tenant_id
        UNIQUE (tenant_id, id),

    CONSTRAINT chk_alerts_title_not_empty
        CHECK (length(trim(title)) > 0),

    CONSTRAINT chk_alerts_severity
        CHECK (severity IN ('low', 'medium', 'high', 'critical')),

    CONSTRAINT chk_alerts_status
        CHECK (status IN ('open', 'investigating', 'resolved', 'closed'))
);


-- =========================================================
-- 3. CASES
-- =========================================================

CREATE TABLE IF NOT EXISTS cases (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   TEXT NOT NULL,
    title       TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'open',
    priority    TEXT NOT NULL DEFAULT 'medium',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT fk_cases_tenant
        FOREIGN KEY (tenant_id)
        REFERENCES tenants(id)
        ON DELETE CASCADE,

    CONSTRAINT uq_cases_tenant_id
        UNIQUE (tenant_id, id),

    CONSTRAINT chk_cases_title_not_empty
        CHECK (length(trim(title)) > 0),

    CONSTRAINT chk_cases_status
        CHECK (status IN ('open', 'investigating', 'resolved', 'closed')),

    CONSTRAINT chk_cases_priority
        CHECK (priority IN ('low', 'medium', 'high', 'critical'))
);


-- =========================================================
-- 4. CASE_ALERTS
-- Associates alerts with cases while enforcing tenant
-- consistency across both referenced records.
-- Pure join table with composite identity; no surrogate id.
-- =========================================================

CREATE TABLE IF NOT EXISTS case_alerts (
    tenant_id   TEXT NOT NULL,
    case_id     UUID NOT NULL,
    alert_id    UUID NOT NULL,
    linked_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT pk_case_alerts
        PRIMARY KEY (case_id, alert_id),

    CONSTRAINT fk_case_alerts_tenant
        FOREIGN KEY (tenant_id)
        REFERENCES tenants(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_case_alerts_case
        FOREIGN KEY (tenant_id, case_id)
        REFERENCES cases(tenant_id, id)
        ON DELETE CASCADE,

    CONSTRAINT fk_case_alerts_alert
        FOREIGN KEY (tenant_id, alert_id)
        REFERENCES alerts(tenant_id, id)
        ON DELETE CASCADE
);


-- =========================================================
-- 5. ENTITIES
-- =========================================================

CREATE TABLE IF NOT EXISTS entities (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   TEXT NOT NULL,
    type        TEXT NOT NULL,
    value       TEXT NOT NULL,
    attributes  JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT fk_entities_tenant
        FOREIGN KEY (tenant_id)
        REFERENCES tenants(id)
        ON DELETE CASCADE,

    CONSTRAINT chk_entities_type_not_empty
        CHECK (length(trim(type)) > 0),

    CONSTRAINT chk_entities_value_not_empty
        CHECK (length(trim(value)) > 0)
);


-- =========================================================
-- 6. ACTIONS
-- Actions may optionally reference a case.
-- Deleting a case preserves the action record and clears
-- case_id, while tenant ownership remains intact.
-- =========================================================

CREATE TABLE IF NOT EXISTS actions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   TEXT NOT NULL,
    case_id     UUID,
    kind        TEXT NOT NULL,
    payload     JSONB NOT NULL DEFAULT '{}'::jsonb,
    status      TEXT NOT NULL DEFAULT 'pending',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT fk_actions_tenant
        FOREIGN KEY (tenant_id)
        REFERENCES tenants(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_actions_case
        FOREIGN KEY (tenant_id, case_id)
        REFERENCES cases(tenant_id, id)
        ON DELETE SET NULL (case_id),

    CONSTRAINT chk_actions_kind_not_empty
        CHECK (length(trim(kind)) > 0),

    CONSTRAINT chk_actions_status
        CHECK (
            status IN (
                'pending',
                'approved',
                'running',
                'succeeded',
                'failed',
                'cancelled'
            )
        )
);


-- =========================================================
-- 7. NOTES
-- Notes belong to a tenant and may optionally reference
-- a case. Deleting a case preserves the note as evidence,
-- clearing case_id while tenant ownership remains intact.
-- =========================================================

CREATE TABLE IF NOT EXISTS notes (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   TEXT NOT NULL,
    case_id     UUID,
    body        TEXT NOT NULL,
    author      TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT fk_notes_tenant
        FOREIGN KEY (tenant_id)
        REFERENCES tenants(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_notes_case
        FOREIGN KEY (tenant_id, case_id)
        REFERENCES cases(tenant_id, id)
        ON DELETE SET NULL (case_id),

    CONSTRAINT chk_notes_body_not_empty
        CHECK (length(trim(body)) > 0)
);


-- =========================================================
-- 8. INDEXES
-- Support common tenant-scoped SOC queries.
-- =========================================================

CREATE INDEX IF NOT EXISTS idx_alerts_tenant_created
    ON alerts (tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_alerts_tenant_status
    ON alerts (tenant_id, status);

CREATE INDEX IF NOT EXISTS idx_cases_tenant_created
    ON cases (tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_cases_tenant_status
    ON cases (tenant_id, status);

CREATE INDEX IF NOT EXISTS idx_case_alerts_alert_id
    ON case_alerts (alert_id);

CREATE INDEX IF NOT EXISTS idx_entities_tenant_type_value
    ON entities (tenant_id, type, value);

CREATE INDEX IF NOT EXISTS idx_actions_tenant_status
    ON actions (tenant_id, status);

CREATE INDEX IF NOT EXISTS idx_notes_case_created
    ON notes (case_id, created_at DESC);


-- =========================================================
-- 9. INITIAL TENANT SEED
-- =========================================================

INSERT INTO tenants (id, name)
VALUES ('org_aa', 'Org AA')
ON CONFLICT (id) DO NOTHING;


-- =========================================================
-- 10. UPDATED_AT TRIGGERS
-- Maintain updated_at on alerts and cases.
-- CREATE TRIGGER has no IF NOT EXISTS, so drop first
-- to keep the init script idempotent.
-- =========================================================

CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_alerts_updated_at ON alerts;
CREATE TRIGGER trg_alerts_updated_at
    BEFORE UPDATE ON alerts
    FOR EACH ROW
    EXECUTE FUNCTION set_updated_at();

DROP TRIGGER IF EXISTS trg_cases_updated_at ON cases;
CREATE TRIGGER trg_cases_updated_at
    BEFORE UPDATE ON cases
    FOR EACH ROW
    EXECUTE FUNCTION set_updated_at();