# Canonical Schemas — v0.1

This directory documents SOCForge's canonical data model: four schemas
that normalize security data from any source (SIEM, EDR, case-management,
SOAR) into a stable, source-independent representation.

They live in `schemas/`, with a frozen copy in `schemas/versions/v0.1/`.

---

## Why a canonical layer exists

Every security source speaks its own dialect. Wazuh emits `data.srcip`.
Splunk emits `src`. Sentinel emits `RemoteIP`. A downstream consumer that
wants "the source IP of this alert" has to know which source produced it
and branch accordingly. That branching is the problem this layer solves.

The canonical layer sits between sources and consumers:

```
  Wazuh ─┐
 Splunk ─┼──► [ adapters ] ──► canonical schemas ──► consumers
    EDR ─┘                       (this directory)
```

Adapters translate source-native events into canonical records. Consumers
read canonical records and never branch on source. The canonical layer is
the stable contract; sources change, consumers don't.

---

## The four schemas and their responsibilities

Each schema answers a different question. No two overlap.

| Schema | Question it answers | File |
|---|---|---|
| Alert | What did the source detect? | `canonical_alert.yaml` |
| Case | What investigation groups these alerts? | `canonical_case.yaml` |
| Entity | Who or what was involved? | `canonical_entity.yaml` |
| Action | What did we do about it? | `canonical_action.yaml` |

The relationships between them:

```
  Case ──── references ────► Alert (via alert_ids)
                              │
                              │ references
                              ▼
                            Entity (via target_user, source_ip,
                                    target_system, actor_user)
  Action ── references ──► Case (via case_id, optional)
           references ──► Entity (via target_entity_ids, optional)
```

Two deliberate omissions in v0.1:

- **Cases do not reference entities directly.** They reach entities by
  traversing their constituent alerts. A direct case→entity path would
  create a second source of truth for the same relationship.
- **Cases do not reference actions directly.** The linkage is
  one-directional: `canonical_action.case_id` points at the case. The
  case carries no `action_ids` field. This avoids a circular reference
  and a second source of truth.

---

## Cross-cutting principles

These principles apply to all four schemas. They're stated once here
rather than repeated in each file.

### 1. `null` and `unknown` are distinct

`null` means *not yet determined*. `unknown` means *determination was
attempted and the answer is unknown*. Collapsing them destroys
operational signal — "we haven't classified this case yet" and "we
classified this case and couldn't categorize it" are different problems
with different fixes. Schemas preserve the distinction wherever a
classification field exists.

### 2. Empty is a signal, not an absence

Where a required object may legitimately have no content (e.g.
`grouping_keys` on a manually-created case), the schema requires the
object to be present but allows it to be `{}`. An empty object means
"this is empty, and here's why" — distinct from "this field was absent."

### 3. Native identifiers are preserved, never canonicalized

Source-native IDs (Wazuh `rule.id`, Splunk `signature_id`) ride in
`raw_ref` and `raw_payload`. They are never used as the canonical
classification. Downstream consumers MUST branch on canonical fields
(`event_type`, `case_type`), never on native IDs. This is what makes
adding a new source a non-breaking change.

### 4. Enrichment is an open object

MITRE ATT&CK is the only enrichment type observed in the v0.1 fixture
set. It lives inside an `enrichment` object rather than as a first-class
field, so adding `enrichment.geo`, `enrichment.threat_intel`, etc. later
does not require a schema revision. See
[Enrichment shape](#enrichment-shape) below.

### 5. Tenant identity comes from trusted context

`tenant_id` is required on all four schemas. It is injected by the
adapter from trusted configuration or ingestion context — **never
inferred from untrusted event content**. When tenant cannot be resolved,
the alert is quarantined, not guessed.

### 6. `required-nullable` and `optional` are not interchangeable

Two distinct patterns appear in the schemas:

- **optional** — the field may be absent entirely.
  Example: `canonical_alert.target_user`. Fixture 08 has no user, so
  the field is simply not present.

- **required + nullable** — the field must be present, but its value
  may be null in a narrow, defined case.
  Example: `canonical_action.actor_id`. It is always present; it is
  null only when `actor_type: system` and no specific subsystem applies.

These are not stylistic variants. `optional` means "may not exist";
`required + nullable` means "must exist, may be empty." Consumers that
conflate them will mishandle one or the other.

### 7. The schema describes shape; the adapter describes behavior

Required fields, enums, and types are in the schema. Enforcement rules
that cannot be expressed structurally (e.g. "exactly one `natural_key`
field is populated," "no transitions after a terminal action state")
are documented in prose and enforced in the validator layer. See
[Validator-enforced invariants](#validator-enforced-invariants) below.

---

## Enrichment shape

All four schemas carry an `enrichment` object. Its contents are not
fixed — enrichment types are added as sources provide them. This section
is the single canonical definition; the schemas reference it rather than
repeating it.

### `enrichment.mitre`

MITRE ATT&CK mapping. Present when the source system supplies it.

```yaml
enrichment:
  mitre:
    id: ["T1110"]
    tactic: ["Credential Access"]
    technique: ["Brute Force"]
```

**At alert level**, `mitre` reflects the single detection's mapping.

**At case level**, `mitre` is the UNION of `mitre` across constituent
alerts.

**At entity and action level**, `mitre` may appear when the entity or
action is independently associated with an ATT&CK technique (e.g. a
threat-intel-enriched IP).

Future enrichment types (`geo`, `threat_intel`, `ueba`) follow the same
pattern: a named object under `enrichment`, extended additively. Adding
a new enrichment type is NOT a breaking schema change.

---

## `canonical_alert.yaml` — what was detected

### Purpose

A canonical alert represents **a single normalized detection event**.
One alert = one event. Correlation across events is a case-level
concern, not an alert-level concern.

### Fields

#### `id` — *required, string*

Stable, globally unique identifier for this alert instance. Sourced from
the adapter's native event ID where available.

**Why it exists:** every record needs a primary key. Consumers reference
alerts by this ID, and it must survive storage, replay, and reprocessing.

**Example:** `"1730000122.482910"` (Wazuh event ID)

#### `tenant_id` — *required, string*

The tenant that owns this alert.

**Why it exists:** multi-tenant storage and retrieval are ambiguous
without it. An alert with no owner is a data-leak risk.

**Resolution:** `trusted_context_only` — injected by the adapter, never
inferred from payload. If unresolved, the alert is quarantined.

**Example:** `"org_aa"`

#### `timestamp` — *required, ISO 8601 date-time*

Event time, in UTC. Sourced from the source system's event timestamp,
**not ingestion time**.

**Why it exists:** correlation and investigation depend on when things
actually happened. Ingestion lag would corrupt every timeline.

**Example:** `"2026-10-14T09:15:22.481Z"`

#### `source_adapter` — *required, string*

Identifier of the adapter that produced this alert.

**Why it exists:** traceability and adapter-specific replay. When an
adapter bug is found, you need to find everything it produced.

**Example:** `"wazuh"`

#### `event_type` — *required, enum*

Normalized classification of what happened.

**Enum:** `auth_failure`, `auth_success`, `brute_force_detected`

**Why it exists:** this is the field that lets consumers ignore native
rule IDs. Wazuh `5710` and `5760` both map to `auth_failure`; `5712` maps
to `brute_force_detected`. Downstream code branches on `event_type`,
never on `rule_id`.

**Example:** `"auth_failure"`

#### `source_ip` — *required, IPv4/IPv6*

Originating IP of the activity. No port.

**Why it exists:** source IP is the primary correlation key for
brute-force and most network-based detections. It appears in every
fixture.

**Example:** `"203.0.113.47"`

#### `severity` — *required, enum*

Normalized severity of the event.

**Enum:** `informational`, `low`, `medium`, `high`, `critical`

**Why it exists:** different sources use different severity scales.
Normalizing lets consumers compare across sources.

**Wazuh mapping (v0.1):** level 0–3 → informational, 4–6 → low,
7–9 → medium, 10–12 → high, 13+ → critical.

**Distinct from:** case `priority`. Severity answers "how bad is this
event"; priority answers "how urgent is this investigation."

**Example:** `"low"` (from Wazuh level 5)

#### `target_system` — *required, string*

The system on which the activity occurred, normalized to a hostname.

**Why it exists:** investigation pivots on which asset was affected.
Source: Wazuh `agent.name`.

**Example:** `"web-server-01"`

#### `raw_ref` — *required, object*

Structured pointer back to the original event.

**Why it exists:** audit and retrieval. A URL string would force adapters
to invent link schemes that may not exist; structured fields let each
adapter express its own retrieval path.

**Fields:** `adapter`, `rule_id`, `event_id`, `index_hint` (optional)

**Example:**
```yaml
raw_ref:
  adapter: wazuh
  rule_id: "5760"
  event_id: "1730000122.482910"
  index_hint: "/var/log/auth.log"
```

#### `raw_payload` — *required, object*

The original, unmodified source event.

**Why it exists:** audit, replay, and schema evolution. Adapters MUST
NOT prune unknown fields here — future schema versions may need them.

**Why required (unlike case/entity/action):** every alert *derives from*
a source event. There is always a raw payload. Cases, entities, and
actions may be constructed natively with no source representation, so
`raw_payload` is optional there. The asymmetry is intentional.

#### `target_user` — *optional, string, nullable*

The account being acted upon.

**Why it exists:** user-centric investigation. It's **optional** because
some failure events don't identify a user (fixture 08). Consumers MUST
NOT assume presence.

**Source:** Wazuh `data.dstuser`.

**Example:** `"deploy"`

#### `actor_user` — *optional, string, nullable*

The account performing the action, when distinct from `target_user`.

**Why it exists:** distinguishing actor from target. For SSH failures
this is usually absent. In invalid-user attempts, Wazuh populates
`data.srcuser` — but it mirrors `dstuser`, so it isn't a genuine actor.
Marked separate so future adapters with a real actor concept can use it.

#### `source_port` — *optional, integer, nullable*

Originating TCP/UDP port.

**Why it exists:** useful for network forensics. **Optional** because
fixture 07 lacks it.

#### `protocol` — *optional, string, nullable*

Application protocol.

**Why it exists:** context for the activity. Present in all fixtures but
**optional** — that presence is an artifact of the SSH-only fixture set.

**Example:** `"ssh2"`

#### `enrichment` — *optional, object, nullable*

Structured enrichment. See [Enrichment shape](#enrichment-shape).

At alert level, `enrichment.mitre` reflects **this detection's** ATT&CK
mapping.

---

## `canonical_case.yaml` — what investigation groups the alerts

### Purpose

A canonical case represents **an investigation**: a grouping of one or
more alerts that a correlation policy or analyst has decided belong
together.

### Fields

#### `id` — *required, string*

Unique identifier for this case. Assigned by the case-management layer.

#### `tenant_id` — *required, string*

Tenant that owns this case. MUST match the `tenant_id` of every
constituent alert. Cross-tenant cases are rejected at construction.

#### `created_at` / `updated_at` — *required, ISO 8601*

When the case was opened and last modified.

**Why they exist:** `created_at` is not the timestamp of the first alert
— a case may be opened retroactively when correlation runs against
stored alerts. `updated_at` is meaningful because cases are mutable
investigation records.

**Contrast:** entities do not carry a separate `updated_at` — their
`last_seen` is the update signal. Actions are append-only, so nothing is
ever updated.

#### `status` — *required, enum*

Lifecycle state of the investigation.

**Enum:** `open`, `triaged`, `investigating`, `contained`, `closed`,
`false_positive`

**Why it exists:** distinct from classification. A case can be `open`
with no classification, or `closed` with `case_type = brute_force`.

#### `case_type` — *required, nullable, enum*

Normalized classification of the **investigation**.

**Enum:** `brute_force`, `credential_access`, `lateral_movement`,
`suspicious_authentication`, `unknown`

**Why it exists:** named `case_type` (not `event_type`) to keep it
distinct from `canonical_alert.event_type`. A case is a grouping, not an
event.

**Three-state semantics — critical:**

| Value | Meaning |
|---|---|
| `null` | Classification not yet performed, or pending review. Measurable as backlog. |
| `unknown` | Classification attempted; evidence insufficient. NOT a synonym for null. |
| `<category>` | Evidence and policy support the classification. |

Adapters MUST NOT emit `unknown` as a substitute for `null`, and MUST
NOT leave `case_type` null after classification has run.

**Classification is derived** from constituent alert `event_type`s,
constituent alert `severity`s, and the correlation policy. It is
**analyst-overridable**, and overrides are recorded (see
`classification_override`).

#### `severity` — *required, enum*

Aggregate severity of the case, derived from constituent alerts.

**Why it exists:** distinct from `priority`. This is "how bad is the
evidence"; priority is "how urgently must we act."

#### `priority` — *required, enum*

Investigation urgency.

**Enum:** `p1`, `p2`, `p3`, `p4`

**Why it exists:** separate from severity on purpose. A high-severity
event on a low-value asset may be p3; a medium-severity event on a
domain controller may be p1. Priority is a triage judgment, not a
severity copy.

#### `alert_ids` — *required, array of string, min 1*

Canonical alert IDs that constitute this case.

**Why it exists:** the case→alert reference. A case with zero alerts is
malformed.

#### `grouping_keys` — *required, object (may be `{}`)*

The key(s) the correlation policy matched on.

**Why it exists:** auditability. It answers "why are these alerts in one
case?" without which grouping policies cannot be reviewed or tuned.

**May be `{}`** when no machine grouping applies — a manual or imported
case. An empty object is a **signal**, not an absence. Interpret it
alongside `grouping_origin`:

| `grouping_origin` | `grouping_keys = {}` |
|---|---|
| `correlation_policy` | BUG — policy cases must have keys |
| `manual` | Expected — human-created case |
| `import` | Expected — no rationale supplied |

**Example:**
```yaml
grouping_keys:
  source_ip: "203.0.113.47"
  target_user: "deploy"
  time_window_seconds: 240
```

#### `grouping_origin` — *required, enum*

How the case came to exist.

**Enum:** `correlation_policy`, `manual`, `import`

**Why it exists:** makes `grouping_keys = {}` unambiguous. Same principle
as `null` vs `unknown`.

#### `classification_override` — *optional, object*

Records an analyst override of the derived `case_type`, `severity`, or
`priority`.

**Why it exists:** preserves **both** the derived value and the override.
Overwriting the derived value would destroy training data and audit
history.

#### `assignee`, `closed_at`, `close_reason` — *optional*

Standard case-management fields. `closed_at` is null while the case is
open.

#### `enrichment` — *optional, object, nullable*

See [Enrichment shape](#enrichment-shape). At case level,
`enrichment.mitre` is the **union** of `mitre` across constituent
alerts.

#### `raw_payload` — *optional, object, nullable*

Optional passthrough of the source case-management system's native
representation. Cases constructed natively by the correlation engine
leave this null.

---

## `canonical_entity.yaml` — who or what was involved

### Purpose

A canonical entity represents **a thing that alerts and cases can
reference**: a user account, host, IP, domain, service, or application.
Entities are the join key that lets SOCForge answer "has this user been
targeted before?" or "what else has this host been involved in?"

### Fields

#### `id` — *required, string*

Surrogate key identifying the **record**. The thing itself is identified
by `(tenant_id, entity_type, natural_key)`.

**Why the distinction:** records can be merged (`merged_from`) and
re-created without changing the identity of the underlying thing.

#### `tenant_id` — *required, string*

Tenant that owns this entity record.

**Scope rules — identity vs. matchability:**

- `user`, `host`, `service`, `application` → **tenant-scoped in full**.
  The same username in two tenants is two different entities.
- `ip`, `domain` → **tenant-scoped for ownership and attributes**, but
  their `natural_key` is a **globally matchable observable**. The
  platform may match these across tenants for correlation and
  enrichment, subject to access controls. Matching does **not** merge
  records — it only surfaces relationships.

**Why:** identity and matchability are different concerns. An IP is an
IP everywhere; a username is only meaningful within a tenant.

#### `entity_type` — *required, enum*

**Enum:** `user`, `host`, `ip`, `domain`, `service`, `application`,
`unknown`

Determines which `natural_key` fields are meaningful.

#### `natural_key` — *required, object*

The minimal fields that uniquely identify this entity **within its
tenant**.

**Why it exists:** deduplication. Two records with the same
`(tenant_id, entity_type, natural_key)` refer to the same thing.

**Fields:** `user_name`, `host_name`, `ip_address`, `domain_name`,
`service_name`, `app_name`

Each field carries a `scope`:
- `tenant` — identity is tenant-local
- `global_observable` — matchable across tenants; access-controlled

**Example:**
```yaml
entity_type: ip
natural_key:
  ip_address: "203.0.113.47"
```

#### `first_seen` / `last_seen` — *required, ISO 8601*

Earliest and most recent observation in any alert.

**Why they exist:** entity timelines. `first_seen` is set once;
`last_seen` updates on every reference. No separate `updated_at` is
needed — `last_seen` **is** the update signal.

#### `attributes` — *optional, object, nullable*

Volatile, type-dependent attributes.

**Why it exists:** distinct from `natural_key`. `natural_key` answers
"which thing is this?"; `attributes` answers "what do we know about it?"

**Attributes are enriched, not authoritative.** A missing attribute
means "unknown," not "false." Consumers MUST NOT treat absence as a
negative assertion.

**Examples:**
```yaml
attributes:
  display_name: "Deploy Service Account"
  privileged: true
```
```yaml
attributes:
  os: "Ubuntu 22.04"
  criticality: high
```

#### `aliases` — *optional, array of string*

Alternative identifiers referring to the same entity.

**Why it exists:** correlation hints. Aliases are **hints, not
identity** — two entities are the same only if `(tenant_id,
entity_type, natural_key)` match.

#### `merged_from` — *optional, array of string*

Entity IDs that were merged into this one.

**Why it exists:** audit and reference resolution. If an alert
references a merged-away entity ID, consumers resolve it via this
field.

#### `enrichment` — *optional, object, nullable*

See [Enrichment shape](#enrichment-shape). For entities, enrichment
typically comes from inventory or threat-intel sources rather than from
the alert itself.

#### `raw_payload` — *optional, object, nullable*

Optional passthrough of a source system's native representation, if the
entity was imported from an external inventory rather than constructed
from alert evidence.

---

## `canonical_action.yaml` — what we did about it

### Purpose

A canonical action represents **a response or case-management action**
taken (or intended) by an analyst, SOCForge, or an automated workflow.

**Modeled as an event log, not a stateful object.** Each record is a
*state transition* of a logical action. The logical action is identified
by `action_id`; its transitions share that `action_id` and are ordered
by `occurred_at`.

**Why event log:**
- Matches the event-based philosophy of `canonical_alert`.
- Preserves full audit history — essential for disruptive actions.
- Append-only: no concurrent-update corruption.
- "Current state" is a fold over transitions, materializable later.

### Fields

#### `id` — *required, string*

Identifier for **this state transition**, not the logical action.

#### `action_id` — *required, string*

Identifier for the **logical action**. All transitions of the same
action share this value.

**Why both exist:** to reconstruct an action's history, query by
`action_id` ordered by `occurred_at`. To fetch one transition, use `id`.

#### `tenant_id` — *required, string*

Tenant that owns this action.

#### `occurred_at` — *required, ISO 8601*

When **this transition** happened.

**Why not "created_at":** ordering is by this field, and each transition
has its own time.

#### `state` — *required, enum*

The state this transition moves the action into.

**Enum:** `proposed`, `approved`, `rejected`, `executed`, `failed`,
`cancelled`

**Lifecycle semantics:**

| State | Meaning | Terminal? |
|---|---|---|
| `proposed` | Requested | No |
| `approved` | Authorized, not executed | No |
| `rejected` | Denied | Yes |
| `executed` | Successfully carried out | Yes |
| `failed` | Attempted, did not succeed | Yes |
| `cancelled` | Authorized but withdrawn | Yes |

**`rejected` vs `cancelled`:** rejected = "never authorized";
cancelled = "authorized but withdrawn." Different audit meanings — do
not collapse.

**Invariants (validator-enforced):**
- The first transition MUST be `proposed`.
- `approved` MUST follow `proposed`.
- Terminal states MUST NOT be followed by further transitions.
- Disruptive action types (containment) MUST NOT skip from `proposed`
  directly to `executed`.

#### `action_type` — *required, enum*

Category of response.

**Enum:** `triage`, `containment`, `investigation`, `lifecycle`

**Examples by type:**
- triage → assign analyst, change priority, escalate
- containment → isolate host, block IP, disable account
- investigation → request enrichment, trigger analysis
- lifecycle → close, reopen, mark false positive

**Note:** `automation` is NOT an `action_type`. It is recorded via
`actor_type`. An automated containment action is:

```yaml
action_type: containment
actor_type: automation
```

This keeps "what was done" (`action_type`) orthogonal to "who or what
did it" (`actor_type`).

#### `actor_type` — *required, enum*

Who or what performed this transition.

**Enum:** `analyst`, `automation`, `system`

#### `actor_id` — *required, nullable, string*

Identifier of the actor.

**Nullable only** when `actor_type: system` and no specific subsystem
applies. This is the canonical example of **required-nullable** — see
[cross-cutting principle 6](#6-required-nullable-and-optional-are-not-interchangeable).

#### `case_id` — *optional, string, nullable*

The case this action responds to.

**Why optional:** some actions are not case-scoped (threat-intel-driven
IP block, proactive host isolation).

**Invariant:** if `case_id` is null, `rationale` is **required**. A
standalone action must justify itself.

#### `target_entity_ids` — *optional, array of string*

Entity IDs this action operates on. References into
`canonical_entity.yaml`.

**Why optional:** some actions have no entity target (e.g. "close case",
"assign analyst"). Those operate on the case.

#### `rationale` — *optional, string, nullable*

Why this transition was taken.

**Required** when `case_id` is null. Recommended for disruptive actions.

#### `approval_ref` / `approver_id` — *optional*

Reference to and identifier of the approval. Populated on `approved`
and subsequent transitions.

**Why distinct from `actor_id`:** the approver may differ from the actor.

#### `automation_id` — *optional, string*

Identifier of the automation workflow, when `actor_type: automation`.

**Why distinct from `actor_id`:** a workflow acting on behalf of an
analyst can record both.

#### `execution_details` — *optional, object*

Outcome summary when the action reached a terminal execution state.

**Why it exists:** the schema records **that** execution happened. The
mechanism belongs to an execution/adapter layer.
`execution_details.external_ref` is the seam between the two.

**Example:**
```yaml
execution_details:
  success: true
  duration_ms: 1420
  external_ref: "edr-job-88217"
```

#### `enrichment` — *optional, object, nullable*

See [Enrichment shape](#enrichment-shape).

#### `raw_payload` — *optional, object, nullable*

Optional passthrough of a source system's native representation, if the
action was imported from an external case-management or SOAR system.

---

## Validator-enforced invariants

Some constraints cannot be expressed in YAML structure. They are
documented here and must be enforced in the validator layer.

| Schema | Invariant |
|---|---|
| Entity | For non-`unknown` entity types, **exactly one** `natural_key` field is populated. Zero or more than one indicates an adapter bug. |
| Entity | For `entity_type: unknown`, `natural_key` must be `{}`. |
| Action | The first transition of an action MUST be `state: proposed`. |
| Action | `state: approved` MUST follow a `state: proposed` transition. |
| Action | Terminal states (`rejected`, `executed`, `failed`, `cancelled`) MUST NOT be followed by further transitions. |
| Action | Containment actions MUST NOT skip from `proposed` directly to `executed`. |
| Action | If `case_id` is null, `rationale` is required. |
| Case | `grouping_origin: correlation_policy` MUST have non-empty `grouping_keys`. |
| Case | All constituent alerts' `tenant_id` MUST match the case's `tenant_id`. |
| All | `tenant_id` MUST be resolvable from trusted context. Unresolved → quarantine. |

---

## Extending the canonical layer

### Adding a new source adapter

Implement a translation from the source's native events into the four
canonical schemas. The source's native IDs ride in `raw_ref` and
`raw_payload`. If the source emits a field that doesn't map to a
canonical field, it belongs in `enrichment` or `raw_payload` — not in a
new top-level field.

### Adding a new field

Before adding a field, check whether the information is:

- **Classification** → an enum value on an existing field
- **Source-specific detail** → `raw_payload`
- **Optional structured data** → `enrichment`
- **A new dimension not covered anywhere** → a genuine new field

Most "new fields" turn out to be the first three.

### Versioning

v0.1 is frozen in `schemas/versions/v0.1/`. Changes require a new
version directory. Additive, backward-compatible changes may bump to
v0.1.1; breaking changes require v0.2.

---

## Version history

| Version | Date | Notes |
|---|---|---|
| v0.1 | 2026-10-14 | Initial canonical schemas. Four schemas. Synthesized from 10 Wazuh SSH fixtures. |
| v0.1.1 | 2026-10-15 | Corrects the v0.1 alert parse error and completes the action schema. Also removes `automation` from `action_type`. |