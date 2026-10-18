# Wazuh Adapter — Field Mapping (v0.1)

**Adapter version:** 0.1.0
**Canonical schema:** `schemas/canonical_alert.yaml` v0.1
**Source:** Wazuh JSON alert envelope (as emitted by wazuh-manager / API / integrator)
**Public API:** `parse(raw: dict, *, tenant_id: str) -> dict`
**Errors:** `WazuhParseError`

---

## 1. Scope

This adapter translates **one** Wazuh alert object into **one** canonical
alert dictionary. It performs no ingestion, enrichment fetches, correlation,
case creation, or persistence.

The `tenant_id` is **never** read from the Wazuh event. It is supplied by
the caller as a keyword argument (`tenant_id=...`) because the canonical
schema declares `tenant_id` as `resolution: trusted_context_only`.

Fixture metadata (the `_fixture` block present in synthesized fixtures) is
test-only and MUST be stripped by the caller before invocation. It is not
part of a real Wazuh event and is not preserved in `raw_payload`.

---

## 2. Classification rules

`event_type` is derived from `rule.id` first, then from `rule.groups` as a
fallback. If neither yields a recognized classification, the parser raises
`WazuhParseError` — it does **not** default to a silent value.

| Rule ID | Groups contains | → `event_type` |
|---|---|---|
| `5712` | *(any)* | `brute_force_detected` |
| `5715` | *(any)* | `auth_success` |
| `5710` | *(any)* | `auth_failure` |
| `5760` | *(any)* | `auth_failure` |
| *(other)* | `authentication_success` | `auth_success` |
| *(other)* | `authentication_failed` | `auth_failure` |
| *(other)* | *(neither)* | **`WazuhParseError`** |

**Rule-ID-first** precedence is chosen deliberately: per
`canonical_alert.yaml`, the mapping evidence is stated in terms of native
rule IDs, and rule IDs are Wazuh's stable detection contract. `rule.groups`
is a coarser taxonomy that can be customized in local rulesets, so it is a
fallback, not the primary signal.

`rule.description` is not used for classification — it is free-form text
and not stable across Wazuh ruleset versions.

---

## 3. Severity mapping

Wazuh `rule.level` is an integer 0–15. The mapping below matches the
guidance in `canonical_alert.yaml`:

| `rule.level` | → `severity` |
|---|---|
| 0–3 | `informational` |
| 4–6 | `low` |
| 7–9 | `medium` |
| 10–12 | `high` |
| 13–15 | `critical` |

Missing `rule.level`, or a non-integer value, raises `WazuhParseError`.

---

## 4. Field mapping table

Every mapping below is implemented in `parser.py` and asserted in
`tests/adapter_tests/test_wazuh.py`. Absent/malformed rules follow the
Day 5 policy: missing or malformed **required** source data → `WazuhParseError`;
absent **optional** source data → canonical field omitted; the parser never
invents a value.

| # | Wazuh source | Canonical field | Transformation | Absent / malformed | Notes |
|---|---|---|---|---|---|
| 1 | *(constant)* | `source_adapter` | Set to literal `"wazuh"` | n/a | Adapter identity |
| 2 | *(kwarg)* | `tenant_id` | Passed by caller | Missing or empty → `WazuhParseError` | Never from payload |
| 3 | `id` (top-level) | `id` | String passthrough | Missing → `WazuhParseError` | e.g. `"1730000122.482910"` |
| 4 | `timestamp` (top-level) | `timestamp` | ISO 8601 string; parser parses to datetime and re-emits ISO 8601 | Missing / unparseable → `WazuhParseError` | Preserved as event time, not ingestion time |
| 5 | `rule.id` | `raw_ref.rule_id` | String passthrough | Missing → `WazuhParseError` | Preserved for traceability; **not** used as classification downstream |
| 6 | *(constant)* | `raw_ref.adapter` | Literal `"wazuh"` | n/a | |
| 7 | `id` (top-level) | `raw_ref.event_id` | Mirrors `id` (mapping #3) | Missing `id` → `WazuhParseError` | Native event ID |
| 8 | `location` | `raw_ref.index_hint` | String passthrough | Absent → `index_hint` omitted | e.g. `"/var/log/auth.log"` |
| 9 | *(classification, §2)* | `event_type` | Rule-ID-first, groups fallback | Unclassifiable → `WazuhParseError` | |
| 10 | `data.srcip` | `source_ip` | String passthrough; parser validates it parses as an IP literal | Missing / not an IP → `WazuhParseError` | Required by schema |
| 11 | `rule.level` *(§3)* | `severity` | Integer 0–15 → enum | Missing / non-integer → `WazuhParseError` | |
| 12 | `agent.name` | `target_system` | String passthrough | Falls back to `agent.id` if `agent.name` absent; both absent → `WazuhParseError` | Hostname preferred |
| 13 | `data.dstuser` | `target_user` | String passthrough | Absent → `target_user` omitted | Optional — fixture 08 |
| 14 | `data.srcport` | `source_port` | String → int via `int()` | Absent → `source_port` omitted; non-integer → `WazuhParseError` | Optional — fixture 07 |
| 15 | `data.protocol` | `protocol` | String passthrough | Absent → `protocol` omitted | Optional |
| 16 | `rule.mitre` | `enrichment.mitre` | Deep-copy `{id, tactic, technique}` arrays verbatim | Absent → `enrichment` omitted entirely | Optional — fixture 10 |
| 17 | Full `raw` dict as received | `raw_payload` | Deep copy, unmodified | Parser never mutates or prunes | Excludes `_fixture` per test-only stripping |

### Fields explicitly **not** populated

| Wazuh source | Canonical field | Reason |
|---|---|---|
| `data.srcuser` | *(none)* | Per `canonical_alert.yaml`, on SSH failures `srcuser` mirrors `dstuser` (attempted username, not a genuine separate actor). Populating `actor_user` would misrepresent it. Reserved for future adapters with a true actor concept. |
| `rule.description` | *(none)* | Free-form text; not a stable classification signal |
| `manager.name` | *(none)* | Manager identity, not part of the event's target system |
| `full_log` | *(none as first-class)* | Preserved inside `raw_payload`; not a canonical field |
| `decoder.name` | *(none)* | Preserved inside `raw_payload`; not a canonical field |
| `rule.frequency`, `rule.timeframe` | *(none)* | Correlation metadata; schema explicitly assigns this to `canonical_case.yaml` |

---

## 5. Error policy (summary)

| Situation | Action |
|---|---|
| Required source field missing (e.g. `id`, `timestamp`, `rule.id`, `data.srcip`, `agent.name`+`agent.id`) | `WazuhParseError` |
| Required source field present but malformed (unparseable timestamp, non-IP `srcip`, non-integer `srcport`, non-integer `rule.level`) | `WazuhParseError` |
| Event cannot be classified (§2) | `WazuhParseError` |
| `tenant_id` kwarg missing or empty string | `WazuhParseError` |
| Optional source field absent (`srcport`, `dstuser`, `protocol`, `rule.mitre`, `location`) | Field omitted from canonical dict |
| Canonical validation (`validate_alert`) fails despite parser success | Pydantic `ValidationError` (not wrapped) |

The parser does **not** return partial canonical alerts. A dict returned by
`parse()` is expected to pass `validate_alert()` on well-formed fixtures.

---

## 6. Fixture coverage

| Fixture | Rule | Event | Severity | Edge case exercised |
|---|---|---|---|---|
| 01 | 5760 | `auth_failure` | `low` | Baseline |
| 02 | 5710 | `auth_failure` | `low` | Invalid user (`srcuser` present — must NOT populate `actor_user`) |
| 03 | 5760 | `auth_failure` | `low` | Repeat-failure shape |
| 04 | 5712 | `brute_force_detected` | `high` | Correlated brute force |
| 05 | 5715 | `auth_success` | `informational` | Negative control |
| 06 | 5712 | `brute_force_detected` | `high` | Invalid-user brute force (`srcuser` present) |
| 07 | 5760 | `auth_failure` | `low` | `srcport` absent → `source_port` omitted |
| 08 | 5760 | `auth_failure` | `low` | `dstuser` absent → `target_user` omitted |
| 09 | 5760 | `auth_failure` | `low` | Multi-source — no case-level aggregation |
| 10 | 5712 | `brute_force_detected` | `high` | `rule.mitre` present → `enrichment.mitre` populated |