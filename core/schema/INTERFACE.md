# SOCForge Schema Loader Interface

**Status:** Locked (API surface) — implementation details may change during Day 4
**Version:** v0.1
**Date:** 2026-10-15

This document defines the public API of `core/schema`. It is written
**before** the implementation, so that `test_schema_loader.py`,
`models.py`, and `loader.py` all target the same contract. Any change
to this document is a change to the contract and must be reflected in
the tests.

---

## 1. Purpose

The schema loader provides a single entry point for accessing and
validating SOCForge canonical data models.

It maps stable schema names to Pydantic model classes and validates
incoming dictionaries against the corresponding model. The loader
belongs to `core/schema/` and must not depend on external alert
producers or source-specific adapters.

The loader connects three layers:

| Layer | Role | Source of truth for |
|---|---|---|
| YAML schemas | Human-readable contract | Field intent, rationale, invariants-in-prose |
| `models.py` | Runtime validation | Types, required/optional, enum membership |
| `loader.py` | Registry + lookup | Which model corresponds to which schema name |

---

## 2. Supported Schemas

The following schema names are registered:

| Schema key | Model class | YAML file |
|---|---|---|
| `alert` | `CanonicalAlert` | `schemas/canonical_alert.yaml` |
| `case` | `CanonicalCase` | `schemas/canonical_case.yaml` |
| `entity` | `CanonicalEntity` | `schemas/canonical_entity.yaml` |
| `action` | `CanonicalAction` | `schemas/canonical_action.yaml` |

Schema keys are stable identifiers used by callers. They must not
depend on filenames or external product names. Short names are used
(not `"canonical_alert"`) because the `canonical_` prefix is redundant —
this module only handles canonical schemas.

---

## 3. Public API

Three functions. Nothing else is public.

### `load_schema(name: str) -> type[BaseModel]`

Returns the Pydantic model class registered under `name`.

**Parameters:**

- `name` — short schema name. One of: `"alert"`, `"case"`, `"entity"`,
  `"action"`.

**Returns:** the model *class*, not a model instance. For
`name="alert"`, returns `CanonicalAlert`.

**Raises:**

- `KeyError` — if `name` is not registered. The error message MUST
  identify the unknown name and list the supported schema keys.

**Example:**

```python
AlertModel = load_schema("alert")
assert AlertModel is CanonicalAlert
```

---

### `validate(name: str, data: dict) -> BaseModel`

Validates `data` against the model registered under `name` and returns
the resulting model instance.

**Parameters:**

- `name` — short schema name. Same values as `load_schema`.
- `data` — a mapping to validate.

**Returns:** an instance of the corresponding concrete model class,
such as `CanonicalAlert`. The return type annotation is `BaseModel`;
the runtime type is the concrete subclass.

**Raises:**

- `KeyError` — if `name` is not registered. Same behavior as
  `load_schema`.
- `pydantic.ValidationError` — if `data` does not conform. Propagated
  unchanged; not wrapped.

**Example:**

```python
alert = validate("alert", alert_data)
assert isinstance(alert, CanonicalAlert)
```

---

### `validate_alert(data: dict) -> CanonicalAlert`

Convenience wrapper for validating canonical alert data.

It must delegate to:

```python
validate("alert", data)
```

It must not implement separate validation logic.

**Parameters:**

- `data` — a mapping to validate against the alert schema.

**Returns:** a `CanonicalAlert` instance.

**Raises:**

- `pydantic.ValidationError` — if `data` does not conform.

**Rationale:** `validate_alert` exists because alert validation is the
most common call site. It delegates to `validate` and adds no logic.
It is the only schema-specific validator; other schemas use
`validate(name, data)`.


---

## 4. Error Handling

### Unknown schema name

`load_schema()` and `validate()` must raise `KeyError` when the supplied
schema name is not registered.

The error message should identify the unknown name and list the
supported schema keys.

### Invalid data

When data fails Pydantic validation, `validate()` and `validate_alert()`
must allow Pydantic's `ValidationError` to propagate to the caller.

The loader must not silently discard invalid fields, invent missing
values, or convert validation errors into success responses.

**No custom exception classes in v0.1.** Pydantic's `ValidationError`
carries precise per-field error information; wrapping it would lose
that. `KeyError` is Pythonic for a registry lookup and its message can
be made informative.

---

## 5. Canonical Model Contracts

The Pydantic models must align with the corresponding YAML schema
contracts:

- `canonical_alert.yaml`
- `canonical_case.yaml`
- `canonical_entity.yaml`
- `canonical_action.yaml`

For top-level fields, the implementation must preserve these
distinctions:

- **Required:** the field must be supplied.
- **Optional:** the field may be omitted.
- **Nullable:** the field may explicitly contain `null`.
- **Required and nullable:** the field must be supplied, but its value
  may be `null`.
- **Optional and nullable:** the field may be omitted or explicitly
  contain `null`.

Required and optional field presence must follow the YAML `required`
and `optional` sections. Nullable behavior and value types must follow
the field definitions.

Where a YAML schema defines a strict `enum`, the model must enforce the
allowed values. An `enum_hint` is guidance only and must not
automatically become a strict validation constraint.

---

## 6. Architecture Boundaries

- Canonical models belong under `core/schema/models.py`.
- Schema lookup and validation belong under `core/schema/loader.py`.
- Public schema behavior must be tested under
  `tests/unit/test_schema_loader.py`.
- The loader must not import Wazuh-specific code or other source
  adapters.
- Source-specific payloads must be translated into the canonical
  contract by their respective adapters before canonical validation.

**The loader does not read YAML at runtime.** The registry is a
hardcoded dict. YAML files are read only by the consistency test, which
verifies the registry and models stay aligned with the contracts. This
keeps validation on the hot path free of filesystem I/O and parsing.

---

## 7. Testing Requirements

The Day 4 test suite must verify:

1. All four schema keys resolve to their expected Pydantic model
   classes.
2. Valid canonical alert data produces a `CanonicalAlert` instance.
3. Invalid canonical alert data raises Pydantic `ValidationError`.
4. YAML and Pydantic models agree on top-level required and optional
   fields, types, nullability, and explicit enums where represented.
5. Generic `validate()` returns the correct concrete model instance
   for each registered schema.
6. Unknown schema names raise `KeyError`.

### Consistency test scope (v0.1)

The YAML consistency test asserts, for each schema:

- The YAML parses via `yaml.safe_load()`.
- Top-level field names in the YAML's `required:` and `optional:`
  sections match the model's `model_fields` — no field in one but not
  the other.
- Each field's required/optional status agrees between YAML and model.
- Each field's declared type agrees between YAML and model, using the
  mapping table below.
- Each field's nullability agrees between YAML and model.
- Each field whose YAML carries a strict `enum:` constraint has
  matching values in the model's `Literal`/`Enum` members.

### Type mapping (v0.1)

| YAML type | Python/Pydantic type |
|---|---|
| `string` | `str` |
| `integer` | `int` |
| `boolean` | `bool` |
| `object` | A nested `BaseModel` subclass or `dict[str, Any]` |
| `array` | `list[...]` (element type follows the same mapping) |
| `string` + `format: date-time` | `datetime` |
| `string` + `format: ipv4-or-ipv6` | `str`, with format validation handled separately |

The consistency test compares each field's declared YAML `type` and,
where present, its `format` against the model field's declared type
using this table. Mismatches fail the test.

**Nullability:** Compare the underlying field type separately from
whether `None` is allowed. For example, `str | None` is still a string
field that accepts `None`; nullability must not be treated as a
replacement for the declared YAML type. Required/optional status,
type, and nullability are checked independently.

**Format validation:** In v0.1, the consistency test checks the
declared YAML `format` against the corresponding model definition.
Runtime format validation must be enforced through Pydantic field
types or validators where required. In particular, `date-time` and
`ipv4-or-ipv6` values must not be assumed valid merely because their
underlying type is `datetime` or `str`. Format-specific validation
should have dedicated tests.

For `object` fields, both mappings are accepted: a nested `BaseModel`
subclass (e.g. `raw_ref` → `RawRef`) and `dict[str, Any]` (e.g.
`enrichment` → `dict[str, Any]`). The test does not require one over
the other in v0.1.

The consistency test does **not** check in v0.1 (deferred):

- **Nested fields.** `raw_ref.properties`, `enrichment.properties`,
  and similar nested objects are not recursively compared. Only
  top-level field presence, required/optional status, type, and
  nullability are compared.
- **`enum_hint`.** Guidance, not a constraint. Not compared.
- **Prose keys.** `evidence:`, `description:`, `invariant:`, and other
  documentation-only keys are ignored by the test.

**Why the deferrals are acceptable:** the drift that matters most is
top-level field drift — a field added to the YAML but not the model,
or vice versa — or a change in type, nullability, or required/optional
status on one side but not the other. Nested-field consistency is
valuable, but its edge cases (`raw_ref` versus `enrichment` shapes)
are not worth resolving on Day 4. The limitations are recorded here so
they are visible, not silent.

Raw Wazuh fixture validation is outside the loader's scope until the
Wazuh adapter translates source events into canonical alert data.
---

## 8. Day 4 Scope

Day 4 establishes and tests the canonical model and loader interface.
It does not implement source ingestion, Wazuh translation, enrichment,
correlation, triage, or case-management workflows.

---

## 9. Non-goals

**YAML does not generate models.** Pydantic does not read YAML and
produce classes. The YAML files are human-readable contracts; the
Pydantic models are explicit Python definitions. The loader does not
attempt dynamic model generation, and the consistency test is what
keeps the two in agreement.

**Rationale:** the YAML contains prose rationale (`description:`,
`evidence:`, invariants) that is not machine-convertible. Converting
it to JSON Schema would discard that. A custom YAML→model generator
would be a framework, not a Day 4 task. Explicit models plus a
consistency test is the smallest arrangement that keeps the contract
and the runtime honest.

**Other explicit non-goals for this module:**

- Generating Pydantic models from YAML at runtime or import time.
- Enforcing validator-layer invariants (e.g. "exactly one
  `natural_key` field populated"). Those live in the validator, not
  this module.
- Translating source-native events into canonical form. That is the
  adapter layer.

---

## 10. Change Policy

This interface is locked for Day 4. Any change requires:

1. An update to this document.
2. An update to `tests/unit/test_schema_loader.py`.
3. A note in the commit message explaining why the contract changed.

The interface should not drift silently. If a signature here does not
match what the implementation needs, the implementation is wrong or
this document is wrong — decide which, and change the other.