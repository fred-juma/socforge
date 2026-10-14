# Canonical Schemas — v0.1 (frozen)

**Frozen:** 2026-10-14
**Status:** Immutable. Do not edit files in this directory.

These are the frozen v0.1 canonical schemas. They were copied from
`schemas/` at freeze time and must not be modified. Any change —
including a typo fix — requires a new version directory (v0.1.1 for
non-breaking changes, v0.2 for breaking changes).

## Files

| File | Purpose |
|---|---|
| `canonical_alert.yaml` | What the source detected |
| `canonical_case.yaml` | What investigation groups the alerts |
| `canonical_entity.yaml` | Who or what was involved |
| `canonical_action.yaml` | What we did about it |

## Provenance

- Source of truth for v0.1: `schemas/` (working copies, frozen on 2026-10-14).
  Integrity is guaranteed by `MANIFEST.sha256`, not by a source commit reference.
- Fixture set: `adapters/siem/wazuh/fixtures/` (10 synthesized Wazuh SSH alerts)
- Documentation: `docs/canonical-schema/README.md`

## Integrity

See `MANIFEST.sha256`. Any mismatch between a file here and its hash
indicates unauthorized modification.

Verify with:

    cd schemas/versions/v0.1
    sha256sum -c MANIFEST.sha256

## Consuming v0.1

Consumers pin to this directory, not to `schemas/`:

    consumers reference schemas/versions/v0.1/*.yaml

`schemas/` (the working copies) may drift as v0.2 development begins.
This directory will not.