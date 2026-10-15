# Canonical Schemas — v0.1.1 (frozen)

**Frozen:** 2026-10-15
**Status:** Immutable. Do not edit files in this directory.
**Supersedes:** v0.1

These are the frozen v0.1.1 canonical schemas. They correct two defects
in v0.1 and must not be modified. Any further change requires a new
version directory (v0.1.2 for non-breaking changes, v0.2 for breaking
changes).

## Changes since v0.1

Two files changed. `canonical_case.yaml` and `canonical_entity.yaml`
are byte-identical to v0.1.

### `canonical_alert.yaml`

- Corrected a YAML parsing error that prevented the file from loading.
- <add any other alert revisions made since v0.1, if applicable>

### `canonical_action.yaml`

- Completed a truncated file. v0.1's copy ended mid-sequence in the
  `state` enum, omitting the remainder of `required:`, the entire
  `optional:` section, and the "Explicitly NOT modeled" block.
- Removed `automation` from the `action_type` enum. Automation is
  orthogonal to what was done and is recorded via `actor_type`.
- Added justification notes for `raw_payload`.
- Added the shared enrichment reference.

## Files

| File | Purpose | Changed from v0.1 |
|---|---|---|
| `canonical_alert.yaml` | What the source detected | Yes |
| `canonical_case.yaml` | What investigation groups the alerts | No |
| `canonical_entity.yaml` | Who or what was involved | No |
| `canonical_action.yaml` | What we did about it | Yes |

## Provenance

- Source of truth for v0.1.1: `schemas/` (working copies, frozen on 2026-10-15).
  Integrity is guaranteed by `MANIFEST.sha256`.
- Fixture set: `adapters/siem/wazuh/fixtures/` (10 synthesized Wazuh SSH alerts)
- Documentation: `docs/canonical-schema/README.md`

## Integrity

See `MANIFEST.sha256`. Any mismatch between a file here and its hash
indicates unauthorized modification.

Verify with:

    cd schemas/versions/v0.1.1
    sha256sum -c MANIFEST.sha256

## Consuming v0.1.1

Consumers should pin to v0.1.1, not v0.1:

    consumers reference schemas/versions/v0.1.1/*.yaml

Consumers still pinned to v0.1 remain valid for `canonical_case.yaml`
and `canonical_entity.yaml`. For `canonical_alert.yaml` and
`canonical_action.yaml`, v0.1 is defective and MUST NOT be used.