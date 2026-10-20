"""Adapter protocol for SIEM/EDR sources feeding the ingestion pipeline."""

from __future__ import annotations

from typing import Any, Protocol


class Adapter(Protocol):
    """Translates a source-native event into a canonical alert dict.

    Contract:
      - Input `raw` is a source-native event dict.
      - `tenant_id` comes from trusted ingestion context, never from `raw`.
      - Output is a dict suitable for core.schema.loader.validate_alert().
      - Output `id` must be globally unique within its source family
        (e.g. "wazuh:{manager}:{native_id}").
      - Adapter-specific parse errors are the adapter's own exception type.
    """

    def parse(self, raw: dict[str, Any], *, tenant_id: str) -> dict[str, Any]:
        ...