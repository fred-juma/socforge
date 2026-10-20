"""Simple in-process FIFO ingestion queue for PoC use only.

Not thread-safe across processes. Not persistent. Not a Kafka
replacement. Its job is to prove the ingest path works end-to-end
without adding infrastructure.
"""

from __future__ import annotations

from collections import deque
from typing import Any

from core.ingestion.ingest import ingest


class IngestQueue:
    """FIFO queue of canonical alert dicts, drained via ingest()."""

    def __init__(self) -> None:
        self._items: deque[dict[str, Any]] = deque()

    def put(self, alert_dict: dict[str, Any]) -> None:
        self._items.append(alert_dict)

    def get(self) -> dict[str, Any] | None:
        return self._items.popleft() if self._items else None

    def size(self) -> int:
        return len(self._items)

    def drain(self, *, tenant_id: str, title: str | None = None) -> int:
        """Ingest all queued items; return the number processed.

        Stops and re-raises on the first ingest failure, leaving the
        remaining items in the queue for retry.
        """
        processed = 0
        while self._items:
            item = self.get()
            ingest(item, tenant_id=tenant_id, title=title)
            processed += 1
        return processed