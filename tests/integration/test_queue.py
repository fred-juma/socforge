"""Tests for the in-process ingestion queue (PoC, not production)."""

from __future__ import annotations

import pytest


def test_enqueue_dequeue_fifo():
    from core.ingestion.queue import IngestQueue

    q = IngestQueue()
    q.put({"id": "a"})
    q.put({"id": "b"})
    assert q.get() == {"id": "a"}
    assert q.get() == {"id": "b"}


def test_empty_queue_get_returns_none():
    from core.ingestion.queue import IngestQueue

    q = IngestQueue()
    assert q.get() is None


def test_size_tracks_pending_items():
    from core.ingestion.queue import IngestQueue

    q = IngestQueue()
    assert q.size() == 0
    q.put({"id": "a"})
    assert q.size() == 1
    q.get()
    assert q.size() == 0


def test_drain_processes_all_pending_via_ingest(ingest_conn, monkeypatch):
    """drain() calls ingest() once per queued alert and returns count."""
    import core.ingestion.queue as queue_module

    calls = []

    def fake_ingest(alert, *, tenant_id, title=None):
        calls.append((alert["id"], tenant_id))
        return alert["id"]

    monkeypatch.setattr(queue_module, "ingest", fake_ingest)

    q = queue_module.IngestQueue()
    q.put({"id": "a"})
    q.put({"id": "b"})
    processed = q.drain(tenant_id="org_aa")

    assert processed == 2
    assert calls == [("a", "org_aa"), ("b", "org_aa")]
    assert q.size() == 0


def test_drain_propagates_ingest_errors(ingest_conn, monkeypatch):
    """A failing ingest stops the drain and re-raises."""
    import core.ingestion.queue as queue_module

    def boom(alert, *, tenant_id, title=None):
        raise RuntimeError("ingest failed")

    monkeypatch.setattr(queue_module, "ingest", boom)

    q = queue_module.IngestQueue()
    q.put({"id": "a"})

    with pytest.raises(RuntimeError):
        q.drain(tenant_id="org_aa")