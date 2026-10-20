"""Postgres connection factory for ingestion (psycopg 3)."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

import psycopg

from core.platform.config import get_settings


def connect() -> psycopg.Connection:
    """Open a new connection using the configured DSN."""
    return psycopg.connect(get_settings().db_dsn)


@contextmanager
def connection_scope() -> Iterator[psycopg.Connection]:
    """Yield a connection; commit on success, rollback on exception."""
    conn = connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()