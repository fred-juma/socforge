"""Unit tests for core.platform.config."""

import pytest
from pydantic import ValidationError

from core.platform.config import get_settings


def _set_valid_env(monkeypatch):
    monkeypatch.setenv(
        "SOCFORGE_DB_URL",
        "postgresql+psycopg://user:password@localhost:5432/testdb",
    )
    monkeypatch.setenv("SOCFORGE_TENANT_ID", "org_test")


def test_log_level_is_normalized(monkeypatch):
    _set_valid_env(monkeypatch)
    monkeypatch.setenv("SOCFORGE_LOG_LEVEL", " debug ")

    get_settings.cache_clear()
    settings = get_settings()

    assert settings.log_level == "DEBUG"


def test_invalid_tenant_id_is_rejected(monkeypatch):
    _set_valid_env(monkeypatch)
    monkeypatch.setenv("SOCFORGE_TENANT_ID", "acme")  # missing org_ prefix

    get_settings.cache_clear()
    with pytest.raises(ValidationError):
        get_settings()