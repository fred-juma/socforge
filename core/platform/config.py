"""Central application configuration loaded from environment variables.

This module provides a single, validated source of truth for runtime
configuration. It is intended to be imported once per process via
``get_settings()`` and shared by database initialization, logging setup,
and application startup code.

Design notes
------------
* Environment variables are prefixed with ``SOCFORGE_`` (e.g.
  ``SOCFORGE_DB_URL``) and matched case-insensitively to accommodate
  different development environments.
* Unknown environment variables are ignored so a shared ``.env`` file
  can serve multiple services without causing validation errors.
* ``tenant_id`` identifies the *configured deployment context*. It does
  NOT enforce tenant isolation or authorize access. Those controls must
  be implemented separately in the application and data-access layers.
* Tests that mutate the environment should call
  ``get_settings.cache_clear()`` to force a re-read.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, PostgresDsn, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]


class Settings(BaseSettings):
    """Runtime settings for the SOCForge core platform."""

    model_config = SettingsConfigDict(
        env_prefix="SOCFORGE_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        validate_default=True,
    )

    db_url: PostgresDsn = Field(
        description="Primary PostgreSQL DSN used by the application.",
    )
    tenant_id: str = Field(
        min_length=1,
        pattern=r"^org_[a-z0-9_-]+$",
        description=(
            "Deployment tenant context (e.g. 'org_aa'). Configuration only; "
            "not an authorization or isolation control."
        ),
    )
    log_level: LogLevel = Field(
        default="INFO",
        description="Root log level. Case-insensitive; normalized to uppercase.",
    )
    app_name: str = Field(
        default="socforge-core",
        description="Logical application name used in logs and telemetry.",
    )

    @field_validator("log_level", mode="before")
    @classmethod
    def _normalize_log_level(cls, value: object) -> object:
        """Trim and uppercase log-level input; leave non-strings for Pydantic."""
        if isinstance(value, str):
            return value.strip().upper()
        return value

    @property
    def db_dsn(self) -> str:
        """Return the database URL as a plain string for driver calls."""
        return str(self.db_url)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the cached application settings.

    The result is memoized for the lifetime of the process. Tests that
    mutate environment variables must call ``get_settings.cache_clear()``
    before re-invoking this function.
    """
    return Settings()