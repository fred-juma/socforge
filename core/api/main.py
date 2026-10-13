"""SOCForge Core API entrypoint."""

from __future__ import annotations

import logging

from fastapi import FastAPI

from core.platform.config import get_settings
from core.platform.health import router as health_router


def configure_logging() -> None:
    settings = get_settings()
    logging.basicConfig(
        level=settings.log_level,
        format="%(asctime)s %(levelname)s %(name)s :: %(message)s",
    )


configure_logging()

app = FastAPI(title=get_settings().app_name)
app.include_router(health_router)


@app.get("/")
def root() -> dict[str, str]:
    """Return basic SOCForge service information."""
    settings = get_settings()
    return {"service": settings.app_name, "tenant": settings.tenant_id}