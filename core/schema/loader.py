"""Schema loader: registry and validation dispatch.

See core/schema/INTERFACE.md for the API contract.
"""

from pydantic import BaseModel

from core.schema.models import (
    CanonicalAction,
    CanonicalAlert,
    CanonicalCase,
    CanonicalEntity,
)


_REGISTRY: dict[str, type[BaseModel]] = {
    "alert": CanonicalAlert,
    "case": CanonicalCase,
    "entity": CanonicalEntity,
    "action": CanonicalAction,
}


def load_schema(name: str) -> type[BaseModel]:
    """Return the model class registered under name.

    Raises KeyError if name is not a registered schema.
    """
    try:
        return _REGISTRY[name]
    except KeyError:
        valid = ", ".join(sorted(_REGISTRY))
        raise KeyError(
            f"Unknown schema name: {name!r}. Valid names: {valid}"
        ) from None


def validate(name: str, data: dict) -> BaseModel:
    """Validate data against the named schema; return an instance.

    Raises:
        KeyError: if name is not registered.
        pydantic.ValidationError: if data does not conform.
    """
    model_cls = load_schema(name)
    return model_cls.model_validate(data)


def validate_alert(data: dict) -> CanonicalAlert:
    """Convenience wrapper for validate('alert', data)."""
    return validate("alert", data)  # type: ignore[return-value]