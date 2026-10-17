"""Shared helpers for schema consistency tests.

Extracts field metadata from canonical YAML schemas and compares it
against Pydantic model definitions. Scope is limited to top-level
fields per core/schema/INTERFACE.md §7 (nested fields deferred to v0.2).
"""

from __future__ import annotations

import enum
import types
import typing
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel


REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMAS_DIR = REPO_ROOT / "schemas"


# ---------------------------------------------------------------------------
# YAML type -> Python type mapping (INTERFACE.md §7)
# ---------------------------------------------------------------------------

YAML_TYPE_MAP: dict[str, type] = {
    "string": str,
    "integer": int,
    "boolean": bool,
}


def load_yaml_schema(schema_name: str) -> dict[str, Any]:
    """Load and return a canonical schema YAML as a dict."""
    path = SCHEMAS_DIR / f"{schema_name}.yaml"
    with open(path) as f:
        return yaml.safe_load(f)


def yaml_field_names(doc: dict[str, Any]) -> set[str]:
    """Return the set of top-level field names declared in the YAML."""
    names: set[str] = set()
    for section in ("required", "optional"):
        section_data = doc.get(section) or {}
        names.update(section_data.keys())
    return names


def yaml_field_is_required(doc: dict[str, Any], field: str) -> bool:
    """Return True if the field appears under the YAML `required:` section."""
    required = doc.get("required") or {}
    return field in required


def yaml_field_decl(doc: dict[str, Any], field: str) -> dict[str, Any]:
    """Return the YAML field declaration dict for a top-level field."""
    for section in ("required", "optional"):
        section_data = doc.get(section) or {}
        if field in section_data:
            return section_data[field]
    raise KeyError(f"Field {field!r} not found in required/optional sections")


def yaml_field_type(decl: dict[str, Any]) -> Any:
    """Return the expected Python type for a YAML field declaration.

    Special cases per INTERFACE.md §7:
      - string + format: date-time     -> datetime
      - string + format: ipv4-or-ipv6  -> str (format enforced separately)
      - object                         -> dict (sentinel; matched loosely)
      - array                          -> list (sentinel; matched loosely)
    """
    yaml_type = decl.get("type")
    fmt = decl.get("format")

    if yaml_type == "string":
        if fmt == "date-time":
            return datetime
        return str
    if yaml_type in YAML_TYPE_MAP:
        return YAML_TYPE_MAP[yaml_type]
    if yaml_type == "object":
        return dict
    if yaml_type == "array":
        return list
    raise ValueError(f"Unmapped YAML type: {yaml_type!r} (format={fmt!r})")


def yaml_field_is_nullable(decl: dict[str, Any]) -> bool:
    """Return True if the YAML field declares nullable: true."""
    return bool(decl.get("nullable", False))


def yaml_field_enum(decl: dict[str, Any]) -> list[Any] | None:
    """Return the YAML enum values, or None if not a strict enum."""
    enum_values = decl.get("enum")
    if enum_values is None:
        return None
    return list(enum_values)


# ---------------------------------------------------------------------------
# Pydantic model introspection
# ---------------------------------------------------------------------------

def model_field_names(model_cls: type[BaseModel]) -> set[str]:
    """Return the set of top-level field names declared on a model."""
    return set(model_cls.model_fields.keys())


def model_field_is_required(model_cls: type[BaseModel], field: str) -> bool:
    """Return True if the field is required (no default and not Optional)."""
    info = model_cls.model_fields[field]
    return info.is_required()


def pydantic_underlying_type(annotation: Any) -> tuple[Any, bool]:
    """Extract the underlying type from a possibly-Optional annotation.

    Returns (base_type, is_optional). Supports both:
      - typing.Optional[X]  -> typing.Union[X, None]
      - X | None            -> types.UnionType (PEP 604, Python 3.10+)
    """
    origin = typing.get_origin(annotation)

    if origin is typing.Union or origin is types.UnionType:
        args = typing.get_args(annotation)
        non_none = [a for a in args if a is not type(None)]
        has_none = len(non_none) < len(args)
        if len(non_none) == 1:
            return non_none[0], has_none
        # Multi-type union that isn't just "X | None"; return as-is.
        return annotation, has_none

    return annotation, False


def model_field_python_type(model_cls: type[BaseModel], field: str) -> Any:
    """Return the underlying Python type for a model field."""
    info = model_cls.model_fields[field]
    base, _ = pydantic_underlying_type(info.annotation)
    return base


def model_field_is_nullable(model_cls: type[BaseModel], field: str) -> bool:
    """Return True if the model field allows None."""
    info = model_cls.model_fields[field]
    _, is_optional = pydantic_underlying_type(info.annotation)
    return is_optional


def model_field_enum_values(
    model_cls: type[BaseModel], field: str
) -> list[Any] | None:
    """Return the set of allowed values for an enum-typed field.

    Supports:
      - Literal["a", "b", "c"]         -> ["a", "b", "c"]
      - class Color(str, Enum): ...    -> ["red", "green", ...]  (member.value)
      - bare enum.Enum subclasses      -> same, via member.value
    Returns None if the field is neither a Literal nor an Enum.
    """
    info = model_cls.model_fields[field]
    annotation, _ = pydantic_underlying_type(info.annotation)

    if typing.get_origin(annotation) is typing.Literal:
        return list(typing.get_args(annotation))

    if isinstance(annotation, type) and issubclass(annotation, enum.Enum):
        return [member.value for member in annotation]

    return None


# ---------------------------------------------------------------------------
# Type-acceptance helpers (used by the type-consistency test)
# ---------------------------------------------------------------------------

def is_object_type(actual: Any) -> bool:
    """True if `actual` is a valid model-side type for a YAML `object`.

    Accepts:
      - the bare dict type
      - a dict[...] generic alias (e.g. dict[str, Any])
      - a Pydantic BaseModel subclass
    """
    if actual is dict:
        return True
    if typing.get_origin(actual) is dict:
        return True
    if isinstance(actual, type) and issubclass(actual, BaseModel):
        return True
    return False


def is_array_type(actual: Any) -> bool:
    """True if `actual` is a valid model-side type for a YAML `array`.

    Accepts the bare list type and any list[...] generic alias.
    """
    if actual is list:
        return True
    if typing.get_origin(actual) is list:
        return True
    return False