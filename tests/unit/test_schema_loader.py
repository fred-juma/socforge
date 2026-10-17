"""Unit tests for core.schema.loader.

Covers the six testing requirements in core/schema/INTERFACE.md §7:

  1. All four schema keys resolve to expected model classes.
  2. Valid canonical alert data produces a CanonicalAlert instance.
  3. Invalid canonical alert data raises Pydantic ValidationError.
  4. YAML and Pydantic models agree on top-level required/optional
     fields, types, nullability, and explicit enums.
  5. Generic validate() returns the correct concrete instance.
  6. Unknown schema names raise KeyError.

Plus format-validation tests (Req 4's format sub-clause):
  - Invalid timestamp raises ValidationError.
  - Invalid source_ip raises ValidationError.

Consistency-test scope (v0.1): top-level fields only. Nested fields and
enum_hint are deferred, per INTERFACE.md §7.
"""

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from core.schema import models
from core.schema.loader import load_schema, validate, validate_alert

from tests.unit import _schema_helpers as helpers


REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures"


SCHEMA_MODEL_PAIRS = [
    ("alert", "canonical_alert_valid.json", models.CanonicalAlert),
    ("case", "canonical_case_valid.json", models.CanonicalCase),
    ("entity", "canonical_entity_valid.json", models.CanonicalEntity),
    ("action", "canonical_action_valid.json", models.CanonicalAction),
]


CONSISTENCY_PAIRS = [
    ("canonical_alert", models.CanonicalAlert),
    ("canonical_case", models.CanonicalCase),
    ("canonical_entity", models.CanonicalEntity),
    ("canonical_action", models.CanonicalAction),
]


def _load_fixture(name: str) -> dict:
    with open(FIXTURES_DIR / name) as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Requirement 1: registry
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name,_fixture,model_cls", SCHEMA_MODEL_PAIRS)
def test_load_schema_returns_expected_class(name, _fixture, model_cls):
    """Req 1: each schema key resolves to its expected model class."""
    assert load_schema(name) is model_cls


# ---------------------------------------------------------------------------
# Requirement 5: generic validate() dispatch
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name,fixture_name,model_cls", SCHEMA_MODEL_PAIRS)
def test_validate_returns_concrete_model_instance(name, fixture_name, model_cls):
    """Req 5: validate() returns the correct concrete instance."""
    data = _load_fixture(fixture_name)
    result = validate(name, data)
    assert isinstance(result, model_cls)


# ---------------------------------------------------------------------------
# Requirements 2 and 3: valid / invalid alert
# ---------------------------------------------------------------------------

def test_valid_alert_passes():
    """Req 2: valid canonical alert data produces a CanonicalAlert."""
    data = _load_fixture("canonical_alert_valid.json")
    result = validate_alert(data)
    assert isinstance(result, models.CanonicalAlert)


def test_invalid_alert_raises():
    """Req 3: malformed alert data raises Pydantic ValidationError."""
    malformed = {"id": "x"}  # missing all other required fields
    with pytest.raises(ValidationError):
        validate_alert(malformed)


# ---------------------------------------------------------------------------
# Requirement 6: unknown schema names
# ---------------------------------------------------------------------------

def test_load_schema_unknown_name_raises_keyerror():
    """Req 6: unknown name to load_schema raises KeyError."""
    with pytest.raises(KeyError):
        load_schema("not-a-schema")


def test_validate_unknown_name_raises_keyerror():
    """Req 6: unknown name to validate raises KeyError."""
    with pytest.raises(KeyError):
        validate("not-a-schema", {})


# ---------------------------------------------------------------------------
# Format validation (INTERFACE.md §7 format sub-clause)
# ---------------------------------------------------------------------------

def test_invalid_timestamp_raises():
    """Format: a non-ISO-8601 timestamp raises ValidationError."""
    data = _load_fixture("canonical_alert_valid.json")
    data["timestamp"] = "not-a-date"
    with pytest.raises(ValidationError):
        validate_alert(data)


def test_invalid_source_ip_raises():
    """Format: a malformed source_ip raises ValidationError."""
    data = _load_fixture("canonical_alert_valid.json")
    data["source_ip"] = "999.999.999.999"
    with pytest.raises(ValidationError):
        validate_alert(data)


# ---------------------------------------------------------------------------
# Requirement 4: YAML / model consistency
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("schema_name,_model_cls", CONSISTENCY_PAIRS)
def test_yaml_parses(schema_name, _model_cls):
    """Req 4a: schema YAML parses via yaml.safe_load()."""
    doc = helpers.load_yaml_schema(schema_name)
    assert isinstance(doc, dict)


@pytest.mark.parametrize("schema_name,model_cls", CONSISTENCY_PAIRS)
def test_yaml_and_model_top_level_fields_agree(schema_name, model_cls):
    """Req 4b: top-level field names agree between YAML and model."""
    doc = helpers.load_yaml_schema(schema_name)
    yaml_fields = helpers.yaml_field_names(doc)
    model_fields = helpers.model_field_names(model_cls)

    only_in_yaml = yaml_fields - model_fields
    only_in_model = model_fields - yaml_fields

    assert not only_in_yaml, f"Fields in YAML but not model: {sorted(only_in_yaml)}"
    assert not only_in_model, f"Fields in model but not YAML: {sorted(only_in_model)}"


@pytest.mark.parametrize("schema_name,model_cls", CONSISTENCY_PAIRS)
def test_yaml_and_model_required_status_agrees(schema_name, model_cls):
    """Req 4c: required/optional status agrees between YAML and model."""
    doc = helpers.load_yaml_schema(schema_name)
    mismatches = []

    for field in helpers.yaml_field_names(doc):
        yaml_required = helpers.yaml_field_is_required(doc, field)
        model_required = helpers.model_field_is_required(model_cls, field)
        if yaml_required != model_required:
            mismatches.append(
                f"{field}: yaml_required={yaml_required}, "
                f"model_required={model_required}"
            )

    assert not mismatches, "Required/optional mismatches:\n" + "\n".join(mismatches)


@pytest.mark.parametrize("schema_name,model_cls", CONSISTENCY_PAIRS)
def test_yaml_and_model_types_agree(schema_name, model_cls):
    """Req 4d: declared type agrees between YAML and model.

    Fields with a strict YAML enum are skipped here — their values are
    compared by test_yaml_and_model_enums_agree. Their model-side type
    is an Enum subclass (a str subclass), which the strict type
    comparison would reject even though the enum values match.
    """
    doc = helpers.load_yaml_schema(schema_name)
    mismatches = []

    for field in helpers.yaml_field_names(doc):
        decl = helpers.yaml_field_decl(doc, field)

        # Enum fields are covered by the enum-consistency test, not here.
        if helpers.yaml_field_enum(decl) is not None:
            continue

        yaml_type = decl.get("type")
        actual = helpers.model_field_python_type(model_cls, field)

        if yaml_type == "object":
            if not helpers.is_object_type(actual):
                mismatches.append(f"{field}: object vs {actual}")
            continue

        if yaml_type == "array":
            if not helpers.is_array_type(actual):
                mismatches.append(f"{field}: array vs {actual}")
            continue

        expected = helpers.yaml_field_type(decl)
        if expected is not actual:
            mismatches.append(f"{field}: expected {expected}, got {actual}")

    assert not mismatches, "Type mismatches:\n" + "\n".join(mismatches)


@pytest.mark.parametrize("schema_name,model_cls", CONSISTENCY_PAIRS)
def test_yaml_and_model_nullability_agrees(schema_name, model_cls):
    """Req 4e: nullability agrees between YAML and model."""
    doc = helpers.load_yaml_schema(schema_name)
    mismatches = []

    for field in helpers.yaml_field_names(doc):
        decl = helpers.yaml_field_decl(doc, field)
        yaml_nullable = helpers.yaml_field_is_nullable(decl)
        model_nullable = helpers.model_field_is_nullable(model_cls, field)
        if yaml_nullable != model_nullable:
            mismatches.append(
                f"{field}: yaml_nullable={yaml_nullable}, "
                f"model_nullable={model_nullable}"
            )

    assert not mismatches, "Nullability mismatches:\n" + "\n".join(mismatches)


@pytest.mark.parametrize("schema_name,model_cls", CONSISTENCY_PAIRS)
def test_yaml_and_model_enums_agree(schema_name, model_cls):
    """Req 4f: explicit enum values agree between YAML and model."""
    doc = helpers.load_yaml_schema(schema_name)
    mismatches = []

    for field in helpers.yaml_field_names(doc):
        decl = helpers.yaml_field_decl(doc, field)
        yaml_enum = helpers.yaml_field_enum(decl)
        if yaml_enum is None:
            continue  # field has no strict enum

        model_enum = helpers.model_field_enum_values(model_cls, field)
        if model_enum is None:
            mismatches.append(
                f"{field}: YAML enum present but model has no Literal/Enum"
            )
            continue

        if set(yaml_enum) != set(model_enum):
            mismatches.append(f"{field}: yaml={yaml_enum}, model={model_enum}")

    assert not mismatches, "Enum mismatches:\n" + "\n".join(mismatches)