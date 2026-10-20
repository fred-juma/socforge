"""Load DetectionRule objects from a directory of YAML files.

Public API:
    load_rules(rules_dir: Path | str) -> list[DetectionRule]

Behaviour:
  - Returns [] if the directory is missing.
  - Only *.yaml files are considered.
  - Files are sorted by filename for deterministic ordering.
  - A malformed rule raises ValueError with the offending path.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from core.detection.models import DetectionRule


def load_rules(rules_dir: Path | str) -> list[DetectionRule]:
    """Load all *.yaml rules from rules_dir, sorted by filename.

    Raises:
        ValueError: if a file fails YAML parsing or DetectionRule validation.
    """
    path = Path(rules_dir)
    if not path.exists() or not path.is_dir():
        return []

    rules: list[DetectionRule] = []
    for yaml_file in sorted(path.glob("*.yaml")):
        try:
            with open(yaml_file, encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except yaml.YAMLError as exc:
            raise ValueError(f"Invalid YAML in {yaml_file}: {exc}") from exc

        if data is None:
            raise ValueError(f"Empty rule file: {yaml_file}")

        try:
            rules.append(DetectionRule.model_validate(data))
        except Exception as exc:
            raise ValueError(f"Invalid rule in {yaml_file}: {exc}") from exc

    return rules