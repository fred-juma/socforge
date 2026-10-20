"""Detection engine package (Day 7).

Public API:
    run(alerts, rules) -> list[DetectionHit]
    load_rules(rules_dir) -> list[DetectionRule]
"""

from core.detection.engine import run
from core.detection.models import (
    DetectionHit,
    DetectionRule,
    MatchConfig,
    ThresholdConfig,
)
from core.detection.rule_loader import load_rules

__all__ = [
    "run",
    "load_rules",
    "DetectionRule",
    "DetectionHit",
    "MatchConfig",
    "ThresholdConfig",
]