"""Wazuh SIEM adapter — public API (Day 5).

Public surface is intentionally tiny. Additional helpers may live in
submodules but must not be re-exported without a contract change.
"""

from adapters.siem.wazuh.src.parser import WazuhParseError, parse

__all__ = ["parse", "WazuhParseError"]