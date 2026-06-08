"""TTPHUNT - Hunt MITRE ATT&CK techniques across logs with a rule pack.

Defensive forensics/triage tool. Stdlib only, zero install.
"""
from .core import (
    Rule,
    Finding,
    DEFAULT_RULES,
    load_rules,
    load_events,
    hunt,
    summarize,
)

TOOL_NAME = "ttphunt"
TOOL_VERSION = "1.0.0"

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "Rule",
    "Finding",
    "DEFAULT_RULES",
    "load_rules",
    "load_events",
    "hunt",
    "summarize",
]
