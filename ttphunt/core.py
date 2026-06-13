"""Core hunting engine for TTPHUNT.

A rule is a Sigma-flavored detection mapped to a MITRE ATT&CK technique.
Each rule matches against normalized log events (one dict per event). Matching
supports field equality, list membership, substring (``contains``), regex
(``re``), and ``not`` negation, with all conditions ANDed together.

Events are read from JSON (array or JSONL). A handful of common fields are
normalized so the same rule pack works across slightly different log shapes.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Rule:
    id: str
    title: str
    technique: str          # MITRE ATT&CK id, e.g. T1059.001
    tactic: str
    severity: str
    description: str
    detection: Dict[str, Any]  # field -> matcher spec

    def severity_rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity.lower(), 0)


@dataclass
class Finding:
    rule: Rule
    event: Dict[str, Any]
    matched_fields: Dict[str, Any] = field(default_factory=dict)


# --- normalization ---------------------------------------------------------

_FIELD_ALIASES = {
    "command_line": "cmdline",
    "commandline": "cmdline",
    "command": "cmdline",
    "process_name": "image",
    "process": "image",
    "exe": "image",
    "src_ip": "source_ip",
    "srcip": "source_ip",
    "dst_ip": "dest_ip",
    "username": "user",
    "account": "user",
}


def _normalize_event(ev: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in ev.items():
        key = str(k).lower()
        key = _FIELD_ALIASES.get(key, key)
        out[key] = v
    return out


# --- matching --------------------------------------------------------------

def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return " ".join(str(x) for x in value)
    return str(value)


def _match_field(value: Any, spec: Any) -> bool:
    """Match a single event field value against a matcher spec."""
    # dict spec: operator-based
    if isinstance(spec, dict):
        for op, operand in spec.items():
            if not _apply_op(value, op, operand):
                return False
        return True
    # list spec: any-of equality (case-insensitive text compare)
    if isinstance(spec, list):
        vtext = _as_text(value).lower()
        return any(_as_text(s).lower() == vtext for s in spec)
    # scalar: case-insensitive equality
    return _as_text(value).lower() == _as_text(spec).lower()


def _apply_op(value: Any, op: str, operand: Any) -> bool:
    text = _as_text(value)
    op = op.lower()
    if op in ("eq", "equals"):
        return text.lower() == _as_text(operand).lower()
    if op in ("contains", "contains_any"):
        operands = operand if isinstance(operand, list) else [operand]
        low = text.lower()
        return any(_as_text(o).lower() in low for o in operands)
    if op == "contains_all":
        operands = operand if isinstance(operand, list) else [operand]
        low = text.lower()
        return all(_as_text(o).lower() in low for o in operands)
    if op in ("in", "any"):
        operands = operand if isinstance(operand, list) else [operand]
        return any(text.lower() == _as_text(o).lower() for o in operands)
    if op in ("re", "regex"):
        return re.search(operand, text, re.IGNORECASE) is not None
    if op in ("startswith",):
        return text.lower().startswith(_as_text(operand).lower())
    if op in ("endswith",):
        return text.lower().endswith(_as_text(operand).lower())
    if op == "not":
        return not _match_field(value, operand)
    raise ValueError(f"unknown match operator: {op}")


def _rule_matches(rule: Rule, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    matched: Dict[str, Any] = {}
    for fieldname, spec in rule.detection.items():
        fname = _FIELD_ALIASES.get(fieldname.lower(), fieldname.lower())
        value = event.get(fname)
        negate = False
        real_spec = spec
        if isinstance(spec, dict) and set(spec.keys()) == {"not"}:
            negate = True
            real_spec = spec["not"]
        ok = _match_field(value, real_spec)
        if negate:
            ok = not ok
        if not ok:
            return None
        if not negate:
            matched[fname] = value
    return matched


# --- loading ---------------------------------------------------------------

def load_events(path: str) -> List[Dict[str, Any]]:
    """Load events from a JSON array file or JSONL file."""
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    return load_events_from_text(text)


def load_events_from_text(text: str) -> List[Dict[str, Any]]:
    text = text.strip()
    if not text:
        return []
    events: List[Dict[str, Any]] = []
    # Try a single JSON document first.
    try:
        doc = json.loads(text)
        if isinstance(doc, list):
            events = [e for e in doc if isinstance(e, dict)]
        elif isinstance(doc, dict):
            # allow {"events": [...]} wrapper
            inner = doc.get("events")
            events = inner if isinstance(inner, list) else [doc]
        return [_normalize_event(e) for e in events]
    except json.JSONDecodeError:
        pass
    # Fall back to JSONL.
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        obj = json.loads(line)
        if isinstance(obj, dict):
            events.append(_normalize_event(obj))
    return events


def load_rules(path: str) -> List[Rule]:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, dict):
        data = data.get("rules", [])
    return [_rule_from_dict(d) for d in data]


def _rule_from_dict(d: Dict[str, Any]) -> Rule:
    return Rule(
        id=d["id"],
        title=d.get("title", d["id"]),
        technique=d.get("technique", ""),
        tactic=d.get("tactic", ""),
        severity=d.get("severity", "medium"),
        description=d.get("description", ""),
        detection=d.get("detection", {}),
    )


# --- hunting ---------------------------------------------------------------

def hunt(
    events: Iterable[Dict[str, Any]],
    rules: Iterable[Rule],
    min_severity: str = "info",
    techniques: Optional[Iterable[str]] = None,
) -> List[Finding]:
    rules = list(rules)
    min_rank = SEVERITY_ORDER.get(min_severity.lower(), 0)
    tech_filter = {t.upper() for t in techniques} if techniques else None
    findings: List[Finding] = []
    for ev in events:
        for rule in rules:
            if rule.severity_rank() < min_rank:
                continue
            if tech_filter and rule.technique.upper() not in tech_filter:
                continue
            matched = _rule_matches(rule, ev)
            if matched is not None:
                findings.append(Finding(rule=rule, event=ev, matched_fields=matched))
    findings.sort(key=lambda f: f.rule.severity_rank(), reverse=True)
    return findings


def summarize(findings: List[Finding]) -> Dict[str, Any]:
    by_sev: Dict[str, int] = {}
    by_tech: Dict[str, int] = {}
    by_tactic: Dict[str, int] = {}
    for f in findings:
        sev = f.rule.severity.lower()
        by_sev[sev] = by_sev.get(sev, 0) + 1
        key = f"{f.rule.technique} {f.rule.title}".strip()
        by_tech[key] = by_tech.get(key, 0) + 1
        tac = f.rule.tactic or "unknown"
        by_tactic[tac] = by_tactic.get(tac, 0) + 1
    return {
        "total": len(findings),
        "by_severity": by_sev,
        "by_technique": by_tech,
        "by_tactic": by_tactic,
    }


# --- built-in rule pack ----------------------------------------------------

DEFAULT_RULES: List[Rule] = [
    _rule_from_dict(d)
    for d in [
        {
            "id": "ttp-powershell-encoded",
            "title": "PowerShell Encoded Command",
            "technique": "T1059.001",
            "tactic": "Execution",
            "severity": "high",
            "description": "Obfuscated PowerShell via -EncodedCommand / -enc.",
            "detection": {
                "image": {"contains": "powershell"},
                "cmdline": {"re": r"(-enc(odedcommand)?|-e\b|frombase64string)"},
            },
        },
        {
            "id": "ttp-powershell-download-cradle",
            "title": "PowerShell Download Cradle",
            "technique": "T1059.001",
            "tactic": "Execution",
            "severity": "high",
            "description": "In-memory download + execute via Net.WebClient/IEX.",
            "detection": {
                "image": {"contains": "powershell"},
                "cmdline": {"contains_any": ["downloadstring", "downloadfile", "iex(", "invoke-expression"]},
            },
        },
        {
            "id": "ttp-certutil-download",
            "title": "Certutil Used to Download/Decode",
            "technique": "T1105",
            "tactic": "Command and Control",
            "severity": "high",
            "description": "LOLBIN certutil -urlcache/-decode abuse.",
            "detection": {
                "image": {"contains": "certutil"},
                "cmdline": {"contains_any": ["-urlcache", "-decode", "-decodehex", "urlcache"]},
            },
        },
        {
            "id": "ttp-wmic-process-call",
            "title": "WMIC Remote/Local Process Creation",
            "technique": "T1047",
            "tactic": "Execution",
            "severity": "medium",
            "description": "wmic process call create used for execution.",
            "detection": {
                "image": {"contains": "wmic"},
                "cmdline": {"contains_all": ["process", "call", "create"]},
            },
        },
        {
            "id": "ttp-bcdedit-recovery-disable",
            "title": "Inhibit System Recovery (bcdedit/vssadmin/wbadmin)",
            "technique": "T1490",
            "tactic": "Impact",
            "severity": "critical",
            "description": "Shadow-copy / recovery tampering — common ransomware precursor.",
            "detection": {
                "cmdline": {"re": r"(vssadmin\s+delete\s+shadows|wbadmin\s+delete|bcdedit.*recoveryenabled\s+no|wmic\s+shadowcopy\s+delete)"},
            },
        },
        {
            "id": "ttp-registry-run-key",
            "title": "Run Key Persistence via reg.exe",
            "technique": "T1547.001",
            "tactic": "Persistence",
            "severity": "medium",
            "description": "reg add writing to a Run/RunOnce autostart key.",
            "detection": {
                "cmdline": {"re": r"reg(\.exe)?\s+add.*\\(run|runonce)\b"},
            },
        },
        {
            "id": "ttp-scheduled-task-create",
            "title": "Scheduled Task Creation",
            "technique": "T1053.005",
            "tactic": "Persistence",
            "severity": "medium",
            "description": "schtasks /create used for persistence or execution.",
            "detection": {
                "image": {"contains": "schtasks"},
                "cmdline": {"contains": "/create"},
            },
        },
        {
            "id": "ttp-mshta-execution",
            "title": "Mshta Remote Script Execution",
            "technique": "T1218.005",
            "tactic": "Defense Evasion",
            "severity": "high",
            "description": "mshta executing http(s) or script: payloads (signed-binary proxy).",
            "detection": {
                "image": {"contains": "mshta"},
                "cmdline": {"re": r"(https?:|javascript:|vbscript:)"},
            },
        },
        {
            "id": "ttp-rundll32-suspicious",
            "title": "Rundll32 Proxy Execution",
            "technique": "T1218.011",
            "tactic": "Defense Evasion",
            "severity": "medium",
            "description": "rundll32 invoking javascript: or url.dll,OpenURL style proxy.",
            "detection": {
                "image": {"contains": "rundll32"},
                "cmdline": {"contains_any": ["javascript:", "url.dll,openurl", "shell32.dll,control_rundll"]},
            },
        },
        {
            "id": "ttp-clear-event-logs",
            "title": "Windows Event Log Cleared",
            "technique": "T1070.001",
            "tactic": "Defense Evasion",
            "severity": "high",
            "description": "wevtutil cl / Clear-EventLog indicator removal.",
            "detection": {
                "cmdline": {"re": r"(wevtutil\s+cl|clear-eventlog|wevtutil\s+clear-log)"},
            },
        },
        {
            "id": "ttp-net-user-add",
            "title": "Local Account Created via net user",
            "technique": "T1136.001",
            "tactic": "Persistence",
            "severity": "medium",
            "description": "net user /add or net localgroup administrators /add.",
            "detection": {
                "cmdline": {"re": r"net(\s+\d)?\s+(user|localgroup).*\/add"},
            },
        },
        {
            "id": "ttp-failed-logon-burst",
            "title": "Failed Logon (Brute Force Candidate)",
            "technique": "T1110",
            "tactic": "Credential Access",
            "severity": "low",
            "description": "Authentication failure events (correlate volume externally).",
            "detection": {
                "event_id": {"in": ["4625", 4625]},
            },
        },
    ]
]
