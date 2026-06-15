"""TTPHUNT MCP server — exposes hunt as an MCP tool for Cognis.Studio."""
from __future__ import annotations

import json

from ttphunt.core import DEFAULT_RULES, hunt, load_events_from_text, summarize


def _scan_text(text: str) -> str:
    """Run a hunt over raw log text and return a JSON findings payload."""
    events = load_events_from_text(text)
    findings = hunt(events, DEFAULT_RULES)
    summary = summarize(findings)
    return json.dumps(
        {
            "summary": summary,
            "findings": [
                {
                    "rule_id": f.rule.id,
                    "title": f.rule.title,
                    "technique": f.rule.technique,
                    "tactic": f.rule.tactic,
                    "severity": f.rule.severity,
                    "matched_fields": f.matched_fields,
                }
                for f in findings
            ],
        },
        indent=2,
    )


def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-ttphunt[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-ttphunt[mcp]'")
        return 1
    app = FastMCP("ttphunt")

    @app.tool()
    def ttphunt_scan(log_text: str) -> str:
        """Hunt MITRE ATT&CK techniques across logs with a rule pack. Returns JSON findings."""
        return _scan_text(log_text)

    app.run()
    return 0
