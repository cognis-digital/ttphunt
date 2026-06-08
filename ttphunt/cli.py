"""Command-line interface for TTPHUNT."""
from __future__ import annotations

import argparse
import html
import json
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    DEFAULT_RULES,
    Finding,
    SEVERITY_ORDER,
    hunt,
    load_events,
    load_rules,
    summarize,
)

_SEV_COLOR = {
    "critical": "#7c1d1d",
    "high": "#b91c1c",
    "medium": "#b45309",
    "low": "#1d4ed8",
    "info": "#374151",
}


def _finding_dict(f: Finding) -> dict:
    return {
        "rule_id": f.rule.id,
        "title": f.rule.title,
        "technique": f.rule.technique,
        "tactic": f.rule.tactic,
        "severity": f.rule.severity,
        "description": f.rule.description,
        "matched_fields": f.matched_fields,
        "event": f.event,
    }


def _render_table(findings: List[Finding], summary: dict) -> str:
    lines = []
    lines.append(f"{TOOL_NAME} {TOOL_VERSION} - {summary['total']} finding(s)")
    sev = summary["by_severity"]
    if sev:
        order = sorted(sev, key=lambda s: SEVERITY_ORDER.get(s, 0), reverse=True)
        lines.append("  " + "  ".join(f"{s}={sev[s]}" for s in order))
    lines.append("")
    if not findings:
        lines.append("No techniques detected.")
        return "\n".join(lines)
    header = f"{'SEVERITY':<9} {'TECHNIQUE':<12} {'TACTIC':<20} TITLE"
    lines.append(header)
    lines.append("-" * len(header))
    for f in findings:
        lines.append(
            f"{f.rule.severity.upper():<9} {f.rule.technique:<12} "
            f"{f.rule.tactic:<20} {f.rule.title}"
        )
        ev = f.event
        ctx = ev.get("cmdline") or ev.get("image") or ev.get("message") or ""
        host = ev.get("host") or ev.get("hostname") or ""
        ts = ev.get("timestamp") or ev.get("time") or ""
        meta = "  ".join(x for x in [str(ts), str(host)] if x)
        if meta:
            lines.append(f"          {meta}")
        if ctx:
            lines.append(f"          > {str(ctx)[:160]}")
    return "\n".join(lines)


def _render_html(findings: List[Finding], summary: dict, source: str) -> str:
    rows = []
    for f in findings:
        color = _SEV_COLOR.get(f.rule.severity.lower(), "#374151")
        ev = f.event
        ctx = html.escape(str(ev.get("cmdline") or ev.get("image") or ev.get("message") or ""))
        host = html.escape(str(ev.get("host") or ev.get("hostname") or ""))
        ts = html.escape(str(ev.get("timestamp") or ev.get("time") or ""))
        rows.append(f"""      <tr>
        <td><span class="badge" style="background:{color}">{html.escape(f.rule.severity.upper())}</span></td>
        <td class="mono">{html.escape(f.rule.technique)}</td>
        <td>{html.escape(f.rule.tactic)}</td>
        <td>{html.escape(f.rule.title)}<div class="desc">{html.escape(f.rule.description)}</div></td>
        <td class="mono small">{ts} {host}</td>
        <td class="mono small evidence">{ctx}</td>
      </tr>""")
    sev = summary["by_severity"]
    sev_order = sorted(sev, key=lambda s: SEVERITY_ORDER.get(s, 0), reverse=True)
    sev_cards = "".join(
        f'<div class="card" style="border-color:{_SEV_COLOR.get(s, "#374151")}">'
        f'<div class="num" style="color:{_SEV_COLOR.get(s, "#374151")}">{sev[s]}</div>'
        f'<div class="lbl">{html.escape(s.upper())}</div></div>'
        for s in sev_order
    )
    tech_rows = "".join(
        f"<tr><td class=mono>{html.escape(k)}</td><td>{v}</td></tr>"
        for k, v in sorted(summary["by_technique"].items(), key=lambda kv: kv[1], reverse=True)
    )
    body_rows = "\n".join(rows) if rows else (
        '<tr><td colspan="6" style="text-align:center;padding:24px;color:#16a34a">'
        'No ATT&amp;CK techniques detected.</td></tr>'
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{TOOL_NAME} report</title>
<style>
  :root {{ font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; }}
  body {{ margin:0; background:#0f172a; color:#e2e8f0; }}
  header {{ padding:20px 28px; background:#111827; border-bottom:2px solid #1f2937; }}
  h1 {{ margin:0; font-size:20px; }} h1 span {{ color:#38bdf8; }}
  .sub {{ color:#94a3b8; font-size:13px; margin-top:4px; }}
  .wrap {{ padding:20px 28px; }}
  .cards {{ display:flex; gap:12px; flex-wrap:wrap; margin-bottom:20px; }}
  .card {{ background:#1e293b; border-left:4px solid; border-radius:6px; padding:10px 16px; min-width:80px; }}
  .card .num {{ font-size:26px; font-weight:700; }}
  .card .lbl {{ font-size:11px; color:#94a3b8; letter-spacing:.5px; }}
  table {{ width:100%; border-collapse:collapse; background:#1e293b; border-radius:8px; overflow:hidden; margin-bottom:24px; }}
  th, td {{ text-align:left; padding:10px 12px; border-bottom:1px solid #334155; vertical-align:top; font-size:13px; }}
  th {{ background:#0b1220; color:#94a3b8; text-transform:uppercase; font-size:11px; letter-spacing:.5px; }}
  tr:last-child td {{ border-bottom:none; }}
  .badge {{ color:#fff; padding:2px 8px; border-radius:10px; font-size:11px; font-weight:700; }}
  .mono {{ font-family: ui-monospace, SFMono-Regular, Consolas, monospace; }}
  .small {{ font-size:11px; }}
  .desc {{ color:#94a3b8; font-size:11px; margin-top:3px; }}
  .evidence {{ color:#fbbf24; max-width:480px; word-break:break-all; }}
  h2 {{ font-size:14px; color:#cbd5e1; border-left:3px solid #38bdf8; padding-left:8px; }}
</style></head>
<body>
<header>
  <h1><span>{TOOL_NAME}</span> ATT&amp;CK Hunt Report <span style="color:#64748b;font-size:13px">v{TOOL_VERSION}</span></h1>
  <div class="sub">Source: {html.escape(source)} &middot; {summary['total']} finding(s)</div>
</header>
<div class="wrap">
  <div class="cards">{sev_cards or '<div class=card><div class=num>0</div><div class=lbl>FINDINGS</div></div>'}</div>
  <h2>Findings</h2>
  <table>
    <thead><tr><th>Severity</th><th>Technique</th><th>Tactic</th><th>Rule</th><th>When / Host</th><th>Evidence</th></tr></thead>
    <tbody>
{body_rows}
    </tbody>
  </table>
  <h2>By Technique</h2>
  <table><thead><tr><th>Technique</th><th>Count</th></tr></thead><tbody>{tech_rows or '<tr><td colspan=2>none</td></tr>'}</tbody></table>
</div>
</body></html>"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Hunt MITRE ATT&CK techniques across logs with a rule pack.",
    )
    p.add_argument("--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = p.add_subparsers(dest="command")

    h = sub.add_parser("hunt", help="Scan a log file for ATT&CK techniques.")
    h.add_argument("logfile", help="Path to JSON array or JSONL log file.")
    h.add_argument("-r", "--rules", help="Path to custom rule pack JSON (default: built-in).")
    h.add_argument("--format", choices=["table", "json", "html"], default="table")
    h.add_argument("-o", "--output", help="Write report to this file instead of stdout.")
    h.add_argument("--min-severity", default="info", choices=list(SEVERITY_ORDER))
    h.add_argument("-t", "--technique", action="append", help="Only this ATT&CK technique id (repeatable).")

    lr = sub.add_parser("rules", help="List rules in the active pack.")
    lr.add_argument("-r", "--rules", help="Path to custom rule pack JSON (default: built-in).")
    lr.add_argument("--format", choices=["table", "json"], default="table")

    return p


def _cmd_rules(args) -> int:
    rules = load_rules(args.rules) if args.rules else DEFAULT_RULES
    if args.format == "json":
        print(json.dumps([
            {"id": r.id, "title": r.title, "technique": r.technique,
             "tactic": r.tactic, "severity": r.severity} for r in rules
        ], indent=2))
        return 0
    print(f"{TOOL_NAME}: {len(rules)} rule(s)")
    for r in rules:
        print(f"  [{r.severity.upper():<8}] {r.technique:<12} {r.id:<32} {r.title}")
    return 0


def _cmd_hunt(args) -> int:
    try:
        events = load_events(args.logfile)
    except (OSError, ValueError) as exc:
        print(f"{TOOL_NAME}: error reading log: {exc}", file=sys.stderr)
        return 2
    try:
        rules = load_rules(args.rules) if args.rules else DEFAULT_RULES
    except (OSError, ValueError, KeyError) as exc:
        print(f"{TOOL_NAME}: error loading rules: {exc}", file=sys.stderr)
        return 2

    findings = hunt(
        events, rules,
        min_severity=args.min_severity,
        techniques=args.technique,
    )
    summary = summarize(findings)

    if args.format == "json":
        out = json.dumps({
            "tool": TOOL_NAME, "version": TOOL_VERSION,
            "source": args.logfile, "summary": summary,
            "findings": [_finding_dict(f) for f in findings],
        }, indent=2)
    elif args.format == "html":
        out = _render_html(findings, summary, args.logfile)
    else:
        out = _render_table(findings, summary)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out)
        print(f"{TOOL_NAME}: wrote {args.format} report -> {args.output} "
              f"({summary['total']} finding(s))", file=sys.stderr)
    else:
        print(out)

    # Non-zero exit when findings exist (useful in CI/pipelines).
    return 1 if findings else 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 0
    if args.command == "rules":
        return _cmd_rules(args)
    if args.command == "hunt":
        return _cmd_hunt(args)
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
