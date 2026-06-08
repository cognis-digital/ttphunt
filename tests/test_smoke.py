"""Smoke tests for TTPHUNT. Stdlib + unittest only, no network."""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ttphunt import (  # noqa: E402
    TOOL_NAME,
    TOOL_VERSION,
    DEFAULT_RULES,
    hunt,
    summarize,
)
from ttphunt.core import load_events_from_text  # noqa: E402
from ttphunt.cli import main, _render_html  # noqa: E402

DEMO = os.path.join(os.path.dirname(__file__), "..", "demos", "01-basic", "endpoint.jsonl")


class TestCore(unittest.TestCase):
    def setUp(self):
        with open(DEMO, encoding="utf-8") as fh:
            self.events = load_events_from_text(fh.read())

    def test_metadata(self):
        self.assertEqual(TOOL_NAME, "ttphunt")
        self.assertTrue(TOOL_VERSION)

    def test_default_rules_loaded(self):
        self.assertGreater(len(DEFAULT_RULES), 5)

    def test_events_loaded(self):
        self.assertEqual(len(self.events), 10)

    def test_hunt_finds_known_techniques(self):
        findings = hunt(self.events, DEFAULT_RULES)
        techs = {f.rule.technique for f in findings}
        for expected in {"T1059.001", "T1105", "T1490", "T1070.001", "T1547.001", "T1110"}:
            self.assertIn(expected, techs, f"missing {expected}")

    def test_benign_not_flagged(self):
        findings = hunt(self.events, DEFAULT_RULES)
        for f in findings:
            self.assertNotIn("notepad", str(f.event.get("cmdline", "")).lower())

    def test_severity_sorting(self):
        findings = hunt(self.events, DEFAULT_RULES)
        ranks = [f.rule.severity_rank() for f in findings]
        self.assertEqual(ranks, sorted(ranks, reverse=True))

    def test_min_severity_filter(self):
        all_f = hunt(self.events, DEFAULT_RULES, min_severity="info")
        crit = hunt(self.events, DEFAULT_RULES, min_severity="critical")
        self.assertLess(len(crit), len(all_f))
        self.assertTrue(all(f.rule.severity == "critical" for f in crit))

    def test_technique_filter(self):
        only = hunt(self.events, DEFAULT_RULES, techniques=["T1490"])
        self.assertTrue(only)
        self.assertTrue(all(f.rule.technique == "T1490" for f in only))

    def test_summarize(self):
        s = summarize(hunt(self.events, DEFAULT_RULES))
        self.assertGreater(s["total"], 0)
        self.assertIn("critical", s["by_severity"])

    def test_jsonl_and_array_equivalent(self):
        arr = json.dumps([{"image": "powershell", "cmdline": "powershell -enc AAAA"}])
        jl = '{"image": "powershell", "cmdline": "powershell -enc AAAA"}'
        self.assertEqual(
            len(load_events_from_text(arr)), len(load_events_from_text(jl))
        )

    def test_field_alias_normalization(self):
        ev = load_events_from_text('{"CommandLine": "vssadmin delete shadows /all"}')
        findings = hunt(ev, DEFAULT_RULES)
        self.assertTrue(any(f.rule.technique == "T1490" for f in findings))

    def test_html_self_contained(self):
        findings = hunt(self.events, DEFAULT_RULES)
        out = _render_html(findings, summarize(findings), "demo")
        self.assertIn("<!doctype html>", out)
        self.assertIn("<style>", out)
        self.assertNotIn("http://", out.split("<body>")[0])  # no external assets in head


class TestCLI(unittest.TestCase):
    def test_hunt_exit_code_on_findings(self):
        rc = main(["hunt", DEMO, "--format", "json"])
        self.assertEqual(rc, 1)

    def test_no_findings_exit_zero(self):
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False, encoding="utf-8") as fh:
            fh.write('{"image": "notepad.exe", "cmdline": "notepad.exe hello.txt"}\n')
            path = fh.name
        try:
            self.assertEqual(main(["hunt", path, "--format", "json"]), 0)
        finally:
            os.unlink(path)

    def test_missing_file_exit_two(self):
        self.assertEqual(main(["hunt", "/no/such/file.jsonl"]), 2)

    def test_html_output_written(self):
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as fh:
            out = fh.name
        try:
            rc = main(["hunt", DEMO, "--format", "html", "-o", out])
            self.assertEqual(rc, 1)
            with open(out, encoding="utf-8") as f:
                self.assertIn("ATT&amp;CK Hunt Report", f.read())
        finally:
            os.unlink(out)

    def test_rules_subcommand(self):
        self.assertEqual(main(["rules", "--format", "json"]), 0)


if __name__ == "__main__":
    unittest.main()
