"""Hardening tests: error paths, edge cases, and bad-input handling.

All tests use stdlib only; no network calls.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ttphunt.core import (  # noqa: E402
    DEFAULT_RULES,
    hunt,
    load_events_from_text,
    load_rules,
    summarize,
    _rule_from_dict,
    _apply_op,
)
from ttphunt.cli import main  # noqa: E402


class TestLoadEventsEdgeCases(unittest.TestCase):
    """load_events_from_text edge cases."""

    def test_empty_string_returns_empty_list(self):
        self.assertEqual(load_events_from_text(""), [])

    def test_whitespace_only_returns_empty_list(self):
        self.assertEqual(load_events_from_text("   \n\t  "), [])

    def test_json_array_with_non_dict_entries_skipped(self):
        text = json.dumps([{"image": "cmd.exe"}, "not-a-dict", 42, None])
        events = load_events_from_text(text)
        self.assertEqual(len(events), 1)

    def test_json_object_with_events_wrapper(self):
        text = json.dumps({"events": [{"image": "cmd.exe"}, {"image": "ps.exe"}]})
        events = load_events_from_text(text)
        self.assertEqual(len(events), 2)

    def test_json_object_without_events_key_treated_as_single_event(self):
        text = json.dumps({"image": "cmd.exe", "cmdline": "cmd /c whoami"})
        events = load_events_from_text(text)
        self.assertEqual(len(events), 1)

    def test_jsonl_with_blank_lines_skipped(self):
        text = '{"image": "a.exe"}\n\n{"image": "b.exe"}\n'
        events = load_events_from_text(text)
        self.assertEqual(len(events), 2)

    def test_jsonl_partial_bad_lines_skipped_gracefully(self):
        # One valid line + one bad line → returns the valid line, ignores bad one.
        text = '{"image": "a.exe"}\nNOT_JSON_AT_ALL\n'
        events = load_events_from_text(text)
        self.assertEqual(len(events), 1)

    def test_fully_malformed_input_raises_value_error(self):
        with self.assertRaises(ValueError) as ctx:
            load_events_from_text("this is not json at all\nnor is this\n")
        self.assertIn("parse", str(ctx.exception).lower())

    def test_hunt_on_empty_events_returns_no_findings(self):
        findings = hunt([], DEFAULT_RULES)
        self.assertEqual(findings, [])

    def test_summarize_empty_findings(self):
        s = summarize([])
        self.assertEqual(s["total"], 0)
        self.assertEqual(s["by_severity"], {})
        self.assertEqual(s["by_technique"], {})


class TestRuleValidation(unittest.TestCase):
    """_rule_from_dict and load_rules validation."""

    def test_missing_id_raises_value_error(self):
        with self.assertRaises(ValueError) as ctx:
            _rule_from_dict({"title": "No ID Rule", "technique": "T9999"})
        self.assertIn("id", str(ctx.exception))

    def test_unknown_severity_raises_value_error(self):
        with self.assertRaises(ValueError) as ctx:
            _rule_from_dict({"id": "r1", "severity": "extreme"})
        self.assertIn("severity", str(ctx.exception))

    def test_non_dict_detection_raises_value_error(self):
        with self.assertRaises(ValueError) as ctx:
            _rule_from_dict({"id": "r1", "detection": ["list", "not", "dict"]})
        self.assertIn("detection", str(ctx.exception))

    def test_valid_rule_round_trips(self):
        r = _rule_from_dict({
            "id": "test-rule",
            "title": "Test Rule",
            "technique": "T1059",
            "tactic": "Execution",
            "severity": "high",
            "description": "A test rule.",
            "detection": {"cmdline": {"contains": "evil"}},
        })
        self.assertEqual(r.id, "test-rule")
        self.assertEqual(r.severity, "high")

    def test_load_rules_rules_key_not_list_raises_value_error(self):
        # When the top-level object has a "rules" key whose value is not a list.
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as fh:
            json.dump({"rules": "should-be-a-list"}, fh)
            path = fh.name
        try:
            with self.assertRaises(ValueError) as ctx:
                load_rules(path)
            self.assertIn("array", str(ctx.exception).lower())
        finally:
            os.unlink(path)

    def test_load_rules_rule_missing_id_raises_value_error(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as fh:
            json.dump([{"title": "No ID", "technique": "T9999"}], fh)
            path = fh.name
        try:
            with self.assertRaises(ValueError):
                load_rules(path)
        finally:
            os.unlink(path)

    def test_load_rules_non_dict_entry_raises_value_error(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as fh:
            json.dump(["not-a-dict"], fh)
            path = fh.name
        try:
            with self.assertRaises(ValueError) as ctx:
                load_rules(path)
            self.assertIn("object", str(ctx.exception).lower())
        finally:
            os.unlink(path)


class TestApplyOpEdgeCases(unittest.TestCase):
    """_apply_op edge cases."""

    def test_bad_regex_raises_value_error(self):
        with self.assertRaises(ValueError) as ctx:
            _apply_op("some text", "re", "[unclosed")
        self.assertIn("regex", str(ctx.exception).lower())

    def test_none_value_treated_as_empty_string(self):
        # contains against None should not crash
        result = _apply_op(None, "contains", "something")
        self.assertFalse(result)

    def test_unknown_operator_raises_value_error(self):
        with self.assertRaises(ValueError):
            _apply_op("val", "nonexistent_op", "operand")


class TestCLIHardening(unittest.TestCase):
    """CLI hardening: bad input / error paths."""

    def test_missing_log_file_returns_exit_2(self):
        rc = main(["hunt", "/no/such/path/events.jsonl"])
        self.assertEqual(rc, 2)

    def test_malformed_rules_file_returns_exit_2(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as fh:
            fh.write("this is not valid json {{{")
            rules_path = fh.name
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False, encoding="utf-8") as fh:
            fh.write('{"image": "cmd.exe"}\n')
            log_path = fh.name
        try:
            rc = main(["hunt", log_path, "--rules", rules_path])
            self.assertEqual(rc, 2)
        finally:
            os.unlink(rules_path)
            os.unlink(log_path)

    def test_rules_bad_custom_file_returns_exit_2(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as fh:
            fh.write("NOT JSON")
            path = fh.name
        try:
            rc = main(["rules", "--rules", path])
            self.assertEqual(rc, 2)
        finally:
            os.unlink(path)

    def test_unwritable_output_path_returns_exit_2(self):
        demo = os.path.join(
            os.path.dirname(__file__), "..", "demos", "01-basic", "endpoint.jsonl"
        )
        bad_out = "/no/such/directory/report.html"
        rc = main(["hunt", demo, "--format", "html", "-o", bad_out])
        self.assertEqual(rc, 2)

    def test_empty_log_file_returns_exit_0(self):
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False, encoding="utf-8") as fh:
            fh.write("")
            path = fh.name
        try:
            rc = main(["hunt", path, "--format", "json"])
            self.assertEqual(rc, 0)
        finally:
            os.unlink(path)

    def test_hunt_with_technique_filter_no_match_exit_0(self):
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False, encoding="utf-8") as fh:
            fh.write('{"image": "powershell.exe", "cmdline": "powershell -enc AAAA"}\n')
            path = fh.name
        try:
            # T9999 doesn't exist in the rule pack — should match nothing → exit 0
            rc = main(["hunt", path, "--technique", "T9999"])
            self.assertEqual(rc, 0)
        finally:
            os.unlink(path)


class TestMCPServer(unittest.TestCase):
    """mcp_server module compiles and _scan_text works without MCP installed."""

    def test_module_importable(self):
        import importlib
        mod = importlib.import_module("ttphunt.mcp_server")
        self.assertTrue(callable(mod.serve))

    def test_scan_text_returns_valid_json(self):
        from ttphunt.mcp_server import _scan_text
        result = _scan_text('{"image": "powershell.exe", "cmdline": "powershell -enc AAAA"}')
        data = json.loads(result)
        self.assertIn("summary", data)
        self.assertIn("findings", data)
        self.assertGreater(data["summary"]["total"], 0)

    def test_scan_text_empty_input_returns_zero_findings(self):
        from ttphunt.mcp_server import _scan_text
        result = _scan_text("")
        data = json.loads(result)
        self.assertEqual(data["summary"]["total"], 0)


if __name__ == "__main__":
    unittest.main()
