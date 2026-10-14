"""
HAIA-Overwatch v2.1 - Structured Logging Test Suite

Tests for the structured_logger module and the migration of all 7 modules
from ad-hoc logging to centralised JSON Lines structured logging.

Author: Basil C. Puglisi, MPA
License: CC BY-NC 4.0
Attribution: #AIassisted under HAIA-RECCLIN & Checkpoint-Based Governance
"""

import json
import logging
import unittest

from overwatch.structured_logger import (
    JSONLinesFormatter,
    get_logger,
    sanitize_log_value,
)


class TestSanitizeLogValue(unittest.TestCase):
    """Tests for the consolidated sanitize_log_value function."""

    def test_strips_ansi_escape_sequences(self):
        raw = "\x1b[31mRED TEXT\x1b[0m"
        result = sanitize_log_value(raw)
        self.assertEqual(result, "RED TEXT")
        self.assertNotIn("\x1b", result)

    def test_strips_null_bytes(self):
        raw = "hello\x00world"
        result = sanitize_log_value(raw)
        self.assertEqual(result, "hello?world")

    def test_strips_newlines(self):
        raw = "line1\nline2\rline3"
        result = sanitize_log_value(raw)
        self.assertEqual(result, "line1?line2?line3")

    def test_preserves_tabs(self):
        raw = "col1\tcol2\tcol3"
        result = sanitize_log_value(raw)
        self.assertEqual(result, "col1\tcol2\tcol3")

    def test_truncates_long_values(self):
        raw = "A" * 600
        result = sanitize_log_value(raw)
        self.assertEqual(len(result), 500 + len("...[truncated]"))
        self.assertTrue(result.endswith("...[truncated]"))

    def test_clean_string_unchanged(self):
        raw = "Normal log message with no special chars"
        result = sanitize_log_value(raw)
        self.assertEqual(result, raw)

    def test_complex_ansi_sequences(self):
        raw = "\x1b[1;32;40mBOLD GREEN\x1b[0m normal"
        result = sanitize_log_value(raw)
        self.assertEqual(result, "BOLD GREEN normal")

    def test_delete_character(self):
        raw = "before\x7fafter"
        result = sanitize_log_value(raw)
        self.assertEqual(result, "before?after")


class TestJSONLinesFormatter(unittest.TestCase):
    """Tests for the JSON Lines log formatter."""

    def setUp(self):
        self.formatter = JSONLinesFormatter()

    def _make_record(self, msg, level=logging.INFO, name="overwatch.test",
                     **extras):
        record = logging.LogRecord(
            name=name,
            level=level,
            pathname="test.py",
            lineno=1,
            msg=msg,
            args=(),
            exc_info=None,
        )
        for k, v in extras.items():
            setattr(record, k, v)
        return record

    def test_output_is_valid_json(self):
        record = self._make_record("test message")
        output = self.formatter.format(record)
        parsed = json.loads(output)
        self.assertIsInstance(parsed, dict)

    def test_required_fields_present(self):
        record = self._make_record("test event")
        output = self.formatter.format(record)
        parsed = json.loads(output)
        self.assertIn("timestamp", parsed)
        self.assertIn("level", parsed)
        self.assertIn("module", parsed)
        self.assertIn("event", parsed)

    def test_level_field_matches(self):
        for level, name in [(logging.DEBUG, "DEBUG"), (logging.WARNING, "WARNING"),
                            (logging.ERROR, "ERROR"), (logging.CRITICAL, "CRITICAL")]:
            record = self._make_record("msg", level=level)
            parsed = json.loads(self.formatter.format(record))
            self.assertEqual(parsed["level"], name)

    def test_module_field_is_logger_name(self):
        record = self._make_record("msg", name="overwatch.pipeline")
        parsed = json.loads(self.formatter.format(record))
        self.assertEqual(parsed["module"], "overwatch.pipeline")

    def test_event_field_contains_formatted_message(self):
        record = logging.LogRecord(
            name="overwatch.test", level=logging.INFO,
            pathname="t.py", lineno=1,
            msg="Transaction %s processed in %dms",
            args=("txn-001", 42),
            exc_info=None,
        )
        parsed = json.loads(self.formatter.format(record))
        self.assertEqual(parsed["event"], "Transaction txn-001 processed in 42ms")

    def test_extras_collected(self):
        record = self._make_record("msg", transaction_id="txn-99",
                                   severity="CRITICAL")
        parsed = json.loads(self.formatter.format(record))
        self.assertIn("extras", parsed)
        self.assertEqual(parsed["extras"]["transaction_id"], "txn-99")
        self.assertEqual(parsed["extras"]["severity"], "CRITICAL")

    def test_no_extras_key_when_empty(self):
        record = self._make_record("msg")
        parsed = json.loads(self.formatter.format(record))
        self.assertNotIn("extras", parsed)

    def test_single_line_output(self):
        record = self._make_record("multi\nline\nmessage")
        output = self.formatter.format(record)
        # JSON encoding should escape newlines, keeping output single-line
        self.assertNotIn("\n", output)

    def test_exception_info_included(self):
        try:
            raise ValueError("test error")
        except ValueError:
            import sys
            record = self._make_record("caught error")
            record.exc_info = sys.exc_info()
            parsed = json.loads(self.formatter.format(record))
            self.assertIn("exception", parsed)
            self.assertIn("ValueError", parsed["exception"])

    def test_timestamp_format_iso8601(self):
        record = self._make_record("msg")
        parsed = json.loads(self.formatter.format(record))
        ts = parsed["timestamp"]
        # Should match pattern like 2026-05-08T12:34:56.789Z
        self.assertTrue(ts.endswith("Z"))
        self.assertEqual(len(ts), 24)  # YYYY-MM-DDTHH:MM:SS.mmmZ


class TestGetLogger(unittest.TestCase):
    """Tests for the get_logger factory function."""

    def test_returns_logger_under_overwatch_namespace(self):
        log = get_logger("overwatch.test_module")
        self.assertEqual(log.name, "overwatch.test_module")
        self.assertIsInstance(log, logging.Logger)

    def test_auto_prefixes_bare_name(self):
        log = get_logger("my_module")
        self.assertEqual(log.name, "overwatch.my_module")

    def test_does_not_double_prefix(self):
        log = get_logger("overwatch.pipeline")
        self.assertEqual(log.name, "overwatch.pipeline")

    def test_handler_installed_on_root(self):
        # Calling get_logger should install handler on 'overwatch' root
        get_logger("overwatch.check")
        root = logging.getLogger("overwatch")
        self.assertTrue(len(root.handlers) > 0)
        # At least one handler should use JSONLinesFormatter
        has_jsonl = any(
            isinstance(h.formatter, JSONLinesFormatter)
            for h in root.handlers
        )
        self.assertTrue(has_jsonl)


class TestModuleMigration(unittest.TestCase):
    """Verify all 7 modules import from structured_logger, not logging directly."""

    def test_gopel_observer_uses_structured_logger(self):
        import overwatch.gopel_observer as mod
        # Should NOT have a module-level _sanitize_log defined locally
        # (it's imported from structured_logger)
        import inspect
        source = inspect.getsource(mod)
        self.assertNotIn("def _sanitize_log(", source)
        # Should import from structured_logger
        self.assertIn("from .structured_logger import", source)

    def test_channel_manager_uses_structured_logger(self):
        import overwatch.channel_manager as mod
        import inspect
        source = inspect.getsource(mod)
        self.assertNotIn("def _sanitize_log(", source)
        self.assertIn("from .structured_logger import", source)

    def test_pipeline_uses_structured_logger(self):
        import overwatch.pipeline as mod
        import inspect
        source = inspect.getsource(mod)
        self.assertNotIn("def _sanitize_log(", source)
        self.assertIn("from .structured_logger import", source)

    def test_execution_graph_uses_structured_logger(self):
        import overwatch.execution_graph as mod
        import inspect
        source = inspect.getsource(mod)
        self.assertIn("from .structured_logger import", source)

    def test_escalation_engine_uses_structured_logger(self):
        import overwatch.escalation_engine as mod
        import inspect
        source = inspect.getsource(mod)
        self.assertIn("from .structured_logger import", source)

    def test_caipr_dispatcher_uses_structured_logger(self):
        import overwatch.caipr_dispatcher as mod
        import inspect
        source = inspect.getsource(mod)
        self.assertIn("from .structured_logger import", source)

    def test_structural_verifier_uses_structured_logger(self):
        import overwatch.structural_verifier as mod
        import inspect
        source = inspect.getsource(mod)
        self.assertIn("from .structured_logger import", source)

    def test_no_module_imports_logging_getlogger_directly(self):
        """None of the 7 migrated modules should call logging.getLogger()."""
        import inspect
        modules = [
            "overwatch.gopel_observer",
            "overwatch.channel_manager",
            "overwatch.pipeline",
            "overwatch.execution_graph",
            "overwatch.escalation_engine",
            "overwatch.caipr_dispatcher",
            "overwatch.structural_verifier",
        ]
        for mod_name in modules:
            mod = __import__(mod_name, fromlist=[""])
            source = inspect.getsource(mod)
            # Allow 'import logging' only if it's NOT followed by getLogger
            if "logging.getLogger" in source:
                self.fail(
                    f"{mod_name} still calls logging.getLogger() directly"
                )


class TestNoFStringLogging(unittest.TestCase):
    """Verify f-string log calls have been eliminated from migrated modules."""

    def _get_source(self, mod_name):
        import inspect
        mod = __import__(mod_name, fromlist=[""])
        return inspect.getsource(mod)

    def test_execution_graph_no_fstring_logs(self):
        source = self._get_source("overwatch.execution_graph")
        # Check for f-string patterns in logger calls
        import re
        fstring_log = re.findall(r'logger\.\w+\(f["\']', source)
        self.assertEqual(fstring_log, [],
                         "execution_graph.py still has f-string log calls")

    def test_escalation_engine_no_fstring_logs(self):
        source = self._get_source("overwatch.escalation_engine")
        import re
        fstring_log = re.findall(r'logger\.\w+\(f["\']', source)
        self.assertEqual(fstring_log, [],
                         "escalation_engine.py still has f-string log calls")

    def test_caipr_dispatcher_no_fstring_logs(self):
        source = self._get_source("overwatch.caipr_dispatcher")
        import re
        fstring_log = re.findall(r'logger\.\w+\(f["\']', source)
        self.assertEqual(fstring_log, [],
                         "caipr_dispatcher.py still has f-string log calls")

    def test_structural_verifier_no_fstring_logs(self):
        source = self._get_source("overwatch.structural_verifier")
        import re
        fstring_log = re.findall(r'logger\.\w+\(f["\']', source)
        self.assertEqual(fstring_log, [],
                         "structural_verifier.py still has f-string log calls")


class TestLogOutputIntegration(unittest.TestCase):
    """Integration test: verify actual log output is valid JSON Lines."""

    def test_log_output_is_parseable_jsonl(self):
        """Capture actual log output from a structured logger and parse it."""
        import io
        # Create a handler that captures output
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.setFormatter(JSONLinesFormatter())

        test_logger = logging.getLogger("overwatch.integration_test")
        test_logger.addHandler(handler)
        test_logger.setLevel(logging.DEBUG)

        try:
            test_logger.info("Test event alpha")
            test_logger.warning("Test event %s", "beta")
            test_logger.error("Test event gamma with extra",
                              extra={"txn_id": "T-001"})

            output = stream.getvalue()
            lines = [l for l in output.strip().split("\n") if l]

            self.assertEqual(len(lines), 3)
            for line in lines:
                parsed = json.loads(line)
                self.assertIn("timestamp", parsed)
                self.assertIn("level", parsed)
                self.assertIn("event", parsed)

            # Check specific entries
            first = json.loads(lines[0])
            self.assertEqual(first["event"], "Test event alpha")
            self.assertEqual(first["level"], "INFO")

            second = json.loads(lines[1])
            self.assertEqual(second["event"], "Test event beta")

        finally:
            test_logger.removeHandler(handler)

    def test_sanitized_values_in_structured_output(self):
        """Verify that sanitized values produce clean JSON Lines output."""
        import io
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.setFormatter(JSONLinesFormatter())

        test_logger = logging.getLogger("overwatch.sanitize_integration")
        test_logger.addHandler(handler)
        test_logger.setLevel(logging.DEBUG)

        try:
            malicious = "\x1b[31mATTACK\x1b[0m\x00\ninjected"
            clean = sanitize_log_value(malicious)
            test_logger.warning("Observed: %s", clean)

            output = stream.getvalue().strip()
            parsed = json.loads(output)
            # The event should contain the sanitized version
            self.assertNotIn("\x1b", parsed["event"])
            self.assertNotIn("\x00", parsed["event"])
            self.assertIn("ATTACK", parsed["event"])
        finally:
            test_logger.removeHandler(handler)


class TestExportedFromPackage(unittest.TestCase):
    """Verify structured_logger exports are available from the package."""

    def test_get_logger_exported(self):
        from overwatch import get_logger
        self.assertTrue(callable(get_logger))

    def test_sanitize_log_value_exported(self):
        from overwatch import sanitize_log_value
        self.assertTrue(callable(sanitize_log_value))

    def test_version_is_current(self):
        import overwatch
        # Version should be at least 2.1.0 (structured logging)
        major, minor, patch = overwatch.__version__.split(".")
        self.assertGreaterEqual(int(major), 2)
        self.assertGreaterEqual(int(minor), 1)


if __name__ == "__main__":
    unittest.main()
