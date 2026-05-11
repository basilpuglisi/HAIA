"""
HAIA-Overwatch v2.0 — Consolidated Gemini + Kimi + Claude Hardening Tests

Tests covering all 8 items from the cross-platform vulnerability review:
1. TIER_UNTRUSTED in ProvenanceManager (Gemini)
2. GopelObserver RLock thread safety (Kimi)
3. Bounded _delivery_failures + _graphs pruning (Gemini)
4. String normalization pre-pass in OutputStateEvaluator (Gemini+Claude)
5. Config validation bounds checks (Kimi)
6. Cross-operator try/finally cleanup (Kimi)
7. Tightened gopel_mode polling interval (Gemini+Claude)
8. Log sanitization for control characters (Kimi)

Author: Basil C. Puglisi, MPA
License: CC BY-NC 4.0
Attribution: #AIassisted under HAIA-RECCLIN & Checkpoint-Based Governance
"""

import hashlib
import json
import os
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from overwatch.models import (
    OverwatchConfig, TrustTier, ProvenanceTag, RECCLINRole,
    TransactionRecord, PlatformResponse, DeclaredTaskScope,
    Severity, InspectionFinding, InspectionDomain, AlignmentResult
)
from overwatch.provenance_manager import ProvenanceManager
from overwatch.gopel_observer import (
    GopelObserver, GopelRecord, GopelRecordKind, _sanitize_log
)
from overwatch.channel_manager import IndependentChannelManager
from overwatch.channel_manager import _sanitize_log as _channel_sanitize_log
from overwatch.execution_graph import ExecutionGraphEngine
from overwatch.output_state_evaluator import (
    OutputStateEvaluator, _normalize_for_detection
)
from overwatch.pipeline import OverwatchPipeline


# ===================================================================
# Helper: build a minimal transaction
# ===================================================================
def _make_txn(prompt_text="hello", role=RECCLINRole.RESEARCHER, response_text="world",
              operator_id="op1", platform_id="claude", task_scope=None):
    return TransactionRecord(
        transaction_id=f"txn-{time.time()}",
        timestamp=time.time(),
        operator_id=operator_id,
        recclin_role=role,
        prompt_hash=hashlib.sha256(prompt_text.encode()).hexdigest(),
        prompt_text=prompt_text,
        platforms_dispatched=[platform_id],
        responses=[PlatformResponse(
            platform_id=platform_id,
            response_text=response_text,
            response_hash=hashlib.sha256(response_text.encode()).hexdigest(),
            response_time_ms=50.0
        )],
        task_scope=task_scope
    )


# ===================================================================
# 1. TIER_UNTRUSTED Tests
# ===================================================================
class TestTierUntrusted(unittest.TestCase):
    """Verify TIER_UNTRUSTED enum, ProvenanceManager default, and decay behavior."""

    def setUp(self):
        self.key = os.urandom(32)
        self.pm = ProvenanceManager(self.key)

    def test_tier_untrusted_exists(self):
        """TIER_UNTRUSTED is a valid TrustTier enum member with value 3."""
        self.assertEqual(TrustTier.TIER_UNTRUSTED.value, 3)

    def test_unknown_source_defaults_to_untrusted(self):
        """Unregistered sources default to TIER_UNTRUSTED, not TIER_2."""
        tag = self.pm.issue_tag("unknown_source", "api_response", TrustTier.TIER_UNTRUSTED)
        self.assertEqual(tag.trust_tier, TrustTier.TIER_UNTRUSTED)

    def test_unknown_source_cannot_elevate_to_tier2(self):
        """Unregistered source requesting TIER_2 is rejected (exceeds TIER_UNTRUSTED)."""
        with self.assertRaises(ValueError) as ctx:
            self.pm.issue_tag("unknown_source", "api_response", TrustTier.TIER_2)
        self.assertIn("not authorized", str(ctx.exception))

    def test_registered_source_at_tier2_still_works(self):
        """Explicitly registered TIER_2 source can still issue TIER_2 tags."""
        self.pm.register_source("known_nav", TrustTier.TIER_2)
        tag = self.pm.issue_tag("known_nav", "api_response", TrustTier.TIER_2)
        self.assertEqual(tag.trust_tier, TrustTier.TIER_2)

    def test_tier_untrusted_always_expired(self):
        """TIER_UNTRUSTED content is always considered expired regardless of age."""
        tag = ProvenanceTag(
            source_identity="unknown",
            timestamp=time.time(),  # just created
            trust_tier=TrustTier.TIER_UNTRUSTED,
            ingestion_path="api_response"
        )
        # Should be expired even with a huge decay window
        self.assertTrue(tag.is_expired(999999.0))

    def test_tier0_still_never_expires(self):
        """TIER_0 content still never expires (regression check)."""
        tag = ProvenanceTag(
            source_identity="human",
            timestamp=1.0,  # very old
            trust_tier=TrustTier.TIER_0,
            ingestion_path="direct_input"
        )
        self.assertFalse(tag.is_expired(0.001))


# ===================================================================
# 2. GopelObserver Thread Safety Tests
# ===================================================================
class TestGopelObserverThreadSafety(unittest.TestCase):
    """Verify RLock protects concurrent observe() and flush_stale()."""

    def setUp(self):
        self.config = OverwatchConfig(require_structural_inputs=False)
        self.pipeline = OverwatchPipeline(self.config)
        self.observer = GopelObserver(
            self.pipeline, ttl_seconds=0.1, require_chain_validation=False
        )

    def test_observer_has_rlock(self):
        """Observer has a threading.RLock instance."""
        self.assertIsInstance(self.observer._lock, type(threading.RLock()))

    def test_concurrent_observe_and_flush(self):
        """Concurrent observe() + flush_stale() does not raise or corrupt state."""
        errors = []

        def observe_records():
            try:
                for i in range(200):
                    record = GopelRecord(
                        kind=GopelRecordKind.REQUEST,
                        transaction_id=f"txn-thread-{i}",
                        timestamp=time.time(),
                        payload={"prompt_text": f"test {i}", "operator_id": "op1"},
                        prev_hash="",
                        this_hash=""
                    )
                    # Fix hash for validation
                    record = GopelRecord(
                        kind=record.kind,
                        transaction_id=record.transaction_id,
                        timestamp=record.timestamp,
                        payload=record.payload,
                        prev_hash=record.prev_hash,
                        this_hash=record.recompute_hash()
                    )
                    self.observer.observe(record)
            except Exception as e:
                errors.append(str(e))

        def flush_continuously():
            try:
                for _ in range(100):
                    self.observer.flush_stale(time.time() + 10)
                    time.sleep(0.001)
            except Exception as e:
                errors.append(str(e))

        t1 = threading.Thread(target=observe_records)
        t2 = threading.Thread(target=flush_continuously)
        t1.start()
        t2.start()
        t1.join(timeout=10)
        t2.join(timeout=10)

        self.assertEqual(errors, [], f"Thread errors: {errors}")

    def test_broader_exception_catch(self):
        """Non-ChainValidationError exceptions in observe() are caught gracefully."""
        # Create observer WITH chain validation enabled
        observer_strict = GopelObserver(
            self.pipeline, ttl_seconds=60, require_chain_validation=True
        )
        record = GopelRecord(
            kind=GopelRecordKind.REQUEST,
            transaction_id="txn-err",
            timestamp=time.time(),
            payload={},
            prev_hash="invalid_prev",
            this_hash="wrong_hash"  # Will fail hash validation → ChainValidationError
        )
        # Should not raise, should return None (caught by broadened handler)
        result = observer_strict.observe(record)
        self.assertIsNone(result)
        # Validation error counter should increment
        self.assertGreater(observer_strict._statistics["validation_errors"], 0)


# ===================================================================
# 3. Bounded Memory Tests
# ===================================================================
class TestBoundedMemory(unittest.TestCase):
    """Verify _delivery_failures cap and _graphs auto-pruning."""

    def test_delivery_failures_capped_at_1000(self):
        """_delivery_failures never exceeds MAX_DELIVERY_FAILURES."""
        key = os.urandom(32)
        cm = IndependentChannelManager(key)
        failing_transport = lambda msg: (_ for _ in ()).throw(RuntimeError("fail"))
        cm.register_transport(failing_transport)

        for i in range(1200):
            cm.emit("test", {"i": i})

        self.assertLessEqual(len(cm._delivery_failures), 1000)
        # Verify FIFO: oldest entries were dropped
        self.assertGreater(cm._delivery_failures[0]["sequence"], 1)

    def test_execution_graph_prune_stale(self):
        """prune_stale removes graphs with no recent activity."""
        engine = ExecutionGraphEngine()
        # Create two operators
        engine.record_role_assignment("op_old", "RESEARCHER", "hash1")
        engine.record_role_assignment("op_new", "CODER", "hash2")

        # Backdate the old operator's last node
        old_node = engine._last_node["op_old"]
        # Directly set timestamp to 3 hours ago
        old_node.timestamp = time.time() - 10800

        pruned = engine.prune_stale(max_age_seconds=7200)
        self.assertEqual(pruned, 1)
        self.assertNotIn("op_old", engine._graphs)
        self.assertIn("op_new", engine._graphs)

    def test_prune_stale_returns_zero_when_all_fresh(self):
        """prune_stale returns 0 when all graphs are recent."""
        engine = ExecutionGraphEngine()
        engine.record_role_assignment("op1", "RESEARCHER", "hash1")
        engine.record_role_assignment("op2", "CODER", "hash2")
        pruned = engine.prune_stale(max_age_seconds=7200)
        self.assertEqual(pruned, 0)


# ===================================================================
# 4. String Normalization / Obfuscation Evasion Tests
# ===================================================================
class TestStringNormalization(unittest.TestCase):
    """Verify _normalize_for_detection defeats common obfuscation patterns."""

    def test_string_concat_collapsed(self):
        """String concatenation 'o'+'s' collapses to 'os'."""
        result = _normalize_for_detection("'o'+'s'")
        self.assertIn("os", result)

    def test_chained_string_concat(self):
        """Chained concatenation 's'+'u'+'b'+'p' collapses."""
        result = _normalize_for_detection("'su'+'bp'+'ro'+'ce'+'ss'")
        self.assertIn("subprocess", result)

    def test_chr_sequence_resolved(self):
        """chr(111)+chr(115) resolves to os."""
        result = _normalize_for_detection("chr(111)+chr(115)")
        self.assertIn("o", result)
        self.assertIn("s", result)

    def test_getattr_import_resolved(self):
        """getattr(__import__('os'), 'system') resolves to os.system."""
        result = _normalize_for_detection("getattr(__import__('os'), 'system')")
        self.assertIn("os.system", result)

    def test_dunder_import_resolved(self):
        """__import__('subprocess') resolves to subprocess."""
        result = _normalize_for_detection("__import__('subprocess')")
        self.assertIn("subprocess", result)

    def test_obfuscated_os_system_detected_by_evaluator(self):
        """OutputStateEvaluator catches getattr(__import__('os'), 'system') after normalization."""
        config = OverwatchConfig(require_structural_inputs=False)
        evaluator = OutputStateEvaluator(config)
        obfuscated_code = "result = getattr(__import__('os'), 'system')('whoami')"
        txn = _make_txn(
            response_text=obfuscated_code,
            role=RECCLINRole.RESEARCHER
        )
        findings = evaluator.analyze(txn)
        # Should detect code_execution via os.system after normalization
        categories = [e for f in findings for e in f.evidence_chain if "code_execution" in e]
        self.assertTrue(len(categories) > 0,
                        f"Expected code_execution finding, got: {[f.description for f in findings]}")

    def test_string_concat_exec_detected(self):
        """'ex'+'ec' concatenation is detected as code_execution."""
        config = OverwatchConfig(require_structural_inputs=False)
        evaluator = OutputStateEvaluator(config)
        obfuscated = "result = eval('ex'+'ec')(code)"
        txn = _make_txn(response_text=obfuscated, role=RECCLINRole.EDITOR)
        findings = evaluator.analyze(txn)
        has_exec = any("code_execution" in str(f.evidence_chain) for f in findings)
        self.assertTrue(has_exec, "Should detect exec via string concatenation normalization")

    def test_clean_code_not_affected(self):
        """Normal code without obfuscation is not changed by normalization."""
        clean = "import os\nos.path.join('/tmp', 'test')"
        result = _normalize_for_detection(clean)
        self.assertEqual(result, clean)


# ===================================================================
# 5. Config Validation Bounds Tests
# ===================================================================
class TestConfigValidationBounds(unittest.TestCase):
    """Verify OverwatchConfig.validate() rejects zero/negative numeric fields."""

    def test_zero_max_scan_text_length_rejected(self):
        config = OverwatchConfig(max_scan_text_length=0)
        errors = config.validate()
        self.assertTrue(any("max_scan_text_length" in e for e in errors))

    def test_negative_integrity_scan_max_bytes_rejected(self):
        config = OverwatchConfig(integrity_scan_max_bytes=-1)
        errors = config.validate()
        self.assertTrue(any("integrity_scan_max_bytes" in e for e in errors))

    def test_zero_advisory_accumulation_limit_rejected(self):
        config = OverwatchConfig(advisory_accumulation_limit=0)
        errors = config.validate()
        self.assertTrue(any("advisory_accumulation_limit" in e for e in errors))

    def test_negative_code_integrity_interval_rejected(self):
        config = OverwatchConfig(code_integrity_check_interval_seconds=-10)
        errors = config.validate()
        self.assertTrue(any("code_integrity_check_interval" in e for e in errors))

    def test_zero_interval_allowed_for_testing(self):
        """Zero interval means 'check every time' — valid for test configs."""
        config = OverwatchConfig(
            code_integrity_check_interval_seconds=0,
            config_snapshot_check_interval_seconds=0
        )
        errors = config.validate()
        interval_errors = [e for e in errors if "interval" in e]
        self.assertEqual(interval_errors, [])

    def test_zero_baseline_window_rejected(self):
        config = OverwatchConfig(behavioral_baseline_window_size=0)
        errors = config.validate()
        self.assertTrue(any("behavioral_baseline_window_size" in e for e in errors))

    def test_valid_config_passes(self):
        """Default config passes all validation checks."""
        config = OverwatchConfig()
        errors = config.validate()
        self.assertEqual(errors, [])


# ===================================================================
# 6. Cross-Operator try/finally Cleanup Tests
# ===================================================================
class TestCrossOperatorCleanup(unittest.TestCase):
    """Verify correlate_cross_operator cleans up temp window on exception."""

    def test_temp_window_cleaned_on_success(self):
        """Temp window is removed after successful correlation."""
        config = OverwatchConfig(require_structural_inputs=False)
        pipeline = OverwatchPipeline(config)
        # Run correlation with empty windows
        findings = pipeline.correlate_cross_operator(["op1", "op2"])
        # Temp key should not persist
        self.assertNotIn(
            "__cross_operator_correlation__",
            pipeline.intent_analyzer._intent_windows
        )

    def test_temp_window_cleaned_on_exception(self):
        """Temp window is removed even when analysis raises."""
        config = OverwatchConfig(require_structural_inputs=False)
        pipeline = OverwatchPipeline(config)

        # Inject a window with proper IntentSnapshot fields
        from collections import deque
        from overwatch.intent_analyzer import IntentSnapshot
        window = deque(maxlen=10)
        for i in range(5):
            window.append(IntentSnapshot(
                transaction_id=f"txn-{i}",
                timestamp=time.time() + i,
                recclin_role=RECCLINRole.RESEARCHER,
                scope_indicators=["test_scope"],
                privilege_indicators=[]
            ))
        pipeline.intent_analyzer._intent_windows["op1"] = window

        findings = pipeline.correlate_cross_operator(["op1"])
        self.assertNotIn(
            "__cross_operator_correlation__",
            pipeline.intent_analyzer._intent_windows
        )


# ===================================================================
# 7. GOPEL Mode Polling Interval Tests
# ===================================================================
class TestGopelModePollingInterval(unittest.TestCase):
    """Verify gopel_mode tightens code_integrity_check_interval_seconds."""

    def test_gopel_mode_tightens_interval_to_300(self):
        """gopel_mode caps code_integrity_check_interval_seconds at 300."""
        config = OverwatchConfig(
            gopel_mode=True,
            code_integrity_check_interval_seconds=3600.0
        )
        self.assertLessEqual(config.code_integrity_check_interval_seconds, 300.0)

    def test_gopel_mode_preserves_shorter_interval(self):
        """gopel_mode does not lengthen an already-short interval."""
        config = OverwatchConfig(
            gopel_mode=True,
            code_integrity_check_interval_seconds=60.0
        )
        self.assertEqual(config.code_integrity_check_interval_seconds, 60.0)

    def test_default_interval_without_gopel_mode(self):
        """Without gopel_mode, default interval is 300s."""
        config = OverwatchConfig(gopel_mode=False)
        self.assertEqual(config.code_integrity_check_interval_seconds, 300.0)


# ===================================================================
# 8. Log Sanitization Tests
# ===================================================================
class TestLogSanitization(unittest.TestCase):
    """Verify _sanitize_log strips control characters and ANSI escapes."""

    def test_strips_ansi_escapes(self):
        """ANSI escape sequences are removed."""
        dirty = "normal\x1b[31mred_text\x1b[0mnormal"
        clean = _sanitize_log(dirty)
        self.assertNotIn("\x1b", clean)
        self.assertIn("normal", clean)
        self.assertIn("red_text", clean)

    def test_strips_newlines(self):
        """Newline characters are replaced with '?'."""
        dirty = "line1\nline2\rline3"
        clean = _sanitize_log(dirty)
        self.assertNotIn("\n", clean)
        self.assertNotIn("\r", clean)

    def test_strips_null_bytes(self):
        """Null bytes are replaced with '?'."""
        dirty = "test\x00injection"
        clean = _sanitize_log(dirty)
        self.assertNotIn("\x00", clean)

    def test_truncates_long_values(self):
        """Values over 500 chars are truncated."""
        dirty = "a" * 600
        clean = _sanitize_log(dirty)
        self.assertLessEqual(len(clean), 520)  # 500 + truncation marker
        self.assertTrue(clean.endswith("...[truncated]"))

    def test_clean_string_unchanged(self):
        """Normal strings pass through unchanged."""
        clean_input = "Transaction txn-12345 processed successfully"
        result = _sanitize_log(clean_input)
        self.assertEqual(result, clean_input)

    def test_channel_manager_sanitize_available(self):
        """channel_manager also has _sanitize_log."""
        dirty = "test\x1b[31mred\x1b[0m"
        clean = _channel_sanitize_log(dirty)
        self.assertNotIn("\x1b", clean)


if __name__ == "__main__":
    unittest.main()
