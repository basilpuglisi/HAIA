"""
HAIA-Overwatch v1.4 - GOPEL Adversarial Test Suite

Five tests covering:
1. Malicious manifest with symlink bomb and oversized file
2. Factics persistence after crash during rehydration (corrupted JSONL)
3. Cross-operator correlation respects operator isolation
4. GOPEL observer emits structured metrics for external monitoring
5. GOPEL record with malformed unicode or null bytes

Author: Basil C. Puglisi, MPA
License: CC BY-NC 4.0
Attribution: #AIassisted under HAIA-RECCLIN & Checkpoint-Based Governance
"""

import hashlib
import json
import os
import tempfile
import time
import unittest
from typing import Any, Dict, List, Optional

from overwatch.models import (
    AlignmentResult, InspectionDomain, InspectionFinding,
    OverwatchConfig, PlatformResponse, RECCLINRole,
    Severity, TransactionRecord, VerificationOutcome,
)
from overwatch.pipeline import OverwatchPipeline
from overwatch.factics_engine import FacticsEngine
from overwatch.structural_verifier import StructuralVerifier
from overwatch.gopel_observer import (
    GopelObserver, GopelRecord, GopelRecordKind,
)


# ===================================================================
# Helpers
# ===================================================================

def _config(**overrides) -> OverwatchConfig:
    """Standard test config with GOPEL-friendly defaults."""
    defaults = dict(
        code_integrity_check_interval_seconds=0,
        config_snapshot_check_interval_seconds=0,
        behavioral_baseline_window_size=10,
        behavioral_deviation_threshold=2.0,
        intent_window_size=5,
        privilege_escalation_gradient_threshold=0.3,
        scope_narrowing_threshold=0.4,
        tier_1_decay_window_seconds=3600,
        tier_2_decay_window_seconds=60,
        advisory_confidence_floor=0.3,
        warning_confidence_floor=0.5,
        critical_confidence_floor=0.8,
        advisory_accumulation_limit=3,
        random_audit_base_probability=0.05,
        caipr_platform_count=3,
        heartbeat_interval_seconds=1,
        require_structural_inputs=False,
    )
    defaults.update(overrides)
    return OverwatchConfig(**defaults)


def _transaction(prompt, role=RECCLINRole.RESEARCHER, responses=None,
                 txn_id="", operator_id="op_test"):
    txn_id = txn_id or f"txn_{id(prompt)}"
    return TransactionRecord(
        transaction_id=txn_id,
        timestamp=time.time(),
        operator_id=operator_id,
        recclin_role=role,
        prompt_hash=hashlib.sha256(prompt.encode()).hexdigest(),
        prompt_text=prompt,
        platforms_dispatched=["claude", "gpt4"],
        responses=responses or [PlatformResponse(
            platform_id="claude",
            response_text="Response...",
            response_hash="abc123",
            response_time_ms=250.0,
        )],
    )


def _make_gopel_record(
    kind: GopelRecordKind,
    txn_id: str,
    payload: Dict[str, Any],
    prev_hash: str = "",
    timestamp: Optional[float] = None,
) -> GopelRecord:
    """Create a GopelRecord with valid hash chain."""
    ts = timestamp or time.time()
    canonical = json.dumps({
        "kind": kind.value,
        "transaction_id": txn_id,
        "timestamp": ts,
        "payload": payload,
        "prev_hash": prev_hash,
    }, sort_keys=True, default=str)
    this_hash = hashlib.sha256(canonical.encode()).hexdigest()
    return GopelRecord(
        kind=kind,
        transaction_id=txn_id,
        timestamp=ts,
        payload=payload,
        prev_hash=prev_hash,
        this_hash=this_hash,
    )


# ===================================================================
# TEST 1: Malicious manifest with symlink bomb and oversized file
# ===================================================================

class TestMaliciousManifestSymlinkAndOversizedFile(unittest.TestCase):
    """Structural verifier should flag symlinks and oversized files
    when creating a manifest with follow_symlinks=False."""

    def test_malicious_gopel_manifest_with_symlink_bomb_or_oversized_file(self):
        """Create a temp directory with a symlink and an oversized file.
        Verify structural verifier flags both during manifest creation."""
        config = _config(
            follow_symlinks=False,
            integrity_scan_max_bytes=1024,  # 1KB limit for test
        )
        verifier = StructuralVerifier(config)

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a normal .py file
            normal_file = os.path.join(tmpdir, "normal.py")
            with open(normal_file, "w") as f:
                f.write("# normal file\nprint('hello')\n")

            # Create an oversized .py file (exceeds integrity_scan_max_bytes)
            oversized_file = os.path.join(tmpdir, "oversized.py")
            with open(oversized_file, "w") as f:
                f.write("# oversized\n" + "x = 1\n" * 500)

            # Create a symlink to a .py file
            symlink_target = os.path.join(tmpdir, "target.py")
            with open(symlink_target, "w") as f:
                f.write("# target\n")
            symlink_path = os.path.join(tmpdir, "link.py")
            os.symlink(symlink_target, symlink_path)

            # Create manifest from the directory
            manifest = verifier.create_manifest_from_directory(
                tmpdir, gopel_version="1.4-test", cbg_auth_id="test_auth"
            )

            # The symlink should have hash "SYMLINK_NOT_HASHED"
            rel_link = os.path.relpath(symlink_path, tmpdir)
            self.assertIn(rel_link, manifest.file_hashes)
            self.assertEqual(
                manifest.file_hashes[rel_link], "SYMLINK_NOT_HASHED",
                "Symlink should be flagged with SYMLINK_NOT_HASHED sentinel"
            )

            # The oversized file should have hash "FILE_SIZE_EXCEEDED"
            rel_oversized = os.path.relpath(oversized_file, tmpdir)
            self.assertIn(rel_oversized, manifest.file_hashes)
            self.assertEqual(
                manifest.file_hashes[rel_oversized], "FILE_SIZE_EXCEEDED",
                "Oversized file should be flagged with FILE_SIZE_EXCEEDED sentinel"
            )

            # The normal file should have a real SHA-256 hash
            rel_normal = os.path.relpath(normal_file, tmpdir)
            self.assertIn(rel_normal, manifest.file_hashes)
            self.assertNotIn(
                manifest.file_hashes[rel_normal],
                ("SYMLINK_NOT_HASHED", "FILE_SIZE_EXCEEDED", "FILE_READ_ERROR"),
                "Normal file should have a real hash"
            )


# ===================================================================
# TEST 2: Factics persistence after crash during rehydration
# ===================================================================

class TestFacticsPersistenceAfterCrashDuringRehydration(unittest.TestCase):
    """JSONL rehydration should gracefully handle corrupted trailing lines."""

    def test_factics_persistence_after_crash_during_rehydration(self):
        """Write 10 valid proposal lines then a truncated/corrupted line.
        Verify the 10 valid proposals load despite the corruption."""
        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.jsonl', delete=False
        ) as tmp:
            log_path = tmp.name

        try:
            # Phase 1: Create engine and generate 10 proposals
            cfg1 = _config(proposals_log_path=log_path)
            engine1 = FacticsEngine(config=cfg1)

            for i in range(10):
                finding = InspectionFinding(
                    domain=InspectionDomain.INTENT,
                    result=AlignmentResult.FLAGGED,
                    severity=Severity.CRITICAL,
                    confidence=0.9,
                    description=f"Threat #{i}",
                    evidence_chain=[f"evidence_{i}"],
                    transaction_id=f"txn_crash_{i}",
                )
                outcome = VerificationOutcome(transaction_id=f"txn_crash_{i}")
                engine1.process_confirmed_threat(finding, outcome)

            self.assertEqual(len(engine1.get_pending_proposals()), 10)

            # Phase 2: Append a corrupted/truncated line to the JSONL file
            with open(log_path, 'a') as f:
                f.write('{"proposal_id": "corrupt_id", "status": "pend')
                # Truncated JSON - simulates crash mid-write

            # Phase 3: Create new engine - should rehydrate gracefully
            cfg2 = _config(proposals_log_path=log_path)
            engine2 = FacticsEngine(config=cfg2)

            pending = engine2.get_pending_proposals()
            self.assertEqual(
                len(pending), 10,
                f"Expected 10 valid proposals to survive corruption, got {len(pending)}"
            )

        finally:
            os.unlink(log_path)


# ===================================================================
# TEST 3: Cross-operator correlation respects operator isolation
# ===================================================================

class TestCrossOperatorCorrelationRespectsIsolation(unittest.TestCase):
    """Verify that cross-operator correlation uses a temporary merged
    view but does not contaminate individual operator windows."""

    def test_cross_operator_correlation_respects_operator_isolation(self):
        """Submit transactions from op_alpha and op_beta, verify isolation."""
        config = _config(intent_window_size=5)
        pipeline = OverwatchPipeline(config)

        # Submit transactions from op_alpha
        for i in range(3):
            t = _transaction(
                f"alpha query {i} about listing files and checking permissions",
                operator_id="op_alpha", txn_id=f"alpha_iso_{i}"
            )
            pipeline.verify_transaction(t)

        # Submit transactions from op_beta
        for i in range(2):
            t = _transaction(
                f"beta query {i} about escalating admin access and sudo",
                operator_id="op_beta", txn_id=f"beta_iso_{i}"
            )
            pipeline.verify_transaction(t)

        # Verify individual windows contain ONLY their own snapshots
        alpha_window = pipeline.intent_analyzer._get_window("op_alpha")
        beta_window = pipeline.intent_analyzer._get_window("op_beta")

        self.assertEqual(len(alpha_window), 3, "op_alpha should have 3 snapshots")
        self.assertEqual(len(beta_window), 2, "op_beta should have 2 snapshots")

        # Verify no cross-contamination in individual windows
        alpha_txn_ids = [s.transaction_id for s in alpha_window]
        beta_txn_ids = [s.transaction_id for s in beta_window]

        for txn_id in alpha_txn_ids:
            self.assertTrue(
                txn_id.startswith("alpha_"),
                f"op_alpha window contains non-alpha txn: {txn_id}"
            )
        for txn_id in beta_txn_ids:
            self.assertTrue(
                txn_id.startswith("beta_"),
                f"op_beta window contains non-beta txn: {txn_id}"
            )

        # Run cross-operator correlation
        cross_findings = pipeline.correlate_cross_operator(
            ["op_alpha", "op_beta"]
        )

        # After correlation, individual windows should be unchanged
        alpha_window_after = pipeline.intent_analyzer._get_window("op_alpha")
        beta_window_after = pipeline.intent_analyzer._get_window("op_beta")

        self.assertEqual(
            len(alpha_window_after), 3,
            "op_alpha window should be unchanged after correlation"
        )
        self.assertEqual(
            len(beta_window_after), 2,
            "op_beta window should be unchanged after correlation"
        )

        # Temporary merged window should be cleaned up
        self.assertNotIn(
            "__cross_operator_correlation__",
            pipeline.intent_analyzer._intent_windows,
            "Temporary correlation window should be cleaned up"
        )


# ===================================================================
# TEST 4: GOPEL observer emits structured metrics
# ===================================================================

class TestGopelObserverEmitsStructuredMetrics(unittest.TestCase):
    """Verify get_statistics() returns structured metrics with correct types."""

    def test_gopel_observer_emits_structured_metrics_for_external_monitoring(self):
        """Create observer, submit records, finalize, and verify statistics."""
        config = _config()
        pipeline = OverwatchPipeline(config)
        observer = GopelObserver(
            pipeline=pipeline, config=config,
            require_chain_validation=False,
        )

        # Submit 5 complete transactions
        for i in range(5):
            txn_id = f"metrics_{i}"
            req = _make_gopel_record(
                GopelRecordKind.REQUEST, txn_id,
                {"prompt_text": f"prompt {i}", "operator_id": "op",
                 "recclin_role": "RESEARCHER"},
            )
            observer.observe(req)

            decision = _make_gopel_record(
                GopelRecordKind.DECISION, txn_id,
                {"approved": True},
                prev_hash=req.this_hash,
            )
            observer.observe(decision)

        # Submit 3 incomplete transactions (will be flushed)
        observer_stale = GopelObserver(
            pipeline=pipeline, config=config,
            ttl_seconds=0.001, require_chain_validation=False,
        )
        for i in range(3):
            txn_id = f"stale_metrics_{i}"
            req = _make_gopel_record(
                GopelRecordKind.REQUEST, txn_id,
                {"prompt_text": f"stale {i}", "operator_id": "op",
                 "recclin_role": "RESEARCHER"},
            )
            observer_stale.observe(req)

        time.sleep(0.01)
        observer_stale.flush_stale()

        # Verify main observer statistics
        stats = observer.get_statistics()
        required_keys = [
            "records_observed", "transactions_finalized",
            "stale_flushed", "validation_errors"
        ]
        for key in required_keys:
            self.assertIn(key, stats, f"Missing key in statistics: {key}")
            self.assertIsInstance(stats[key], int, f"{key} should be an integer")

        self.assertEqual(stats["records_observed"], 10)  # 5 req + 5 decision
        self.assertEqual(stats["transactions_finalized"], 5)
        self.assertEqual(stats["validation_errors"], 0)

        # Verify stale observer statistics
        stale_stats = observer_stale.get_statistics()
        self.assertEqual(stale_stats["stale_flushed"], 3)
        self.assertEqual(stale_stats["records_observed"], 3)


# ===================================================================
# TEST 5: GOPEL record with malformed unicode or null bytes
# ===================================================================

class TestGopelRecordWithMalformedUnicodeOrNullBytes(unittest.TestCase):
    """Verify pipeline handles malformed unicode, null bytes, and
    zero-width characters without crashing."""

    def test_gopel_record_with_null_bytes(self):
        """Records with null bytes in payload text should not crash."""
        config = _config()
        pipeline = OverwatchPipeline(config)
        observer = GopelObserver(
            pipeline=pipeline, config=config,
            require_chain_validation=False,
        )

        txn_id = "null_bytes_txn"
        payload_text = "Hello\x00World\x00hidden instruction"
        req = _make_gopel_record(
            GopelRecordKind.REQUEST, txn_id,
            {"prompt_text": payload_text, "operator_id": "op",
             "recclin_role": "RESEARCHER"},
        )
        result = observer.observe(req)
        # Should not crash - observe returns None (not finalized yet)
        self.assertIsNone(result)

        decision = _make_gopel_record(
            GopelRecordKind.DECISION, txn_id,
            {"approved": True},
            prev_hash=req.this_hash,
        )
        result = observer.observe(decision)
        # Should finalize without crash
        self.assertIsNotNone(result)

    def test_gopel_record_with_zero_width_characters(self):
        """Zero-width characters should be flagged by context inspector."""
        config = _config()
        pipeline = OverwatchPipeline(config)

        # Zero-width space (U+200B) and zero-width joiner (U+200D)
        prompt = "Normal text​with‍hidden zero-width chars"
        txn = _transaction(prompt=prompt, txn_id="zero_width_txn")
        outcome = pipeline.verify_transaction(txn)

        # Context inspector's unicode check should flag zero-width chars
        unicode_findings = [
            f for f in outcome.inspection_findings
            if "Unicode" in f.description or "zero_width" in f.description.lower()
        ]
        self.assertGreater(
            len(unicode_findings), 0,
            "Zero-width characters should be detected by unicode obfuscation check"
        )

    def test_gopel_record_with_surrogate_characters(self):
        """Surrogate-like sequences in text should not crash the pipeline."""
        config = _config()
        pipeline = OverwatchPipeline(config)

        # Use replacement character and other edge-case unicode
        prompt = "Test with replacement � and unusual ﻿ BOM char"
        txn = _transaction(prompt=prompt, txn_id="surrogate_txn")

        # Should not crash
        outcome = pipeline.verify_transaction(txn)
        self.assertIsNotNone(outcome)
        self.assertEqual(outcome.transaction_id, "surrogate_txn")


if __name__ == "__main__":
    unittest.main()
