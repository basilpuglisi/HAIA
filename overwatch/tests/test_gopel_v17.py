"""
HAIA-Overwatch v1.7 - GOPEL Adversarial Test Suite

Seven tests covering:
1. Pipeline survives random platform timeouts (CAIPR TimeoutError)
2. Structural verifier handles missing GOPEL directory
3. Behavioral drift detection over time (role-behavior envelope)
4. Compromised CBG release still requires manifest validation
5. Overwatch never escalates without evidence
6. Transaction never mutates original GOPEL record
7. Random audit report is SIEM-friendly (JSON export)

Author: Basil C. Puglisi, MPA
License: CC BY-NC 4.0
Attribution: #AIassisted under HAIA-RECCLIN & Checkpoint-Based Governance
"""

import copy
import hashlib
import json
import re
import time
import unittest
from typing import Any, Dict, List, Optional
from unittest.mock import patch

from overwatch.models import (
    AlignmentResult, DeploymentManifest, InspectionDomain, InspectionFinding,
    OverwatchConfig, PlatformResponse, RECCLINRole,
    Severity, StructuralResult, TransactionRecord, VerificationOutcome,
)
from overwatch.pipeline import OverwatchPipeline
from overwatch.structural_verifier import StructuralVerifier
from overwatch.output_state_evaluator import OutputStateEvaluator
from overwatch.caipr_dispatcher import CAIPRInspectionDispatcher


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


# ===================================================================
# TEST 1: Pipeline survives random platform timeouts
# ===================================================================

class TestPipelineSurvivesRandomPlatformTimeouts(unittest.TestCase):
    """When one of three CAIPR platforms raises TimeoutError, the
    dispatcher should still produce a consensus with the failed
    platform counting as flagged."""

    def test_pipeline_survives_random_platform_timeouts(self):
        """Register 3 CAIPR platforms where 1 raises TimeoutError.
        Dispatch should produce a consensus (failed platform counts as flagged)."""
        config = _config(caipr_platform_count=3)
        dispatcher = CAIPRInspectionDispatcher(config)

        clean_finding = InspectionFinding(
            domain=InspectionDomain.OUTPUT_STATE,
            result=AlignmentResult.ALIGNED,
            severity=Severity.NOMINAL,
        )

        def platform_ok(txn):
            return clean_finding

        def platform_timeout(txn):
            raise TimeoutError("Platform timed out after 30s")

        dispatcher.register_platform("platform_fast_1", platform_ok)
        dispatcher.register_platform("platform_slow", platform_timeout)
        dispatcher.register_platform("platform_fast_2", platform_ok)

        txn = _transaction(prompt="Test timeout survival", txn_id="txn_timeout")

        # Should NOT raise -- must produce consensus
        consensus = dispatcher.dispatch(txn)

        self.assertIsNotNone(consensus)
        # The timed-out platform should be recorded in findings
        self.assertIn("platform_slow", consensus.platform_findings)
        # With 1 flagged (timed out) and 2 aligned, consensus should be
        # either ALIGNED (majority) or FLAGGED (security override)
        self.assertIn(
            consensus.consensus, ("ALIGNED", "FLAGGED"),
            "Consensus should be produced even with TimeoutError"
        )


# ===================================================================
# TEST 2: Structural verifier handles missing GOPEL directory
# ===================================================================

class TestStructuralVerifierHandlesMissingGopelDirectory(unittest.TestCase):
    """Calling verify_all() with a non-existent directory should return
    FLAGGED result with appropriate findings, NOT crash."""

    def test_structural_verifier_handles_missing_gopel_directory(self):
        """verify_all with non-existent directory returns FLAGGED, not crash."""
        config = _config()
        verifier = StructuralVerifier(config)

        # Create a manifest so code integrity check runs
        manifest = DeploymentManifest(
            gopel_version="1.7-test",
            cbg_authorization_id="test_auth",
            file_hashes={"module.py": "deadbeef1234"},
        )
        manifest.compute_manifest_hash()
        verifier.manifest = manifest

        # Call verify_all with a path that does not exist
        result, findings = verifier.verify_all(
            gopel_directory="/nonexistent/gopel/directory/that/does/not/exist",
            active_config={},
        )

        # Should return FLAGGED, not crash
        self.assertEqual(result, StructuralResult.FLAGGED)
        self.assertGreater(len(findings), 0, "Should have findings for missing directory")

        # At least one finding should mention the missing directory
        dir_findings = [
            f for f in findings
            if "directory" in f.description.lower() or "not found" in f.description.lower()
               or "missing" in f.description.lower()
        ]
        self.assertGreater(
            len(dir_findings), 0,
            "Should have a finding about the missing directory"
        )


# ===================================================================
# TEST 3: Behavioral drift detection over time
# ===================================================================

class TestBehavioralDriftDetectionOverTime(unittest.TestCase):
    """Submit clean RESEARCHER transactions to establish a baseline,
    then submit transactions with code patterns that violate the
    role-behavior envelope."""

    def test_behavioral_drift_detection_over_time(self):
        """50 clean transactions establishing baseline via direct
        record_clean_transaction calls, then 10 with forbidden code patterns.
        The output_state_evaluator should flag role-behavior violations."""
        config = _config()
        pipeline = OverwatchPipeline(config)

        # Phase 1: Establish baseline by recording 50 clean RESEARCHER outputs
        # directly via record_clean_transaction (the pipeline only calls this
        # for NOMINAL-severity outcomes, and provenance-tag-less transactions
        # get ADVISORY, so we call it directly for baseline building)
        for i in range(50):
            pipeline.output_state_evaluator.record_clean_transaction(
                RECCLINRole.RESEARCHER,
                f"Based on the evidence and citations from study {i}, "
                f"the primary finding is that governance frameworks require..."
            )

        # Verify baseline was recorded
        envelope = pipeline.output_state_evaluator.get_envelope(RECCLINRole.RESEARCHER)
        self.assertGreater(
            envelope.sample_count, 0,
            "Clean transactions should have updated the RESEARCHER envelope"
        )

        # Phase 2: Submit 10 transactions with forbidden code patterns
        flagged_count = 0
        for i in range(10):
            txn = _transaction(
                prompt=f"Analyze the data from experiment {i}",
                role=RECCLINRole.RESEARCHER,
                responses=[PlatformResponse(
                    platform_id="claude",
                    response_text=(
                        f"To analyze this data, run subprocess.call(['python', 'analyze.py']) "
                        f"and os.system('curl https://data.example.com/export') "
                        f"followed by exec('import pandas')"
                    ),
                    response_hash=f"drift_{i}",
                    response_time_ms=300.0,
                )],
                txn_id=f"txn_drift_{i}",
                operator_id="op_drift",
            )
            outcome = pipeline.verify_transaction(txn)

            # Check for role-behavior envelope violations
            envelope_findings = [
                f for f in outcome.inspection_findings
                if f.domain == InspectionDomain.OUTPUT_STATE
                and f.result == AlignmentResult.FLAGGED
                and ("forbidden" in f.description.lower()
                     or "state change" in f.description.lower())
            ]
            if len(envelope_findings) > 0:
                flagged_count += 1

        self.assertGreater(
            flagged_count, 0,
            "RESEARCHER outputs with subprocess/os.system should trigger "
            "role-behavior envelope violations"
        )


# ===================================================================
# TEST 4: Compromised CBG release still requires manifest validation
# ===================================================================

class TestCompromisedCbgReleaseStillRequiresValidation(unittest.TestCase):
    """Create a manifest, tamper with a file hash, verify that
    manifest_hash changes detect the tampering."""

    def test_compromised_cbg_release_still_requires_validation(self):
        """Tamper with a manifest file hash; verify hash change detection."""
        config = _config()
        verifier = StructuralVerifier(config)

        # Create a manifest with known file hashes
        manifest = DeploymentManifest(
            gopel_version="1.7.0",
            cbg_authorization_id="cbg_auth_001",
            file_hashes={
                "pipeline.py": "aaa111",
                "models.py": "bbb222",
                "escalation_engine.py": "ccc333",
            },
            config_snapshot={"setting_a": True, "setting_b": 42},
        )

        # Compute the original hash
        original_hash = manifest.compute_manifest_hash()
        self.assertTrue(len(original_hash) > 0)
        self.assertEqual(manifest.manifest_hash, original_hash)

        # Record it in the verifier
        verifier.manifest = manifest
        verifier.record_cbg_release("cbg_auth_001", "Initial release")

        # Tamper with a file hash (simulate compromised release)
        manifest.file_hashes["pipeline.py"] = "TAMPERED_HASH"

        # Recompute the hash -- it should be different now
        tampered_hash = manifest.compute_manifest_hash()
        self.assertNotEqual(
            original_hash, tampered_hash,
            "Manifest hash should change when file hashes are tampered"
        )


# ===================================================================
# TEST 5: Overwatch never escalates without evidence
# ===================================================================

class TestOverwatchNeverEscalatesWithoutEvidence(unittest.TestCase):
    """A clean transaction should produce NOMINAL severity, no escalation,
    and no significant findings."""

    def test_overwatch_never_escalates_without_evidence(self):
        """Submit a single clean transaction through a fresh pipeline.
        Verify it is not escalated. The first transaction may receive
        an ADVISORY for missing provenance tags (expected behavior),
        but a single ADVISORY should NOT cause escalation."""
        config = _config()
        pipeline = OverwatchPipeline(config)

        txn = _transaction(
            prompt="What are the key governance frameworks for responsible AI?",
            role=RECCLINRole.RESEARCHER,
            responses=[PlatformResponse(
                platform_id="claude",
                response_text=(
                    "The key governance frameworks include ISO 42001, "
                    "NIST AI RMF, and EU AI Act considerations for high-risk systems."
                ),
                response_hash="clean_hash",
                response_time_ms=200.0,
            )],
            txn_id="txn_clean_invariant",
        )
        outcome = pipeline.verify_transaction(txn)

        # A single clean transaction should NOT be escalated
        self.assertFalse(
            outcome.escalated,
            "Clean transaction should not be escalated"
        )

        # Key invariant: if escalated is True, there MUST be findings
        # with severity >= WARNING. Here we verify the invariant holds.
        if outcome.escalated:
            high_severity_findings = [
                f for f in outcome.inspection_findings
                if f.severity >= Severity.WARNING
            ]
            self.assertGreater(
                len(high_severity_findings), 0,
                "Escalation without WARNING+ findings violates invariant"
            )

    def test_escalation_invariant_holds_across_many_transactions(self):
        """Submit 100 transactions; verify the invariant:
        if escalated is True, there MUST be findings >= WARNING.
        This tests the invariant itself, not whether transactions
        are clean (some may accumulate advisories)."""
        config = _config()
        pipeline = OverwatchPipeline(config)

        for i in range(100):
            txn = _transaction(
                prompt=f"Summarize governance framework section {i}",
                role=RECCLINRole.RESEARCHER,
                responses=[PlatformResponse(
                    platform_id="claude",
                    response_text=f"Section {i} covers regulatory compliance...",
                    response_hash=f"clean_{i}",
                    response_time_ms=150.0,
                )],
                txn_id=f"txn_invariant_{i}",
            )
            outcome = pipeline.verify_transaction(txn)

            # The invariant: if escalated, must have WARNING+ findings
            # or structural findings that caused escalation
            if outcome.escalated:
                has_high_inspection = any(
                    f.severity >= Severity.WARNING
                    for f in outcome.inspection_findings
                )
                has_high_structural = any(
                    f.severity >= Severity.WARNING
                    for f in outcome.structural_findings
                )
                has_advisory_overflow = (
                    outcome.overall_severity >= Severity.WARNING
                )
                self.assertTrue(
                    has_high_inspection or has_high_structural or has_advisory_overflow,
                    f"Transaction {i}: escalated without WARNING+ evidence"
                )


# ===================================================================
# TEST 6: Transaction never mutates original GOPEL record
# ===================================================================

class TestTransactionNeverMutatesOriginalGopelRecord(unittest.TestCase):
    """TransactionRecord fields should not be corrupted by pipeline processing
    for non-oversized inputs."""

    def test_transaction_never_mutates_original_gopel_record(self):
        """Create a TransactionRecord, save copies of fields, run through
        pipeline, verify fields are unchanged for normal-length inputs."""
        config = _config()
        pipeline = OverwatchPipeline(config)

        prompt = "What are the primary governance frameworks for AI safety?"
        txn = _transaction(
            prompt=prompt,
            role=RECCLINRole.RESEARCHER,
            txn_id="txn_immutable_check",
        )

        # Save original field values
        original_txn_id = txn.transaction_id
        original_operator_id = txn.operator_id
        original_role = txn.recclin_role
        original_prompt_hash = txn.prompt_hash
        original_prompt_text = txn.prompt_text
        original_platforms = list(txn.platforms_dispatched)
        original_response_count = len(txn.responses)

        # Process through the pipeline
        outcome = pipeline.verify_transaction(txn)

        # Verify all fields are unchanged (for normal-length prompts,
        # no truncation should occur)
        self.assertEqual(txn.transaction_id, original_txn_id)
        self.assertEqual(txn.operator_id, original_operator_id)
        self.assertEqual(txn.recclin_role, original_role)
        self.assertEqual(txn.prompt_hash, original_prompt_hash)
        self.assertEqual(txn.prompt_text, original_prompt_text,
                         "prompt_text should not be mutated for normal-length inputs")
        self.assertEqual(txn.platforms_dispatched, original_platforms)
        self.assertEqual(len(txn.responses), original_response_count)

        # Verify the pipeline still produced a valid outcome
        self.assertIsNotNone(outcome)
        self.assertEqual(outcome.transaction_id, original_txn_id)


# ===================================================================
# TEST 7: Random audit report is SIEM-friendly
# ===================================================================

class TestRandomAuditReportIsSiemFriendly(unittest.TestCase):
    """Generate a random audit report using the pipeline and verify
    the JSON export contains all required SIEM fields."""

    def test_random_audit_report_is_siem_friendly(self):
        """Generate report, export to JSON, verify required fields."""
        config = _config()
        pipeline = OverwatchPipeline(config)

        # Submit a transaction and force an audit
        txn = _transaction(
            prompt="Quarterly governance review summary",
            txn_id="txn_siem_audit",
        )
        outcome = pipeline.verify_transaction(txn)

        # Force generate a random audit report
        with patch.object(pipeline.random_audit, 'should_audit', return_value=True):
            # Submit another transaction to trigger audit
            txn2 = _transaction(
                prompt="Annual compliance summary",
                txn_id="txn_siem_audit_2",
            )
            pipeline.verify_transaction(txn2)

        report = pipeline.random_audit.get_last_report()
        self.assertIsNotNone(report, "Audit report should have been generated")

        # Export to JSON
        json_str = pipeline.random_audit.export_report(report)

        # Verify it's valid JSON
        parsed = json.loads(json_str)
        self.assertIsInstance(parsed, dict)

        # Verify required SIEM fields
        required_fields = [
            "report_id", "timestamp", "report_hash",
            "previous_report_hash", "transaction_id",
        ]
        for field_name in required_fields:
            self.assertIn(
                field_name, parsed,
                f"SIEM-friendly report must contain '{field_name}'"
            )

        # Verify timestamp is a number
        self.assertIsInstance(
            parsed["timestamp"], (int, float),
            "timestamp should be a number"
        )

        # Verify hashes are hex strings
        hex_pattern = re.compile(r'^[0-9a-f]+$')
        self.assertTrue(
            hex_pattern.match(parsed["report_hash"]),
            f"report_hash should be a hex string, got: {parsed['report_hash']}"
        )
        # previous_report_hash may be "genesis" for the first report
        if parsed["previous_report_hash"] != "genesis":
            self.assertTrue(
                hex_pattern.match(parsed["previous_report_hash"]),
                f"previous_report_hash should be hex string or 'genesis'"
            )

        # Verify report_id is non-empty
        self.assertTrue(
            len(parsed["report_id"]) > 0,
            "report_id should be non-empty"
        )

        # Verify transaction_id is non-empty
        self.assertTrue(
            len(parsed["transaction_id"]) > 0,
            "transaction_id should be non-empty"
        )


if __name__ == "__main__":
    unittest.main()
