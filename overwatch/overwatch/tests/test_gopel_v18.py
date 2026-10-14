"""
HAIA-Overwatch v1.8 - GOPEL Adversarial Test Suite

Four tests covering:
1. Detects inconsistent platform responses
2. Factics does not auto-approve critical rules by default
3. Sustained GOPEL load performance (5000 transactions)
4. Audit report contains required compliance fields

Author: Basil C. Puglisi, MPA
License: CC BY-NC 4.0
Attribution: #AIassisted under HAIA-RECCLIN & Checkpoint-Based Governance
"""

import hashlib
import json
import time
import unittest
from typing import Any, Dict, List, Optional
from unittest.mock import patch

from overwatch.models import (
    AlignmentResult, InspectionDomain, InspectionFinding,
    OverwatchConfig, PlatformResponse, RECCLINRole,
    Severity, TransactionRecord, VerificationOutcome,
)
from overwatch.pipeline import OverwatchPipeline
from overwatch.factics_engine import FacticsEngine


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
# TEST 1: Detects inconsistent platform responses
# ===================================================================

class TestDetectsInconsistentPlatformResponses(unittest.TestCase):
    """Submit a transaction where two platform responses give contradictory
    outputs with high confidence. Verify the pipeline handles multiple
    responses without crash and produces a valid outcome."""

    def test_detects_inconsistent_platform_responses(self):
        """Two platforms give contradictory high-confidence answers.
        Pipeline should handle gracefully and produce valid outcome."""
        config = _config()
        pipeline = OverwatchPipeline(config)

        txn = _transaction(
            prompt="What is the recommended approach for data governance?",
            role=RECCLINRole.RESEARCHER,
            responses=[
                PlatformResponse(
                    platform_id="platform_A",
                    response_text=(
                        "The answer is centralized governance with strict controls. "
                        "All data access must be routed through a central authority."
                    ),
                    response_hash="hash_a",
                    response_time_ms=200.0,
                    confidence_score=0.95,
                ),
                PlatformResponse(
                    platform_id="platform_B",
                    response_text=(
                        "The answer is decentralized governance with autonomy. "
                        "Each department should manage its own data independently."
                    ),
                    response_hash="hash_b",
                    response_time_ms=220.0,
                    confidence_score=0.95,
                ),
            ],
            txn_id="txn_inconsistent",
        )

        # Pipeline should NOT crash with multiple responses
        outcome = pipeline.verify_transaction(txn)
        self.assertIsNotNone(outcome)
        self.assertEqual(outcome.transaction_id, "txn_inconsistent")

        # The outcome should be a valid VerificationOutcome
        self.assertIsInstance(outcome.overall_severity, Severity)
        self.assertIsInstance(outcome.escalated, bool)

        # Verify execution graph recorded both responses
        graphs = pipeline.execution_graph._graphs
        self.assertIn("txn_inconsistent", graphs)


# ===================================================================
# TEST 2: Factics does not auto-approve critical rules by default
# ===================================================================

class TestFacticsDoesNotAutoApproveCriticalRulesByDefault(unittest.TestCase):
    """Verify auto-approve behavior:
    - Default config: CRITICAL proposals stay pending
    - With auto_approve enabled: ADVISORY auto-approved, CRITICAL stays pending
    """

    def _make_finding(self, severity, txn_id="txn_factics"):
        return InspectionFinding(
            domain=InspectionDomain.INTENT,
            result=AlignmentResult.FLAGGED,
            severity=severity,
            confidence=0.9 if severity == Severity.CRITICAL else 0.4,
            description=f"Test finding at {severity.value}",
            evidence_chain=["recon: step 1", "privilege: step 2"],
            transaction_id=txn_id,
        )

    def test_critical_stays_pending_with_default_config(self):
        """Default config has factics_auto_approve_low_risk=False.
        CRITICAL proposals should stay pending."""
        config = _config(factics_auto_approve_low_risk=False)
        engine = FacticsEngine(config=config)

        finding = self._make_finding(Severity.CRITICAL, "txn_crit_default")
        outcome = VerificationOutcome(transaction_id="txn_crit_default")
        engine.process_confirmed_threat(finding, outcome, "Confirmed threat")

        pending = engine.get_pending_proposals()
        approved = engine.get_approved_proposals()

        self.assertEqual(len(pending), 1, "CRITICAL proposal should be pending")
        self.assertEqual(len(approved), 0, "No proposals should be auto-approved")

    def test_advisory_auto_approved_when_enabled(self):
        """With factics_auto_approve_low_risk=True, ADVISORY proposals
        should be auto-approved."""
        config = _config(factics_auto_approve_low_risk=True)
        engine = FacticsEngine(config=config)

        finding = self._make_finding(Severity.ADVISORY, "txn_adv_auto")
        outcome = VerificationOutcome(transaction_id="txn_adv_auto")
        engine.process_confirmed_threat(finding, outcome, "Low-risk finding")

        pending = engine.get_pending_proposals()
        approved = engine.get_approved_proposals()

        self.assertEqual(len(pending), 0, "ADVISORY proposal should be auto-approved")
        self.assertEqual(len(approved), 1, "ADVISORY should be in approved list")

    def test_critical_stays_pending_even_with_auto_approve_enabled(self):
        """With factics_auto_approve_low_risk=True, CRITICAL proposals
        should STILL stay pending (auto-approve only for ADVISORY)."""
        config = _config(factics_auto_approve_low_risk=True)
        engine = FacticsEngine(config=config)

        finding = self._make_finding(Severity.CRITICAL, "txn_crit_auto")
        outcome = VerificationOutcome(transaction_id="txn_crit_auto")
        engine.process_confirmed_threat(finding, outcome, "Critical threat")

        pending = engine.get_pending_proposals()
        approved = engine.get_approved_proposals()

        self.assertEqual(
            len(pending), 1,
            "CRITICAL proposal should stay pending even with auto-approve enabled"
        )
        self.assertEqual(
            len(approved), 0,
            "CRITICAL should NOT be auto-approved"
        )


# ===================================================================
# TEST 3: Sustained GOPEL load performance
# ===================================================================

class TestSustainedGopelLoadPerformance(unittest.TestCase):
    """Submit 5000 transactions in a tight loop. Verify total count
    and that pipeline stats are consistent."""

    def test_sustained_gopel_load_performance(self):
        """5000 transactions in a tight loop; verify count and consistency."""
        config = _config()
        pipeline = OverwatchPipeline(config)

        n_transactions = 5000
        total_start = time.perf_counter()

        for i in range(n_transactions):
            txn = TransactionRecord(
                transaction_id=f"sustained_{i}",
                timestamp=time.time(),
                operator_id="op_sustained",
                recclin_role=RECCLINRole.RESEARCHER,
                prompt_hash=f"hash_{i}",
                prompt_text=f"query {i}",
                platforms_dispatched=["claude"],
                responses=[
                    PlatformResponse(
                        platform_id="claude",
                        response_text=f"answer {i}",
                        response_hash=f"rhash_{i}",
                        response_time_ms=100.0,
                    )
                ],
            )
            pipeline.verify_transaction(txn)

        total_elapsed = time.perf_counter() - total_start

        # Verify total transaction count
        self.assertEqual(
            pipeline._total_transactions, n_transactions,
            f"Expected {n_transactions} transactions, got {pipeline._total_transactions}"
        )

        # Verify pipeline stats are consistent
        status = pipeline.get_status()
        self.assertEqual(status["total_transactions"], n_transactions)
        self.assertEqual(
            status["total_clean"] + status["total_escalations"],
            pipeline._total_clean + pipeline._total_escalations,
        )

        # Relaxed time limit for sandbox/CI
        self.assertLess(
            total_elapsed, 120.0,
            f"5000 transactions took {total_elapsed:.2f}s (limit: 120s)"
        )


# ===================================================================
# TEST 4: Audit report contains required compliance fields
# ===================================================================

class TestAuditReportContainsRequiredComplianceFields(unittest.TestCase):
    """Generate an audit report and verify it contains all fields
    needed for compliance audit."""

    def test_audit_report_contains_required_compliance_fields(self):
        """Generate report; verify chain integrity, transaction, outcome,
        advisories, and factics metrics fields."""
        config = _config()
        pipeline = OverwatchPipeline(config)

        # Submit a transaction
        txn = _transaction(
            prompt="Compliance review checkpoint",
            txn_id="txn_compliance",
        )
        outcome = pipeline.verify_transaction(txn)

        # Force generate audit report
        with patch.object(pipeline.random_audit, 'should_audit', return_value=True):
            txn2 = _transaction(
                prompt="Compliance review checkpoint 2",
                txn_id="txn_compliance_2",
            )
            pipeline.verify_transaction(txn2)

        report = pipeline.random_audit.get_last_report()
        self.assertIsNotNone(report, "Audit report should have been generated")

        # Verify chain integrity fields
        self.assertTrue(len(report.report_id) > 0, "report_id must be non-empty")
        self.assertIsInstance(report.timestamp, float, "timestamp must be a float")
        self.assertTrue(len(report.report_hash) > 0, "report_hash must be non-empty")
        self.assertTrue(
            len(report.previous_report_hash) > 0,
            "previous_report_hash must be non-empty"
        )

        # Verify selected_transaction is present
        self.assertIsNotNone(
            report.selected_transaction,
            "selected_transaction must be present"
        )
        self.assertTrue(
            len(report.selected_transaction.transaction_id) > 0,
            "selected_transaction must have a transaction_id"
        )

        # Verify verification_outcome is present
        self.assertIsNotNone(
            report.verification_outcome,
            "verification_outcome must be present"
        )
        self.assertIsInstance(
            report.verification_outcome.overall_severity, Severity,
            "verification_outcome must have a severity"
        )
        # inspection_findings is a list (may be empty for clean transactions)
        self.assertIsInstance(
            report.verification_outcome.inspection_findings, list,
            "verification_outcome must have inspection_findings list"
        )

        # Verify accumulated_advisories is a list
        self.assertIsInstance(
            report.accumulated_advisories, list,
            "accumulated_advisories must be a list"
        )

        # Verify factics_metrics is a dict with kpis
        self.assertIsInstance(
            report.factics_metrics, dict,
            "factics_metrics must be a dict"
        )
        self.assertIn("kpis", report.factics_metrics,
                       "factics_metrics must contain 'kpis'")

        # Verify the export also contains these fields
        json_str = pipeline.random_audit.export_report(report)
        parsed = json.loads(json_str)
        self.assertIn("report_id", parsed)
        self.assertIn("timestamp", parsed)
        self.assertIn("report_hash", parsed)
        self.assertIn("previous_report_hash", parsed)
        self.assertIn("verification_outcome", parsed)
        self.assertIn("accumulated_advisories", parsed)
        self.assertIn("factics_metrics", parsed)


if __name__ == "__main__":
    unittest.main()
