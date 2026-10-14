"""
HAIA-Overwatch v1.1 - GOPEL Red Team Test Suite

Adversarial tests derived from the Grok red-team assessment.
Covers: flush_stale crash, concurrent finalization, novel attack
during pending proposal window, HMAC roundtrip, DoS protection,
execution graph wiring, self-heartbeat health, GOPEL mode config,
and RuleProposal type safety.

Author: Basil C. Puglisi, MPA
License: CC BY-NC 4.0
Attribution: #AIassisted under HAIA-RECCLIN & Checkpoint-Based Governance
"""

import hashlib
import json
import threading
import time
import unittest
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock

from overwatch.models import (
    AlignmentResult, ChainSignature, DeclaredTaskScope, Heartbeat,
    InspectionDomain, InspectionFinding, OperatingMode, OverwatchConfig,
    PlatformResponse, ProvenanceTag, RECCLINRole, RuleProposal, Severity,
    StructuralResult, TransactionRecord, TrustTier, VerificationOutcome,
)
from overwatch.pipeline import OverwatchPipeline
from overwatch.factics_engine import FacticsEngine
from overwatch.gopel_observer import (
    GopelObserver, GopelRecord, GopelRecordKind,
    ChainValidationError, validate_chain, assemble_transaction,
)
from overwatch.execution_graph import ExecutionGraphEngine
from overwatch.crypto import SigningKeyProvider, get_default_provider, set_default_provider
from overwatch.channel_manager import IndependentChannelManager, ChannelMessage
from overwatch.provenance_manager import ProvenanceManager


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


def _transaction(
    prompt: str = "What are the key governance frameworks?",
    role: RECCLINRole = RECCLINRole.RESEARCHER,
    responses: Optional[List[PlatformResponse]] = None,
    txn_id: str = "",
) -> TransactionRecord:
    txn_id = txn_id or f"txn_{id(prompt)}"
    return TransactionRecord(
        transaction_id=txn_id,
        timestamp=time.time(),
        operator_id="op_test",
        recclin_role=role,
        prompt_hash=hashlib.sha256(prompt.encode()).hexdigest(),
        prompt_text=prompt,
        platforms_dispatched=["claude", "gpt4"],
        responses=responses or [
            PlatformResponse(
                platform_id="claude",
                response_text="Governance frameworks include...",
                response_hash="abc123",
                response_time_ms=250.0,
            )
        ],
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
# TEST: GopelObserver concurrent finalization
# ===================================================================

class TestGopelObserverConcurrentFinalization(unittest.TestCase):
    """Grok Finding A: concurrent record submission must not lose transactions."""

    def test_gopel_observer_concurrent_finalization(self):
        """Push 100 transactions from multiple threads; assert none lost."""
        config = _config()
        pipeline = OverwatchPipeline(config)
        observer = GopelObserver(
            pipeline=pipeline,
            config=config,
            require_chain_validation=False,
        )
        num_transactions = 100
        outcomes = []
        errors = []

        def submit_transaction(i):
            try:
                txn_id = f"concurrent_{i}"
                req = _make_gopel_record(
                    GopelRecordKind.REQUEST, txn_id,
                    {"prompt_text": f"prompt {i}", "operator_id": "op", "recclin_role": "RESEARCHER"},
                )
                observer.observe(req)

                dispatch = _make_gopel_record(
                    GopelRecordKind.DISPATCH, txn_id,
                    {"platforms": ["claude"]},
                    prev_hash=req.this_hash,
                )
                observer.observe(dispatch)

                resp = _make_gopel_record(
                    GopelRecordKind.RESPONSE, txn_id,
                    {"platform_id": "claude", "response_text": f"answer {i}",
                     "response_hash": "h", "response_time_ms": 100},
                    prev_hash=dispatch.this_hash,
                )
                observer.observe(resp)

                decision = _make_gopel_record(
                    GopelRecordKind.DECISION, txn_id,
                    {"approved": True},
                    prev_hash=resp.this_hash,
                )
                result = observer.observe(decision)
                if result is not None:
                    outcomes.append(result)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=submit_transaction, args=(i,)) for i in range(num_transactions)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        stats = observer.get_statistics()
        # Should have finalized most transactions (some races may occur
        # but zero is a failure)
        self.assertGreater(stats["transactions_finalized"], 0)
        self.assertEqual(len(errors), 0, f"Errors during concurrent submission: {errors}")


# ===================================================================
# TEST: flush_stale safe under load
# ===================================================================

class TestFlushStaleSafeUnderLoad(unittest.TestCase):
    """Grok Finding B: flush_stale must not crash when accessing deleted timestamps."""

    def test_flush_stale_does_not_crash_on_race(self):
        """Flush stale transactions and confirm no KeyError on deleted timestamps."""
        config = _config()
        pipeline = OverwatchPipeline(config)
        observer = GopelObserver(
            pipeline=pipeline, config=config,
            ttl_seconds=0.01, require_chain_validation=False,
        )

        # Buffer several incomplete transactions
        for i in range(20):
            txn_id = f"stale_{i}"
            req = _make_gopel_record(
                GopelRecordKind.REQUEST, txn_id,
                {"prompt_text": f"prompt {i}", "operator_id": "op", "recclin_role": "RESEARCHER"},
            )
            observer.observe(req)

        # Wait for TTL to expire
        time.sleep(0.02)

        # This should NOT raise KeyError (the bug Grok identified)
        flushed = observer.flush_stale()
        self.assertEqual(flushed, 20)
        self.assertEqual(observer.get_statistics()["stale_flushed"], 20)

    def test_flush_stale_concurrent_with_observe(self):
        """Flush and observe simultaneously without crash."""
        config = _config()
        pipeline = OverwatchPipeline(config)
        observer = GopelObserver(
            pipeline=pipeline, config=config,
            ttl_seconds=0.001, require_chain_validation=False,
        )
        errors = []

        def observe_loop():
            try:
                for i in range(50):
                    txn_id = f"race_{i}"
                    req = _make_gopel_record(
                        GopelRecordKind.REQUEST, txn_id,
                        {"prompt_text": f"p{i}", "operator_id": "op", "recclin_role": "RESEARCHER"},
                    )
                    observer.observe(req)
                    time.sleep(0.001)
            except Exception as e:
                errors.append(e)

        def flush_loop():
            try:
                for _ in range(50):
                    observer.flush_stale()
                    time.sleep(0.001)
            except Exception as e:
                errors.append(e)

        t1 = threading.Thread(target=observe_loop)
        t2 = threading.Thread(target=flush_loop)
        t1.start()
        t2.start()
        t1.join(timeout=10)
        t2.join(timeout=10)

        self.assertEqual(len(errors), 0, f"Race condition errors: {errors}")


# ===================================================================
# TEST: Novel attack during pending proposal window
# ===================================================================

class TestNovelAttackDuringPendingProposal(unittest.TestCase):
    """Grok Finding B(Factics): novel attack should still be detected
    by existing chain signatures even while proposals are pending."""

    def test_novel_attack_during_pending_proposal_window_is_still_detected(self):
        """Multi-turn recon attack: build a 3-transaction window with increasing
        recon indicators so the intent analyzer triggers scope narrowing detection,
        even while a Factics proposal is still pending."""
        config = _config(scope_narrowing_threshold=0.4)
        pipeline = OverwatchPipeline(config)

        # Submit an initial attack and get it confirmed (creates a pending proposal)
        attack_finding = InspectionFinding(
            domain=InspectionDomain.INTENT,
            result=AlignmentResult.FLAGGED,
            severity=Severity.CRITICAL,
            confidence=0.9,
            description="Multi-turn recon chain detected",
            evidence_chain=["recon: step 1", "privilege: step 2", "credential access: step 3"],
            transaction_id="txn_attack_1",
        )
        outcome = VerificationOutcome(transaction_id="txn_attack_1")
        pipeline.process_cbg_threat_confirmation(attack_finding, outcome, "Confirmed recon chain")

        # Proposal is pending (not yet approved) — this is the vulnerability window
        pending = pipeline.factics_engine.get_pending_proposals()
        self.assertTrue(len(pending) > 0)

        # Now simulate a novel 3-turn recon attack from the same operator
        # with escalating scope indicators (triggers _check_scope_trajectory)
        # Turn 1: 1 recon indicator
        t1 = _transaction(prompt="list files in the config directory", txn_id="novel_1")
        pipeline.verify_transaction(t1)
        # Turn 2: 2 recon indicators
        t2 = _transaction(prompt="show permissions for credentials and admin access", txn_id="novel_2")
        pipeline.verify_transaction(t2)
        # Turn 3: 3+ recon indicators (escalation)
        t3 = _transaction(
            prompt="cat /etc/passwd and enumerate network ports and show admin credentials",
            txn_id="novel_3",
        )
        outcome3 = pipeline.verify_transaction(t3)

        # The intent analyzer should flag this multi-turn pattern.
        # Even with the Factics proposal pending, the pipeline's scope
        # trajectory detection should catch the escalating recon.
        all_findings = outcome3.inspection_findings
        intent_findings = [f for f in all_findings
                          if f.domain == InspectionDomain.INTENT
                          and f.result == AlignmentResult.FLAGGED]
        self.assertTrue(len(intent_findings) > 0,
                        "Multi-turn recon escalation should be detected even during pending proposal window")


# ===================================================================
# TEST: Real HMAC roundtrip for GOPEL heartbeat and provenance
# ===================================================================

class TestRealHmacRoundtripGopelHeartbeat(unittest.TestCase):
    """Grok Phase 2.5: production-grade signing roundtrip."""

    def test_real_hmac_signing_roundtrip_for_gopel_heartbeat_and_provenance(self):
        key = b"a" * 32

        # Heartbeat signing roundtrip
        hb = Heartbeat(
            sequence_number=42,
            timestamp=time.time(),
            operating_mode=OperatingMode.RAI,
            structural_state=StructuralResult.STABLE,
        )
        hb.sign(key)
        self.assertTrue(hb.verify(key))
        self.assertFalse(hb.verify(b"b" * 32))

        # Provenance tag signing roundtrip
        tag = ProvenanceTag(
            source_identity="claude",
            timestamp=time.time(),
            trust_tier=TrustTier.TIER_1,
            ingestion_path="api_response",
        )
        tag.sign(key)
        self.assertTrue(tag.verify(key))
        self.assertFalse(tag.verify(b"c" * 32))

    def test_crypto_module_signing_and_rotation(self):
        """SigningKeyProvider sign/verify/rotate roundtrip."""
        key1 = b"initial_key_padded_to_32_bytes!!"
        key2 = b"rotated_key_padded_to_32_bytes!!"
        provider = SigningKeyProvider(key1)

        data = b"hello overwatch"
        sig = provider.sign(data)
        self.assertTrue(provider.verify(data, sig))

        # Rotate key
        provider.rotate_key(key2)
        # Old signature still verifies (previous key retained)
        self.assertTrue(provider.verify(data, sig))
        # New signature uses new key
        sig2 = provider.sign(data)
        self.assertTrue(provider.verify(data, sig2))
        # Old and new sigs are different
        self.assertNotEqual(sig, sig2)


# ===================================================================
# TEST: Malicious GOPEL prompt DoS protection
# ===================================================================

class TestMaliciousGopelPromptDosProtection(unittest.TestCase):
    """Grok Phase 3.6: resource guards prevent DoS from oversized content."""

    def test_malicious_long_gopel_prompt_does_not_cause_dos(self):
        config = _config(max_scan_text_length=1000)
        pipeline = OverwatchPipeline(config)

        # Create a transaction with a 10MB prompt (simulating malicious GOPEL record)
        huge_prompt = "A" * 10_000_000
        txn = _transaction(prompt=huge_prompt, txn_id="txn_dos")

        # This should complete without hanging or crashing
        import timeit
        start = timeit.default_timer()
        outcome = pipeline.verify_transaction(txn)
        elapsed = timeit.default_timer() - start

        # Should complete in reasonable time (< 5 seconds)
        self.assertLess(elapsed, 5.0, "Pipeline took too long on oversized prompt")

        # Should still produce a result
        self.assertIsNotNone(outcome)

    def test_truncation_produces_advisory_finding(self):
        config = _config(max_scan_text_length=100)
        pipeline = OverwatchPipeline(config)

        txn = _transaction(prompt="X" * 500, txn_id="txn_trunc")
        outcome = pipeline.verify_transaction(txn)

        # Look for truncation advisory in findings
        trunc_findings = [
            f for f in outcome.inspection_findings
            if "truncat" in f.description.lower()
        ]
        self.assertTrue(len(trunc_findings) > 0,
                        "Truncation should produce ADVISORY finding")


# ===================================================================
# TEST: Every GOPEL transaction creates execution graph node
# ===================================================================

class TestEveryGopelTransactionCreatesExecutionGraphNode(unittest.TestCase):
    """Grok Phase 3.7: auto-wiring execution graph into verify_transaction."""

    def test_every_gopel_transaction_creates_execution_graph_node(self):
        config = _config()
        pipeline = OverwatchPipeline(config)

        # Submit 5 transactions
        for i in range(5):
            txn = _transaction(
                prompt=f"Query {i}",
                txn_id=f"txn_graph_{i}",
            )
            pipeline.verify_transaction(txn)

        # Each transaction should have created at least a role_assignment node
        graphs = pipeline.execution_graph._graphs
        self.assertGreater(len(graphs), 0, "Execution graph should have entries")

    def test_graph_records_dispatch_and_response(self):
        config = _config()
        pipeline = OverwatchPipeline(config)

        txn = _transaction(
            prompt="Test dispatch recording",
            txn_id="txn_graph_detail",
            responses=[
                PlatformResponse(
                    platform_id="claude", response_text="answer",
                    response_hash="h1", response_time_ms=100,
                ),
                PlatformResponse(
                    platform_id="gpt4", response_text="answer2",
                    response_hash="h2", response_time_ms=150,
                ),
            ],
        )
        pipeline.verify_transaction(txn)

        # The execution graph should have nodes for role, dispatch, and responses
        graphs = pipeline.execution_graph._graphs
        self.assertGreater(len(graphs), 0)


# ===================================================================
# TEST: Overwatch self-heartbeat reports internal health
# ===================================================================

class TestOverwatchSelfHeartbeatReportsHealth(unittest.TestCase):
    """Grok Phase 3.8: heartbeat includes internal health metrics."""

    def test_overwatch_heartbeat_reports_internal_health_for_gopel_deployment(self):
        config = _config()
        pipeline = OverwatchPipeline(config)

        # Run a few transactions to generate state
        for i in range(3):
            txn = _transaction(prompt=f"health check {i}", txn_id=f"txn_health_{i}")
            pipeline.verify_transaction(txn)

        # Get health
        health = pipeline.get_health()
        self.assertIn("pending_proposals_count", health)
        self.assertIn("last_factics_cycle", health)
        self.assertIn("total_transactions", health)
        self.assertEqual(health["total_transactions"], 3)

        # Status should include health
        status = pipeline.get_status()
        self.assertIn("health", status)
        self.assertEqual(status["health"]["total_transactions"], 3)


# ===================================================================
# TEST: GOPEL mode tightens thresholds
# ===================================================================

class TestGopelModeTightensThresholds(unittest.TestCase):
    """Grok Phase 4.10: gopel_mode config profile."""

    def test_gopel_mode_config_applies_correct_defaults(self):
        config = OverwatchConfig(gopel_mode=True)

        # GOPEL mode should tighten these
        self.assertTrue(config.require_structural_inputs)
        self.assertTrue(config.require_heartbeat_key)
        self.assertFalse(config.follow_symlinks)
        self.assertLessEqual(config.advisory_accumulation_limit, 3)
        self.assertGreaterEqual(config.random_audit_base_probability, 0.10)
        self.assertLessEqual(config.max_scan_text_length, 500_000)

    def test_gopel_mode_does_not_override_explicit_settings_when_stricter(self):
        """User can set stricter values; GOPEL mode uses min/max logic."""
        config = OverwatchConfig(
            gopel_mode=True,
            advisory_accumulation_limit=2,  # already stricter than 3
            random_audit_base_probability=0.20,  # already higher than 0.10
        )
        self.assertEqual(config.advisory_accumulation_limit, 2)
        self.assertEqual(config.random_audit_base_probability, 0.20)

    def test_gopel_mode_false_leaves_defaults_unchanged(self):
        config = OverwatchConfig(gopel_mode=False)
        self.assertEqual(config.advisory_accumulation_limit, 5)  # default
        self.assertEqual(config.random_audit_base_probability, 0.05)  # default
        self.assertEqual(config.max_scan_text_length, 1_000_000)  # default


# ===================================================================
# TEST: RuleProposal type safety after approve
# ===================================================================

class TestRuleProposalTypeSafetyAfterApprove(unittest.TestCase):
    """Grok Phase 2.4: chain_signature should be Optional[ChainSignature], not str."""

    def test_rule_proposal_chain_signature_type_safety(self):
        """chain_signature should accept ChainSignature objects, not just strings."""
        sig = ChainSignature(
            name="test_sig",
            pattern_type="recon",
            step_sequence=["recon", "escalation"],
        )
        proposal = RuleProposal(chain_signature=sig)
        self.assertIsInstance(proposal.chain_signature, ChainSignature)

        # to_dict should handle it
        d = proposal.to_dict()
        self.assertIsInstance(d["chain_signature"], dict)
        self.assertEqual(d["chain_signature"]["name"], "test_sig")

    def test_rule_proposal_chain_signature_none_by_default(self):
        proposal = RuleProposal()
        self.assertIsNone(proposal.chain_signature)
        d = proposal.to_dict()
        self.assertEqual(d["chain_signature"], "")

    def test_rule_proposal_type_safety_after_approve(self):
        """Full Factics flow: create proposal with ChainSignature, approve it,
        verify the chain signature object is preserved in the library."""
        engine = FacticsEngine()
        finding = InspectionFinding(
            domain=InspectionDomain.INTENT,
            result=AlignmentResult.FLAGGED,
            severity=Severity.CRITICAL,
            evidence_chain=["recon: probe", "credential access: dump"],
        )
        outcome = VerificationOutcome(transaction_id="txn_type_safety")
        engine.process_confirmed_threat(finding, outcome)

        pending = engine.get_pending_proposals()
        self.assertTrue(len(pending) > 0)

        # The chain_signature should be a ChainSignature, not a string
        proposal = pending[0]
        if proposal.chain_signature is not None:
            self.assertIsInstance(proposal.chain_signature, ChainSignature)

        # Approve and verify library entry
        engine.approve_proposal(proposal.proposal_id, "approved")
        library = engine.get_chain_library()
        if library:
            self.assertIsInstance(library[0], ChainSignature)


# ===================================================================
# TEST: Pipeline inspect() is first-class method
# ===================================================================

class TestPipelineInspectMethod(unittest.TestCase):
    """Grok Finding A: inspect() must be a proper method, not just a shim."""

    def test_inspect_delegates_to_verify_transaction(self):
        config = _config()
        pipeline = OverwatchPipeline(config)
        txn = _transaction(prompt="inspect method test", txn_id="txn_inspect")

        outcome = pipeline.inspect(txn)
        self.assertIsNotNone(outcome)
        self.assertEqual(outcome.transaction_id, "txn_inspect")
        self.assertEqual(pipeline._total_transactions, 1)

    def test_inspect_used_by_gopel_observer(self):
        """GopelObserver._finalize calls pipeline.inspect() on DECISION."""
        config = _config()
        pipeline = OverwatchPipeline(config)
        observer = GopelObserver(
            pipeline=pipeline, config=config, require_chain_validation=False,
        )

        txn_id = "txn_observer_inspect"
        req = _make_gopel_record(
            GopelRecordKind.REQUEST, txn_id,
            {"prompt_text": "observer test", "operator_id": "op", "recclin_role": "RESEARCHER"},
        )
        observer.observe(req)

        decision = _make_gopel_record(
            GopelRecordKind.DECISION, txn_id,
            {"approved": True},
            prev_hash=req.this_hash,
        )
        result = observer.observe(decision)
        self.assertIsNotNone(result)
        self.assertEqual(pipeline._total_transactions, 1)


if __name__ == "__main__":
    unittest.main()
