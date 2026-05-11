"""
GOPEL v0.6.2 Security Hardening Test Suite
=============================================
Tests for all 11 security fixes identified in the Security Review Report.

SEC-01: Thread-safe sequence counter (sentinel.py)
SEC-02: HMAC verification on obfuscation decrypt (security.py)
SEC-03: signable_payload includes transaction context (governance.py)
SEC-04: BreachReport.finalize() hashes complete dict (breach.py)
SEC-05: EscalationEngine.evaluate() catches rule exceptions (governance.py)
SEC-06: Witness file HMAC authentication (security.py)
SEC-07: Public API promotion for external monitors (logger.py, governance.py)
SEC-08: deque replaces list.pop(0) for decision log (governance.py)
SEC-09: Post-read chain verification in read_lock (security.py)
SEC-10: signable_payload promoted to public (governance.py)
SEC-11: Callback error counter in Sentinel (sentinel.py)

Author: Basil C. Puglisi, MPA
"""

import base64
import collections
import json
import os
import tempfile
import threading
from pathlib import Path

import pytest

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from haia_agent.sentinel import Sentinel, PipelineIdentity
from haia_agent.security import AuditEncryption, HashWitness, AuditFileLock
from haia_agent.governance import (
    GovernanceRuntime,
    EscalationEngine,
    EscalationRule,
    EscalationLevel,
    EvidenceGate,
    EvidenceSubmission,
    EvidenceType,
    GovernanceDecision,
    GovernanceContext,
    OperatorProfile,
    OperatorRole,
    GovAction,
    PolicyVerdict,
)
from haia_agent.breach import BreachReport, BreachEvent, BreachSeverity, BreachCategory
from haia_agent.logger import AuditLogger


# ======================================================================
# SEC-01: Thread-safe sequence counter
# ======================================================================

class TestSEC01ThreadSafeSequence:

    def test_concurrent_sequence_no_duplicates(self):
        identity = PipelineIdentity("sec01-test")
        sentinel = Sentinel(identity)
        results = []
        barrier = threading.Barrier(10)

        def grab_sequences():
            barrier.wait()
            for _ in range(100):
                results.append(sentinel._next_sequence())

        threads = [threading.Thread(target=grab_sequences) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(results) == 1000
        assert len(set(results)) == 1000, "Duplicate sequence numbers detected"

    def test_sequence_is_monotonic(self):
        identity = PipelineIdentity("sec01-mono")
        sentinel = Sentinel(identity)
        seqs = [sentinel._next_sequence() for _ in range(50)]
        assert seqs == sorted(seqs)
        assert len(set(seqs)) == 50

    def test_sentinel_has_seq_lock(self):
        identity = PipelineIdentity("sec01-lock")
        sentinel = Sentinel(identity)
        assert hasattr(sentinel, "_seq_lock")


# ======================================================================
# SEC-02: HMAC verification on obfuscation decrypt
# ======================================================================

class TestSEC02HMACDecrypt:

    def test_tampered_ciphertext_raises(self):
        # Use a valid Fernet key, then force obfuscation path
        key = base64.urlsafe_b64encode(os.urandom(32)).decode()
        enc = AuditEncryption(key)
        enc._fernet = None  # Force obfuscation fallback

        original = json.dumps({"record_type": "REQUEST", "data": "test"})
        encrypted = enc.encrypt(original)

        # Tamper: encrypted format is OBFUSCATED:key:b64data
        assert encrypted.startswith("OBFUSCATED:")
        parts = encrypted.split(":")
        # Replace the HMAC tag (second part) with a wrong one
        tampered = f"{parts[0]}:{'0' * len(parts[1])}:{parts[2]}"

        with pytest.raises((ValueError, Exception)):
            enc.decrypt(tampered)

    def test_valid_ciphertext_decrypts(self):
        key = base64.urlsafe_b64encode(os.urandom(32)).decode()
        enc = AuditEncryption(key)
        enc._fernet = None

        original = "This is audit data for SEC-02 test"
        encrypted = enc.encrypt(original)
        decrypted = enc.decrypt(encrypted)
        assert decrypted == original


# ======================================================================
# SEC-03: signable_payload includes transaction context
# ======================================================================

class TestSEC03SignablePayload:
    """signable_payload lives on EvidenceSubmission (SEC-03 + SEC-10)."""

    def _make_submission(self):
        return EvidenceSubmission(
            evidence_type=EvidenceType.SECOND_APPROVER,
            content="I approve this action",
            submitted_by="approver-1",
        )

    def test_payload_includes_transaction_id(self):
        sub = self._make_submission()
        payload = sub.signable_payload(
            transaction_id="txn-123",
            gate_name="approval_gate",
        )
        assert "transaction_id" in payload
        assert payload["transaction_id"] == "txn-123"

    def test_payload_includes_gate_name(self):
        sub = self._make_submission()
        payload = sub.signable_payload(
            transaction_id="txn-456",
            gate_name="review_gate",
        )
        assert "gate_name" in payload
        assert payload["gate_name"] == "review_gate"

    def test_method_is_public(self):
        sub = self._make_submission()
        assert hasattr(sub, "signable_payload")
        assert callable(sub.signable_payload)


# ======================================================================
# SEC-04: BreachReport.finalize() hashes complete dict
# ======================================================================

class TestSEC04BreachFinalize:

    def test_finalize_includes_metadata(self):
        report1 = BreachReport(transaction_id="txn-a")
        report1.add_event(BreachEvent(
            category=BreachCategory.CHAIN_INTEGRITY,
            severity=BreachSeverity.WARNING,
            description="Test event",
        ))
        report1.finalize()
        hash1 = report1.report_hash

        report2 = BreachReport(transaction_id="txn-a")
        report2.add_event(BreachEvent(
            category=BreachCategory.CHAIN_INTEGRITY,
            severity=BreachSeverity.WARNING,
            description="Test event",
        ))
        # Override severity before finalize to change hash
        report2.overall_severity = BreachSeverity.CRITICAL
        report2.finalize()
        hash2 = report2.report_hash

        assert hash1 != hash2, "Hash should differ when metadata differs"

    def test_finalize_includes_transaction_id(self):
        report1 = BreachReport(transaction_id="txn-x")
        report1.finalize()

        report2 = BreachReport(transaction_id="txn-y")
        report2.finalize()

        assert report1.report_hash != report2.report_hash


# ======================================================================
# SEC-05: EscalationEngine catches rule exceptions
# ======================================================================

class TestSEC05EscalationSafety:

    def _make_operator(self):
        return OperatorProfile(
            operator_id="test-op",
            roles={OperatorRole.ANALYST},
        )

    def _make_context(self):
        return GovernanceContext(
            operator=self._make_operator(),
            action=GovAction.EXECUTE_PIPELINE,
        )

    def test_crashing_rule_triggers_lockdown(self):
        def crashing_condition(context):
            raise RuntimeError("Simulated rule crash")

        engine = EscalationEngine()
        engine.register_rule(EscalationRule(
            name="crasher",
            description="Rule that crashes",
            target_level=EscalationLevel.ELEVATED,
            condition=crashing_condition,
            required_role=OperatorRole.ANALYST,
        ))

        result = engine.evaluate(self._make_context())
        assert result.level == EscalationLevel.LOCKDOWN

    def test_valid_rule_works_normally(self):
        engine = EscalationEngine()
        engine.register_rule(EscalationRule(
            name="always_warn",
            description="Always triggers",
            target_level=EscalationLevel.ELEVATED,
            condition=lambda ctx: True,
            required_role=OperatorRole.ANALYST,
        ))
        result = engine.evaluate(self._make_context())
        assert result.level == EscalationLevel.ELEVATED


# ======================================================================
# SEC-06: Witness file HMAC authentication
# ======================================================================

class TestSEC06WitnessHMAC:

    def test_witness_writes_hmac(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            wpath = Path(tmpdir) / "witness.json"
            hw = HashWitness(wpath, witness_interval=1, witness_hmac_key="secret")
            hw.record_witness(1, "abc123", 1)

            data = json.loads(wpath.read_text())
            assert "hmac" in data
            assert len(data["hmac"]) == 64

    def test_witness_verifies_hmac_on_load(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            wpath = Path(tmpdir) / "witness.json"
            hw = HashWitness(wpath, witness_interval=1, witness_hmac_key="mykey")
            hw.record_witness(1, "hash1", 1)
            hw.record_witness(2, "hash2", 2)

            hw2 = HashWitness(wpath, witness_interval=1, witness_hmac_key="mykey")
            assert len(hw2._witnesses) == 2

    def test_witness_rejects_tampered_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            wpath = Path(tmpdir) / "witness.json"
            hw = HashWitness(wpath, witness_interval=1, witness_hmac_key="goodkey")
            hw.record_witness(1, "hash1", 1)

            data = json.loads(wpath.read_text())
            data["witnesses"][0]["chain_hash"] = "tampered_hash"
            wpath.write_text(json.dumps(data))

            with pytest.raises(ValueError, match="Witness file HMAC verification failed"):
                HashWitness(wpath, witness_interval=1, witness_hmac_key="goodkey")

    def test_witness_rejects_wrong_key(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            wpath = Path(tmpdir) / "witness.json"
            hw = HashWitness(wpath, witness_interval=1, witness_hmac_key="key1")
            hw.record_witness(1, "hash1", 1)

            with pytest.raises(ValueError, match="HMAC verification failed"):
                HashWitness(wpath, witness_interval=1, witness_hmac_key="key2")

    def test_witness_no_hmac_when_no_key(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            wpath = Path(tmpdir) / "witness.json"
            hw = HashWitness(wpath, witness_interval=1)
            hw.record_witness(1, "hash1", 1)

            data = json.loads(wpath.read_text())
            assert "hmac" not in data


# ======================================================================
# SEC-07: Public API promotion
# ======================================================================

class TestSEC07PublicAPI:

    def test_logger_get_records(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = AuditLogger(
                audit_file_path=Path(tmpdir) / "audit.json",
                operator_id="test",
            )
            assert hasattr(logger, "get_records")
            records = logger.get_records()
            assert isinstance(records, list)

    def test_logger_log_system_event_public(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = AuditLogger(
                audit_file_path=Path(tmpdir) / "audit.json",
                operator_id="test",
            )
            assert hasattr(logger, "log_system_event")
            assert callable(logger.log_system_event)

    def test_logger_backward_compat_alias(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = AuditLogger(
                audit_file_path=Path(tmpdir) / "audit.json",
                operator_id="test",
            )
            # Note: AuditLogger.__init__ may log a startup event
            before = logger.get_record_count()
            logger._log_system_event("test", "backward compat check")
            assert logger.get_record_count() == before + 1

    def test_governance_escalation_engine_property(self):
        runtime = GovernanceRuntime()
        assert hasattr(runtime, "escalation_engine")
        assert isinstance(runtime.escalation_engine, EscalationEngine)

    def test_get_records_returns_copy(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = AuditLogger(
                audit_file_path=Path(tmpdir) / "audit.json",
                operator_id="test",
            )
            logger.log_system_event("test", "event1")
            count_before = logger.get_record_count()
            records = logger.get_records()
            records.clear()  # Mutate the copy
            assert logger.get_record_count() == count_before  # Internal unaffected


# ======================================================================
# SEC-08: deque replaces list.pop(0)
# ======================================================================

class TestSEC08DequeDecisionLog:

    def test_decision_log_is_deque(self):
        runtime = GovernanceRuntime(max_decision_log=5)
        assert isinstance(runtime._decision_log, collections.deque)

    def test_deque_has_maxlen(self):
        runtime = GovernanceRuntime(max_decision_log=42)
        assert runtime._decision_log.maxlen == 42

    def test_deque_eviction_tracked(self):
        runtime = GovernanceRuntime(max_decision_log=3)
        for i in range(5):
            decision = GovernanceDecision(
                action=GovAction.EXECUTE_PIPELINE,
                operator_id="test",
                authorized=True,
                policy_verdict=PolicyVerdict.ALLOW,
                escalation_level=EscalationLevel.NORMAL,
                evidence_gate_passed=True,
                reason=f"test-{i}",
            )
            runtime._log_decision(decision)

        assert len(runtime._decision_log) == 3
        assert runtime._decisions_evicted == 2


# ======================================================================
# SEC-09: Post-read chain verification in read_lock
# ======================================================================

class TestSEC09PostReadVerify:

    def test_read_lock_with_passing_callback(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            lock = AuditFileLock(Path(tmpdir) / "test.lock")
            with lock.read_lock(verify_after_read=lambda: (True, "")):
                pass

    def test_read_lock_with_failing_callback(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            lock = AuditFileLock(Path(tmpdir) / "test.lock")
            with pytest.raises(ValueError, match="Post-read chain integrity check failed"):
                with lock.read_lock(
                    verify_after_read=lambda: (False, "chain broken at seq 5")
                ):
                    pass

    def test_read_lock_without_callback(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            lock = AuditFileLock(Path(tmpdir) / "test.lock")
            with lock.read_lock():
                pass


# ======================================================================
# SEC-10: signable_payload promoted to public
# ======================================================================

class TestSEC10PublicSignable:

    def test_signable_payload_is_public(self):
        sub = EvidenceSubmission(
            evidence_type=EvidenceType.SECOND_APPROVER,
            content="Approved",
            submitted_by="op-1",
        )
        assert hasattr(sub, "signable_payload")
        payload = sub.signable_payload(transaction_id="t", gate_name="g")
        assert isinstance(payload, dict)


# ======================================================================
# SEC-11: Callback error counter in Sentinel
# ======================================================================

class TestSEC11CallbackErrors:

    def test_callback_errors_starts_at_zero(self):
        sentinel = Sentinel(PipelineIdentity("sec11"))
        assert sentinel.callback_errors == 0

    def test_oob_callback_error_counted(self):
        sentinel = Sentinel(PipelineIdentity("sec11-oob"))

        def failing_oob(alert):
            raise RuntimeError("OOB crash")

        sentinel._oob_callbacks.append(failing_oob)

        report = BreachReport(transaction_id="txn-oob")
        report.add_event(BreachEvent(
            category=BreachCategory.CHAIN_INTEGRITY,
            severity=BreachSeverity.CRITICAL,
            description="Test critical event",
        ))
        report.finalize()

        dispatched = sentinel.dispatch_oob_alert(report)
        assert dispatched == 0
        assert sentinel.callback_errors == 1

    def test_callback_errors_property_accessible(self):
        sentinel = Sentinel(PipelineIdentity("sec11-prop"))
        assert isinstance(sentinel.callback_errors, int)

    def test_multiple_oob_errors_accumulate(self):
        sentinel = Sentinel(PipelineIdentity("sec11-multi"))

        sentinel._oob_callbacks.append(lambda a: (_ for _ in ()).throw(RuntimeError))
        sentinel._oob_callbacks.append(lambda a: (_ for _ in ()).throw(RuntimeError))

        for i in range(3):
            report = BreachReport(transaction_id=f"txn-{i}")
            report.add_event(BreachEvent(
                category=BreachCategory.CHAIN_INTEGRITY,
                severity=BreachSeverity.CRITICAL,
                description="Test",
            ))
            report.finalize()
            sentinel.dispatch_oob_alert(report)

        # 2 callbacks x 3 dispatches = 6 errors
        assert sentinel.callback_errors == 6


# ======================================================================
# Integration: Combined scenarios
# ======================================================================

class TestSecurityIntegration:

    def test_witness_hmac_plus_read_lock(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            wpath = Path(tmpdir) / "witness.json"
            lpath = Path(tmpdir) / "audit.lock"

            hw = HashWitness(wpath, witness_interval=1, witness_hmac_key="integ-key")
            lock = AuditFileLock(lpath)

            with lock.write_lock():
                hw.record_witness(1, "chain_hash_1", 1)
                hw.record_witness(2, "chain_hash_2", 2)

            def verify_witness():
                hw2 = HashWitness(wpath, witness_interval=1, witness_hmac_key="integ-key")
                return (len(hw2._witnesses) == 2, "Expected 2 witnesses")

            with lock.read_lock(verify_after_read=verify_witness):
                pass

    def test_escalation_lockdown_plus_breach_hash(self):
        engine = EscalationEngine()
        engine.register_rule(EscalationRule(
            name="poison",
            description="Deliberately crashing rule",
            target_level=EscalationLevel.ELEVATED,
            condition=lambda ctx: 1 / 0,
            required_role=OperatorRole.ANALYST,
        ))

        ctx = GovernanceContext(
            operator=OperatorProfile(
                operator_id="test",
                roles={OperatorRole.ANALYST},
            ),
            action=GovAction.EXECUTE_PIPELINE,
        )
        result = engine.evaluate(ctx)
        assert result.level == EscalationLevel.LOCKDOWN

        report = BreachReport(transaction_id="poison-test")
        report.add_event(BreachEvent(
            category=BreachCategory.CONFIG_VIOLATION,
            severity=BreachSeverity.CRITICAL,
            description="Escalation rule crashed, forced LOCKDOWN",
        ))
        report.finalize()
        assert report.report_hash  # SEC-04: hash covers all fields
