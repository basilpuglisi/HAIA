"""
HAIA Agent Framework - Sentinel Tests
========================================
Tests for pipeline identity verification, anti-impersonation,
heartbeat monitoring, challenge-response authentication,
and out-of-band alert dispatch.

Attack scenarios tested:
    IMP1: Rogue agent sends unsigned alert (rejected)
    IMP2: Rogue agent sends alert with wrong key (rejected)
    IMP3: Rogue agent replays a captured heartbeat (detected)
    IMP4: Rogue agent sends heartbeat with wrong fingerprint (detected)
    IMP5: Pipeline goes silent (dead-man's switch fires)
    IMP6: Human challenges the pipeline (authentic response)
    IMP7: Rogue answers challenge without key (fails verification)

System tests:
    SEN1: Pipeline identity creation and signing
    SEN2: Signed alert envelope integrity
    SEN3: Heartbeat emission and monitoring
    SEN4: Challenge-response roundtrip
    SEN5: Out-of-band alert dispatch
    SEN6: Full pipeline integration with sentinel
    SEN7: Sequence number monotonicity

Author: Basil C. Puglisi, MPA
"""

import sys
import tempfile
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from haia_agent import (
    AuditLogger,
    BreachEvent,
    BreachReport,
    BreachSeverity,
    BreachCategory,
    HeartbeatMonitor,
    MockAdapter,
    NavigatorValidator,
    OperatingModel,
    OperatorIdentity,
    OperatorRegistry,
    PipelineCircuitBreaker,
    PipelineIdentity,
    PlatformSelector,
    RECCLINRole,
    SecureGOPELPipeline,
    Sentinel,
    SignedAlert,
)
from haia_agent.navigator import NavigatorRouter
from haia_agent.adapters import AdapterResponse


# ======================================================================
# HELPERS
# ======================================================================

def make_sentinel_pipeline(tmp_dir):
    """Build pipeline with sentinel enabled."""
    registry = OperatorRegistry()
    registry.register_operator(OperatorIdentity("test_human"))
    registry.register_operator(OperatorIdentity("haia_agent"))

    logger = AuditLogger(Path(tmp_dir) / "audit.json", operator_id="haia_agent")
    selector = PlatformSelector()
    for name in ["alpha", "bravo", "charlie"]:
        selector.register_adapter(MockAdapter(platform_id=name))
    selector.set_anchor("alpha")

    nav = NavigatorRouter(MockAdapter(platform_id="nav"))
    identity = PipelineIdentity("gopel-test-instance")
    sentinel = Sentinel(identity)

    pipeline = SecureGOPELPipeline(
        logger=logger,
        selector=selector,
        navigator=nav,
        operator_registry=registry,
        sentinel=sentinel,
    )
    return pipeline, sentinel, identity


# ======================================================================
# SEN1: PIPELINE IDENTITY
# ======================================================================

def test_sen1_identity_creation():
    """SEN1: Pipeline identity generates unique key and fingerprint."""
    print("TEST SEN1: Pipeline identity creation...", end=" ")
    id1 = PipelineIdentity("instance-a")
    id2 = PipelineIdentity("instance-b")
    assert id1.fingerprint != id2.fingerprint, "Different instances should have different fingerprints"
    assert len(id1.signing_key_hex) == 64, "32-byte key = 64 hex chars"
    assert len(id1.fingerprint) == 16, "Fingerprint is first 16 chars of SHA-256"
    print("PASSED")


def test_sen1_deterministic_key():
    """SEN1: Providing a key produces deterministic identity."""
    print("TEST SEN1b: Deterministic key...", end=" ")
    key = "a" * 64  # 32 bytes in hex
    id1 = PipelineIdentity("inst", signing_key=key)
    id2 = PipelineIdentity("inst", signing_key=key)
    assert id1.fingerprint == id2.fingerprint
    assert id1.sign("test") == id2.sign("test")
    print("PASSED")


# ======================================================================
# SEN2: SIGNED ALERT ENVELOPE
# ======================================================================

def test_sen2_sign_and_verify():
    """SEN2: Signed alert verifies correctly."""
    print("TEST SEN2: Sign and verify alert...", end=" ")
    identity = PipelineIdentity("test")
    sentinel = Sentinel(identity)
    report = BreachReport(transaction_id="txn-1")
    alert = sentinel.sign_breach_report(report)
    assert alert.signature != "", "Alert must be signed"
    assert alert.pipeline_fingerprint == identity.fingerprint
    assert sentinel.verify_alert(alert), "Valid alert should verify"
    print("PASSED")


def test_sen2_tampered_alert_fails():
    """SEN2: Modifying alert content after signing fails verification."""
    print("TEST SEN2b: Tampered alert fails verification...", end=" ")
    identity = PipelineIdentity("test")
    sentinel = Sentinel(identity)
    report = BreachReport(transaction_id="txn-2")
    report.add_event(BreachEvent(
        category=BreachCategory.INJECTION_DETECTED,
        severity=BreachSeverity.CRITICAL,
        description="Real critical breach",
    ))
    report.finalize()
    alert = sentinel.sign_breach_report(report)

    # Tamper: attacker downgrades severity to hide the breach
    alert.payload["overall_severity"] = "NOMINAL"
    alert.payload["pipeline_halted"] = False
    alert.payload["event_count"] = 0
    assert not sentinel.verify_alert(alert), "Tampered alert must fail verification"
    print("PASSED")


def test_sen2_dict_roundtrip():
    """SEN2: Alert survives dict serialization and re-verification."""
    print("TEST SEN2c: Dict serialization roundtrip...", end=" ")
    identity = PipelineIdentity("test")
    sentinel = Sentinel(identity)
    alert = sentinel.sign_custom("test_type", {"data": "value"})
    alert_dict = alert.to_dict()
    assert sentinel.verify_alert_dict(alert_dict)
    # Tamper
    alert_dict["payload"]["data"] = "modified"
    assert not sentinel.verify_alert_dict(alert_dict)
    print("PASSED")


# ======================================================================
# IMP1: ROGUE SENDS UNSIGNED ALERT
# ======================================================================

def test_imp1_unsigned_alert_rejected():
    """IMP1: Alert with empty signature is rejected."""
    print("TEST IMP1: Unsigned alert rejected...", end=" ")
    identity = PipelineIdentity("real-gopel")
    sentinel = Sentinel(identity)
    fake_alert = SignedAlert(
        pipeline_instance="real-gopel",
        pipeline_fingerprint=identity.fingerprint,
        alert_type="breach_report",
        payload={"overall_severity": "NOMINAL"},
        signature="",  # No signature
    )
    assert not sentinel.verify_alert(fake_alert)
    print("PASSED")


# ======================================================================
# IMP2: ROGUE SENDS ALERT WITH WRONG KEY
# ======================================================================

def test_imp2_wrong_key_rejected():
    """IMP2: Alert signed with a different key is rejected."""
    print("TEST IMP2: Wrong key rejected...", end=" ")
    real_identity = PipelineIdentity("real-gopel")
    real_sentinel = Sentinel(real_identity)

    # Rogue creates its own identity and signs with its key
    rogue_identity = PipelineIdentity("real-gopel")  # Same name, different key
    rogue_sentinel = Sentinel(rogue_identity)
    rogue_report = BreachReport(transaction_id="fake")
    rogue_alert = rogue_sentinel.sign_breach_report(rogue_report)

    # Real sentinel rejects the rogue's signature
    assert not real_sentinel.verify_alert(rogue_alert), (
        "Alert signed with wrong key must be rejected"
    )
    print("PASSED")


# ======================================================================
# IMP3: ROGUE REPLAYS CAPTURED HEARTBEAT
# ======================================================================

def test_imp3_replayed_heartbeat_detected():
    """IMP3: Replaying a captured heartbeat is detected by sequence check."""
    print("TEST IMP3: Replayed heartbeat detected...", end=" ")
    identity = PipelineIdentity("gopel-prod")
    sentinel = Sentinel(identity)

    alarms = []
    monitor = HeartbeatMonitor(
        expected_fingerprint=identity.fingerprint,
        max_silence_seconds=120,
        alarm_callback=lambda msg: alarms.append(msg),
    )

    # Legitimate heartbeats
    hb1 = sentinel.emit_single_heartbeat()
    hb2 = sentinel.emit_single_heartbeat()
    monitor.receive_heartbeat(hb1)
    monitor.receive_heartbeat(hb2)

    # Replay hb1 (sequence number is now stale)
    status = monitor.receive_heartbeat(hb1)
    assert not status["sequence_advancing"], "Replayed heartbeat should not advance"
    assert len(alarms) > 0
    assert "REPLAY" in alarms[-1]
    print("PASSED")


# ======================================================================
# IMP4: ROGUE HEARTBEAT WITH WRONG FINGERPRINT
# ======================================================================

def test_imp4_wrong_fingerprint_detected():
    """IMP4: Heartbeat from impersonator has wrong fingerprint."""
    print("TEST IMP4: Wrong fingerprint detected...", end=" ")
    real_identity = PipelineIdentity("gopel-prod")
    rogue_identity = PipelineIdentity("gopel-prod")
    rogue_sentinel = Sentinel(rogue_identity)

    alarms = []
    monitor = HeartbeatMonitor(
        expected_fingerprint=real_identity.fingerprint,
        max_silence_seconds=120,
        alarm_callback=lambda msg: alarms.append(msg),
    )

    # Rogue sends heartbeat
    rogue_hb = rogue_sentinel.emit_single_heartbeat()
    status = monitor.receive_heartbeat(rogue_hb)
    assert not status["fingerprint_match"]
    assert len(alarms) > 0
    assert "IMPERSONATION" in alarms[-1]
    print("PASSED")


# ======================================================================
# IMP5: PIPELINE GOES SILENT (DEAD MAN'S SWITCH)
# ======================================================================

def test_imp5_silence_detected():
    """IMP5: Pipeline silence triggers alarm after threshold."""
    print("TEST IMP5: Silence detection...", end=" ")
    identity = PipelineIdentity("gopel-prod")
    sentinel = Sentinel(identity)

    alarms = []
    monitor = HeartbeatMonitor(
        expected_fingerprint=identity.fingerprint,
        max_silence_seconds=1,  # 1 second for testing
        alarm_callback=lambda msg: alarms.append(msg),
    )

    # Receive one heartbeat
    hb = sentinel.emit_single_heartbeat()
    monitor.receive_heartbeat(hb)

    # Wait for silence threshold
    time.sleep(1.5)

    # Check silence
    status = monitor.check_silence()
    assert status["alarm"] == "silence_detected"
    assert len(alarms) > 0
    assert "SILENCE" in alarms[-1]
    assert "DO NOT TRUST" in alarms[-1]
    print("PASSED")


# ======================================================================
# SEN3: HEARTBEAT EMISSION
# ======================================================================

def test_sen3_heartbeat_emits():
    """SEN3: Heartbeat thread emits signed heartbeats to callbacks."""
    print("TEST SEN3: Heartbeat emission...", end=" ")
    identity = PipelineIdentity("gopel-hb-test")
    sentinel = Sentinel(identity)
    received = []
    sentinel.register_heartbeat_callback(lambda alert: received.append(alert))
    sentinel.start_heartbeat(interval_seconds=1)
    time.sleep(2.5)
    sentinel.stop_heartbeat()
    assert len(received) >= 2, f"Should have received 2+ heartbeats, got {len(received)}"
    # All heartbeats should verify
    for hb in received:
        assert sentinel.verify_alert(hb), "Heartbeat must be verifiable"
    print(f"PASSED ({len(received)} heartbeats received)")


# ======================================================================
# SEN4 / IMP6: CHALLENGE-RESPONSE
# ======================================================================

def test_sen4_challenge_response():
    """SEN4/IMP6: Human challenges pipeline, gets authenticated response."""
    print("TEST SEN4: Challenge-response authentication...", end=" ")
    identity = PipelineIdentity("gopel-challenge")
    sentinel = Sentinel(identity)

    nonce = "random-nonce-2026-02-22-test-abc123"
    response = sentinel.answer_challenge(nonce)
    assert sentinel.verify_challenge_response(nonce, response)
    assert response.payload["nonce"] == nonce
    print("PASSED")


# ======================================================================
# IMP7: ROGUE ANSWERS CHALLENGE WITHOUT KEY
# ======================================================================

def test_imp7_rogue_challenge_fails():
    """IMP7: Rogue cannot answer challenge without the real key."""
    print("TEST IMP7: Rogue challenge response fails...", end=" ")
    real_identity = PipelineIdentity("gopel-real")
    real_sentinel = Sentinel(real_identity)

    rogue_identity = PipelineIdentity("gopel-real")
    rogue_sentinel = Sentinel(rogue_identity)

    nonce = "human-challenge-nonce-xyz"
    # Rogue answers the challenge with its own key
    rogue_response = rogue_sentinel.answer_challenge(nonce)
    # Real sentinel rejects the rogue's response
    assert not real_sentinel.verify_challenge_response(nonce, rogue_response), (
        "Rogue's challenge response must fail verification"
    )
    print("PASSED")


def test_imp7_wrong_nonce_fails():
    """IMP7: Response to a different nonce fails verification."""
    print("TEST IMP7b: Wrong nonce fails...", end=" ")
    identity = PipelineIdentity("gopel")
    sentinel = Sentinel(identity)
    response = sentinel.answer_challenge("nonce-A")
    # Verify against different nonce
    assert not sentinel.verify_challenge_response("nonce-B", response)
    print("PASSED")


# ======================================================================
# SEN5: OUT-OF-BAND ALERT DISPATCH
# ======================================================================

def test_sen5_oob_dispatches():
    """SEN5: Critical breach triggers OOB alert dispatch."""
    print("TEST SEN5: Out-of-band alert dispatch...", end=" ")
    identity = PipelineIdentity("gopel-oob")
    sentinel = Sentinel(identity)

    oob_received = []
    sentinel.register_oob_callback(lambda alert: oob_received.append(alert))

    # NOMINAL: should NOT dispatch OOB
    nominal = BreachReport(transaction_id="nominal")
    sentinel.dispatch_oob_alert(nominal)
    assert len(oob_received) == 0, "NOMINAL should not trigger OOB"

    # CRITICAL: should dispatch OOB
    critical = BreachReport(transaction_id="critical")
    critical.add_event(BreachEvent(
        category=BreachCategory.INJECTION_DETECTED,
        severity=BreachSeverity.CRITICAL,
        description="Test critical event",
    ))
    count = sentinel.dispatch_oob_alert(critical)
    assert count == 1
    assert len(oob_received) == 1
    # OOB alert should be signed
    assert sentinel.verify_alert(oob_received[0])
    print("PASSED")


def test_sen5_oob_file_channel():
    """SEN5: File-based OOB channel writes signed alerts."""
    print("TEST SEN5b: File-based OOB channel...", end=" ")
    with tempfile.TemporaryDirectory() as tmp:
        alert_path = Path(tmp) / "oob_alerts.jsonl"
        identity = PipelineIdentity("gopel-file-oob")
        sentinel = Sentinel(identity)
        sentinel.register_oob_callback(Sentinel.file_oob_factory(alert_path))

        warning = BreachReport(transaction_id="file-test")
        warning.add_event(BreachEvent(
            category=BreachCategory.TRANSPORT_INTEGRITY,
            severity=BreachSeverity.WARNING,
            description="Test warning for file OOB",
        ))
        sentinel.dispatch_oob_alert(warning)

        assert alert_path.exists()
        content = alert_path.read_text()
        assert "file-test" in content
    print("PASSED")


# ======================================================================
# SEN6: FULL PIPELINE INTEGRATION
# ======================================================================

def test_sen6_pipeline_with_sentinel():
    """SEN6: Pipeline execution produces signed alerts."""
    print("TEST SEN6: Full pipeline with sentinel...", end=" ")
    with tempfile.TemporaryDirectory() as tmp:
        pipeline, sentinel, identity = make_sentinel_pipeline(tmp)
        result = pipeline.execute(
            prompt="Test sentinel integration",
            recclin_role=RECCLINRole.RESEARCHER,
            operating_model=OperatingModel.MODEL_2,
            human_operator_id="test_human",
        )
        assert result.signed_alert is not None, "Pipeline should produce signed alert"
        assert result.signed_alert.pipeline_fingerprint == identity.fingerprint
        assert sentinel.verify_alert(result.signed_alert), "Signed alert must verify"
    print("PASSED")


def test_sen6_pipeline_without_sentinel():
    """SEN6: Pipeline works without sentinel (backward compatible)."""
    print("TEST SEN6b: Pipeline without sentinel (backward compat)...", end=" ")
    with tempfile.TemporaryDirectory() as tmp:
        registry = OperatorRegistry()
        registry.register_operator(OperatorIdentity("test_human"))
        registry.register_operator(OperatorIdentity("haia_agent"))
        logger = AuditLogger(Path(tmp) / "audit.json", operator_id="haia_agent")
        selector = PlatformSelector()
        for n in ["a", "b", "c"]:
            selector.register_adapter(MockAdapter(platform_id=n))
        selector.set_anchor("a")
        nav = NavigatorRouter(MockAdapter(platform_id="nav"))
        pipeline = SecureGOPELPipeline(
            logger=logger, selector=selector, navigator=nav,
            operator_registry=registry,
            sentinel=None,  # No sentinel
        )
        result = pipeline.execute(
            prompt="Test",
            recclin_role=RECCLINRole.RESEARCHER,
            operating_model=OperatingModel.MODEL_2,
            human_operator_id="test_human",
        )
        assert result.success
        assert result.signed_alert is None, "No sentinel means no signed alert"
    print("PASSED")


# ======================================================================
# SEN7: SEQUENCE NUMBER MONOTONICITY
# ======================================================================

def test_sen7_sequence_monotonic():
    """SEN7: Alert sequence numbers are strictly monotonic."""
    print("TEST SEN7: Sequence number monotonicity...", end=" ")
    identity = PipelineIdentity("gopel-seq")
    sentinel = Sentinel(identity)
    alerts = []
    for i in range(10):
        alerts.append(sentinel.sign_custom("test", {"index": i}))
    sequences = [a.sequence_number for a in alerts]
    for i in range(1, len(sequences)):
        assert sequences[i] > sequences[i - 1], (
            f"Sequence must be strictly increasing: {sequences}"
        )
    print("PASSED")


# ======================================================================
# RUN ALL TESTS
# ======================================================================

def run_all_tests():
    print("=" * 70)
    print("HAIA AGENT FRAMEWORK - SENTINEL TESTS")
    print("Pipeline identity verification and anti-impersonation")
    print("=" * 70)
    print()

    tests = [
        # Pipeline Identity
        test_sen1_identity_creation,
        test_sen1_deterministic_key,
        # Signed Alert Envelope
        test_sen2_sign_and_verify,
        test_sen2_tampered_alert_fails,
        test_sen2_dict_roundtrip,
        # Impersonation Attacks
        test_imp1_unsigned_alert_rejected,
        test_imp2_wrong_key_rejected,
        test_imp3_replayed_heartbeat_detected,
        test_imp4_wrong_fingerprint_detected,
        test_imp5_silence_detected,
        # Challenge-Response
        test_sen4_challenge_response,
        test_imp7_rogue_challenge_fails,
        test_imp7_wrong_nonce_fails,
        # Out-of-Band
        test_sen5_oob_dispatches,
        test_sen5_oob_file_channel,
        # Pipeline Integration
        test_sen6_pipeline_with_sentinel,
        test_sen6_pipeline_without_sentinel,
        # Sequence Monotonicity
        test_sen7_sequence_monotonic,
    ]

    passed = 0
    failed = 0
    for test_fn in tests:
        try:
            test_fn()
            passed += 1
        except AssertionError as e:
            print(f"FAILED: {e}")
            failed += 1
        except Exception as e:
            print(f"ERROR: {type(e).__name__}: {e}")
            import traceback
            traceback.print_exc()
            failed += 1

    print()
    print("=" * 70)
    print(f"Results: {passed} passed, {failed} failed, {passed + failed} total")
    print()
    print("IMPERSONATION ATTACK COVERAGE:")
    print("  IMP1  Unsigned alert:                    1 test  (REJECTED)")
    print("  IMP2  Wrong-key alert:                   1 test  (REJECTED)")
    print("  IMP3  Replayed heartbeat:                1 test  (DETECTED)")
    print("  IMP4  Wrong fingerprint:                 1 test  (DETECTED)")
    print("  IMP5  Pipeline silence:                  1 test  (ALARM FIRES)")
    print("  IMP6  Authentic challenge-response:      1 test  (VERIFIED)")
    print("  IMP7  Rogue challenge-response:          2 tests (REJECTED)")
    print()
    print("SENTINEL SYSTEM COVERAGE:")
    print("  SEN1  Pipeline identity:                 2 tests")
    print("  SEN2  Signed alert envelope:             3 tests")
    print("  SEN3  Heartbeat emission:                1 test")
    print("  SEN4  Challenge-response:                1 test")
    print("  SEN5  Out-of-band alerts:                2 tests")
    print("  SEN6  Pipeline integration:              2 tests")
    print("  SEN7  Sequence monotonicity:             1 test")
    print("=" * 70)
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
