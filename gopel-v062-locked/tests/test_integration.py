"""
HAIA Agent Framework - Integration Tests
==========================================
Proves the governance runtime is wired into the production pipeline.

These tests exercise the FULL execution path: governance authorization
at pipeline entry, evidence gates at arbitration, escalation feedback
from breach detection, and identity system coordination.

Prior to v0.5.1, the governance runtime (governance.py) and the
production pipeline (secure_pipeline.py) were developed and tested
independently. The 41 governance tests proved the five layers work.
The 10 pipeline tests proved dispatch/collect/log work. Neither proved
they work TOGETHER.

This test suite closes that gap.

Author: Basil C. Puglisi, MPA
"""

import sys
from pathlib import Path

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from haia_agent.adapters.mock_adapter import MockAdapter
from haia_agent.breach import BreachDetector, PipelineCircuitBreaker
from haia_agent.governance import (
    ARBITRATION_GATE,
    EscalationEngine,
    EvidenceSubmission,
    EvidenceType,
    GovAction,
    GovernanceRuntime,
    OperatorProfile,
    OperatorRole,
    PolicyEngine,
    PolicyVerdict,
    POLICY_BREACH_BLOCKS_EXECUTION,
    POLICY_WARNING_REQUIRES_GOV_OFFICER,
    POLICY_MODEL2_REQUIRES_EVIDENCE,
    POLICY_OVERRIDE_REQUIRES_DUAL_APPROVAL,
    POLICY_INJECTION_THRESHOLD_ESCALATES,
    RULE_BREACH_WARNING_ELEVATES,
    RULE_BREACH_CRITICAL_HIGH,
    RULE_BREACH_HALT_LOCKDOWN,
    RULE_INJECTION_FLOOD_CRITICAL,
    RULE_PLATFORM_FAILURE_ELEVATED,
)
from haia_agent.logger import AuditLogger
from haia_agent.models import OperatingModel, RECCLINRole, ArbitrationDecision
from haia_agent.navigator import NavigatorRouter
from haia_agent.secure_pipeline import (
    SecureGOPELPipeline,
    SecureArbitrationInput,
)
from haia_agent.security import OperatorIdentity, OperatorRegistry
from haia_agent.selector import PlatformSelector


# ======================================================================
# HELPERS
# ======================================================================

# Navigator mock response that satisfies structural validation.
# Without this, the breach detector triggers WARNING on every execution
# because mock responses lack required sections, which escalates to
# ELEVATED and blocks analyst operations. This is correct governance
# behavior but makes testing impossible without governance-compliant mocks.
NAVIGATOR_MOCK_RESPONSE = (
    "CONVERGENCE:\n"
    "All sources agree that the research question warrants further investigation.\n"
    "The fundamental findings are consistent across independent analyses.\n\n"
    "DIVERGENCE:\n"
    "Source A emphasizes quantitative metrics while Source B focuses on qualitative assessment.\n"
    "Source C provides a hybrid perspective combining both approaches.\n\n"
    "DISSENT:\n"
    "Source B notes that the quantitative approach may undercount edge cases.\n"
    "This minority position is preserved without resolution.\n\n"
    "SOURCES:\n"
    "Source A: Internal analysis based on available data.\n"
    "Source B: Independent assessment using alternative methodology.\n"
    "Source C: Cross-validated synthesis of both approaches.\n"
    "All claims verified against source material. No [PROVISIONAL] flags.\n\n"
    "CONFLICTS:\n"
    "No direct contradictions identified between sources.\n"
    "Methodological disagreements documented in DIVERGENCE section.\n\n"
    "CONFIDENCE: 72%\n"
    "Based on agreement across three independent sources with one methodological disagreement.\n\n"
    "RECOMMENDATION:\n"
    "Proceed with the research direction. Address Source B's edge case concern\n"
    "in the next iteration of analysis.\n\n"
    "EXPIRY:\n"
    "Valid until new data becomes available. Recommend re-evaluation quarterly.\n"
)


def make_governance_runtime() -> GovernanceRuntime:
    """Build a fully configured governance runtime."""
    policy_engine = PolicyEngine()
    policy_engine.register_policy(POLICY_BREACH_BLOCKS_EXECUTION)
    policy_engine.register_policy(POLICY_WARNING_REQUIRES_GOV_OFFICER)
    policy_engine.register_policy(POLICY_MODEL2_REQUIRES_EVIDENCE)
    policy_engine.register_policy(POLICY_OVERRIDE_REQUIRES_DUAL_APPROVAL)
    policy_engine.register_policy(POLICY_INJECTION_THRESHOLD_ESCALATES)

    esc_engine = EscalationEngine()
    esc_engine.register_rule(RULE_BREACH_WARNING_ELEVATES)
    esc_engine.register_rule(RULE_BREACH_CRITICAL_HIGH)
    esc_engine.register_rule(RULE_BREACH_HALT_LOCKDOWN)
    esc_engine.register_rule(RULE_INJECTION_FLOOD_CRITICAL)
    esc_engine.register_rule(RULE_PLATFORM_FAILURE_ELEVATED)

    runtime = GovernanceRuntime(
        policy_engine=policy_engine,
        escalation_engine=esc_engine,
    )

    # Register operators
    runtime.bootstrap_register(OperatorProfile(
        operator_id="analyst_jane",
        roles={OperatorRole.ANALYST},
        department="research",
        clearance_level=1,
    ))
    runtime.bootstrap_register(OperatorProfile(
        operator_id="gov_officer_mark",
        roles={OperatorRole.GOVERNANCE_OFFICER},
        department="governance",
        clearance_level=2,
    ))
    runtime.bootstrap_register(OperatorProfile(
        operator_id="admin_sarah",
        roles={OperatorRole.ADMINISTRATOR},
        department="operations",
        clearance_level=3,
    ))
    runtime.bootstrap_register(OperatorProfile(
        operator_id="observer_tom",
        roles={OperatorRole.OBSERVER},
        department="external",
        clearance_level=0,
    ))

    # Register evidence gate for arbitration
    runtime.register_evidence_gate(
        GovAction.RECORD_ARBITRATION.value,
        ARBITRATION_GATE,
    )

    return runtime


def make_pipeline(
    governance_runtime=None,
    operator_registry=None,
    tmpdir="/tmp/haia_integration_test",
    require_authentication=True,
):
    """Build a configured pipeline with mock adapters."""
    Path(tmpdir).mkdir(parents=True, exist_ok=True)
    audit_path = Path(tmpdir) / "audit.json"
    if audit_path.exists():
        audit_path.unlink()

    logger = AuditLogger(
        audit_file_path=str(audit_path),
        operator_id="pipeline_agent",
    )
    mock_a = MockAdapter("mock_alpha", "alpha-model")
    mock_b = MockAdapter("mock_beta", "beta-model")
    mock_c = MockAdapter("mock_gamma", "gamma-model")
    mock_nav = MockAdapter("mock_navigator", "nav-model", responses=[NAVIGATOR_MOCK_RESPONSE])

    selector = PlatformSelector(min_rotation=2)
    selector.register_adapter(mock_a)
    selector.register_adapter(mock_b)
    selector.register_adapter(mock_c)
    selector.set_anchor("mock_alpha")

    navigator = NavigatorRouter(navigator_adapter=mock_nav)

    return SecureGOPELPipeline(
        logger=logger,
        selector=selector,
        navigator=navigator,
        operator_registry=operator_registry,
        governance_runtime=governance_runtime,
        require_authentication=require_authentication,
    )


# ======================================================================
# INTEGRATION TESTS
# ======================================================================

def test_int1_governance_authorizes_execution():
    """INT1: Analyst authorized for pipeline execution through governance."""
    print("TEST INT1: Governance authorizes execution...", end=" ")
    runtime = make_governance_runtime()
    pipeline = make_pipeline(governance_runtime=runtime, tmpdir="/tmp/int1")

    result = pipeline.execute(
        prompt="What are the key risks in AI governance?",
        recclin_role=RECCLINRole.RESEARCHER,
        operating_model=OperatingModel.MODEL_1,
        human_operator_id="analyst_jane",
    )

    assert result.success, f"Should succeed: {result.error}"
    assert result.governance_decision is not None
    assert result.governance_decision.authorized
    assert result.checkpoint_package is not None
    print("PASSED")


def test_int2_governance_blocks_unregistered():
    """INT2: Unregistered operator blocked by governance at pipeline entry."""
    print("TEST INT2: Governance blocks unregistered...", end=" ")
    runtime = make_governance_runtime()
    pipeline = make_pipeline(governance_runtime=runtime, tmpdir="/tmp/int2")

    result = pipeline.execute(
        prompt="Test prompt",
        recclin_role=RECCLINRole.RESEARCHER,
        operating_model=OperatingModel.MODEL_1,
        human_operator_id="unknown_intruder",
    )

    assert not result.success
    assert "not registered" in result.error.lower()
    assert result.governance_decision is not None
    assert not result.governance_decision.authorized
    print("PASSED")


def test_int3_governance_blocks_wrong_role():
    """INT3: Observer cannot execute pipeline (wrong role)."""
    print("TEST INT3: Governance blocks wrong role...", end=" ")
    runtime = make_governance_runtime()
    pipeline = make_pipeline(governance_runtime=runtime, tmpdir="/tmp/int3")

    result = pipeline.execute(
        prompt="Test prompt",
        recclin_role=RECCLINRole.RESEARCHER,
        operating_model=OperatingModel.MODEL_1,
        human_operator_id="observer_tom",
    )

    assert not result.success
    assert result.governance_decision is not None
    assert not result.governance_decision.authorized
    assert "lacks required role" in result.governance_decision.reason.lower() or \
           "lacks required role" in result.error.lower()
    print("PASSED")


def test_int4_model2_requires_scope():
    """INT4: Model 2 execution denied without scope statement."""
    print("TEST INT4: Model 2 requires scope...", end=" ")
    runtime = make_governance_runtime()
    pipeline = make_pipeline(governance_runtime=runtime, tmpdir="/tmp/int4")

    # Execute WITHOUT task_scope -> should be denied by policy
    result = pipeline.execute(
        prompt="Analyze quarterly earnings",
        recclin_role=RECCLINRole.RESEARCHER,
        operating_model=OperatingModel.MODEL_2,
        human_operator_id="analyst_jane",
        task_scope="",  # Empty: no scope statement
    )

    assert not result.success, f"Should fail without scope: {result.error}"
    assert result.governance_decision is not None
    assert result.governance_decision.policy_verdict == PolicyVerdict.DENY
    print("PASSED")


def test_int5_model2_with_scope_succeeds():
    """INT5: Model 2 execution succeeds with scope statement."""
    print("TEST INT5: Model 2 with scope succeeds...", end=" ")
    runtime = make_governance_runtime()
    pipeline = make_pipeline(governance_runtime=runtime, tmpdir="/tmp/int5")

    result = pipeline.execute(
        prompt="Analyze quarterly earnings",
        recclin_role=RECCLINRole.RESEARCHER,
        operating_model=OperatingModel.MODEL_2,
        human_operator_id="analyst_jane",
        task_scope="Q4 2025 earnings analysis for internal review",
    )

    assert result.success, f"Should succeed with scope: {result.error}"
    assert result.governance_decision.authorized
    print("PASSED")


def test_int6_arbitration_requires_rationale():
    """INT6: Arbitration denied without sufficient rationale."""
    print("TEST INT6: Arbitration requires rationale...", end=" ")
    runtime = make_governance_runtime()
    pipeline = make_pipeline(governance_runtime=runtime, tmpdir="/tmp/int6")

    # First execute to get a transaction
    result = pipeline.execute(
        prompt="Research question",
        recclin_role=RECCLINRole.RESEARCHER,
        operating_model=OperatingModel.MODEL_1,
        human_operator_id="analyst_jane",
    )
    assert result.success

    # Arbitrate with empty rationale -> should fail evidence gate
    arb = SecureArbitrationInput(
        decision=ArbitrationDecision.APPROVE,
        rationale="ok",  # Too short (< 20 chars)
    )
    recorded = pipeline.record_arbitration(
        transaction_id=result.transaction_id,
        human_operator_id="analyst_jane",
        arbitration=arb,
        checkpoint_role=RECCLINRole.RESEARCHER,
        navigation_record_id="nav-001",
    )

    assert not recorded, "Short rationale should be blocked by evidence gate"
    print("PASSED")


def test_int7_arbitration_with_rationale_succeeds():
    """INT7: Arbitration succeeds with sufficient rationale."""
    print("TEST INT7: Arbitration with rationale succeeds...", end=" ")
    runtime = make_governance_runtime()
    pipeline = make_pipeline(governance_runtime=runtime, tmpdir="/tmp/int7")

    result = pipeline.execute(
        prompt="Research question",
        recclin_role=RECCLINRole.RESEARCHER,
        operating_model=OperatingModel.MODEL_1,
        human_operator_id="analyst_jane",
    )
    assert result.success

    arb = SecureArbitrationInput(
        decision=ArbitrationDecision.APPROVE,
        rationale="Synthesis accurately represents all three platform responses. No modifications needed.",
    )
    recorded = pipeline.record_arbitration(
        transaction_id=result.transaction_id,
        human_operator_id="analyst_jane",
        arbitration=arb,
        checkpoint_role=RECCLINRole.RESEARCHER,
        navigation_record_id="nav-001",
    )

    assert recorded, "Valid rationale should pass"
    print("PASSED")


def test_int8_legacy_c3_fallback():
    """INT8: Legacy C3 auth works when governance_runtime is None."""
    print("TEST INT8: Legacy C3 fallback...", end=" ")
    registry = OperatorRegistry()
    registry.register_operator(OperatorIdentity("legacy_user"))

    pipeline = make_pipeline(
        governance_runtime=None,
        operator_registry=registry,
        tmpdir="/tmp/int8",
    )

    # Registered user succeeds
    result = pipeline.execute(
        prompt="Test",
        recclin_role=RECCLINRole.RESEARCHER,
        operating_model=OperatingModel.MODEL_1,
        human_operator_id="legacy_user",
    )
    assert result.success, f"Registered user should succeed: {result.error}"
    assert result.governance_decision is None  # No governance runtime

    # Unregistered user fails
    result2 = pipeline.execute(
        prompt="Test",
        recclin_role=RECCLINRole.RESEARCHER,
        operating_model=OperatingModel.MODEL_1,
        human_operator_id="unknown",
    )
    assert not result2.success
    assert "not registered" in result2.error.lower()
    print("PASSED")


def test_int9_identity_coordination():
    """INT9: Both identity systems can coexist on the same pipeline."""
    print("TEST INT9: Dual identity coordination...", end=" ")
    # Set up both identity systems sharing operator_id
    registry = OperatorRegistry()
    registry.register_operator(OperatorIdentity("analyst_jane"))
    registry.register_operator(OperatorIdentity("observer_tom"))

    runtime = make_governance_runtime()

    pipeline = make_pipeline(
        governance_runtime=runtime,
        operator_registry=registry,
        tmpdir="/tmp/int9",
    )

    # Analyst has both signing key and analyst role: succeeds
    result = pipeline.execute(
        prompt="Test",
        recclin_role=RECCLINRole.RESEARCHER,
        operating_model=OperatingModel.MODEL_1,
        human_operator_id="analyst_jane",
    )
    assert result.success

    # Observer has signing key but wrong governance role: blocked
    result2 = pipeline.execute(
        prompt="Test",
        recclin_role=RECCLINRole.RESEARCHER,
        operating_model=OperatingModel.MODEL_1,
        human_operator_id="observer_tom",
    )
    assert not result2.success
    assert "lacks required role" in result2.error.lower() or \
           "lacks required role" in result2.governance_decision.reason.lower()
    print("PASSED")


def test_int10_governance_decision_in_audit():
    """INT10: Governance decision is captured in pipeline result for audit."""
    print("TEST INT10: Governance decision in audit trail...", end=" ")
    runtime = make_governance_runtime()
    pipeline = make_pipeline(governance_runtime=runtime, tmpdir="/tmp/int10")

    result = pipeline.execute(
        prompt="Audit trail test",
        recclin_role=RECCLINRole.RESEARCHER,
        operating_model=OperatingModel.MODEL_1,
        human_operator_id="analyst_jane",
    )

    assert result.governance_decision is not None
    d = result.governance_decision.to_dict()
    assert "action" in d
    assert "operator_id" in d
    assert "authorized" in d
    assert d["authorized"] is True
    assert d["operator_id"] == "analyst_jane"

    # Also check the runtime's internal decision log
    log = runtime.decision_log
    assert len(log) >= 1
    assert log[0].operator_id == "analyst_jane"
    print("PASSED")


def test_int11_no_governance_no_auth_open():
    """INT11: Pipeline with neither governance nor registry runs open."""
    print("TEST INT11: No governance + no registry = open...", end=" ")
    pipeline = make_pipeline(
        governance_runtime=None,
        operator_registry=None,
        tmpdir="/tmp/int11",
        require_authentication=False,
    )

    result = pipeline.execute(
        prompt="Open access test",
        recclin_role=RECCLINRole.RESEARCHER,
        operating_model=OperatingModel.MODEL_1,
        human_operator_id="anyone",
    )

    assert result.success, f"Open pipeline should succeed: {result.error}"
    assert result.governance_decision is None
    print("PASSED")


def test_int15_auth_misconfiguration_fails_closed():
    """INT15: FIX5 - require_authentication=True with no auth backend raises."""
    print("TEST INT15: Auth misconfiguration fails closed...", end=" ")
    try:
        make_pipeline(
            governance_runtime=None,
            operator_registry=None,
            tmpdir="/tmp/int15",
            require_authentication=True,
        )
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "misconfiguration" in str(e).lower()
    print("PASSED")


# ======================================================================
# SYNTX 8.2: Dispatch Failure and Degraded Synthesis Tests
# ======================================================================

def make_failing_pipeline(
    fail_count: int,
    total_count: int = 3,
    governance_runtime=None,
    tmpdir="/tmp/haia_dispatch_fail",
):
    """Build a pipeline where fail_count of total_count adapters return errors."""
    Path(tmpdir).mkdir(parents=True, exist_ok=True)
    audit_path = Path(tmpdir) / "audit.json"
    if audit_path.exists():
        audit_path.unlink()

    logger = AuditLogger(
        audit_file_path=str(audit_path),
        operator_id="pipeline_agent",
    )

    adapters = []
    for i in range(total_count):
        simulate_error = i < fail_count
        adapters.append(MockAdapter(
            f"mock_{chr(65 + i)}",
            f"model-{chr(65 + i)}",
            simulate_error=simulate_error,
        ))

    mock_nav = MockAdapter("mock_navigator", "nav-model")

    selector = PlatformSelector(min_rotation=2)
    for a in adapters:
        selector.register_adapter(a)
    selector.set_anchor(adapters[0].platform_id)

    navigator = NavigatorRouter(navigator_adapter=mock_nav)

    return SecureGOPELPipeline(
        logger=logger,
        selector=selector,
        navigator=navigator,
        governance_runtime=governance_runtime,
        require_authentication=False,
    )


def test_int12_total_dispatch_failure():
    """INT12: All platforms fail. Pipeline halts with explicit failure."""
    print("TEST INT12: Total dispatch failure halts pipeline...", end=" ")
    pipeline = make_failing_pipeline(
        fail_count=3, total_count=3, tmpdir="/tmp/int12",
    )

    result = pipeline.execute(
        prompt="Test prompt",
        recclin_role=RECCLINRole.RESEARCHER,
        operating_model=OperatingModel.MODEL_1,
        human_operator_id="anyone",
    )

    assert not result.success, "Total dispatch failure must not succeed"
    assert "total dispatch failure" in result.error.lower()
    assert result.breach_halted is True
    assert result.breach_report is not None
    assert result.checkpoint_package is None
    print("PASSED")


def test_int13_degraded_cross_validation():
    """INT13: Only 1 of 3 platforms succeeds. Checkpoint flags degraded status."""
    print("TEST INT13: Degraded cross-validation flagged...", end=" ")
    pipeline = make_failing_pipeline(
        fail_count=2, total_count=3, tmpdir="/tmp/int13",
    )

    result = pipeline.execute(
        prompt="Test prompt",
        recclin_role=RECCLINRole.RESEARCHER,
        operating_model=OperatingModel.MODEL_1,
        human_operator_id="anyone",
    )

    assert result.success, f"Degraded should still succeed: {result.error}"
    pkg = result.checkpoint_package
    assert pkg is not None
    assert pkg.cross_validation_status == "DEGRADED"
    assert pkg.usable_responses == 1
    assert pkg.total_dispatched == 3
    # Security warnings must flag the degradation
    degraded_warnings = [
        w for w in result.security_warnings if "DEGRADED" in w
    ]
    assert len(degraded_warnings) >= 1, "Must warn about degraded cross-validation"
    print("PASSED")


def test_int14_full_cross_validation_status():
    """INT14: All platforms succeed. Checkpoint shows FULL status."""
    print("TEST INT14: Full cross-validation confirmed...", end=" ")
    pipeline = make_failing_pipeline(
        fail_count=0, total_count=3, tmpdir="/tmp/int14",
    )

    result = pipeline.execute(
        prompt="Test prompt",
        recclin_role=RECCLINRole.RESEARCHER,
        operating_model=OperatingModel.MODEL_1,
        human_operator_id="anyone",
    )

    assert result.success, f"Full should succeed: {result.error}"
    pkg = result.checkpoint_package
    assert pkg is not None
    assert pkg.cross_validation_status == "FULL"
    assert pkg.usable_responses == 3
    assert pkg.total_dispatched == 3
    print("PASSED")


def test_int16_navigator_synthesis_persisted():
    """INT16: FIX15 - Full Navigator synthesis stored in audit trail."""
    print("TEST INT16: Navigator synthesis persisted in audit...", end=" ")
    runtime = make_governance_runtime()
    pipeline = make_pipeline(governance_runtime=runtime, tmpdir="/tmp/int16")

    result = pipeline.execute(
        prompt="Test synthesis persistence",
        recclin_role=RECCLINRole.RESEARCHER,
        operating_model=OperatingModel.MODEL_1,
        human_operator_id="analyst_jane",
    )
    assert result.success, f"Pipeline should succeed: {result.error}"

    # Find navigation records in the audit trail
    nav_records = [
        r for r in pipeline.logger._records
        if r.get("record_type") == "navigation"
    ]
    assert len(nav_records) > 0, "Should have at least one navigation record"

    nav = nav_records[0]
    synthesis = nav.get("full_synthesis_text", "")
    assert len(synthesis) > 0, "full_synthesis_text should not be empty"
    # The mock navigator returns CONVERGENCE/DIVERGENCE sections
    assert "CONVERGENCE" in synthesis or len(synthesis) > 50, (
        "Synthesis should contain Navigator output, not a placeholder"
    )
    # Should not be truncated to 500 chars if output is longer
    assert synthesis != nav.get("recommendation", ""), (
        "full_synthesis_text should be complete, not same as truncated recommendation"
    )
    print("PASSED")


def test_int17_breach_state_blocks_next_transaction():
    """INT17: Breach state persists and blocks next transaction via policy (T1-A)."""
    print("TEST INT17: Breach state blocks next transaction...", end=" ")
    runtime = make_governance_runtime()
    pipeline = make_pipeline(governance_runtime=runtime, tmpdir="/tmp/int17")

    # Transaction 1: Normal execution succeeds
    result1 = pipeline.execute(
        prompt="Normal analysis request.",
        recclin_role=RECCLINRole.RESEARCHER,
        operating_model=OperatingModel.MODEL_1,
        human_operator_id="analyst_jane",
    )
    assert result1.success, f"First txn should succeed: {result1.error}"

    # Simulate that Transaction 1 produced a CRITICAL breach
    # (In production this happens via breach_detector.analyze_transaction)
    from haia_agent.breach import BreachSeverity
    pipeline._last_breach_severity = BreachSeverity.CRITICAL
    pipeline._last_injection_count = 5

    # Transaction 2: Gov officer tries to execute during active breach.
    # POLICY_BREACH_BLOCKS_EXECUTION must DENY because
    # ctx.breach_severity is now CRITICAL (carried from prior txn).
    # Before T1-A fix, this would pass because context always defaulted
    # to NOMINAL regardless of prior breach state.
    result2 = pipeline.execute(
        prompt="Another request during active breach.",
        recclin_role=RECCLINRole.RESEARCHER,
        operating_model=OperatingModel.MODEL_1,
        human_operator_id="gov_officer_mark",
    )
    assert not result2.success, "Should be blocked during CRITICAL breach"
    assert "breach" in result2.error.lower() or "denied" in result2.error.lower(), \
        f"Error should reference breach or denial: {result2.error}"
    print("PASSED")


def test_int18_logger_health_catches_corruption():
    """INT18: Logger health check detects corrupted audit file (T1-C)."""
    print("TEST INT18: Logger health catches corruption...", end=" ")
    runtime = make_governance_runtime()
    pipeline = make_pipeline(governance_runtime=runtime, tmpdir="/tmp/int18")

    result = pipeline.execute(
        prompt="Normal request.",
        recclin_role=RECCLINRole.RESEARCHER,
        operating_model=OperatingModel.MODEL_1,
        human_operator_id="analyst_jane",
    )
    assert result.success, f"Should succeed: {result.error}"
    assert pipeline._verify_logger_health(), "Should pass on valid file"

    with open(pipeline.logger.audit_file_path, "w") as f:
        f.write('{"schema": {"version": 1}, "records": [{"broken')

    assert not pipeline._verify_logger_health(), \
        "Should fail on corrupted JSON"
    print("PASSED")


def test_int19_breach_acknowledgment_resolves_deadlock():
    """INT19: Breach acknowledgment clears state so execution resumes (CLAUDE-R9)."""
    print("TEST INT19: Breach acknowledgment resolves deadlock...", end=" ")
    from haia_agent.breach import BreachSeverity
    runtime = make_governance_runtime()
    pipeline = make_pipeline(governance_runtime=runtime, tmpdir="/tmp/int19")

    # Transaction 1: Normal success
    result1 = pipeline.execute(
        prompt="Normal request.",
        recclin_role=RECCLINRole.RESEARCHER,
        operating_model=OperatingModel.MODEL_1,
        human_operator_id="analyst_jane",
    )
    assert result1.success

    # Simulate CRITICAL breach
    pipeline._last_breach_severity = BreachSeverity.CRITICAL

    # Transaction 2: Blocked by policy
    result2 = pipeline.execute(
        prompt="Blocked request.",
        recclin_role=RECCLINRole.RESEARCHER,
        operating_model=OperatingModel.MODEL_1,
        human_operator_id="gov_officer_mark",
    )
    assert not result2.success, "Should be blocked during CRITICAL breach"

    # Analyst cannot acknowledge (wrong role)
    ack_analyst = pipeline.acknowledge_breach(
        human_operator_id="analyst_jane",
        justification="Breach was investigated and found to be a false positive",
    )
    assert not ack_analyst, "Analyst should not be able to acknowledge breach"

    # Gov officer acknowledges
    ack_gov = pipeline.acknowledge_breach(
        human_operator_id="gov_officer_mark",
        justification="Breach was investigated and confirmed as false positive from test data",
    )
    assert ack_gov, "Gov officer should be able to acknowledge breach"

    # Transaction 3: Gov officer can execute after acknowledgment
    # Note: escalation engine is still elevated (requires gov officer).
    # Breach acknowledgment clears the POLICY block but does not
    # de-escalate the governance posture. That is deliberate:
    # defense-in-depth means both must be addressed separately.
    result3 = pipeline.execute(
        prompt="Resumed request after acknowledgment.",
        recclin_role=RECCLINRole.RESEARCHER,
        operating_model=OperatingModel.MODEL_1,
        human_operator_id="gov_officer_mark",
    )
    assert result3.success, f"Gov officer should succeed after acknowledgment: {result3.error}"
    print("PASSED")


# ======================================================================
# RUN ALL TESTS
# ======================================================================

def run_all_tests():
    print("=" * 70)
    print("HAIA AGENT FRAMEWORK - INTEGRATION TESTS")
    print("Governance runtime + secure pipeline end-to-end")
    print("=" * 70)
    print()

    tests = [
        test_int1_governance_authorizes_execution,
        test_int2_governance_blocks_unregistered,
        test_int3_governance_blocks_wrong_role,
        test_int4_model2_requires_scope,
        test_int5_model2_with_scope_succeeds,
        test_int6_arbitration_requires_rationale,
        test_int7_arbitration_with_rationale_succeeds,
        test_int8_legacy_c3_fallback,
        test_int9_identity_coordination,
        test_int10_governance_decision_in_audit,
        test_int11_no_governance_no_auth_open,
        test_int12_total_dispatch_failure,
        test_int13_degraded_cross_validation,
        test_int14_full_cross_validation_status,
        test_int15_auth_misconfiguration_fails_closed,
        test_int16_navigator_synthesis_persisted,
        test_int17_breach_state_blocks_next_transaction,
        test_int18_logger_health_catches_corruption,
        test_int19_breach_acknowledgment_resolves_deadlock,
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
    print("INTEGRATION COVERAGE:")
    print("  INT1   Governance authorizes execution:        Pipeline + 5-layer auth")
    print("  INT2   Governance blocks unregistered:         Pipeline + Layer 1")
    print("  INT3   Governance blocks wrong role:           Pipeline + Layer 2")
    print("  INT4   Model 2 denied without scope:           Pipeline + Layer 3 policy")
    print("  INT5   Model 2 succeeds with scope:            Pipeline + Layer 4 evidence")
    print("  INT6   Arbitration requires rationale:         Arbitration + evidence gate")
    print("  INT7   Arbitration with rationale succeeds:    Arbitration + evidence gate")
    print("  INT8   Legacy C3 fallback:                     Backward compatibility")
    print("  INT9   Dual identity coordination:             OperatorRegistry + GovernanceRuntime")
    print("  INT10  Governance decision in audit:           Audit trail completeness")
    print("  INT11  Open pipeline (no auth):                Permissive configuration")
    print("  INT12  Total dispatch failure:                 SYNTX 8.2 exception protocol")
    print("  INT13  Degraded cross-validation:              SYNTX 8.2 single-source flag")
    print("  INT14  Full cross-validation status:           SYNTX 8.2 baseline confirmation")
    print("  INT15  Auth misconfiguration fails closed:      FIX5 negative test")
    print("  INT16  Navigator synthesis persisted:           FIX15 audit completeness")
    print("  INT17  Breach state blocks next transaction:    T1-A governance context fix")
    print("  INT18  Logger health catches corruption:        T1-C chain verification")
    print("  INT19  Breach acknowledgment resolves deadlock:  CLAUDE-R9 deadlock fix")
    print("=" * 70)
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
