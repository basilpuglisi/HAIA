"""
HAIA Agent Framework - Governance Runtime Tests
==================================================
Tests the five enterprise governance enforcement layers:

    GOV1: WHO is allowed to act (authorization)
    GOV2: WHAT they are allowed to do (permissions)
    GOV3: WHAT evidence they must attach (evidence gates)
    GOV4: WHAT policy must be satisfied (policy engine)
    GOV5: WHAT escalation path triggers (escalation engine)
    GOV6: Full runtime orchestration (all layers combined)

Attack scenarios:
    AUTH1: Unregistered operator blocked
    AUTH2: Inactive operator blocked
    AUTH3: Analyst cannot override circuit breaker
    AUTH4: Observer cannot execute pipeline
    AUTH5: Governance officer can override (with evidence)

    POL1: CRITICAL breach blocks execution
    POL2: WARNING escalates to governance officer
    POL3: Model 2 requires scope statement
    POL4: Override requires dual approval
    POL5: Injection flood escalates

    ESC1: WARNING breach elevates posture
    ESC2: CRITICAL breach triggers HIGH
    ESC3: HALT triggers LOCKDOWN
    ESC4: Escalation only goes up (ratchet)
    ESC5: De-escalation requires authority
    ESC6: Lockdown blocks all except acknowledgment

Author: Basil C. Puglisi, MPA
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from haia_agent.governance import (
    AuthorizationResult,
    Authorizer,
    EscalationEngine,
    EscalationLevel,
    EscalationRule,
    EscalationState,
    EvidenceGate,
    EvidenceGateResult,
    EvidenceRequirement,
    EvidenceSubmission,
    EvidenceType,
    GovAction,
    GovernanceContext,
    GovernanceDecision,
    GovernanceRuntime,
    OperatorProfile,
    OperatorRole,
    Policy,
    PolicyEngine,
    PolicyEvaluationResult,
    PolicyResult,
    PolicyVerdict,
    ARBITRATION_GATE,
    CIRCUIT_BREAKER_OVERRIDE_GATE,
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
from haia_agent.breach import BreachSeverity
from haia_agent.models import OperatingModel, RECCLINRole


# ======================================================================
# HELPERS
# ======================================================================

def make_analyst() -> OperatorProfile:
    return OperatorProfile(
        operator_id="analyst_jane",
        roles={OperatorRole.ANALYST},
        department="research",
        clearance_level=1,
    )

def make_gov_officer() -> OperatorProfile:
    return OperatorProfile(
        operator_id="gov_officer_mark",
        roles={OperatorRole.GOVERNANCE_OFFICER},
        department="governance",
        clearance_level=2,
    )

def make_admin() -> OperatorProfile:
    return OperatorProfile(
        operator_id="admin_sarah",
        roles={OperatorRole.ADMINISTRATOR},
        department="operations",
        clearance_level=3,
    )

def make_observer() -> OperatorProfile:
    return OperatorProfile(
        operator_id="observer_tom",
        roles={OperatorRole.OBSERVER},
        department="external",
        clearance_level=0,
    )

def make_auditor() -> OperatorProfile:
    return OperatorProfile(
        operator_id="auditor_lisa",
        roles={OperatorRole.AUDITOR},
        department="compliance",
        clearance_level=1,
    )

def make_standard_runtime() -> GovernanceRuntime:
    """Build runtime with all standard policies and rules."""
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

    # Use bootstrap_register for test setup (bypasses GV12 auth chain)
    runtime.bootstrap_register(make_analyst())
    runtime.bootstrap_register(make_gov_officer())
    runtime.bootstrap_register(make_admin())
    runtime.bootstrap_register(make_observer())
    runtime.bootstrap_register(make_auditor())

    return runtime


# ======================================================================
# GOV1: WHO IS ALLOWED TO ACT
# ======================================================================

def test_gov1_registered_operator_authorized():
    """GOV1: Registered analyst can execute pipeline."""
    print("TEST GOV1: Registered operator authorized...", end=" ")
    runtime = make_standard_runtime()
    decision = runtime.authorize("analyst_jane", GovAction.EXECUTE_PIPELINE)
    assert decision.authorized, f"Should be authorized: {decision.reason}"
    print("PASSED")

def test_auth1_unregistered_blocked():
    """AUTH1: Unregistered operator blocked."""
    print("TEST AUTH1: Unregistered operator blocked...", end=" ")
    runtime = make_standard_runtime()
    decision = runtime.authorize("unknown_user", GovAction.EXECUTE_PIPELINE)
    assert not decision.authorized
    assert "not registered" in decision.reason
    print("PASSED")

def test_auth2_inactive_blocked():
    """AUTH2: Inactive operator blocked even if registered."""
    print("TEST AUTH2: Inactive operator blocked...", end=" ")
    runtime = make_standard_runtime()
    inactive = OperatorProfile(
        operator_id="inactive_bob",
        roles={OperatorRole.ANALYST},
        active=False,
    )
    runtime.register_profile(inactive)
    decision = runtime.authorize("inactive_bob", GovAction.EXECUTE_PIPELINE)
    assert not decision.authorized
    assert "inactive" in decision.reason.lower()
    print("PASSED")


# ======================================================================
# GOV2: WHAT THEY ARE ALLOWED TO DO
# ======================================================================

def test_auth3_analyst_cannot_override():
    """AUTH3: Analyst cannot override circuit breaker."""
    print("TEST AUTH3: Analyst cannot override circuit breaker...", end=" ")
    runtime = make_standard_runtime()
    decision = runtime.authorize("analyst_jane", GovAction.OVERRIDE_CIRCUIT_BREAKER)
    assert not decision.authorized
    assert "lacks required role" in decision.reason
    print("PASSED")

def test_auth4_observer_cannot_execute():
    """AUTH4: Observer cannot execute pipeline."""
    print("TEST AUTH4: Observer cannot execute pipeline...", end=" ")
    runtime = make_standard_runtime()
    decision = runtime.authorize("observer_tom", GovAction.EXECUTE_PIPELINE)
    assert not decision.authorized
    print("PASSED")

def test_gov2_admin_can_do_everything():
    """GOV2: Administrator has role-level permissions for all actions."""
    print("TEST GOV2: Administrator role permissions...", end=" ")
    authorizer = Authorizer()
    admin = make_admin()
    for action in GovAction:
        result = authorizer.check(admin, action)
        assert result.authorized, f"Admin should have role for {action.value}: {result.reason}"
    print("PASSED")

def test_gov2_auditor_read_only():
    """GOV2: Auditor can only view and export."""
    print("TEST GOV2b: Auditor read-only permissions...", end=" ")
    runtime = make_standard_runtime()
    # Allowed
    d1 = runtime.authorize("auditor_lisa", GovAction.VIEW_BREACH_REPORT)
    assert d1.authorized
    d2 = runtime.authorize("auditor_lisa", GovAction.EXPORT_AUDIT_TRAIL)
    assert d2.authorized
    # Denied
    d3 = runtime.authorize("auditor_lisa", GovAction.EXECUTE_PIPELINE)
    assert not d3.authorized
    d4 = runtime.authorize("auditor_lisa", GovAction.MODIFY_POLICY)
    assert not d4.authorized
    print("PASSED")


# ======================================================================
# GOV3: WHAT EVIDENCE THEY MUST ATTACH
# ======================================================================

def test_gov3_arbitration_requires_rationale():
    """GOV3: Arbitration gate requires rationale text."""
    print("TEST GOV3: Arbitration requires rationale...", end=" ")
    # Missing evidence
    result = ARBITRATION_GATE.check([])
    assert not result.passed
    assert len(result.missing) > 0

    # Insufficient evidence
    result2 = ARBITRATION_GATE.check([
        EvidenceSubmission(EvidenceType.RATIONALE, "short", "analyst_jane")
    ])
    assert not result2.passed
    assert len(result2.insufficient) > 0

    # Sufficient evidence
    result3 = ARBITRATION_GATE.check([
        EvidenceSubmission(
            EvidenceType.RATIONALE,
            "Approved because all three platforms converged on the same finding.",
            "analyst_jane",
        )
    ])
    assert result3.passed
    print("PASSED")

def test_gov3_override_requires_dual_approval():
    """GOV3: Circuit breaker override requires justification, risk, and second approver."""
    print("TEST GOV3b: Override requires dual approval...", end=" ")
    # Missing all
    result = CIRCUIT_BREAKER_OVERRIDE_GATE.check([])
    assert not result.passed
    assert len(result.missing) == 3

    # Only justification
    result2 = CIRCUIT_BREAKER_OVERRIDE_GATE.check([
        EvidenceSubmission(
            EvidenceType.JUSTIFICATION,
            "The breach was a false positive triggered by a known Unicode test string in the platform response.",
            "gov_officer_mark",
        ),
    ])
    assert not result2.passed

    # All three present
    result3 = CIRCUIT_BREAKER_OVERRIDE_GATE.check([
        EvidenceSubmission(
            EvidenceType.JUSTIFICATION,
            "The breach was a false positive triggered by a known Unicode test string in the platform response.",
            "gov_officer_mark",
        ),
        EvidenceSubmission(
            EvidenceType.RISK_ASSESSMENT,
            "Residual risk accepted: output may contain non-ASCII characters.",
            "gov_officer_mark",
        ),
        EvidenceSubmission(
            EvidenceType.SECOND_APPROVER,
            "admin_sarah",
            "gov_officer_mark",
        ),
    ])
    assert result3.passed
    print("PASSED")

def test_gov3_evidence_gate_in_runtime():
    """GOV3: Evidence gate enforced through full runtime."""
    print("TEST GOV3c: Evidence gate in runtime...", end=" ")
    runtime = make_standard_runtime()
    runtime.register_evidence_gate(
        GovAction.EXECUTE_PIPELINE.value,
        ARBITRATION_GATE,
    )
    # Without evidence
    d1 = runtime.authorize("analyst_jane", GovAction.EXECUTE_PIPELINE)
    assert not d1.authorized
    assert "Evidence gate" in d1.reason

    # With evidence
    d2 = runtime.authorize(
        "analyst_jane",
        GovAction.EXECUTE_PIPELINE,
        evidence=[
            EvidenceSubmission(
                EvidenceType.RATIONALE,
                "Proceeding with standard research query. Low risk, routine analysis.",
                "analyst_jane",
            ),
        ],
    )
    assert d2.authorized
    print("PASSED")


# ======================================================================
# GOV4: WHAT POLICY MUST BE SATISFIED
# ======================================================================

def test_pol1_critical_breach_blocks():
    """POL1: CRITICAL breach severity blocks pipeline execution via policy."""
    print("TEST POL1: CRITICAL breach blocks execution...", end=" ")
    runtime = make_standard_runtime()
    # Use governance officer so escalation doesn't block first.
    # The POLICY should still block because CRITICAL severity is denied.
    officer = runtime.get_profile("gov_officer_mark")
    context = GovernanceContext(
        operator=officer,
        action=GovAction.EXECUTE_PIPELINE,
        breach_severity=BreachSeverity.CRITICAL,
    )
    decision = runtime.authorize(
        "gov_officer_mark", GovAction.EXECUTE_PIPELINE, context=context
    )
    assert not decision.authorized
    assert decision.policy_verdict == PolicyVerdict.DENY
    print("PASSED")

def test_pol2_warning_escalates_to_gov_officer():
    """POL2: WARNING breach with analyst triggers escalation."""
    print("TEST POL2: WARNING escalates to gov officer...", end=" ")
    runtime = make_standard_runtime()
    analyst = runtime.get_profile("analyst_jane")
    context = GovernanceContext(
        operator=analyst,
        action=GovAction.EXECUTE_PIPELINE,
        breach_severity=BreachSeverity.WARNING,
    )
    decision = runtime.authorize(
        "analyst_jane", GovAction.EXECUTE_PIPELINE, context=context
    )
    # Should be blocked: analyst lacks governance_officer role for elevated state
    assert not decision.authorized
    print("PASSED")

def test_pol2_gov_officer_proceeds_on_warning():
    """POL2: Governance officer can proceed despite WARNING."""
    print("TEST POL2b: Gov officer proceeds on WARNING...", end=" ")
    runtime = make_standard_runtime()
    officer = runtime.get_profile("gov_officer_mark")
    context = GovernanceContext(
        operator=officer,
        action=GovAction.EXECUTE_PIPELINE,
        breach_severity=BreachSeverity.WARNING,
    )
    decision = runtime.authorize(
        "gov_officer_mark", GovAction.EXECUTE_PIPELINE, context=context
    )
    assert decision.authorized, f"Gov officer should proceed: {decision.reason}"
    print("PASSED")

def test_pol3_model2_requires_scope():
    """POL3: Model 2 execution requires scope statement."""
    print("TEST POL3: Model 2 requires scope statement...", end=" ")
    runtime = make_standard_runtime()
    analyst = runtime.get_profile("analyst_jane")
    # Without scope
    context = GovernanceContext(
        operator=analyst,
        action=GovAction.EXECUTE_PIPELINE,
        operating_model=OperatingModel.MODEL_2,
    )
    decision = runtime.authorize(
        "analyst_jane", GovAction.EXECUTE_PIPELINE, context=context
    )
    assert not decision.authorized
    assert "scope" in decision.reason.lower()

    # With scope
    decision2 = runtime.authorize(
        "analyst_jane",
        GovAction.EXECUTE_PIPELINE,
        context=GovernanceContext(
            operator=analyst,
            action=GovAction.EXECUTE_PIPELINE,
            operating_model=OperatingModel.MODEL_2,
        ),
        evidence=[
            EvidenceSubmission(
                EvidenceType.SCOPE_STATEMENT,
                "Analyzing EU AI Act Article 14 compliance requirements.",
                "analyst_jane",
            ),
        ],
    )
    assert decision2.authorized, f"Should pass with scope: {decision2.reason}"
    print("PASSED")

def test_pol4_override_requires_dual():
    """POL4: Circuit breaker override requires dual approval."""
    print("TEST POL4: Override requires dual approval...", end=" ")
    runtime = make_standard_runtime()
    # Without evidence
    decision = runtime.authorize(
        "gov_officer_mark", GovAction.OVERRIDE_CIRCUIT_BREAKER
    )
    assert not decision.authorized
    assert decision.policy_verdict == PolicyVerdict.DENY

    # With evidence
    decision2 = runtime.authorize(
        "gov_officer_mark",
        GovAction.OVERRIDE_CIRCUIT_BREAKER,
        evidence=[
            EvidenceSubmission(
                EvidenceType.JUSTIFICATION,
                "False positive from known Unicode test string in training data response.",
                "gov_officer_mark",
            ),
            EvidenceSubmission(
                EvidenceType.SECOND_APPROVER,
                "admin_sarah",
                "gov_officer_mark",
            ),
        ],
    )
    assert decision2.authorized, f"Should pass with dual approval: {decision2.reason}"
    print("PASSED")

def test_pol5_injection_flood():
    """POL5: High injection count triggers escalation."""
    print("TEST POL5: Injection flood escalates...", end=" ")
    runtime = make_standard_runtime()
    analyst = runtime.get_profile("analyst_jane")
    context = GovernanceContext(
        operator=analyst,
        action=GovAction.EXECUTE_PIPELINE,
        injection_count=5,
    )
    decision = runtime.authorize(
        "analyst_jane", GovAction.EXECUTE_PIPELINE, context=context
    )
    # Injection flood triggers escalation, analyst lacks gov_officer role
    assert not decision.authorized
    print("PASSED")


# ======================================================================
# GOV5: WHAT ESCALATION PATH TRIGGERS
# ======================================================================

def test_esc1_warning_elevates():
    """ESC1: WARNING breach elevates governance posture."""
    print("TEST ESC1: WARNING elevates posture...", end=" ")
    engine = EscalationEngine()
    engine.register_rule(RULE_BREACH_WARNING_ELEVATES)
    analyst = make_analyst()
    context = GovernanceContext(
        operator=analyst,
        action=GovAction.EXECUTE_PIPELINE,
        breach_severity=BreachSeverity.WARNING,
    )
    state = engine.evaluate(context)
    assert state.level == EscalationLevel.ELEVATED
    print("PASSED")

def test_esc2_critical_triggers_high():
    """ESC2: CRITICAL breach triggers HIGH escalation."""
    print("TEST ESC2: CRITICAL triggers HIGH...", end=" ")
    engine = EscalationEngine()
    engine.register_rule(RULE_BREACH_CRITICAL_HIGH)
    analyst = make_analyst()
    context = GovernanceContext(
        operator=analyst,
        action=GovAction.EXECUTE_PIPELINE,
        breach_severity=BreachSeverity.CRITICAL,
    )
    state = engine.evaluate(context)
    assert state.level == EscalationLevel.HIGH
    print("PASSED")

def test_esc3_halt_triggers_lockdown():
    """ESC3: HALT breach triggers LOCKDOWN."""
    print("TEST ESC3: HALT triggers LOCKDOWN...", end=" ")
    engine = EscalationEngine()
    engine.register_rule(RULE_BREACH_HALT_LOCKDOWN)
    analyst = make_analyst()
    context = GovernanceContext(
        operator=analyst,
        action=GovAction.EXECUTE_PIPELINE,
        breach_severity=BreachSeverity.HALT,
    )
    state = engine.evaluate(context)
    assert state.level == EscalationLevel.LOCKDOWN
    print("PASSED")

def test_esc4_ratchet_only_goes_up():
    """ESC4: Escalation only goes up, never down automatically."""
    print("TEST ESC4: Escalation ratchet (only up)...", end=" ")
    engine = EscalationEngine()
    engine.register_rule(RULE_BREACH_WARNING_ELEVATES)
    engine.register_rule(RULE_BREACH_CRITICAL_HIGH)
    analyst = make_analyst()

    # First: CRITICAL -> HIGH
    ctx1 = GovernanceContext(
        operator=analyst,
        action=GovAction.EXECUTE_PIPELINE,
        breach_severity=BreachSeverity.CRITICAL,
    )
    state1 = engine.evaluate(ctx1)
    assert state1.level == EscalationLevel.HIGH

    # Second: WARNING (lower) -> should stay HIGH
    ctx2 = GovernanceContext(
        operator=analyst,
        action=GovAction.EXECUTE_PIPELINE,
        breach_severity=BreachSeverity.WARNING,
    )
    state2 = engine.evaluate(ctx2)
    assert state2.level == EscalationLevel.HIGH, (
        f"Should stay HIGH, not drop to ELEVATED: {state2.level}"
    )
    print("PASSED")

def test_esc5_de_escalation_requires_authority():
    """ESC5: De-escalation requires governance officer or admin."""
    print("TEST ESC5: De-escalation requires authority...", end=" ")
    engine = EscalationEngine()
    engine.register_rule(RULE_BREACH_CRITICAL_HIGH)
    analyst = make_analyst()
    officer = make_gov_officer()

    # Escalate to HIGH
    ctx = GovernanceContext(
        operator=analyst,
        action=GovAction.EXECUTE_PIPELINE,
        breach_severity=BreachSeverity.CRITICAL,
    )
    engine.evaluate(ctx)
    assert engine.current_state.level == EscalationLevel.HIGH

    # Analyst cannot de-escalate
    result = engine.de_escalate(analyst, EscalationLevel.NORMAL, "I want to")
    assert not result
    assert engine.current_state.level == EscalationLevel.HIGH

    # Governance officer can de-escalate
    result2 = engine.de_escalate(
        officer, EscalationLevel.NORMAL,
        "Root cause identified and resolved. False positive confirmed."
    )
    assert result2
    assert engine.current_state.level == EscalationLevel.NORMAL
    print("PASSED")

def test_esc6_lockdown_blocks_all():
    """ESC6: LOCKDOWN blocks all actions except breach acknowledgment."""
    print("TEST ESC6: LOCKDOWN blocks all except acknowledgment...", end=" ")
    runtime = make_standard_runtime()
    admin = runtime.get_profile("admin_sarah")

    # Trigger lockdown via HALT breach
    context = GovernanceContext(
        operator=admin,
        action=GovAction.EXECUTE_PIPELINE,
        breach_severity=BreachSeverity.HALT,
    )
    decision = runtime.authorize(
        "admin_sarah", GovAction.EXECUTE_PIPELINE, context=context
    )
    assert not decision.authorized
    assert "LOCKDOWN" in decision.reason

    # Acknowledge breach should still work for admin
    ack_decision = runtime.authorize(
        "admin_sarah", GovAction.ACKNOWLEDGE_BREACH
    )
    assert ack_decision.authorized, f"Acknowledgment should work: {ack_decision.reason}"
    print("PASSED")


# ======================================================================
# GOV6: FULL RUNTIME ORCHESTRATION
# ======================================================================

def test_gov6_full_happy_path():
    """GOV6: Full runtime: analyst executes clean Model 1 transaction."""
    print("TEST GOV6: Full happy path...", end=" ")
    runtime = make_standard_runtime()
    decision = runtime.authorize(
        "analyst_jane",
        GovAction.EXECUTE_PIPELINE,
        context=GovernanceContext(
            operator=make_analyst(),
            action=GovAction.EXECUTE_PIPELINE,
            operating_model=OperatingModel.MODEL_1,
            breach_severity=BreachSeverity.NOMINAL,
        ),
    )
    assert decision.authorized
    assert decision.policy_verdict == PolicyVerdict.ALLOW
    assert decision.escalation_level == EscalationLevel.NORMAL
    assert decision.evidence_gate_passed
    print("PASSED")

def test_gov6_decision_log_audit():
    """GOV6: All decisions are logged for audit."""
    print("TEST GOV6b: Decision log audit trail...", end=" ")
    runtime = make_standard_runtime()
    runtime.authorize("analyst_jane", GovAction.EXECUTE_PIPELINE)
    runtime.authorize("unknown_user", GovAction.EXECUTE_PIPELINE)
    runtime.authorize("observer_tom", GovAction.EXECUTE_PIPELINE)
    assert len(runtime.decision_log) == 3
    # First should be authorized, second and third denied
    assert runtime.decision_log[0].authorized
    assert not runtime.decision_log[1].authorized
    assert not runtime.decision_log[2].authorized
    # All should be serializable
    for d in runtime.decision_log:
        serialized = d.to_dict()
        assert "action" in serialized
        assert "operator_id" in serialized
        assert "authorized" in serialized
    print("PASSED")

def test_gov6_cascading_denial():
    """GOV6: Multiple layers block simultaneously, first failure wins."""
    print("TEST GOV6c: Cascading denial (first failure wins)...", end=" ")
    runtime = make_standard_runtime()
    # Observer + CRITICAL breach + no evidence = fails at authorization
    decision = runtime.authorize(
        "observer_tom",
        GovAction.EXECUTE_PIPELINE,
        context=GovernanceContext(
            operator=make_observer(),
            action=GovAction.EXECUTE_PIPELINE,
            breach_severity=BreachSeverity.CRITICAL,
        ),
    )
    assert not decision.authorized
    # Should fail at authorization, not reach policy
    assert "lacks required role" in decision.reason
    print("PASSED")

def test_gov6_escalation_callback():
    """GOV6: Escalation fires callback for external notification."""
    print("TEST GOV6d: Escalation callback...", end=" ")
    escalations = []
    esc_engine = EscalationEngine()
    esc_engine.register_rule(RULE_BREACH_CRITICAL_HIGH)
    esc_engine.register_callback(lambda state: escalations.append(state))

    runtime = GovernanceRuntime(escalation_engine=esc_engine)
    runtime.register_profile(make_analyst())

    context = GovernanceContext(
        operator=make_analyst(),
        action=GovAction.EXECUTE_PIPELINE,
        breach_severity=BreachSeverity.CRITICAL,
    )
    runtime.authorize("analyst_jane", GovAction.EXECUTE_PIPELINE, context=context)
    assert len(escalations) == 1
    assert escalations[0].level == EscalationLevel.HIGH
    print("PASSED")


# ======================================================================
# VULNERABILITY TESTS (GV1-GV12)
# ======================================================================

def test_gv1_self_approval_blocked():
    """GV1: Operator cannot name themselves as second approver."""
    print("TEST GV1: Self-approval blocked...", end=" ")
    gate = CIRCUIT_BREAKER_OVERRIDE_GATE
    result = gate.check(
        [
            EvidenceSubmission(
                EvidenceType.JUSTIFICATION,
                "False positive from known Unicode test string in training data response.",
                "gov_officer_mark",
            ),
            EvidenceSubmission(
                EvidenceType.RISK_ASSESSMENT,
                "Residual risk accepted: output may contain non-ASCII characters.",
                "gov_officer_mark",
            ),
            EvidenceSubmission(
                EvidenceType.SECOND_APPROVER,
                "gov_officer_mark",  # Same operator!
                "gov_officer_mark",
            ),
        ],
        requesting_operator_id="gov_officer_mark",
        registered_operator_ids={"gov_officer_mark", "admin_sarah"},
    )
    assert not result.passed, "Self-approval should be blocked"
    assert any("self-approval" in s for s in result.insufficient)
    print("PASSED")

def test_gv1_phantom_approver_blocked():
    """GV1: Second approver must be a registered operator."""
    print("TEST GV1b: Phantom approver blocked...", end=" ")
    gate = CIRCUIT_BREAKER_OVERRIDE_GATE
    result = gate.check(
        [
            EvidenceSubmission(
                EvidenceType.JUSTIFICATION,
                "False positive from known Unicode test string in training data response.",
                "gov_officer_mark",
            ),
            EvidenceSubmission(
                EvidenceType.RISK_ASSESSMENT,
                "Residual risk accepted: output may contain non-ASCII characters.",
                "gov_officer_mark",
            ),
            EvidenceSubmission(
                EvidenceType.SECOND_APPROVER,
                "phantom_user_xyz",  # Not registered!
                "gov_officer_mark",
            ),
        ],
        requesting_operator_id="gov_officer_mark",
        registered_operator_ids={"gov_officer_mark", "admin_sarah"},
    )
    assert not result.passed, "Phantom approver should be blocked"
    assert any("not a registered" in s for s in result.insufficient)
    print("PASSED")

def test_gv1_valid_second_approver():
    """GV1: Legitimate second approver passes."""
    print("TEST GV1c: Valid second approver passes...", end=" ")
    gate = CIRCUIT_BREAKER_OVERRIDE_GATE
    result = gate.check(
        [
            EvidenceSubmission(
                EvidenceType.JUSTIFICATION,
                "False positive from known Unicode test string in training data response.",
                "gov_officer_mark",
            ),
            EvidenceSubmission(
                EvidenceType.RISK_ASSESSMENT,
                "Residual risk accepted: output may contain non-ASCII characters.",
                "gov_officer_mark",
            ),
            EvidenceSubmission(
                EvidenceType.SECOND_APPROVER,
                "admin_sarah",  # Different, registered operator
                "gov_officer_mark",
            ),
        ],
        requesting_operator_id="gov_officer_mark",
        registered_operator_ids={"gov_officer_mark", "admin_sarah"},
    )
    assert result.passed, f"Valid approver should pass: {result.insufficient}"
    print("PASSED")

def test_gv3_empty_roles_denied():
    """GV3: Operator with no roles is denied for all actions."""
    print("TEST GV3: Empty roles denied...", end=" ")
    authorizer = Authorizer()
    empty = OperatorProfile(operator_id="no_roles_bob", roles=set())
    for action in GovAction:
        result = authorizer.check(empty, action)
        assert not result.authorized, f"Empty roles should be denied for {action.value}"
    print("PASSED")

def test_gv4_analyst_cannot_modify_permissions():
    """GV4: Non-admin cannot modify permission matrix."""
    print("TEST GV4: Analyst cannot modify permissions...", end=" ")
    runtime = make_standard_runtime()
    result = runtime.modify_permission(
        "analyst_jane", OperatorRole.ANALYST, GovAction.OVERRIDE_CIRCUIT_BREAKER, grant=True
    )
    assert not result, "Analyst should not be able to grant permissions"
    # Verify permission was NOT granted
    analyst = runtime.get_profile("analyst_jane")
    auth = Authorizer().check(analyst, GovAction.OVERRIDE_CIRCUIT_BREAKER)
    assert not auth.authorized
    print("PASSED")

def test_gv4_admin_can_modify_permissions():
    """GV4: Admin can modify permission matrix."""
    print("TEST GV4b: Admin can modify permissions...", end=" ")
    runtime = make_standard_runtime()
    result = runtime.modify_permission(
        "admin_sarah", OperatorRole.AUDITOR, GovAction.EXECUTE_PIPELINE, grant=True
    )
    assert result, "Admin should be able to grant permissions"
    print("PASSED")

def test_gv5_crashing_policy_denies():
    """GV5: Policy that raises exception produces DENY, not ALLOW."""
    print("TEST GV5: Crashing policy denies...", end=" ")
    def crashing_policy(ctx):
        raise RuntimeError("Unexpected failure in policy logic")

    engine = PolicyEngine()
    engine.register_policy(Policy(
        name="crasher",
        description="This policy crashes",
        evaluate_fn=crashing_policy,
    ))
    analyst = make_analyst()
    context = GovernanceContext(operator=analyst, action=GovAction.EXECUTE_PIPELINE)
    result = engine.evaluate(context)
    assert result.overall_verdict == PolicyVerdict.DENY
    assert "crasher" in result.blocking_policies
    assert "RuntimeError" in result.results[0].reason
    print("PASSED")

def test_gv6_decision_log_bounded():
    """GV6: Decision log does not grow without bound."""
    print("TEST GV6: Decision log bounded...", end=" ")
    runtime = GovernanceRuntime(max_decision_log=5)
    runtime.bootstrap_register(make_analyst())
    for i in range(10):
        runtime.authorize("analyst_jane", GovAction.EXECUTE_PIPELINE)
    assert len(runtime.decision_log) == 5
    assert runtime.decisions_evicted == 5
    print("PASSED")

def test_gv7_callback_error_recorded():
    """GV7: Failing callback is recorded, not silently swallowed."""
    print("TEST GV7: Callback error recorded...", end=" ")
    def bad_callback(state):
        raise ValueError("Notification service unreachable")

    engine = EscalationEngine()
    engine.register_rule(RULE_BREACH_CRITICAL_HIGH)
    engine.register_callback(bad_callback)

    analyst = make_analyst()
    context = GovernanceContext(
        operator=analyst,
        action=GovAction.EXECUTE_PIPELINE,
        breach_severity=BreachSeverity.CRITICAL,
    )
    state = engine.evaluate(context)
    # Escalation still took effect despite callback failure
    assert state.level == EscalationLevel.HIGH
    # Error was recorded
    assert len(engine.callback_errors) == 1
    assert "ValueError" in engine.callback_errors[0]
    print("PASSED")

def test_gv9_empty_operator_id_rejected():
    """GV9: Empty or whitespace operator_id rejected."""
    print("TEST GV9: Empty operator ID rejected...", end=" ")
    try:
        OperatorProfile(operator_id="", roles={OperatorRole.ANALYST})
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "empty" in str(e).lower()

    try:
        OperatorProfile(operator_id="   ", roles={OperatorRole.ANALYST})
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "empty" in str(e).lower()
    print("PASSED")

def test_gv9_long_operator_id_rejected():
    """GV9: Excessively long operator_id rejected."""
    print("TEST GV9b: Long operator ID rejected...", end=" ")
    try:
        OperatorProfile(operator_id="x" * 200, roles={OperatorRole.ANALYST})
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert "128" in str(e)
    print("PASSED")

def test_gv10_empty_deescalation_rejected():
    """GV10: De-escalation with empty justification rejected."""
    print("TEST GV10: Empty de-escalation justification rejected...", end=" ")
    engine = EscalationEngine()
    engine.register_rule(RULE_BREACH_CRITICAL_HIGH)
    analyst = make_analyst()
    officer = make_gov_officer()

    # Escalate to HIGH
    ctx = GovernanceContext(
        operator=analyst,
        action=GovAction.EXECUTE_PIPELINE,
        breach_severity=BreachSeverity.CRITICAL,
    )
    engine.evaluate(ctx)

    # Wrap in runtime for GV10 check
    runtime = GovernanceRuntime(escalation_engine=engine)
    runtime.bootstrap_register(officer)

    result = runtime.de_escalate("gov_officer_mark", EscalationLevel.NORMAL, "too short")
    assert not result, "Short justification should be rejected"
    assert engine.current_state.level == EscalationLevel.HIGH
    print("PASSED")

def test_gv11_duplicate_acknowledgment_rejected():
    """GV11: Same operator cannot acknowledge escalation twice."""
    print("TEST GV11: Duplicate acknowledgment rejected...", end=" ")
    engine = EscalationEngine()
    engine.register_rule(RULE_BREACH_CRITICAL_HIGH)
    officer = make_gov_officer()

    # Escalate
    ctx = GovernanceContext(
        operator=make_analyst(),
        action=GovAction.EXECUTE_PIPELINE,
        breach_severity=BreachSeverity.CRITICAL,
    )
    engine.evaluate(ctx)

    # First acknowledgment succeeds
    assert engine.acknowledge(officer)
    assert len(engine.current_state.acknowledgments) == 1

    # Second from same operator fails
    assert not engine.acknowledge(officer)
    assert len(engine.current_state.acknowledgments) == 1  # Still 1
    print("PASSED")

def test_gv12_registration_requires_authorization():
    """GV12: After bootstrap, registration requires REGISTER_OPERATOR auth."""
    print("TEST GV12: Registration requires authorization...", end=" ")
    runtime = GovernanceRuntime()

    # First registration: bootstrap (no auth needed)
    admin = make_admin()
    assert runtime.register_profile(admin)

    # Second registration by admin: succeeds
    analyst = make_analyst()
    assert runtime.register_profile(analyst, registering_operator_id="admin_sarah")

    # Registration by analyst: fails (analyst lacks REGISTER_OPERATOR)
    new_user = OperatorProfile(operator_id="new_user", roles={OperatorRole.OBSERVER})
    assert not runtime.register_profile(new_user, registering_operator_id="analyst_jane")

    # Registration without identifying registrar: fails
    assert not runtime.register_profile(
        OperatorProfile(operator_id="anon_user", roles={OperatorRole.OBSERVER})
    )
    print("PASSED")

def test_gv1_runtime_self_approval_integration():
    """GV1 integrated: Self-approval blocked through full runtime."""
    print("TEST GV1d: Runtime self-approval integration...", end=" ")
    runtime = make_standard_runtime()
    runtime.register_evidence_gate(
        GovAction.OVERRIDE_CIRCUIT_BREAKER.value,
        CIRCUIT_BREAKER_OVERRIDE_GATE,
    )
    # Gov officer tries to override with self as second approver
    decision = runtime.authorize(
        "gov_officer_mark",
        GovAction.OVERRIDE_CIRCUIT_BREAKER,
        evidence=[
            EvidenceSubmission(
                EvidenceType.JUSTIFICATION,
                "False positive from known Unicode test string in training data response.",
                "gov_officer_mark",
            ),
            EvidenceSubmission(
                EvidenceType.RISK_ASSESSMENT,
                "Residual risk accepted: output may contain non-ASCII characters.",
                "gov_officer_mark",
            ),
            EvidenceSubmission(
                EvidenceType.SECOND_APPROVER,
                "gov_officer_mark",  # Self!
                "gov_officer_mark",
            ),
        ],
    )
    assert not decision.authorized, f"Self-approval should be blocked: {decision.reason}"
    assert "self-approval" in decision.reason.lower()
    print("PASSED")


# ======================================================================
# CHATGPT REVIEW FIXES
# ======================================================================

def test_fix11_unregistered_evidence_submitter_blocked():
    """FIX11: Evidence claiming submission by unknown operator is blocked."""
    print("TEST FIX11: Unregistered evidence submitter blocked...", end=" ")
    runtime = make_standard_runtime()
    # Evidence claims submission by "ghost_user" who is not registered
    decision = runtime.authorize(
        "analyst_jane",
        GovAction.EXECUTE_PIPELINE,
        evidence=[
            EvidenceSubmission(
                EvidenceType.RATIONALE,
                "This evidence claims to be from someone who does not exist.",
                "ghost_user",
            ),
        ],
    )
    assert not decision.authorized, "Should block on unregistered submitter"
    assert "attribution" in decision.reason.lower() or "submitter" in decision.reason.lower()
    print("PASSED")


def test_fix11_registered_evidence_submitter_passes():
    """FIX11: Evidence from a registered operator passes attribution check."""
    print("TEST FIX11b: Registered evidence submitter passes...", end=" ")
    runtime = make_standard_runtime()
    # Evidence submitted by analyst_jane (registered) about their own action
    decision = runtime.authorize(
        "analyst_jane",
        GovAction.EXECUTE_PIPELINE,
        evidence=[
            EvidenceSubmission(
                EvidenceType.RATIONALE,
                "Standard research query. Routine analysis with low risk assessment.",
                "analyst_jane",
            ),
        ],
    )
    assert decision.authorized, f"Should pass: {decision.reason}"
    print("PASSED")


def _t1b_base_evidence(submitted_by: str) -> list:
    """Common evidence for CIRCUIT_BREAKER_OVERRIDE_GATE tests (T1-B)."""
    return [
        EvidenceSubmission(
            evidence_type=EvidenceType.JUSTIFICATION,
            content="Overriding because the breach was a false positive from test data injection",
            submitted_by=submitted_by,
        ),
        EvidenceSubmission(
            evidence_type=EvidenceType.RISK_ASSESSMENT,
            content="Residual risk accepted: false positive confirmed via manual inspection",
            submitted_by=submitted_by,
        ),
    ]


def test_t1b_unsigned_second_approver_blocked():
    """T1-B: Second approver evidence without signature blocked when registry present."""
    print("TEST T1-B: Unsigned second approver blocked...", end=" ")
    from haia_agent.security import OperatorIdentity, OperatorRegistry

    registry = OperatorRegistry()
    registry.register_operator(OperatorIdentity("admin_sarah"))
    registry.register_operator(OperatorIdentity("gov_officer_mark"))

    evidence = _t1b_base_evidence("admin_sarah") + [
        EvidenceSubmission(
            evidence_type=EvidenceType.SECOND_APPROVER,
            content="gov_officer_mark",
            submitted_by="admin_sarah",
        ),
    ]

    result = CIRCUIT_BREAKER_OVERRIDE_GATE.check(
        evidence,
        requesting_operator_id="admin_sarah",
        registered_operator_ids={"admin_sarah", "gov_officer_mark"},
        operator_registry=registry,
    )
    assert not result.passed, "Should reject unsigned second approver"
    assert any("signature required" in s for s in result.insufficient), \
        f"Should mention missing signature: {result.insufficient}"
    print("PASSED")


def test_t1b_signed_second_approver_passes():
    """T1-B: Properly signed second approver evidence accepted."""
    print("TEST T1-B: Signed second approver passes...", end=" ")
    from haia_agent.security import OperatorIdentity, OperatorRegistry

    registry = OperatorRegistry()
    registry.register_operator(OperatorIdentity("admin_sarah"))
    approver_identity = OperatorIdentity("gov_officer_mark")
    registry.register_operator(approver_identity)

    approval = EvidenceSubmission(
        evidence_type=EvidenceType.SECOND_APPROVER,
        content="gov_officer_mark",
        submitted_by="admin_sarah",
    )
    approval.signature = approver_identity.sign_record(approval._signable_payload())

    evidence = _t1b_base_evidence("admin_sarah") + [approval]

    result = CIRCUIT_BREAKER_OVERRIDE_GATE.check(
        evidence,
        requesting_operator_id="admin_sarah",
        registered_operator_ids={"admin_sarah", "gov_officer_mark"},
        operator_registry=registry,
    )
    assert result.passed, f"Should accept signed approval: {result.missing} {result.insufficient}"
    print("PASSED")


def test_t1b_wrong_key_signature_rejected():
    """T1-B: Evidence signed with wrong key is rejected."""
    print("TEST T1-B: Wrong key signature rejected...", end=" ")
    from haia_agent.security import OperatorIdentity, OperatorRegistry

    registry = OperatorRegistry()
    registry.register_operator(OperatorIdentity("admin_sarah"))
    registry.register_operator(OperatorIdentity("gov_officer_mark"))

    forger = OperatorIdentity("forger_key")
    approval = EvidenceSubmission(
        evidence_type=EvidenceType.SECOND_APPROVER,
        content="gov_officer_mark",
        submitted_by="admin_sarah",
    )
    approval.signature = forger.sign_record(approval._signable_payload())

    evidence = _t1b_base_evidence("admin_sarah") + [approval]

    result = CIRCUIT_BREAKER_OVERRIDE_GATE.check(
        evidence,
        requesting_operator_id="admin_sarah",
        registered_operator_ids={"admin_sarah", "gov_officer_mark"},
        operator_registry=registry,
    )
    assert not result.passed, "Should reject forged signature"
    assert any("verification failed" in s for s in result.insufficient), \
        f"Should mention verification failure: {result.insufficient}"
    print("PASSED")


def test_t1b_no_registry_backward_compatible():
    """T1-B: Without operator_registry, string-only check still works."""
    print("TEST T1-B: Backward compatible without registry...", end=" ")

    evidence = _t1b_base_evidence("admin_sarah") + [
        EvidenceSubmission(
            evidence_type=EvidenceType.SECOND_APPROVER,
            content="gov_officer_mark",
            submitted_by="admin_sarah",
        ),
    ]

    result = CIRCUIT_BREAKER_OVERRIDE_GATE.check(
        evidence,
        requesting_operator_id="admin_sarah",
        registered_operator_ids={"admin_sarah", "gov_officer_mark"},
    )
    assert result.passed, f"Should pass without registry: {result.missing} {result.insufficient}"
    print("PASSED")


# ======================================================================
# RUN ALL TESTS
# ======================================================================

def run_all_tests():
    print("=" * 70)
    print("HAIA AGENT FRAMEWORK - GOVERNANCE RUNTIME TESTS")
    print("Enterprise governance: five enforcement layers + security hardening")
    print("=" * 70)
    print()

    tests = [
        # GOV1: Who is allowed to act
        test_gov1_registered_operator_authorized,
        test_auth1_unregistered_blocked,
        test_auth2_inactive_blocked,
        # GOV2: What they are allowed to do
        test_auth3_analyst_cannot_override,
        test_auth4_observer_cannot_execute,
        test_gov2_admin_can_do_everything,
        test_gov2_auditor_read_only,
        # GOV3: What evidence they must attach
        test_gov3_arbitration_requires_rationale,
        test_gov3_override_requires_dual_approval,
        test_gov3_evidence_gate_in_runtime,
        # GOV4: What policy must be satisfied
        test_pol1_critical_breach_blocks,
        test_pol2_warning_escalates_to_gov_officer,
        test_pol2_gov_officer_proceeds_on_warning,
        test_pol3_model2_requires_scope,
        test_pol4_override_requires_dual,
        test_pol5_injection_flood,
        # GOV5: What escalation path triggers
        test_esc1_warning_elevates,
        test_esc2_critical_triggers_high,
        test_esc3_halt_triggers_lockdown,
        test_esc4_ratchet_only_goes_up,
        test_esc5_de_escalation_requires_authority,
        test_esc6_lockdown_blocks_all,
        # GOV6: Full runtime orchestration
        test_gov6_full_happy_path,
        test_gov6_decision_log_audit,
        test_gov6_cascading_denial,
        test_gov6_escalation_callback,
        # GV1-GV12: Vulnerability hardening
        test_gv1_self_approval_blocked,
        test_gv1_phantom_approver_blocked,
        test_gv1_valid_second_approver,
        test_gv1_runtime_self_approval_integration,
        test_gv3_empty_roles_denied,
        test_gv4_analyst_cannot_modify_permissions,
        test_gv4_admin_can_modify_permissions,
        test_gv5_crashing_policy_denies,
        test_gv6_decision_log_bounded,
        test_gv7_callback_error_recorded,
        test_gv9_empty_operator_id_rejected,
        test_gv9_long_operator_id_rejected,
        test_gv10_empty_deescalation_rejected,
        test_gv11_duplicate_acknowledgment_rejected,
        test_gv12_registration_requires_authorization,
        # ChatGPT review fixes
        test_fix11_unregistered_evidence_submitter_blocked,
        test_fix11_registered_evidence_submitter_passes,
        test_t1b_unsigned_second_approver_blocked,
        test_t1b_signed_second_approver_passes,
        test_t1b_wrong_key_signature_rejected,
        test_t1b_no_registry_backward_compatible,
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
    print("GOVERNANCE ENFORCEMENT COVERAGE:")
    print("  GOV1  Who is allowed to act:              3 tests")
    print("  GOV2  What they are allowed to do:        4 tests")
    print("  GOV3  What evidence they must attach:     3 tests")
    print("  GOV4  What policy must be satisfied:      6 tests")
    print("  GOV5  What escalation path triggers:      6 tests")
    print("  GOV6  Full runtime orchestration:         4 tests")
    print()
    print("VULNERABILITY HARDENING (GV1-GV12):")
    print("  GV1   Self-approval / phantom approver:   4 tests  BLOCKED")
    print("  GV3   Empty roles privilege:              1 test   BLOCKED")
    print("  GV4   Unauth permission modification:    2 tests  BLOCKED")
    print("  GV5   Crashing policy -> fail open:       1 test   FIXED (fail closed)")
    print("  GV6   Unbounded decision log:             1 test   BOUNDED")
    print("  GV7   Silent callback failure:            1 test   RECORDED")
    print("  GV9   Invalid operator ID format:         2 tests  VALIDATED")
    print("  GV10  Empty de-escalation justification:  1 test   BLOCKED")
    print("  GV11  Duplicate acknowledgment:           1 test   BLOCKED")
    print("  GV12  Unauth operator registration:       1 test   GATED")
    print()
    print("CHATGPT REVIEW FIXES:")
    print("  FIX11 Evidence submitter enforcement:      2 tests  BLOCKED on unregistered")
    print()
    print("MULTI-AI REVIEW FIXES:")
    print("  T1-B  Signed second approver:              4 tests  SIGNATURE verified")
    print("=" * 70)
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
