"""
HAIA Agent Framework - Governance Runtime
============================================
Enterprise governance is runtime enforcement.

Five requirements, enforced at execution time:

    1. WHO is allowed to act.
       Role-based authorization. Not just "registered" but "permitted
       for this action in this context." An analyst can execute queries.
       Only a governance officer can override a circuit breaker halt.
       Only an administrator can modify platform rotation.

    2. WHAT they are allowed to do.
       Action authorization. Each operator role carries a permission
       set. Permissions are bound to specific pipeline actions, not
       broad access levels. The permission check is a set membership
       test (deterministic, non-cognitive).

    3. WHAT evidence they must attach.
       Mandatory evidence gates. Before execution proceeds past a
       checkpoint, the required evidence must be present. An
       arbitration decision requires rationale text. A circuit breaker
       override requires a justification and a second approver.
       Evidence requirements are configurable per operating model.

    4. WHAT policy must be satisfied before execution.
       Pre-execution policy evaluation. Policies are deterministic
       rules: "Model 2 requires human arbitration at every checkpoint,"
       "transactions touching financial data require two approvers,"
       "breach severity WARNING or above requires governance officer
       review." Policies are evaluated before the action proceeds.

    5. WHAT escalation path triggers when risk changes.
       Dynamic escalation. When breach severity increases, when
       injection count crosses a threshold, when a platform fails
       repeatedly, the governance runtime escalates: changes the
       operating model, requires additional approvers, notifies
       higher authority, or halts the pipeline.

Non-cognitive constraint maintained:
    Every check is set membership, threshold comparison, counter
    evaluation, or string matching. No check evaluates the meaning
    of any AI-generated content. The governance runtime enforces
    structural rules about who, what, and when. It never decides
    whether content is correct.

Author: Basil C. Puglisi, MPA
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Callable

from .breach import BreachReport, BreachSeverity
from .models import OperatingModel, RECCLINRole


# ======================================================================
# 1. WHO IS ALLOWED TO ACT
# ======================================================================

class OperatorRole(str, Enum):
    """
    Roles an operator can hold in the governance hierarchy.

    This is not a job title. It is a permission boundary.
    An operator may hold multiple roles.
    """
    ANALYST = "analyst"
    GOVERNANCE_OFFICER = "governance_officer"
    ADMINISTRATOR = "administrator"
    AUDITOR = "auditor"
    OBSERVER = "observer"


@dataclass
class OperatorProfile:
    """
    An operator's identity, roles, and authorization context.

    Extends the existing OperatorIdentity (which handles signing keys)
    with role-based authorization. The signing key proves identity.
    The profile determines what that identity is permitted to do.
    """
    operator_id: str
    roles: set[OperatorRole] = field(default_factory=set)
    department: str = ""
    clearance_level: int = 0  # 0=none, 1=standard, 2=elevated, 3=full
    active: bool = True
    registered_at: str = ""
    last_action_at: str = ""

    def __post_init__(self):
        if not self.registered_at:
            self.registered_at = datetime.now(timezone.utc).isoformat()
        # GV9: Validate operator_id format
        if not self.operator_id or not self.operator_id.strip():
            raise ValueError("operator_id cannot be empty or whitespace")
        if len(self.operator_id) > 128:
            raise ValueError("operator_id exceeds 128 character limit")

    def has_role(self, role: OperatorRole) -> bool:
        return role in self.roles

    def has_any_role(self, roles: set[OperatorRole]) -> bool:
        return bool(self.roles & roles)

    def update_last_action(self) -> None:
        self.last_action_at = datetime.now(timezone.utc).isoformat()


# ======================================================================
# 2. WHAT THEY ARE ALLOWED TO DO
# ======================================================================

class GovAction(str, Enum):
    """
    Enumeration of every governable action in the pipeline.

    Each action maps to a specific pipeline operation that
    requires authorization before execution.
    """
    EXECUTE_PIPELINE = "execute_pipeline"
    RECORD_ARBITRATION = "record_arbitration"
    OVERRIDE_CIRCUIT_BREAKER = "override_circuit_breaker"
    MODIFY_PLATFORM_ROTATION = "modify_platform_rotation"
    EXPORT_AUDIT_TRAIL = "export_audit_trail"
    REGISTER_OPERATOR = "register_operator"
    MODIFY_POLICY = "modify_policy"
    VIEW_BREACH_REPORT = "view_breach_report"
    ESCALATE_OPERATING_MODEL = "escalate_operating_model"
    ACKNOWLEDGE_BREACH = "acknowledge_breach"


# Default permission matrix: which roles can perform which actions
DEFAULT_PERMISSIONS: dict[OperatorRole, set[GovAction]] = {
    OperatorRole.ANALYST: {
        GovAction.EXECUTE_PIPELINE,
        GovAction.RECORD_ARBITRATION,
        GovAction.VIEW_BREACH_REPORT,
    },
    OperatorRole.GOVERNANCE_OFFICER: {
        GovAction.EXECUTE_PIPELINE,
        GovAction.RECORD_ARBITRATION,
        GovAction.OVERRIDE_CIRCUIT_BREAKER,
        GovAction.VIEW_BREACH_REPORT,
        GovAction.ESCALATE_OPERATING_MODEL,
        GovAction.ACKNOWLEDGE_BREACH,
    },
    OperatorRole.ADMINISTRATOR: {
        GovAction.EXECUTE_PIPELINE,
        GovAction.RECORD_ARBITRATION,
        GovAction.OVERRIDE_CIRCUIT_BREAKER,
        GovAction.MODIFY_PLATFORM_ROTATION,
        GovAction.EXPORT_AUDIT_TRAIL,
        GovAction.REGISTER_OPERATOR,
        GovAction.MODIFY_POLICY,
        GovAction.VIEW_BREACH_REPORT,
        GovAction.ESCALATE_OPERATING_MODEL,
        GovAction.ACKNOWLEDGE_BREACH,
    },
    OperatorRole.AUDITOR: {
        GovAction.VIEW_BREACH_REPORT,
        GovAction.EXPORT_AUDIT_TRAIL,
    },
    OperatorRole.OBSERVER: {
        GovAction.VIEW_BREACH_REPORT,
    },
}


@dataclass
class AuthorizationResult:
    """Result of an authorization check."""
    authorized: bool
    operator_id: str
    action: GovAction
    reason: str
    checked_at: str = ""
    required_roles: set[OperatorRole] = field(default_factory=set)
    operator_roles: set[OperatorRole] = field(default_factory=set)

    def __post_init__(self):
        if not self.checked_at:
            self.checked_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {
            "authorized": self.authorized,
            "operator_id": self.operator_id,
            "action": self.action.value,
            "reason": self.reason,
            "checked_at": self.checked_at,
            "required_roles": [r.value for r in self.required_roles],
            "operator_roles": [r.value for r in self.operator_roles],
        }


class Authorizer:
    """
    Determines whether an operator is permitted to perform an action.

    The check is set membership: does the operator's role set
    intersect with the set of roles permitted for this action?

    This is a deterministic, non-cognitive operation.
    """

    def __init__(
        self,
        permissions: Optional[dict[OperatorRole, set[GovAction]]] = None,
    ):
        self._permissions = permissions or dict(DEFAULT_PERMISSIONS)
        # Build reverse index: action -> set of roles that can perform it
        self._action_roles: dict[GovAction, set[OperatorRole]] = {}
        for role, actions in self._permissions.items():
            for action in actions:
                if action not in self._action_roles:
                    self._action_roles[action] = set()
                self._action_roles[action].add(role)

    def check(self, profile: OperatorProfile, action: GovAction) -> AuthorizationResult:
        """
        Check whether an operator is authorized for an action.

        Returns AuthorizationResult with the decision and evidence.
        """
        if not profile.active:
            return AuthorizationResult(
                authorized=False,
                operator_id=profile.operator_id,
                action=action,
                reason=f"Operator '{profile.operator_id}' is inactive.",
                operator_roles=profile.roles,
            )

        required_roles = self._action_roles.get(action, set())
        if not required_roles:
            return AuthorizationResult(
                authorized=False,
                operator_id=profile.operator_id,
                action=action,
                reason=f"Action '{action.value}' has no authorized roles configured.",
                required_roles=required_roles,
                operator_roles=profile.roles,
            )

        if profile.has_any_role(required_roles):
            profile.update_last_action()
            return AuthorizationResult(
                authorized=True,
                operator_id=profile.operator_id,
                action=action,
                reason=f"Authorized via role(s): "
                       f"{', '.join(r.value for r in profile.roles & required_roles)}",
                required_roles=required_roles,
                operator_roles=profile.roles,
            )

        return AuthorizationResult(
            authorized=False,
            operator_id=profile.operator_id,
            action=action,
            reason=(
                f"Operator '{profile.operator_id}' lacks required role(s). "
                f"Has: {', '.join(r.value for r in profile.roles)}. "
                f"Needs one of: {', '.join(r.value for r in required_roles)}."
            ),
            required_roles=required_roles,
            operator_roles=profile.roles,
        )

    def grant_action(self, role: OperatorRole, action: GovAction) -> None:
        """Add a permission (administrator action, requires MODIFY_POLICY)."""
        if role not in self._permissions:
            self._permissions[role] = set()
        self._permissions[role].add(action)
        if action not in self._action_roles:
            self._action_roles[action] = set()
        self._action_roles[action].add(role)

    def revoke_action(self, role: OperatorRole, action: GovAction) -> None:
        """Remove a permission."""
        if role in self._permissions:
            self._permissions[role].discard(action)
        if action in self._action_roles:
            self._action_roles[action].discard(role)


# ======================================================================
# 3. WHAT EVIDENCE THEY MUST ATTACH
# ======================================================================

class EvidenceType(str, Enum):
    """Types of evidence that can be required at a governance gate."""
    RATIONALE = "rationale"           # Text explaining why
    SECOND_APPROVER = "second_approver"  # Another operator's ID
    RISK_ASSESSMENT = "risk_assessment"  # Explicit risk statement
    REFERENCE_ID = "reference_id"     # Link to external record (ticket, case)
    JUSTIFICATION = "justification"   # Why an override is warranted
    SCOPE_STATEMENT = "scope_statement"  # What this transaction covers
    EXPIRY_ACKNOWLEDGED = "expiry_acknowledged"  # Time-sensitive info accepted


@dataclass
class EvidenceRequirement:
    """A single evidence requirement for a governance gate."""
    evidence_type: EvidenceType
    description: str
    mandatory: bool = True
    min_length: int = 10  # Minimum character count (prevents empty submissions)


@dataclass
class EvidenceSubmission:
    """Evidence attached by an operator at a governance gate."""
    evidence_type: EvidenceType
    content: str
    submitted_by: str
    submitted_at: str = ""
    # T1-B: Cryptographic signature for evidence requiring proof of consent.
    # For SECOND_APPROVER evidence, this must be an HMAC-SHA256 signature
    # produced by the approving operator's signing key over the approval
    # payload. Without this, the gate accepts a bare operator ID string
    # as approval, which can be spoofed by any operator who knows the ID.
    signature: str = ""

    def __post_init__(self):
        if not self.submitted_at:
            self.submitted_at = datetime.now(timezone.utc).isoformat()

    def _signable_payload(self) -> dict:
        """Produce the dict that should be signed for verification."""
        return {
            "evidence_type": self.evidence_type.value,
            "content": self.content.strip(),
            "submitted_by": self.submitted_by,
        }


@dataclass
class EvidenceGateResult:
    """Result of an evidence gate check."""
    passed: bool
    gate_name: str
    requirements: list[EvidenceRequirement]
    submissions: list[EvidenceSubmission]
    missing: list[str] = field(default_factory=list)
    insufficient: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "passed": self.passed,
            "gate_name": self.gate_name,
            "requirements_count": len(self.requirements),
            "submissions_count": len(self.submissions),
            "missing": self.missing,
            "insufficient": self.insufficient,
        }


class EvidenceGate:
    """
    Enforces evidence requirements at a governance checkpoint.

    The gate checks:
        1. All mandatory evidence types are present
        2. Each submission meets minimum length
        3. Each submission is attributed to a registered operator
        4. SECOND_APPROVER evidence refers to a different operator

    The gate does NOT evaluate evidence quality. It checks presence,
    attribution, and minimum substance (length). Whether the rationale
    is good is the reviewing human's judgment.
    """

    def __init__(self, gate_name: str, requirements: list[EvidenceRequirement]):
        self.gate_name = gate_name
        self.requirements = requirements

    def check(
        self,
        submissions: list[EvidenceSubmission],
        requesting_operator_id: str = "",
        registered_operator_ids: Optional[set[str]] = None,
        operator_registry: Optional[object] = None,
    ) -> EvidenceGateResult:
        """
        Evaluate submitted evidence against requirements.

        Args:
            submissions: Evidence attached by the operator
            requesting_operator_id: The operator requesting the action.
                Used to prevent self-approval on SECOND_APPROVER evidence.
            registered_operator_ids: Set of valid operator IDs.
                Used to verify SECOND_APPROVER refers to a real operator.
            operator_registry: Optional OperatorRegistry for cryptographic
                signature verification on SECOND_APPROVER evidence (T1-B).
                When provided, the second approver must have signed the
                evidence payload with their HMAC key, proving actual consent.

        Returns EvidenceGateResult with pass/fail and specifics.
        """
        submitted_types = {s.evidence_type for s in submissions}
        submission_map = {s.evidence_type: s for s in submissions}

        missing = []
        insufficient = []

        for req in self.requirements:
            if req.mandatory and req.evidence_type not in submitted_types:
                missing.append(
                    f"{req.evidence_type.value}: {req.description}"
                )
                continue

            if req.evidence_type in submission_map:
                sub = submission_map[req.evidence_type]
                if len(sub.content.strip()) < req.min_length:
                    insufficient.append(
                        f"{req.evidence_type.value}: requires {req.min_length}+ chars, "
                        f"got {len(sub.content.strip())}"
                    )
                    continue

                # GV1: SECOND_APPROVER must be a different, registered operator
                if req.evidence_type == EvidenceType.SECOND_APPROVER:
                    approver_id = sub.content.strip()
                    if requesting_operator_id and approver_id == requesting_operator_id:
                        insufficient.append(
                            f"{req.evidence_type.value}: second approver cannot be "
                            f"the requesting operator (self-approval blocked)"
                        )
                    elif registered_operator_ids and approver_id not in registered_operator_ids:
                        insufficient.append(
                            f"{req.evidence_type.value}: '{approver_id}' is not a "
                            f"registered operator"
                        )
                    # T1-B: Cryptographic proof of second approver consent.
                    # When operator_registry is available, require HMAC
                    # signature from the approving operator. Without this,
                    # any operator could claim another operator approved
                    # by entering their ID string.
                    elif operator_registry is not None:
                        if not sub.signature:
                            insufficient.append(
                                f"{req.evidence_type.value}: cryptographic "
                                f"signature required from second approver "
                                f"but not provided"
                            )
                        else:
                            approver_identity = operator_registry.get_operator(
                                approver_id
                            )
                            if approver_identity is None:
                                insufficient.append(
                                    f"{req.evidence_type.value}: approver "
                                    f"'{approver_id}' has no signing key "
                                    f"in operator registry"
                                )
                            elif not approver_identity.verify_signature(
                                sub._signable_payload(), sub.signature
                            ):
                                insufficient.append(
                                    f"{req.evidence_type.value}: approver "
                                    f"signature verification failed "
                                    f"(consent not cryptographically proven)"
                                )

        passed = len(missing) == 0 and len(insufficient) == 0
        return EvidenceGateResult(
            passed=passed,
            gate_name=self.gate_name,
            requirements=self.requirements,
            submissions=submissions,
            missing=missing,
            insufficient=insufficient,
        )


# ======================================================================
# Pre-built evidence gates for common governance scenarios
# ======================================================================

ARBITRATION_GATE = EvidenceGate(
    gate_name="arbitration",
    requirements=[
        EvidenceRequirement(
            EvidenceType.RATIONALE,
            "Explanation of the arbitration decision (approve/modify/reject)",
            mandatory=True,
            min_length=20,
        ),
    ],
)

CIRCUIT_BREAKER_OVERRIDE_GATE = EvidenceGate(
    gate_name="circuit_breaker_override",
    requirements=[
        EvidenceRequirement(
            EvidenceType.JUSTIFICATION,
            "Why overriding the circuit breaker halt is warranted",
            mandatory=True,
            min_length=50,
        ),
        EvidenceRequirement(
            EvidenceType.RISK_ASSESSMENT,
            "Explicit statement of residual risk accepted by proceeding",
            mandatory=True,
            min_length=30,
        ),
        EvidenceRequirement(
            EvidenceType.SECOND_APPROVER,
            "ID of a second governance officer approving the override",
            mandatory=True,
            min_length=3,
        ),
    ],
)

MODEL_ESCALATION_GATE = EvidenceGate(
    gate_name="model_escalation",
    requirements=[
        EvidenceRequirement(
            EvidenceType.JUSTIFICATION,
            "Why changing the operating model is warranted",
            mandatory=True,
            min_length=30,
        ),
    ],
)

EXECUTION_GATE_MODEL_2 = EvidenceGate(
    gate_name="execution_model_2",
    requirements=[
        EvidenceRequirement(
            EvidenceType.SCOPE_STATEMENT,
            "What this transaction covers and its intended use",
            mandatory=True,
            min_length=10,
        ),
    ],
)


# ======================================================================
# 4. WHAT POLICY MUST BE SATISFIED BEFORE EXECUTION
# ======================================================================

class PolicyVerdict(str, Enum):
    """Result of a policy evaluation."""
    ALLOW = "allow"
    DENY = "deny"
    ESCALATE = "escalate"


@dataclass
class PolicyResult:
    """Result of evaluating a single policy."""
    policy_name: str
    verdict: PolicyVerdict
    reason: str
    evaluated_at: str = ""

    def __post_init__(self):
        if not self.evaluated_at:
            self.evaluated_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {
            "policy_name": self.policy_name,
            "verdict": self.verdict.value,
            "reason": self.reason,
            "evaluated_at": self.evaluated_at,
        }


@dataclass
class PolicyEvaluationResult:
    """Aggregated result of all policy evaluations for an action."""
    overall_verdict: PolicyVerdict
    results: list[PolicyResult] = field(default_factory=list)
    blocking_policies: list[str] = field(default_factory=list)
    escalation_policies: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "overall_verdict": self.overall_verdict.value,
            "results": [r.to_dict() for r in self.results],
            "blocking_policies": self.blocking_policies,
            "escalation_policies": self.escalation_policies,
        }


@dataclass
class GovernanceContext:
    """
    The runtime context against which policies are evaluated.

    This is everything the policy engine knows at decision time.
    It is assembled from the pipeline state, breach report, operator
    profile, and transaction metadata. The policies evaluate this
    context, not AI-generated content.
    """
    operator: OperatorProfile
    action: GovAction
    operating_model: Optional[OperatingModel] = None
    recclin_role: Optional[RECCLINRole] = None
    breach_severity: BreachSeverity = BreachSeverity.NOMINAL
    breach_event_count: int = 0
    injection_count: int = 0
    platform_failure_count: int = 0
    transaction_count_today: int = 0
    evidence_submitted: list[EvidenceSubmission] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)


class Policy:
    """
    A single governance policy.

    A policy is a named function that evaluates a GovernanceContext
    and returns a PolicyResult. The function contains deterministic
    logic only: threshold comparisons, set membership tests, counter
    evaluations. No content evaluation.

    Policies compose. The PolicyEngine evaluates all applicable
    policies and aggregates the results. A single DENY blocks.
    A single ESCALATE triggers escalation unless overridden by DENY.
    """

    def __init__(
        self,
        name: str,
        description: str,
        evaluate_fn: Callable[[GovernanceContext], PolicyResult],
        applies_to: Optional[set[GovAction]] = None,
    ):
        self.name = name
        self.description = description
        self._evaluate = evaluate_fn
        self.applies_to = applies_to  # None means applies to all actions

    def evaluate(self, context: GovernanceContext) -> PolicyResult:
        """Evaluate this policy against the given context."""
        if self.applies_to and context.action not in self.applies_to:
            return PolicyResult(
                policy_name=self.name,
                verdict=PolicyVerdict.ALLOW,
                reason="Policy not applicable to this action.",
            )
        return self._evaluate(context)


class PolicyEngine:
    """
    Evaluates all registered policies against a governance context.

    Aggregation rules:
        - Any DENY -> overall DENY (single veto blocks)
        - Any ESCALATE (with no DENY) -> overall ESCALATE
        - All ALLOW -> overall ALLOW

    The engine is a loop over deterministic functions.
    """

    def __init__(self):
        self._policies: list[Policy] = []

    def register_policy(self, policy: Policy) -> None:
        """Register a policy for evaluation."""
        self._policies.append(policy)

    def evaluate(self, context: GovernanceContext) -> PolicyEvaluationResult:
        """
        Evaluate all registered policies against the context.

        GV5: If a policy function raises an exception, the result
        is treated as DENY with the exception recorded. A crashing
        policy must never produce ALLOW.
        """
        results = []
        blocking = []
        escalating = []

        for policy in self._policies:
            try:
                result = policy.evaluate(context)
            except Exception as exc:
                # GV5: Exception in policy -> DENY (fail closed)
                result = PolicyResult(
                    policy_name=policy.name,
                    verdict=PolicyVerdict.DENY,
                    reason=f"Policy raised exception: {type(exc).__name__}: {exc}",
                )
            results.append(result)
            if result.verdict == PolicyVerdict.DENY:
                blocking.append(policy.name)
            elif result.verdict == PolicyVerdict.ESCALATE:
                escalating.append(policy.name)

        if blocking:
            overall = PolicyVerdict.DENY
        elif escalating:
            overall = PolicyVerdict.ESCALATE
        else:
            overall = PolicyVerdict.ALLOW

        return PolicyEvaluationResult(
            overall_verdict=overall,
            results=results,
            blocking_policies=blocking,
            escalation_policies=escalating,
        )

    @property
    def policy_count(self) -> int:
        return len(self._policies)


# ======================================================================
# Pre-built policies
# ======================================================================

def _policy_breach_blocks_execution(ctx: GovernanceContext) -> PolicyResult:
    """CRITICAL or HALT breach severity blocks pipeline execution."""
    if ctx.breach_severity in (BreachSeverity.CRITICAL, BreachSeverity.HALT):
        return PolicyResult(
            policy_name="breach_blocks_execution",
            verdict=PolicyVerdict.DENY,
            reason=(
                f"Breach severity {ctx.breach_severity.value} blocks execution. "
                f"Resolve breach before proceeding."
            ),
        )
    return PolicyResult(
        policy_name="breach_blocks_execution",
        verdict=PolicyVerdict.ALLOW,
        reason="Breach severity within acceptable range.",
    )

POLICY_BREACH_BLOCKS_EXECUTION = Policy(
    name="breach_blocks_execution",
    description="CRITICAL or HALT breach severity blocks pipeline execution.",
    evaluate_fn=_policy_breach_blocks_execution,
    applies_to={GovAction.EXECUTE_PIPELINE},
)


def _policy_warning_requires_gov_officer(ctx: GovernanceContext) -> PolicyResult:
    """WARNING breach severity requires governance officer for execution."""
    if ctx.breach_severity == BreachSeverity.WARNING:
        if not ctx.operator.has_role(OperatorRole.GOVERNANCE_OFFICER):
            return PolicyResult(
                policy_name="warning_requires_gov_officer",
                verdict=PolicyVerdict.ESCALATE,
                reason=(
                    "Breach severity WARNING requires a governance officer "
                    "to authorize continued execution."
                ),
            )
    return PolicyResult(
        policy_name="warning_requires_gov_officer",
        verdict=PolicyVerdict.ALLOW,
        reason="No escalation required for current breach severity and operator role.",
    )

POLICY_WARNING_REQUIRES_GOV_OFFICER = Policy(
    name="warning_requires_gov_officer",
    description="WARNING breach requires governance officer authorization.",
    evaluate_fn=_policy_warning_requires_gov_officer,
    applies_to={GovAction.EXECUTE_PIPELINE},
)


def _policy_model2_requires_evidence(ctx: GovernanceContext) -> PolicyResult:
    """Model 2 execution requires scope statement evidence."""
    if ctx.operating_model == OperatingModel.MODEL_2:
        has_scope = any(
            e.evidence_type == EvidenceType.SCOPE_STATEMENT
            for e in ctx.evidence_submitted
        )
        if not has_scope:
            return PolicyResult(
                policy_name="model2_requires_evidence",
                verdict=PolicyVerdict.DENY,
                reason="Model 2 (Agent AI Governance) execution requires a scope statement.",
            )
    return PolicyResult(
        policy_name="model2_requires_evidence",
        verdict=PolicyVerdict.ALLOW,
        reason="Evidence requirements satisfied.",
    )

POLICY_MODEL2_REQUIRES_EVIDENCE = Policy(
    name="model2_requires_evidence",
    description="Model 2 execution requires scope statement evidence.",
    evaluate_fn=_policy_model2_requires_evidence,
    applies_to={GovAction.EXECUTE_PIPELINE},
)


def _policy_override_requires_dual_approval(ctx: GovernanceContext) -> PolicyResult:
    """Circuit breaker override requires dual approval evidence."""
    has_justification = any(
        e.evidence_type == EvidenceType.JUSTIFICATION
        for e in ctx.evidence_submitted
    )
    has_second = any(
        e.evidence_type == EvidenceType.SECOND_APPROVER
        for e in ctx.evidence_submitted
    )
    if not (has_justification and has_second):
        missing = []
        if not has_justification:
            missing.append("justification")
        if not has_second:
            missing.append("second approver")
        return PolicyResult(
            policy_name="override_requires_dual_approval",
            verdict=PolicyVerdict.DENY,
            reason=f"Circuit breaker override missing: {', '.join(missing)}.",
        )
    return PolicyResult(
        policy_name="override_requires_dual_approval",
        verdict=PolicyVerdict.ALLOW,
        reason="Override evidence requirements satisfied.",
    )

POLICY_OVERRIDE_REQUIRES_DUAL_APPROVAL = Policy(
    name="override_requires_dual_approval",
    description="Circuit breaker override requires justification and second approver.",
    evaluate_fn=_policy_override_requires_dual_approval,
    applies_to={GovAction.OVERRIDE_CIRCUIT_BREAKER},
)


def _policy_injection_threshold_escalates(ctx: GovernanceContext) -> PolicyResult:
    """High injection count escalates to governance officer review."""
    if ctx.injection_count >= 3:
        return PolicyResult(
            policy_name="injection_threshold_escalates",
            verdict=PolicyVerdict.ESCALATE,
            reason=(
                f"Injection count ({ctx.injection_count}) exceeds threshold. "
                f"Governance officer review required."
            ),
        )
    return PolicyResult(
        policy_name="injection_threshold_escalates",
        verdict=PolicyVerdict.ALLOW,
        reason="Injection count within acceptable range.",
    )

POLICY_INJECTION_THRESHOLD_ESCALATES = Policy(
    name="injection_threshold_escalates",
    description="3+ injection detections triggers escalation to governance officer.",
    evaluate_fn=_policy_injection_threshold_escalates,
    applies_to={GovAction.EXECUTE_PIPELINE, GovAction.RECORD_ARBITRATION},
)


# ======================================================================
# 5. WHAT ESCALATION PATH TRIGGERS WHEN RISK CHANGES
# ======================================================================

class EscalationLevel(str, Enum):
    """Escalation tiers for governance response to changing risk."""
    NORMAL = "normal"          # Standard operation
    ELEVATED = "elevated"      # Additional review required
    HIGH = "high"              # Governance officer required
    CRITICAL = "critical"      # Pipeline pauses, administrator notified
    LOCKDOWN = "lockdown"      # All execution suspended pending review


@dataclass
class EscalationState:
    """Current escalation state of the governance runtime."""
    level: EscalationLevel = EscalationLevel.NORMAL
    reason: str = ""
    escalated_at: str = ""
    escalated_by: str = ""  # "system" or operator_id
    required_role_for_action: OperatorRole = OperatorRole.ANALYST
    acknowledgments: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "level": self.level.value,
            "reason": self.reason,
            "escalated_at": self.escalated_at,
            "escalated_by": self.escalated_by,
            "required_role_for_action": self.required_role_for_action.value,
            "acknowledgments": self.acknowledgments,
        }


@dataclass
class EscalationRule:
    """
    A rule that triggers escalation based on runtime conditions.

    Each rule is a deterministic test: compare a counter or
    severity against a threshold. If the test passes, escalation
    triggers.
    """
    name: str
    description: str
    target_level: EscalationLevel
    condition: Callable[[GovernanceContext], bool]
    required_role: OperatorRole = OperatorRole.GOVERNANCE_OFFICER


class EscalationEngine:
    """
    Evaluates runtime conditions and determines escalation level.

    The engine processes all rules and returns the highest
    triggered escalation level. Escalation only goes up, never
    down, without explicit acknowledgment from an authorized
    operator.

    The engine maintains state across transactions within
    a session. Escalation persists until explicitly de-escalated.
    """

    def __init__(self):
        self._rules: list[EscalationRule] = []
        self._state = EscalationState()
        self._callbacks: list[Callable[[EscalationState], None]] = []
        self._history: list[EscalationState] = []
        self._callback_errors: list[str] = []  # GV7: Record callback failures

    @property
    def current_state(self) -> EscalationState:
        return self._state

    @property
    def callback_errors(self) -> list[str]:
        """GV7: Retrieve callback error log for audit."""
        return list(self._callback_errors)

    def register_rule(self, rule: EscalationRule) -> None:
        """Register an escalation rule."""
        self._rules.append(rule)

    def register_callback(self, callback: Callable[[EscalationState], None]) -> None:
        """Register a callback for escalation events."""
        self._callbacks.append(callback)

    def evaluate(self, context: GovernanceContext) -> EscalationState:
        """
        Evaluate all rules against current context.

        Returns the new escalation state. If any rule triggers
        a higher level than the current state, the state is
        escalated. The state never decreases without explicit
        de-escalation.
        """
        level_order = [
            EscalationLevel.NORMAL,
            EscalationLevel.ELEVATED,
            EscalationLevel.HIGH,
            EscalationLevel.CRITICAL,
            EscalationLevel.LOCKDOWN,
        ]

        current_index = level_order.index(self._state.level)
        triggered_level = self._state.level
        triggered_reason = self._state.reason
        triggered_role = self._state.required_role_for_action

        for rule in self._rules:
            if rule.condition(context):
                rule_index = level_order.index(rule.target_level)
                if rule_index > level_order.index(triggered_level):
                    triggered_level = rule.target_level
                    triggered_reason = f"{rule.name}: {rule.description}"
                    triggered_role = rule.required_role

        if level_order.index(triggered_level) > current_index:
            new_state = EscalationState(
                level=triggered_level,
                reason=triggered_reason,
                escalated_at=datetime.now(timezone.utc).isoformat(),
                escalated_by="system",
                required_role_for_action=triggered_role,
            )
            self._history.append(self._state)
            self._state = new_state

            for cb in self._callbacks:
                try:
                    cb(new_state)
                except Exception as exc:
                    # GV7: Record callback failures. A failing callback
                    # must not prevent escalation from taking effect.
                    self._callback_errors.append(
                        f"{type(exc).__name__}: {exc}"
                    )

        return self._state

    def de_escalate(
        self,
        operator: OperatorProfile,
        target_level: EscalationLevel,
        justification: str,
    ) -> bool:
        """
        De-escalate to a lower level.

        Requires GOVERNANCE_OFFICER or ADMINISTRATOR role.
        Returns True if de-escalation succeeded.
        """
        if not operator.has_any_role({
            OperatorRole.GOVERNANCE_OFFICER,
            OperatorRole.ADMINISTRATOR,
        }):
            return False

        level_order = [
            EscalationLevel.NORMAL,
            EscalationLevel.ELEVATED,
            EscalationLevel.HIGH,
            EscalationLevel.CRITICAL,
            EscalationLevel.LOCKDOWN,
        ]

        if level_order.index(target_level) >= level_order.index(self._state.level):
            return False  # Can only go down

        self._history.append(self._state)
        self._state = EscalationState(
            level=target_level,
            reason=f"De-escalated by {operator.operator_id}: {justification}",
            escalated_at=datetime.now(timezone.utc).isoformat(),
            escalated_by=operator.operator_id,
            required_role_for_action=(
                OperatorRole.ANALYST if target_level == EscalationLevel.NORMAL
                else OperatorRole.GOVERNANCE_OFFICER
            ),
        )
        return True

    def acknowledge(self, operator: OperatorProfile) -> bool:
        """
        Record that an authorized operator has acknowledged the escalation.

        GV11: Duplicate acknowledgments from the same operator are
        rejected. Each operator can acknowledge once per escalation state.
        """
        if not operator.has_any_role({
            OperatorRole.GOVERNANCE_OFFICER,
            OperatorRole.ADMINISTRATOR,
        }):
            return False
        if operator.operator_id in self._state.acknowledgments:
            return False  # GV11: Already acknowledged
        self._state.acknowledgments.append(operator.operator_id)
        return True

    @property
    def history(self) -> list[EscalationState]:
        return list(self._history)


# ======================================================================
# Pre-built escalation rules
# ======================================================================

RULE_BREACH_WARNING_ELEVATES = EscalationRule(
    name="breach_warning_elevates",
    description="WARNING breach severity elevates governance posture.",
    target_level=EscalationLevel.ELEVATED,
    condition=lambda ctx: ctx.breach_severity == BreachSeverity.WARNING,
    required_role=OperatorRole.GOVERNANCE_OFFICER,
)

RULE_BREACH_CRITICAL_HIGH = EscalationRule(
    name="breach_critical_high",
    description="CRITICAL breach severity triggers HIGH escalation.",
    target_level=EscalationLevel.HIGH,
    condition=lambda ctx: ctx.breach_severity == BreachSeverity.CRITICAL,
    required_role=OperatorRole.GOVERNANCE_OFFICER,
)

RULE_BREACH_HALT_LOCKDOWN = EscalationRule(
    name="breach_halt_lockdown",
    description="HALT breach severity triggers LOCKDOWN.",
    target_level=EscalationLevel.LOCKDOWN,
    condition=lambda ctx: ctx.breach_severity == BreachSeverity.HALT,
    required_role=OperatorRole.ADMINISTRATOR,
)

RULE_INJECTION_FLOOD_CRITICAL = EscalationRule(
    name="injection_flood_critical",
    description="5+ injection detections in a transaction triggers CRITICAL.",
    target_level=EscalationLevel.CRITICAL,
    condition=lambda ctx: ctx.injection_count >= 5,
    required_role=OperatorRole.GOVERNANCE_OFFICER,
)

RULE_PLATFORM_FAILURE_ELEVATED = EscalationRule(
    name="platform_failure_elevated",
    description="2+ platform failures elevates governance posture.",
    target_level=EscalationLevel.ELEVATED,
    condition=lambda ctx: ctx.platform_failure_count >= 2,
    required_role=OperatorRole.GOVERNANCE_OFFICER,
)


# ======================================================================
# Governance Runtime (the orchestrator)
# ======================================================================

@dataclass
class GovernanceDecision:
    """
    The complete governance decision for a pipeline action.

    This is the record of what the governance runtime decided
    and why. It becomes part of the audit trail.
    """
    action: GovAction
    operator_id: str
    authorized: bool
    policy_verdict: PolicyVerdict
    escalation_level: EscalationLevel
    evidence_gate_passed: bool
    reason: str
    authorization_result: Optional[AuthorizationResult] = None
    policy_result: Optional[PolicyEvaluationResult] = None
    evidence_result: Optional[EvidenceGateResult] = None
    escalation_state: Optional[EscalationState] = None
    decided_at: str = ""

    def __post_init__(self):
        if not self.decided_at:
            self.decided_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        d = {
            "action": self.action.value,
            "operator_id": self.operator_id,
            "authorized": self.authorized,
            "policy_verdict": self.policy_verdict.value,
            "escalation_level": self.escalation_level.value,
            "evidence_gate_passed": self.evidence_gate_passed,
            "reason": self.reason,
            "decided_at": self.decided_at,
        }
        if self.authorization_result:
            d["authorization"] = self.authorization_result.to_dict()
        if self.policy_result:
            d["policy"] = self.policy_result.to_dict()
        if self.evidence_result:
            d["evidence"] = self.evidence_result.to_dict()
        if self.escalation_state:
            d["escalation"] = self.escalation_state.to_dict()
        return d


class GovernanceRuntime:
    """
    The enterprise governance enforcement layer.

    Orchestrates all five governance requirements into a single
    pre-execution check. Before any pipeline action proceeds,
    it must pass through the runtime:

        decision = runtime.authorize(operator, action, context, evidence)
        if not decision.authorized:
            # Action blocked. Reason in decision.reason.

    The runtime evaluates in order:
        1. Authorization (who is allowed to act)
        2. Escalation (has risk changed the rules)
        3. Policy (are preconditions satisfied)
        4. Evidence (is required documentation attached)

    Any failure at any layer blocks the action. The decision
    record captures every layer's result for the audit trail.

    Security hardening (GV1-GV12):
        GV1:  Second approver cannot be the requesting operator
        GV2:  Evidence submitter verified against operator identity
        GV4:  Permission modifications require MODIFY_POLICY authorization
        GV8:  Caller-supplied context validated with warnings
        GV10: De-escalation requires evidence (justification minimum)
        GV11: Acknowledgment deduplication
        GV12: Profile registration requires REGISTER_OPERATOR authorization
    """

    def __init__(
        self,
        authorizer: Optional[Authorizer] = None,
        policy_engine: Optional[PolicyEngine] = None,
        escalation_engine: Optional[EscalationEngine] = None,
        max_decision_log: int = 10000,
        operator_registry: Optional[object] = None,
    ):
        self._profiles: dict[str, OperatorProfile] = {}
        self._authorizer = authorizer or Authorizer()
        self._policy_engine = policy_engine or PolicyEngine()
        self._escalation_engine = escalation_engine or EscalationEngine()
        self._evidence_gates: dict[str, EvidenceGate] = {}
        self._decision_log: list[GovernanceDecision] = []
        self._max_decision_log = max_decision_log  # GV6: Bound log size
        self._decisions_evicted: int = 0  # GV6: Track eviction count
        self._bootstrapped: bool = False  # First profile can self-register
        # T1-B: Optional signing key registry for cryptographic verification
        # of second-approver evidence. When provided, SECOND_APPROVER
        # evidence must carry an HMAC signature from the approving operator.
        self._operator_registry = operator_registry

    def register_profile(
        self,
        profile: OperatorProfile,
        registering_operator_id: str = "",
    ) -> bool:
        """
        Register an operator profile.

        GV12: After bootstrap, registration requires REGISTER_OPERATOR
        authorization from an existing operator. The first profile
        registered is the bootstrap administrator.

        Args:
            profile: The operator profile to register
            registering_operator_id: Who is performing the registration.
                Empty string during bootstrap (first operator).

        Returns True if registration succeeded.
        """
        if not self._bootstrapped:
            # First registration: bootstrap. No authorization needed.
            self._profiles[profile.operator_id] = profile
            self._bootstrapped = True
            return True

        # Subsequent registrations require authorization
        if not registering_operator_id:
            # GV12: Cannot register without identifying who is registering
            return False

        registrar = self._profiles.get(registering_operator_id)
        if registrar is None:
            return False

        auth = self._authorizer.check(registrar, GovAction.REGISTER_OPERATOR)
        if not auth.authorized:
            return False

        self._profiles[profile.operator_id] = profile
        return True

    def bootstrap_register(self, profile: OperatorProfile) -> None:
        """
        Unconditional registration for testing and initial setup.

        Production deployments should use register_profile with
        proper authorization chains.
        """
        self._profiles[profile.operator_id] = profile
        self._bootstrapped = True

    def get_profile(self, operator_id: str) -> Optional[OperatorProfile]:
        """Retrieve an operator profile."""
        return self._profiles.get(operator_id)

    def register_evidence_gate(self, action_key: str, gate: EvidenceGate) -> None:
        """Register an evidence gate for an action or context key."""
        self._evidence_gates[action_key] = gate

    def _log_decision(self, decision: GovernanceDecision) -> None:
        """
        GV6: Append decision with bounded log size.

        When the log exceeds max_decision_log, oldest entries are
        evicted. Eviction count is tracked for audit awareness.
        """
        self._decision_log.append(decision)
        while len(self._decision_log) > self._max_decision_log:
            self._decision_log.pop(0)
            self._decisions_evicted += 1

    def _validate_evidence_submitters(
        self,
        evidence: list[EvidenceSubmission],
        operator_id: str,
    ) -> list[str]:
        """
        GV2: Verify evidence submitters are legitimate.

        Returns list of warnings for evidence where submitted_by
        does not match the requesting operator and is not a
        registered operator.
        """
        warnings = []
        for sub in evidence:
            if sub.submitted_by != operator_id:
                if sub.submitted_by not in self._profiles:
                    warnings.append(
                        f"Evidence type '{sub.evidence_type.value}' claims "
                        f"submission by '{sub.submitted_by}' who is not a "
                        f"registered operator."
                    )
        return warnings

    def _validate_context(
        self,
        context: GovernanceContext,
        operator_id: str,
    ) -> list[str]:
        """
        GV8: Validate caller-supplied context for consistency.

        Returns list of warnings. Does not block (context fields
        should ideally be assembled by the pipeline, not the caller,
        but the runtime cannot enforce this without pipeline integration).
        """
        warnings = []
        if context.operator.operator_id != operator_id:
            warnings.append(
                f"GV8: Context operator '{context.operator.operator_id}' "
                f"does not match requesting operator '{operator_id}'. "
                f"Context operator will be overwritten."
            )
        return warnings

    def authorize(
        self,
        operator_id: str,
        action: GovAction,
        context: Optional[GovernanceContext] = None,
        evidence: Optional[list[EvidenceSubmission]] = None,
    ) -> GovernanceDecision:
        """
        Execute the full governance check for an action.

        Returns GovernanceDecision with the verdict and evidence
        for the audit trail.
        """
        evidence = evidence or []
        profile = self._profiles.get(operator_id)

        # Layer 1: Does the operator exist and have the right role?
        if profile is None:
            decision = GovernanceDecision(
                action=action,
                operator_id=operator_id,
                authorized=False,
                policy_verdict=PolicyVerdict.DENY,
                escalation_level=self._escalation_engine.current_state.level,
                evidence_gate_passed=False,
                reason=f"Operator '{operator_id}' not registered in governance runtime.",
            )
            self._log_decision(decision)
            return decision

        auth_result = self._authorizer.check(profile, action)
        if not auth_result.authorized:
            decision = GovernanceDecision(
                action=action,
                operator_id=operator_id,
                authorized=False,
                policy_verdict=PolicyVerdict.DENY,
                escalation_level=self._escalation_engine.current_state.level,
                evidence_gate_passed=False,
                reason=auth_result.reason,
                authorization_result=auth_result,
            )
            self._log_decision(decision)
            return decision

        # GV2: Validate evidence submitters
        # FIX11: Enforce evidence submitter registration.
        # Evidence claiming submission by an unregistered operator is
        # blocked, not just warned. This prevents evidence spoofing.
        submitter_warnings = self._validate_evidence_submitters(evidence, operator_id)
        if submitter_warnings:
            reason = (
                "Evidence attribution failed: " + "; ".join(submitter_warnings)
            )
            decision = GovernanceDecision(
                action=action,
                operator_id=operator_id,
                authorized=False,
                policy_verdict=PolicyVerdict.DENY,
                escalation_level=self._escalation_engine.current_state.level,
                evidence_gate_passed=False,
                reason=reason,
            )
            self._log_decision(decision)
            return decision

        # Layer 2: Has escalation changed the rules?
        if context is None:
            context = GovernanceContext(operator=profile, action=action)
        else:
            # GV8: Validate and overwrite context operator
            self._validate_context(context, operator_id)
            context.operator = profile
            context.action = action
        context.evidence_submitted = evidence

        esc_state = self._escalation_engine.evaluate(context)

        # If escalation requires a higher role than the operator has
        if not profile.has_role(esc_state.required_role_for_action):
            # Check if the operator has a sufficient role anyway
            level_order = [
                EscalationLevel.NORMAL,
                EscalationLevel.ELEVATED,
                EscalationLevel.HIGH,
                EscalationLevel.CRITICAL,
                EscalationLevel.LOCKDOWN,
            ]
            if level_order.index(esc_state.level) > level_order.index(EscalationLevel.NORMAL):
                decision = GovernanceDecision(
                    action=action,
                    operator_id=operator_id,
                    authorized=False,
                    policy_verdict=PolicyVerdict.ESCALATE,
                    escalation_level=esc_state.level,
                    evidence_gate_passed=False,
                    reason=(
                        f"Escalation level {esc_state.level.value} requires "
                        f"{esc_state.required_role_for_action.value} role. "
                        f"Operator has: {', '.join(r.value for r in profile.roles)}."
                    ),
                    authorization_result=auth_result,
                    escalation_state=esc_state,
                )
                self._log_decision(decision)
                return decision

        # Lockdown blocks everything except de-escalation
        if esc_state.level == EscalationLevel.LOCKDOWN:
            if action != GovAction.ACKNOWLEDGE_BREACH:
                decision = GovernanceDecision(
                    action=action,
                    operator_id=operator_id,
                    authorized=False,
                    policy_verdict=PolicyVerdict.DENY,
                    escalation_level=esc_state.level,
                    evidence_gate_passed=False,
                    reason="LOCKDOWN: All execution suspended. Only breach acknowledgment permitted.",
                    authorization_result=auth_result,
                    escalation_state=esc_state,
                )
                self._log_decision(decision)
                return decision

        # Layer 3: Do policies allow this action?
        policy_result = self._policy_engine.evaluate(context)
        if policy_result.overall_verdict == PolicyVerdict.DENY:
            decision = GovernanceDecision(
                action=action,
                operator_id=operator_id,
                authorized=False,
                policy_verdict=policy_result.overall_verdict,
                escalation_level=esc_state.level,
                evidence_gate_passed=False,
                reason=(
                    f"Policy blocked: {', '.join(policy_result.blocking_policies)}. "
                    + "; ".join(
                        r.reason for r in policy_result.results
                        if r.verdict == PolicyVerdict.DENY
                    )
                ),
                authorization_result=auth_result,
                policy_result=policy_result,
                escalation_state=esc_state,
            )
            self._log_decision(decision)
            return decision

        if policy_result.overall_verdict == PolicyVerdict.ESCALATE:
            decision = GovernanceDecision(
                action=action,
                operator_id=operator_id,
                authorized=False,
                policy_verdict=policy_result.overall_verdict,
                escalation_level=esc_state.level,
                evidence_gate_passed=False,
                reason=(
                    f"Policy requires escalation: "
                    f"{', '.join(policy_result.escalation_policies)}."
                ),
                authorization_result=auth_result,
                policy_result=policy_result,
                escalation_state=esc_state,
            )
            self._log_decision(decision)
            return decision

        # Layer 4: Is required evidence attached?
        gate_key = action.value
        evidence_result = None
        if gate_key in self._evidence_gates:
            gate = self._evidence_gates[gate_key]
            evidence_result = gate.check(
                evidence,
                requesting_operator_id=operator_id,
                registered_operator_ids=set(self._profiles.keys()),
                operator_registry=self._operator_registry,
            )
            if not evidence_result.passed:
                missing_str = "; ".join(evidence_result.missing + evidence_result.insufficient)
                decision = GovernanceDecision(
                    action=action,
                    operator_id=operator_id,
                    authorized=False,
                    policy_verdict=PolicyVerdict.ALLOW,
                    escalation_level=esc_state.level,
                    evidence_gate_passed=False,
                    reason=f"Evidence gate '{gate.gate_name}' failed: {missing_str}",
                    authorization_result=auth_result,
                    policy_result=policy_result,
                    evidence_result=evidence_result,
                    escalation_state=esc_state,
                )
                self._log_decision(decision)
                return decision

        # All four layers passed
        decision = GovernanceDecision(
            action=action,
            operator_id=operator_id,
            authorized=True,
            policy_verdict=PolicyVerdict.ALLOW,
            escalation_level=esc_state.level,
            evidence_gate_passed=True,
            reason="Authorized. All governance checks passed.",
            authorization_result=auth_result,
            policy_result=policy_result,
            evidence_result=evidence_result,
            escalation_state=esc_state,
        )
        self._log_decision(decision)
        return decision

    @property
    def decision_log(self) -> list[GovernanceDecision]:
        """Complete governance decision history for audit."""
        return list(self._decision_log)

    @property
    def decisions_evicted(self) -> int:
        """GV6: Number of oldest decisions evicted from the log."""
        return self._decisions_evicted

    @property
    def escalation_state(self) -> EscalationState:
        """Current escalation state."""
        return self._escalation_engine.current_state

    def de_escalate(
        self,
        operator_id: str,
        target_level: EscalationLevel,
        justification: str,
    ) -> bool:
        """
        De-escalate. Requires governance officer or administrator.

        GV10: Justification must be at least 20 characters.
        """
        if len(justification.strip()) < 20:
            return False
        profile = self._profiles.get(operator_id)
        if not profile:
            return False
        return self._escalation_engine.de_escalate(profile, target_level, justification)

    def modify_permission(
        self,
        operator_id: str,
        target_role: OperatorRole,
        action: GovAction,
        grant: bool = True,
    ) -> bool:
        """
        GV4: Modify permission matrix. Requires MODIFY_POLICY authorization.

        Args:
            operator_id: Who is requesting the modification
            target_role: Role whose permissions are being changed
            action: The action to grant or revoke
            grant: True to grant, False to revoke

        Returns True if modification succeeded.
        """
        profile = self._profiles.get(operator_id)
        if not profile:
            return False
        auth = self._authorizer.check(profile, GovAction.MODIFY_POLICY)
        if not auth.authorized:
            return False
        if grant:
            self._authorizer.grant_action(target_role, action)
        else:
            self._authorizer.revoke_action(target_role, action)
        return True
