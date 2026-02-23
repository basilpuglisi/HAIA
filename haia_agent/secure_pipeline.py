"""
HAIA Agent Framework - GOPEL Secure Pipeline
==============================================
Hardened pipeline integrating all security modules into the
operational execution path.

Fixes from adversarial review (second pass):
    C1:  Security modules wired into execution path (not standalone)
    A1:  Input sanitization on platform responses before Navigator
    A2:  Single Navigator point-of-failure flagged in checkpoint package
    A3:  Minimized governance architecture exposure in synthesis prompt
    A4:  Randomized response ordering before Navigator insertion
    A5:  Error messages sanitized before Navigator insertion
    H4:  Configuration validation and bounds checking
    H5:  Logger health verification after every write
    C3:  Pipeline entry authentication via OperatorRegistry

The original GOPELPipeline in pipeline.py is preserved for backward
compatibility and testing. This module is the production path.

Author: Basil C. Puglisi, MPA
"""

from __future__ import annotations

import hashlib
import re
import uuid
from dataclasses import dataclass, field
from typing import Optional

from .adapters import AdapterResponse, PlatformAdapter
from .logger import AuditLogger
from .models import (
    ArbitrationDecision,
    OperatingModel,
    PlatformStatus,
    RECCLINRole,
)
from .navigator import NavigatorRouter
from .navigator_validator import NavigatorValidator, NavigatorValidationResult
from .secure_logger import SecureAuditLogger
from .security import (
    OperatorRegistry,
    SecureRotationSeed,
    TransportVerifier,
)
from .selector import PlatformSelector, PlatformSelection
from .breach import (
    BreachCategory,
    BreachDetector,
    BreachEvent,
    BreachNotifier,
    BreachReport,
    BreachReportFormatter,
    BreachSeverity,
    PipelineCircuitBreaker,
)
from .sentinel import PipelineIdentity, Sentinel, SignedAlert
from .governance import (
    EvidenceSubmission,
    EvidenceType,
    GovAction,
    GovernanceContext,
    GovernanceDecision,
    GovernanceRuntime,
    OperatorProfile,
    OperatorRole,
)


# ======================================================================
# A3: Reduced-exposure synthesis prompt
# Does not reveal governance architecture details to Navigator platform
# ======================================================================

SECURE_SYNTHESIS_PROMPT = """You are synthesizing responses from {platform_count} independent sources on the same task.

TASK: {original_prompt}

RESPONSES (presented in randomized order):
{platform_responses}

Produce a structured synthesis with these sections:

CONVERGENCE: Where do the sources agree?

DIVERGENCE: Where do the sources disagree? Identify which sources are on each side.

DISSENT: Document any minority position in full. Do not suppress dissenting views.

SOURCES: What references or evidence do the sources cite? Flag unverified claims as [PROVISIONAL].

CONFLICTS: List direct contradictions between sources.

CONFIDENCE: 0 to 100, how confident should the decision-maker be in the convergent findings? Justify based on agreement level and evidence quality.

RECOMMENDATION: Present the strongest recommendation with rationale. This is subject to review.

EXPIRY: Is this information time-sensitive? Note any expiration conditions."""


# ======================================================================
# H4: Configuration bounds
# ======================================================================

CONFIG_BOUNDS = {
    "max_tokens": {"min": 50, "max": 32768, "default": 4096},
    "temperature": {"min": 0.0, "max": 2.0, "default": 0.7},
    "prompt_max_length": {"max": 500000},  # ~125k tokens
}


# ======================================================================
# A1 / A5: Response sanitization patterns
# Strips known prompt injection markers from platform responses
# before they reach the Navigator. This is NOT content filtering
# (the original response is preserved in the audit trail). This is
# transport hygiene on the input to the synthesis prompt.
# ======================================================================

INJECTION_PATTERNS = [
    r"SYSTEM\s*(?:OVERRIDE|INSTRUCTION|PROMPT|MESSAGE)\s*:",
    r"IGNORE\s+(?:ALL\s+)?(?:PREVIOUS|ABOVE|PRIOR)\s+INSTRUCTIONS",
    r"YOU\s+(?:ARE|MUST)\s+NOW\s+(?:A|AN|IGNORE|FORGET)",
    r"<\s*/?(?:system|instruction|prompt|override)\s*>",
    r"\[INST\].*?\[/INST\]",
    r"<<\s*SYS\s*>>.*?<<\s*/SYS\s*>>",
    r"ASSISTANT\s*:",
    r"Human\s*:\s*(?=.*(?:ignore|forget|override))",
]

SANITIZATION_MARKER = "[INJECTION_PATTERN_DETECTED_AND_NEUTRALIZED]"


def sanitize_for_synthesis(text: str) -> tuple[str, list[str]]:
    """
    Sanitize platform response text before Navigator insertion.

    Does NOT modify the audit record (original preserved verbatim).
    Only modifies the copy sent to the Navigator synthesis prompt.

    Returns (sanitized_text, list_of_detections).
    """
    detections = []
    sanitized = text
    for pattern in INJECTION_PATTERNS:
        matches = re.findall(pattern, sanitized, re.IGNORECASE | re.DOTALL)
        if matches:
            detections.extend([f"Pattern: {pattern}, Match: {m[:50]}" for m in matches])
            sanitized = re.sub(
                pattern,
                SANITIZATION_MARKER,
                sanitized,
                flags=re.IGNORECASE | re.DOTALL,
            )
    return sanitized, detections


def sanitize_error_detail(error: str) -> str:
    """
    Sanitize error detail before Navigator insertion (A5).
    Error messages are an unguarded injection channel.
    Truncate and strip control patterns.
    """
    if not error:
        return ""
    # Truncate error messages (no legitimate error needs 1000+ chars)
    truncated = error[:200]
    # Strip the same injection patterns
    for pattern in INJECTION_PATTERNS:
        truncated = re.sub(pattern, "[REDACTED]", truncated, flags=re.IGNORECASE)
    return truncated


# ======================================================================
# A4: Randomized response ordering
# ======================================================================

def randomize_response_order(
    responses: list[AdapterResponse], seed: str, task_id: str
) -> list[AdapterResponse]:
    """
    Randomize the order of platform responses before Navigator insertion.
    Eliminates primacy/recency bias from deterministic ordering.

    Uses the same cryptographic seed as rotation selection so
    the ordering is reconstructable from the audit trail.
    """
    return SecureRotationSeed.select_rotation(
        pool=responses,
        count=len(responses),
        seed=seed,
        task_id=f"{task_id}_ordering",
    )


# ======================================================================
# Secure Checkpoint Package
# ======================================================================

@dataclass
class SecureCheckpointPackage:
    """
    Hardened governance package delivered to the human at checkpoint.

    Includes all security metadata so the human can assess
    both the content and the integrity of the process.
    """
    transaction_id: str
    recclin_role: RECCLINRole
    original_prompt: str
    platform_responses: list[AdapterResponse]
    navigator_synthesis: AdapterResponse
    navigator_validation: NavigatorValidationResult
    navigator_validation_text: str
    navigation_record_id: str
    operating_model: OperatingModel
    is_final: bool = False
    # Security metadata
    rotation_seed: str = ""
    response_ordering_seed: str = ""
    transport_violations: list[dict] = field(default_factory=list)
    injection_detections: list[str] = field(default_factory=list)
    logger_health_verified: bool = False
    single_navigator_warning: str = (
        "NOTICE: Synthesis produced by a single AI platform. "
        "No independent cross-validation of the Navigator's work. "
        "Evaluate synthesis against raw platform responses directly."
    )
    breach_report: Optional[BreachReport] = None
    breach_report_text: str = ""
    # Dispatch validation (SYNTX 8.2)
    total_dispatched: int = 0
    usable_responses: int = 0
    cross_validation_status: str = "FULL"  # FULL, DEGRADED, NONE


@dataclass
class SecureArbitrationInput:
    """Human's arbitration decision with authentication."""
    decision: ArbitrationDecision
    rationale: str
    modifications: str = ""
    final_output: str = ""


@dataclass
class SecurePipelineResult:
    """Complete result of a secure pipeline execution."""
    transaction_id: str
    checkpoint_package: Optional[SecureCheckpointPackage]
    success: bool = True
    error: str = ""
    security_warnings: list[str] = field(default_factory=list)
    breach_report: Optional[BreachReport] = None
    breach_halted: bool = False
    signed_alert: Optional[SignedAlert] = None
    governance_decision: Optional[GovernanceDecision] = None


# ======================================================================
# Secure Pipeline
# ======================================================================

class SecureGOPELPipeline:
    """
    Production-hardened GOPEL pipeline.

    Integrates all security modules into the operational execution path:
        - SecureAuditLogger for signed, witnessed, encrypted audit trail
        - Cryptographic rotation for unpredictable platform selection
        - Navigator structural validation
        - Response sanitization before Navigator insertion
        - Randomized response ordering
        - Transport integrity verification
        - Configuration bounds checking
        - Logger health verification
        - Pipeline entry authentication

    Non-cognitive constraint maintained: sanitization is pattern-matching
    (regex), not content evaluation. Randomization is mathematical, not
    preferential. Validation checks structure, not substance.
    """

    def __init__(
        self,
        logger: AuditLogger,
        selector: PlatformSelector,
        navigator: NavigatorRouter,
        operator_registry: Optional[OperatorRegistry] = None,
        navigator_validator: Optional[NavigatorValidator] = None,
        breach_detector: Optional[BreachDetector] = None,
        circuit_breaker: Optional[PipelineCircuitBreaker] = None,
        breach_notifier: Optional[BreachNotifier] = None,
        sentinel: Optional[Sentinel] = None,
        governance_runtime: Optional[GovernanceRuntime] = None,
        operator_id: str = "haia_agent",
        require_authentication: bool = True,
    ):
        self.logger = logger
        self.selector = selector
        self.navigator = navigator
        self.operator_registry = operator_registry
        self.nav_validator = navigator_validator or NavigatorValidator()
        self.breach_detector = breach_detector or BreachDetector()
        self.circuit_breaker = circuit_breaker or PipelineCircuitBreaker()
        self.breach_notifier = breach_notifier
        self.sentinel = sentinel
        self.governance_runtime = governance_runtime
        self.operator_id = operator_id
        self.require_authentication = require_authentication

        # FIX5: Fail-closed on auth misconfiguration.
        # If authentication is required, at least one auth backend
        # (governance_runtime or operator_registry) must be provided.
        # Without this guard, require_authentication=True silently
        # passes when neither backend is configured.
        if require_authentication and not governance_runtime and not operator_registry:
            raise ValueError(
                "Authentication misconfiguration: require_authentication=True "
                "but neither governance_runtime nor operator_registry is "
                "provided. Pipeline would silently skip authentication. "
                "Provide an auth backend or set require_authentication=False."
            )

        # T1-A: Persistent breach state across transactions.
        # The pipeline must carry forward the most recent breach severity
        # and injection count so that pre-execution governance policies
        # (e.g. POLICY_BREACH_BLOCKS_EXECUTION) can evaluate against
        # the actual system health state, not a fresh NOMINAL default.
        # Without this, a governance officer with the correct elevated
        # role could authorize execution during an active CRITICAL breach
        # because the policy checked breach_severity=NOMINAL.
        self._last_breach_severity = BreachSeverity.NOMINAL
        self._last_injection_count = 0
        self._last_platform_failure_count = 0

    def execute(
        self,
        prompt: str,
        recclin_role: RECCLINRole,
        operating_model: OperatingModel,
        human_operator_id: str,
        task_scope: str = "",
        success_criteria: str = "",
        system_prompt: Optional[str] = None,
        transaction_id: Optional[str] = None,
        max_tokens: int = 4096,
        temperature: float = 0.7,
    ) -> SecurePipelineResult:
        """
        Execute the full hardened GOPEL pipeline.

        All security modules are active in this execution path.
        """
        tid = transaction_id or str(uuid.uuid4())
        prompt_hash = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
        security_warnings: list[str] = []

        try:
            # ==============================================================
            # GOVERNANCE GATE: Five-layer authorization
            # Replaces old C3 binary authentication with full runtime.
            # If governance_runtime is configured, it handles:
            #   Layer 1: Who is allowed to act (role-based)
            #   Layer 2: Has escalation changed the rules
            #   Layer 3: Policy preconditions
            #   Layer 4: Evidence requirements
            # Falls back to C3 binary check when runtime not provided.
            # ==============================================================
            gov_decision = None
            if self.governance_runtime:
                # Build governance context from pipeline state
                # T1-A: Include persistent breach state from prior transactions.
                # Without this, policies like POLICY_BREACH_BLOCKS_EXECUTION
                # always see NOMINAL severity at pre-execution and never fire.
                gov_context = GovernanceContext(
                    operator=OperatorProfile(
                        operator_id=human_operator_id,
                        roles=set(),  # Will be overwritten by runtime lookup
                    ),
                    action=GovAction.EXECUTE_PIPELINE,
                    operating_model=operating_model,
                    recclin_role=recclin_role,
                    breach_severity=self._last_breach_severity,
                    injection_count=self._last_injection_count,
                    platform_failure_count=self._last_platform_failure_count,
                )
                # Build evidence from execution parameters
                evidence = []
                if task_scope:
                    evidence.append(EvidenceSubmission(
                        evidence_type=EvidenceType.SCOPE_STATEMENT,
                        content=task_scope,
                        submitted_by=human_operator_id,
                    ))

                gov_decision = self.governance_runtime.authorize(
                    operator_id=human_operator_id,
                    action=GovAction.EXECUTE_PIPELINE,
                    context=gov_context,
                    evidence=evidence,
                )

                if not gov_decision.authorized:
                    return SecurePipelineResult(
                        transaction_id=tid,
                        checkpoint_package=None,
                        success=False,
                        error=f"Governance denied: {gov_decision.reason}",
                        security_warnings=[
                            f"Governance verdict: {gov_decision.policy_verdict.value}",
                            f"Escalation level: {gov_decision.escalation_level.value}",
                        ],
                        governance_decision=gov_decision,
                    )

            elif self.require_authentication and self.operator_registry:
                # Legacy C3: Binary registered/not-registered check
                operator = self.operator_registry.get_operator(human_operator_id)
                if operator is None:
                    return SecurePipelineResult(
                        transaction_id=tid,
                        checkpoint_package=None,
                        success=False,
                        error=f"Operator '{human_operator_id}' not registered. "
                              f"Pipeline execution denied.",
                    )

            # ==============================================================
            # H4: Configuration bounds checking
            # ==============================================================
            max_tokens = max(
                CONFIG_BOUNDS["max_tokens"]["min"],
                min(max_tokens, CONFIG_BOUNDS["max_tokens"]["max"]),
            )
            temperature = max(
                CONFIG_BOUNDS["temperature"]["min"],
                min(temperature, CONFIG_BOUNDS["temperature"]["max"]),
            )
            if len(prompt) > CONFIG_BOUNDS["prompt_max_length"]["max"]:
                return SecurePipelineResult(
                    transaction_id=tid,
                    checkpoint_package=None,
                    success=False,
                    error=f"Prompt exceeds maximum length "
                          f"({len(prompt)} > {CONFIG_BOUNDS['prompt_max_length']['max']})",
                )

            # ==============================================================
            # Step 1-2: Receive task, write Request Record
            # V9: Cryptographic rotation selection
            # ==============================================================
            use_secure_select = hasattr(self.selector, "secure_select")
            if use_secure_select:
                selection = self.selector.secure_select(recclin_role, tid)
                rotation_seed = selection.rotation_seed
            else:
                selection = self.selector.select(recclin_role)
                rotation_seed = ""
                security_warnings.append(
                    "Using deterministic round-robin selection (V9 not active)"
                )

            platform_ids = [a.platform_id for a in selection.all_platforms]
            anchor_id = selection.anchor.platform_id

            self.logger.log_request(
                transaction_id=tid,
                operator_id=human_operator_id,
                prompt_text=prompt,
                recclin_role=recclin_role,
                operating_model=operating_model,
                task_scope=task_scope,
                success_criteria=success_criteria,
                platform_selections=platform_ids,
                anchor_platform=anchor_id,
            )

            # H5: Verify logger health after write
            if not self._verify_logger_health():
                security_warnings.append("Logger health check failed after request record")

            # ==============================================================
            # Steps 3-7: Dispatch, collect, log
            # V7: Transport integrity verification
            # ==============================================================
            platform_responses: list[AdapterResponse] = []
            all_injection_detections: list[str] = []

            for adapter in selection.all_platforms:
                # Operation 1: DISPATCH
                response = adapter.send_prompt(
                    prompt=prompt,
                    system_prompt=system_prompt,
                    max_tokens=max_tokens,
                    temperature=temperature,
                )

                # V7: Verify dispatch integrity
                if not TransportVerifier.verify_dispatch_integrity(prompt, prompt_hash):
                    security_warnings.append(
                        f"Dispatch integrity violation for {adapter.platform_id}"
                    )

                # Write Dispatch Record
                dispatch_status = (
                    PlatformStatus.SENT if response.success
                    else PlatformStatus.ERROR
                )
                self.logger.log_dispatch(
                    transaction_id=tid,
                    operator_id=self.operator_id,
                    platform_id=adapter.platform_id,
                    platform_model=adapter.default_model,
                    prompt_hash=prompt_hash,
                    is_anchor=(adapter.platform_id == anchor_id),
                    dispatch_status=dispatch_status,
                    api_confirmation=response.api_confirmation,
                )

                # V7: Verify response integrity
                if response.success and response.response_text:
                    if not TransportVerifier.verify_response_integrity(
                        response.response_text, response.response_hash
                    ):
                        security_warnings.append(
                            f"Response integrity violation for {adapter.platform_id}"
                        )

                # Write Response Record (original, unsanitized)
                resp_status = (
                    PlatformStatus.RECEIVED if response.success
                    else PlatformStatus.ERROR
                )
                self.logger.log_response(
                    transaction_id=tid,
                    operator_id=self.operator_id,
                    platform_id=adapter.platform_id,
                    platform_model=response.platform_model,
                    response_text=response.response_text,
                    response_status=resp_status,
                    token_count=response.token_count,
                    latency_ms=response.latency_ms,
                    error_detail=response.error_detail,
                )

                platform_responses.append(response)

            # H5: Verify logger health after dispatch/response writes
            if not self._verify_logger_health():
                security_warnings.append("Logger health check failed after dispatch/response")

            # ==============================================================
            # SYNTX 8.2: Total Dispatch Failure and Degraded Synthesis
            # Guard against silent degradation when platforms fail.
            # ==============================================================
            usable_count = sum(
                1 for r in platform_responses if r.success and r.response_text
            )
            total_dispatched = len(platform_responses)

            if usable_count == 0:
                # TOTAL DISPATCH FAILURE: No platform returned usable output.
                # Log the failure, preserve all error responses, return to human
                # with explicit flag that no cross-validation occurred.
                self.logger._log_system_event(
                    event_type="total_dispatch_failure",
                    detail=(
                        f"Transaction {tid}: All {total_dispatched} platforms "
                        f"failed to return usable responses. No Navigator "
                        f"synthesis possible. Transaction returned to human "
                        f"operator without cross-validation."
                    ),
                    severity="critical",
                )

                # Build breach report for the total failure
                failure_report = BreachReport(transaction_id=tid)
                failure_report.add_event(BreachEvent(
                    category=BreachCategory.RESPONSE_ANOMALY,
                    severity=BreachSeverity.HALT,
                    description=(
                        f"Total dispatch failure: {total_dispatched} platforms "
                        f"dispatched, 0 usable responses received. "
                        f"Cross-validation impossible."
                    ),
                    transaction_id=tid,
                    recommended_action=(
                        "Retry with different platforms, proceed with "
                        "single-platform output (downgrade to Model 3), "
                        "or abort transaction."
                    ),
                ))
                failure_report.finalize()

                if self.breach_notifier:
                    self.breach_notifier.notify(failure_report)

                # Feed into governance escalation
                if self.governance_runtime:
                    esc_context = GovernanceContext(
                        operator=OperatorProfile(
                            operator_id=human_operator_id, roles=set(),
                        ),
                        action=GovAction.EXECUTE_PIPELINE,
                        breach_severity=BreachSeverity.HALT,
                        platform_failure_count=total_dispatched,
                    )
                    self.governance_runtime._escalation_engine.evaluate(
                        esc_context
                    )

                # T1-A: Persist breach state for next transaction
                self._last_breach_severity = BreachSeverity.HALT
                self._last_injection_count = 0
                self._last_platform_failure_count = total_dispatched

                return SecurePipelineResult(
                    transaction_id=tid,
                    checkpoint_package=None,
                    success=False,
                    error=(
                        f"Total dispatch failure: {total_dispatched} platforms "
                        f"dispatched, 0 usable responses. No synthesis possible."
                    ),
                    security_warnings=security_warnings,
                    breach_report=failure_report,
                    breach_halted=True,
                    governance_decision=gov_decision,
                )

            # Track cross-validation status for checkpoint package
            if usable_count >= 2:
                cross_validation_status = "FULL"
            elif usable_count == 1:
                cross_validation_status = "DEGRADED"
                security_warnings.append(
                    f"DEGRADED CROSS-VALIDATION: Only {usable_count} of "
                    f"{total_dispatched} platforms returned usable responses. "
                    f"Navigator synthesis has no independent comparison point. "
                    f"Treat output as single-source, not cross-validated."
                )
                self.logger._log_system_event(
                    event_type="degraded_cross_validation",
                    detail=(
                        f"Transaction {tid}: {usable_count} of "
                        f"{total_dispatched} platforms returned usable "
                        f"responses. Cross-validation degraded."
                    ),
                    severity="warning",
                )
            else:
                cross_validation_status = "NONE"  # Unreachable (caught above)

            # ==============================================================
            # A1/A5: Sanitize responses before Navigator insertion
            # Originals preserved in audit trail above
            # ==============================================================
            sanitized_responses = []
            for resp in platform_responses:
                if resp.success and resp.response_text:
                    clean_text, detections = sanitize_for_synthesis(resp.response_text)
                    all_injection_detections.extend(detections)
                    sanitized_resp = AdapterResponse(
                        platform_id=resp.platform_id,
                        platform_model=resp.platform_model,
                        response_text=clean_text,
                        response_hash=resp.response_hash,
                        token_count=resp.token_count,
                        latency_ms=resp.latency_ms,
                        success=resp.success,
                        error_detail=sanitize_error_detail(resp.error_detail),
                        api_confirmation=resp.api_confirmation,
                    )
                else:
                    sanitized_resp = AdapterResponse(
                        platform_id=resp.platform_id,
                        platform_model=resp.platform_model,
                        response_text=resp.response_text,
                        response_hash=resp.response_hash,
                        token_count=resp.token_count,
                        latency_ms=resp.latency_ms,
                        success=resp.success,
                        error_detail=sanitize_error_detail(resp.error_detail),
                        api_confirmation=resp.api_confirmation,
                    )
                sanitized_responses.append(sanitized_resp)

            if all_injection_detections:
                security_warnings.append(
                    f"Injection patterns detected and neutralized in "
                    f"{len(all_injection_detections)} instance(s)"
                )
                # Log injection detections as system event
                self.logger._log_system_event(
                    event_type="injection_detection",
                    detail=f"Transaction {tid}: {len(all_injection_detections)} "
                           f"injection patterns neutralized before Navigator insertion. "
                           f"Original responses preserved in audit trail.",
                    severity="warning",
                )

            # ==============================================================
            # A4: Randomize response ordering
            # ==============================================================
            ordering_seed = SecureRotationSeed.generate_seed()
            ordered_responses = randomize_response_order(
                sanitized_responses, ordering_seed, tid
            )

            # ==============================================================
            # Steps 8-9: Route to Navigator with secure synthesis prompt
            # A3: Reduced-exposure prompt (no governance architecture details)
            # ==============================================================
            nav_response = self._secure_route_for_synthesis(
                original_prompt=prompt,
                platform_responses=ordered_responses,
                system_prompt=system_prompt,
                max_tokens=max_tokens,
            )

            # ==============================================================
            # V1: Navigator structural validation
            # ==============================================================
            nav_validation = self.nav_validator.validate(
                nav_response.response_text if nav_response.success else ""
            )
            nav_validation_text = self.nav_validator.format_validation_for_human(
                nav_validation
            )

            if not nav_validation.is_valid:
                security_warnings.append(
                    f"Navigator output missing required sections: "
                    f"{', '.join(nav_validation.sections_missing)}"
                )

            # Step 10: Write Navigation Record
            # FIX15: Store full synthesis text for audit reconstruction.
            full_synthesis = nav_response.response_text if nav_response.success else ""
            nav_record = self.logger.log_navigation(
                transaction_id=tid,
                operator_id=self.operator_id,
                navigator_platform=self.navigator.navigator_adapter.platform_id,
                convergence_summary="See full_synthesis_text field",
                divergence_summary="See full_synthesis_text field",
                dissent_records=[],
                recommendation=full_synthesis[:500] if full_synthesis else "",
                confidence_score=nav_validation.confidence_value or 0,
                confidence_justification="Computed by Navigator in synthesis output",
                response_record_ids=[],
                full_synthesis_text=full_synthesis,
            )

            # V7: Transport verification across all records
            transport_violations = TransportVerifier.verify_transaction_transport(
                self.logger._records
            )
            if transport_violations:
                security_warnings.append(
                    f"{len(transport_violations)} transport integrity violation(s) detected"
                )

            # H5: Final logger health check
            logger_healthy = self._verify_logger_health()

            # ==============================================================
            # Step 11: Build secure checkpoint package
            # ==============================================================

            # Breach detection: analyze all collected evidence
            breach_report = self.breach_detector.analyze_transaction(
                transaction_id=tid,
                platform_responses=platform_responses,
                navigator_response=nav_response,
                navigator_validation=nav_validation,
                security_warnings=security_warnings,
                injection_detections=all_injection_detections,
                transport_violations=transport_violations,
                logger_healthy=logger_healthy,
            )

            # Feed breach state into governance escalation engine.
            # This ensures future transactions see the escalated posture.
            if self.governance_runtime and breach_report.overall_severity != BreachSeverity.NOMINAL:
                esc_context = GovernanceContext(
                    operator=OperatorProfile(
                        operator_id=human_operator_id, roles=set(),
                    ),
                    action=GovAction.EXECUTE_PIPELINE,
                    breach_severity=breach_report.overall_severity,
                    injection_count=len(all_injection_detections),
                    platform_failure_count=sum(
                        1 for r in platform_responses if not r.success
                    ),
                )
                # Evaluate updates the escalation engine's persistent state
                self.governance_runtime._escalation_engine.evaluate(esc_context)

            # T1-A: Persist breach state for next transaction's pre-execution
            # governance check. This is the critical link that ensures policies
            # like POLICY_BREACH_BLOCKS_EXECUTION see the real system state.
            self._last_breach_severity = breach_report.overall_severity
            self._last_injection_count = len(all_injection_detections)
            self._last_platform_failure_count = sum(
                1 for r in platform_responses if not r.success
            )

            # Circuit breaker: should we halt?
            should_halt = self.circuit_breaker.should_halt(breach_report)

            if should_halt:
                # Log the halt
                self.logger._log_system_event(
                    event_type="pipeline_halted",
                    detail=(
                        f"Transaction {tid}: Pipeline halted by circuit breaker. "
                        f"Severity: {breach_report.overall_severity.value}. "
                        f"Events: {len(breach_report.events)}."
                    ),
                    severity="critical",
                )

                # Notify
                if self.breach_notifier:
                    self.breach_notifier.notify(breach_report)

                # Sign the halt report and dispatch OOB
                signed = None
                if self.sentinel:
                    signed = self.sentinel.sign_breach_report(breach_report)
                    self.sentinel.dispatch_oob_alert(breach_report)

                return SecurePipelineResult(
                    transaction_id=tid,
                    checkpoint_package=None,
                    success=False,
                    error=(
                        f"Pipeline halted by circuit breaker. "
                        f"Severity: {breach_report.overall_severity.value}. "
                        f"Breach report attached."
                    ),
                    security_warnings=security_warnings,
                    breach_report=breach_report,
                    breach_halted=True,
                    signed_alert=signed,
                )

            # Not halted: build the checkpoint package with breach report
            breach_text = BreachReportFormatter.format_full(breach_report)

            package = SecureCheckpointPackage(
                transaction_id=tid,
                recclin_role=recclin_role,
                original_prompt=prompt,
                platform_responses=platform_responses,  # Originals, not sanitized
                navigator_synthesis=nav_response,
                navigator_validation=nav_validation,
                navigator_validation_text=nav_validation_text,
                navigation_record_id=nav_record.record_id,
                operating_model=operating_model,
                rotation_seed=rotation_seed,
                response_ordering_seed=ordering_seed,
                transport_violations=transport_violations,
                injection_detections=all_injection_detections,
                logger_health_verified=logger_healthy,
                breach_report=breach_report,
                breach_report_text=breach_text,
                total_dispatched=total_dispatched,
                usable_responses=usable_count,
                cross_validation_status=cross_validation_status,
            )

            # Notify on non-nominal
            if self.breach_notifier and breach_report.overall_severity != BreachSeverity.NOMINAL:
                self.breach_notifier.notify(breach_report)

            # Sign the checkpoint package
            signed = None
            if self.sentinel:
                signed = self.sentinel.sign_checkpoint_package({
                    "transaction_id": tid,
                    "breach_severity": breach_report.overall_severity.value,
                    "event_count": len(breach_report.events),
                })
                # OOB dispatch on WARNING+
                if breach_report.overall_severity != BreachSeverity.NOMINAL:
                    self.sentinel.dispatch_oob_alert(breach_report)

            return SecurePipelineResult(
                transaction_id=tid,
                checkpoint_package=package,
                success=True,
                security_warnings=security_warnings,
                breach_report=breach_report,
                signed_alert=signed,
                governance_decision=gov_decision,
            )

        except Exception as e:
            try:
                self.logger._log_system_event(
                    event_type="secure_pipeline_error",
                    detail=f"Pipeline failed for transaction {tid}: {str(e)}",
                    severity="error",
                )
            except Exception:
                # H5: Logger itself failed. Cannot recover.
                security_warnings.append("CRITICAL: Logger failed during error handling")

            # Generate breach report for the failure itself
            failure_report = BreachReport(transaction_id=tid)
            failure_report.add_event(BreachEvent(
                category=BreachCategory.LOGGER_FAILURE,
                severity=BreachSeverity.CRITICAL,
                description=f"Pipeline execution failed with exception: {str(e)}",
                transaction_id=tid,
                recommended_action="Investigate exception. Re-run transaction after fix.",
            ))
            failure_report.finalize()

            if self.breach_notifier:
                self.breach_notifier.notify(failure_report)

            return SecurePipelineResult(
                transaction_id=tid,
                checkpoint_package=None,
                success=False,
                error=str(e),
                security_warnings=security_warnings,
                breach_report=failure_report,
            )

    def record_arbitration(
        self,
        transaction_id: str,
        human_operator_id: str,
        arbitration: SecureArbitrationInput,
        checkpoint_role: RECCLINRole,
        navigation_record_id: str,
    ) -> bool:
        """
        Record human's arbitration decision with governance authorization.

        Returns True if recorded successfully.
        """
        # Governance gate for arbitration
        if self.governance_runtime:
            evidence = [
                EvidenceSubmission(
                    evidence_type=EvidenceType.RATIONALE,
                    content=arbitration.rationale,
                    submitted_by=human_operator_id,
                ),
            ]

            gov_decision = self.governance_runtime.authorize(
                operator_id=human_operator_id,
                action=GovAction.RECORD_ARBITRATION,
                evidence=evidence,
            )
            if not gov_decision.authorized:
                return False

        elif self.require_authentication and self.operator_registry:
            # Legacy C3: Binary check
            operator = self.operator_registry.get_operator(human_operator_id)
            if operator is None:
                return False

        self.logger.log_arbitration(
            transaction_id=transaction_id,
            operator_id=human_operator_id,
            arbitration_decision=arbitration.decision,
            rationale=arbitration.rationale,
            modifications=arbitration.modifications,
            checkpoint_role=checkpoint_role,
            navigation_record_id=navigation_record_id,
        )

        final_output = arbitration.final_output or arbitration.rationale
        self.logger.log_decision(
            transaction_id=transaction_id,
            operator_id=human_operator_id,
            final_output=final_output,
            upstream_record_ids=[],
            is_final=True,
        )

        return True

    # ==================================================================
    # CLAUDE-R9: Breach acknowledgment (resolves T1-A deadlock)
    # ==================================================================

    def acknowledge_breach(
        self,
        human_operator_id: str,
        justification: str,
    ) -> bool:
        """
        Acknowledge and clear a breach state to resume pipeline execution.

        CLAUDE-R9: T1-A introduced persistent breach state, which correctly
        blocks execution during active breaches via POLICY_BREACH_BLOCKS_EXECUTION.
        However, without a reset path, the pipeline deadlocks permanently
        after any CRITICAL or HALT breach: execute() is blocked by the policy,
        and breach state can only update through execute().

        This method provides the authorized reset path:
            1. Requires ACKNOWLEDGE_BREACH governance authorization
            2. Logs the acknowledgment in the audit trail
            3. Resets pipeline breach state to NOMINAL
            4. Does NOT reset the escalation engine (that requires de_escalate)

        The separation is deliberate: acknowledging a breach lets the pipeline
        run again, but the governance posture remains elevated until explicitly
        de-escalated. This preserves defense-in-depth.

        Returns True if breach acknowledged successfully.
        """
        if not self.governance_runtime:
            # No governance: direct reset
            self._last_breach_severity = BreachSeverity.NOMINAL
            self._last_injection_count = 0
            self._last_platform_failure_count = 0
            return True

        # Require governance authorization
        evidence = [
            EvidenceSubmission(
                evidence_type=EvidenceType.JUSTIFICATION,
                content=justification,
                submitted_by=human_operator_id,
            ),
        ]

        gov_decision = self.governance_runtime.authorize(
            operator_id=human_operator_id,
            action=GovAction.ACKNOWLEDGE_BREACH,
            evidence=evidence,
        )

        if not gov_decision.authorized:
            return False

        # Log the acknowledgment
        prior_severity = self._last_breach_severity.value
        self.logger._log_system_event(
            event_type="breach_acknowledged",
            detail=(
                f"Operator {human_operator_id} acknowledged breach "
                f"(prior severity: {prior_severity}). "
                f"Justification: {justification[:200]}"
            ),
        )

        # Reset breach state
        self._last_breach_severity = BreachSeverity.NOMINAL
        self._last_injection_count = 0
        self._last_platform_failure_count = 0
        return True

    # ==================================================================
    # Internal methods
    # ==================================================================

    def _secure_route_for_synthesis(
        self,
        original_prompt: str,
        platform_responses: list[AdapterResponse],
        system_prompt: Optional[str] = None,
        max_tokens: int = 4096,
    ) -> AdapterResponse:
        """
        Route to Navigator using the reduced-exposure synthesis prompt (A3).
        Response ordering already randomized by caller (A4).
        Responses already sanitized by caller (A1/A5).
        """
        formatted = self._format_responses_anonymous(platform_responses)

        synthesis_prompt = SECURE_SYNTHESIS_PROMPT.format(
            platform_count=len(platform_responses),
            original_prompt=original_prompt,
            platform_responses=formatted,
        )

        nav_system = (
            "You are synthesizing multiple independent responses to produce "
            "a structured analysis. Your synthesis will be reviewed. "
            "Do not resolve disagreements. Present them."
        )
        if system_prompt:
            nav_system = f"{nav_system}\n\n{system_prompt}"

        return self.navigator.navigator_adapter.send_prompt(
            prompt=synthesis_prompt,
            system_prompt=nav_system,
            max_tokens=max_tokens,
        )

    def _format_responses_anonymous(self, responses: list[AdapterResponse]) -> str:
        """
        Format responses with anonymized identifiers (A3).
        Does not reveal platform names to Navigator.
        Uses "Source A", "Source B" instead of platform IDs.
        """
        labels = [chr(65 + i) for i in range(len(responses))]  # A, B, C...
        sections = []
        for label, resp in zip(labels, responses):
            if resp.success:
                section = (
                    f"--- SOURCE {label} ---\n"
                    f"RESPONSE:\n{resp.response_text}\n"
                )
            else:
                section = (
                    f"--- SOURCE {label} ---\n"
                    f"STATUS: Unavailable\n"
                    f"DETAIL: {resp.error_detail}\n"
                )
            sections.append(section)
        return "\n".join(sections)

    def _verify_logger_health(self) -> bool:
        """
        H5: Verify the logger actually persisted records.

        T1-C: Strengthened from existence+size check to include:
            1. Audit file exists on disk
            2. File has non-zero size
            3. File is parseable JSON (not corrupted mid-write)
            4. Hash chain integrity holds (tamper detection)
        Previously only checked (1) and (2), which allowed a truncated
        or corrupted file to pass, giving false assurance.
        """
        try:
            if not self.logger.audit_file_path.exists():
                return False
            file_size = self.logger.audit_file_path.stat().st_size
            if file_size == 0:
                return False
            # T1-C: Verify file is parseable
            import json as _json
            with open(self.logger.audit_file_path, "r", encoding="utf-8") as f:
                _json.load(f)
            # T1-C: Verify chain integrity
            is_valid, _ = self.logger.verify_chain_integrity()
            return is_valid
        except Exception:
            return False
