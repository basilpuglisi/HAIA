"""
HAIA-Overwatch v1.0 - Escalation Engine

Manages the dual-mode operating model (RAI/AIG) and five-level severity
classification. Determines when to escalate from machine-speed RAI mode
to human-checkpoint AIG mode.

Author: Basil C. Puglisi, MPA
License: CC BY-NC 4.0
"""

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .models import (
    AlignmentResult, InspectionFinding, OperatingMode, OverwatchConfig,
    Severity, StructuralFinding, StructuralResult, VerificationOutcome
)
from .structured_logger import get_logger, sanitize_log_value as _sanitize_log

logger = get_logger("overwatch.escalation")


@dataclass(slots=True)
class EscalationState:
    """Persistent state tracking across transactions for escalation decisions."""
    current_mode: OperatingMode = OperatingMode.RAI
    current_severity: Severity = Severity.NOMINAL
    advisory_accumulator: int = 0  # count of ADVISORY findings since last clear
    warning_active: bool = False
    critical_active: bool = False
    last_escalation_timestamp: float = 0.0
    last_deescalation_timestamp: float = 0.0
    consecutive_clean_transactions: int = 0
    total_escalations: int = 0
    escalation_history: List[Dict[str, Any]] = field(default_factory=list)
    _aig_hold: bool = False  # MiniMax Advisory accumulation bug fix


class EscalationEngine:
    """Manages RAI-to-AIG mode transitions.

    The escalation engine does not decide. It classifies.
    The severity classification determines whether the human governor
    is called. The thresholds that drive classification are human-configured
    governance parameters (OverwatchConfig).

    RAI mode: machine speed, no human, all checks passing.
    AIG mode: human at checkpoint, discrepancy detected, evidence presented.
    """

    def __init__(self, config: OverwatchConfig):
        self.config = config
        self.state = EscalationState()
        self._notification_callbacks: List[Callable] = []
        self._advisory_callbacks: List[Callable] = []

    def register_notification_callback(self, callback: Callable) -> None:
        """Register callback for CRITICAL/HALT notifications via independent channel."""
        self._notification_callbacks.append(callback)

    def register_advisory_callback(self, callback: Callable) -> None:
        """Register callback for ADVISORY/WARNING level findings."""
        self._advisory_callbacks.append(callback)

    # -------------------------------------------------------------------
    # Core Escalation Logic
    # -------------------------------------------------------------------

    def evaluate(
        self,
        transaction_id: str,
        structural_result: StructuralResult,
        structural_findings: List[StructuralFinding],
        inspection_findings: List[InspectionFinding]
    ) -> VerificationOutcome:
        """Evaluate all findings and produce a VerificationOutcome.

        This is the central decision point. It determines severity,
        operating mode, and whether escalation to CBG is required.
        """
        outcome = VerificationOutcome(transaction_id=transaction_id)

        # Populate structural results
        outcome.structural_result = structural_result
        outcome.structural_findings = structural_findings

        # Populate inspection results by domain
        for finding in inspection_findings:
            outcome.inspection_findings.append(finding)
            if finding.domain.value == "INTENT":
                if finding.result == AlignmentResult.FLAGGED:
                    outcome.intent_result = AlignmentResult.FLAGGED
            elif finding.domain.value == "CONTEXT":
                if finding.result == AlignmentResult.FLAGGED:
                    outcome.context_result = AlignmentResult.FLAGGED
            elif finding.domain.value == "OUTPUT_STATE":
                if finding.result == AlignmentResult.FLAGGED:
                    outcome.output_state_result = AlignmentResult.FLAGGED

        # Determine overall severity
        outcome.overall_severity = self._compute_severity(
            structural_result, structural_findings, inspection_findings
        )

        # Determine operating mode and escalation
        outcome.operating_mode, outcome.escalated, outcome.escalation_reason = (
            self._determine_mode(outcome.overall_severity, structural_result)
        )

        # Update persistent state
        self._update_state(outcome)

        # Fire callbacks if needed
        self._fire_callbacks(outcome, transaction_id)

        return outcome

    def _compute_severity(
        self,
        structural_result: StructuralResult,
        structural_findings: List[StructuralFinding],
        inspection_findings: List[InspectionFinding]
    ) -> Severity:
        """Compute overall severity from all findings.
        Takes the highest severity found across all domains."""

        max_severity = Severity.NOMINAL

        # Structural findings
        for sf in structural_findings:
            if sf.severity > max_severity:
                max_severity = sf.severity

        # Inspection findings with confidence gating
        for inf in inspection_findings:
            if inf.result == AlignmentResult.FLAGGED:
                severity = self._confidence_to_severity(inf.confidence)
                if severity > max_severity:
                    max_severity = severity

        # Advisory accumulation escalation
        if max_severity == Severity.ADVISORY:
            self.state.advisory_accumulator += 1
            if self.state.advisory_accumulator >= self.config.advisory_accumulation_limit:
                max_severity = Severity.WARNING

        # HALT override: any code integrity hash mismatch
        for sf in structural_findings:
            if sf.category == "code_integrity" and sf.severity == Severity.HALT:
                max_severity = Severity.HALT
                break

        return max_severity

    def _confidence_to_severity(self, confidence: float) -> Severity:
        """Map finding confidence to severity level using configured thresholds."""
        if confidence >= self.config.critical_confidence_floor:
            return Severity.CRITICAL
        elif confidence >= self.config.warning_confidence_floor:
            return Severity.WARNING
        elif confidence >= self.config.advisory_confidence_floor:
            return Severity.ADVISORY
        return Severity.NOMINAL

    def _determine_mode(
        self, severity: Severity, structural_result: StructuralResult
    ) -> tuple:
        """Determine operating mode based on severity.
        Returns (mode, escalated, reason).

        MiniMax Advisory accumulation bug fix: maintain AIG mode while _aig_hold is True.
        """

        if severity == Severity.NOMINAL:
            self.state.consecutive_clean_transactions += 1
            if self.state._aig_hold:
                # Still holding AIG mode despite NOMINAL severity
                return OperatingMode.AIG, False, "AIG hold active"
            return OperatingMode.RAI, False, ""

        if severity == Severity.ADVISORY:
            if self.state._aig_hold:
                # Maintain AIG mode while hold is active
                return OperatingMode.AIG, False, "AIG hold active"
            # RAI continues, finding queued for random audit
            return OperatingMode.RAI, False, ""

        if severity == Severity.WARNING:
            # Trigger AIG hold on WARNING
            self.state._aig_hold = True
            # Soft transition: advisory injected into governance package
            return OperatingMode.RAI, False, "Pre-checkpoint advisory injected"

        if severity == Severity.CRITICAL:
            # Trigger AIG hold on CRITICAL
            self.state._aig_hold = True
            reason = "High-confidence discrepancy detected"
            if structural_result == StructuralResult.FLAGGED:
                reason = "GOPEL configuration integrity deviation detected"
            return OperatingMode.AIG, True, reason

        if severity == Severity.HALT:
            # Trigger AIG hold on HALT
            self.state._aig_hold = True
            return (
                OperatingMode.AIG, True,
                "GOPEL infrastructure integrity failure: pipeline suspension recommended"
            )

        return OperatingMode.RAI, False, ""

    def _update_state(self, outcome: VerificationOutcome) -> None:
        """Update persistent escalation state after evaluation."""
        self.state.current_mode = outcome.operating_mode
        self.state.current_severity = outcome.overall_severity

        if outcome.escalated:
            self.state.total_escalations += 1
            self.state.last_escalation_timestamp = time.time()
            self.state.consecutive_clean_transactions = 0
            self.state.escalation_history.append({
                "transaction_id": outcome.transaction_id,
                "severity": outcome.overall_severity.value,
                "reason": outcome.escalation_reason,
                "timestamp": time.time()
            })
            # Cap history to prevent unbounded growth
            if len(self.state.escalation_history) > 1000:
                self.state.escalation_history = self.state.escalation_history[-500:]

        if outcome.overall_severity <= Severity.NOMINAL:
            # Clean transaction, do not reset advisory accumulator
            # (advisories persist until explicit clear or WARNING escalation)
            pass

        if outcome.overall_severity >= Severity.WARNING:
            # WARNING or above clears the advisory accumulator
            self.state.advisory_accumulator = 0

    def _fire_callbacks(self, outcome: VerificationOutcome, transaction_id: str) -> None:
        """Fire appropriate callbacks based on severity.

        AUD-03: Log exceptions at ERROR level with transaction_id.
        """
        if outcome.overall_severity >= Severity.CRITICAL:
            for cb in self._notification_callbacks:
                try:
                    cb(outcome)
                except Exception as e:
                    logger.error(
                        "Notification callback failed for transaction %s: %s",
                        _sanitize_log(transaction_id), _sanitize_log(str(e))
                    )

        if outcome.overall_severity in (Severity.ADVISORY, Severity.WARNING):
            for cb in self._advisory_callbacks:
                try:
                    cb(outcome)
                except Exception as e:
                    logger.error(
                        "Advisory callback failed for transaction %s: %s",
                        _sanitize_log(transaction_id), _sanitize_log(str(e))
                    )

    # -------------------------------------------------------------------
    # CBG Response Processing
    # -------------------------------------------------------------------

    def process_cbg_decision(
        self,
        transaction_id: str,
        confirmed_threat: bool,
        rationale: str = ""
    ) -> Dict[str, Any]:
        """Process human governor's decision on an escalated finding.

        confirmed_threat=True: the finding was a real threat.
        confirmed_threat=False: the finding was a false positive.

        Both outcomes feed back into the Factics adaptation loop.
        """
        decision = {
            "transaction_id": transaction_id,
            "confirmed_threat": confirmed_threat,
            "rationale": rationale,
            "timestamp": time.time(),
            "previous_mode": self.state.current_mode.value
        }

        if not confirmed_threat:
            # False positive: de-escalate if no other active findings
            if not self.state.critical_active:
                self.state.current_mode = OperatingMode.RAI
                self.state.current_severity = Severity.NOMINAL
                self.state._aig_hold = False  # Clear hold on false positive
                self.state.last_deescalation_timestamp = time.time()
                decision["new_mode"] = OperatingMode.RAI.value
        else:
            # Confirmed threat: maintain AIG until human explicitly clears
            self.state.current_mode = OperatingMode.AIG
            decision["new_mode"] = OperatingMode.AIG.value

        return decision

    def force_rai_mode(self, authorization_id: str) -> None:
        """Human governor explicitly returns to RAI mode.
        Requires authorization ID for audit trail.

        MiniMax fix: clear _aig_hold when returning to RAI.
        """
        self.state.current_mode = OperatingMode.RAI
        self.state.current_severity = Severity.NOMINAL
        self.state.advisory_accumulator = 0
        self.state.critical_active = False
        self.state.warning_active = False
        self.state._aig_hold = False  # Clear hold when explicitly forcing RAI
        self.state.last_deescalation_timestamp = time.time()
        self.state.consecutive_clean_transactions = 0

    # -------------------------------------------------------------------
    # State Queries
    # -------------------------------------------------------------------

    def get_state(self) -> Dict[str, Any]:
        return {
            "current_mode": self.state.current_mode.value,
            "current_severity": self.state.current_severity.value,
            "advisory_accumulator": self.state.advisory_accumulator,
            "consecutive_clean": self.state.consecutive_clean_transactions,
            "total_escalations": self.state.total_escalations,
            "last_escalation": self.state.last_escalation_timestamp
        }

    def is_rai_mode(self) -> bool:
        return self.state.current_mode == OperatingMode.RAI

    def is_aig_mode(self) -> bool:
        return self.state.current_mode == OperatingMode.AIG
