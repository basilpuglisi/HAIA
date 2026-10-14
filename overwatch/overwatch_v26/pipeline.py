"""
HAIA-Overwatch v2.6 - Main Pipeline

The complete Overwatch pipeline integrating all modules:
- Structural Verifier (Part 1)
- Intent Analyzer (Part 2, Intent)
- Context Inspector (Part 2, Context)
- Output State Evaluator (Part 2, Output State)
- Escalation Engine (RAI/AIG mode management)
- Random Audit Generator
- Factics Engine (adaptation)

Overwatch observes. It does not enforce. It does not block.
It does not modify. It watches everything.

Its one action authority over GOPEL is to stop the pipe and route to
human (paper sections 8, 9 and 14; ruling R5). v2.5 makes that action
real: every escalation to AIG mode (severity CRITICAL or HALT, or a
trajectory alert) publishes exactly one signed stop line through the
StopChannelPublisher, when one is attached. GOPEL honors the stop until a
human releases it through GOPEL's evidence gates.

Author: Basil C. Puglisi, MPA
License: CC BY-NC 4.0
Repository: github.com/basilpuglisi/HAIA
"""

import time
from typing import Any, Callable, Dict, List, Mapping, Optional

from .crypto import KeyScopeGuard
from .models import (
    AlignmentResult, Heartbeat, InspectionFinding, OperatingMode,
    OverwatchConfig, RandomAuditReport, Severity, StructuralResult,
    TrajectoryAlert, TransactionRecord, VerificationOutcome, StructuralFinding
)
from .structural_verifier import BehavioralSample, StructuralVerifier
from .intent_analyzer import IntentAnalyzer
from .context_inspector import ContextInspector
from .output_state_evaluator import OutputStateEvaluator
from .escalation_engine import EscalationEngine
from .random_audit import RandomAuditGenerator
from .factics_engine import FacticsEngine
from .execution_graph import ExecutionGraphEngine
from .structured_logger import get_logger, sanitize_log_value as _sanitize_log

logger = get_logger(__name__)


class OverwatchPipeline:
    """The complete HAIA-Overwatch pipeline.

    Runs the two-part verification gate on every transaction:
    Part 1: GOPEL structural soundness
    Part 2: Exchange alignment (intent, context, output state)

    Operates in RAI mode at machine speed when everything checks out.
    Escalates to AIG mode through CBG when discrepancies are detected.

    The pipeline is the Overwatch position: separate trust boundary,
    independent observation, same governance authority chain through CBG.
    """

    VERSION = "2.6.0"

    def __init__(self, config: OverwatchConfig):
        self.config = config

        # Validate configuration
        errors = config.validate()
        if errors:
            raise ValueError(f"Invalid Overwatch configuration: {'; '.join(errors)}")

        # v2.5: every signing key serves one scope (stop key distinct from
        # heartbeat, calibration, provenance and manifest keys).
        self._key_scopes = KeyScopeGuard()

        # v2.6 (Basil's ruling X3): a signed deployment manifest is required
        # by default; the local test setting says so at start.
        if getattr(config, "local_test_unsigned_manifests", False):
            logger.warning(
                "LOCAL TEST SETTING: unsigned deployment manifests are accepted by their "
                "content hash. Every outcome is marked unsigned. Never use this in deployment."
            )

        # Initialize all modules
        self.structural_verifier = StructuralVerifier(config, key_guard=self._key_scopes)
        self.intent_analyzer = IntentAnalyzer(config)
        self.context_inspector = ContextInspector(config)
        self.output_state_evaluator = OutputStateEvaluator(config)
        self.escalation_engine = EscalationEngine(config)
        self.random_audit = RandomAuditGenerator(config)
        # v2.5: the Factics engine receives the pipeline config, so GOPEL-mode
        # thresholds hold (paper section 6.4) and proposals_log_path reaches it
        # (paper section 11.1).
        self.factics_engine = FacticsEngine(config, key_guard=self._key_scopes)
        self.execution_graph = ExecutionGraphEngine()

        # Chain signatures approved before a restart are back in detection.
        restored = self.factics_engine.get_chain_library()
        if restored:
            self.intent_analyzer.load_chain_library(restored)

        # Stop channel (v2.5, step 20)
        self._stop_publisher: Any = None
        self._stops_published: int = 0
        self._stop_publish_failures: int = 0

        # Heartbeat state
        self._heartbeat_sequence: int = 0
        self._heartbeat_key: Optional[bytes] = None
        self._heartbeat_key_missing_logged: bool = False
        self._last_heartbeat: float = 0.0

        # Pipeline statistics
        self._total_transactions: int = 0
        self._total_escalations: int = 0
        self._total_clean: int = 0
        self._start_time: float = time.time()

        # Notification callbacks
        self._notification_callbacks: List[Callable] = []

        # Optional GOPEL observer reference for health metrics
        self._gopel_observer = None

    # -------------------------------------------------------------------
    # Setup
    # -------------------------------------------------------------------

    def attach_gopel_observer(self, observer: Any) -> None:
        """Attach a GopelObserver for health metric exposure."""
        self._gopel_observer = observer

    def set_heartbeat_key(self, key: bytes) -> None:
        """Set the HMAC signing key for heartbeat authentication."""
        if len(key) < 32:
            raise ValueError(
                f"Heartbeat key must be at least 32 bytes; got {len(key)}"
            )
        self._key_scopes.register("heartbeat", key)
        self._heartbeat_key = key

    def set_manifest_key(self, key: bytes) -> None:
        """Set the manifest-scoped HMAC key the Structural Verifier uses to
        verify signed deployment manifests (v2.5, S1)."""
        self.structural_verifier.set_manifest_key(key)

    def register_key_scope(self, scope: str, key: bytes) -> None:
        """Register a key the pipeline does not hold itself (for example the
        provenance or alert-channel key) so the stop key cannot reuse it."""
        self._key_scopes.register(scope, key)

    def attach_stop_publisher(self, publisher: Any) -> None:
        """Attach the StopChannelPublisher. Every escalation to AIG mode then
        publishes exactly one stop line. The stop key must be scoped to the
        stop channel only."""
        self._key_scopes.register_fingerprint("stop", publisher.key_fingerprint)
        self._stop_publisher = publisher

    def register_notification_callback(self, callback: Callable) -> None:
        """Register callback for independent channel notifications."""
        self._notification_callbacks.append(callback)
        self.escalation_engine.register_notification_callback(callback)

    # -------------------------------------------------------------------
    # Core Pipeline: Verify Transaction
    # -------------------------------------------------------------------

    def verify_transaction(
        self,
        transaction: TransactionRecord,
        gopel_directory: str = "",
        active_gopel_config: Optional[Dict[str, Any]] = None,
        behavioral_sample: Optional[BehavioralSample] = None,
        gopel_record_refs: Optional[List[Mapping[str, Any]]] = None,
    ) -> VerificationOutcome:
        """Run the complete two-part verification gate on a transaction.

        This is the main entry point. Called for every transaction that
        passes through GOPEL. Returns a VerificationOutcome indicating
        whether the transaction is clean or flagged, and what action
        (if any) the escalation engine recommends.

        In RAI mode, this runs at machine speed and returns immediately.
        In AIG mode, the outcome triggers CBG notification and the
        pipeline pauses until the human decides.

        v2.5: an escalated outcome publishes one stop line (when a stop
        publisher is attached), naming the finding IDs and, for
        GOPEL-assembled transactions, the GOPEL record IDs and chain
        hashes passed in gopel_record_refs.
        """
        self._total_transactions += 1

        # ---------------------------------------------------------------
        # PART 1: GOPEL Structural Soundness
        # ---------------------------------------------------------------
        structural_result = StructuralResult.STABLE
        structural_findings = []

        if gopel_directory or active_gopel_config:
            structural_result, structural_findings = (
                self.structural_verifier.verify_all(
                    gopel_directory=gopel_directory or self.config.gopel_source_directory,
                    active_config=active_gopel_config or {},
                    behavioral_sample=behavioral_sample
                )
            )
        elif self.config.require_structural_inputs:
            # ChatGPT #2: mandatory structural verification when required
            structural_finding = StructuralFinding(
                result=StructuralResult.FLAGGED,
                category="structural_verification",
                severity=Severity.CRITICAL,
                description="STRUCTURAL_VERIFICATION_NOT_PERFORMED",
                expected_value="structural_inputs_provided",
                actual_value="no_gopel_directory_or_config"
            )
            structural_result = StructuralResult.FLAGGED
            structural_findings = [structural_finding]

        # ---------------------------------------------------------------
        # PART 2: Exchange Alignment
        # ---------------------------------------------------------------

        # Intent inspection
        intent_findings = self.intent_analyzer.analyze(transaction)

        # Context inspection
        context_findings = self.context_inspector.analyze(transaction)

        # Output state inspection
        output_findings = self.output_state_evaluator.analyze(transaction)

        # Combine all Part 2 findings
        all_inspection_findings = intent_findings + context_findings + output_findings

        # ---------------------------------------------------------------
        # TRAJECTORY GATEKEEPER (v2.3) + CALIBRATION (v2.4)
        # ---------------------------------------------------------------
        # Push live calibrated thresholds before trajectory evaluation
        calibrated = self.factics_engine.get_calibrated_thresholds()
        self.intent_analyzer.apply_calibrated_thresholds(calibrated)

        trajectory_alert = self.intent_analyzer.evaluate_trajectory(
            transaction.operator_id, transaction.transaction_id
        )

        # ---------------------------------------------------------------
        # ESCALATION EVALUATION
        # ---------------------------------------------------------------
        outcome = self.escalation_engine.evaluate_with_trajectory(
            transaction_id=transaction.transaction_id,
            structural_result=structural_result,
            structural_findings=structural_findings,
            inspection_findings=all_inspection_findings,
            trajectory_alert=trajectory_alert,
        )
        # v2.6: every outcome carries how the loaded deployment manifest
        # stood, so an unsigned one (local test setting) marks each record.
        if self.structural_verifier.manifest is not None:
            outcome.manifest_status = self.structural_verifier.manifest_status

        # ---------------------------------------------------------------
        # STOP THE PIPE, ROUTE TO HUMAN (v2.5, step 20)
        # ---------------------------------------------------------------
        if outcome.escalated:
            self._publish_stop(outcome, trajectory_alert, gopel_record_refs)

        # ---------------------------------------------------------------
        # POST-VERIFICATION ACTIONS
        # ---------------------------------------------------------------

        # Track clean transactions for envelope refinement
        if outcome.overall_severity == Severity.NOMINAL:
            self._total_clean += 1
            self.output_state_evaluator.record_clean_transaction(
                transaction.recclin_role, ""
            )

        # Track escalations
        if outcome.escalated:
            self._total_escalations += 1

        # Record advisories for random audit accumulation
        for finding in all_inspection_findings:
            if finding.severity == Severity.ADVISORY:
                self.random_audit.record_advisory(finding)

        # ---------------------------------------------------------------
        # EXECUTION GRAPH RECORDING
        # ---------------------------------------------------------------
        self.execution_graph.record_role_assignment(
            transaction.transaction_id,
            transaction.recclin_role.value,
            transaction.operator_id
        )
        if transaction.platforms_dispatched:
            self.execution_graph.record_dispatch(
                transaction.transaction_id,
                transaction.platforms_dispatched,
                transaction.prompt_hash
            )
        for resp in transaction.responses:
            self.execution_graph.record_response(
                transaction.transaction_id,
                resp.platform_id,
                resp.response_hash
            )

        # ---------------------------------------------------------------
        # RANDOM AUDIT CHECK
        # ---------------------------------------------------------------
        if (self.escalation_engine.is_rai_mode()
                and self.random_audit.should_audit()):
            self._generate_random_audit(transaction, outcome)

        return outcome

    # -------------------------------------------------------------------
    # CBG Decision Processing
    # -------------------------------------------------------------------

    def process_cbg_threat_confirmation(
        self,
        finding: InspectionFinding,
        outcome: VerificationOutcome,
        human_rationale: str = "",
        trajectory_alert: Optional[TrajectoryAlert] = None,
    ) -> Dict[str, Any]:
        """Process human governor's confirmation that a finding is a real threat.

        Feeds the confirmed threat into the Factics adaptation cycle.
        If a trajectory_alert is provided, also runs v2.4 calibration.
        Returns the Factics record and any generated proposals.
        """
        # Process through Factics engine
        record = self.factics_engine.process_confirmed_threat(
            finding, outcome, human_rationale
        )

        # Process through escalation engine
        decision = self.escalation_engine.process_cbg_decision(
            transaction_id=finding.transaction_id,
            confirmed_threat=True,
            rationale=human_rationale
        )

        # If chain signature was generated, add to intent analyzer
        new_signatures = self.factics_engine.get_chain_library()
        self.intent_analyzer.load_chain_library(new_signatures)

        # v2.4: Trajectory calibration loop
        calibration_adjustments = self.factics_engine.calibrate_from_trajectory(
            trajectory_alert, confirmed_threat=True
        )

        result = {
            "factics_record": record.to_dict(),
            "escalation_decision": decision,
            "pending_proposals": len(self.factics_engine.get_pending_proposals()),
        }
        if calibration_adjustments:
            result["calibration_adjustments"] = calibration_adjustments
        return result

    def process_cbg_false_positive(
        self,
        finding: InspectionFinding,
        human_rationale: str = "",
        trajectory_alert: Optional[TrajectoryAlert] = None,
    ) -> Dict[str, Any]:
        """Process human governor's ruling that a finding is a false positive.

        Feeds the false positive into the Factics adaptation cycle.
        Adjusts detection to prevent future misclassification.
        If a trajectory_alert is provided, also runs v2.4 calibration.
        """
        record = self.factics_engine.process_confirmed_false_positive(
            finding, human_rationale
        )

        decision = self.escalation_engine.process_cbg_decision(
            transaction_id=finding.transaction_id,
            confirmed_threat=False,
            rationale=human_rationale
        )

        # Add to context inspector's safe patterns if it was a context finding
        if finding.domain.value == "CONTEXT" and finding.evidence_chain:
            for evidence in finding.evidence_chain:
                if "Pattern:" in evidence:
                    pattern = evidence.replace("Pattern: ", "")
                    self.context_inspector.add_safe_pattern(pattern)

        # v2.4: Trajectory calibration loop
        calibration_adjustments = self.factics_engine.calibrate_from_trajectory(
            trajectory_alert, confirmed_threat=False
        )

        result = {
            "factics_record": record.to_dict(),
            "escalation_decision": decision,
        }
        if calibration_adjustments:
            result["calibration_adjustments"] = calibration_adjustments
        return result

    # -------------------------------------------------------------------
    # Random Audit
    # -------------------------------------------------------------------

    def _generate_random_audit(
        self, transaction: TransactionRecord, outcome: VerificationOutcome
    ) -> RandomAuditReport:
        """Generate a random audit report for the current transaction."""
        report = self.random_audit.generate_report(
            transaction=transaction,
            outcome=outcome,
            structural_snapshot=self.structural_verifier.get_structural_snapshot(),
            intent_trajectory=self.intent_analyzer.get_intent_trajectory(
                transaction.operator_id
            ),
            factics_metrics=self.factics_engine.get_metrics_summary()
        )
        return report

    # -------------------------------------------------------------------
    # Heartbeat
    # -------------------------------------------------------------------

    def emit_heartbeat(self) -> Optional[Heartbeat]:
        """Emit a signed heartbeat on the independent channel.
        Returns the heartbeat if interval has elapsed, None otherwise."""
        now = time.time()
        if (now - self._last_heartbeat) < self.config.heartbeat_interval_seconds:
            return None

        # PIPE-01: Heartbeat key enforcement
        if self.config.require_heartbeat_key and self._heartbeat_key is None:
            if not self._heartbeat_key_missing_logged:
                logger.error(
                    "Heartbeat key required but not set; cannot emit unsigned heartbeat"
                )
                self._heartbeat_key_missing_logged = True
            raise RuntimeError(
                "Heartbeat key required by configuration but not set"
            )

        self._heartbeat_sequence += 1
        heartbeat = Heartbeat(
            sequence_number=self._heartbeat_sequence,
            timestamp=now,
            operating_mode=self.escalation_engine.state.current_mode,
            structural_state=(
                StructuralResult.STABLE
                if self.escalation_engine.state.current_severity <= Severity.ADVISORY
                else StructuralResult.FLAGGED
            ),
            last_verification_timestamp=now
        )

        if self._heartbeat_key:
            heartbeat.sign(self._heartbeat_key)

        self._last_heartbeat = now

        # PIPE-02: Callback logging with exception handling
        for cb in self._notification_callbacks:
            try:
                cb(heartbeat)
            except Exception as e:
                logger.warning(
                    "Notification callback failed for heartbeat sequence %d: %s",
                    self._heartbeat_sequence, _sanitize_log(str(e))
                )

        return heartbeat

    # -------------------------------------------------------------------
    # GOPEL Observer Entry Point
    # -------------------------------------------------------------------

    def inspect(
        self,
        transaction: TransactionRecord,
        gopel_directory: str = "",
        deployment_manifest: Any = None,
        active_gopel_config: Optional[Dict[str, Any]] = None,
        gopel_record_refs: Optional[List[Mapping[str, Any]]] = None,
    ) -> VerificationOutcome:
        """First-class entry point for GopelObserver finalization.

        v2.5: the observer passes its structural inputs (the GOPEL
        directory, the signed deployment manifest and GOPEL's active
        config) so Part 1 structural verification runs on its schedule
        instead of every transaction being flagged as not performed, and
        the transaction's GOPEL record refs, which a stop names as sources.
        Called with the transaction alone it behaves as in v2.4.
        """
        if deployment_manifest is not None:
            self.structural_verifier.use_manifest(deployment_manifest)
        return self.verify_transaction(
            transaction,
            gopel_directory=gopel_directory,
            active_gopel_config=active_gopel_config,
            gopel_record_refs=gopel_record_refs,
        )

    # -------------------------------------------------------------------
    # Stop the pipe (v2.5, step 20)
    # -------------------------------------------------------------------

    def _publish_stop(
        self,
        outcome: VerificationOutcome,
        trajectory_alert: Optional[TrajectoryAlert],
        gopel_record_refs: Optional[List[Mapping[str, Any]]],
    ) -> None:
        """Publish one stop for an escalated outcome. Without a publisher no
        stop is possible and nothing raises; a failed write is logged and
        counted, never raised into the inspection path."""
        if self._stop_publisher is None:
            return
        if trajectory_alert is not None:
            trigger = "TRAJECTORY"
        elif outcome.overall_severity == Severity.HALT:
            trigger = "HALT"
        else:
            trigger = "CRITICAL"
        # M2, sources always: the stop names what triggered it, the
        # structural and inspection findings and, for a trajectory
        # escalation, the trajectory alert itself.
        finding_ids = (
            [f.finding_id for f in outcome.structural_findings]
            + [f.finding_id for f in outcome.inspection_findings]
        )
        if trajectory_alert is not None and trajectory_alert.alert_id not in finding_ids:
            finding_ids.append(trajectory_alert.alert_id)
        try:
            published = self._stop_publisher.publish(
                transaction_id=outcome.transaction_id,
                trigger=trigger,
                finding_ids=finding_ids,
                gopel_record_refs=list(gopel_record_refs or []),
            )
            outcome.stop_event_id = published["event_id"]
            self._stops_published += 1
        except Exception as e:
            self._stop_publish_failures += 1
            logger.critical(
                "Stop could not be published for transaction %s: %s",
                _sanitize_log(str(outcome.transaction_id)), _sanitize_log(str(e)),
            )

    # -------------------------------------------------------------------
    # Status and Monitoring
    # -------------------------------------------------------------------

    def get_status(self) -> Dict[str, Any]:
        """Return current Overwatch status for monitoring."""
        return {
            "version": self.VERSION,
            "operating_mode": self.escalation_engine.state.current_mode.value,
            "current_severity": self.escalation_engine.state.current_severity.value,
            "uptime_seconds": time.time() - self._start_time,
            "total_transactions": self._total_transactions,
            "total_clean": self._total_clean,
            "total_escalations": self._total_escalations,
            "clean_rate": (
                self._total_clean / self._total_transactions
                if self._total_transactions > 0 else 1.0
            ),
            "escalation_engine": self.escalation_engine.get_state(),
            "factics_kpis": self.factics_engine.get_kpis(),
            "random_audit": self.random_audit.get_audit_statistics(),
            "heartbeat_sequence": self._heartbeat_sequence,
            "health": self.get_health()
        }

    def get_health(self) -> Dict[str, Any]:
        """Return internal health metrics for self-monitoring.

        Exposes operational internals that the heartbeat and external
        monitors can reference to detect degraded pipeline state.
        """
        factics_records = self.factics_engine.get_records()
        last_factics_cycle = (
            factics_records[-1].timestamp if factics_records else None
        )
        return {
            "pending_proposals_count": len(
                self.factics_engine.get_pending_proposals()
            ),
            "last_factics_cycle": last_factics_cycle,
            "execution_graph_operators": len(
                self.execution_graph._graphs
            ),
            "total_transactions": self._total_transactions,
            "total_escalations": self._total_escalations,
            "total_clean": self._total_clean,
            "uptime_seconds": time.time() - self._start_time,
            "heartbeat_sequence": self._heartbeat_sequence,
            "observer_buffer_depth": (
                len(self._gopel_observer._buffers) if self._gopel_observer else 0
            ),
            "stop_channel": (
                "configured" if self._stop_publisher is not None else "not configured"
            ),
            "stops_published": self._stops_published,
            "stop_publish_failures": self._stop_publish_failures,
            "manifest_mode": (
                "local test: unsigned manifests accepted"
                if getattr(self.config, "local_test_unsigned_manifests", False)
                else "signed manifest required"
            ),
        }

    def correlate_cross_operator(
        self, operator_ids: List[str]
    ) -> List[InspectionFinding]:
        """Correlate intent windows across multiple operators.

        Detects multi-turn attacks split across operator sessions.
        Returns findings from the merged window analysis.
        """
        from collections import deque

        merged_window: deque = deque(
            maxlen=self.config.intent_window_size * len(operator_ids)
        )

        for op_id in operator_ids:
            window = self.intent_analyzer._get_window(op_id)
            for snapshot in window:
                merged_window.append(snapshot)

        # Sort by timestamp
        sorted_snapshots = sorted(merged_window, key=lambda s: s.timestamp)

        # Temporarily install merged window and run checks
        temp_op_id = "__cross_operator_correlation__"
        self.intent_analyzer._intent_windows[temp_op_id] = deque(
            sorted_snapshots, maxlen=len(sorted_snapshots) + 1
        )

        findings: List[InspectionFinding] = []

        try:
            # Run scope trajectory check
            scope_finding = self.intent_analyzer._check_scope_trajectory(
                temp_op_id, f"cross_operator_{'_'.join(operator_ids)}"
            )
            if scope_finding:
                scope_finding.description = f"[CROSS-OPERATOR] {scope_finding.description}"
                scope_finding.evidence_chain.insert(
                    0, f"Correlated operators: {', '.join(operator_ids)}"
                )
                findings.append(scope_finding)

            # Run privilege gradient check
            priv_finding = self.intent_analyzer._check_privilege_gradient(
                temp_op_id, f"cross_operator_{'_'.join(operator_ids)}"
            )
            if priv_finding:
                priv_finding.description = f"[CROSS-OPERATOR] {priv_finding.description}"
                priv_finding.evidence_chain.insert(
                    0, f"Correlated operators: {', '.join(operator_ids)}"
                )
                findings.append(priv_finding)
        finally:
            # Cleanup: always remove temporary window, even on exception
            self.intent_analyzer._intent_windows.pop(temp_op_id, None)

        return findings

    def get_factics_proposals(self) -> List[Dict[str, Any]]:
        """Return pending Factics rule proposals for CBG review."""
        return self.factics_engine.get_pending_proposals()
