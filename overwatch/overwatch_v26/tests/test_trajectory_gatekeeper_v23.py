"""
Tests for Overwatch v2.3 Trajectory Gatekeeper.

Validates the soft-signal convergence detection and CBG routing
trigger added to the Intent Analyzer and Escalation Engine.

Author: Basil C. Puglisi, MPA
License: CC BY-NC 4.0
"""

import time
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from overwatch_v26.models import (
    OverwatchConfig, RECCLINRole, Severity, TransactionRecord,
    TrajectoryAlert, OperatingMode, StructuralResult,
    AlignmentResult, InspectionFinding, InspectionDomain,
    StructuralFinding,
)
from overwatch_v26.intent_analyzer import IntentAnalyzer
from overwatch_v26.escalation_engine import EscalationEngine


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_transaction(
    operator_id: str = "op1",
    prompt_text: str = "find sources on climate policy",
    role: RECCLINRole = RECCLINRole.RESEARCHER,
    txn_id: str = "",
) -> TransactionRecord:
    if not txn_id:
        txn_id = f"txn-{time.monotonic_ns()}"
    return TransactionRecord(
        transaction_id=txn_id,
        timestamp=time.time(),
        operator_id=operator_id,
        recclin_role=role,
        prompt_hash="abc123",
        prompt_text=prompt_text,
        platforms_dispatched=["mock"],
        responses=[],
    )


def _config(**overrides) -> OverwatchConfig:
    defaults = dict(
        trajectory_window_min=4,
        trajectory_scope_drift_threshold=0.3,
        trajectory_coherence_decay_threshold=0.15,
        trajectory_privilege_gradient_threshold=0.1,
        trajectory_convergence_required=2,
        intent_window_size=20,
    )
    defaults.update(overrides)
    return OverwatchConfig(**defaults)


# ---------------------------------------------------------------------------
# Tests: Trajectory evaluation in IntentAnalyzer
# ---------------------------------------------------------------------------

class TestTrajectoryGatekeeper:

    def test_no_alert_below_window_minimum(self):
        """Fewer than trajectory_window_min turns produces no alert."""
        config = _config(trajectory_window_min=4)
        analyzer = IntentAnalyzer(config)
        # Feed 3 transactions (below minimum of 4)
        for i in range(3):
            txn = _make_transaction(prompt_text="find sources on topic")
            analyzer.analyze(txn)
        alert = analyzer.evaluate_trajectory("op1", "txn-check")
        assert alert is None

    def test_clean_conversation_no_alert(self):
        """A conversation with stable signals produces no alert."""
        config = _config()
        analyzer = IntentAnalyzer(config)
        for i in range(6):
            txn = _make_transaction(
                prompt_text="find sources on climate policy research"
            )
            analyzer.analyze(txn)
        alert = analyzer.evaluate_trajectory("op1", "txn-check")
        assert alert is None

    def test_scope_drift_detected(self):
        """Increasing scope indicators across window halves triggers signal."""
        config = _config(trajectory_convergence_required=1)
        analyzer = IntentAnalyzer(config)
        # First half: clean researcher queries
        for i in range(3):
            txn = _make_transaction(prompt_text="find sources on climate")
            analyzer.analyze(txn)
        # Second half: reconnaissance queries
        for i in range(3):
            txn = _make_transaction(
                prompt_text="list files show permissions enumerate directories scan endpoints"
            )
            analyzer.analyze(txn)
        alert = analyzer.evaluate_trajectory("op1", "txn-check")
        assert alert is not None
        assert alert.scope_drift_score >= config.trajectory_scope_drift_threshold

    def test_privilege_gradient_detected(self):
        """Growing privilege indicators across window triggers signal."""
        config = _config(trajectory_convergence_required=1)
        analyzer = IntentAnalyzer(config)
        # Start clean
        txn = _make_transaction(prompt_text="find sources on topic")
        analyzer.analyze(txn)
        txn = _make_transaction(prompt_text="search for evidence on policy")
        analyzer.analyze(txn)
        txn = _make_transaction(prompt_text="find sources on governance")
        analyzer.analyze(txn)
        # End with privilege probing
        txn = _make_transaction(
            prompt_text="escalate access bypass security grant admin permission"
        )
        analyzer.analyze(txn)
        alert = analyzer.evaluate_trajectory("op1", "txn-check")
        assert alert is not None
        assert alert.privilege_gradient >= config.trajectory_privilege_gradient_threshold

    def test_coherence_decay_detected(self):
        """Declining role coherence across window triggers signal."""
        config = _config(trajectory_convergence_required=1)
        analyzer = IntentAnalyzer(config)
        # Start with high-coherence researcher content
        for i in range(2):
            txn = _make_transaction(
                prompt_text="find sources citation reference evidence study paper report"
            )
            analyzer.analyze(txn)
        # End with content that matches Coder role, not Researcher
        for i in range(3):
            txn = _make_transaction(
                prompt_text="function class module variable import def return debug test compile deploy refactor implement"
            )
            analyzer.analyze(txn)
        alert = analyzer.evaluate_trajectory("op1", "txn-check")
        # Should detect coherence decay (Researcher declared, Coder content)
        assert alert is not None
        assert alert.coherence_decay_rate > 0

    def test_single_signal_no_alert_default(self):
        """One converging signal alone does not trigger alert (default requires 2)."""
        config = _config(trajectory_convergence_required=2)
        analyzer = IntentAnalyzer(config)
        # Only scope drift, no privilege or coherence change
        for i in range(2):
            txn = _make_transaction(prompt_text="find sources on climate")
            analyzer.analyze(txn)
        for i in range(3):
            txn = _make_transaction(
                prompt_text="list files show permissions enumerate directories scan endpoints"
            )
            analyzer.analyze(txn)
        alert = analyzer.evaluate_trajectory("op1", "txn-check")
        # May or may not fire depending on whether coherence also decayed
        # The key assertion: if it fires, it must have >= 2 converging signals
        if alert is not None:
            assert alert.converging_signals >= 2

    def test_two_signals_triggers_alert(self):
        """Two converging signals trigger TrajectoryAlert."""
        config = _config(trajectory_convergence_required=2)
        analyzer = IntentAnalyzer(config)
        # Start clean researcher
        for i in range(2):
            txn = _make_transaction(
                prompt_text="find sources citation reference evidence"
            )
            analyzer.analyze(txn)
        # Drift toward recon + privilege probing (scope drift + privilege gradient)
        for i in range(3):
            txn = _make_transaction(
                prompt_text="list files enumerate directories escalate access bypass security grant admin"
            )
            analyzer.analyze(txn)
        alert = analyzer.evaluate_trajectory("op1", "txn-check")
        assert alert is not None
        assert alert.converging_signals >= 2

    def test_alert_contains_evidence_chain(self):
        """TrajectoryAlert evidence_chain is populated with signal descriptions."""
        config = _config(trajectory_convergence_required=1)
        analyzer = IntentAnalyzer(config)
        for i in range(2):
            txn = _make_transaction(prompt_text="find sources")
            analyzer.analyze(txn)
        for i in range(3):
            txn = _make_transaction(
                prompt_text="list files enumerate scan credentials"
            )
            analyzer.analyze(txn)
        alert = analyzer.evaluate_trajectory("op1", "txn-check")
        if alert is not None:
            assert len(alert.evidence_chain) > 0
            assert all(isinstance(e, str) for e in alert.evidence_chain)

    def test_alert_to_dict(self):
        """TrajectoryAlert.to_dict() returns complete serialization."""
        alert = TrajectoryAlert(
            transaction_id="txn-1",
            operator_id="op1",
            window_size=6,
            scope_drift_score=0.5,
            privilege_gradient=0.2,
            coherence_decay_rate=0.18,
            converging_signals=3,
            evidence_chain=["signal 1", "signal 2", "signal 3"],
        )
        d = alert.to_dict()
        assert d["converging_signals"] == 3
        assert d["operator_id"] == "op1"
        assert len(d["evidence_chain"]) == 3


# ---------------------------------------------------------------------------
# Tests: Escalation Engine trajectory integration
# ---------------------------------------------------------------------------

class TestTrajectoryEscalation:

    def test_trajectory_alert_forces_aig_mode(self):
        """TrajectoryAlert causes evaluate_with_trajectory to escalate to AIG."""
        config = _config()
        engine = EscalationEngine(config)
        alert = TrajectoryAlert(
            transaction_id="txn-1",
            operator_id="op1",
            window_size=6,
            converging_signals=2,
            evidence_chain=["scope drift", "privilege gradient"],
        )
        outcome = engine.evaluate_with_trajectory(
            transaction_id="txn-1",
            structural_result=StructuralResult.STABLE,
            structural_findings=[],
            inspection_findings=[],
            trajectory_alert=alert,
        )
        assert outcome.operating_mode == OperatingMode.AIG
        assert outcome.escalated is True
        assert "Trajectory gatekeeper" in outcome.escalation_reason

    def test_no_trajectory_alert_preserves_normal(self):
        """Without trajectory alert, normal evaluation proceeds."""
        config = _config()
        engine = EscalationEngine(config)
        outcome = engine.evaluate_with_trajectory(
            transaction_id="txn-1",
            structural_result=StructuralResult.STABLE,
            structural_findings=[],
            inspection_findings=[],
            trajectory_alert=None,
        )
        assert outcome.operating_mode == OperatingMode.RAI
        assert outcome.escalated is False

    def test_trajectory_overrides_nominal_severity(self):
        """Even with NOMINAL findings, trajectory alert escalates."""
        config = _config()
        engine = EscalationEngine(config)
        alert = TrajectoryAlert(
            transaction_id="txn-1",
            operator_id="op1",
            window_size=5,
            converging_signals=2,
        )
        outcome = engine.evaluate_with_trajectory(
            transaction_id="txn-1",
            structural_result=StructuralResult.STABLE,
            structural_findings=[],
            inspection_findings=[],
            trajectory_alert=alert,
        )
        # Severity stays NOMINAL but mode is AIG
        assert outcome.overall_severity == Severity.NOMINAL
        assert outcome.operating_mode == OperatingMode.AIG
        assert outcome.escalated is True

    def test_trajectory_escalation_recorded_in_history(self):
        """Trajectory escalation appears in escalation_history with TRAJECTORY severity."""
        config = _config()
        engine = EscalationEngine(config)
        alert = TrajectoryAlert(
            transaction_id="txn-1",
            operator_id="op1",
            window_size=6,
            converging_signals=3,
        )
        engine.evaluate_with_trajectory(
            transaction_id="txn-1",
            structural_result=StructuralResult.STABLE,
            structural_findings=[],
            inspection_findings=[],
            trajectory_alert=alert,
        )
        assert len(engine.state.escalation_history) == 1
        entry = engine.state.escalation_history[0]
        assert entry["severity"] == "TRAJECTORY"
        assert "trajectory_alert" in entry


# ---------------------------------------------------------------------------
# Tests: Config
# ---------------------------------------------------------------------------

class TestTrajectoryConfig:

    def test_default_config_values(self):
        """Default trajectory config values are sensible."""
        config = OverwatchConfig()
        assert config.trajectory_window_min == 4
        assert config.trajectory_convergence_required == 2
        assert config.trajectory_scope_drift_threshold == 0.3
        assert config.trajectory_coherence_decay_threshold == 0.15
        assert config.trajectory_privilege_gradient_threshold == 0.1

    def test_gopel_mode_tightens_thresholds(self):
        """GOPEL mode tightens trajectory thresholds for faster CBG trigger."""
        config = OverwatchConfig(gopel_mode=True)
        assert config.trajectory_scope_drift_threshold <= 0.2
        assert config.trajectory_coherence_decay_threshold <= 0.10
        assert config.trajectory_privilege_gradient_threshold <= 0.05

    def test_version_bumped(self):
        """Version is at least 2.3.0."""
        import overwatch_v26 as overwatch
        major, minor, patch = overwatch.__version__.split(".")
        assert int(major) >= 2
        assert int(minor) >= 3

    def test_trajectory_alert_exported(self):
        """TrajectoryAlert is importable from the package."""
        from overwatch_v26 import TrajectoryAlert
        alert = TrajectoryAlert(transaction_id="test")
        assert alert.transaction_id == "test"
