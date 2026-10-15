"""
Tests for Overwatch v2.4 Factics Calibration.

Validates tamper-evident CalibrationState, asymmetric adjustment,
per-signal independence, exponential smoothing, oscillation prevention,
floor/ceiling clamping, and full pipeline integration.

Author: Basil C. Puglisi, MPA
License: CC BY-NC 4.0
"""

import os
import time
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from overwatch_v25.models import (
    CalibrationState, OverwatchConfig, RECCLINRole, Severity,
    TrajectoryAlert, TransactionRecord, VerificationOutcome,
    InspectionFinding, InspectionDomain, AlignmentResult,
    StructuralResult, StructuralFinding, OperatingMode,
)
from overwatch_v25.factics_engine import FacticsEngine
from overwatch_v25.intent_analyzer import IntentAnalyzer
from overwatch_v25.escalation_engine import EscalationEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SIGNING_KEY = b"A" * 32  # 32-byte key for testing


def _make_alert(
    scope=0.5, priv=0.2, coherence=0.2, signals=2, evidence=None
) -> TrajectoryAlert:
    return TrajectoryAlert(
        transaction_id="txn-cal-test",
        operator_id="op1",
        window_size=6,
        scope_drift_score=scope,
        privilege_gradient=priv,
        coherence_decay_rate=coherence,
        converging_signals=signals,
        evidence_chain=evidence or [
            "Scope drift: indicator rate increased",
            "Privilege gradient: 0.200",
        ],
    )


def _make_config(**overrides) -> OverwatchConfig:
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
# Tests: CalibrationState dataclass
# ---------------------------------------------------------------------------

class TestCalibrationState:

    def test_sign_and_verify(self):
        """Signed state verifies correctly."""
        state = CalibrationState()
        state.sign(SIGNING_KEY)
        assert state.verify(SIGNING_KEY)

    def test_unsigned_fails_verify(self):
        """Unsigned state fails verification."""
        state = CalibrationState()
        assert not state.verify(SIGNING_KEY)

    def test_tamper_detected(self):
        """Modifying state after signing fails verification."""
        state = CalibrationState()
        state.sign(SIGNING_KEY)
        assert state.verify(SIGNING_KEY)
        # Tamper with a threshold
        state.scope_drift_threshold = 0.99
        assert not state.verify(SIGNING_KEY)

    def test_tamper_incident_counter(self):
        """Modifying incident counters after signing fails verification."""
        state = CalibrationState()
        state.sign(SIGNING_KEY)
        state.scope_drift_threats = 999
        assert not state.verify(SIGNING_KEY)

    def test_tamper_rates(self):
        """Modifying calibration rates after signing fails verification."""
        state = CalibrationState()
        state.sign(SIGNING_KEY)
        state.tighten_rate = 0.0  # Attempt to disable tightening
        assert not state.verify(SIGNING_KEY)

    def test_wrong_key_fails_verify(self):
        """Verification with wrong key fails."""
        state = CalibrationState()
        state.sign(SIGNING_KEY)
        wrong_key = b"B" * 32
        assert not state.verify(wrong_key)

    def test_record_threat(self):
        """record_threat increments the correct signal counter."""
        state = CalibrationState()
        state.record_threat("scope_drift")
        assert state.scope_drift_threats == 1
        assert state.coherence_decay_threats == 0
        assert state.privilege_gradient_threats == 0

    def test_record_false_positive(self):
        """record_false_positive increments the correct signal counter."""
        state = CalibrationState()
        state.record_false_positive("privilege_gradient")
        assert state.privilege_gradient_false_positives == 1
        assert state.scope_drift_false_positives == 0

    def test_get_thresholds(self):
        """get_thresholds returns current values."""
        state = CalibrationState(
            scope_drift_threshold=0.25,
            coherence_decay_threshold=0.12,
            privilege_gradient_threshold=0.08,
        )
        t = state.get_thresholds()
        assert t["scope_drift"] == 0.25
        assert t["coherence_decay"] == 0.12
        assert t["privilege_gradient"] == 0.08

    def test_to_dict(self):
        """to_dict serializes completely."""
        state = CalibrationState()
        state.sign(SIGNING_KEY)
        d = state.to_dict()
        assert "thresholds" in d
        assert "incidents" in d
        assert "signature" in d
        assert d["signature"] != ""


# ---------------------------------------------------------------------------
# Tests: Asymmetric Adjustment
# ---------------------------------------------------------------------------

class TestAsymmetricAdjustment:

    def test_tighten_on_threats(self):
        """More threats than FPs tightens the threshold."""
        state = CalibrationState(min_incidents_before_adjust=3)
        state.sign(SIGNING_KEY)
        # 3 threats, 0 FPs for scope_drift
        for _ in range(3):
            state.record_threat("scope_drift")
        original = state.scope_drift_threshold
        adjustments = state.maybe_adjust(SIGNING_KEY)
        assert len(adjustments) == 1
        assert adjustments[0]["direction"] == "tighten"
        assert state.scope_drift_threshold < original

    def test_loosen_on_false_positives(self):
        """More FPs than threats loosens the threshold."""
        state = CalibrationState(min_incidents_before_adjust=3)
        state.sign(SIGNING_KEY)
        for _ in range(3):
            state.record_false_positive("scope_drift")
        original = state.scope_drift_threshold
        adjustments = state.maybe_adjust(SIGNING_KEY)
        assert len(adjustments) == 1
        assert adjustments[0]["direction"] == "loosen"
        assert state.scope_drift_threshold > original

    def test_asymmetric_rates(self):
        """Tightening moves threshold more than loosening (10% vs 5%)."""
        # Tighten path
        state_t = CalibrationState(
            scope_drift_threshold=0.30,
            min_incidents_before_adjust=3,
            smoothing_alpha=1.0,  # No smoothing for clean comparison
        )
        state_t.sign(SIGNING_KEY)
        for _ in range(3):
            state_t.record_threat("scope_drift")
        state_t.maybe_adjust(SIGNING_KEY)
        tighten_delta = abs(0.30 - state_t.scope_drift_threshold)

        # Loosen path
        state_l = CalibrationState(
            scope_drift_threshold=0.30,
            min_incidents_before_adjust=3,
            smoothing_alpha=1.0,
        )
        state_l.sign(SIGNING_KEY)
        for _ in range(3):
            state_l.record_false_positive("scope_drift")
        state_l.maybe_adjust(SIGNING_KEY)
        loosen_delta = abs(state_l.scope_drift_threshold - 0.30)

        assert tighten_delta > loosen_delta  # 10% > 5%

    def test_equal_incidents_no_change(self):
        """Equal threats and FPs produces no threshold change."""
        state = CalibrationState(
            scope_drift_threshold=0.30,
            min_incidents_before_adjust=2,
        )
        state.sign(SIGNING_KEY)
        state.record_threat("scope_drift")
        state.record_false_positive("scope_drift")
        adjustments = state.maybe_adjust(SIGNING_KEY)
        # No adjustment, just counter reset
        assert len(adjustments) == 0
        assert state.scope_drift_threshold == 0.30
        assert state.scope_drift_threats == 0  # Counters reset


# ---------------------------------------------------------------------------
# Tests: Per-Signal Independence
# ---------------------------------------------------------------------------

class TestPerSignalIndependence:

    def test_signals_adjust_independently(self):
        """Each signal adjusts based on its own incident history."""
        state = CalibrationState(min_incidents_before_adjust=3)
        state.sign(SIGNING_KEY)

        # scope_drift: 3 threats -> tighten
        for _ in range(3):
            state.record_threat("scope_drift")
        # privilege_gradient: 3 FPs -> loosen
        for _ in range(3):
            state.record_false_positive("privilege_gradient")
        # coherence_decay: only 1 incident -> no change
        state.record_threat("coherence_decay")

        original_scope = state.scope_drift_threshold
        original_priv = state.privilege_gradient_threshold
        original_coh = state.coherence_decay_threshold

        adjustments = state.maybe_adjust(SIGNING_KEY)

        assert state.scope_drift_threshold < original_scope  # Tightened
        assert state.privilege_gradient_threshold > original_priv  # Loosened
        assert state.coherence_decay_threshold == original_coh  # Unchanged
        assert len(adjustments) == 2  # Only scope and privilege adjusted

    def test_counters_reset_after_adjustment(self):
        """Incident counters reset to 0 after adjustment fires."""
        state = CalibrationState(min_incidents_before_adjust=3)
        state.sign(SIGNING_KEY)
        for _ in range(3):
            state.record_threat("scope_drift")
        state.maybe_adjust(SIGNING_KEY)
        assert state.scope_drift_threats == 0
        assert state.scope_drift_false_positives == 0


# ---------------------------------------------------------------------------
# Tests: Smoothing and Oscillation Prevention
# ---------------------------------------------------------------------------

class TestSmoothingAndOscillation:

    def test_smoothing_dampens_adjustment(self):
        """Exponential smoothing reduces the magnitude of adjustment."""
        # With smoothing (alpha=0.3, default)
        state_smooth = CalibrationState(
            scope_drift_threshold=0.30,
            min_incidents_before_adjust=3,
            smoothing_alpha=0.3,
        )
        state_smooth.sign(SIGNING_KEY)
        for _ in range(3):
            state_smooth.record_threat("scope_drift")
        state_smooth.maybe_adjust(SIGNING_KEY)

        # Without smoothing (alpha=1.0)
        state_raw = CalibrationState(
            scope_drift_threshold=0.30,
            min_incidents_before_adjust=3,
            smoothing_alpha=1.0,
        )
        state_raw.sign(SIGNING_KEY)
        for _ in range(3):
            state_raw.record_threat("scope_drift")
        state_raw.maybe_adjust(SIGNING_KEY)

        # Smoothed adjustment should be smaller
        smooth_delta = abs(0.30 - state_smooth.scope_drift_threshold)
        raw_delta = abs(0.30 - state_raw.scope_drift_threshold)
        assert smooth_delta < raw_delta

    def test_min_incidents_prevents_premature_adjustment(self):
        """Below min_incidents_before_adjust, no adjustment fires."""
        state = CalibrationState(min_incidents_before_adjust=3)
        state.sign(SIGNING_KEY)
        state.record_threat("scope_drift")
        state.record_threat("scope_drift")
        # Only 2 incidents, need 3
        adjustments = state.maybe_adjust(SIGNING_KEY)
        assert len(adjustments) == 0
        assert state.scope_drift_threshold == 0.30  # Unchanged

    def test_repeated_tightening_converges_to_floor(self):
        """Repeated confirmed threats eventually hit the floor, not below."""
        state = CalibrationState(
            scope_drift_threshold=0.30,
            min_incidents_before_adjust=3,
            smoothing_alpha=1.0,  # No smoothing for faster convergence
            scope_drift_floor=0.15,
        )
        state.sign(SIGNING_KEY)
        for cycle in range(50):
            for _ in range(3):
                state.record_threat("scope_drift")
            state.maybe_adjust(SIGNING_KEY)
        assert state.scope_drift_threshold == state.scope_drift_floor

    def test_repeated_loosening_converges_to_ceiling(self):
        """Repeated false positives eventually hit the ceiling, not above."""
        state = CalibrationState(
            scope_drift_threshold=0.30,
            min_incidents_before_adjust=3,
            smoothing_alpha=1.0,
            scope_drift_ceiling=0.60,
        )
        state.sign(SIGNING_KEY)
        for cycle in range(50):
            for _ in range(3):
                state.record_false_positive("scope_drift")
            state.maybe_adjust(SIGNING_KEY)
        assert state.scope_drift_threshold == state.scope_drift_ceiling


# ---------------------------------------------------------------------------
# Tests: Floor and Ceiling Bounds
# ---------------------------------------------------------------------------

class TestFloorCeiling:

    def test_floor_prevents_over_tightening(self):
        """Threshold cannot go below floor even with extreme tightening."""
        state = CalibrationState(
            scope_drift_threshold=0.16,  # Just above floor of 0.15
            min_incidents_before_adjust=3,
            smoothing_alpha=1.0,
            tighten_rate=0.50,  # Aggressive 50% tighten
            scope_drift_floor=0.15,
        )
        state.sign(SIGNING_KEY)
        for _ in range(3):
            state.record_threat("scope_drift")
        state.maybe_adjust(SIGNING_KEY)
        assert state.scope_drift_threshold >= state.scope_drift_floor

    def test_ceiling_prevents_over_loosening(self):
        """Threshold cannot go above ceiling even with extreme loosening."""
        state = CalibrationState(
            scope_drift_threshold=0.58,  # Just below ceiling of 0.60
            min_incidents_before_adjust=3,
            smoothing_alpha=1.0,
            loosen_rate=0.50,
            scope_drift_ceiling=0.60,
        )
        state.sign(SIGNING_KEY)
        for _ in range(3):
            state.record_false_positive("scope_drift")
        state.maybe_adjust(SIGNING_KEY)
        assert state.scope_drift_threshold <= state.scope_drift_ceiling

    def test_all_signals_have_bounds(self):
        """All three signals have floor and ceiling defined."""
        state = CalibrationState()
        for signal in ("scope_drift", "coherence_decay", "privilege_gradient"):
            floor = getattr(state, f"{signal}_floor")
            ceiling = getattr(state, f"{signal}_ceiling")
            threshold = getattr(state, f"{signal}_threshold")
            assert floor < ceiling
            assert floor <= threshold <= ceiling


# ---------------------------------------------------------------------------
# Tests: Tamper Evidence in Factics Engine
# ---------------------------------------------------------------------------

class TestFacticsCalibrationIntegration:

    def test_set_calibration_key_signs_state(self):
        """Setting calibration key immediately signs the state."""
        engine = FacticsEngine()
        engine.set_calibration_key(SIGNING_KEY)
        assert engine._calibration_state.verify(SIGNING_KEY)

    def test_key_too_short_raises(self):
        """Key shorter than 32 bytes raises ValueError."""
        engine = FacticsEngine()
        with pytest.raises(ValueError):
            engine.set_calibration_key(b"short")

    def test_get_calibration_state_verifies(self):
        """get_calibration_state verifies integrity before returning."""
        engine = FacticsEngine()
        engine.set_calibration_key(SIGNING_KEY)
        state = engine.get_calibration_state()
        assert state is engine._calibration_state

    def test_tampered_state_raises_on_get(self):
        """Tampered CalibrationState raises RuntimeError on get."""
        engine = FacticsEngine()
        engine.set_calibration_key(SIGNING_KEY)
        # Tamper directly
        engine._calibration_state.scope_drift_threshold = 0.99
        with pytest.raises(RuntimeError, match="tampered"):
            engine.get_calibration_state()

    def test_tampered_state_falls_back_on_thresholds(self):
        """get_calibrated_thresholds falls back to config defaults when tampered."""
        config = _make_config()
        engine = FacticsEngine(config=config)
        engine.set_calibration_key(SIGNING_KEY)
        # Tamper
        engine._calibration_state.scope_drift_threshold = 0.99
        thresholds = engine.get_calibrated_thresholds()
        # Should return config defaults, not tampered values
        assert thresholds["scope_drift"] == config.trajectory_scope_drift_threshold

    def test_no_key_returns_config_defaults(self):
        """Without calibration key, get_calibrated_thresholds returns config defaults."""
        config = _make_config()
        engine = FacticsEngine(config=config)
        thresholds = engine.get_calibrated_thresholds()
        assert thresholds["scope_drift"] == config.trajectory_scope_drift_threshold

    def test_calibrate_from_trajectory_threat(self):
        """calibrate_from_trajectory records threat for converging signals."""
        config = _make_config()
        engine = FacticsEngine(config=config)
        engine.set_calibration_key(SIGNING_KEY)
        alert = _make_alert(scope=0.5, priv=0.2, coherence=0.0)
        engine.calibrate_from_trajectory(alert, confirmed_threat=True)
        state = engine.get_calibration_state()
        assert state.scope_drift_threats == 1
        assert state.privilege_gradient_threats == 1
        assert state.coherence_decay_threats == 0  # Below threshold

    def test_calibrate_from_trajectory_false_positive(self):
        """calibrate_from_trajectory records FP for converging signals."""
        config = _make_config()
        engine = FacticsEngine(config=config)
        engine.set_calibration_key(SIGNING_KEY)
        alert = _make_alert(scope=0.5, priv=0.2, coherence=0.2)
        engine.calibrate_from_trajectory(alert, confirmed_threat=False)
        state = engine.get_calibration_state()
        assert state.scope_drift_false_positives == 1
        assert state.privilege_gradient_false_positives == 1
        assert state.coherence_decay_false_positives == 1

    def test_calibrate_triggers_adjustment_after_min_incidents(self):
        """Adjustment fires after min_incidents_before_adjust outcomes."""
        config = _make_config()
        engine = FacticsEngine(config=config)
        engine.set_calibration_key(SIGNING_KEY)
        engine._calibration_state.min_incidents_before_adjust = 3

        original = engine._calibration_state.scope_drift_threshold
        alert = _make_alert(scope=0.5, priv=0.0, coherence=0.0)

        # 3 confirmed threats on scope_drift signal
        for _ in range(3):
            adjustments = engine.calibrate_from_trajectory(alert, confirmed_threat=True)

        # Third call should trigger adjustment
        assert len(adjustments) >= 1
        assert engine._calibration_state.scope_drift_threshold < original

    def test_calibrate_no_key_is_noop(self):
        """Without calibration key, calibrate_from_trajectory is a no-op."""
        engine = FacticsEngine()
        alert = _make_alert()
        adjustments = engine.calibrate_from_trajectory(alert, confirmed_threat=True)
        assert adjustments == []

    def test_calibrate_none_alert_is_noop(self):
        """With None alert, calibrate_from_trajectory is a no-op."""
        engine = FacticsEngine()
        engine.set_calibration_key(SIGNING_KEY)
        adjustments = engine.calibrate_from_trajectory(None, confirmed_threat=True)
        assert adjustments == []

    def test_calibrate_refuses_on_tamper(self):
        """calibrate_from_trajectory refuses to modify tampered state."""
        config = _make_config()
        engine = FacticsEngine(config=config)
        engine.set_calibration_key(SIGNING_KEY)
        # Tamper
        engine._calibration_state.scope_drift_threshold = 0.99
        alert = _make_alert()
        adjustments = engine.calibrate_from_trajectory(alert, confirmed_threat=True)
        assert adjustments == []

    def test_metrics_include_calibration(self):
        """get_metrics_summary includes calibration state."""
        engine = FacticsEngine()
        engine.set_calibration_key(SIGNING_KEY)
        summary = engine.get_metrics_summary()
        assert "calibration" in summary
        assert "thresholds" in summary["calibration"]


# ---------------------------------------------------------------------------
# Tests: Intent Analyzer Live Threshold Application
# ---------------------------------------------------------------------------

class TestIntentAnalyzerCalibration:

    def test_apply_calibrated_thresholds(self):
        """apply_calibrated_thresholds updates config values."""
        config = _make_config()
        analyzer = IntentAnalyzer(config)
        analyzer.apply_calibrated_thresholds({
            "scope_drift": 0.22,
            "coherence_decay": 0.08,
            "privilege_gradient": 0.06,
        })
        assert config.trajectory_scope_drift_threshold == 0.22
        assert config.trajectory_coherence_decay_threshold == 0.08
        assert config.trajectory_privilege_gradient_threshold == 0.06

    def test_partial_threshold_update(self):
        """Only specified thresholds are updated."""
        config = _make_config()
        analyzer = IntentAnalyzer(config)
        original_coherence = config.trajectory_coherence_decay_threshold
        analyzer.apply_calibrated_thresholds({"scope_drift": 0.22})
        assert config.trajectory_scope_drift_threshold == 0.22
        assert config.trajectory_coherence_decay_threshold == original_coherence


# ---------------------------------------------------------------------------
# Tests: Audit Trail
# ---------------------------------------------------------------------------

class TestCalibrationAuditTrail:

    def test_adjustment_recorded_in_history(self):
        """Each adjustment is recorded in adjustment_history."""
        state = CalibrationState(min_incidents_before_adjust=3)
        state.sign(SIGNING_KEY)
        for _ in range(3):
            state.record_threat("scope_drift")
        adjustments = state.maybe_adjust(SIGNING_KEY)
        assert len(state.adjustment_history) == 1
        entry = state.adjustment_history[0]
        assert entry["signal"] == "scope_drift"
        assert entry["direction"] == "tighten"
        assert "previous" in entry
        assert "clamped" in entry
        assert "timestamp" in entry

    def test_total_adjustments_incremented(self):
        """total_adjustments counter tracks cumulative adjustments."""
        state = CalibrationState(min_incidents_before_adjust=3)
        state.sign(SIGNING_KEY)
        for _ in range(3):
            state.record_threat("scope_drift")
        state.maybe_adjust(SIGNING_KEY)
        assert state.total_adjustments == 1

        # Second round
        for _ in range(3):
            state.record_false_positive("scope_drift")
        state.maybe_adjust(SIGNING_KEY)
        assert state.total_adjustments == 2

    def test_history_capped(self):
        """adjustment_history is capped to prevent unbounded growth."""
        state = CalibrationState(
            min_incidents_before_adjust=3,
            smoothing_alpha=1.0,
        )
        state.sign(SIGNING_KEY)
        for cycle in range(250):
            for _ in range(3):
                state.record_threat("scope_drift")
            state.maybe_adjust(SIGNING_KEY)
        # Cap triggers at >200, slicing to last 100, then more accumulate
        # History should never exceed 200 (cap trigger point)
        assert len(state.adjustment_history) <= 200


# ---------------------------------------------------------------------------
# Tests: Version and Export
# ---------------------------------------------------------------------------

class TestCalibrationExport:

    def test_version_bumped(self):
        """Version is 2.5.0."""
        import overwatch_v25 as overwatch
        assert overwatch.__version__ == "2.5.0"

    def test_calibration_state_exported(self):
        """CalibrationState is importable from the package."""
        from overwatch_v25 import CalibrationState
        state = CalibrationState()
        assert state.scope_drift_threshold == 0.3

    def test_state_re_signs_after_adjustment(self):
        """State is re-signed after maybe_adjust applies changes."""
        state = CalibrationState(min_incidents_before_adjust=3)
        state.sign(SIGNING_KEY)
        for _ in range(3):
            state.record_threat("scope_drift")
        state.maybe_adjust(SIGNING_KEY)
        # Should be valid after adjustment (re-signed internally)
        assert state.verify(SIGNING_KEY)
