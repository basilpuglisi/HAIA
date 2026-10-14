"""
HAIA-Overwatch v2.5 - Tests: the calibration loop stays inside its scope

Plan step 14d. Ruling R4: outcome monitoring is outside Overwatch; the
published v2.4 scope stands, calibration loop included.

These tests record current behavior. The Factics calibration loop
(paper section 6.6) adjusts only Overwatch's own three trajectory
thresholds, within the published bounds, and never touches GOPEL
routing, scoring, or dispatch.

Author: Basil C. Puglisi, MPA
License: CC BY-NC 4.0
Repository: github.com/basilpuglisi/HAIA
Attribution: #AIassisted under HAIA-RECCLIN & Checkpoint-Based Governance
"""

import ast
import dataclasses
import inspect
import sys
import time
from pathlib import Path

import overwatch_v26
from overwatch_v26 import factics_engine as factics_module
from overwatch_v26.factics_engine import FacticsEngine
from overwatch_v26.models import (
    AlignmentResult, CalibrationState, InspectionDomain, InspectionFinding,
    OverwatchConfig, PlatformResponse, RECCLINRole, Severity, TrajectoryAlert,
    TransactionRecord,
)
from overwatch_v26.pipeline import OverwatchPipeline

PACKAGE_DIR = Path(overwatch_v26.__file__).resolve().parent
CALIBRATION_KEY = b"calibration-scope-key-for-tests-0001"

# Identifiers that would mean the loop reaches into GOPEL's routing,
# scoring, or dispatch (GOPEL operations 1 to 3, platform selection).
GOPEL_ACTION_WORDS = {
    "dispatch", "send_prompt", "route", "routing", "router", "route_for_synthesis",
    "select", "selector", "secure_select", "platform", "platforms",
    "platforms_dispatched", "navigator", "adapter", "adapters",
    "rank", "ranking", "weight", "score_response",
}


def _alert(**kw):
    defaults = dict(
        transaction_id="txn-cal", operator_id="op-cal", window_size=6,
        scope_drift_score=0.9, privilege_gradient=0.9, coherence_decay_rate=0.9,
        converging_signals=3, evidence_chain=["scope drift", "privilege gradient", "coherence decay"],
    )
    defaults.update(kw)
    return TrajectoryAlert(**defaults)


def _finding(tid="txn-cal"):
    return InspectionFinding(
        domain=InspectionDomain.INTENT, result=AlignmentResult.FLAGGED,
        severity=Severity.CRITICAL, confidence=0.9, description="trajectory",
        evidence_chain=["recon", "privilege"], transaction_id=tid,
    )


def _identifiers(fn):
    tree = ast.parse(_dedent(inspect.getsource(fn)))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, ast.FunctionDef):
            names.add(node.name)
    return names


def _dedent(source):
    import textwrap
    return textwrap.dedent(source)


class TestPublishedCalibrationScope:

    def test_calibration_parameters_match_the_published_v24_values(self):
        state = CalibrationState()
        assert (state.tighten_rate, state.loosen_rate) == (0.10, 0.05)
        assert state.smoothing_alpha == 0.3
        assert state.min_incidents_before_adjust == 3
        assert (state.scope_drift_floor, state.coherence_decay_floor,
                state.privilege_gradient_floor) == (0.15, 0.05, 0.03)
        assert (state.scope_drift_ceiling, state.coherence_decay_ceiling,
                state.privilege_gradient_ceiling) == (0.60, 0.30, 0.20)

    def test_calibration_state_holds_only_the_three_trajectory_thresholds(self):
        thresholds = CalibrationState().get_thresholds()
        assert set(thresholds) == {"scope_drift", "coherence_decay", "privilege_gradient"}

    def test_bounds_hold_under_repeated_adjustment(self):
        state = CalibrationState()
        state.sign(CALIBRATION_KEY)
        for _ in range(200):
            for signal in ("scope_drift", "coherence_decay", "privilege_gradient"):
                state.record_threat(signal)
            state.maybe_adjust(CALIBRATION_KEY)
        assert state.scope_drift_threshold >= state.scope_drift_floor
        assert state.coherence_decay_threshold >= state.coherence_decay_floor
        assert state.privilege_gradient_threshold >= state.privilege_gradient_floor
        for _ in range(400):
            for signal in ("scope_drift", "coherence_decay", "privilege_gradient"):
                state.record_false_positive(signal)
            state.maybe_adjust(CALIBRATION_KEY)
        assert state.scope_drift_threshold <= state.scope_drift_ceiling
        assert state.coherence_decay_threshold <= state.coherence_decay_ceiling
        assert state.privilege_gradient_threshold <= state.privilege_gradient_ceiling


class TestCalibrationNeverTouchesGopel:

    def test_calibration_code_names_no_gopel_routing_scoring_or_dispatch(self):
        functions = [
            FacticsEngine.calibrate_from_trajectory,
            FacticsEngine.get_calibrated_thresholds,
            FacticsEngine.get_calibration_state,
            FacticsEngine.set_calibration_key,
            CalibrationState.maybe_adjust,
            CalibrationState.record_threat,
            CalibrationState.record_false_positive,
            CalibrationState.get_thresholds,
        ]
        for fn in functions:
            hits = _identifiers(fn) & GOPEL_ACTION_WORDS
            assert hits == set(), f"{fn.__qualname__} names {sorted(hits)}"

    def test_factics_engine_imports_only_stdlib_and_overwatch_modules(self):
        tree = ast.parse((PACKAGE_DIR / "factics_engine.py").read_text(encoding="utf-8"))
        stdlib = set(getattr(sys, "stdlib_module_names", ())) or {"json", "os", "time", "typing"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name.split(".")[0] in stdlib, alias.name
            elif isinstance(node, ast.ImportFrom):
                if node.level == 0:
                    assert node.module.split(".")[0] in stdlib, node.module

    def test_calibration_changes_only_overwatch_trajectory_thresholds(self):
        config = OverwatchConfig(require_structural_inputs=False)
        pipeline = OverwatchPipeline(config)
        pipeline.factics_engine.set_calibration_key(CALIBRATION_KEY)
        notified = []
        pipeline.register_notification_callback(notified.append)

        trajectory_fields = {
            "trajectory_scope_drift_threshold",
            "trajectory_coherence_decay_threshold",
            "trajectory_privilege_gradient_threshold",
        }
        before = {f.name: getattr(config, f.name) for f in dataclasses.fields(config)}
        adjustments = []
        for i in range(3):
            result = pipeline.process_cbg_threat_confirmation(
                _finding(f"txn-cal-{i}"), outcome=_outcome(f"txn-cal-{i}"),
                human_rationale="confirmed", trajectory_alert=_alert(transaction_id=f"txn-cal-{i}"),
            )
            adjustments += result.get("calibration_adjustments", [])
        assert {a["signal"] for a in adjustments} == {"scope_drift", "coherence_decay", "privilege_gradient"}
        assert all(a["direction"] == "tighten" for a in adjustments)
        assert notified == [], "calibration must not emit on the notification channel"

        # Thresholds reach Overwatch's own intent analyzer on the next evaluation.
        pipeline.verify_transaction(_transaction("txn-after-calibration"))
        after = {f.name: getattr(config, f.name) for f in dataclasses.fields(config)}
        changed = {k for k in before if before[k] != after[k]}
        assert changed == trajectory_fields

    def test_calibrated_thresholds_appear_in_no_outcome_sent_outward(self):
        config = OverwatchConfig(require_structural_inputs=False)
        pipeline = OverwatchPipeline(config)
        pipeline.factics_engine.set_calibration_key(CALIBRATION_KEY)
        for i in range(3):
            pipeline.process_cbg_threat_confirmation(
                _finding(f"txn-o-{i}"), outcome=_outcome(f"txn-o-{i}"),
                trajectory_alert=_alert(transaction_id=f"txn-o-{i}"),
            )
        outcome = pipeline.verify_transaction(_transaction("txn-o-next"))

        def keys(obj):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    yield str(k)
                    yield from keys(v)
            elif isinstance(obj, list):
                for v in obj:
                    yield from keys(v)

        leaked = [k for k in keys(outcome.to_dict())
                  if "threshold" in k.lower() or "calibrat" in k.lower()]
        assert leaked == []


def _outcome(tid):
    from overwatch_v26.models import VerificationOutcome
    return VerificationOutcome(transaction_id=tid)


def _transaction(tid):
    return TransactionRecord(
        transaction_id=tid, timestamp=time.time(), operator_id="op-cal",
        recclin_role=RECCLINRole.RESEARCHER, prompt_hash="h",
        prompt_text="Summarize the governance literature.",
        platforms_dispatched=["p1"],
        responses=[PlatformResponse(platform_id="p1", response_text="Summary.",
                                    response_hash="r", response_time_ms=10.0)],
    )
