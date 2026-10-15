"""
HAIA-Overwatch v2.5 - Tests: GOPEL-mode thresholds hold

Plan step 22. Paper section 6.4 (paragraph 113): in GOPEL mode all
trajectory thresholds tighten (scope drift 0.2, coherence decay 0.10,
privilege gradient 0.05).

Defect in v2.4: the pipeline built FacticsEngine() without its config
(pipeline.py:73), so the calibrated-threshold push before every
trajectory evaluation (pipeline.py:186-187) reset the thresholds to the
non-GOPEL defaults after the first transaction.

Author: Basil C. Puglisi, MPA
License: CC BY-NC 4.0
Repository: github.com/basilpuglisi/HAIA
Attribution: #AIassisted under HAIA-RECCLIN & Checkpoint-Based Governance
"""

import time

import pytest

from overwatch_v27.models import (
    OverwatchConfig, PlatformResponse, RECCLINRole, TransactionRecord,
)
from overwatch_v27.pipeline import OverwatchPipeline

GOPEL_MODE = {"scope_drift": 0.2, "coherence_decay": 0.10, "privilege_gradient": 0.05}
DEFAULTS = {"scope_drift": 0.3, "coherence_decay": 0.15, "privilege_gradient": 0.1}
CALIBRATION_KEY = b"gopel-mode-calibration-key-0001-test"


def _transaction(i):
    return TransactionRecord(
        transaction_id=f"txn-gm-{i}", timestamp=time.time(), operator_id="op-gm",
        recclin_role=RECCLINRole.RESEARCHER, prompt_hash=f"h{i}",
        prompt_text=f"Summarize governance source {i}.",
        platforms_dispatched=["p1"],
        responses=[PlatformResponse(platform_id="p1", response_text=f"Summary {i}.",
                                    response_hash=f"r{i}", response_time_ms=10.0)],
    )


def _live(pipeline):
    c = pipeline.intent_analyzer.config
    return {
        "scope_drift": c.trajectory_scope_drift_threshold,
        "coherence_decay": c.trajectory_coherence_decay_threshold,
        "privilege_gradient": c.trajectory_privilege_gradient_threshold,
    }


def test_gopel_mode_config_starts_at_the_published_values():
    config = OverwatchConfig(gopel_mode=True)
    assert config.trajectory_scope_drift_threshold == 0.2
    assert config.trajectory_coherence_decay_threshold == 0.10
    assert config.trajectory_privilege_gradient_threshold == 0.05


@pytest.mark.parametrize("n", [1, 3, 10])
def test_gopel_mode_thresholds_hold_after_transactions(n):
    pipeline = OverwatchPipeline(OverwatchConfig(gopel_mode=True))
    for i in range(n):
        pipeline.verify_transaction(_transaction(i))
    assert _live(pipeline) == GOPEL_MODE
    assert pipeline.factics_engine.get_calibrated_thresholds() == GOPEL_MODE


def test_gopel_mode_thresholds_hold_with_a_calibration_key():
    pipeline = OverwatchPipeline(OverwatchConfig(gopel_mode=True))
    pipeline.factics_engine.set_calibration_key(CALIBRATION_KEY)
    for i in range(3):
        pipeline.verify_transaction(_transaction(i))
    assert _live(pipeline) == GOPEL_MODE
    assert pipeline.factics_engine.get_calibration_state().get_thresholds() == GOPEL_MODE


def test_the_factics_engine_receives_the_pipeline_config():
    config = OverwatchConfig(gopel_mode=True, proposals_log_path="")
    pipeline = OverwatchPipeline(config)
    assert pipeline.factics_engine._config is config


def test_default_mode_thresholds_are_unchanged():
    pipeline = OverwatchPipeline(OverwatchConfig(require_structural_inputs=False))
    for i in range(3):
        pipeline.verify_transaction(_transaction(i))
    assert _live(pipeline) == DEFAULTS
