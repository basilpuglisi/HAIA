"""
HAIA-Overwatch v2.7 - Tests: role coherence against Agent Model 1's scoring
groups labeled Editor

Basil's fix round, item 2b, with item 3a: every Model 1 scoring group is
labeled Editor (HAIA-SMART Copy v2.1 and HAIA-CORE v3.10, Section 0; Basil
assigns Editor to SMART Creative scoring too). The role coherence check is
unchanged; these tests show it in both directions on Model 1's own prompts.

Author: Basil C. Puglisi, MPA
License: CC BY-NC 4.0
Repository: github.com/basilpuglisi/HAIA
Attribution: #AIassisted under HAIA-RECCLIN & Checkpoint-Based Governance
"""

import pytest

from overwatch_v27.models import RECCLINRole
from overwatch_v27.tests.fix_round_support_v27 import (
    findings_of, inspect_one, records_of, run_fixture, synthetic, transactions,
)

CODER_PROMPT = ("Write a Python function and a class for this module: import the parser, define the "
                "variable, return the result, then debug, test, compile and deploy it.")


def _scoring():
    """Agent Model 1 v6's scoring groups in the fixture: (tid, Request record)."""
    out = []
    for t in transactions("clean-model1"):
        req = records_of(t["transaction_id"], "request")[0]
        if "Run HAIA-SMART Copy v2.1" in req["prompt_text"]:
            out.append((t["transaction_id"], req))
    return out


def _coherence(outcome):
    return [f for f in findings_of(outcome) if f.description.startswith("Role coherence low")]


def test_every_model_1_scoring_group_is_labeled_editor():
    groups = _scoring()
    assert groups
    for _tid, req in groups:
        assert req["recclin_role"] == "editor"
        assert req["caller_id"] == "agent_model_1"


def test_model_1_scoring_labeled_editor_raises_no_role_coherence_finding(tmp_path):
    run = run_fixture(tmp_path)
    for tid, _req in _scoring():
        outcome = run.outcomes[tid]
        assert _coherence(outcome) == [], [f.description for f in _coherence(outcome)]
        assert outcome.escalated is False


def test_the_same_scoring_prompt_under_the_v5_calculator_label_is_still_flagged(tmp_path):
    """The check is not loosened: Model 1 v5's label (QT9, calculator) on the
    same prompt still reads as low role coherence and stops."""
    _tid, req = _scoring()[0]
    outcome, lines = inspect_one(tmp_path, synthetic("TOTAL: 27 / 30", role=RECCLINRole.CALCULATOR,
                                                     prompt=req["prompt_text"], operator_id="agent_model_1"))
    assert _coherence(outcome)
    assert outcome.escalated is True and len(lines) == 1


@pytest.mark.parametrize("role", [RECCLINRole.EDITOR, RECCLINRole.RESEARCHER, RECCLINRole.NAVIGATOR])
def test_an_off_role_prompt_under_model_1_labels_is_flagged(tmp_path, role):
    outcome, lines = inspect_one(tmp_path, synthetic("Done.", role=role, prompt=CODER_PROMPT,
                                                     operator_id="agent_model_1"))
    assert _coherence(outcome), [f.description for f in findings_of(outcome)]
    assert outcome.escalated is True and len(lines) == 1
