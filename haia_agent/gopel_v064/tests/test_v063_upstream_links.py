"""
GOPEL v0.6.3, step 17: the Decision Record links every upstream record.

DecisionRecord.upstream_record_ids lists every upstream record ID of the
transaction (request, dispatch, response, navigation, arbitration), in
both GOPELPipeline and SecureGOPELPipeline record_arbitration.

Author: Basil C. Puglisi, MPA
"""

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT))

from haia_agent.gopel_v064.models import ArbitrationDecision, RECCLINRole  # noqa: E402
from haia_agent.gopel_v064.pipeline import ArbitrationInput  # noqa: E402
from haia_agent.gopel_v064.secure_pipeline import SecureArbitrationInput  # noqa: E402
from haia_agent.gopel_v064.tests import v063_support as sup  # noqa: E402

UPSTREAM_TYPES = ("request", "dispatch", "response", "navigation", "arbitration")


@pytest.mark.parametrize("kind", ["base", "secure"])
def test_decision_record_lists_every_upstream_record(tmp_path, kind):
    pipeline, logger, _ = sup.make_pipeline(kind, tmp_path, with_channel=False)

    # Two transactions: the decision must link only its own upstream records.
    other = sup.run(pipeline, prompt="Another transaction on the same chain.")
    assert other.success, other.error
    result = sup.run(pipeline)
    assert result.success, result.error
    tid = result.transaction_id

    arb_cls = ArbitrationInput if kind == "base" else SecureArbitrationInput
    recorded = pipeline.record_arbitration(
        transaction_id=tid,
        human_operator_id="analyst_jane",
        arbitration=arb_cls(
            decision=ArbitrationDecision.MODIFY,
            rationale="Modified to reflect the dissent recorded by the Navigator.",
            modifications="Added the minority position to the summary.",
            final_output="Final authorized output with the dissent included.",
        ),
        checkpoint_role=RECCLINRole.RESEARCHER,
        navigation_record_id=result.checkpoint_package.navigation_record_id,
    )
    assert recorded is not False

    chain = logger.reconstruct_transaction(tid)
    decisions = [r for r in chain if r["record_type"] == "decision"]
    assert len(decisions) == 1
    expected = [r["record_id"] for r in chain if r["record_type"] in UPSTREAM_TYPES]
    # 1 request + 3 dispatch + 3 response + 1 navigation + 1 arbitration
    assert len(expected) == 9
    assert decisions[0]["upstream_record_ids"] == expected

    other_ids = {r["record_id"] for r in logger.reconstruct_transaction(other.transaction_id)}
    assert not other_ids & set(decisions[0]["upstream_record_ids"])

    ok, violations = logger.verify_chain_integrity()
    assert ok, violations
