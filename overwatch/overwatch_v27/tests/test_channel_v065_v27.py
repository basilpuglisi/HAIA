"""
HAIA-Overwatch v2.7 - Tests: reading GOPEL v0.6.5's channel records

Basil's fix round, item 1 (tests first, Overwatch's half): a lone-surrogate
answer leaves a Dispatch record and a Response record, and Overwatch v2.7
reads and inspects that record without skipping it. GOPEL v0.6.5 records
the answer escaped without loss and flags it (text_escaped); Overwatch
carries the flag to the human with the response.

Item 1c: a group closes as soon as no further send is planned for it, so a
withdrawn platform no longer leaves the group open and uninspected.

Author: Basil C. Puglisi, MPA
License: CC BY-NC 4.0
Repository: github.com/basilpuglisi/HAIA
Attribution: #AIassisted under HAIA-RECCLIN & Checkpoint-Based Governance
"""

import pytest

from overwatch_v27.gopel_observer import GopelObserver, GopelSchemaExpectation
from overwatch_v27.pipeline import OverwatchPipeline
from overwatch_v27.tests.fix_round_support_v27 import (
    GOPEL_VERSION, config, findings_of, fixture, records_of, run_fixture,
)
from overwatch_v27.tests.gopel_fixture_support_v25 import (
    RecordingPipeline, alerts, audit_document, channel_with_sink, expected_finalized,
)

SURROGATE = "chan-fixture-20-surrogate"
WITHDRAWN = "chan-fixture-24-withdrawn"


def _recorded():
    recorder = RecordingPipeline()
    cm, messages = channel_with_sink()
    observer = GopelObserver(recorder, channel_manager=cm, config=config())
    observer.observe_audit_document(audit_document(fixture()), source_gopel_version=GOPEL_VERSION)
    return recorder, messages, observer


def test_the_default_expectation_is_gopel_0_6_5():
    assert GopelSchemaExpectation().gopel_version == "0.6.5"
    prov = fixture()["provenance"]
    assert prov["gopel_version"] == "0.6.5"
    assert prov["command"].startswith("python -I haia_agent/e2e/make_overwatch_fixtures_v3.py")
    assert prov["source_tree_clean"] is True


def test_the_lone_surrogate_answer_left_a_dispatch_and_an_escaped_flagged_response():
    assert len(records_of(SURROGATE, "dispatch")) == 1
    (resp,) = records_of(SURROGATE, "response")
    assert resp["text_escaped"] is True and resp["escapes"]
    assert "\\ud800" in resp["response_text"]
    resp["response_text"].encode("utf-8")      # valid UTF-8 as stored


def test_overwatch_reads_the_escaped_record_and_carries_the_flag():
    recorder, messages, _observer = _recorded()
    txn = recorder.transactions()[SURROGATE]
    (response,) = txn.responses
    assert "\\ud800" in response.response_text
    assert response.metadata["text_escaped"] is True
    assert response.metadata["escapes"]
    assert [a for a in alerts(messages) if SURROGATE in str(getattr(a, "payload", ""))] == []


def test_overwatch_inspects_the_escaped_record_without_skipping_it(tmp_path):
    run = run_fixture(tmp_path)
    outcome = run.outcomes[SURROGATE]
    assert outcome.escalated is False
    assert any("Downgraded" in f.description for f in findings_of(outcome)), \
        "the answer's cited address was read, so its text was inspected"


def test_a_withdrawn_group_is_finalized_and_inspected():
    recorder, messages, _observer = _recorded()
    txn = recorder.transactions()[WITHDRAWN]
    assert txn.metadata["gopel"]["finalized_by"] == "system:channel_group_closed"
    assert len(txn.responses) == 2
    closed = [s for s in txn.metadata["gopel"]["system_events"] if s["event_type"] == "channel_group_closed"]
    assert closed and closed[0]["detail"]["reason"].startswith("withdrawn: ")
    assert alerts(messages) == []


def test_every_transaction_with_a_request_is_finalized_with_no_alert():
    recorder, messages, observer = _recorded()
    assert sorted(recorder.transactions()) == sorted(expected_finalized(fixture()["records"]))
    assert alerts(messages) == []
    assert observer.get_statistics().get("schema_refusals", 0) == 0


def test_a_default_observer_reads_the_v0_6_5_audit(tmp_path):
    pipeline = OverwatchPipeline(config())
    observer = GopelObserver(pipeline, config=config())
    outcomes = observer.observe_audit_document(audit_document(fixture()), source_gopel_version="0.6.5")
    assert {o.transaction_id for o in outcomes} == set(expected_finalized(fixture()["records"]))


@pytest.mark.parametrize("version", ["0.6.4", "0.6.6"])
def test_another_declared_version_is_still_refused(version):
    recorder = RecordingPipeline()
    cm, messages = channel_with_sink()
    observer = GopelObserver(recorder, channel_manager=cm, config=config())
    observer.observe_audit_document(audit_document(fixture()), source_gopel_version=version)
    assert recorder.calls == []
    assert alerts(messages)
