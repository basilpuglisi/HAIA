"""
HAIA-Overwatch v2.6 - Tests: watching the GOPEL v0.6.4 channel

Team Gate of HAIA_Update_Plan_v4, Part C5. Overwatch watches the GOPEL that
Agent Models 1 and 2 both use. GOPEL v0.6.4 adds the channel: each group of
platform calls, and each routed Navigator turn, closes with a
channel_group_closed system record. Overwatch v2.6 finalizes a transaction
on that record, so every agent call is inspected; its single action, stop
the pipe and route to human, is unchanged.

The GOPEL records come only from the committed fixture
tests/fixtures/gopel_v064_mock_audit_v1.json. Nothing here imports GOPEL.

Author: Basil C. Puglisi, MPA
License: CC BY-NC 4.0
Repository: github.com/basilpuglisi/HAIA
Attribution: #AIassisted under HAIA-RECCLIN & Checkpoint-Based Governance
"""

import hashlib
import hmac
import json

from overwatch_v27.gopel_observer import GopelObserver, GopelSchemaExpectation
from overwatch_v27.models import OverwatchConfig
from overwatch_v27.pipeline import OverwatchPipeline
from overwatch_v27.channel_manager import StopChannelPublisher
from overwatch_v27.tests.gopel_fixture_support_v25 import (
    RecordingPipeline,
    alerts,
    audit_document,
    canonical,
    channel_with_sink,
    fixture_records,
    load_fixture,
    rechain,
    records_for,
)

CHANNEL_TIDS = (
    "chan-fixture-08-model2-step",
    "chan-fixture-08-model2-step-navigator",
    "chan-fixture-09-model1-research",
    "chan-fixture-10-model2-injected",
)
STOP_KEY = hashlib.sha256(b"overwatch v2.6 team channel stop key").digest()
NO_INPUTS = OverwatchConfig(require_structural_inputs=False)


def _recorded():
    recorder = RecordingPipeline()
    cm, messages = channel_with_sink()
    observer = GopelObserver(recorder, channel_manager=cm, config=NO_INPUTS)
    observer.observe_audit_document(audit_document())
    return recorder, messages


def test_the_default_expectation_is_gopel_0_6_4():
    assert GopelSchemaExpectation().gopel_version == "0.6.5"
    assert load_fixture()["provenance"]["gopel_version"] == "0.6.5"


def test_channel_group_closed_finalizes_every_channel_transaction():
    recorder, messages = _recorded()
    seen = recorder.transactions()
    for tid in CHANNEL_TIDS:
        assert tid in seen, tid
        assert seen[tid].metadata["gopel"]["finalized_by"] == "system:channel_group_closed"
    assert alerts(messages) == []


def test_a_channel_transaction_carries_its_caller_and_image_hashes():
    recorder, _messages = _recorded()
    seen = recorder.transactions()
    model1 = seen["chan-fixture-09-model1-research"].metadata["gopel"]["request"]
    assert model1["caller_id"] == "agent_model_1"
    assert len(model1["image_sha256"]) == 1
    model2 = seen["chan-fixture-08-model2-step"].metadata["gopel"]["request"]
    assert model2["caller_id"] == "agent_model_2" and model2["image_sha256"] == []


def test_every_dispatch_in_a_channel_group_carries_one_prompt_hash():
    recorder, _messages = _recorded()
    txn = recorder.transactions()["chan-fixture-08-model2-step"]
    hashes = {d["prompt_hash"] for d in txn.metadata["gopel"]["dispatches"]}
    assert len(hashes) == 1 and len(txn.responses) == 3


def test_a_routed_navigator_turn_is_inspected_with_its_response():
    recorder, _messages = _recorded()
    txn = recorder.transactions()["chan-fixture-08-model2-step-navigator"]
    assert len(txn.responses) == 1
    assert txn.responses[0].platform_id == "mock_navigator"


def test_a_malformed_channel_group_closed_detail_raises_an_alert():
    records = fixture_records()
    target = next(r for r in records if r.get("event_type") == "channel_group_closed")
    target["event_detail"] = canonical({"caller_id": "agent_model_2", "reason": "complete"})
    rechain(records)
    cm, messages = channel_with_sink()
    observer = GopelObserver(RecordingPipeline(), channel_manager=cm, config=NO_INPUTS)
    doc = audit_document()
    doc["records"] = records
    observer.observe_audit_document(doc)
    bad = [m for m in alerts(messages) if m.payload.get("reason") == "bad_event_detail"]
    assert bad and bad[0].payload.get("record_id") == target["record_id"]


def test_an_injected_channel_answer_escalates_and_stops_the_pipe_naming_its_records(tmp_path):
    pipeline = OverwatchPipeline(OverwatchConfig(require_structural_inputs=False))
    pipeline.attach_stop_publisher(StopChannelPublisher(
        channel_path=str(tmp_path / "stops.jsonl"), key_id="stop-key-v26", stop_key=STOP_KEY,
        target_pipeline="gopel-v064-fixture-instance"))
    observer = GopelObserver(pipeline, config=NO_INPUTS)
    outcomes = {o.transaction_id: o for o in observer.observe_audit_document(audit_document())}
    tid = "chan-fixture-10-model2-injected"
    assert outcomes[tid].escalated is True and outcomes[tid].stop_event_id
    lines = [json.loads(x) for x in (tmp_path / "stops.jsonl").read_text(encoding="utf-8").splitlines()]
    bodies = {json.loads(x["body"])["transaction_id"]: (x, json.loads(x["body"])) for x in lines}
    line, body = bodies[tid]
    assert hmac.compare_digest(line["mac"], hmac.new(STOP_KEY, line["body"].encode("utf-8"),
                                                     hashlib.sha256).hexdigest())
    ids = {r["record_id"]: r["chain_hash"] for r in records_for(fixture_records(), tid)}
    assert body["gopel_record_refs"]
    for ref in body["gopel_record_refs"]:
        assert ids[ref["record_id"]] == ref["chain_hash"]
    for clean in ("chan-fixture-08-model2-step", "chan-fixture-09-model1-research"):
        assert outcomes[clean].escalated is False, clean
