"""
GOPEL v0.6.3, step 20: stop the pipe, route to human (R5; S5; S6;
addendum 1 and 2; Gate 1 Shared Spec v1, section 1).

Overwatch appends one JSON line per stop to a channel file it owns. GOPEL
opens it read only, verifies each line (canonical body, HMAC-SHA256 with
the single stop-channel key, compare_digest), refuses replays by consumed
event ID only (S5), keeps durable atomic state that survives a restart,
checks for an active stop at three check points in BOTH pipelines, and
resumes only after a human release through the RELEASE_OVERWATCH_STOP
evidence gate. With no channel configured, GOPEL runs normally.

The stop lines in these tests are written by v063_support, an independent
re-implementation of the spec's line format.

Author: Basil C. Puglisi, MPA
"""

import json
import os
import secrets
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT))

from haia_agent.gopel_v065.adapters.mock_adapter import MockAdapter  # noqa: E402
from haia_agent.gopel_v065.breach import PipelineCircuitBreaker  # noqa: E402
from haia_agent.gopel_v065.logger import AuditLogger  # noqa: E402
from haia_agent.gopel_v065.models import ArbitrationDecision, RECCLINRole  # noqa: E402
from haia_agent.gopel_v065.pipeline import ArbitrationInput  # noqa: E402
from haia_agent.gopel_v065.secure_pipeline import SecureArbitrationInput  # noqa: E402
from haia_agent.gopel_v065.security import OperatorIdentity  # noqa: E402
from haia_agent.gopel_v065.sentinel import PipelineIdentity, Sentinel  # noqa: E402
from haia_agent.gopel_v065.tests import v063_support as sup  # noqa: E402

KINDS = ["base", "secure"]


def _assert_stopped(result, *event_ids):
    assert result.success is False
    assert result.stopped_by_overwatch is True
    assert result.checkpoint_package is None
    assert result.error.startswith("STOPPED_BY_OVERWATCH")
    for eid in event_ids:
        assert eid in result.error


def _assert_runs(result):
    assert result.success is True, result.error
    assert result.stopped_by_overwatch is False
    assert result.checkpoint_package is not None


def _detail(record: dict) -> dict:
    return json.loads(record["event_detail"])


def _release(pipeline, ids, identities, runtime, requester="gov_officer_mark", **kw):
    return pipeline.release_overwatch_stop(
        human_operator_id=requester,
        stop_event_ids=ids,
        evidence=sup.release_evidence(ids, identities, requester=requester, **kw),
        governance_runtime=runtime,
    )


def _rig(kind, tmp_path, **kw):
    runtime, identities = sup.make_runtime()
    pipeline, logger, channel = sup.make_pipeline(kind, tmp_path, runtime=runtime, **kw)
    return pipeline, logger, channel, runtime, identities


# ======================================================================
# 1. A valid stop halts the next dispatch
# ======================================================================

@pytest.mark.parametrize("kind", KINDS)
def test_valid_stop_halts_next_dispatch(tmp_path, kind):
    pipeline, logger, channel, _, _ = _rig(kind, tmp_path)
    _assert_runs(sup.run(pipeline))  # nothing in the channel yet

    body = sup.make_body(
        trigger="HALT", transaction_id="ow-view-of-tx",
        finding_ids=["OW-F-17", "OW-F-18"],
        refs=[{"record_id": "rec-1", "chain_hash": "a" * 64}],
    )
    sup.append_line(channel.channel_path, sup.make_line(body))

    result = sup.run(pipeline)
    _assert_stopped(result, body["event_id"])
    tid = result.transaction_id
    assert sup.records_of(logger, tid, "dispatch") == []
    assert sup.records_of(logger, tid, "navigation") == []

    stops = sup.system_records(logger, "overwatch_stop")
    assert len(stops) == 1
    assert stops[0]["transaction_id"] == tid
    assert stops[0]["severity"] == "critical"
    detail = _detail(stops[0])
    assert detail["body"] == body
    assert detail["received_at"].endswith("Z")
    assert detail["line_sha256"] == sup.line_sha(sup.make_line(body))
    assert stops[0]["event_detail"] == sup.canonical(detail)

    # Still stopped on the next attempt (no new record: the line is consumed).
    _assert_stopped(sup.run(pipeline), body["event_id"])
    assert len(sup.system_records(logger, "overwatch_stop")) == 1
    ok, violations = logger.verify_chain_integrity()
    assert ok, violations


# ======================================================================
# 2. A forged stop (wrong MAC) is rejected and recorded
# ======================================================================

@pytest.mark.parametrize("kind", KINDS)
def test_forged_stop_rejected_and_recorded(tmp_path, kind):
    pipeline, logger, channel, _, _ = _rig(kind, tmp_path)
    forged = sup.make_line(sup.make_body(), key=secrets.token_bytes(32))
    sup.append_line(channel.channel_path, forged)
    # Body altered after signing: the MAC no longer matches.
    good = json.loads(sup.make_line(sup.make_body()))
    altered_body = json.loads(good["body"])
    altered_body["trigger"] = "TRAJECTORY"
    altered = json.dumps({"body": sup.canonical(altered_body), "mac": good["mac"]}) + "\n"
    sup.append_line(channel.channel_path, altered)

    result = sup.run(pipeline)
    _assert_runs(result)
    assert channel.active_stop_ids() == []

    rejected = sup.system_records(logger, "overwatch_stop_rejected")
    assert [_detail(r)["reason"] for r in rejected] == ["bad_mac", "bad_mac"]
    assert {_detail(r)["line_sha256"] for r in rejected} == {sup.line_sha(forged), sup.line_sha(altered)}
    assert all(r["severity"] == "warning" for r in rejected)
    assert all(r["transaction_id"] == result.transaction_id for r in rejected)

    # Each line is processed once: a second run writes no new rejection.
    _assert_runs(sup.run(pipeline))
    assert len(sup.system_records(logger, "overwatch_stop_rejected")) == 2


# ======================================================================
# 3. S6: a stop signed with any other key is refused
# ======================================================================

OTHER_KEYS = {
    "overwatch_heartbeat": secrets.token_bytes(32),
    "overwatch_calibration": secrets.token_bytes(32),
    "overwatch_provenance": secrets.token_bytes(32),
    "overwatch_manifest": secrets.token_bytes(32),
    "gopel_operator": bytes.fromhex(OperatorIdentity("haia_agent").signing_key_hex),
    "gopel_pipeline_identity": bytes.fromhex(PipelineIdentity(sup.PIPELINE_ID).signing_key_hex),
}


@pytest.mark.parametrize("key_name", sorted(OTHER_KEYS))
def test_stop_signed_with_any_other_key_is_refused(tmp_path, key_name):
    pipeline, logger, channel, _, _ = _rig("secure", tmp_path)
    other = OTHER_KEYS[key_name]
    # (a) claims the stop key ID, signed with the other key
    sup.append_line(channel.channel_path, sup.make_line(sup.make_body(), key=other))
    # (b) names the other key, signed with the other key
    sup.append_line(channel.channel_path,
                    sup.make_line(sup.make_body(key_id=key_name + "-key"), key=other))

    _assert_runs(sup.run(pipeline))
    assert channel.active_stop_ids() == []
    reasons = [_detail(r)["reason"] for r in sup.system_records(logger, "overwatch_stop_rejected")]
    assert reasons == ["bad_mac", "wrong_key_id"]


# ======================================================================
# 4. A replayed stop is refused
# ======================================================================

def test_replayed_stop_refused(tmp_path):
    pipeline, logger, channel, runtime, identities = _rig("secure", tmp_path)
    body = sup.make_body()
    line = sup.make_line(body)
    sup.append_line(channel.channel_path, line)
    _assert_stopped(sup.run(pipeline), body["event_id"])

    rel = _release(pipeline, [body["event_id"]], identities, runtime)
    assert rel.released, rel.reason
    _assert_runs(sup.run(pipeline))

    # The identical line appended again, and the same body and MAC in a
    # re-serialized outer object, are both refused as replays.
    sup.append_line(channel.channel_path, line)
    outer = json.loads(line)
    sup.append_line(channel.channel_path, json.dumps(outer, indent=1).replace("\n", " ") + "\n")
    _assert_runs(sup.run(pipeline))
    assert channel.active_stop_ids() == []
    reasons = [_detail(r)["reason"] for r in sup.system_records(logger, "overwatch_stop_rejected")]
    assert reasons == ["replay", "replay"]
    assert len(sup.system_records(logger, "overwatch_stop")) == 1


# ======================================================================
# 5. S5: a valid stop issued before a release, delivered after it, halts
# ======================================================================

def test_stop_issued_before_release_and_delivered_after_still_halts(tmp_path):
    pipeline, logger, channel, runtime, identities = _rig("secure", tmp_path)
    first = sup.make_body()
    sup.append_line(channel.channel_path, sup.make_line(first))
    _assert_stopped(sup.run(pipeline), first["event_id"])

    # Overwatch issues a second stop now; it is delivered only after the release.
    issued = datetime.now(timezone.utc) - timedelta(seconds=5)
    late = sup.make_body(issued_at=sup.iso_ms_z(issued))
    late_line = sup.make_line(late)

    rel = _release(pipeline, [first["event_id"]], identities, runtime)
    assert rel.released, rel.reason
    _assert_runs(sup.run(pipeline))

    sup.append_line(channel.channel_path, late_line)
    result = sup.run(pipeline)
    _assert_stopped(result, late["event_id"])

    state = json.loads(channel.state_path.read_text(encoding="utf-8"))
    released_at = state["releases"][0]["released_at"]
    assert late["issued_at"] < released_at  # issued before the release
    assert late["event_id"] in state["active"]


# ======================================================================
# 6. A stop survives a restart
# ======================================================================

@pytest.mark.parametrize("kind", KINDS)
def test_stop_survives_restart(tmp_path, kind):
    pipeline, logger, channel, runtime, _ = _rig(kind, tmp_path)
    body = sup.make_body()
    sup.append_line(channel.channel_path, sup.make_line(body))
    _assert_stopped(sup.run(pipeline), body["event_id"])

    state = json.loads(channel.state_path.read_text(encoding="utf-8"))
    assert state["schema"] == "gopel.overwatch_stop_state.v1"
    assert state["active"] == {body["event_id"]: body}
    assert state["consumed"] == [body["event_id"]]
    assert state["rejected_line_sha256"] == []
    assert state["releases"] == []

    # Simulated restart: new logger, new channel object, new pipeline.
    # The channel file is gone; the stop is held by GOPEL's own state.
    channel_path, state_path = channel.channel_path, channel.state_path
    del pipeline, channel
    channel_path.unlink()
    logger2 = AuditLogger(logger.audit_file_path, operator_id="pipeline_agent")
    channel2 = sup.make_channel(tmp_path, logger2)
    assert channel2.state_path == state_path
    assert channel2.active_stop_ids() == [body["event_id"]]
    pipeline2, _, _ = sup.make_pipeline(kind, tmp_path, logger=logger2, channel=channel2,
                                        runtime=runtime)
    _assert_stopped(sup.run(pipeline2), body["event_id"])


# ======================================================================
# 7. Concurrent stops are all recorded; a release clears only those named
# ======================================================================

def test_concurrent_stops_all_recorded_release_clears_only_named(tmp_path):
    pipeline, logger, channel, runtime, identities = _rig("secure", tmp_path)
    a, b, c = sup.make_body(), sup.make_body(trigger="TRAJECTORY"), sup.make_body(trigger="HALT")
    for body in (a, b, c):
        sup.append_line(channel.channel_path, sup.make_line(body))

    result = sup.run(pipeline)
    _assert_stopped(result, a["event_id"], b["event_id"], c["event_id"])
    recorded = [_detail(r)["body"]["event_id"] for r in sup.system_records(logger, "overwatch_stop")]
    assert recorded == [a["event_id"], b["event_id"], c["event_id"]]

    rel = _release(pipeline, [a["event_id"], c["event_id"]], identities, runtime)
    assert rel.released, rel.reason
    assert sorted(rel.cleared) == sorted([a["event_id"], c["event_id"]])
    assert channel.active_stop_ids() == [b["event_id"]]
    still = sup.run(pipeline)
    _assert_stopped(still, b["event_id"])
    assert a["event_id"] not in still.error and c["event_id"] not in still.error

    released = sup.system_records(logger, "overwatch_stop_released")
    assert len(released) == 1
    d = _detail(released[0])
    assert sorted(d["cleared"]) == sorted([a["event_id"], c["event_id"]])
    assert d["operator_id"] == "gov_officer_mark"
    assert len(d["evidence_ids"]) == 3

    rel2 = _release(pipeline, [b["event_id"]], identities, runtime)
    assert rel2.released, rel2.reason
    _assert_runs(sup.run(pipeline))


# ======================================================================
# 8. A stop arriving during a dispatch: in-flight response recorded,
#    no further dispatch
# ======================================================================

@pytest.mark.parametrize("kind", KINDS)
def test_stop_during_dispatch_records_in_flight_response_and_halts(tmp_path, kind):
    body = sup.make_body(trigger="CRITICAL")
    channel_path = tmp_path / "overwatch" / "stop_channel.jsonl"
    anchor = sup.StopDuringDispatchAdapter("inflight_anchor", channel_path, body)
    beta = sup.CountingAdapter("mock_beta", "beta-model")
    gamma = sup.CountingAdapter("mock_gamma", "gamma-model")
    pipeline, logger, channel, _, _ = _rig(kind, tmp_path, adapters=[anchor, beta, gamma])
    assert channel.channel_path == channel_path

    result = sup.run(pipeline)
    _assert_stopped(result, body["event_id"])
    tid = result.transaction_id
    assert anchor.calls == 1
    assert beta.calls == 0 and gamma.calls == 0

    dispatches = sup.records_of(logger, tid, "dispatch")
    responses = sup.records_of(logger, tid, "response")
    assert [r["platform_id"] for r in dispatches] == ["inflight_anchor"]
    assert [r["platform_id"] for r in responses] == ["inflight_anchor"]
    assert responses[0]["response_text"] == anchor.response_text
    assert sup.records_of(logger, tid, "navigation") == []
    stop = sup.system_records(logger, "overwatch_stop")
    assert len(stop) == 1 and stop[0]["transaction_id"] == tid


@pytest.mark.parametrize("kind", KINDS)
def test_stop_during_synthesis_produces_no_checkpoint_package(tmp_path, kind):
    body = sup.make_body()
    channel_path = tmp_path / "overwatch" / "stop_channel.jsonl"
    nav = sup.StopDuringDispatchAdapter(
        "inflight_navigator", channel_path, body, response_text=sup.NAVIGATOR_MOCK_RESPONSE)
    pipeline, logger, _, _, _ = _rig(kind, tmp_path, nav_adapter=nav)
    result = sup.run(pipeline)
    _assert_stopped(result, body["event_id"])
    assert nav.calls == 1
    tid = result.transaction_id
    assert len(sup.records_of(logger, tid, "dispatch")) == 3
    assert len(sup.records_of(logger, tid, "response")) == 3


@pytest.mark.parametrize("kind", KINDS)
def test_stop_before_release_blocks_record_arbitration(tmp_path, kind):
    pipeline, logger, channel, _, _ = _rig(kind, tmp_path)
    result = sup.run(pipeline)
    _assert_runs(result)
    body = sup.make_body()
    sup.append_line(channel.channel_path, sup.make_line(body))

    arb_cls = ArbitrationInput if kind == "base" else SecureArbitrationInput
    recorded = pipeline.record_arbitration(
        transaction_id=result.transaction_id,
        human_operator_id="analyst_jane",
        arbitration=arb_cls(ArbitrationDecision.ACCEPT, "Accepted after review of every response."),
        checkpoint_role=RECCLINRole.RESEARCHER,
        navigation_record_id=result.checkpoint_package.navigation_record_id,
    )
    assert recorded is False
    tid = result.transaction_id
    assert sup.records_of(logger, tid, "arbitration") == []
    assert sup.records_of(logger, tid, "decision") == []
    stop = sup.system_records(logger, "overwatch_stop")
    assert len(stop) == 1 and stop[0]["transaction_id"] == tid


# ======================================================================
# 9. An acknowledgment without release authority, and acknowledge_breach
#    alone, are both refused
# ======================================================================

def test_ack_without_release_authority_refused_and_acknowledge_breach_does_not_clear(tmp_path):
    pipeline, logger, channel, runtime, identities = _rig("secure", tmp_path)
    body = sup.make_body()
    eid = body["event_id"]
    sup.append_line(channel.channel_path, sup.make_line(body))
    _assert_stopped(sup.run(pipeline), eid)

    # An analyst holds no release authority, even with complete evidence.
    analyst = _release(pipeline, [eid], identities, runtime, requester="analyst_jane")
    assert analyst.released is False
    assert channel.active_stop_ids() == [eid]

    # acknowledge_breach by a governance officer succeeds for the breach
    # state, but never clears an Overwatch stop.
    assert pipeline.acknowledge_breach(
        "gov_officer_mark", "Breach state acknowledged after review of the report.") is True
    assert channel.active_stop_ids() == [eid]
    _assert_stopped(sup.run(pipeline), eid)

    # Missing evidence (no risk statement, no second approver) is refused.
    partial = pipeline.release_overwatch_stop(
        "gov_officer_mark", [eid],
        sup.release_evidence([eid], identities)[:1], runtime,
    )
    assert partial.released is False

    # A second-approver signature bound to a different release is refused (SEC-03).
    other_binding = _release(pipeline, [eid], identities, runtime, sign_for=["f" * 32])
    assert other_binding.released is False

    # Self-approval is refused.
    self_approved = _release(pipeline, [eid], identities, runtime, approver="gov_officer_mark")
    assert self_approved.released is False

    # A release naming a stop that is not active is refused, and clears nothing.
    unknown = _release(pipeline, [eid, "0" * 32], identities, runtime)
    assert unknown.released is False

    # No governance runtime: refused.
    no_runtime = pipeline.overwatch_stop.release_overwatch_stop(
        "gov_officer_mark", [eid], sup.release_evidence([eid], identities), None)
    assert no_runtime.released is False

    # The evidence gate applies even when the deployer registered none.
    bare_runtime, _ = sup.make_runtime(register_release_gate=False)
    no_gate = channel.release_overwatch_stop("gov_officer_mark", [eid], [], bare_runtime)
    assert no_gate.released is False

    assert channel.active_stop_ids() == [eid]
    assert sup.system_records(logger, "overwatch_stop_released") == []
    _assert_stopped(sup.run(pipeline), eid)


# ======================================================================
# 10. A valid human release through the evidence gate resumes the pipe
# ======================================================================

@pytest.mark.parametrize("kind", KINDS)
def test_valid_human_release_through_evidence_gate_resumes(tmp_path, kind):
    pipeline, logger, channel, runtime, identities = _rig(kind, tmp_path)
    body = sup.make_body()
    eid = body["event_id"]
    sup.append_line(channel.channel_path, sup.make_line(body))
    _assert_stopped(sup.run(pipeline), eid)

    evidence = sup.release_evidence([eid], identities)
    rel = pipeline.release_overwatch_stop("gov_officer_mark", [eid], evidence, runtime)
    assert rel.released, rel.reason
    assert rel.cleared == [eid]
    assert rel.governance_decision.authorized
    assert rel.governance_decision.evidence_gate_passed

    state = json.loads(channel.state_path.read_text(encoding="utf-8"))
    assert state["active"] == {}
    assert state["consumed"] == [eid]
    entry = state["releases"][0]
    assert entry["cleared"] == [eid]
    assert entry["operator_id"] == "gov_officer_mark"
    assert entry["release_id"] == rel.release_id
    assert entry["evidence_ids"] == rel.evidence_ids and len(entry["evidence_ids"]) == 3
    assert entry["released_at"].endswith("Z")

    released = sup.system_records(logger, "overwatch_stop_released")
    assert len(released) == 1
    assert released[0]["transaction_id"] == "system"
    d = _detail(released[0])
    assert d["release_id"] == rel.release_id and d["cleared"] == [eid]

    _assert_runs(sup.run(pipeline))
    ok, violations = logger.verify_chain_integrity()
    assert ok, violations


# ======================================================================
# 11. GOPEL runs normally with no Overwatch configured (v2.4 section 4.2)
# ======================================================================

@pytest.mark.parametrize("kind", KINDS)
def test_runs_normally_with_no_channel_configured(tmp_path, kind):
    pipeline, logger, _ = sup.make_pipeline(kind, tmp_path, with_channel=False)
    result = sup.run(pipeline)
    assert result.success, result.error
    assert result.checkpoint_package is not None
    assert getattr(result, "stopped_by_overwatch", False) is False


@pytest.mark.parametrize("kind", KINDS)
def test_runs_normally_when_channel_file_does_not_exist(tmp_path, kind):
    pipeline, logger, channel, _, _ = _rig(kind, tmp_path)
    assert not channel.channel_path.exists()
    _assert_runs(sup.run(pipeline))
    assert sup.system_records(logger, "overwatch_stop_rejected") == []


# ======================================================================
# Line verification reasons, single processing, and configuration guards
# ======================================================================

def test_malformed_schema_noncanonical_and_wrong_pipeline_lines_are_rejected(tmp_path):
    pipeline, logger, channel, _, _ = _rig("base", tmp_path)
    good = sup.make_body()
    extra = dict(sup.make_body(), extra_field="x")
    missing = sup.make_body()
    del missing["finding_ids"]
    bad_schema = sup.make_body()
    bad_schema["schema_version"] = "haia.overwatch.stop.v0"
    bad_event = sup.make_body(event_id="NOT-HEX")
    bad_time = sup.make_body(issued_at="2026-10-14T16:05:09Z")
    bad_trigger = sup.make_body(trigger="WARNING")
    lines = [
        ("not json at all\n", "malformed"),
        (json.dumps({"body": sup.canonical(good)}) + "\n", "malformed"),
        (sup.make_line(extra), "schema"),
        (sup.make_line(missing), "schema"),
        (sup.make_line(bad_schema), "schema"),
        (sup.make_line(bad_event), "schema"),
        (sup.make_line(bad_time), "schema"),
        (sup.make_line(bad_trigger), "schema"),
        (sup.make_line(good, body_text=json.dumps(good, indent=2)), "non_canonical"),
        (sup.make_line(sup.make_body(target_pipeline="some-other-gopel")), "wrong_pipeline"),
    ]
    for line, _ in lines:
        sup.append_line(channel.channel_path, line)
    # The same malformed line again: one record per distinct rejected line.
    sup.append_line(channel.channel_path, "not json at all\n")
    # A partial line still being written is not read until it is complete.
    with open(channel.channel_path, "a", encoding="utf-8") as f:
        f.write('{"body": "{\\"event_id\\"')

    _assert_runs(sup.run(pipeline))
    rejected = sup.system_records(logger, "overwatch_stop_rejected")
    assert [_detail(r)["reason"] for r in rejected] == [reason for _, reason in lines]
    assert [_detail(r)["line_sha256"] for r in rejected] == [sup.line_sha(l) for l, _ in lines]
    state = json.loads(channel.state_path.read_text(encoding="utf-8"))
    assert len(state["rejected_line_sha256"]) == len(lines)
    assert state["active"] == {} and state["consumed"] == []


@pytest.mark.parametrize("kind", KINDS)
def test_halt_and_stop_system_records_carry_the_real_transaction_id(tmp_path, kind):
    """Spec section 3: overwatch_stop, pipeline_halted, total_dispatch_failure."""
    failing = [MockAdapter(p, p + "-model", simulate_error=True, simulate_latency_ms=0)
               for p in ("fail_a", "fail_b", "fail_c")]
    pipeline, logger, _ = sup.make_pipeline(kind, tmp_path, with_channel=False, adapters=failing)
    result = sup.run(pipeline)
    if kind == "secure":
        assert result.success is False
        fails = sup.system_records(logger, "total_dispatch_failure")
        assert len(fails) == 1 and fails[0]["transaction_id"] == result.transaction_id

        class AlwaysHalt(PipelineCircuitBreaker):
            def should_halt(self, report):
                return True

        halting, logger2, _ = sup.make_pipeline(
            "secure", tmp_path / "halt", with_channel=False, circuit_breaker=AlwaysHalt())
        halted = sup.run(halting)
        assert halted.breach_halted is True
        recs = sup.system_records(logger2, "pipeline_halted")
        assert len(recs) == 1 and recs[0]["transaction_id"] == halted.transaction_id
    # The logger's public system-event API takes an optional transaction_id.
    logger.log_system_event("probe", "probe detail", "info", transaction_id="tx-probe")
    logger.log_system_event("probe_default", "default detail")
    assert sup.system_records(logger, "probe")[0]["transaction_id"] == "tx-probe"
    assert sup.system_records(logger, "probe_default")[0]["transaction_id"] == "system"


def test_channel_configuration_guards(tmp_path):
    m = sup.ow()
    logger = AuditLogger(tmp_path / "audit.json")
    with pytest.raises(ValueError):
        sup.make_channel(tmp_path, logger, stop_key=b"short-key")
    # The channel writes to the pipeline's own audit logger, nowhere else.
    other_logger = AuditLogger(tmp_path / "other.json")
    channel = sup.make_channel(tmp_path, other_logger)
    with pytest.raises(ValueError):
        sup.make_pipeline("base", tmp_path / "p", logger=logger, channel=channel)
    # A sentinel identity that names a different pipeline is a misconfiguration.
    channel_ok = sup.make_channel(tmp_path / "s", logger)
    with pytest.raises(ValueError):
        sup.make_pipeline("secure", tmp_path / "s", logger=logger, channel=channel_ok,
                          sentinel=Sentinel(PipelineIdentity("a-different-pipeline")))
    # A corrupt state file fails closed at construction.
    bad_state = tmp_path / "bad_state" / "state.json"
    bad_state.parent.mkdir(parents=True)
    bad_state.write_text("{not json", encoding="utf-8")
    with pytest.raises(m.OverwatchStopStateError):
        sup.make_channel(tmp_path, logger, state_path=bad_state)
    # The stop key file must be readable only by its owner (mode 0600).
    key_file = tmp_path / "stop.key"
    key_file.write_text(sup.STOP_KEY.hex(), encoding="ascii")
    os.chmod(key_file, 0o644)
    with pytest.raises(m.OverwatchStopError):
        m.load_stop_key_file(key_file)
    os.chmod(key_file, 0o600)
    assert m.load_stop_key_file(key_file) == sup.STOP_KEY
    # The canonical form is the spec's json.dumps settings.
    assert m.canonical_json({"b": 1, "a": "é"}) == '{"a":"é","b":1}'
