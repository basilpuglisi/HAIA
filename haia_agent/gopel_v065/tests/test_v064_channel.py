"""
GOPEL v0.6.4, Team Gate (HAIA_Update_Plan_v4, Part C2): the channel.

GOPEL is the governed channel between the human governor and the AI
platforms (Overwatch v2.4, Section 3.3). The agents decide how the channel
is used; the channel only dispatches, collects, routes, logs, pauses,
hashes, and reports.

These tests check, with mock adapters only:
- a group freezes its messages, so every dispatch in it sends the same
  bytes and every Dispatch record carries the same prompt hash;
- responses come back and are logged unaltered;
- a group closes with a channel_group_closed system record;
- the three stop check points (before the group, before each call, after
  collecting) and the human release through the evidence gate;
- route writes Request, Dispatch, Response, and Navigation;
- status reports IDs and hashes only, and sees a tampered chain;
- images are hashed, never stored.

No API keys. No network.

Author: Basil C. Puglisi, MPA
"""

import hashlib
import importlib
import json
from pathlib import Path

import sys

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from haia_agent.gopel_v065.tests import v063_support as sup  # noqa: E402

from haia_agent.gopel_v065.models import OperatingModel, RECCLINRole  # noqa: E402
from haia_agent.gopel_v065.secure_logger import SecureAuditLogger  # noqa: E402
from haia_agent.gopel_v065.sentinel import PipelineIdentity, Sentinel  # noqa: E402

CALLERS = ("agent_model_1", "agent_model_2")
PLATFORMS = [("alpha", "alpha-model"), ("beta", "beta-model"), ("gamma", "gamma-model")]
MESSAGES = [
    {"role": "user", "content": "Session prompt."},
    {"role": "assistant", "content": "Mode question."},
    {"role": "user", "content": "Selection and task: name three sources."},
]


def ch():
    """Import the v0.6.4 channel at call time (absent before the build)."""
    return importlib.import_module("haia_agent.gopel_v065.channel")


def mad():
    return importlib.import_module("haia_agent.gopel_v065.adapters.message_adapter")


def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def build(tmp_path, responses=None, secure=False, with_stop=True, adapters=None, sentinel=True):
    """A channel over three mock platforms and a Navigator, with the stop intake."""
    tmp_path = Path(tmp_path)
    if secure:
        registry, _ids = sup.make_registry()
        from haia_agent.gopel_v065.security import OperatorIdentity
        for c in CALLERS + ("system",):
            registry.register_operator(OperatorIdentity(c))
        logger = SecureAuditLogger(tmp_path / "audit" / "audit.json", operator_registry=registry,
                                   operator_id="system")
    else:
        logger = sup.AuditLogger(tmp_path / "audit" / "audit.json", operator_id="gopel_channel")
    stop = sup.make_channel(tmp_path, logger) if with_stop else None
    m = mad()
    responses = responses or {}
    if adapters is None:
        adapters = {}
        for pid, _model in PLATFORMS + [("nav", "nav-model")]:
            adapters[pid] = m.MessageMockAdapter(
                pid, responses.get(pid, f"{pid} answer."), service=f"https://{pid}.invalid")
    channel = ch().GOPELChannel(
        logger=logger, adapters=adapters, overwatch_stop=stop,
        sentinel=Sentinel(PipelineIdentity(sup.PIPELINE_ID)) if sentinel else None,
        callers=CALLERS)
    return channel, logger, stop, adapters


def records(logger, rtype=None, tid=None):
    out = logger.get_records()
    if rtype:
        out = [r for r in out if r["record_type"] == rtype]
    if tid:
        out = [r for r in out if r["transaction_id"] == tid]
    return out


def open_group(channel, **kw):
    args = dict(caller_id="agent_model_2", operating_model=OperatingModel.MODEL_2,
                recclin_role=RECCLINRole.RESEARCHER, messages=MESSAGES, platforms=PLATFORMS)
    args.update(kw)
    return channel.open_dispatch(**args)


# ----------------------------------------------------------------------
# Groups: identical prompts by construction
# ----------------------------------------------------------------------

def test_group_freezes_messages_and_every_dispatch_carries_the_same_prompt_hash(tmp_path):
    channel, logger, _stop, adapters = build(tmp_path)
    msgs = json.loads(json.dumps(MESSAGES))
    group = open_group(channel, messages=msgs)
    msgs[2]["content"] = "changed after the group opened"
    for pid, _model in PLATFORMS:
        res = channel.dispatch(group, pid)
        assert res.success and not res.stopped
    expected = hashlib.sha256(canonical(MESSAGES).encode("utf-8")).hexdigest()
    dispatches = records(logger, "dispatch", group.transaction_id)
    assert len(dispatches) == 3
    assert {d["prompt_hash"] for d in dispatches} == {expected}
    sent = [adapters[pid].calls[0]["messages"] for pid, _ in PLATFORMS]
    assert sent[0] == sent[1] == sent[2] == MESSAGES
    request = records(logger, "request", group.transaction_id)
    assert len(request) == 1
    assert request[0]["prompt_text"] == canonical(MESSAGES)
    assert request[0]["caller_id"] == "agent_model_2"
    assert request[0]["platform_selections"] == [pid for pid, _ in PLATFORMS]


def test_responses_come_back_and_are_logged_unaltered(tmp_path):
    odd = "\nline one\r\nline two <b>&amp;</b> \U0001F600 end\r"
    channel, logger, _stop, _ad = build(tmp_path, responses={"alpha": odd})
    group = open_group(channel)
    res = channel.dispatch(group, "alpha")
    assert res.text == odd
    resp = records(logger, "response", group.transaction_id)
    assert resp[0]["response_text"] == odd
    assert res.response_hash == hashlib.sha256(odd.encode("utf-8")).hexdigest()
    assert res.response_ref == {"record_id": resp[0]["record_id"], "chain_hash": resp[0]["chain_hash"]}


def test_a_group_closes_with_one_channel_group_closed_record(tmp_path):
    channel, logger, _stop, _ad = build(tmp_path)
    group = open_group(channel)
    for pid, _model in PLATFORMS:
        channel.dispatch(group, pid)
    closed = [r for r in records(logger, "system", group.transaction_id)
              if r["event_type"] == "channel_group_closed"]
    assert len(closed) == 1
    detail = json.loads(closed[0]["event_detail"])
    resp_ids = [r["record_id"] for r in records(logger, "response", group.transaction_id)]
    assert detail["response_record_ids"] == resp_ids
    assert detail["reason"] == "complete"
    assert closed[0]["event_detail"] == canonical(detail)
    with pytest.raises(ch().ChannelError):
        channel.dispatch(group, "alpha")


def test_close_on_a_partial_group_records_the_reason(tmp_path):
    channel, logger, _stop, _ad = build(tmp_path)
    group = open_group(channel)
    channel.dispatch(group, "alpha")
    channel.close(group, "the caller needed one answer")
    closed = [r for r in records(logger, "system", group.transaction_id)
              if r["event_type"] == "channel_group_closed"]
    assert len(closed) == 1
    assert json.loads(closed[0]["event_detail"])["reason"] == "the caller needed one answer"
    channel.close(group, "again")
    assert len([r for r in records(logger, "system", group.transaction_id)
                if r["event_type"] == "channel_group_closed"]) == 1


def test_a_platform_outside_the_group_or_dispatched_twice_is_refused(tmp_path):
    channel, _logger, _stop, _ad = build(tmp_path)
    group = open_group(channel, platforms=PLATFORMS[:2])
    with pytest.raises(ch().ChannelError):
        channel.dispatch(group, "gamma")
    channel.dispatch(group, "alpha")
    with pytest.raises(ch().ChannelError):
        channel.dispatch(group, "alpha")


def test_unknown_caller_unregistered_platform_and_bad_messages_are_refused(tmp_path):
    channel, _logger, _stop, _ad = build(tmp_path)
    with pytest.raises(ch().ChannelError):
        open_group(channel, caller_id="someone_else")
    with pytest.raises(ch().ChannelError):
        open_group(channel, platforms=[("delta", "d-model")])
    with pytest.raises(ch().ChannelError):
        open_group(channel, messages=[{"role": "user"}])
    with pytest.raises(ch().ChannelError):
        open_group(channel, platforms=[("alpha", "a"), ("alpha", "a")])


def test_images_are_hashed_and_never_stored(tmp_path):
    channel, logger, _stop, adapters = build(tmp_path)
    image = b"\x89PNG fake image bytes for the channel test"
    group = open_group(channel, images=[("image/png", image)], platforms=PLATFORMS[:1])
    channel.dispatch(group, "alpha")
    request = records(logger, "request", group.transaction_id)[0]
    assert request["image_sha256"] == [hashlib.sha256(image).hexdigest()]
    assert adapters["alpha"].calls[0]["images"] == [("image/png", image)]
    raw = Path(logger.audit_file_path).read_bytes()
    assert image not in raw


def test_a_failed_call_logs_its_error_and_returns_no_text(tmp_path):
    m = mad()
    adapters = {pid: m.MessageMockAdapter(pid, f"{pid} answer.", service=f"https://{pid}.invalid")
                for pid, _ in PLATFORMS}
    adapters["alpha"] = m.MessageMockAdapter("alpha", RuntimeError("provider down"),
                                             service="https://alpha.invalid")
    channel, logger, _stop, _ad = build(tmp_path, adapters=adapters)
    group = open_group(channel)
    res = channel.dispatch(group, "alpha")
    assert res.success is False and res.text is None
    assert "provider down" in res.error
    resp = records(logger, "response", group.transaction_id)[0]
    assert resp["response_status"] == "error" and "provider down" in resp["error_detail"]
    disp = records(logger, "dispatch", group.transaction_id)[0]
    # v0.6.5: the Dispatch record is written before the call, so it records the send; the
    # failure is on the Response record above.
    assert disp["dispatch_status"] == "sent"


# ----------------------------------------------------------------------
# The three stop check points, and the human release
# ----------------------------------------------------------------------

def test_a_stop_before_the_group_opens_returns_stopped_and_sends_nothing(tmp_path):
    channel, logger, stop, adapters = build(tmp_path)
    sup.append_line(stop.channel_path, sup.make_line(sup.make_body()))
    res = open_group(channel)
    assert res.stopped is True and res.active_stop_event_ids
    assert records(logger, "request") == []
    assert all(not a.calls for a in adapters.values())
    stops = records(logger, "system")
    assert any(r["event_type"] == "overwatch_stop" for r in stops)


def test_a_stop_between_dispatches_halts_the_rest(tmp_path):
    channel, logger, stop, adapters = build(tmp_path)
    group = open_group(channel)
    assert channel.dispatch(group, "alpha").success
    sup.append_line(stop.channel_path, sup.make_line(sup.make_body()))
    res = channel.dispatch(group, "beta")
    assert res.stopped is True and res.text is None
    assert adapters["beta"].calls == []
    assert [d["platform_id"] for d in records(logger, "dispatch", group.transaction_id)] == ["alpha"]
    closed = [r for r in records(logger, "system", group.transaction_id)
              if r["event_type"] == "channel_group_closed"]
    assert len(closed) == 1 and json.loads(closed[0]["event_detail"])["reason"] == "stopped"


def test_a_stop_arriving_during_a_call_logs_the_response_and_withholds_the_text(tmp_path):
    m = mad()
    holder = {}

    def respond(model, messages, images):
        sup.append_line(holder["stop"].channel_path, sup.make_line(sup.make_body()))
        return "in-flight answer"

    adapters = {pid: m.MessageMockAdapter(pid, f"{pid} answer.", service=f"https://{pid}.invalid")
                for pid, _ in PLATFORMS}
    adapters["alpha"] = m.MessageMockAdapter("alpha", respond, service="https://alpha.invalid")
    channel, logger, stop, _ad = build(tmp_path, adapters=adapters)
    holder["stop"] = stop
    group = open_group(channel)
    res = channel.dispatch(group, "alpha")
    assert res.stopped is True and res.text is None
    resp = records(logger, "response", group.transaction_id)
    assert len(resp) == 1 and resp[0]["response_text"] == "in-flight answer"
    assert res.response_ref["record_id"] == resp[0]["record_id"]


def test_a_human_release_through_the_evidence_gate_reopens_the_channel(tmp_path):
    channel, logger, stop, _ad = build(tmp_path)
    body = sup.make_body()
    sup.append_line(stop.channel_path, sup.make_line(body))
    assert open_group(channel).stopped is True
    runtime, identities = sup.make_runtime()
    refused = channel.release_overwatch_stop("gov_officer_mark", [body["event_id"]], [], runtime)
    assert refused.released is False
    assert channel.status().active_stop_event_ids == [body["event_id"]]
    released = channel.release_overwatch_stop(
        "gov_officer_mark", [body["event_id"]], sup.release_evidence([body["event_id"]], identities), runtime)
    assert released.released is True
    st = channel.status()
    assert st.active_stop_event_ids == [] and released.release_id in st.release_ids
    group = open_group(channel)
    assert not getattr(group, "stopped", False)
    assert channel.dispatch(group, "alpha").success


# ----------------------------------------------------------------------
# Route: one Navigator turn
# ----------------------------------------------------------------------

def test_route_writes_request_dispatch_response_and_navigation_then_closes(tmp_path):
    channel, logger, _stop, _ad = build(tmp_path, responses={"nav": "Navigator synthesis text."})
    group = open_group(channel)
    upstream = [channel.dispatch(group, pid).response_ref["record_id"] for pid, _ in PLATFORMS]
    res = channel.route(caller_id="agent_model_2", operating_model=OperatingModel.MODEL_2,
                        navigator=("nav", "nav-model"), messages=MESSAGES,
                        upstream_response_ids=upstream)
    assert res.success and res.text == "Navigator synthesis text."
    tid = res.transaction_id
    kinds = [r["record_type"] for r in records(logger, tid=tid)]
    assert kinds == ["request", "dispatch", "response", "navigation", "system"]
    nav = records(logger, "navigation", tid)[0]
    assert nav["full_synthesis_text"] == "Navigator synthesis text."
    assert nav["navigator_platform"] == "nav"
    assert nav["response_record_ids"] == upstream + [res.response_ref["record_id"]]
    assert records(logger, "request", tid)[0]["recclin_role"] == "navigator"
    closed = records(logger, "system", tid)[0]
    assert closed["event_type"] == "channel_group_closed"


def test_route_refuses_while_a_stop_is_active(tmp_path):
    channel, logger, stop, adapters = build(tmp_path)
    sup.append_line(stop.channel_path, sup.make_line(sup.make_body()))
    res = channel.route(caller_id="agent_model_1", operating_model=OperatingModel.MODEL_1,
                        navigator=("nav", "nav-model"), messages=MESSAGES)
    assert res.stopped is True and adapters["nav"].calls == []


# ----------------------------------------------------------------------
# Status: report IDs and hashes only
# ----------------------------------------------------------------------

def test_status_reports_ids_and_hashes_only(tmp_path):
    channel, logger, _stop, _ad = build(tmp_path, responses={"alpha": "SECRET-ANSWER-TEXT"})
    group = open_group(channel)
    channel.dispatch(group, "alpha")
    st = channel.status()
    assert st.instance_id == sup.PIPELINE_ID
    assert st.version == "0.6.5"
    assert st.chain_ok is True
    last = logger.get_records()[-1]
    assert (st.head_seq, st.head_chain_hash) == (last["sequence_number"], last["chain_hash"])
    assert channel.status(at_seq=1).chain_hash_at == logger.get_records()[0]["chain_hash"]
    assert "SECRET-ANSWER-TEXT" not in repr(st)
    assert st.active_stop_event_ids == []


def test_status_sees_a_tampered_chain_on_disk(tmp_path):
    channel, logger, _stop, _ad = build(tmp_path)
    group = open_group(channel)
    channel.dispatch(group, "alpha")
    path = Path(logger.audit_file_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    data["records"][1]["prompt_text"] = "rewritten"
    path.write_text(json.dumps(data), encoding="utf-8")
    assert channel.status().chain_ok is False


def test_the_platform_registry_hash_is_stable_and_names_each_service(tmp_path):
    a, _l1, _s1, _ad1 = build(tmp_path / "a")
    b, _l2, _s2, _ad2 = build(tmp_path / "b")
    assert a.registry_sha256() == b.registry_sha256()
    m = mad()
    other = {pid: m.MessageMockAdapter(pid, "x", service=f"https://other-{pid}.invalid")
             for pid, _ in PLATFORMS + [("nav", "")]}
    c, _l3, _s3, _ad3 = build(tmp_path / "c", adapters=other)
    assert c.registry_sha256() != a.registry_sha256()
    assert a.registry() == {pid: f"https://{pid}.invalid" for pid, _ in PLATFORMS + [("nav", "")]}


# ----------------------------------------------------------------------
# Construction guards
# ----------------------------------------------------------------------

def test_construction_refuses_a_stop_intake_on_another_logger_or_pipeline(tmp_path):
    channel, logger, stop, adapters = build(tmp_path)
    other = sup.AuditLogger(Path(tmp_path) / "other" / "audit.json", operator_id="x")
    with pytest.raises(ch().ChannelError):
        ch().GOPELChannel(logger=other, adapters=adapters, overwatch_stop=stop, callers=CALLERS)
    with pytest.raises(ch().ChannelError):
        ch().GOPELChannel(logger=logger, adapters=adapters, overwatch_stop=stop, callers=CALLERS,
                          sentinel=Sentinel(PipelineIdentity("another-instance")))


def test_secure_logger_signs_channel_records_with_the_caller_identity(tmp_path):
    channel, logger, _stop, _ad = build(tmp_path, secure=True)
    group = open_group(channel)
    channel.dispatch(group, "alpha")
    for r in records(logger, tid=group.transaction_id):
        assert not str(r.get("operator_signature", "")).startswith("unsigned")
    ok, _violations = logger.verify_chain_integrity()
    assert ok
