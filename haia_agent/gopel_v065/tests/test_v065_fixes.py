"""
GOPEL v0.6.5: the fix round after the Team Gate's CAIPR review.

Basil's fix round, item 1 (October 14, 2026):
  a. The Dispatch record is written before the platform call. An answer that
     cannot be encoded is still recorded, escaped without loss and flagged,
     never as invalid UTF-8. No Response record is ever skipped (finding G-1).
  b. Secret redaction in failure text happens inside GOPEL's adapters, and the
     record notes that a redaction happened.
  c. A group closes as soon as no further send is planned for it, so Overwatch
     inspects every answer that arrived.
  d. A planted-violation fixture proves the analyzer catches what it searches
     for.

Mock and callable adapters only. No network, no API keys.

Author: Basil C. Puglisi, MPA
"""

import json
import shutil
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from haia_agent.gopel_v065 import (  # noqa: E402
    CallableMessageAdapter,
    ChannelError,
    GOPELChannel,
    MessageAdapter,
    MessageMockAdapter,
)
from haia_agent.gopel_v065 import static_analyzer as sa  # noqa: E402
from haia_agent.gopel_v065.logger import AuditLogger, read_audit_file, verify_record_chain  # noqa: E402
from haia_agent.gopel_v065.models import OperatingModel, RECCLINRole  # noqa: E402

LONE = "Answer with a stray \ud800 surrogate and a real \U0001F600 face."
MESSAGES = [{"role": "user", "content": "Summarize Article 14."}]
PLATFORMS = [("p_a", "model-a"), ("p_b", "model-b"), ("p_c", "model-c")]


def channel(tmp_path, adapters):
    logger = AuditLogger(tmp_path / "audit.json", operator_id="gopel_test")
    return GOPELChannel(logger=logger, adapters=adapters, callers=("agent_model_1", "agent_model_2")), logger


def stored(tmp_path):
    raw = (tmp_path / "audit.json").read_bytes()
    raw.decode("utf-8")                        # the file is valid UTF-8
    return json.loads(raw)["records"]


def unescape(text, escapes):
    """Restores the original text from the recorded escapes (GOPEL's published rule)."""
    out = text
    for pos, code in sorted(escapes, reverse=True):
        out = out[:pos] + chr(code) + out[pos + 6:]
    return out


def is_lone(ch):
    return 0xD800 <= ord(ch) <= 0xDFFF


def open_group(ch, platforms=PLATFORMS):
    return ch.open_dispatch("agent_model_2", OperatingModel.MODEL_2, RECCLINRole.RESEARCHER, MESSAGES,
                            platforms=platforms)


# ---------------------------------------------------------------- a. G-1

def test_a_lone_surrogate_answer_leaves_a_dispatch_and_a_response_record(tmp_path):
    adapters = {"p_a": CallableMessageAdapter("p_a", lambda m, msgs, imgs, t: {"text": LONE, "response_id": "r1"})}
    ch, _ = channel(tmp_path, adapters)
    g = open_group(ch, [("p_a", "model-a")])
    res = ch.dispatch(g, "p_a")
    recs = [r for r in stored(tmp_path) if r["transaction_id"] == g.transaction_id]
    kinds = [r["record_type"] for r in recs]
    assert kinds.count("dispatch") == 1 and kinds.count("response") == 1
    resp = next(r for r in recs if r["record_type"] == "response")
    assert resp["text_escaped"] is True and resp["escapes"]
    assert not any(is_lone(c) for c in resp["response_text"])
    assert unescape(resp["response_text"], resp["escapes"]) == LONE
    assert res.success is True and res.text == LONE, "the caller gets the answer as it arrived"
    assert verify_record_chain(stored(tmp_path)) == []


def test_a_the_mock_adapter_takes_a_lone_surrogate_answer(tmp_path):
    ch, _ = channel(tmp_path, {"p_a": MessageMockAdapter("p_a", LONE)})
    g = open_group(ch, [("p_a", "model-a")])
    res = ch.dispatch(g, "p_a")
    resp = next(r for r in stored(tmp_path) if r["record_type"] == "response")
    assert res.success and resp["text_escaped"] is True
    assert unescape(resp["response_text"], resp["escapes"]) == LONE


def test_a_an_answer_without_a_lone_surrogate_is_recorded_as_it_came(tmp_path):
    text = "Plain answer with a \\ud800 written out as six characters, and \U0001F600."
    ch, _ = channel(tmp_path, {"p_a": MessageMockAdapter("p_a", text)})
    ch.dispatch(open_group(ch, [("p_a", "model-a")]), "p_a")
    resp = next(r for r in stored(tmp_path) if r["record_type"] == "response")
    assert resp["response_text"] == text and resp["text_escaped"] is False and resp["escapes"] == []


def test_a_the_dispatch_record_is_written_before_the_platform_call(tmp_path):
    seen = {}

    def call(model, messages, images, timeout):
        seen["kinds"] = [r["record_type"] for r in json.loads((tmp_path / "audit.json").read_text())["records"]]
        return {"text": "ok"}
    ch, _ = channel(tmp_path, {"p_a": CallableMessageAdapter("p_a", call)})
    ch.dispatch(open_group(ch, [("p_a", "model-a")]), "p_a")
    assert seen["kinds"][-1] == "dispatch"


def test_a_an_adapter_that_raises_still_leaves_a_response_record(tmp_path):
    class Broken(MessageAdapter):
        def send_messages(self, model, messages, images=(), timeout=None, max_tokens=None, temperature=None):
            raise RuntimeError("transport fell over")
    ch, _ = channel(tmp_path, {"p_a": Broken("p_a")})
    g = open_group(ch, [("p_a", "model-a")])
    res = ch.dispatch(g, "p_a")
    recs = [r for r in stored(tmp_path) if r["transaction_id"] == g.transaction_id]
    resp = [r for r in recs if r["record_type"] == "response"]
    assert len(resp) == 1 and resp[0]["response_status"] == "error" and "transport fell over" in resp[0]["error_detail"]
    assert res.success is False and g.closed


def test_a_failure_text_with_a_lone_surrogate_is_escaped_and_flagged(tmp_path):
    def call(model, messages, images, timeout):
        raise ValueError("bad byte \udcff in the reply")
    ch, _ = channel(tmp_path, {"p_a": CallableMessageAdapter("p_a", call)})
    ch.dispatch(open_group(ch, [("p_a", "model-a")]), "p_a")
    resp = next(r for r in stored(tmp_path) if r["record_type"] == "response")
    assert resp["text_escaped"] is True and resp["error_escapes"]
    assert not any(is_lone(c) for c in resp["error_detail"])
    assert "\udcff" in unescape(resp["error_detail"], resp["error_escapes"])


def test_a_a_routed_navigator_answer_with_a_lone_surrogate_is_recorded_twice_escaped(tmp_path):
    ch, _ = channel(tmp_path, {"nav": MessageMockAdapter("nav", LONE)})
    res = ch.route("agent_model_1", OperatingModel.MODEL_1, ("nav", "n1"), MESSAGES)
    recs = [r for r in stored(tmp_path) if r["transaction_id"] == res.transaction_id]
    resp = next(r for r in recs if r["record_type"] == "response")
    nav = next(r for r in recs if r["record_type"] == "navigation")
    assert resp["text_escaped"] is True and nav["text_escaped"] is True
    assert unescape(nav["full_synthesis_text"], nav["escapes"]) == LONE
    assert any(r.get("event_type") == "channel_group_closed" for r in recs)


def test_a_the_audit_reads_back_through_the_published_reader(tmp_path):
    ch, _ = channel(tmp_path, {"p_a": MessageMockAdapter("p_a", LONE)})
    ch.dispatch(open_group(ch, [("p_a", "model-a")]), "p_a")
    assert len(read_audit_file(tmp_path / "audit.json")) == len(stored(tmp_path))


# ---------------------------------------------------------------- b. redaction inside the adapters

def test_b_a_secret_in_failure_text_is_redacted_inside_the_adapter_and_the_record_says_so(tmp_path, monkeypatch):
    monkeypatch.setenv("TEST_PROVIDER_API_KEY", "sk-test-0123456789abcdef")

    def call(model, messages, images, timeout):
        raise PermissionError("401 for key sk-test-0123456789abcdef")
    ch, _ = channel(tmp_path, {"p_a": CallableMessageAdapter("p_a", call)})
    res = ch.dispatch(open_group(ch, [("p_a", "model-a")]), "p_a")
    resp = next(r for r in stored(tmp_path) if r["record_type"] == "response")
    assert "sk-test-0123456789abcdef" not in json.dumps(stored(tmp_path))
    assert "sk-test-0123456789abcdef" not in res.error
    assert resp["redaction_applied"] is True and "(secret removed)" in resp["error_detail"]


def test_b_named_secret_variables_are_redacted_too(tmp_path, monkeypatch):
    monkeypatch.setenv("CBG_VENDOR_CREDENTIAL", "vendor-credential-value-42")

    def call(model, messages, images, timeout):
        raise RuntimeError("upstream echoed vendor-credential-value-42")
    adapter = CallableMessageAdapter("p_a", call, secret_env_names=("CBG_VENDOR_CREDENTIAL",))
    ch, _ = channel(tmp_path, {"p_a": adapter})
    ch.dispatch(open_group(ch, [("p_a", "model-a")]), "p_a")
    resp = next(r for r in stored(tmp_path) if r["record_type"] == "response")
    assert "vendor-credential-value-42" not in resp["error_detail"] and resp["redaction_applied"] is True


def test_b_an_answer_is_never_redacted(tmp_path, monkeypatch):
    monkeypatch.setenv("TEST_PROVIDER_API_KEY", "sk-test-0123456789abcdef")
    text = "The answer happens to contain sk-test-0123456789abcdef as text."
    ch, _ = channel(tmp_path, {"p_a": MessageMockAdapter("p_a", text)})
    ch.dispatch(open_group(ch, [("p_a", "model-a")]), "p_a")
    resp = next(r for r in stored(tmp_path) if r["record_type"] == "response")
    assert resp["response_text"] == text and resp["redaction_applied"] is False


# ---------------------------------------------------------------- c. a group closes when no send is planned

def closed_events(tmp_path, tid):
    return [json.loads(r["event_detail"]) for r in stored(tmp_path)
            if r.get("event_type") == "channel_group_closed" and r["transaction_id"] == tid]


def test_c_a_withdrawn_platform_closes_the_group_once_the_rest_have_answered(tmp_path):
    ch, _ = channel(tmp_path, {p: MessageMockAdapter(p, f"{p} answer") for p, _ in PLATFORMS})
    g = open_group(ch)
    ch.dispatch(g, "p_a")
    ch.withdraw(g, "p_c", "the governor stopped the task")
    assert not g.closed
    ch.dispatch(g, "p_b")
    assert g.closed
    ev = closed_events(tmp_path, g.transaction_id)
    assert len(ev) == 1 and set(ev[0]) == {"caller_id", "kind", "reason", "response_record_ids"}
    assert ev[0]["reason"].startswith("withdrawn") and len(ev[0]["response_record_ids"]) == 2
    with pytest.raises(ChannelError):
        ch.dispatch(g, "p_c")


def test_c_withdrawing_the_last_unsent_platform_closes_the_group_at_once(tmp_path):
    ch, _ = channel(tmp_path, {p: MessageMockAdapter(p, f"{p} answer") for p, _ in PLATFORMS})
    g = open_group(ch)
    ch.dispatch(g, "p_a")
    ch.dispatch(g, "p_b")
    ch.withdraw(g, "p_c", "no further send is planned")
    assert g.closed and len(closed_events(tmp_path, g.transaction_id)) == 1


def test_c_a_failed_send_counts_as_answered(tmp_path):
    adapters = {p: MessageMockAdapter(p, f"{p} answer") for p, _ in PLATFORMS}
    adapters["p_b"] = MessageMockAdapter("p_b", RuntimeError("down"))
    ch, _ = channel(tmp_path, adapters)
    g = open_group(ch)
    for p, _ in PLATFORMS:
        ch.dispatch(g, p)
    ev = closed_events(tmp_path, g.transaction_id)
    assert g.closed and ev[0]["reason"] == "complete" and len(ev[0]["response_record_ids"]) == 3


def test_c_withdrawing_a_sent_or_unknown_platform_is_refused(tmp_path):
    ch, _ = channel(tmp_path, {p: MessageMockAdapter(p, f"{p} answer") for p, _ in PLATFORMS})
    g = open_group(ch)
    ch.dispatch(g, "p_a")
    with pytest.raises(ChannelError):
        ch.withdraw(g, "p_a", "already sent")
    with pytest.raises(ChannelError):
        ch.withdraw(g, "p_z", "not in the group")


# ---------------------------------------------------------------- d. the analyzer catches what it searches for

def copy_scanned(tmp_path):
    pkg = Path(sa.__file__).resolve().parent
    root = tmp_path / "pkg"
    root.mkdir()
    for name in sa.SCAN_TARGETS:
        shutil.copy2(pkg / name, root / name)
    return root


@pytest.mark.parametrize("planted, kind", [
    ("import transformers\n", "cognitive_import"),
    ("def judge(model, text):\n    return model.predict(text)\n", "cognitive_call"),
    ("def route_by_content(response_text):\n    if response_text == 'approve':\n        return 1\n    return 0\n",
     "content_dependent_branch"),
])
def test_d_a_planted_violation_is_caught(tmp_path, planted, kind):
    root = copy_scanned(tmp_path)
    assert sa.NonCognitiveAnalyzer(framework_root=root).scan().is_compliant
    with open(root / "channel.py", "a", encoding="utf-8") as f:
        f.write("\n\n" + planted)
    result = sa.NonCognitiveAnalyzer(framework_root=root).scan()
    assert not result.is_compliant
    assert any(v.violation_type == kind and v.file_path.endswith("channel.py") for v in result.violations)


def test_d_the_package_itself_is_compliant_and_fully_scanned():
    result = sa.NonCognitiveAnalyzer().scan()
    assert result.is_compliant and result.files_scanned == len(sa.SCAN_TARGETS)
