"""
HAIA-Overwatch v2.5 - Tests: every AIG escalation stops the pipe

Plan steps 14e and 20 (Overwatch side). Ruling R5: stop the pipe, route
to human, is Overwatch's only authority over GOPEL; code that does not do
this is a defect. Paper sections 8, 9 and 14. Gate 1 shared spec,
sections 1 and 2.

Defect in v2.4: escalation only holds AIG mode and alerts
(escalation_engine.py:168-213); no stop is ever issued.

The line format is checked independently here: canonical JSON body,
HMAC-SHA256 over the exact UTF-8 bytes of the body, compare_digest.

Author: Basil C. Puglisi, MPA
License: CC BY-NC 4.0
Repository: github.com/basilpuglisi/HAIA
Attribution: #AIassisted under HAIA-RECCLIN & Checkpoint-Based Governance
"""

import hashlib
import hmac
import json
import os
import re
import stat
import time

import pytest

from overwatch_v27.gopel_observer import GopelObserver
from overwatch_v27.models import (
    OverwatchConfig, PlatformResponse, RECCLINRole, Severity, TrajectoryAlert,
    TransactionRecord,
)
from overwatch_v27.pipeline import OverwatchPipeline
from overwatch_v27.provenance_manager import ProvenanceManager
from overwatch_v27.tests.gopel_fixture_support_v25 import (
    audit_document,
    channel_with_sink,
    expected_finalized,
    fixture_records,
    refs_for,
    require,
)

try:
    from overwatch_v27.channel_manager import StopChannelPublisher
except ImportError:  # absent before step 20
    StopChannelPublisher = None

STOP_KEY = b"overwatch-stop-channel-key-0001-test"
HEARTBEAT_KEY = b"overwatch-heartbeat-key-0001-test-xx"
CALIBRATION_KEY = b"overwatch-calibration-key-0001-test-x"
MANIFEST_KEY = b"overwatch-manifest-key-0001-test-xxxx"
PROVENANCE_KEY = b"overwatch-provenance-key-0001-test-xx"
KEY_ID = "overwatch-stop-key-2026-10"
TARGET = "gopel-alpha-instance-1"

BODY_FIELDS = {
    "schema_version", "event_id", "issued_at", "key_id", "target_pipeline",
    "transaction_id", "trigger", "finding_ids", "gopel_record_refs",
}
ISO_MS_Z = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
EVENT_ID = re.compile(r"^[0-9a-f]{32}$")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _publisher(tmp_path, key=STOP_KEY, name="stops.jsonl"):
    cls = require(StopChannelPublisher, "StopChannelPublisher (step 20)")
    return cls(channel_path=str(tmp_path / name), key_id=KEY_ID,
               stop_key=key, target_pipeline=TARGET)


def _pipeline(tmp_path, config=None, attach=True):
    pipeline = OverwatchPipeline(config or OverwatchConfig())
    publisher = None
    if attach:
        publisher = _publisher(tmp_path)
        attach_fn = require(getattr(pipeline, "attach_stop_publisher", None),
                            "OverwatchPipeline.attach_stop_publisher (step 20)")
        attach_fn(publisher)
    return pipeline, publisher


def _lines(tmp_path, name="stops.jsonl"):
    path = tmp_path / name
    if not path.exists():
        return []
    raw = path.read_bytes().decode("utf-8")
    assert raw == "" or raw.endswith("\n")
    return [json.loads(line) for line in raw.splitlines()]


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _mac_ok(line, key):
    expected = hmac.new(key, line["body"].encode("utf-8"), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, line["mac"])


def _body(line):
    return json.loads(line["body"])


def _transaction(tid, prompt="Summarize the published governance literature."):
    return TransactionRecord(
        transaction_id=tid, timestamp=time.time(), operator_id="op-stop",
        recclin_role=RECCLINRole.RESEARCHER, prompt_hash="h", prompt_text=prompt,
        platforms_dispatched=["p1"],
        responses=[PlatformResponse(platform_id="p1", response_text="A summary.",
                                    response_hash="r", response_time_ms=10.0)],
    )


def _finding_ids(outcome):
    return ([f.finding_id for f in outcome.structural_findings]
            + [f.finding_id for f in outcome.inspection_findings])


# ===========================================================================
# One stop per escalation, in the spec's exact line format
# ===========================================================================

class TestStopLine:

    def test_critical_escalation_publishes_exactly_one_verified_stop(self, tmp_path):
        # Default settings: no structural inputs, so a CRITICAL finding escalates.
        pipeline, _pub = _pipeline(tmp_path)
        outcome = pipeline.verify_transaction(_transaction("txn-critical"))
        assert outcome.escalated is True
        assert outcome.overall_severity == Severity.CRITICAL

        lines = _lines(tmp_path)
        assert len(lines) == 1
        line = lines[0]
        assert set(line) == {"body", "mac"}
        assert re.fullmatch(r"[0-9a-f]{64}", line["mac"])
        assert _mac_ok(line, STOP_KEY)

        body = _body(line)
        assert line["body"] == _canonical(body), "body must be canonical JSON"
        assert set(body) == BODY_FIELDS
        assert body["schema_version"] == "haia.overwatch.stop.v1"
        assert EVENT_ID.match(body["event_id"])
        assert ISO_MS_Z.match(body["issued_at"])
        assert body["key_id"] == KEY_ID
        assert body["target_pipeline"] == TARGET
        assert body["transaction_id"] == "txn-critical"
        assert body["trigger"] == "CRITICAL"
        assert body["finding_ids"] == _finding_ids(outcome)
        not_performed = [f.finding_id for f in outcome.structural_findings
                         if f.description == "STRUCTURAL_VERIFICATION_NOT_PERFORMED"]
        assert not_performed and not_performed[0] in body["finding_ids"]
        assert body["gopel_record_refs"] == []
        assert outcome.stop_event_id == body["event_id"]

    def test_the_mac_verifies_only_with_the_stop_key(self, tmp_path):
        pipeline, _pub = _pipeline(tmp_path)
        pipeline.verify_transaction(_transaction("txn-keys"))
        line = _lines(tmp_path)[0]
        assert _mac_ok(line, STOP_KEY)
        for other in (HEARTBEAT_KEY, CALIBRATION_KEY, MANIFEST_KEY, PROVENANCE_KEY):
            assert not _mac_ok(line, other)

    def test_halt_escalation_trigger_is_halt(self, tmp_path):
        gopel_dir = tmp_path / "gopel"
        gopel_dir.mkdir()
        for name in ("pipeline.py", "security.py", "logger.py"):
            (gopel_dir / name).write_text(f"# fake GOPEL module {name}\n", encoding="utf-8")
        # v2.6: an unsigned manifest needs the named local test setting.
        pipeline, _pub = _pipeline(tmp_path, OverwatchConfig(local_test_unsigned_manifests=True))
        pipeline.structural_verifier.create_manifest_from_directory(str(gopel_dir), "0.6.5", "CBG-AUTH-HALT")
        (gopel_dir / "security.py").unlink()
        outcome = pipeline.verify_transaction(_transaction("txn-halt"), gopel_directory=str(gopel_dir))
        assert outcome.escalated and outcome.overall_severity == Severity.HALT
        lines = _lines(tmp_path)
        assert len(lines) == 1
        assert _body(lines[0])["trigger"] == "HALT"
        assert _body(lines[0])["finding_ids"] == _finding_ids(outcome)

    def test_trajectory_escalation_trigger_is_trajectory(self, tmp_path):
        pipeline, _pub = _pipeline(tmp_path, OverwatchConfig(require_structural_inputs=False))
        alert = TrajectoryAlert(transaction_id="txn-trajectory", operator_id="op-stop",
                                window_size=6, scope_drift_score=0.5, privilege_gradient=0.2,
                                coherence_decay_rate=0.3, converging_signals=3)
        pipeline.intent_analyzer.evaluate_trajectory = lambda operator_id, transaction_id: alert
        outcome = pipeline.verify_transaction(_transaction("txn-trajectory"))
        assert outcome.escalated is True
        lines = _lines(tmp_path)
        assert len(lines) == 1
        body = _body(lines[0])
        assert body["trigger"] == "TRAJECTORY"
        assert body["transaction_id"] == "txn-trajectory"
        assert body["finding_ids"] == _finding_ids(outcome) + [alert.alert_id]

    def test_trajectory_stop_names_the_trajectory_alert(self, tmp_path):
        """M2, sources always: a stop raised by a trajectory alert alone
        still names what triggered it, the alert's own ID."""
        pipeline, _pub = _pipeline(tmp_path, OverwatchConfig(require_structural_inputs=False))
        alert = TrajectoryAlert(transaction_id="txn-trajectory-only", operator_id="op-stop",
                                window_size=6, scope_drift_score=0.5, privilege_gradient=0.2,
                                coherence_decay_rate=0.3, converging_signals=3)
        pipeline.intent_analyzer.evaluate_trajectory = lambda operator_id, transaction_id: alert
        outcome = pipeline.verify_transaction(_transaction("txn-trajectory-only"))
        assert outcome.escalated is True
        body = _body(_lines(tmp_path)[0])
        assert body["trigger"] == "TRAJECTORY"
        assert alert.alert_id in body["finding_ids"]
        assert body["finding_ids"].count(alert.alert_id) == 1

    def test_inspect_path_publishes_exactly_one_stop(self, tmp_path):
        pipeline, _pub = _pipeline(tmp_path)
        outcome = pipeline.inspect(_transaction("txn-inspect"))
        assert outcome.escalated
        assert len(_lines(tmp_path)) == 1

    def test_every_escalation_appends_one_line_and_never_rewrites(self, tmp_path):
        pipeline, _pub = _pipeline(tmp_path)
        pipeline.verify_transaction(_transaction("txn-a"))
        first = (tmp_path / "stops.jsonl").read_bytes()
        pipeline.verify_transaction(_transaction("txn-b"))
        pipeline.inspect(_transaction("txn-c"))
        data = (tmp_path / "stops.jsonl").read_bytes()
        assert data.startswith(first)
        lines = _lines(tmp_path)
        assert [_body(l)["transaction_id"] for l in lines] == ["txn-a", "txn-b", "txn-c"]
        assert len({_body(l)["event_id"] for l in lines}) == 3
        assert all(_mac_ok(l, STOP_KEY) for l in lines)

    def test_every_publish_leaves_the_file_ending_in_one_newline(self, tmp_path):
        """GOPEL reads only newline-terminated lines; a last line without
        a newline is treated as still being written."""
        pipeline, _pub = _pipeline(tmp_path)
        path = tmp_path / "stops.jsonl"
        for n in range(1, 6):
            pipeline.verify_transaction(_transaction(f"txn-nl-{n}"))
            raw = path.read_bytes()
            assert raw.endswith(b"\n")
            assert not raw.endswith(b"\n\n")
            assert raw.count(b"\n") == n
            for line in raw.split(b"\n")[:-1]:
                obj = json.loads(line.decode("utf-8"))
                assert set(obj) == {"body", "mac"}
                assert _mac_ok(obj, STOP_KEY)

    def test_a_published_line_is_exactly_the_json_object_and_one_newline(self, tmp_path):
        publisher = _publisher(tmp_path)
        result = publisher.publish(transaction_id="t-exact", trigger="HALT",
                                   finding_ids=["f"], gopel_record_refs=[])
        raw = (tmp_path / "stops.jsonl").read_bytes()
        assert raw == (result["line"] + "\n").encode("utf-8")
        assert json.loads(result["line"]) == {"body": json.loads(raw)["body"], "mac": json.loads(raw)["mac"]}

    def test_non_escalated_outcomes_publish_no_stop(self, tmp_path):
        pipeline, _pub = _pipeline(tmp_path, OverwatchConfig(require_structural_inputs=False))
        for i in range(5):
            outcome = pipeline.verify_transaction(_transaction(f"txn-clean-{i}"))
            assert outcome.escalated is False
        assert _lines(tmp_path) == []
        assert pipeline.get_health()["stops_published"] == 0


# ===========================================================================
# GOPEL records as sources (M2): the observer passes record refs
# ===========================================================================

class TestStopCarriesGopelSources:

    def test_observer_stops_name_the_triggering_gopel_records(self, tmp_path):
        records = fixture_records()
        pipeline, _pub = _pipeline(tmp_path)   # default settings: escalates
        cm, _messages = channel_with_sink()
        observer = GopelObserver(pipeline, channel_manager=cm)
        observer.observe_audit_document(audit_document())

        finalized = expected_finalized(records)
        lines = _lines(tmp_path)
        assert len(lines) == len(finalized)
        for line, tid in zip(lines, finalized):
            body = _body(line)
            assert _mac_ok(line, STOP_KEY)
            assert body["transaction_id"] == tid
            assert body["gopel_record_refs"] == refs_for(records, tid)
            assert body["finding_ids"]


# ===========================================================================
# No publisher: nothing raises; health says so
# ===========================================================================

class TestWithoutPublisher:

    def test_no_publisher_reports_not_configured_and_nothing_raises(self, tmp_path):
        pipeline = OverwatchPipeline(OverwatchConfig())
        outcome = pipeline.verify_transaction(_transaction("txn-no-publisher"))
        assert outcome.escalated is True
        health = pipeline.get_health()
        assert health["stop_channel"] == "not configured"
        assert pipeline.get_status()["health"]["stop_channel"] == "not configured"
        assert list(tmp_path.iterdir()) == []

    def test_configured_publisher_reports_configured_and_counts(self, tmp_path):
        pipeline, _pub = _pipeline(tmp_path)
        pipeline.verify_transaction(_transaction("txn-count-1"))
        pipeline.verify_transaction(_transaction("txn-count-2"))
        health = pipeline.get_health()
        assert health["stop_channel"] == "configured"
        assert health["stops_published"] == 2
        assert health["stop_publish_failures"] == 0

    def test_publish_failure_is_reported_and_does_not_raise(self, tmp_path):
        cls = require(StopChannelPublisher, "StopChannelPublisher (step 20)")
        pipeline = OverwatchPipeline(OverwatchConfig())
        publisher = cls(channel_path=str(tmp_path / "missing_dir" / "stops.jsonl"),
                        key_id=KEY_ID, stop_key=STOP_KEY, target_pipeline=TARGET)
        pipeline.attach_stop_publisher(publisher)
        outcome = pipeline.verify_transaction(_transaction("txn-fail"))
        assert outcome.escalated
        assert outcome.stop_event_id == ""
        health = pipeline.get_health()
        assert health["stops_published"] == 0
        assert health["stop_publish_failures"] == 1


# ===========================================================================
# The stop key is scoped to the stop channel only
# ===========================================================================

class TestStopKeyScope:

    def test_short_stop_key_is_refused(self, tmp_path):
        with pytest.raises(ValueError):
            _publisher(tmp_path, key=b"x" * 31)

    @pytest.mark.parametrize("field, value", [
        ("key_id", ""), ("target_pipeline", ""),
    ])
    def test_empty_identity_is_refused(self, tmp_path, field, value):
        cls = require(StopChannelPublisher, "StopChannelPublisher (step 20)")
        kwargs = dict(channel_path=str(tmp_path / "s.jsonl"), key_id=KEY_ID,
                      stop_key=STOP_KEY, target_pipeline=TARGET)
        kwargs[field] = value
        with pytest.raises(ValueError):
            cls(**kwargs)

    def test_stop_key_equal_to_the_heartbeat_key_is_refused(self, tmp_path):
        pipeline = OverwatchPipeline(OverwatchConfig())
        pipeline.set_heartbeat_key(HEARTBEAT_KEY)
        with pytest.raises(ValueError):
            pipeline.attach_stop_publisher(_publisher(tmp_path, key=HEARTBEAT_KEY))

    def test_other_keys_cannot_reuse_the_stop_key(self, tmp_path):
        pipeline, _pub = _pipeline(tmp_path)
        with pytest.raises(ValueError):
            pipeline.set_heartbeat_key(STOP_KEY)
        with pytest.raises(ValueError):
            pipeline.factics_engine.set_calibration_key(STOP_KEY)
        with pytest.raises(ValueError):
            pipeline.set_manifest_key(STOP_KEY)
        with pytest.raises(ValueError):
            pipeline.register_key_scope("provenance", STOP_KEY)

    def test_stop_key_equal_to_calibration_manifest_or_provenance_key_is_refused(self, tmp_path):
        provenance = ProvenanceManager(PROVENANCE_KEY)
        for scope, key in (("calibration", CALIBRATION_KEY), ("manifest", MANIFEST_KEY),
                           ("provenance", provenance.signing_key)):
            pipeline = OverwatchPipeline(OverwatchConfig())
            if scope == "calibration":
                pipeline.factics_engine.set_calibration_key(key)
            elif scope == "manifest":
                pipeline.set_manifest_key(key)
            else:
                pipeline.register_key_scope("provenance", key)
            with pytest.raises(ValueError):
                pipeline.attach_stop_publisher(_publisher(tmp_path, key=key))

    def test_distinct_keys_are_accepted(self, tmp_path):
        pipeline = OverwatchPipeline(OverwatchConfig())
        pipeline.set_heartbeat_key(HEARTBEAT_KEY)
        pipeline.factics_engine.set_calibration_key(CALIBRATION_KEY)
        pipeline.set_manifest_key(MANIFEST_KEY)
        pipeline.register_key_scope("provenance", PROVENANCE_KEY)
        pipeline.attach_stop_publisher(_publisher(tmp_path))
        assert pipeline.get_health()["stop_channel"] == "configured"

    def test_key_file_must_be_readable_only_by_its_owner(self, tmp_path):
        """The key file holds the key as hex text, the format GOPEL v0.6.3
        reads, so one file configures both sides."""
        cls = require(StopChannelPublisher, "StopChannelPublisher (step 20)")
        key_file = tmp_path / "stop.key"
        key_file.write_text(STOP_KEY.hex() + "\n", encoding="ascii")
        os.chmod(key_file, 0o644)
        with pytest.raises(ValueError):
            cls.from_key_file(str(tmp_path / "s.jsonl"), KEY_ID, str(key_file), TARGET)
        os.chmod(key_file, stat.S_IRUSR | stat.S_IWUSR)
        publisher = cls.from_key_file(str(tmp_path / "s.jsonl"), KEY_ID, str(key_file), TARGET)
        publisher.publish(transaction_id="t", trigger="HALT", finding_ids=[], gopel_record_refs=[])
        line = _lines(tmp_path, "s.jsonl")[0]
        assert _mac_ok(line, STOP_KEY)

    def test_a_key_file_that_is_not_hex_is_refused(self, tmp_path):
        cls = require(StopChannelPublisher, "StopChannelPublisher (step 20)")
        key_file = tmp_path / "stop.key"
        key_file.write_text("not hex at all, not a key", encoding="ascii")
        os.chmod(key_file, stat.S_IRUSR | stat.S_IWUSR)
        with pytest.raises(ValueError):
            cls.from_key_file(str(tmp_path / "s.jsonl"), KEY_ID, str(key_file), TARGET)

    def test_unknown_trigger_is_refused(self, tmp_path):
        publisher = _publisher(tmp_path)
        with pytest.raises(ValueError):
            publisher.publish(transaction_id="t", trigger="WARNING", finding_ids=[],
                              gopel_record_refs=[])
        assert _lines(tmp_path) == []
