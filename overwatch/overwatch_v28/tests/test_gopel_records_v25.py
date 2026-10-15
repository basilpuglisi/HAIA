"""
HAIA-Overwatch v2.5 - Tests: every real GOPEL record parses or alerts

Plan steps 13 and 14a. Gate 1 shared spec section 3.

Defect in v2.4: GOPEL's own audit records (lowercase record_type, ISO
timestamps, flat fields, one global hash chain) do not match the
Overwatch-format GopelRecord, and gopel_observer.py:304-308 swallowed the
resulting errors with a counter and no alert. Records were dropped
silently.

GOPEL records come only from the committed fixture
tests/fixtures/gopel_v063_mock_audit_v1.json. Nothing here imports GOPEL.

Author: Basil C. Puglisi, MPA
License: CC BY-NC 4.0
Repository: github.com/basilpuglisi/HAIA
Attribution: #AIassisted under HAIA-RECCLIN & Checkpoint-Based Governance
"""

import copy
import dataclasses
import json
import time

import pytest

from overwatch_v28.gopel_observer import GopelObserver, GopelRecord, GopelRecordKind
from overwatch_v28.models import OverwatchConfig, RECCLINRole
from overwatch_v28.tests.gopel_fixture_support_v25 import (
    COMMIT_KEYS,
    EXPECTED_AUDIT_SCHEMA_VERSION,
    EXPECTED_GOPEL_VERSION,
    RECORD_TYPES,
    REQUIRED_PROVENANCE_KEYS,
    STOP_EVENT_TYPES,
    RecordingPipeline,
    alerts,
    audit_document,
    canonical,
    channel_with_sink,
    declared_gopel_version,
    expected_finalized,
    fixture_records,
    load_fixture,
    rechain,
    records_for,
    refs_for,
    stop_event_detail,
    system_record,
    transaction_ids,
    verify_chain,
)

# GOPEL release and audit schema these tests are written against (step 14f).
assert EXPECTED_GOPEL_VERSION == "0.6.5"
assert EXPECTED_AUDIT_SCHEMA_VERSION == "1.0.0"


def _observer(pipeline=None, **kwargs):
    cm, messages = channel_with_sink()
    pipeline = pipeline if pipeline is not None else RecordingPipeline()
    observer = GopelObserver(
        pipeline,
        channel_manager=cm,
        config=OverwatchConfig(require_structural_inputs=False),
        **kwargs,
    )
    return observer, pipeline, messages


def _observe_document(doc, **kwargs):
    observer, pipeline, messages = _observer(**kwargs)
    observer.observe_audit_document(doc, source_gopel_version=declared_gopel_version())
    return observer, pipeline, messages


def _doc_with(records):
    doc = audit_document()
    doc["records"] = records
    return doc


# ===========================================================================
# The fixture itself (guards: these check the committed evidence)
# ===========================================================================

class TestFixture:

    def test_fixture_records_its_provenance(self):
        fixture = load_fixture()
        prov = fixture["provenance"]
        for key in REQUIRED_PROVENANCE_KEYS:
            assert prov.get(key), f"provenance lacks {key}"
        assert any(prov.get(k) for k in COMMIT_KEYS), "provenance names no commit"
        assert set(fixture) == {"provenance", "schema", "records"}

    def test_fixture_holds_every_gopel_record_type(self):
        types = {r["record_type"] for r in fixture_records()}
        assert set(RECORD_TYPES) <= types

    def test_fixture_holds_two_complete_transactions(self):
        """The tests below derive records from these (see the report's
        fixture requirements)."""
        records = fixture_records()
        full = [tid for tid in transaction_ids(records)
                if {"request", "dispatch", "response", "navigation", "arbitration", "decision"}
                <= {r["record_type"] for r in records_for(records, tid)}]
        assert len(full) >= 2
        assert transaction_ids(records)[:2] == full[:2]

    def test_fixture_chain_verifies_with_the_published_formula(self):
        """The fixture was hashed by GOPEL itself; the formula in the spec
        must reproduce every content_hash and chain_hash."""
        assert verify_chain(fixture_records()) == []


# ===========================================================================
# Step 13: every record parses or raises VALIDATION_ERROR (defect tests)
# ===========================================================================

class TestEveryRecordParsesOrAlerts:

    def test_every_fixture_record_parses_or_raises_validation_alert(self):
        """No record may be dropped silently (v2.4 gopel_observer.py:304-308)."""
        observer, _pipeline, messages = _observer()
        silent = []
        for rec in fixture_records():
            errors_before = observer.get_statistics()["validation_errors"]
            alerts_before = len(alerts(messages))
            observer.observe_jsonl(json.dumps(rec))
            errored = observer.get_statistics()["validation_errors"] > errors_before
            alerted = len(alerts(messages)) > alerts_before
            if errored and not alerted:
                silent.append((rec["sequence_number"], rec["record_type"], rec["record_id"]))
        assert silent == [], f"{len(silent)} GOPEL records dropped without an alert: {silent[:9]}"

    def test_untampered_fixture_parses_with_zero_alerts(self):
        observer, _pipeline, messages = _observer()
        for rec in fixture_records():
            observer.observe_jsonl(json.dumps(rec))
        stats = observer.get_statistics()
        assert alerts(messages) == []
        assert stats["validation_errors"] == 0
        assert stats["records_observed"] == len(fixture_records())
        assert stats["records_parsed"] == len(fixture_records())

    def test_audit_document_parses_with_zero_alerts(self):
        observer, _pipeline, messages = _observe_document(audit_document())
        assert alerts(messages) == []
        assert observer.get_statistics()["records_parsed"] == len(fixture_records())

    def test_unexpected_error_raises_alert_not_only_a_counter(self):
        """The broad except branch must alert too (v2.4 counted only)."""
        observer, _pipeline, messages = _observer()
        broken = GopelRecord(
            kind=None, transaction_id="txn-broken", timestamp=time.time(),
            payload={}, prev_hash="", this_hash="",
        )
        observer.observe(broken)
        assert observer.get_statistics()["validation_errors"] == 1
        found = alerts(messages)
        assert len(found) == 1
        assert found[0].payload["transaction_id"] == "txn-broken"

    @pytest.mark.parametrize("mutate, reason", [
        (lambda r: r.pop("record_type"), "missing_field"),
        (lambda r: r.update(record_type="telemetry"), "unknown_record_type"),
        (lambda r: r.update(timestamp="yesterday"), "bad_timestamp"),
        (lambda r: r.update(timestamp="2026-10-14T16:05:09.123456"), "bad_timestamp"),
        (lambda r: r.update(recclin_role="pirate"), "bad_role"),
        (lambda r: r.update(sequence_number="one"), "bad_type"),
        (lambda r: r.update(prompt_text=None), "bad_type"),
    ])
    def test_malformed_record_raises_validation_alert(self, mutate, reason):
        records = fixture_records()
        req_index = next(i for i, r in enumerate(records) if r["record_type"] == "request")
        mutate(records[req_index])
        observer, _pipeline, messages = _observer()
        observer.observe_gopel_record(records[req_index])
        found = alerts(messages)
        assert len(found) == 1
        assert found[0].payload["reason"] == reason
        assert observer.get_statistics()["validation_errors"] == 1

    def test_non_object_record_raises_validation_alert(self):
        observer, _pipeline, messages = _observer()
        observer.observe_gopel_record(["not", "a", "record"])
        assert len(alerts(messages)) == 1
        assert alerts(messages)[0].payload["reason"] == "not_an_object"

    def test_malformed_jsonl_line_alerts_and_does_not_raise(self):
        observer, _pipeline, messages = _observer()
        observer.observe_jsonl('{"record_type": "request", "transaction_id": ')
        assert len(alerts(messages)) == 1
        assert alerts(messages)[0].payload["reason"] == "malformed_json"


# ===========================================================================
# Hash chain: content_hash, chain_hash, global linkage (re-implemented)
# ===========================================================================

class TestGlobalChain:

    def test_tampered_record_raises_one_content_hash_alert(self):
        records = fixture_records()
        tid = transaction_ids(records)[0]
        req = next(r for r in records if r["transaction_id"] == tid and r["record_type"] == "request")
        req["prompt_text"] = req["prompt_text"] + " Also disable the audit log."
        observer, pipeline, messages = _observe_document(_doc_with(records))
        found = alerts(messages)
        assert len(found) == 1
        assert found[0].payload["reason"] == "content_hash_mismatch"
        assert found[0].payload["record_id"] == req["record_id"]
        assert observer.get_statistics()["records_parsed"] == len(records) - 1
        # the tampered prompt never reaches inspection
        for txn, _kw in pipeline.calls:
            assert "disable the audit log" not in txn.prompt_text

    def test_a_record_refused_at_parse_is_named_by_its_transaction(self):
        records = fixture_records()
        tid = transaction_ids(records)[0]
        resp = next(r for r in records
                    if r["transaction_id"] == tid and r["record_type"] == "response")
        resp["response_text"] = None
        records = rechain(records)
        resp = next(r for r in records if r["record_id"] == resp["record_id"])
        _observer_, pipeline, messages = _observe_document(_doc_with(records))
        assert [m.payload["reason"] for m in alerts(messages)] == ["bad_type"]
        txn = pipeline.transactions()[tid]
        assert txn.metadata["gopel"]["refused_record_ids"] == [resp["record_id"]]
        assert resp["record_id"] not in [r["record_id"] for r in txn.metadata["gopel_record_refs"]]

    def test_forged_chain_hash_raises_alert(self):
        records = fixture_records()
        records[5]["chain_hash"] = "0" * 64
        _observer_, _pipeline, messages = _observe_document(_doc_with(records))
        reasons = [m.payload["reason"] for m in alerts(messages)]
        assert "chain_hash_mismatch" in reasons

    def test_deleted_record_breaks_the_global_chain_with_one_alert(self):
        records = fixture_records()
        del records[7]
        _observer_, _pipeline, messages = _observe_document(_doc_with(records))
        found = alerts(messages)
        assert len(found) == 1
        assert found[0].payload["reason"] in ("previous_hash_mismatch", "sequence_mismatch")
        assert found[0].payload["record_id"] == records[7]["record_id"]

    def test_chain_is_global_across_transactions(self):
        """Each record links to the previous record in the FILE, not the
        previous record of its own transaction."""
        records = fixture_records()
        tids = transaction_ids(records)
        # Swap two whole transactions' first records: links break.
        first_a = next(i for i, r in enumerate(records) if r["transaction_id"] == tids[0])
        first_b = next(i for i, r in enumerate(records) if r["transaction_id"] == tids[1])
        records[first_a], records[first_b] = records[first_b], records[first_a]
        _observer_, _pipeline, messages = _observe_document(_doc_with(records))
        assert len(alerts(messages)) >= 1

    def test_rereading_a_grown_document_observes_only_new_records(self):
        records = fixture_records()
        observer, pipeline, messages = _observer()
        observer.observe_audit_document(_doc_with(records[:20]))
        observer.observe_audit_document(_doc_with(records))
        assert alerts(messages) == []
        assert observer.get_statistics()["records_parsed"] == len(records)
        assert len(pipeline.calls) == len(expected_finalized(records))

    def test_rewritten_history_on_reread_raises_alert(self):
        records = fixture_records()
        observer, _pipeline, messages = _observer()
        observer.observe_audit_document(_doc_with(records[:20]))
        rewritten = copy.deepcopy(records)
        rewritten[19]["chain_hash"] = "f" * 64
        observer.observe_audit_document(_doc_with(rewritten))
        reasons = [m.payload["reason"] for m in alerts(messages)]
        assert "history_rewritten" in reasons


# ===========================================================================
# Assembly: lists per kind, finalization rules, role mapping
# ===========================================================================

class TestAssembly:

    def test_finalized_transactions_reach_inspection_once(self):
        records = fixture_records()
        _observer_, pipeline, _messages = _observe_document(audit_document())
        inspected = [t.transaction_id for t, _ in pipeline.calls]
        assert inspected == expected_finalized(records)

    def test_assembled_transaction_carries_the_gopel_fields(self):
        records = fixture_records()
        _observer_, pipeline, _messages = _observe_document(audit_document())
        txns = pipeline.transactions()
        for tid in expected_finalized(records):
            mine = records_for(records, tid)
            req = next(r for r in mine if r["record_type"] == "request")
            disp = [r for r in mine if r["record_type"] == "dispatch"]
            resp = [r for r in mine if r["record_type"] == "response"]
            nav = [r for r in mine if r["record_type"] == "navigation"]
            txn = txns[tid]
            assert txn.prompt_text == req["prompt_text"]
            assert txn.operator_id == req["operator_id"]
            assert txn.recclin_role == RECCLINRole[req["recclin_role"].upper()]
            assert txn.platforms_dispatched == [d["platform_id"] for d in disp]
            assert txn.prompt_hash == disp[0]["prompt_hash"]
            assert [r.platform_id for r in txn.responses] == [r["platform_id"] for r in resp]
            assert [r.response_text for r in txn.responses] == [r["response_text"] for r in resp]
            if nav:
                assert txn.navigator_output == nav[-1]["full_synthesis_text"]
            assert txn.metadata["gopel_record_refs"] == refs_for(records, tid)

    def test_lists_per_kind_keep_every_dispatch_and_response(self):
        records = fixture_records()
        _observer_, pipeline, _messages = _observe_document(audit_document())
        most = 0
        for tid, txn in pipeline.transactions().items():
            mine = records_for(records, tid)
            n_disp = sum(1 for r in mine if r["record_type"] == "dispatch")
            n_resp = sum(1 for r in mine if r["record_type"] == "response")
            most = max(most, n_disp)
            assert len(txn.platforms_dispatched) == n_disp
            assert len(txn.responses) == n_resp
        assert most > 1, "a v2.4 buffer kept one record per kind"

    def test_inspect_receives_gopel_record_refs(self):
        records = fixture_records()
        _observer_, pipeline, _messages = _observe_document(audit_document())
        for tid in expected_finalized(records):
            assert pipeline.kwargs_for(tid)["gopel_record_refs"] == refs_for(records, tid)

    def test_roles_map_case_insensitively(self):
        records = fixture_records()
        req = next(r for r in records if r["record_type"] == "request")
        if req["recclin_role"].lower() == "researcher":
            req["recclin_role"] = "coder"   # exercise a role other than the legacy default
        roles = {r["transaction_id"]: r["recclin_role"] for r in records if r["record_type"] == "request"}
        req["recclin_role"] = "".join(
            c.upper() if i % 2 else c.lower() for i, c in enumerate(req["recclin_role"])
        )
        expected = RECCLINRole[req["recclin_role"].upper()]
        records = rechain(records)
        _observer_, pipeline, messages = _observe_document(_doc_with(records))
        assert alerts(messages) == []
        txn = pipeline.transactions()[req["transaction_id"]]
        assert txn.recclin_role == expected
        for tid, role in roles.items():
            if tid in pipeline.transactions() and tid != req["transaction_id"]:
                assert pipeline.transactions()[tid].recclin_role == RECCLINRole[role.upper()]

    def test_system_records_without_a_transaction_parse_and_are_kept(self):
        records = fixture_records()
        n_system = sum(1 for r in records if r["record_type"] == "system")
        observer, pipeline, messages = _observe_document(audit_document())
        assert alerts(messages) == []
        assert observer.get_statistics()["system_records_observed"] == n_system
        assert "system" not in [t.transaction_id for t, _ in pipeline.calls]
        assert "system" not in observer._buffers


# ===========================================================================
# v0.6.3 additions (spec section 3): the translator accepts them
# ===========================================================================

GENERATION_SETTINGS = {
    "model": "alpha-model",
    "max_tokens": 4096,
    "temperature": None,
    "temperature_source": "provider_default",
}


class TestV063Additions:

    def test_null_generation_settings_are_accepted(self):
        records = fixture_records()
        tid = transaction_ids(records)[0]
        for r in records:
            if r["transaction_id"] == tid and r["record_type"] in ("dispatch", "response"):
                r["generation_settings"] = None
        _observer_, pipeline, messages = _observe_document(_doc_with(rechain(records)))
        assert alerts(messages) == []
        txn = pipeline.transactions()[tid]
        assert all(d["generation_settings"] is None for d in txn.metadata["gopel"]["dispatches"])
        assert all("generation_settings" not in r.metadata for r in txn.responses)

    def test_fixture_generation_settings_are_carried_when_present(self):
        records = fixture_records()
        _observer_, pipeline, messages = _observe_document(audit_document())
        assert alerts(messages) == []
        for tid, txn in pipeline.transactions().items():
            stored = [r.get("generation_settings") for r in records_for(records, tid)
                      if r["record_type"] == "dispatch"]
            carried = [d["generation_settings"] for d in txn.metadata["gopel"]["dispatches"]]
            assert carried == stored

    def test_generation_settings_on_dispatch_and_response_are_carried(self):
        records = fixture_records()
        tid = transaction_ids(records)[0]
        for r in records:
            if r["transaction_id"] == tid and r["record_type"] in ("dispatch", "response"):
                r["generation_settings"] = dict(GENERATION_SETTINGS)
        records = rechain(records)
        _observer_, pipeline, messages = _observe_document(_doc_with(records))
        assert alerts(messages) == []
        txn = pipeline.transactions()[tid]
        for resp in txn.responses:
            assert resp.metadata["generation_settings"] == GENERATION_SETTINGS
        for disp in txn.metadata["gopel"]["dispatches"]:
            assert disp["generation_settings"] == GENERATION_SETTINGS

    def test_operator_set_temperature_is_carried(self):
        records = fixture_records()
        tid = transaction_ids(records)[0]
        gs = {"model": "alpha-model", "max_tokens": 1024, "temperature": 0.2,
              "temperature_source": "operator"}
        for r in records:
            if r["transaction_id"] == tid and r["record_type"] == "dispatch":
                r["generation_settings"] = dict(gs)
        _observer_, pipeline, messages = _observe_document(_doc_with(rechain(records)))
        assert alerts(messages) == []
        assert pipeline.transactions()[tid].metadata["gopel"]["dispatches"][0]["generation_settings"] == gs

    @pytest.mark.parametrize("bad", [
        {"model": "m", "max_tokens": 10, "temperature": None, "temperature_source": "guess"},
        {"model": "m", "max_tokens": "ten", "temperature": None, "temperature_source": "operator"},
        {"model": "m", "max_tokens": 10, "temperature": "hot", "temperature_source": "operator"},
        {"max_tokens": 10, "temperature": None, "temperature_source": "operator"},
        {"model": "m", "max_tokens": 10, "temperature": None, "temperature_source": "operator",
         "seed": 7},
        "not-an-object",
    ])
    def test_malformed_generation_settings_alert(self, bad):
        records = fixture_records()
        idx = next(i for i, r in enumerate(records) if r["record_type"] == "dispatch")
        records[idx]["generation_settings"] = bad
        records = rechain(records)
        _observer_, _pipeline, messages = _observe_document(_doc_with(records))
        found = alerts(messages)
        assert len(found) == 1
        assert found[0].payload["reason"] == "bad_generation_settings"

    @pytest.mark.parametrize("value", ["accept", "modify", "reject"])
    def test_v063_decision_values_parse(self, value):
        records = fixture_records()
        arb = next(r for r in records if r["record_type"] == "arbitration")
        arb["arbitration_decision"] = value
        records = rechain(records)
        _observer_, pipeline, messages = _observe_document(_doc_with(records))
        assert alerts(messages) == []
        txn = pipeline.transactions()[arb["transaction_id"]]
        assert txn.metadata["gopel"]["arbitration"]["decision"] == value

    def test_unknown_decision_value_alerts(self):
        records = fixture_records()
        arb = next(r for r in records if r["record_type"] == "arbitration")
        arb["arbitration_decision"] = "maybe"
        _observer_, _pipeline, messages = _observe_document(_doc_with(rechain(records)))
        assert [m.payload["reason"] for m in alerts(messages)] == ["bad_decision"]

    def test_stored_approve_verifies_reads_as_accept_and_stays_unchanged(self):
        records = fixture_records()
        arb = next(r for r in records if r["record_type"] == "arbitration")
        arb["arbitration_decision"] = "approve"
        records = rechain(records)
        pristine = copy.deepcopy(records)
        arb = next(r for r in records if r["record_type"] == "arbitration")

        record = GopelRecord.from_gopel_dict(arb)
        assert record.payload["arbitration_decision"] == "approve"
        assert record.recompute_content_hash() == arb["content_hash"]
        assert record.stored_record() == pristine[records.index(arb)]

        _observer_, pipeline, messages = _observe_document(_doc_with(records))
        assert alerts(messages) == []
        view = pipeline.transactions()[arb["transaction_id"]].metadata["gopel"]["arbitration"]
        assert view["decision"] == "accept"
        assert view["decision_as_stored"] == "approve"
        assert records == pristine, "the observer must never rewrite stored records"

    def test_tampered_approve_fails_before_it_is_mapped(self):
        records = fixture_records()
        arb = next(r for r in records if r["record_type"] == "arbitration")
        arb["arbitration_decision"] = "approve"
        records = rechain(records)
        arb = next(r for r in records if r["record_type"] == "arbitration")
        arb["rationale"] = "rewritten after the fact"
        _observer_, pipeline, messages = _observe_document(_doc_with(records))
        found = alerts(messages)
        assert [m.payload["reason"] for m in found] == ["content_hash_mismatch"]
        txn = pipeline.transactions()[arb["transaction_id"]]
        assert txn.metadata["gopel"].get("arbitration") is None
        assert arb["record_id"] in txn.metadata["gopel"]["refused_record_ids"]

    @pytest.mark.parametrize("event_type", ["overwatch_stop", "pipeline_halted", "total_dispatch_failure"])
    def test_system_record_with_real_transaction_id_finalizes(self, event_type):
        records = fixture_records()
        tid = transaction_ids(records)[1]
        # The transaction stops before arbitration: drop its arbitration and decision.
        records = [r for r in records
                   if not (r["transaction_id"] == tid and r["record_type"] in ("arbitration", "decision"))]
        records.append(system_record(tid, event_type))
        records = rechain(records)
        _observer_, pipeline, messages = _observe_document(_doc_with(records))
        assert alerts(messages) == []
        assert tid in pipeline.transactions()
        txn = pipeline.transactions()[tid]
        assert txn.metadata["gopel"]["finalized_by"] == f"system:{event_type}"
        assert [e["event_type"] for e in txn.metadata["gopel"]["system_events"]] == [event_type]

    def test_non_finalizing_system_record_with_transaction_id_is_kept(self):
        records = fixture_records()
        tid = transaction_ids(records)[0]
        decision_idx = next(i for i, r in enumerate(records)
                            if r["transaction_id"] == tid and r["record_type"] == "decision")
        records.insert(decision_idx, system_record(tid, "injection_detection", "warning"))
        records = rechain(records)
        _observer_, pipeline, messages = _observe_document(_doc_with(records))
        assert alerts(messages) == []
        txn = pipeline.transactions()[tid]
        assert txn.metadata["gopel"]["finalized_by"] == "decision"
        assert [e["event_type"] for e in txn.metadata["gopel"]["system_events"]] == ["injection_detection"]

    def test_upstream_record_ids_are_carried(self):
        records = fixture_records()
        tid = transaction_ids(records)[0]
        dec = next(r for r in records if r["transaction_id"] == tid and r["record_type"] == "decision")
        dec["upstream_record_ids"] = [r["record_id"] for r in records
                                      if r["transaction_id"] == tid and r is not dec]
        records = rechain(records)
        _observer_, pipeline, messages = _observe_document(_doc_with(records))
        assert alerts(messages) == []
        view = pipeline.transactions()[tid].metadata["gopel"]["decision"]
        assert view["upstream_record_ids"] == dec["upstream_record_ids"]


# ===========================================================================
# The frozen interface changes in a versioned way
# ===========================================================================

class TestVersionedRecordInterface:

    def test_gopel_format_record_is_frozen_and_versioned(self):
        rec = next(r for r in fixture_records() if r["record_type"] == "request")
        record = GopelRecord.from_gopel_dict(rec)
        assert record.record_format == "gopel.audit.v1"
        assert record.kind == GopelRecordKind.REQUEST
        assert record.record_id == rec["record_id"]
        assert record.sequence_number == rec["sequence_number"]
        assert record.this_hash == rec["chain_hash"]
        assert record.prev_hash == rec["previous_hash"]
        with pytest.raises(dataclasses.FrozenInstanceError):
            record.transaction_id = "changed"

    def test_legacy_record_format_still_works(self):
        record = GopelRecord(
            kind=GopelRecordKind.REQUEST, transaction_id="txn-legacy",
            timestamp=1000.0, payload={"prompt_text": "x"}, prev_hash="", this_hash="",
        )
        assert record.record_format == "overwatch.legacy.v1"
        assert len(record.recompute_hash()) == 64

    def test_from_jsonl_line_reads_both_formats(self):
        rec = next(r for r in fixture_records() if r["record_type"] == "request")
        record = GopelRecord.from_jsonl_line(json.dumps(rec))
        assert record.record_format == "gopel.audit.v1"
        legacy = GopelRecord.from_jsonl_line(json.dumps({
            "kind": "REQUEST", "transaction_id": "t", "timestamp": 1.0,
            "payload": {}, "prev_hash": "", "this_hash": "",
        }))
        assert legacy.record_format == "overwatch.legacy.v1"

    def test_system_kind_exists(self):
        assert GopelRecordKind.SYSTEM.value == "SYSTEM"


# ===========================================================================
# GOPEL v0.6.3 stop-protocol system events (canonical JSON details)
# ===========================================================================

class TestStopProtocolSystemEvents:

    def _with_events(self, events, tid="system"):
        records = fixture_records()
        for event_type, detail in events:
            rec = system_record(tid, event_type, "warning")
            if detail is not None:
                rec["event_detail"] = detail
            records.append(rec)
        return rechain(records)

    @pytest.mark.parametrize("event_type", STOP_EVENT_TYPES)
    def test_canonical_detail_parses(self, event_type):
        records = self._with_events([(event_type, None)])
        observer, _pipeline, messages = _observe_document(_doc_with(records))
        assert alerts(messages) == []
        last = observer.get_system_records()[-1]
        assert last["event_type"] == event_type
        assert last["detail"] == json.loads(records[-1]["event_detail"])

    @pytest.mark.parametrize("event_type", STOP_EVENT_TYPES)
    @pytest.mark.parametrize("detail", [
        "Transaction t: plain text",
        '{"a": 1}',
        "[1, 2]",
        '{"line_sha256":"x"}',
    ])
    def test_malformed_detail_raises_validation_alert(self, event_type, detail):
        records = self._with_events([(event_type, detail)])
        _observer_, _pipeline, messages = _observe_document(_doc_with(records))
        assert [m.payload["reason"] for m in alerts(messages)] == ["bad_event_detail"]

    def test_non_canonical_detail_is_refused(self):
        obj = json.loads(stop_event_detail("overwatch_stop_rejected"))
        spaced = json.dumps(obj, sort_keys=True)           # ", " and ": " separators
        assert spaced != canonical(obj)
        records = self._with_events([("overwatch_stop_rejected", spaced)])
        _observer_, _pipeline, messages = _observe_document(_doc_with(records))
        assert [m.payload["reason"] for m in alerts(messages)] == ["bad_event_detail"]

    def test_extra_key_in_an_exact_detail_is_refused(self):
        obj = json.loads(stop_event_detail("overwatch_stop"))
        obj["note"] = "extra"
        records = self._with_events([("overwatch_stop", canonical(obj))])
        _observer_, _pipeline, messages = _observe_document(_doc_with(records))
        assert [m.payload["reason"] for m in alerts(messages)] == ["bad_event_detail"]

    def test_rejected_stop_line_and_channel_reset_are_routed_to_human(self):
        records = self._with_events([("overwatch_stop_rejected", None),
                                     ("overwatch_channel_reset", None)])
        _observer_, _pipeline, messages = _observe_document(_doc_with(records))
        assert alerts(messages) == []
        kinds = [m.kind for m in messages]
        assert kinds.count("STOP_LINE_REJECTED_BY_GOPEL") >= 1
        assert kinds.count("STOP_CHANNEL_RESET") >= 1

    def test_fixture_stop_events_parse_when_present(self):
        records = fixture_records()
        present = [r for r in records if r["record_type"] == "system"
                   and r["event_type"] in STOP_EVENT_TYPES]
        observer, _pipeline, messages = _observe_document(audit_document())
        assert alerts(messages) == []
        parsed = [e for e in observer.get_system_records() if e["event_type"] in STOP_EVENT_TYPES]
        assert len(parsed) == len(present)
        assert all(isinstance(e["detail"], dict) for e in parsed)

    def test_a_system_record_written_before_the_request_joins_its_transaction(self):
        records = fixture_records()
        tid = transaction_ids(records)[0]
        req_index = next(i for i, r in enumerate(records)
                         if r["transaction_id"] == tid and r["record_type"] == "request")
        records.insert(req_index, system_record(tid, "overwatch_channel_reset", "warning"))
        records = rechain(records)
        _observer_, pipeline, messages = _observe_document(_doc_with(records))
        assert alerts(messages) == []
        txn = pipeline.transactions()[tid]
        assert txn.metadata["gopel_record_refs"] == refs_for(records, tid)
        assert [e["event_type"] for e in txn.metadata["gopel"]["system_events"]] == \
            ["overwatch_channel_reset"]

    def test_a_transaction_stopped_before_its_request_is_not_finalized(self):
        records = fixture_records()
        records.append(system_record("txn-stopped-at-start", "overwatch_stop"))
        records.append(system_record("txn-stopped-at-start", "overwatch_stop_rejected", "warning"))
        observer, pipeline, messages = _observe_document(_doc_with(rechain(records)))
        assert alerts(messages) == []
        assert "txn-stopped-at-start" not in pipeline.transactions()
        assert "txn-stopped-at-start" not in observer._buffers
