"""
HAIA-Overwatch v2.5 - Tests: receipt fields and the versioned observer view

Plan step 14b, settlement S9.

- The Gate 3 test (receipt fields visible to the observer) keeps the
  strict expected-failure marker until Overwatch v2.6 versions the
  receipt fields in. It is counted separately and is not a defect test.
- Negative cases: fields that are not versioned into the observer stay
  invisible to inspection, while the hash chain still covers them.

GOPEL records come only from the committed fixture. Nothing here imports
GOPEL.

Author: Basil C. Puglisi, MPA
License: CC BY-NC 4.0
Repository: github.com/basilpuglisi/HAIA
Attribution: #AIassisted under HAIA-RECCLIN & Checkpoint-Based Governance
"""

import json
import time

import pytest

from overwatch_v27.gopel_observer import (
    GopelObserver, GopelRecord, GopelRecordKind, assemble_transaction,
)
from overwatch_v27.models import OverwatchConfig
from overwatch_v27.tests.gopel_fixture_support_v25 import (
    RecordingPipeline,
    alerts,
    audit_document,
    channel_with_sink,
    fixture_records,
    rechain,
    transaction_ids,
)

# A Gate 3 response receipt as Part F and Part C rule 7 describe it: the
# dispatch record ID and the V7 hashes, with PQ v1.2 section 4 signature
# metadata. Field names are this test's expectation for v2.6.
RECEIPT = {
    "receipt_id": "rcpt-gate3-test-0001",
    "dispatch_record_id": "",
    "dispatch_hash": "",
    "response_hash": "",
    "signature_algorithm": "Ed25519",
    "signature": "00" * 64,
    "public_key_id": "gopel-tier-a-test-key",
    "canonicalization_version": "haia.canonical.v1",
    "hash_algorithm": "SHA-256",
}


def _records_with_receipts():
    records = fixture_records()
    tid = transaction_ids(records)[0]
    dispatches = [r for r in records if r["transaction_id"] == tid and r["record_type"] == "dispatch"]
    responses = [r for r in records if r["transaction_id"] == tid and r["record_type"] == "response"]
    for disp, resp in zip(dispatches, responses):
        receipt = dict(RECEIPT)
        receipt["dispatch_record_id"] = disp["record_id"]
        receipt["dispatch_hash"] = disp["prompt_hash"]
        receipt["response_hash"] = resp["response_hash"]
        resp["response_receipt"] = receipt
        resp["future_field_x"] = "not versioned in v2.5"
    return tid, rechain(records)


def _observe(records):
    cm, messages = channel_with_sink()
    pipeline = RecordingPipeline()
    observer = GopelObserver(
        pipeline, channel_manager=cm,
        config=OverwatchConfig(require_structural_inputs=False),
    )
    doc = audit_document()
    doc["records"] = records
    observer.observe_audit_document(doc)
    return observer, pipeline, messages


@pytest.mark.xfail(strict=True, reason="Gate 3 receipt fields")
def test_gate3_receipt_fields_are_visible_to_the_observer():
    tid, records = _records_with_receipts()
    _observer, pipeline, messages = _observe(records)
    assert alerts(messages) == []
    txn = pipeline.transactions()[tid]
    for resp in txn.responses:
        receipt = resp.metadata["response_receipt"]
        assert receipt["signature_algorithm"] == "Ed25519"
        assert receipt["dispatch_record_id"]


class TestUnversionedFieldsStayInvisible:

    def test_unversioned_gopel_fields_parse_but_stay_invisible(self):
        tid, records = _records_with_receipts()
        _observer, pipeline, messages = _observe(records)
        assert alerts(messages) == [], "unversioned fields must not make a valid record fail"
        txn = pipeline.transactions()[tid]
        seen = json.dumps(
            {"metadata": txn.metadata,
             "responses": [r.metadata for r in txn.responses]},
            default=str,
        )
        assert "response_receipt" not in seen
        assert "future_field_x" not in seen
        assert "rcpt-gate3-test-0001" not in seen

    def test_unversioned_fields_are_not_in_the_record_view(self):
        _tid, records = _records_with_receipts()
        resp = next(r for r in records if "response_receipt" in r)
        record = GopelRecord.from_gopel_dict(resp)
        assert "response_receipt" not in record.payload
        assert "future_field_x" not in record.payload
        # ...but the stored record still holds them, unchanged.
        assert record.stored_record()["response_receipt"] == resp["response_receipt"]

    def test_unversioned_fields_are_still_covered_by_the_hash_chain(self):
        _tid, records = _records_with_receipts()
        resp = next(r for r in records if "response_receipt" in r)
        resp["response_receipt"]["signature"] = "ff" * 64
        _observer, _pipeline, messages = _observe(records)
        assert [m.payload["reason"] for m in alerts(messages)] == ["content_hash_mismatch"]

    def test_legacy_payload_fields_outside_the_view_stay_invisible(self):
        request = GopelRecord(
            kind=GopelRecordKind.REQUEST, transaction_id="txn-legacy-receipt",
            timestamp=time.time(),
            payload={"operator_id": "op", "recclin_role": "RESEARCHER",
                     "prompt_hash": "h", "prompt_text": "p", "provenance_tags": []},
            prev_hash="", this_hash="req",
        )
        response = GopelRecord(
            kind=GopelRecordKind.RESPONSE, transaction_id="txn-legacy-receipt",
            timestamp=time.time(),
            payload={"platform_id": "p1", "response_text": "r", "response_hash": "rh",
                     "response_time_ms": 1.0, "response_receipt": dict(RECEIPT)},
            prev_hash="req", this_hash="resp",
        )
        txn = assemble_transaction({
            GopelRecordKind.REQUEST: request,
            GopelRecordKind.RESPONSE: response,
        })
        assert "response_receipt" not in txn.responses[0].metadata
        assert "response_receipt" not in json.dumps(txn.metadata, default=str)
