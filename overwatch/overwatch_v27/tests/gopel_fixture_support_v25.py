"""
HAIA-Overwatch v2.5 - Test support for GOPEL fixtures

Shared helpers for the v2.5 tests that read GOPEL audit records. GOPEL
records come ONLY from the committed JSON fixtures in tests/fixtures/.
Nothing here imports GOPEL (isolation invariant, paper section 4.3).

The hash helpers below re-implement GOPEL's published formulas (Gate 1
shared spec, section 3) independently of the observer module, so the
tests can build derived records (v0.6.3 additions, tampering) without
trusting the code under test.

Author: Basil C. Puglisi, MPA
License: CC BY-NC 4.0
Repository: github.com/basilpuglisi/HAIA
Attribution: #AIassisted under HAIA-RECCLIN & Checkpoint-Based Governance
"""

import copy
import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from overwatch_v27.models import VerificationOutcome

# ---------------------------------------------------------------------------
# Declared expectations (step 14f): the GOPEL release and audit schema that
# the v2.5 tests are written against.
# ---------------------------------------------------------------------------
EXPECTED_GOPEL_VERSION = "0.6.5"
EXPECTED_AUDIT_SCHEMA_VERSION = "1.0.0"

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"
FIXTURE_NAME = "gopel_v065_mock_audit_v1.json"
FIXTURE_SCHEMA = "haia.overwatch.gopel_fixture.v1"
# What every fixture's top-level "provenance" object must carry. GOPEL's
# audit file has no GOPEL version string, so the version a test expects is
# read from here. The commit may be named "main_commit" or "source_commit".
REQUIRED_PROVENANCE_KEYS = ("gopel_version", "command")
COMMIT_KEYS = ("main_commit", "source_commit")

RECORD_TYPES = (
    "request", "dispatch", "response", "navigation",
    "arbitration", "decision", "system",
)
FINALIZING_SYSTEM_EVENTS = ("overwatch_stop", "pipeline_halted", "total_dispatch_failure",
                            "channel_group_closed")  # v2.6: GOPEL v0.6.4 channel groups
HASH_EXCLUDED = (
    "content_hash", "previous_hash", "chain_hash",
    "sequence_number", "operator_signature",
)

CHANNEL_KEY = b"overwatch-alert-channel-key-test-0001"


# ---------------------------------------------------------------------------
# Fixture access
# ---------------------------------------------------------------------------

def load_fixture(name: str = FIXTURE_NAME) -> Dict[str, Any]:
    """Return a fresh copy of a committed fixture."""
    with open(FIXTURE_DIR / name, "r", encoding="utf-8") as f:
        return json.load(f)


def fixture_records(name: str = FIXTURE_NAME) -> List[Dict[str, Any]]:
    return load_fixture(name)["records"]


def declared_gopel_version(fixture: Optional[Dict[str, Any]] = None) -> str:
    """The GOPEL version the fixture declares (its provenance block)."""
    fixture = fixture if fixture is not None else load_fixture()
    return fixture["provenance"]["gopel_version"]


def audit_document(fixture: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """The GOPEL audit file content inside a fixture: {schema, records}."""
    fixture = fixture if fixture is not None else load_fixture()
    return {"schema": copy.deepcopy(fixture["schema"]),
            "records": copy.deepcopy(fixture["records"])}


def transaction_ids(records: List[Dict[str, Any]]) -> List[str]:
    seen: List[str] = []
    for r in records:
        tid = r["transaction_id"]
        if tid != "system" and tid not in seen:
            seen.append(tid)
    return seen


def records_for(records: List[Dict[str, Any]], tid: str) -> List[Dict[str, Any]]:
    return [r for r in records if r["transaction_id"] == tid]


def expected_finalized(records: List[Dict[str, Any]]) -> List[str]:
    """Transactions the observer must finalize (shared spec section 3):
    a DECISION record, or a SYSTEM record whose event_type finalizes and
    whose transaction_id names a transaction with a REQUEST record."""
    out: List[str] = []
    with_request = {r["transaction_id"] for r in records if r["record_type"] == "request"}
    for r in records:
        tid = r["transaction_id"]
        if tid in out:
            continue
        if r["record_type"] == "decision":
            out.append(tid)
        elif (r["record_type"] == "system"
              and r.get("event_type") in FINALIZING_SYSTEM_EVENTS
              and tid in with_request):
            out.append(tid)
    return out


def refs_for(records: List[Dict[str, Any]], tid: str) -> List[Dict[str, str]]:
    return [
        {"record_id": r["record_id"], "chain_hash": r["chain_hash"]}
        for r in sorted(records_for(records, tid), key=lambda x: x["sequence_number"])
    ]


# ---------------------------------------------------------------------------
# Independent re-implementation of GOPEL's hash formulas (spec section 3)
# ---------------------------------------------------------------------------

def content_hash(record: Dict[str, Any]) -> str:
    content = {k: v for k, v in record.items() if k not in HASH_EXCLUDED}
    return hashlib.sha256(
        json.dumps(content, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()


def chain_hash(content: str, previous: str) -> str:
    return hashlib.sha256(f"{content}{previous}".encode("utf-8")).hexdigest()


def rechain(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Recompute sequence numbers and hashes for a derived record list,
    exactly as GOPEL's logger finalizes records (genesis first)."""
    out = []
    previous = "genesis"
    for i, rec in enumerate(copy.deepcopy(records), start=1):
        rec["sequence_number"] = i
        rec["previous_hash"] = previous
        rec["content_hash"] = content_hash(rec)
        rec["chain_hash"] = chain_hash(rec["content_hash"], previous)
        previous = rec["chain_hash"]
        out.append(rec)
    return out


def verify_chain(records: List[Dict[str, Any]]) -> List[str]:
    """Return a list of problems (empty if the chain verifies)."""
    problems = []
    previous = "genesis"
    for i, rec in enumerate(records, start=1):
        if rec.get("sequence_number") != i:
            problems.append(f"seq {rec.get('sequence_number')} != {i}")
        if rec.get("previous_hash") != previous:
            problems.append(f"previous_hash at {i}")
        if rec.get("content_hash") != content_hash(rec):
            problems.append(f"content_hash at {i}")
        if rec.get("chain_hash") != chain_hash(rec.get("content_hash", ""), rec.get("previous_hash", "")):
            problems.append(f"chain_hash at {i}")
        previous = rec.get("chain_hash")
    return problems


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def stop_body(transaction_id: str = "", event_id: Optional[str] = None) -> Dict[str, Any]:
    return {
        "schema_version": "haia.overwatch.stop.v1",
        "event_id": event_id or uuid.uuid4().hex,
        "issued_at": "2026-10-14T16:05:09.123Z",
        "key_id": "overwatch-stop-key-test",
        "target_pipeline": "gopel-test-instance",
        "transaction_id": transaction_id,
        "trigger": "CRITICAL",
        "finding_ids": ["f-1"],
        "gopel_record_refs": [],
    }


def stop_event_detail(event_type: str, transaction_id: str = "") -> str:
    """Canonical JSON event_detail, as GOPEL v0.6.3 writes it for the
    stop-protocol system events."""
    line_sha = hashlib.sha256(b"line").hexdigest()
    if event_type == "overwatch_stop":
        return canonical({"body": stop_body(transaction_id), "line_sha256": line_sha,
                          "mac": "a" * 64, "received_at": "2026-10-14T16:05:10.000Z"})
    if event_type == "overwatch_stop_rejected":
        return canonical({"line_sha256": line_sha, "reason": "bad_mac",
                          "received_at": "2026-10-14T16:05:10.000Z"})
    if event_type == "overwatch_stop_released":
        return canonical({"release_id": uuid.uuid4().hex, "cleared": [uuid.uuid4().hex],
                          "operator_id": "gov_officer_mark", "evidence_ids": ["e1"],
                          "released_at": "2026-10-14T16:06:00.000Z", "binding_id": "b",
                          "gate_passed": True, "evidence": []})
    if event_type == "overwatch_channel_reset":
        return canonical({"channel_bytes": 0, "previous_offset": 120,
                          "received_at": "2026-10-14T16:07:00.000Z"})
    raise KeyError(event_type)


STOP_EVENT_TYPES = ("overwatch_stop", "overwatch_stop_rejected",
                    "overwatch_stop_released", "overwatch_channel_reset")


def system_record(tid: str, event_type: str, severity: str = "critical",
                  detail: str = "") -> Dict[str, Any]:
    """A v0.6.3-shaped GOPEL system record (hashes filled by rechain).
    Stop-protocol events get a canonical JSON detail unless one is given."""
    if not detail and event_type in STOP_EVENT_TYPES:
        detail = stop_event_detail(event_type, tid)
    return {
        "record_id": str(uuid.uuid4()),
        "transaction_id": tid,
        "record_type": "system",
        "timestamp": iso_now(),
        "operator_id": "system",
        "sequence_number": 0,
        "content_hash": "",
        "previous_hash": "",
        "chain_hash": "",
        "event_type": event_type,
        "event_detail": detail or f"Transaction {tid}: {event_type}",
        "severity": severity,
    }


# ---------------------------------------------------------------------------
# Duck-typed collaborators
# ---------------------------------------------------------------------------

class RecordingPipeline:
    """Stands in for OverwatchPipeline: records every inspect() call."""

    def __init__(self) -> None:
        self.calls: List[Any] = []

    def inspect(self, transaction, **kwargs):
        self.calls.append((transaction, kwargs))
        return VerificationOutcome(transaction_id=transaction.transaction_id)

    def transactions(self) -> Dict[str, Any]:
        return {t.transaction_id: t for t, _ in self.calls}

    def kwargs_for(self, tid: str) -> Dict[str, Any]:
        for t, kw in self.calls:
            if t.transaction_id == tid:
                return kw
        raise KeyError(tid)


def channel_with_sink():
    """A real IndependentChannelManager plus the list its transport fills."""
    from overwatch_v27.channel_manager import IndependentChannelManager
    messages: List[Any] = []
    cm = IndependentChannelManager(CHANNEL_KEY)
    cm.register_transport(messages.append)
    return cm, messages


def alerts(messages: List[Any], kind: str = "VALIDATION_ERROR") -> List[Any]:
    return [m for m in messages if m.kind == kind]


def require(obj: Any, what: str) -> Any:
    """Fail (never skip) when a v2.5 capability is absent from the build."""
    if obj is None:
        pytest.fail(f"missing in this build: {what}")
    return obj
