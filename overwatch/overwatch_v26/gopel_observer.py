"""
HAIA-Overwatch v2.6 - GOPEL Observer

Read-only integration layer for GOPEL transaction records.
Buffers records by transaction_id, validates SHA-256 chain, and forwards
assembled TransactionRecords to the inspection pipeline.

v2.5 reads GOPEL's own audit record dicts through a versioned translation
(GOPEL_AUDIT_TRANSLATION_VERSION): lowercase record_type, ISO 8601
timestamps, flat fields, and one global hash chain whose content_hash and
chain_hash formulas are re-implemented here, never imported. Every record
either parses and validates, or raises a VALIDATION_ERROR alert on the
channel; no error is only counted. The legacy Overwatch-format record
path is kept unchanged for existing callers.

The observer NEVER writes back into GOPEL.

Author: Basil C. Puglisi, MPA
License: CC BY-NC 4.0
Repository: github.com/basilpuglisi/HAIA
Attribution: #AIassisted under HAIA-RECCLIN & Checkpoint-Based Governance
"""

import copy
import hashlib
import json
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Deque, Dict, List, Mapping, Optional, Tuple

from .channel_manager import IndependentChannelManager
from .models import OverwatchConfig, StructuralInputs, TransactionRecord, VerificationOutcome
from .structured_logger import get_logger, sanitize_log_value as _sanitize_log

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Record formats and the versioned GOPEL translation
# ---------------------------------------------------------------------------

LEGACY_RECORD_FORMAT = "overwatch.legacy.v1"
GOPEL_RECORD_FORMAT = "gopel.audit.v1"
GOPEL_AUDIT_TRANSLATION_VERSION = "gopel-audit-translation-v1"

# Fields excluded from GOPEL's content_hash (Gate 1 shared spec, section 3).
_HASH_EXCLUDED = (
    "content_hash", "previous_hash", "chain_hash",
    "sequence_number", "operator_signature",
)
_GENESIS = "genesis"

# System events that finalize the transaction they name (spec section 3).
FINALIZING_SYSTEM_EVENTS = frozenset({
    "overwatch_stop", "pipeline_halted", "total_dispatch_failure",
    # v2.6: GOPEL v0.6.4 closes each channel group and each routed
    # Navigator turn with this record, so every agent call is inspected.
    "channel_group_closed",
})

# Arbitration decisions GOPEL v0.6.3 writes, plus the legacy "approve",
# which readers map to "accept" for reading only, after the stored
# record's hashes verify.
_DECISIONS = frozenset({"accept", "modify", "reject"})
_LEGACY_DECISIONS = {"approve": "accept"}
_TEMPERATURE_SOURCES = frozenset({"operator", "provider_default"})
_GENERATION_SETTINGS_KEYS = frozenset({"model", "max_tokens", "temperature", "temperature_source"})

# GOPEL v0.6.3 stop-protocol system events carry canonical JSON in
# event_detail. (required keys, exact): with exact=True no other key is
# allowed. Every other event_type keeps a plain-text detail.
_SYSTEM_DETAIL_SCHEMAS: Dict[str, Tuple[frozenset, bool]] = {
    "overwatch_stop": (frozenset({"body", "line_sha256", "mac", "received_at"}), True),
    "overwatch_stop_rejected": (frozenset({"line_sha256", "reason", "received_at"}), True),
    "overwatch_stop_released": (
        frozenset({"release_id", "cleared", "operator_id", "evidence_ids", "released_at"}), False),
    "overwatch_channel_reset": (
        frozenset({"channel_bytes", "previous_offset", "received_at"}), False),
    # v2.6: GOPEL v0.6.4 channel (Team Gate)
    "channel_group_closed": (
        frozenset({"caller_id", "kind", "reason", "response_record_ids"}), True),
}


class GopelRecordKind(Enum):
    """Record types in GOPEL's transaction audit trail."""
    REQUEST = "REQUEST"
    DISPATCH = "DISPATCH"
    RESPONSE = "RESPONSE"
    NAVIGATION = "NAVIGATION"
    ARBITRATION = "ARBITRATION"
    DECISION = "DECISION"
    ESCALATION_TRIGGER = "ESCALATION_TRIGGER"
    SYSTEM = "SYSTEM"


_GOPEL_RECORD_TYPES = {
    "request": GopelRecordKind.REQUEST,
    "dispatch": GopelRecordKind.DISPATCH,
    "response": GopelRecordKind.RESPONSE,
    "navigation": GopelRecordKind.NAVIGATION,
    "arbitration": GopelRecordKind.ARBITRATION,
    "decision": GopelRecordKind.DECISION,
    "system": GopelRecordKind.SYSTEM,
}

_BASE_REQUIRED = (
    "record_id", "transaction_id", "record_type", "timestamp", "operator_id",
    "sequence_number", "content_hash", "previous_hash", "chain_hash",
)

# Translation v1: the fields Overwatch reads, per kind. Each entry is
# (validator, required, default). Fields not listed here are not versioned
# into the observer: they stay in the stored record (and under the hash
# chain) but are invisible to inspection.
_STR, _BOOL, _NUM, _INT = "str", "bool", "num", "int"
_STR_LIST, _ROLE, _DECISION, _GEN = "str_list", "role", "decision", "generation_settings"

_FIELDS_V1: Dict[GopelRecordKind, Dict[str, Tuple[str, bool, Any]]] = {
    GopelRecordKind.REQUEST: {
        "prompt_text": (_STR, True, ""),
        "recclin_role": (_ROLE, True, ""),
        "operating_model": (_STR, True, ""),
        "task_scope": (_STR, False, ""),
        "success_criteria": (_STR, False, ""),
        "platform_selections": (_STR_LIST, False, []),
        "anchor_platform": (_STR, False, ""),
        # v2.6: GOPEL v0.6.4 channel Request records
        "caller_id": (_STR, False, ""),
        "image_sha256": (_STR_LIST, False, []),
        "authority_ref": (_STR, False, ""),
    },
    GopelRecordKind.DISPATCH: {
        "platform_id": (_STR, True, ""),
        "platform_model": (_STR, False, ""),
        "prompt_hash": (_STR, True, ""),
        "is_anchor": (_BOOL, False, False),
        "dispatch_status": (_STR, False, "sent"),
        "api_confirmation": (_STR, False, ""),
        "generation_settings": (_GEN, False, None),
    },
    GopelRecordKind.RESPONSE: {
        "platform_id": (_STR, True, ""),
        "platform_model": (_STR, False, ""),
        "response_text": (_STR, True, ""),
        "response_hash": (_STR, False, ""),
        "response_status": (_STR, False, "received"),
        "token_count": (_INT, False, 0),
        "latency_ms": (_NUM, False, 0),
        "error_detail": (_STR, False, ""),
        "generation_settings": (_GEN, False, None),
    },
    GopelRecordKind.NAVIGATION: {
        "navigator_platform": (_STR, True, ""),
        "convergence_summary": (_STR, False, ""),
        "divergence_summary": (_STR, False, ""),
        "dissent_records": (_STR_LIST, False, []),
        "sources_cited": (_STR_LIST, False, []),
        "conflicts_identified": (_STR_LIST, False, []),
        "confidence_score": (_NUM, False, 0),
        "confidence_justification": (_STR, False, ""),
        "recommendation": (_STR, False, ""),
        "expiry_note": (_STR, False, ""),
        "response_record_ids": (_STR_LIST, False, []),
        "full_synthesis_text": (_STR, False, ""),
    },
    GopelRecordKind.ARBITRATION: {
        "arbitration_decision": (_DECISION, True, ""),
        "rationale": (_STR, True, ""),
        "modifications": (_STR, False, ""),
        "checkpoint_role": (_ROLE, True, ""),
        "navigation_record_id": (_STR, False, ""),
    },
    GopelRecordKind.DECISION: {
        "final_output": (_STR, True, ""),
        "output_hash": (_STR, False, ""),
        "upstream_record_ids": (_STR_LIST, False, []),
        "is_final": (_BOOL, False, False),
    },
    GopelRecordKind.SYSTEM: {
        "event_type": (_STR, True, ""),
        "event_detail": (_STR, True, ""),
        "severity": (_STR, False, "info"),
    },
}


class GopelRecordError(ValueError):
    """A GOPEL record that does not parse under the versioned translation."""

    def __init__(self, reason: str, message: str, record: Any = None):
        super().__init__(message)
        self.reason = reason
        self.record_id = ""
        self.transaction_id = ""
        self.sequence_number: Optional[int] = None
        if isinstance(record, Mapping):
            rid = record.get("record_id")
            tid = record.get("transaction_id")
            seq = record.get("sequence_number")
            self.record_id = rid if isinstance(rid, str) else ""
            self.transaction_id = tid if isinstance(tid, str) else ""
            self.sequence_number = seq if _is_int(seq) else None


@dataclass(frozen=True)
class GopelSchemaExpectation:
    """The GOPEL release and audit schema an observer is configured to read.

    The observer refuses, with a VALIDATION_ERROR alert per record, any
    audit document whose schema header (schema.schema_version, which GOPEL
    writes) does not match audit_schema_version, and any document whose
    declared source GOPEL version does not match gopel_version. GOPEL's
    audit file carries no GOPEL version string, so the version is declared
    by the caller (for example from a fixture's provenance) or taken from
    the signed deployment manifest's gopel_version.
    """
    gopel_version: str = "0.6.4"     # v2.6: GOPEL v0.6.4, the channel
    audit_schema_version: str = "1.0.0"

    def to_dict(self) -> Dict[str, str]:
        return {"gopel_version": self.gopel_version,
                "audit_schema_version": self.audit_schema_version}


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_num(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _norm_version(value: Any) -> str:
    text = str(value).strip()
    return text[1:] if text[:1] in ("v", "V") else text


def _parse_iso_timestamp(value: Any, record: Mapping) -> float:
    if not isinstance(value, str):
        raise GopelRecordError("bad_timestamp", "timestamp must be an ISO 8601 string", record)
    text = value.strip()
    if text.endswith("Z") or text.endswith("z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        raise GopelRecordError("bad_timestamp", f"timestamp is not ISO 8601: {value!r}", record)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise GopelRecordError("bad_timestamp", f"timestamp has no UTC offset: {value!r}", record)
    return parsed.timestamp()


def _map_role(value: Any) -> Any:
    """Map a GOPEL role name to the Overwatch RECCLINRole, case-insensitively."""
    from .models import RECCLINRole
    if not isinstance(value, str):
        return None
    try:
        return RECCLINRole[value.strip().upper()]
    except KeyError:
        return None


def _reject_non_finite(value: str) -> Any:
    raise ValueError(f"non-finite number {value} is not valid here")


def _parse_system_detail(event_type: str, detail: str, record: Mapping) -> Dict[str, Any]:
    """Parse the canonical JSON event_detail of a stop-protocol event."""
    keys, exact = _SYSTEM_DETAIL_SCHEMAS[event_type]
    try:
        parsed = json.loads(detail, parse_constant=_reject_non_finite)
    except ValueError as e:
        raise GopelRecordError("bad_event_detail", f"{event_type} detail is not JSON: {e}", record)
    if not isinstance(parsed, dict):
        raise GopelRecordError("bad_event_detail", f"{event_type} detail must be a JSON object", record)
    canonical = json.dumps(parsed, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    if canonical != detail:
        raise GopelRecordError("bad_event_detail", f"{event_type} detail is not canonical JSON", record)
    present = set(parsed)
    if not keys <= present or (exact and present != keys):
        raise GopelRecordError(
            "bad_event_detail",
            f"{event_type} detail keys {sorted(present)} do not match {sorted(keys)}", record)
    if event_type == "overwatch_stop":
        body = parsed["body"]
        if not isinstance(body, dict) or not isinstance(body.get("event_id"), str):
            raise GopelRecordError("bad_event_detail", "overwatch_stop body lacks an event_id", record)
    if event_type == "overwatch_stop_released":
        if not isinstance(parsed["cleared"], list) or not all(isinstance(i, str) for i in parsed["cleared"]):
            raise GopelRecordError("bad_event_detail", "overwatch_stop_released cleared must list event IDs", record)
    return parsed


def _validate_generation_settings(value: Any, record: Mapping) -> Dict[str, Any]:
    if not isinstance(value, Mapping):
        raise GopelRecordError("bad_generation_settings", "generation_settings must be an object", record)
    if set(value) != _GENERATION_SETTINGS_KEYS:
        raise GopelRecordError(
            "bad_generation_settings",
            f"generation_settings keys {sorted(value)} do not match {sorted(_GENERATION_SETTINGS_KEYS)}",
            record,
        )
    model = value.get("model")
    max_tokens = value.get("max_tokens")
    temperature = value.get("temperature", "absent")
    source = value.get("temperature_source")
    if (not isinstance(model, str) or not _is_int(max_tokens)
            or not (temperature is None or _is_num(temperature))
            or source not in _TEMPERATURE_SOURCES):
        raise GopelRecordError(
            "bad_generation_settings",
            "generation_settings needs model (str), max_tokens (int), temperature "
            "(number or null) and temperature_source (operator or provider_default)",
            record,
        )
    return {"model": model, "max_tokens": max_tokens,
            "temperature": temperature, "temperature_source": source}


def _validate_field(name: str, kind: str, value: Any, record: Mapping) -> Any:
    if kind == _STR:
        if not isinstance(value, str):
            raise GopelRecordError("bad_type", f"{name} must be a string", record)
        return value
    if kind == _BOOL:
        if not isinstance(value, bool):
            raise GopelRecordError("bad_type", f"{name} must be a boolean", record)
        return value
    if kind == _INT:
        if not _is_int(value):
            raise GopelRecordError("bad_type", f"{name} must be an integer", record)
        return value
    if kind == _NUM:
        if not _is_num(value):
            raise GopelRecordError("bad_type", f"{name} must be a number", record)
        return value
    if kind == _STR_LIST:
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise GopelRecordError("bad_type", f"{name} must be a list of strings", record)
        return list(value)
    if kind == _ROLE:
        if _map_role(value) is None:
            raise GopelRecordError("bad_role", f"{name} is not a RECCLIN role: {value!r}", record)
        return value
    if kind == _DECISION:
        if not isinstance(value, str) or (value not in _DECISIONS and value not in _LEGACY_DECISIONS):
            raise GopelRecordError("bad_decision", f"{name} is not accept, modify or reject: {value!r}", record)
        return value
    if kind == _GEN:
        if value is None:
            return None
        return _validate_generation_settings(value, record)
    raise GopelRecordError("bad_type", f"no validator for {name}", record)


# ---------------------------------------------------------------------------
# GopelRecord (frozen; versioned interface)
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class GopelRecord:
    """Immutable GOPEL audit record from the transaction chain.

    Fields:
        kind: GopelRecordKind
        transaction_id: Transaction identifier
        timestamp: Unix timestamp
        payload: Record content (for GOPEL-format records: the fields
            versioned into the observer, values exactly as stored)
        prev_hash: SHA-256 hash of previous record in chain
        this_hash: SHA-256 hash of this record (GOPEL: chain_hash)
        signature: Optional signature for authentication
            (GOPEL: operator_signature; not verified by Overwatch)

    v2.5 additions (all defaulted, so the legacy constructor is unchanged):
        record_format: LEGACY_RECORD_FORMAT or GOPEL_RECORD_FORMAT
        record_id: GOPEL record_id
        sequence_number: position in GOPEL's global chain
        content_hash: GOPEL content_hash as stored
        raw_json: the stored GOPEL record, serialized; the hash chain is
            recomputed from it, and it is never rewritten
    """
    kind: GopelRecordKind
    transaction_id: str
    timestamp: float
    payload: Dict[str, Any]
    prev_hash: str
    this_hash: str
    signature: Optional[str] = None
    record_format: str = LEGACY_RECORD_FORMAT
    record_id: str = ""
    sequence_number: int = 0
    content_hash: str = ""
    raw_json: str = ""

    @classmethod
    def from_jsonl_line(cls, line: str) -> "GopelRecord":
        """Deserialize a GOPEL record from JSONL format.

        Accepts both the legacy Overwatch format ("kind", "payload",
        "prev_hash", "this_hash") and GOPEL's own audit record format
        ("record_type" and flat fields).

        Raises:
            ValueError: If JSON is malformed or fields are missing
        """
        data = json.loads(line)
        if isinstance(data, Mapping) and "record_type" in data and "kind" not in data:
            return cls.from_gopel_dict(data)
        kind_str = data.get("kind")
        kind = GopelRecordKind[kind_str] if isinstance(kind_str, str) else kind_str

        return cls(
            kind=kind,
            transaction_id=data["transaction_id"],
            timestamp=data["timestamp"],
            payload=data.get("payload", {}),
            prev_hash=data.get("prev_hash", ""),
            this_hash=data.get("this_hash", ""),
            signature=data.get("signature")
        )

    @classmethod
    def from_gopel_dict(cls, record: Any) -> "GopelRecord":
        """Translate one GOPEL audit record dict (translation v1).

        Parses and type-checks; it does not verify hashes (the observer
        does that). The stored record is kept, serialized, in raw_json.

        Raises:
            GopelRecordError: with .reason naming what failed
        """
        if not isinstance(record, Mapping):
            raise GopelRecordError("not_an_object", "GOPEL record must be a JSON object", record)
        missing = [f for f in _BASE_REQUIRED if f not in record]
        if missing:
            raise GopelRecordError("missing_field", f"missing base fields: {missing}", record)
        rtype = record["record_type"]
        if not isinstance(rtype, str) or rtype not in _GOPEL_RECORD_TYPES:
            raise GopelRecordError("unknown_record_type", f"unknown record_type: {rtype!r}", record)
        kind = _GOPEL_RECORD_TYPES[rtype]

        for name in ("record_id", "transaction_id", "operator_id"):
            if not isinstance(record[name], str) or not record[name]:
                raise GopelRecordError("bad_type", f"{name} must be a non-empty string", record)
        for name in ("content_hash", "previous_hash", "chain_hash"):
            if not isinstance(record[name], str):
                raise GopelRecordError("bad_type", f"{name} must be a string", record)
        seq = record["sequence_number"]
        if not _is_int(seq) or seq < 1:
            raise GopelRecordError("bad_type", "sequence_number must be a positive integer", record)
        timestamp = _parse_iso_timestamp(record["timestamp"], record)
        signature = record.get("operator_signature")
        if signature is not None and not isinstance(signature, str):
            raise GopelRecordError("bad_type", "operator_signature must be a string", record)

        payload: Dict[str, Any] = {}
        for name, (validator, required, default) in _FIELDS_V1[kind].items():
            if name not in record:
                if required:
                    raise GopelRecordError("missing_field", f"{rtype} record lacks {name}", record)
                payload[name] = copy.deepcopy(default)
                continue
            payload[name] = _validate_field(name, validator, record[name], record)

        if kind == GopelRecordKind.SYSTEM and payload["event_type"] in _SYSTEM_DETAIL_SCHEMAS:
            # Derived view of the canonical JSON detail; event_detail stays as stored.
            payload["event_detail_object"] = _parse_system_detail(
                payload["event_type"], payload["event_detail"], record)

        try:
            raw_json = json.dumps(dict(record), sort_keys=True)
        except (TypeError, ValueError) as e:
            raise GopelRecordError("not_json", f"record is not JSON-serializable: {e}", record)

        return cls(
            kind=kind,
            transaction_id=record["transaction_id"],
            timestamp=timestamp,
            payload=payload,
            prev_hash=record["previous_hash"],
            this_hash=record["chain_hash"],
            signature=signature,
            record_format=GOPEL_RECORD_FORMAT,
            record_id=record["record_id"],
            sequence_number=seq,
            content_hash=record["content_hash"],
            raw_json=raw_json,
        )

    @property
    def is_gopel_format(self) -> bool:
        return self.record_format == GOPEL_RECORD_FORMAT

    def stored_record(self) -> Dict[str, Any]:
        """A copy of the stored GOPEL record (GOPEL format only)."""
        return json.loads(self.raw_json) if self.raw_json else {}

    def canonical_bytes(self) -> bytes:
        """Return canonical bytes of record for chain hashing.

        Legacy format: the Overwatch canonical form. GOPEL format: the
        exact serialization GOPEL hashes into content_hash.

        Returns:
            JSON-encoded bytes for hashing
        """
        if self.is_gopel_format:
            stored = self.stored_record()
            content = {k: v for k, v in stored.items() if k not in _HASH_EXCLUDED}
            return json.dumps(content, sort_keys=True, default=str).encode("utf-8")
        canonical = json.dumps({
            "kind": self.kind.value,
            "transaction_id": self.transaction_id,
            "timestamp": self.timestamp,
            "payload": self.payload,
            "prev_hash": self.prev_hash
        }, sort_keys=True, default=str)
        return canonical.encode()

    def recompute_content_hash(self) -> str:
        """SHA-256 of the record content (GOPEL content_hash formula)."""
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def recompute_hash(self) -> str:
        """Recompute SHA-256 hash of this record.

        Legacy format: hash of the canonical bytes. GOPEL format: the
        chain hash, SHA-256(recomputed content_hash + previous_hash).

        Returns:
            Hex-encoded SHA-256 hash
        """
        if self.is_gopel_format:
            return _chain_hash(self.recompute_content_hash(), self.prev_hash)
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def hash_problem(self) -> Optional[Tuple[str, str]]:
        """Check this GOPEL-format record's own hashes.

        Returns (reason, message) for the first problem, or None.
        """
        recomputed = self.recompute_content_hash()
        if recomputed != self.content_hash:
            return ("content_hash_mismatch",
                    f"content_hash {self.content_hash} does not match recomputed {recomputed}")
        expected_chain = _chain_hash(self.content_hash, self.prev_hash)
        if expected_chain != self.this_hash:
            return ("chain_hash_mismatch",
                    f"chain_hash {self.this_hash} does not match recomputed {expected_chain}")
        return None


def _chain_hash(content_hash: str, previous_hash: str) -> str:
    return hashlib.sha256(f"{content_hash}{previous_hash}".encode("utf-8")).hexdigest()


class ChainValidationError(Exception):
    """Raised when GOPEL chain validation fails."""
    pass


def validate_chain(records: List[GopelRecord]) -> None:
    """Walk SHA-256 chain and validate hashes.

    Legacy records link per transaction (prev_hash to the previous
    this_hash). GOPEL-format records form one global chain: each record's
    hashes verify, previous_hash equals the previous chain_hash ("genesis"
    for sequence 1), and sequence_number increases by one.

    Args:
        records: Ordered list of records to validate

    Raises:
        ChainValidationError: If any hash doesn't match previous record's hash
    """
    for i, record in enumerate(records):
        if record.is_gopel_format:
            problem = record.hash_problem()
            if problem:
                raise ChainValidationError(f"Record {i} {problem[0]}: {problem[1]}")
            if i == 0:
                if record.sequence_number == 1 and record.prev_hash != _GENESIS:
                    raise ChainValidationError("Record 0 previous_hash is not genesis")
            else:
                prev_record = records[i - 1]
                if record.prev_hash != prev_record.this_hash:
                    raise ChainValidationError(
                        f"Record {i} previous_hash mismatch: "
                        f"expected {prev_record.this_hash}, got {record.prev_hash}"
                    )
                if record.sequence_number != prev_record.sequence_number + 1:
                    raise ChainValidationError(
                        f"Record {i} sequence_number {record.sequence_number} does not "
                        f"follow {prev_record.sequence_number}"
                    )
            continue

        # Recompute hash for this record
        expected_hash = record.recompute_hash()
        if expected_hash != record.this_hash:
            raise ChainValidationError(
                f"Record {i} this_hash mismatch: "
                f"expected {expected_hash}, got {record.this_hash}"
            )

        # Check prev_hash matches previous record
        if i > 0:
            prev_record = records[i - 1]
            if prev_record.this_hash != record.prev_hash:
                raise ChainValidationError(
                    f"Record {i} prev_hash mismatch: "
                    f"expected {prev_record.this_hash}, got {record.prev_hash}"
                )


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------

def _as_list(value: Any) -> List[GopelRecord]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def gopel_record_refs(records: Mapping[GopelRecordKind, Any]) -> List[Dict[str, str]]:
    """Sources for a stop (M2): record_id and chain_hash of every
    GOPEL-format record of a transaction, in chain order."""
    flat = [r for v in records.values() for r in _as_list(v)
            if getattr(r, "is_gopel_format", False)]
    flat.sort(key=lambda r: r.sequence_number)
    return [{"record_id": r.record_id, "chain_hash": r.this_hash} for r in flat]


def assemble_transaction(records: Dict[GopelRecordKind, Any]) -> TransactionRecord:
    """Fold GOPEL records into a single TransactionRecord.

    Deep-copies all payloads to prevent mutation. Each kind may map to one
    record or to a list of records (v2.5 keeps a list per kind).

    Args:
        records: Dict mapping GopelRecordKind to GopelRecord or list of them

    Returns:
        Assembled TransactionRecord

    Raises:
        ValueError: If required records are missing
    """
    flat = [r for v in records.values() for r in _as_list(v)]
    if any(getattr(r, "is_gopel_format", False) for r in flat):
        return _assemble_gopel(records)
    return _assemble_legacy(records)


def _assemble_legacy(records: Dict[GopelRecordKind, Any]) -> TransactionRecord:
    """The v2.4 Overwatch-format assembly, unchanged except that each kind
    may hold a list."""
    from .models import PlatformResponse, RECCLINRole

    requests = _as_list(records.get(GopelRecordKind.REQUEST))
    decisions = _as_list(records.get(GopelRecordKind.DECISION))
    request_rec = requests[0] if requests else None
    decision_rec = decisions[0] if decisions else None

    if not request_rec and not decision_rec:
        raise ValueError("Missing REQUEST or DECISION record")

    primary = request_rec or decision_rec
    transaction_id = primary.transaction_id

    platforms: List[Any] = []
    for dispatch_rec in _as_list(records.get(GopelRecordKind.DISPATCH)):
        platforms.extend(copy.deepcopy(dispatch_rec.payload.get("platforms", [])))

    responses = []
    for resp_rec in _as_list(records.get(GopelRecordKind.RESPONSE)):
        resp_payload = copy.deepcopy(resp_rec.payload)
        responses.append(
            PlatformResponse(
                platform_id=resp_payload.get("platform_id", ""),
                response_text=resp_payload.get("response_text", ""),
                response_hash=resp_payload.get("response_hash", ""),
                response_time_ms=resp_payload.get("response_time_ms", 0.0),
                confidence_score=resp_payload.get("confidence_score"),
                metadata=copy.deepcopy(resp_payload.get("metadata", {}))
            )
        )

    navs = _as_list(records.get(GopelRecordKind.NAVIGATION))
    nav_rec = navs[-1] if navs else None

    request_payload = copy.deepcopy(request_rec.payload if request_rec else {})
    recclin_role_str = request_payload.get("recclin_role", "RESEARCHER")
    try:
        recclin_role = RECCLINRole[recclin_role_str]
    except (KeyError, TypeError):
        recclin_role = RECCLINRole.RESEARCHER

    return TransactionRecord(
        transaction_id=transaction_id,
        timestamp=primary.timestamp,
        operator_id=request_payload.get("operator_id", ""),
        recclin_role=recclin_role,
        prompt_hash=request_payload.get("prompt_hash", ""),
        prompt_text=request_payload.get("prompt_text", ""),
        platforms_dispatched=platforms,
        responses=responses,
        navigator_input=copy.deepcopy(nav_rec.payload.get("input")) if nav_rec else None,
        navigator_output=copy.deepcopy(nav_rec.payload.get("output")) if nav_rec else None,
        provenance_tags=request_payload.get("provenance_tags", []),
        gopel_breach_report=request_payload.get("gopel_breach_report"),
        metadata=copy.deepcopy(request_payload.get("metadata", {}))
    )


def _assemble_gopel(records: Dict[GopelRecordKind, Any]) -> TransactionRecord:
    """Assemble a TransactionRecord from GOPEL-format records
    (translation v1). Every record here has already verified."""
    from .models import PlatformResponse, RECCLINRole

    def kind_list(kind: GopelRecordKind) -> List[GopelRecord]:
        return sorted(_as_list(records.get(kind)), key=lambda r: r.sequence_number)

    requests = kind_list(GopelRecordKind.REQUEST)
    decisions = kind_list(GopelRecordKind.DECISION)
    if not requests and not decisions:
        raise ValueError("Missing REQUEST or DECISION record")
    primary = requests[0] if requests else decisions[0]

    req = copy.deepcopy(requests[0].payload) if requests else {}
    role = _map_role(req.get("recclin_role")) or RECCLINRole.RESEARCHER

    dispatches = kind_list(GopelRecordKind.DISPATCH)
    responses = kind_list(GopelRecordKind.RESPONSE)
    navigations = kind_list(GopelRecordKind.NAVIGATION)
    arbitrations = kind_list(GopelRecordKind.ARBITRATION)
    systems = kind_list(GopelRecordKind.SYSTEM)

    prompt_text = req.get("prompt_text", "")
    if dispatches:
        prompt_hash = dispatches[0].payload.get("prompt_hash", "")
    else:
        prompt_hash = hashlib.sha256(prompt_text.encode("utf-8")).hexdigest()

    platform_responses = []
    for r in responses:
        p = copy.deepcopy(r.payload)
        meta = {
            "gopel_record_id": r.record_id,
            "platform_model": p.get("platform_model", ""),
            "response_status": p.get("response_status", ""),
            "token_count": p.get("token_count", 0),
            "error_detail": p.get("error_detail", ""),
        }
        if p.get("generation_settings") is not None:
            meta["generation_settings"] = p["generation_settings"]
        platform_responses.append(PlatformResponse(
            platform_id=p.get("platform_id", ""),
            response_text=p.get("response_text", ""),
            response_hash=p.get("response_hash", ""),
            response_time_ms=float(p.get("latency_ms", 0) or 0),
            confidence_score=None,
            metadata=meta,
        ))

    nav = navigations[-1] if navigations else None
    gopel: Dict[str, Any] = {
        "translation": GOPEL_AUDIT_TRANSLATION_VERSION,
        "request": {
            "record_id": requests[0].record_id if requests else "",
            "operating_model": req.get("operating_model", ""),
            "task_scope": req.get("task_scope", ""),
            "success_criteria": req.get("success_criteria", ""),
            "platform_selections": req.get("platform_selections", []),
            "anchor_platform": req.get("anchor_platform", ""),
            "recclin_role_as_stored": req.get("recclin_role", ""),
            "caller_id": req.get("caller_id", ""),
            "image_sha256": list(req.get("image_sha256", []) or []),
            "authority_ref": req.get("authority_ref", ""),
        },
        "dispatches": [
            {
                "record_id": d.record_id,
                "platform_id": d.payload.get("platform_id", ""),
                "platform_model": d.payload.get("platform_model", ""),
                "prompt_hash": d.payload.get("prompt_hash", ""),
                "is_anchor": d.payload.get("is_anchor", False),
                "dispatch_status": d.payload.get("dispatch_status", ""),
                "api_confirmation": d.payload.get("api_confirmation", ""),
                "generation_settings": copy.deepcopy(d.payload.get("generation_settings")),
            }
            for d in dispatches
        ],
        "navigation": (
            {
                "record_id": nav.record_id,
                "navigator_platform": nav.payload.get("navigator_platform", ""),
                "confidence_score": nav.payload.get("confidence_score", 0),
                "response_record_ids": list(nav.payload.get("response_record_ids", [])),
            } if nav else None
        ),
        "arbitration": None,
        "decision": None,
        "system_events": [
            {
                "record_id": s.record_id,
                "event_type": s.payload.get("event_type", ""),
                "severity": s.payload.get("severity", ""),
                "event_detail": s.payload.get("event_detail", ""),
                "detail": copy.deepcopy(s.payload.get("event_detail_object")),
            }
            for s in systems
        ],
    }
    if arbitrations:
        a = arbitrations[-1]
        stored = a.payload.get("arbitration_decision", "")
        checkpoint_role = _map_role(a.payload.get("checkpoint_role"))
        gopel["arbitration"] = {
            "record_id": a.record_id,
            # Legacy "approve" reads as "accept"; the stored record is not rewritten.
            "decision": _LEGACY_DECISIONS.get(stored, stored),
            "decision_as_stored": stored,
            "rationale": a.payload.get("rationale", ""),
            "modifications": a.payload.get("modifications", ""),
            "checkpoint_role": checkpoint_role.value if checkpoint_role else "",
            "navigation_record_id": a.payload.get("navigation_record_id", ""),
        }
    if decisions:
        d = decisions[-1]
        gopel["decision"] = {
            "record_id": d.record_id,
            "final_output": d.payload.get("final_output", ""),
            "output_hash": d.payload.get("output_hash", ""),
            "upstream_record_ids": list(d.payload.get("upstream_record_ids", [])),
            "is_final": d.payload.get("is_final", False),
        }

    return TransactionRecord(
        transaction_id=primary.transaction_id,
        timestamp=primary.timestamp,
        operator_id=(requests[0] if requests else primary).stored_record().get("operator_id", ""),
        recclin_role=role,
        prompt_hash=prompt_hash,
        prompt_text=prompt_text,
        platforms_dispatched=[d.payload.get("platform_id", "") for d in dispatches],
        responses=platform_responses,
        navigator_input=None,
        navigator_output=nav.payload.get("full_synthesis_text", "") if nav else None,
        provenance_tags=[],
        gopel_breach_report=None,
        metadata={
            "gopel": gopel,
            "gopel_record_refs": gopel_record_refs(records),
        },
    )


# ---------------------------------------------------------------------------
# Observer
# ---------------------------------------------------------------------------

class GopelObserver:
    """Buffers GOPEL records, validates chain, and finalizes transactions.

    Observes individual records, buffers by transaction_id, validates the
    SHA-256 chain step-by-step, and finalizes complete transactions to the
    inspection pipeline.

    v2.5: GOPEL-format records are validated against GOPEL's global chain
    (content_hash, chain_hash, previous_hash, sequence_number). Every
    record parses and validates or raises VALIDATION_ERROR. A transaction
    finalizes on a DECISION record, or on a SYSTEM record whose event_type
    is overwatch_stop, pipeline_halted or total_dispatch_failure for that
    transaction. When structural inputs are configured, they are passed
    into pipeline.inspect() with the transaction's GOPEL record refs.
    """

    MAX_ALERT_HISTORY = 1000
    MAX_SYSTEM_RECORDS = 1000
    MAX_REFUSED_TRACKED = 10000
    MAX_PENDING_SYSTEM = 1000

    def __init__(
        self,
        pipeline: Any,
        channel_manager: Optional[IndependentChannelManager] = None,
        config: Optional[OverwatchConfig] = None,
        ttl_seconds: float = 3600.0,
        require_chain_validation: bool = True,
        schema_expectation: Optional[GopelSchemaExpectation] = None,
        structural_inputs: Optional[StructuralInputs] = None,
    ):
        """Initialize GopelObserver.

        Args:
            pipeline: The inspection pipeline to forward finalized transactions
            channel_manager: Optional channel for alerts
            config: Optional Overwatch configuration
            ttl_seconds: Time-to-live for buffered transactions
            require_chain_validation: Whether to validate SHA-256 chain
            schema_expectation: GOPEL release and audit schema to accept
            structural_inputs: GOPEL directory, deployment manifest and
                active GOPEL config passed into inspect() (step 21)
        """
        self.pipeline = pipeline
        self.channel_manager = channel_manager
        self.config = config or OverwatchConfig()
        self.ttl_seconds = ttl_seconds
        self.require_chain_validation = require_chain_validation
        self.schema_expectation = schema_expectation or GopelSchemaExpectation()
        self.structural_inputs = structural_inputs

        self._lock = threading.RLock()
        self._buffers: Dict[str, Dict[GopelRecordKind, List[GopelRecord]]] = {}
        self._timestamps: Dict[str, float] = {}
        self._last_legacy_hash: Dict[str, str] = {}
        self._refused: Dict[str, List[str]] = {}
        self._pending_system: Dict[str, Tuple[float, List[GopelRecord]]] = {}
        self._gopel_head: Optional[Tuple[int, str]] = None
        self._version_undeclared_noted = False
        self._system_records: Deque[Dict[str, Any]] = deque(maxlen=self.MAX_SYSTEM_RECORDS)
        self._alerts: Deque[Dict[str, Any]] = deque(maxlen=self.MAX_ALERT_HISTORY)
        self._statistics = {
            "records_observed": 0,
            "records_parsed": 0,
            "transactions_finalized": 0,
            "stale_flushed": 0,
            "validation_errors": 0,
            "schema_refusals": 0,
            "system_records_observed": 0,
            "alerts_emitted": 0,
        }

    # -------------------------------------------------------------------
    # Entry points
    # -------------------------------------------------------------------

    def observe(self, record: GopelRecord) -> Optional[VerificationOutcome]:
        """Buffer a single GOPEL record and finalize transaction if complete.

        Validates chain step, buffers record, and finalizes on DECISION record.
        Thread-safe: all buffer access is protected by RLock.

        Args:
            record: GopelRecord to observe

        Returns:
            VerificationOutcome if transaction was finalized, None otherwise
        """
        if getattr(record, "is_gopel_format", False):
            with self._lock:
                self._statistics["records_observed"] += 1
                return self._observe_gopel(record)
        return self._observe_legacy(record)

    def observe_jsonl(self, line: str) -> Optional[VerificationOutcome]:
        """Convenience method to observe from JSONL line.

        Reads both formats. A line that does not parse raises a
        VALIDATION_ERROR alert and returns None.

        Args:
            line: JSON-formatted record line

        Returns:
            VerificationOutcome if transaction finalized, None otherwise
        """
        try:
            data = json.loads(line)
        except (TypeError, ValueError) as e:
            with self._lock:
                self._statistics["records_observed"] += 1
                self._validation_error("", "", None, "malformed_json", str(e))
            return None
        if isinstance(data, Mapping) and "record_type" in data and "kind" not in data:
            return self.observe_gopel_record(data)
        try:
            record = GopelRecord.from_jsonl_line(line)
        except Exception as e:
            with self._lock:
                self._statistics["records_observed"] += 1
                tid = data.get("transaction_id", "") if isinstance(data, Mapping) else ""
                self._validation_error(tid if isinstance(tid, str) else "", "", None,
                                       "malformed_record", str(e))
            return None
        return self.observe(record)

    def observe_gopel_record(self, record: Any) -> Optional[VerificationOutcome]:
        """Translate and observe one GOPEL audit record dict.

        A record that does not parse or does not validate raises a
        VALIDATION_ERROR alert and returns None.
        """
        with self._lock:
            self._statistics["records_observed"] += 1
            try:
                parsed = GopelRecord.from_gopel_dict(record)
            except GopelRecordError as e:
                self._advance_head_from_raw(record)
                self._note_refused_ids(e.transaction_id, e.record_id)
                self._validation_error(e.transaction_id, e.record_id, e.sequence_number,
                                       e.reason, str(e))
                return None
            except Exception as e:  # never silent
                self._advance_head_from_raw(record)
                self._validation_error("", "", None, "unexpected_error", str(e))
                return None
            return self._observe_gopel(parsed)

    def observe_audit_document(
        self, document: Any, source_gopel_version: Optional[str] = None,
    ) -> List[VerificationOutcome]:
        """Observe a GOPEL audit document: {"schema": ..., "records": [...]}.

        Checks the schema header (schema.schema_version) and the declared
        source GOPEL version against the configured expectation first; on a
        mismatch every record is refused with a VALIDATION_ERROR alert.
        GOPEL's audit file carries no GOPEL version string, so the version
        is source_gopel_version when given, else the gopel_version of the
        deployment manifest in structural_inputs. When neither declares it,
        the document is read and one GOPEL_VERSION_UNDECLARED alert is
        raised (once per observer).

        Re-reading a grown document observes only records past the last
        one seen, after checking that record's chain_hash is unchanged.

        Returns:
            The VerificationOutcomes of transactions finalized by this call
        """
        outcomes: List[VerificationOutcome] = []
        if not isinstance(document, Mapping) or not isinstance(document.get("records"), list):
            with self._lock:
                self._validation_error("", "", None, "malformed_document",
                                       "audit document must be an object with a records list")
            return outcomes
        records = document["records"]
        problem = self._schema_problem(document.get("schema"))
        if problem is None:
            with self._lock:
                problem = self._version_problem(source_gopel_version)
        if problem is not None:
            reason, message = problem
            with self._lock:
                for rec in records:
                    self._statistics["records_observed"] += 1
                    self._statistics["schema_refusals"] += 1
                    err = GopelRecordError(reason, message, rec)
                    self._validation_error(err.transaction_id, err.record_id,
                                           err.sequence_number, reason, message)
            return outcomes

        for rec in records:
            if self._already_observed(rec):
                continue
            outcome = self.observe_gopel_record(rec)
            if outcome is not None:
                outcomes.append(outcome)
        return outcomes

    def observe_audit_file(
        self, path: str, source_gopel_version: Optional[str] = None,
    ) -> List[VerificationOutcome]:
        """Read a GOPEL audit file (read only) and observe it."""
        try:
            with open(path, "r", encoding="utf-8") as f:
                document = json.load(f)
        except (OSError, ValueError) as e:
            with self._lock:
                self._validation_error("", "", None, "unreadable_document", str(e))
            return []
        if isinstance(document, Mapping) and document.get("encrypted"):
            with self._lock:
                self._validation_error("", "", None, "encrypted_document",
                                       "audit file is encrypted; Overwatch reads plain records only")
            return []
        return self.observe_audit_document(document, source_gopel_version=source_gopel_version)

    def set_chain_anchor(self, sequence_number: int, chain_hash: str) -> None:
        """Start validating mid-stream: the next GOPEL record must follow
        (sequence_number, chain_hash). Without an anchor the chain starts
        at genesis."""
        with self._lock:
            self._gopel_head = (int(sequence_number), str(chain_hash))

    def flush_stale(self, now: Optional[float] = None) -> int:
        """Drop buffered transactions older than TTL, emit ADVISORY.
        Thread-safe: all buffer access is protected by RLock.

        Args:
            now: Current timestamp (default: time.time())

        Returns:
            Number of stale transactions removed
        """
        with self._lock:
            now = now or time.time()
            stale_entries = []

            for txn_id, created_time in list(self._timestamps.items()):
                if (now - created_time) > self.ttl_seconds:
                    stale_entries.append((txn_id, created_time))

            for txn_id, created_time in stale_entries:
                age = now - created_time
                self._buffers.pop(txn_id, None)
                self._timestamps.pop(txn_id, None)
                self._last_legacy_hash.pop(txn_id, None)
                self._refused.pop(txn_id, None)
                self._statistics["stale_flushed"] += 1
                self._emit_alert(
                    "STALE_TRANSACTION_FLUSHED",
                    {"transaction_id": txn_id, "age_seconds": age}
                )

            # System records held for a transaction that never started (for
            # example one GOPEL stopped before its request) are dropped
            # quietly; they remain in the system-record history.
            for txn_id, (held_time, _records) in list(self._pending_system.items()):
                if (now - held_time) > self.ttl_seconds:
                    self._pending_system.pop(txn_id, None)

            return len(stale_entries)

    def get_statistics(self) -> Dict[str, Any]:
        """Get observer statistics.

        Returns:
            Dict with records_observed, transactions_finalized, stale_flushed, etc.
        """
        with self._lock:
            return copy.deepcopy(self._statistics)

    def get_alerts(self) -> List[Dict[str, Any]]:
        """Every alert this observer raised (bounded history), whether or
        not a channel manager was configured."""
        with self._lock:
            return copy.deepcopy(list(self._alerts))

    def get_system_records(self) -> List[Dict[str, Any]]:
        with self._lock:
            return copy.deepcopy(list(self._system_records))

    def get_schema_expectation(self) -> GopelSchemaExpectation:
        return self.schema_expectation

    # -------------------------------------------------------------------
    # Legacy Overwatch-format path (v2.4 behavior, alerts on every error)
    # -------------------------------------------------------------------

    def _observe_legacy(self, record: GopelRecord) -> Optional[VerificationOutcome]:
        with self._lock:
            self._statistics["records_observed"] += 1
            txn_id = record.transaction_id

            # Initialize buffer for this transaction
            if txn_id not in self._buffers:
                self._buffers[txn_id] = {}
                self._timestamps[txn_id] = time.time()

            # Validate single step
            try:
                self._validate_single_step(txn_id, record)
            except ChainValidationError as e:
                logger.error("Chain validation failed for %s: %s",
                             _sanitize_log(str(txn_id)), _sanitize_log(str(e)))
                self._validation_error(txn_id, "", None, "chain_validation", str(e))
                return None
            except Exception as e:
                logger.error("Unexpected error observing record for %s: %s",
                             _sanitize_log(str(txn_id)), _sanitize_log(str(e)))
                self._validation_error(txn_id, "", None, "unexpected_error",
                                       f"{type(e).__name__}: {e}")
                return None

            # Buffer record (a list per kind)
            self._buffers[txn_id].setdefault(record.kind, []).append(record)
            self._last_legacy_hash[txn_id] = record.this_hash
            self._statistics["records_parsed"] += 1

            # Finalize on DECISION record
            if record.kind == GopelRecordKind.DECISION:
                return self._finalize(txn_id)

            return None

    def _validate_single_step(self, txn_id: str, record: GopelRecord) -> None:
        """Validate single record against buffered state.

        Args:
            txn_id: Transaction ID
            record: Record to validate

        Raises:
            ChainValidationError: If validation fails
        """
        if not self.require_chain_validation:
            return

        # Recompute hash and verify
        expected_hash = record.recompute_hash()
        if expected_hash != record.this_hash:
            raise ChainValidationError(
                f"Hash mismatch: expected {expected_hash}, got {record.this_hash}"
            )

        # Check prev_hash against the last accepted record of this transaction
        last_hash = self._last_legacy_hash.get(txn_id)
        if last_hash is not None and last_hash != record.prev_hash:
            raise ChainValidationError(
                f"Chain break: prev_hash {record.prev_hash} "
                f"doesn't match last record {last_hash}"
            )

    # -------------------------------------------------------------------
    # GOPEL-format path
    # -------------------------------------------------------------------

    def _observe_gopel(self, record: GopelRecord) -> Optional[VerificationOutcome]:
        """Validate one translated GOPEL record against the global chain,
        then buffer it. Caller holds the lock and has counted the record."""
        try:
            problem = self._gopel_chain_problem(record)
        except Exception as e:  # never silent
            problem = ("unexpected_error", f"{type(e).__name__}: {e}")
        # Advance to the stored values, as GOPEL's own verifier does, so one
        # bad record raises one alert rather than one per later record.
        self._gopel_head = (record.sequence_number, record.this_hash)
        if problem is not None:
            self._note_refused(record)
            self._validation_error(record.transaction_id, record.record_id,
                                   record.sequence_number, problem[0], problem[1])
            return None

        self._statistics["records_parsed"] += 1
        txn_id = record.transaction_id

        if record.kind == GopelRecordKind.SYSTEM:
            self._statistics["system_records_observed"] += 1
            event = record.payload.get("event_type", "")
            detail = record.payload.get("event_detail_object")
            self._system_records.append({
                "record_id": record.record_id,
                "transaction_id": txn_id,
                "sequence_number": record.sequence_number,
                "event_type": event,
                "severity": record.payload.get("severity", ""),
                "detail": copy.deepcopy(detail),
            })
            # GOPEL refused a stop line, or Overwatch's channel file was
            # replaced: the pipe may not be stopped. Route to human.
            if event == "overwatch_stop_rejected":
                self._emit_alert("STOP_LINE_REJECTED_BY_GOPEL", {
                    "transaction_id": txn_id, "record_id": record.record_id,
                    "reason": detail.get("reason", ""), "line_sha256": detail.get("line_sha256", ""),
                })
            elif event == "overwatch_channel_reset":
                self._emit_alert("STOP_CHANNEL_RESET", {
                    "transaction_id": txn_id, "record_id": record.record_id,
                    "channel_bytes": detail.get("channel_bytes"),
                    "previous_offset": detail.get("previous_offset"),
                })
            buffer = self._buffers.get(txn_id)
            if buffer is None:
                # GOPEL may write a system record for a transaction before
                # its request (for example a channel reset or a stop found
                # at the start of execute()). Hold it; it joins the
                # transaction if one starts. Bounded; never an alert.
                if txn_id != "system":
                    held = self._pending_system.setdefault(txn_id, (time.time(), []))
                    held[1].append(record)
                    while len(self._pending_system) > self.MAX_PENDING_SYSTEM:
                        self._pending_system.pop(next(iter(self._pending_system)))
                return None
            buffer.setdefault(GopelRecordKind.SYSTEM, []).append(record)
            if event in FINALIZING_SYSTEM_EVENTS and buffer.get(GopelRecordKind.REQUEST):
                return self._finalize(txn_id, finalized_by=f"system:{event}")
            return None

        if txn_id not in self._buffers:
            self._buffers[txn_id] = {}
            self._timestamps[txn_id] = time.time()
            held = self._pending_system.pop(txn_id, None)
            if held:
                self._buffers[txn_id][GopelRecordKind.SYSTEM] = list(held[1])
        self._buffers[txn_id].setdefault(record.kind, []).append(record)

        if record.kind == GopelRecordKind.DECISION:
            return self._finalize(txn_id, finalized_by="decision")
        return None

    def _gopel_chain_problem(self, record: GopelRecord) -> Optional[Tuple[str, str]]:
        if not self.require_chain_validation:
            return None
        problem = record.hash_problem()
        if problem is not None:
            return problem
        if self._gopel_head is None:
            expected_prev, expected_seq = _GENESIS, 1
        else:
            expected_prev, expected_seq = self._gopel_head[1], self._gopel_head[0] + 1
        if record.prev_hash != expected_prev:
            return ("previous_hash_mismatch",
                    f"previous_hash {record.prev_hash} does not link to {expected_prev}")
        if record.sequence_number != expected_seq:
            return ("sequence_mismatch",
                    f"sequence_number {record.sequence_number} does not follow; expected {expected_seq}")
        return None

    def _advance_head_from_raw(self, record: Any) -> None:
        if isinstance(record, Mapping):
            seq = record.get("sequence_number")
            chain = record.get("chain_hash")
            if _is_int(seq) and isinstance(chain, str) and chain:
                self._gopel_head = (seq, chain)

    def _already_observed(self, record: Any) -> bool:
        """For a re-read document: skip records at or before the head; at
        the head itself, confirm its chain_hash is unchanged."""
        with self._lock:
            if self._gopel_head is None or not isinstance(record, Mapping):
                return False
            seq = record.get("sequence_number")
            if not _is_int(seq) or seq > self._gopel_head[0]:
                return False
            if seq == self._gopel_head[0] and record.get("chain_hash") != self._gopel_head[1]:
                err = GopelRecordError("history_rewritten", "", record)
                self._validation_error(
                    err.transaction_id, err.record_id, seq, "history_rewritten",
                    f"record {seq} chain_hash changed after it was observed",
                )
            return True

    def _schema_problem(self, schema: Any) -> Optional[Tuple[str, str]]:
        expected = self.schema_expectation
        if not isinstance(schema, Mapping):
            return ("schema_missing", "audit document has no schema header")
        version = schema.get("schema_version")
        if version != expected.audit_schema_version:
            return ("schema_version_mismatch",
                    f"audit schema_version {version!r} does not match expected "
                    f"{expected.audit_schema_version!r}")
        return None

    def _declared_source_version(self, source_gopel_version: Optional[str]) -> str:
        if source_gopel_version:
            return str(source_gopel_version)
        manifest = self.structural_inputs.deployment_manifest if self.structural_inputs else None
        if isinstance(manifest, Mapping):
            declared = manifest.get("gopel_version", "")
        else:
            declared = getattr(manifest, "gopel_version", "") if manifest is not None else ""
        return str(declared) if declared else ""

    def _version_problem(self, source_gopel_version: Optional[str]) -> Optional[Tuple[str, str]]:
        """Compare the declared source GOPEL version with the expectation.
        Caller holds the lock."""
        expected = self.schema_expectation.gopel_version
        declared = self._declared_source_version(source_gopel_version)
        if not declared:
            if not self._version_undeclared_noted:
                self._version_undeclared_noted = True
                self._emit_alert("GOPEL_VERSION_UNDECLARED", {
                    "expected_gopel_version": expected,
                    "note": "No source GOPEL version was declared for the audit "
                            "document; only its schema_version was checked.",
                })
            return None
        if _norm_version(declared) != _norm_version(expected):
            return ("gopel_version_mismatch",
                    f"declared source GOPEL version {declared!r} does not match expected {expected!r}")
        return None

    def _note_refused(self, record: GopelRecord) -> None:
        self._note_refused_ids(record.transaction_id, record.record_id)

    def _note_refused_ids(self, transaction_id: str, record_id: str) -> None:
        """Remember a refused record (failed parse or failed chain check) so
        its transaction, when it finalizes, names it in metadata. Bounded:
        the oldest entries are dropped."""
        if not transaction_id or transaction_id == "system":
            return
        self._refused.setdefault(transaction_id, []).append(record_id)
        while len(self._refused) > self.MAX_REFUSED_TRACKED:
            self._refused.pop(next(iter(self._refused)))

    # -------------------------------------------------------------------
    # Finalization
    # -------------------------------------------------------------------

    def _finalize(self, txn_id: str, finalized_by: str = "decision") -> Optional[VerificationOutcome]:
        """Assemble and route findings when transaction is complete.

        Args:
            txn_id: Transaction ID
            finalized_by: "decision" or "system:<event_type>"

        Returns:
            VerificationOutcome from pipeline, if available
        """
        try:
            records = self._buffers[txn_id]
            txn = assemble_transaction(records)
            refs = gopel_record_refs(records)
            if "gopel" in txn.metadata:
                txn.metadata["gopel"]["finalized_by"] = finalized_by
                txn.metadata["gopel"]["refused_record_ids"] = list(self._refused.get(txn_id, []))
            self._statistics["transactions_finalized"] += 1

            kwargs: Dict[str, Any] = {}
            if self.structural_inputs is not None:
                kwargs["gopel_directory"] = self.structural_inputs.gopel_directory
                kwargs["deployment_manifest"] = self.structural_inputs.deployment_manifest
                kwargs["active_gopel_config"] = self.structural_inputs.active_gopel_config
            if refs:
                kwargs["gopel_record_refs"] = refs

            # Forward to pipeline
            outcome = self.pipeline.inspect(txn, **kwargs) if kwargs else self.pipeline.inspect(txn)

            # Route high-severity findings to human
            if outcome and outcome.escalated:
                self._route_findings_to_human(txn_id, outcome)

            # Clean up buffer
            del self._buffers[txn_id]
            del self._timestamps[txn_id]
            self._last_legacy_hash.pop(txn_id, None)
            self._refused.pop(txn_id, None)

            return outcome

        except Exception as e:
            logger.exception("Finalization failed for %s: %s",
                             _sanitize_log(str(txn_id)), _sanitize_log(str(e)))
            self._emit_alert(
                "FINALIZATION_ERROR",
                {"transaction_id": txn_id, "error": str(e)}
            )
            return None

    def _route_findings_to_human(
        self,
        txn_id: str,
        outcome: VerificationOutcome
    ) -> None:
        """Route escalated findings to human arbiter.

        Args:
            txn_id: Transaction ID
            outcome: VerificationOutcome with findings
        """
        if outcome.escalation_reason:
            self._emit_alert(
                "ESCALATION_REQUIRED",
                {
                    "transaction_id": txn_id,
                    "severity": outcome.overall_severity.value,
                    "reason": outcome.escalation_reason,
                    "finding_count": len(outcome.inspection_findings),
                    "stop_event_id": getattr(outcome, "stop_event_id", ""),
                }
            )

    # -------------------------------------------------------------------
    # Alerts
    # -------------------------------------------------------------------

    def _validation_error(
        self,
        transaction_id: str,
        record_id: str,
        sequence_number: Optional[int],
        reason: str,
        error: str,
    ) -> None:
        """Count AND alert. There are no errors that are only counted."""
        self._statistics["validation_errors"] += 1
        logger.error(
            "GOPEL record refused (%s) txn=%s record=%s seq=%s: %s",
            _sanitize_log(reason), _sanitize_log(str(transaction_id)),
            _sanitize_log(str(record_id)), sequence_number, _sanitize_log(str(error)),
        )
        self._emit_alert("VALIDATION_ERROR", {
            "transaction_id": transaction_id,
            "record_id": record_id,
            "sequence_number": sequence_number,
            "reason": reason,
            "error": error,
            "translation": GOPEL_AUDIT_TRANSLATION_VERSION,
        })

    def _emit_alert(self, kind: str, payload: Dict[str, Any]) -> None:
        """Record the alert and emit it via the channel manager if available.

        Args:
            kind: Alert type
            payload: Alert content
        """
        self._alerts.append({"kind": kind, "payload": copy.deepcopy(payload),
                             "timestamp": time.time()})
        self._statistics["alerts_emitted"] += 1
        if self.channel_manager:
            try:
                self.channel_manager.emit(kind, payload)
            except Exception as e:
                logger.exception("Failed to emit alert: %s", _sanitize_log(str(e)))
