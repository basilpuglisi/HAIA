"""
HAIA-Overwatch v1.0 - GOPEL Observer

Read-only integration layer for GOPEL transaction records.
Buffers records by transaction_id, validates SHA-256 chain, and forwards
assembled TransactionRecords to the inspection pipeline.

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
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from .channel_manager import IndependentChannelManager
from .models import OverwatchConfig, TransactionRecord, VerificationOutcome
from .structured_logger import get_logger, sanitize_log_value as _sanitize_log

logger = get_logger(__name__)


class GopelRecordKind(Enum):
    """Record types in GOPEL's transaction audit trail."""
    REQUEST = "REQUEST"
    DISPATCH = "DISPATCH"
    RESPONSE = "RESPONSE"
    NAVIGATION = "NAVIGATION"
    ARBITRATION = "ARBITRATION"
    DECISION = "DECISION"
    ESCALATION_TRIGGER = "ESCALATION_TRIGGER"


@dataclass(frozen=True, slots=True)
class GopelRecord:
    """Immutable GOPEL audit record from the transaction chain.

    Fields:
        kind: GopelRecordKind
        transaction_id: Transaction identifier
        timestamp: Unix timestamp
        payload: Record content
        prev_hash: SHA-256 hash of previous record in chain
        this_hash: SHA-256 hash of this record
        signature: Optional signature for authentication
    """
    kind: GopelRecordKind
    transaction_id: str
    timestamp: float
    payload: Dict[str, Any]
    prev_hash: str
    this_hash: str
    signature: Optional[str] = None

    @classmethod
    def from_jsonl_line(cls, line: str) -> "GopelRecord":
        """Deserialize a GOPEL record from JSONL format.

        Args:
            line: JSON-formatted line

        Returns:
            GopelRecord instance

        Raises:
            ValueError: If JSON is malformed or fields are missing
        """
        data = json.loads(line)
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

    def canonical_bytes(self) -> bytes:
        """Return canonical bytes of record for chain hashing.

        Returns:
            JSON-encoded bytes for hashing
        """
        canonical = json.dumps({
            "kind": self.kind.value,
            "transaction_id": self.transaction_id,
            "timestamp": self.timestamp,
            "payload": self.payload,
            "prev_hash": self.prev_hash
        }, sort_keys=True, default=str)
        return canonical.encode()

    def recompute_hash(self) -> str:
        """Recompute SHA-256 hash of this record.

        Returns:
            Hex-encoded SHA-256 hash
        """
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


class ChainValidationError(Exception):
    """Raised when GOPEL chain validation fails."""
    pass


def validate_chain(records: List[GopelRecord]) -> None:
    """Walk SHA-256 chain and validate hashes.

    Args:
        records: Ordered list of records to validate

    Raises:
        ChainValidationError: If any hash doesn't match previous record's hash
    """
    for i, record in enumerate(records):
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


def assemble_transaction(records: Dict[GopelRecordKind, GopelRecord]) -> TransactionRecord:
    """Fold GOPEL records into a single TransactionRecord.

    Deep-copies all payloads to prevent mutation.

    Args:
        records: Dict mapping GopelRecordKind to GopelRecord

    Returns:
        Assembled TransactionRecord

    Raises:
        ValueError: If required records are missing
    """
    # Extract primary record (REQUEST or DECISION)
    request_rec = records.get(GopelRecordKind.REQUEST)
    decision_rec = records.get(GopelRecordKind.DECISION)

    if not request_rec and not decision_rec:
        raise ValueError("Missing REQUEST or DECISION record")

    primary = request_rec or decision_rec
    transaction_id = primary.transaction_id

    # Extract dispatch record
    dispatch_rec = records.get(GopelRecordKind.DISPATCH)

    # Extract response records (may be multiple)
    response_recs = records.get(GopelRecordKind.RESPONSE)
    if response_recs and not isinstance(response_recs, list):
        response_recs = [response_recs]

    # Extract navigation
    nav_rec = records.get(GopelRecordKind.NAVIGATION)

    # Build TransactionRecord
    from .models import PlatformResponse, RECCLINRole

    platforms = []
    responses = []

    if dispatch_rec:
        platforms = copy.deepcopy(dispatch_rec.payload.get("platforms", []))

    if response_recs:
        for resp_rec in (response_recs if isinstance(response_recs, list) else [response_recs]):
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


class GopelObserver:
    """Buffers GOPEL records, validates chain, and finalizes transactions.

    Observes individual records, buffers by transaction_id, validates the
    SHA-256 chain step-by-step, and finalizes complete transactions to the
    inspection pipeline.
    """

    def __init__(
        self,
        pipeline: Any,
        channel_manager: Optional[IndependentChannelManager] = None,
        config: Optional[OverwatchConfig] = None,
        ttl_seconds: float = 3600.0,
        require_chain_validation: bool = True
    ):
        """Initialize GopelObserver.

        Args:
            pipeline: The inspection pipeline to forward finalized transactions
            channel_manager: Optional channel for alerts
            config: Optional Overwatch configuration
            ttl_seconds: Time-to-live for buffered transactions
            require_chain_validation: Whether to validate SHA-256 chain
        """
        self.pipeline = pipeline
        self.channel_manager = channel_manager
        self.config = config or OverwatchConfig()
        self.ttl_seconds = ttl_seconds
        self.require_chain_validation = require_chain_validation

        self._lock = threading.RLock()
        self._buffers: Dict[str, Dict[GopelRecordKind, GopelRecord]] = {}
        self._timestamps: Dict[str, float] = {}
        self._statistics = {
            "records_observed": 0,
            "transactions_finalized": 0,
            "stale_flushed": 0,
            "validation_errors": 0
        }

    def observe(self, record: GopelRecord) -> Optional[VerificationOutcome]:
        """Buffer a single GOPEL record and finalize transaction if complete.

        Validates chain step, buffers record, and finalizes on DECISION record.
        Thread-safe: all buffer access is protected by RLock.

        Args:
            record: GopelRecord to observe

        Returns:
            VerificationOutcome if transaction was finalized, None otherwise
        """
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
                             _sanitize_log(txn_id), _sanitize_log(str(e)))
                self._statistics["validation_errors"] += 1
                self._emit_alert(
                    "VALIDATION_ERROR",
                    {"transaction_id": txn_id, "error": str(e)}
                )
                return None
            except Exception as e:
                logger.error("Unexpected error observing record for %s: %s",
                             _sanitize_log(txn_id), _sanitize_log(str(e)))
                self._statistics["validation_errors"] += 1
                return None

            # Buffer record
            self._buffers[txn_id][record.kind] = record

            # Finalize on DECISION record
            if record.kind == GopelRecordKind.DECISION:
                return self._finalize(txn_id)

            return None

    def observe_jsonl(self, line: str) -> Optional[VerificationOutcome]:
        """Convenience method to observe from JSONL line.

        Args:
            line: JSON-formatted record line

        Returns:
            VerificationOutcome if transaction finalized, None otherwise
        """
        record = GopelRecord.from_jsonl_line(line)
        return self.observe(record)

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
                self._statistics["stale_flushed"] += 1
                self._emit_alert(
                    "STALE_TRANSACTION_FLUSHED",
                    {"transaction_id": txn_id, "age_seconds": age}
                )

            return len(stale_entries)

    def get_statistics(self) -> Dict[str, Any]:
        """Get observer statistics.

        Returns:
            Dict with records_observed, transactions_finalized, stale_flushed, etc.
        """
        return copy.deepcopy(self._statistics)

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

        # Check prev_hash against last buffered record
        buffer = self._buffers.get(txn_id, {})
        if buffer:
            last_record = list(buffer.values())[-1]
            if last_record.this_hash != record.prev_hash:
                raise ChainValidationError(
                    f"Chain break: prev_hash {record.prev_hash} "
                    f"doesn't match last record {last_record.this_hash}"
                )

    def _finalize(self, txn_id: str) -> Optional[VerificationOutcome]:
        """Assemble and route findings when transaction is complete.

        Args:
            txn_id: Transaction ID

        Returns:
            VerificationOutcome from pipeline, if available
        """
        try:
            records = self._buffers[txn_id]
            txn = assemble_transaction(records)
            self._statistics["transactions_finalized"] += 1

            # Forward to pipeline
            outcome = self.pipeline.inspect(txn)

            # Route high-severity findings to human
            if outcome and outcome.escalated:
                self._route_findings_to_human(txn_id, outcome)

            # Clean up buffer
            del self._buffers[txn_id]
            del self._timestamps[txn_id]

            return outcome

        except Exception as e:
            logger.exception("Finalization failed for %s: %s",
                             _sanitize_log(txn_id), _sanitize_log(str(e)))
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
                    "finding_count": len(outcome.inspection_findings)
                }
            )

    def _emit_alert(self, kind: str, payload: Dict[str, Any]) -> None:
        """Emit alert via channel manager if available.

        Args:
            kind: Alert type
            payload: Alert content
        """
        if self.channel_manager:
            try:
                self.channel_manager.emit(kind, payload)
            except Exception as e:
                logger.exception("Failed to emit alert: %s", _sanitize_log(str(e)))
