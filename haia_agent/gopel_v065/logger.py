"""
HAIA Agent Framework - Audit Logging Engine
=============================================
The append-only, hash-chained, immutable logging engine.
This is the foundation of the GOPEL architecture.

Nothing dispatches, nothing collects, nothing routes until this works
and passes reconstruction tests.

Non-cognitive constraint: This engine writes records. It does not
evaluate, summarize, or interpret any content. It does not decide
what to log. It logs everything it receives, exactly as received.

Operations performed:
    4. Log   - Writes structured audit records for every operation
    6. Hash  - Computes SHA-256 cryptographic hashes for tamper detection
    7. Report - Counts approval rates, reversal rates, threshold triggers

v0.6.3:
    Step 16: read_verified_records / read_audit_file verify every stored
             record against the hash chain first, then read a legacy
             "approve" as "accept". Stored bytes are never rewritten.
    Step 17: get_upstream_record_ids lists every upstream record of a
             transaction for the Decision Record.
    Step 20: log_system_event takes an optional transaction_id (default
             "system"), so stop and halt records carry the real one.

Author: Basil C. Puglisi, MPA
"""

from __future__ import annotations

import copy
import json
import hashlib
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Union

from .models import (
    AuditFileSchema,
    AuditRecord,
    ArbitrationDecision,
    ArbitrationRecord,
    DecisionRecord,
    DispatchRecord,
    NavigationRecord,
    RecordType,
    RequestRecord,
    ResponseRecord,
    SystemRecord,
)


class ChainIntegrityError(Exception):
    """Raised when hash chain verification detects tampering."""
    pass


class ImmutabilityViolationError(Exception):
    """Raised when an attempt is made to modify or delete existing records."""
    pass


# ---------------------------------------------------------------------------
# v0.6.3 step 16: verified reading of stored records
# ---------------------------------------------------------------------------

# Fields excluded from content_hash (spec section 3 formula).
HASH_EXCLUDED_FIELDS = (
    "content_hash", "previous_hash", "chain_hash",
    "sequence_number", "operator_signature",
)

# Legacy decision terms, mapped for reading only (addendum 8).
LEGACY_DECISION_TERMS = {"approve": "accept"}

# Record types a Decision Record links as upstream records (step 17).
UPSTREAM_RECORD_TYPES = ("request", "dispatch", "response", "navigation", "arbitration")


def compute_stored_content_hash(record_dict: dict) -> str:
    """SHA-256 of a stored record's content fields, as stored."""
    record_content = {
        k: v for k, v in record_dict.items() if k not in HASH_EXCLUDED_FIELDS
    }
    serialized = json.dumps(record_content, sort_keys=True, default=str)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def verify_record_chain(records: list[dict]) -> list[dict]:
    """
    Verify stored records against the hash chain, exactly as stored.

    Checks each record's content_hash, its previous_hash link, and its
    chain_hash. Returns the list of violations (empty when intact).
    Reads only. Never modifies a record.
    """
    violations = []
    expected_previous = "genesis"

    for record_dict in records:
        recomputed_content_hash = compute_stored_content_hash(record_dict)

        if record_dict.get("content_hash") != recomputed_content_hash:
            violations.append({
                "sequence": record_dict.get("sequence_number"),
                "record_id": record_dict.get("record_id"),
                "violation": "content_hash_mismatch",
                "expected": recomputed_content_hash,
                "found": record_dict.get("content_hash"),
            })

        if record_dict.get("previous_hash") != expected_previous:
            violations.append({
                "sequence": record_dict.get("sequence_number"),
                "record_id": record_dict.get("record_id"),
                "violation": "previous_hash_mismatch",
                "expected": expected_previous,
                "found": record_dict.get("previous_hash"),
            })

        recomputed_chain = hashlib.sha256(
            f"{record_dict.get('content_hash')}{record_dict.get('previous_hash')}".encode("utf-8")
        ).hexdigest()

        if record_dict.get("chain_hash") != recomputed_chain:
            violations.append({
                "sequence": record_dict.get("sequence_number"),
                "record_id": record_dict.get("record_id"),
                "violation": "chain_hash_mismatch",
                "expected": recomputed_chain,
                "found": record_dict.get("chain_hash"),
            })

        expected_previous = record_dict.get("chain_hash")

    return violations


def map_legacy_decision_term(value):
    """Map a legacy decision term to the v0.6.3 term, for reading only."""
    return LEGACY_DECISION_TERMS.get(value, value)


def read_verified_records(records: list[dict]) -> list[dict]:
    """
    Read stored records with v0.6.3 decision terms (addendum 8).

    1. Verify every stored record against the hash chain FIRST.
       Any violation raises ChainIntegrityError and nothing is mapped.
    2. Then return copies in which a legacy arbitration_decision
       "approve" reads as "accept".
    3. The stored records are never modified or rewritten; the hashes
       in the returned copies are the stored hashes.
    """
    violations = verify_record_chain(records)
    if violations:
        error = ChainIntegrityError(
            f"Stored records failed hash chain verification: "
            f"{len(violations)} violation(s). Not read."
        )
        error.violations = violations
        raise error

    readable = []
    for record_dict in records:
        copy_dict = copy.deepcopy(record_dict)
        if copy_dict.get("record_type") == "arbitration" and "arbitration_decision" in copy_dict:
            copy_dict["arbitration_decision"] = map_legacy_decision_term(
                copy_dict["arbitration_decision"]
            )
        readable.append(copy_dict)
    return readable


def read_audit_file(audit_file_path: Union[str, Path]) -> list[dict]:
    """
    Read an unencrypted audit file through read_verified_records.

    Opens the file read only. Never writes to it.
    """
    with open(Path(audit_file_path), "rb") as f:
        data = json.loads(f.read().decode("utf-8"))
    if data.get("encrypted"):
        raise ChainIntegrityError(
            "Audit file is encrypted. Load it with SecureAuditLogger and "
            "the correct key, then call read_records()."
        )
    return read_verified_records(data.get("records", []))


class AuditLogger:
    """
    Append-only, hash-chained audit file writer.

    Responsibilities:
        - Write records to a structured JSON audit file
        - Maintain SHA-256 hash chain across all records
        - Enforce append-only immutability
        - Provide chain verification (tamper detection)
        - Provide transaction reconstruction
        - Generate governance metrics (report operation)

    Non-responsibilities (by architectural constraint):
        - Does NOT evaluate content
        - Does NOT filter or rank records
        - Does NOT summarize or interpret logged content
        - Does NOT decide what to log
    """

    def __init__(
        self,
        audit_file_path: Union[str, Path],
        operator_id: str = "system",
        create_new: bool = True,
    ):
        self.audit_file_path = Path(audit_file_path)
        self.operator_id = operator_id
        self._lock = threading.Lock()
        self._sequence_counter: int = 0
        self._last_chain_hash: str = "genesis"
        self._records: list[dict] = []
        self._schema = AuditFileSchema()
        # FIX19: Chain integrity status on load
        self._chain_valid_on_load: bool = True
        self._load_violations: list[dict] = []

        if create_new and not self.audit_file_path.exists():
            self._initialize_file()
        elif self.audit_file_path.exists():
            self._load_existing()

    # -------------------------------------------------------------------
    # Initialization
    # -------------------------------------------------------------------

    def _initialize_file(self) -> None:
        """Create a new audit file with self-documenting schema header."""
        self.audit_file_path.parent.mkdir(parents=True, exist_ok=True)
        audit_data = {
            "schema": self._schema.model_dump(),
            "records": [],
        }
        self._write_file(audit_data)
        self._log_system_event("startup", "Audit file initialized", "info")

    def _load_existing(self) -> None:
        """Load an existing audit file and restore state."""
        with open(self.audit_file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        # CLAUDE-R8: Detect encrypted wrapper.
        # If a base AuditLogger loads a file created by SecureAuditLogger
        # with encryption, it sees {"encrypted": true, "content": "..."}
        # and would silently return 0 records with chain_valid=True.
        # That is misleading. Detect and warn.
        if data.get("encrypted"):
            import sys
            print(
                "WARNING: Audit file appears to be encrypted. Base "
                "AuditLogger cannot decrypt. Use SecureAuditLogger "
                "with the correct encryption key to load this file.",
                file=sys.stderr,
            )
            self._records = []
            self._chain_valid_on_load = False
            self._load_violations = [{"violation": "encrypted_file_base_logger"}]
            return

        self._records = data.get("records", [])
        if self._records:
            last_record = self._records[-1]
            self._sequence_counter = last_record.get("sequence_number", 0)
            self._last_chain_hash = last_record.get("chain_hash", "genesis")

            # FIX19: Verify chain integrity on load.
            # Detects tampering between process lifetimes.
            is_valid, violations = self.verify_chain_integrity()
            self._chain_valid_on_load = is_valid
            self._load_violations = violations
            if not is_valid:
                import sys
                print(
                    f"WARNING: Audit trail chain integrity check failed on "
                    f"load. {len(violations)} violation(s) detected. "
                    f"File may have been tampered with between sessions.",
                    file=sys.stderr,
                )
        else:
            self._chain_valid_on_load = True
            self._load_violations = []

    # -------------------------------------------------------------------
    # Operation 4: LOG
    # Writes structured audit records for every operation.
    # Does NOT summarize or interpret logged content.
    # -------------------------------------------------------------------

    def log_record(self, record: AuditRecord) -> AuditRecord:
        """
        Append a record to the audit trail.

        This is the core logging operation. It:
        1. Assigns the next sequence number
        2. Sets the previous_hash to the last record's chain_hash
        3. Computes the content_hash and chain_hash
        4. Appends the record (append-only, no overwrites)

        Returns the finalized record with all hashes computed.
        """
        with self._lock:
            # Assign chain position
            self._sequence_counter += 1
            record.finalize(
                sequence_number=self._sequence_counter,
                previous_hash=self._last_chain_hash,
            )

            # Serialize and append
            record_dict = record.model_dump()
            self._records.append(record_dict)
            self._last_chain_hash = record.chain_hash

            # Write to file (full rewrite for atomicity in prototype;
            # production would use append-mode with file locking)
            self._persist()

            return record

    def _persist(self) -> None:
        """Write the complete audit file to disk."""
        audit_data = {
            "schema": self._schema.model_dump(),
            "records": self._records,
        }
        self._write_file(audit_data)

    def _write_file(self, data: dict) -> None:
        """Atomic write: write to temp file, then rename."""
        temp_path = self.audit_file_path.with_suffix(".tmp")
        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        temp_path.replace(self.audit_file_path)

    # -------------------------------------------------------------------
    # Operation 6: HASH
    # Computes SHA-256 cryptographic hashes for tamper detection.
    # Does NOT evaluate content being hashed.
    # -------------------------------------------------------------------

    def verify_chain_integrity(self) -> tuple[bool, list[dict]]:
        """
        Verify the entire hash chain from genesis to current.

        Returns:
            (is_valid, violations): True if chain is intact.
            violations contains details of any broken links.
        """
        violations = verify_record_chain(self._records)
        is_valid = len(violations) == 0
        return is_valid, violations

    # -------------------------------------------------------------------
    # Operation 7: REPORT
    # Counts approval rates, reversal rates, threshold triggers.
    # Does NOT interpret what the counts mean.
    # -------------------------------------------------------------------

    def generate_governance_metrics(self) -> dict:
        """
        Compute deterministic governance metrics from the audit trail.
        Pure counting. No interpretation.

        Returns counts of:
        - Total records by type
        - Arbitration decisions: accept, modify, reject counts and rates
          (v0.6.3: approve_count and approve_rate are kept as legacy alias
          keys with the same values as accept_count and accept_rate; a
          stored legacy "approve" counts as accept only if its record
          verifies against the hash chain)
        - Platform dispatch counts
        - Error counts
        - Chain integrity status
        """
        metrics = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_records": len(self._records),
            "records_by_type": {},
            "arbitration": {
                "total": 0,
                "accept_count": 0,
                "modify_count": 0,
                "reject_count": 0,
                "accept_rate": 0.0,
                "modify_rate": 0.0,
                "reject_rate": 0.0,
                "approve_count": 0,
                "approve_rate": 0.0,
                "unverified_legacy_count": 0,
            },
            "platforms": {},
            "errors": 0,
            "chain_intact": False,
        }

        # Step 16: a legacy "approve" is read as "accept" only when the
        # stored record verifies against the hash chain.
        chain_violations = verify_record_chain(self._records)
        violated_ids = {v.get("record_id") for v in chain_violations}

        for record in self._records:
            rtype = record.get("record_type", "unknown")
            metrics["records_by_type"][rtype] = (
                metrics["records_by_type"].get(rtype, 0) + 1
            )

            # Arbitration counting
            if rtype == "arbitration":
                metrics["arbitration"]["total"] += 1
                decision = record.get("arbitration_decision", "")
                if decision in LEGACY_DECISION_TERMS:
                    if record.get("record_id") in violated_ids:
                        metrics["arbitration"]["unverified_legacy_count"] += 1
                        decision = ""
                    else:
                        decision = map_legacy_decision_term(decision)
                if decision == "accept":
                    metrics["arbitration"]["accept_count"] += 1
                elif decision == "modify":
                    metrics["arbitration"]["modify_count"] += 1
                elif decision == "reject":
                    metrics["arbitration"]["reject_count"] += 1

            # Platform counting
            if rtype == "dispatch":
                pid = record.get("platform_id", "unknown")
                metrics["platforms"][pid] = metrics["platforms"].get(pid, 0) + 1

            # Error counting
            if rtype == "system" and record.get("severity") in ("error", "critical"):
                metrics["errors"] += 1

        # Compute rates (division only, no interpretation)
        total_arb = metrics["arbitration"]["total"]
        if total_arb > 0:
            metrics["arbitration"]["accept_rate"] = round(
                metrics["arbitration"]["accept_count"] / total_arb, 4
            )
            metrics["arbitration"]["modify_rate"] = round(
                metrics["arbitration"]["modify_count"] / total_arb, 4
            )
            metrics["arbitration"]["reject_rate"] = round(
                metrics["arbitration"]["reject_count"] / total_arb, 4
            )

        # Legacy alias keys (same values as the accept keys)
        metrics["arbitration"]["approve_count"] = metrics["arbitration"]["accept_count"]
        metrics["arbitration"]["approve_rate"] = metrics["arbitration"]["accept_rate"]

        # Chain verification
        metrics["chain_intact"] = len(chain_violations) == 0

        return metrics

    # -------------------------------------------------------------------
    # Reconstruction: pull any transaction's full chain
    # -------------------------------------------------------------------

    def reconstruct_transaction(self, transaction_id: str) -> list[dict]:
        """
        Retrieve all records belonging to a single transaction,
        ordered by sequence number.

        This is the reconstruction test: given a transaction_id,
        return the complete chain from Request through Decision.
        """
        chain = [
            r for r in self._records
            if r.get("transaction_id") == transaction_id
        ]
        return sorted(chain, key=lambda r: r.get("sequence_number", 0))

    def get_upstream_record_ids(self, transaction_id: str) -> list[str]:
        """
        Step 17: every upstream record ID of a transaction, in chain order.

        Upstream records are the request, dispatch, response, navigation,
        and arbitration records carrying this transaction_id.
        """
        return [
            r.get("record_id") for r in self.reconstruct_transaction(transaction_id)
            if r.get("record_type") in UPSTREAM_RECORD_TYPES
        ]

    def read_records(self) -> list[dict]:
        """
        Step 16: the records as read under v0.6.3 decision terms.

        Verifies the chain first (ChainIntegrityError on any violation),
        then maps a legacy "approve" to "accept" in the returned copies.
        The stored records are not changed.
        """
        return read_verified_records(self._records)

    def get_records_by_type(self, record_type: RecordType) -> list[dict]:
        """Retrieve all records of a specific type."""
        return [
            r for r in self._records
            if r.get("record_type") == record_type.value
        ]

    def get_all_transaction_ids(self) -> list[str]:
        """Return all unique transaction IDs in the audit trail."""
        seen = set()
        result = []
        for r in self._records:
            tid = r.get("transaction_id", "")
            if tid and tid not in seen:
                seen.add(tid)
                result.append(tid)
        return result

    def get_records(self) -> list[dict]:
        """SEC-07: Public accessor for the full records list.

        Returns a shallow copy to prevent external mutation of the
        internal audit chain. Overwatch and external monitors use
        this instead of accessing _records directly.
        """
        return list(self._records)

    def get_record_count(self) -> int:
        """Total number of records in the audit trail."""
        return len(self._records)

    def get_last_record(self) -> Optional[dict]:
        """Return the most recent record, or None if empty."""
        return self._records[-1] if self._records else None

    # -------------------------------------------------------------------
    # System event logging
    # -------------------------------------------------------------------

    def log_system_event(
        self,
        event_type: str,
        detail: str,
        severity: str = "info",
        transaction_id: str = "system",
    ) -> None:
        """SEC-07: Public API for system event logging.

        Log operational events (startup, shutdown, errors, alerts).
        Promoted from _log_system_event for external monitor access.

        v0.6.3: transaction_id is optional (default "system"). Stop, halt,
        and dispatch failure events pass the real transaction_id.
        """
        record = SystemRecord(
            transaction_id=transaction_id or "system",
            operator_id=self.operator_id,
            event_type=event_type,
            event_detail=detail,
            severity=severity,
        )
        self.log_record(record)

    # SEC-07: backward compatibility alias
    _log_system_event = log_system_event

    # -------------------------------------------------------------------
    # Convenience: log a complete transaction step
    # -------------------------------------------------------------------

    def log_request(self, **kwargs) -> RequestRecord:
        """Create and log a Request Record."""
        record = RequestRecord(**kwargs)
        self.log_record(record)
        return record

    def log_dispatch(self, **kwargs) -> DispatchRecord:
        """Create and log a Dispatch Record."""
        record = DispatchRecord(**kwargs)
        self.log_record(record)
        return record

    def log_response(self, **kwargs) -> ResponseRecord:
        """Create and log a Response Record."""
        record = ResponseRecord(**kwargs)
        self.log_record(record)
        return record

    def log_navigation(self, **kwargs) -> NavigationRecord:
        """Create and log a Navigation Record."""
        record = NavigationRecord(**kwargs)
        self.log_record(record)
        return record

    def log_arbitration(self, **kwargs) -> ArbitrationRecord:
        """Create and log an Arbitration Record."""
        record = ArbitrationRecord(**kwargs)
        self.log_record(record)
        return record

    def log_decision(self, **kwargs) -> DecisionRecord:
        """Create and log a Decision Record."""
        record = DecisionRecord(**kwargs)
        self.log_record(record)
        return record
