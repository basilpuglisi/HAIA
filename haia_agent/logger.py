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

Author: Basil C. Puglisi, MPA
"""

from __future__ import annotations

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
        violations = []
        expected_previous = "genesis"

        for i, record_dict in enumerate(self._records):
            # Recompute content hash from record fields
            record_content = {
                k: v for k, v in record_dict.items()
                if k not in (
                    "content_hash", "previous_hash", "chain_hash",
                    "sequence_number", "operator_signature",
                )
            }
            serialized = json.dumps(record_content, sort_keys=True, default=str)
            recomputed_content_hash = hashlib.sha256(
                serialized.encode("utf-8")
            ).hexdigest()

            # Check content hash
            if record_dict.get("content_hash") != recomputed_content_hash:
                violations.append({
                    "sequence": record_dict.get("sequence_number"),
                    "record_id": record_dict.get("record_id"),
                    "violation": "content_hash_mismatch",
                    "expected": recomputed_content_hash,
                    "found": record_dict.get("content_hash"),
                })

            # Check previous hash linkage
            if record_dict.get("previous_hash") != expected_previous:
                violations.append({
                    "sequence": record_dict.get("sequence_number"),
                    "record_id": record_dict.get("record_id"),
                    "violation": "previous_hash_mismatch",
                    "expected": expected_previous,
                    "found": record_dict.get("previous_hash"),
                })

            # Recompute chain hash
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

            # Advance the expected previous hash
            expected_previous = record_dict.get("chain_hash")

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
        - Arbitration decisions: approve, modify, reject counts and rates
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
                "approve_count": 0,
                "modify_count": 0,
                "reject_count": 0,
                "approve_rate": 0.0,
                "modify_rate": 0.0,
                "reject_rate": 0.0,
            },
            "platforms": {},
            "errors": 0,
            "chain_intact": False,
        }

        for record in self._records:
            rtype = record.get("record_type", "unknown")
            metrics["records_by_type"][rtype] = (
                metrics["records_by_type"].get(rtype, 0) + 1
            )

            # Arbitration counting
            if rtype == "arbitration":
                metrics["arbitration"]["total"] += 1
                decision = record.get("arbitration_decision", "")
                if decision == "approve":
                    metrics["arbitration"]["approve_count"] += 1
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
            metrics["arbitration"]["approve_rate"] = round(
                metrics["arbitration"]["approve_count"] / total_arb, 4
            )
            metrics["arbitration"]["modify_rate"] = round(
                metrics["arbitration"]["modify_count"] / total_arb, 4
            )
            metrics["arbitration"]["reject_rate"] = round(
                metrics["arbitration"]["reject_count"] / total_arb, 4
            )

        # Chain verification
        is_valid, _ = self.verify_chain_integrity()
        metrics["chain_intact"] = is_valid

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

    def get_record_count(self) -> int:
        """Total number of records in the audit trail."""
        return len(self._records)

    def get_last_record(self) -> Optional[dict]:
        """Return the most recent record, or None if empty."""
        return self._records[-1] if self._records else None

    # -------------------------------------------------------------------
    # System event logging
    # -------------------------------------------------------------------

    def _log_system_event(
        self, event_type: str, detail: str, severity: str = "info"
    ) -> None:
        """Log operational events (startup, shutdown, errors, alerts)."""
        record = SystemRecord(
            transaction_id="system",
            operator_id=self.operator_id,
            event_type=event_type,
            event_detail=detail,
            severity=severity,
        )
        self.log_record(record)

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
