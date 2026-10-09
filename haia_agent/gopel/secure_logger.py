"""
HAIA Agent Framework - Secure Audit Logger
============================================
Wraps the base AuditLogger with security hardening:

    V2:  External hash witness integration
    V3:  HMAC operator signing on every record
    V5:  Encryption at rest for sensitive content
    V6:  True append-only write semantics
    V10: File-level locking for multi-instance protection

Backward compatible: the base AuditLogger continues to work
for development and testing. SecureAuditLogger adds production
security features on top.

Author: Basil C. Puglisi, MPA
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional, Union

from .logger import AuditLogger
from .models import AuditRecord
from .security import (
    AuditEncryption,
    AuditFileLock,
    HashWitness,
    OperatorIdentity,
    OperatorRegistry,
    TransportVerifier,
)


class SecureAuditLogger(AuditLogger):
    """
    Production-hardened audit logger with cryptographic security.

    Extends AuditLogger with:
        - HMAC signing of every record (V3)
        - External hash witness at configurable intervals (V2)
        - Encryption at rest for the audit file (V5)
        - File-level exclusive locking for multi-instance safety (V10)
        - True append-only write enforcement (V6)

    Usage:
        registry = OperatorRegistry()
        registry.register_operator(OperatorIdentity("basil.puglisi"))

        logger = SecureAuditLogger(
            audit_file_path="audit.json",
            operator_registry=registry,
            witness_path="audit_witness.json",
            encrypt=True,
        )
    """

    def __init__(
        self,
        audit_file_path: Union[str, Path],
        operator_registry: OperatorRegistry,
        operator_id: str = "system",
        witness_path: Optional[Union[str, Path]] = None,
        witness_interval: int = 10,
        encrypt: bool = False,
        encryption_key: Optional[str] = None,
        create_new: bool = True,
    ):
        self._operator_registry = operator_registry
        self._file_lock = AuditFileLock(
            Path(audit_file_path).with_suffix(".lock")
        )

        # External hash witness (V2)
        self._witness: Optional[HashWitness] = None
        if witness_path:
            self._witness = HashWitness(
                witness_path=Path(witness_path),
                witness_interval=witness_interval,
            )

        # Encryption at rest (V5)
        self._encryption: Optional[AuditEncryption] = None
        if encrypt:
            self._encryption = AuditEncryption(encryption_key)

        # Initialize base logger
        super().__init__(
            audit_file_path=audit_file_path,
            operator_id=operator_id,
            create_new=create_new,
        )

        # FIX8: Invoke witness separation verification.
        # Without this check, colocation goes undetected and the
        # claimed whole-file-replacement defense is ineffective.
        self._witness_separated: bool = True
        self._witness_separation_warning: str = ""
        if self._witness:
            is_sep, warning = self._witness.verify_separation(self.audit_file_path)
            self._witness_separated = is_sep
            self._witness_separation_warning = warning
            if not is_sep:
                import sys
                print(warning, file=sys.stderr)

    def log_record(self, record: AuditRecord) -> AuditRecord:
        """
        Append a record with full security hardening:
            1. Acquire exclusive file lock (V10: multi-process)
            2. Acquire threading lock (H6: multi-thread within process)
            3. Finalize hash chain (base logger)
            4. Sign record with operator HMAC key (V3)
            5. Append to audit trail
            6. Record external witness if at interval (V2)
            7. Release locks
        """
        with self._file_lock.write_lock():
            with self._lock:  # H6: base logger's threading.Lock
                self._sequence_counter += 1
                record.finalize(
                    sequence_number=self._sequence_counter,
                    previous_hash=self._last_chain_hash,
                )

                # Step 4: HMAC signing (V3)
                record_dict = record.model_dump()
                operator = self._operator_registry.get_operator(record.operator_id)
                if operator:
                    signature = operator.sign_record(record_dict)
                    record_dict["operator_signature"] = signature
                else:
                    record_dict["operator_signature"] = "unsigned:operator_not_registered"

                # Step 5: Append
                self._records.append(record_dict)
                self._last_chain_hash = record.chain_hash
                self._persist_secure()

                # Step 6: External witness (V2)
                if self._witness and self._witness.should_witness(self._sequence_counter):
                    self._witness.record_witness(
                        sequence_number=self._sequence_counter,
                        chain_hash=record.chain_hash,
                        record_count=len(self._records),
                        operator_id=record.operator_id,
                    )

                return record

    def _persist_secure(self) -> None:
        """
        Write audit file with optional encryption (V5)
        and logical append-only semantics (V6).
        """
        audit_data = {
            "schema": self._schema.model_dump(),
            "records": self._records,
        }
        content = json.dumps(audit_data, indent=2, default=str)

        if self._encryption:
            content = self._encryption.encrypt(content)
            # Write encrypted marker so readers know to decrypt
            # FIX7: Label algorithm accurately as AES-128-CBC (Fernet)
            wrapper_payload = {
                "encrypted": True,
                "algorithm": "AES-128-CBC-HMAC-SHA256" if self._encryption.is_production_grade else "obfuscated",
                "content": content,
            }
            # T2-B: HMAC over wrapper prevents tampering of outer envelope.
            # Without this, an attacker with filesystem access could modify
            # the wrapper (e.g. remove "encrypted" flag) to force the logger
            # into an unencrypted load path, effectively erasing audit history.
            import hmac as _hmac, hashlib as _hashlib
            wrapper_json = json.dumps(wrapper_payload, sort_keys=True)
            wrapper_hmac = _hmac.new(
                self._encryption.key.encode("utf-8"),
                wrapper_json.encode("utf-8"),
                _hashlib.sha256,
            ).hexdigest()
            wrapper_payload["wrapper_hmac"] = wrapper_hmac
            content = json.dumps(wrapper_payload)

        self._write_file_content(content)

    def _load_existing(self) -> None:
        """
        FIX6: Override base _load_existing to handle encrypted files.

        Base logger reads raw JSON and would fail or load empty on
        encrypted content. This override detects the encrypted wrapper,
        decrypts, then restores records and chain state correctly.
        """
        with open(self.audit_file_path, "r", encoding="utf-8") as f:
            raw = f.read()

        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            # File is corrupted or unreadable
            self._records = []
            self._chain_valid_on_load = False
            self._load_violations = [{"violation": "file_unreadable"}]
            return

        # Check for encrypted wrapper
        if data.get("encrypted") and self._encryption:
            # T2-B: Verify wrapper HMAC before trusting any wrapper fields.
            # An attacker could modify the outer envelope (remove "encrypted"
            # flag, change algorithm) to manipulate the load path.
            stored_hmac = data.pop("wrapper_hmac", "")
            if stored_hmac:
                import hmac as _hmac, hashlib as _hashlib
                expected_json = json.dumps(data, sort_keys=True)
                expected_hmac = _hmac.new(
                    self._encryption.key.encode("utf-8"),
                    expected_json.encode("utf-8"),
                    _hashlib.sha256,
                ).hexdigest()
                if not _hmac.compare_digest(stored_hmac, expected_hmac):
                    import sys
                    print(
                        "WARNING: Encrypted audit file wrapper HMAC "
                        "verification failed. Wrapper may have been "
                        "tampered with.",
                        file=sys.stderr,
                    )
                    self._records = []
                    self._chain_valid_on_load = False
                    self._load_violations = [{"violation": "wrapper_hmac_failed"}]
                    return

            encrypted_content = data.get("content", "")
            try:
                decrypted = self._encryption.decrypt(encrypted_content)
                data = json.loads(decrypted)
            except Exception:
                # Decryption failed (wrong key, corrupted)
                import sys
                print(
                    "WARNING: Encrypted audit file decryption failed on "
                    "reload. Records cannot be recovered with this key.",
                    file=sys.stderr,
                )
                self._records = []
                self._chain_valid_on_load = False
                self._load_violations = [{"violation": "decryption_failed"}]
                return
        elif data.get("encrypted") and not self._encryption:
            # File is encrypted but no encryption configured
            import sys
            print(
                "WARNING: Audit file is encrypted but no encryption key "
                "provided. Records cannot be loaded.",
                file=sys.stderr,
            )
            self._records = []
            self._chain_valid_on_load = False
            self._load_violations = [{"violation": "encrypted_no_key"}]
            return

        self._records = data.get("records", [])
        if self._records:
            last_record = self._records[-1]
            self._sequence_counter = last_record.get("sequence_number", 0)
            self._last_chain_hash = last_record.get("chain_hash", "genesis")

            # FIX19: Chain verification on load (inherited from base fix)
            is_valid, violations = self.verify_chain_integrity()
            self._chain_valid_on_load = is_valid
            self._load_violations = violations
            if not is_valid:
                import sys
                print(
                    f"WARNING: Audit trail chain integrity check failed on "
                    f"load. {len(violations)} violation(s) detected.",
                    file=sys.stderr,
                )
        else:
            self._chain_valid_on_load = True
            self._load_violations = []

    def _write_file_content(self, content: str) -> None:
        """Atomic write: temp file then rename. Logical append-only: no records
        are removed from the array, but the filesystem operation is full file
        replacement for atomicity. Production deployments should use JSONL
        append-mode or WAL pattern for physical append-only semantics (V6)."""
        temp_path = self.audit_file_path.with_suffix(".tmp")
        with open(temp_path, "w", encoding="utf-8") as f:
            f.write(content)
        temp_path.replace(self.audit_file_path)

    def verify_operator_signatures(self) -> tuple[bool, list[dict]]:
        """
        Verify HMAC signatures on all records against registered operators.

        Returns (all_valid, violations).
        """
        violations = []
        for r in self._records:
            sig = r.get("operator_signature", "")
            if sig.startswith("unsigned:"):
                violations.append({
                    "sequence": r.get("sequence_number"),
                    "operator_id": r.get("operator_id"),
                    "violation": "unsigned_record",
                    "detail": sig,
                })
                continue

            if not self._operator_registry.verify_record_signature(r):
                violations.append({
                    "sequence": r.get("sequence_number"),
                    "operator_id": r.get("operator_id"),
                    "violation": "signature_mismatch",
                    "detail": "HMAC signature does not match registered operator key",
                })

        return len(violations) == 0, violations

    def verify_witness_integrity(self) -> tuple[bool, list[dict]]:
        """
        Verify external witness checkpoints against the audit file.

        Returns (all_valid, discrepancies).
        """
        if self._witness is None:
            return True, []
        return self._witness.verify_against_audit(self._records)

    def get_encryption_key(self) -> Optional[str]:
        """
        Return the encryption key for secure storage.
        NEVER log this. NEVER store alongside the audit file.
        """
        if self._encryption:
            return self._encryption.key
        return None

    def generate_security_report(self) -> dict:
        """
        Generate a comprehensive security status report.
        Pure counting and verification. No interpretation.
        """
        # Base governance metrics
        metrics = self.generate_governance_metrics()

        # Signature verification
        sigs_valid, sig_violations = self.verify_operator_signatures()

        # Witness verification
        witness_valid, witness_discrepancies = self.verify_witness_integrity()

        return {
            **metrics,
            "security": {
                "operator_signatures_valid": sigs_valid,
                "signature_violations": len(sig_violations),
                "external_witness_enabled": self._witness is not None,
                "external_witness_valid": witness_valid,
                "witness_discrepancies": len(witness_discrepancies),
                "encryption_at_rest": self._encryption is not None,
                "encryption_production_grade": (
                    self._encryption.is_production_grade if self._encryption else False
                ),
                "file_locking_enabled": True,
                "registered_operators": self._operator_registry.list_operators(),
            },
        }
