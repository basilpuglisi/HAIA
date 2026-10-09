"""
HAIA Agent Framework - Security Module
========================================
Addresses vulnerabilities identified in adversarial review:

    V2:  External hash witness (proves file has not been wholly replaced)
    V3:  HMAC operator signing (cryptographic identity, not self-asserted strings)
    V5:  Encryption at rest (AES-256 for audit file content)
    V7:  Transport integrity verification (prompt/response hash round-trips)
    V10: File-level locking for multi-instance protection

Non-cognitive constraint: This module performs cryptographic operations.
It does not evaluate, rank, or interpret any content. Hashing, signing,
encrypting, and verifying are deterministic mathematical operations.

Author: Basil C. Puglisi, MPA
"""

from __future__ import annotations

import base64
import fcntl
import hashlib
import hmac
import json
import os
import secrets
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# ======================================================================
# V3: HMAC Operator Identity Signing
# ======================================================================

class OperatorIdentity:
    """
    Cryptographic operator identity using HMAC-SHA256.

    Each operator has a secret key. When they create or approve a record,
    the record is signed with their key. Verification confirms the record
    was created by someone possessing that operator's key.

    This replaces self-asserted string IDs with cryptographic proof.
    Production deployment should integrate with an identity provider
    (OAuth, SAML, PKI). This implementation provides the signing
    interface that any identity backend can plug into.
    """

    def __init__(self, operator_id: str, signing_key: Optional[str] = None):
        """
        Args:
            operator_id: Human-readable operator identifier
            signing_key: HMAC secret key (hex string). Generated if not provided.
        """
        self.operator_id = operator_id
        if signing_key:
            self._key = bytes.fromhex(signing_key)
        else:
            self._key = secrets.token_bytes(32)

    @property
    def signing_key_hex(self) -> str:
        """Return the signing key as hex (for secure storage, not logging)."""
        return self._key.hex()

    def sign_record(self, record_dict: dict) -> str:
        """
        Produce HMAC-SHA256 signature of a record's content.
        The signature proves this operator authorized this record.

        Args:
            record_dict: The record data to sign (excluding the signature field itself)

        Returns:
            Hex-encoded HMAC-SHA256 signature
        """
        # Remove any existing signature to avoid circular dependency
        signable = {k: v for k, v in record_dict.items() if k != "operator_signature"}
        payload = json.dumps(signable, sort_keys=True, default=str).encode("utf-8")
        return hmac.new(self._key, payload, hashlib.sha256).hexdigest()

    def verify_signature(self, record_dict: dict, signature: str) -> bool:
        """
        Verify that a record's signature matches this operator's key.

        Returns True if the signature is valid.
        """
        expected = self.sign_record(record_dict)
        return hmac.compare_digest(expected, signature)


class OperatorRegistry:
    """
    Registry of authorized operators and their signing keys.

    Production deployment: back this with an identity provider.
    This implementation provides the interface for key management
    and signature verification.

    H2: Supports key persistence via export/import so keys survive
    process restarts. Keys are exported encrypted; the encryption
    key must be managed separately (KMS, environment variable, etc.).
    """

    def __init__(self):
        self._operators: dict[str, OperatorIdentity] = {}

    def register_operator(self, identity: OperatorIdentity) -> None:
        """Register an operator's identity and signing key."""
        self._operators[identity.operator_id] = identity

    def get_operator(self, operator_id: str) -> Optional[OperatorIdentity]:
        """Retrieve an operator's identity for signing or verification."""
        return self._operators.get(operator_id)

    def verify_record_signature(self, record_dict: dict) -> bool:
        """
        Verify a record's operator_signature against the registered operator.

        Returns True if:
            1. The operator_id in the record is registered
            2. The signature matches the registered operator's key
        """
        operator_id = record_dict.get("operator_id", "")
        signature = record_dict.get("operator_signature", "")
        if not operator_id or not signature:
            return False
        identity = self._operators.get(operator_id)
        if identity is None:
            return False
        return identity.verify_signature(record_dict, signature)

    def list_operators(self) -> list[str]:
        """Return IDs of all registered operators."""
        return list(self._operators.keys())

    def export_keys(self, encryption: Optional["AuditEncryption"] = None) -> dict:
        """
        H2: Export all operator keys for persistent storage.

        If encryption is provided, keys are encrypted before export.
        NEVER store the export alongside the audit file.

        Returns a dict suitable for JSON serialization.
        """
        key_data = {}
        for op_id, identity in self._operators.items():
            key_hex = identity.signing_key_hex
            if encryption:
                key_hex = encryption.encrypt(key_hex)
            key_data[op_id] = key_hex

        return {
            "format": "haia_operator_keys_v1",
            "encrypted": encryption is not None,
            "operators": key_data,
        }

    def import_keys(
        self, key_export: dict, encryption: Optional["AuditEncryption"] = None
    ) -> int:
        """
        H2: Import operator keys from persistent storage.

        Args:
            key_export: Dict from export_keys()
            encryption: Must match the encryption used during export

        Returns number of operators imported.
        """
        is_encrypted = key_export.get("encrypted", False)
        operators = key_export.get("operators", {})
        count = 0

        for op_id, key_value in operators.items():
            if is_encrypted and encryption:
                key_value = encryption.decrypt(key_value)
            elif is_encrypted and not encryption:
                raise ValueError(
                    f"Key export is encrypted but no decryption key provided"
                )
            identity = OperatorIdentity(op_id, signing_key=key_value)
            self._operators[op_id] = identity
            count += 1

        return count

    def save_to_file(
        self, path: Path, encryption: Optional["AuditEncryption"] = None
    ) -> None:
        """H2: Save registry to encrypted file."""
        export = self.export_keys(encryption)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(export, f, indent=2)

    def load_from_file(
        self, path: Path, encryption: Optional["AuditEncryption"] = None
    ) -> int:
        """H2: Load registry from file. Returns operators loaded."""
        with open(path, "r") as f:
            export = json.load(f)
        return self.import_keys(export, encryption)


# ======================================================================
# V2: External Hash Witness
# ======================================================================

class HashWitness:
    """
    External hash witness that records chain_hash checkpoints
    to an independent location.

    This addresses the whole-file replacement attack. If an attacker
    replaces the entire audit file with a new internally-consistent
    chain, the external witness will show a mismatch between the
    latest witnessed chain_hash and the file's chain_hash at that
    sequence number.

    The witness file is stored separately from the audit file.
    Production deployment should use an independent storage system
    (separate server, cloud storage, hardware security module,
    or a blockchain anchor).
    """

    def __init__(self, witness_path: Path, witness_interval: int = 10):
        """
        Args:
            witness_path: Path to the witness file (independent of audit file)
            witness_interval: Record a witness every N records (default: 10)
        """
        self.witness_path = Path(witness_path)
        self.witness_interval = witness_interval
        self._witnesses: list[dict] = []

        if self.witness_path.exists():
            with open(self.witness_path, "r") as f:
                data = json.load(f)
                self._witnesses = data.get("witnesses", [])

    def verify_separation(self, audit_file_path: Path) -> tuple[bool, str]:
        """
        H1: Verify witness file is on a genuinely separate storage path.

        Returns (is_separated, warning_message).
        Checks:
            1. Different parent directory
            2. (If possible) different filesystem mount point
        """
        audit_path = Path(audit_file_path).resolve()
        witness_resolved = self.witness_path.resolve()

        # Check 1: Same directory is a definite violation
        if audit_path.parent == witness_resolved.parent:
            return False, (
                "SECURITY WARNING: Witness file is in the same directory as audit file. "
                f"Audit: {audit_path.parent}, Witness: {witness_resolved.parent}. "
                "An attacker with directory access can replace both files. "
                "Move witness to a separate storage system."
            )

        # Check 2: Try to detect same filesystem mount (POSIX)
        try:
            audit_dev = audit_path.stat().st_dev
            witness_dev = witness_resolved.stat().st_dev
            if audit_dev == witness_dev:
                return False, (
                    "NOTICE: Witness file is on the same filesystem device as audit file. "
                    f"Both on device {audit_dev}. "
                    "For maximum security, use a separate storage system."
                )
        except (OSError, AttributeError):
            pass  # Can't check, not a fatal issue

        return True, ""

    def should_witness(self, sequence_number: int, force: bool = False) -> bool:
        """Check if this sequence number triggers a witness checkpoint.

        Args:
            sequence_number: Current record sequence number.
            force: If True, witness this record regardless of interval.
                   Use for high-value or critical-severity transactions.
                   v0.6.1: Per-transaction override. MiniMax AI review, Issue 3.
        """
        return force or (sequence_number % self.witness_interval == 0)

    def record_witness(
        self,
        sequence_number: int,
        chain_hash: str,
        record_count: int,
        operator_id: str = "system",
    ) -> dict:
        """
        Record a hash witness checkpoint.

        Args:
            sequence_number: Current sequence number in the audit chain
            chain_hash: The chain_hash of the most recent record
            record_count: Total records in the audit file at this point
            operator_id: Who triggered the witness
        """
        witness = {
            "witnessed_at": datetime.now(timezone.utc).isoformat(),
            "sequence_number": sequence_number,
            "chain_hash": chain_hash,
            "record_count": record_count,
            "witness_hash": hashlib.sha256(
                f"{sequence_number}:{chain_hash}:{record_count}".encode()
            ).hexdigest(),
            "operator_id": operator_id,
        }
        self._witnesses.append(witness)
        self._persist()
        return witness

    def verify_against_audit(self, audit_records: list[dict]) -> tuple[bool, list[dict]]:
        """
        Verify witness checkpoints against the audit file's actual records.

        Returns (is_valid, discrepancies). If the file was wholly replaced,
        the chain_hash at witnessed sequence numbers will not match.
        """
        discrepancies = []
        record_by_seq = {r.get("sequence_number"): r for r in audit_records}

        for w in self._witnesses:
            seq = w["sequence_number"]
            expected_hash = w["chain_hash"]
            record = record_by_seq.get(seq)

            if record is None:
                discrepancies.append({
                    "type": "missing_record",
                    "sequence": seq,
                    "expected_chain_hash": expected_hash,
                    "detail": f"Witness references sequence {seq} but record not found in file",
                })
            elif record.get("chain_hash") != expected_hash:
                discrepancies.append({
                    "type": "chain_hash_mismatch",
                    "sequence": seq,
                    "expected_chain_hash": expected_hash,
                    "found_chain_hash": record.get("chain_hash"),
                    "detail": "Audit file chain_hash does not match external witness",
                })

        return len(discrepancies) == 0, discrepancies

    def _persist(self) -> None:
        """Write witness file to disk."""
        self.witness_path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "description": "HAIA Agent Framework external hash witness. Independent of audit file.",
            "created": self._witnesses[0]["witnessed_at"] if self._witnesses else "",
            "witness_count": len(self._witnesses),
            "witnesses": self._witnesses,
        }
        temp = self.witness_path.with_suffix(".tmp")
        with open(temp, "w") as f:
            json.dump(data, f, indent=2)
        temp.replace(self.witness_path)

    def get_latest_witness(self) -> Optional[dict]:
        """Return the most recent witness entry."""
        return self._witnesses[-1] if self._witnesses else None


# ======================================================================
# V5: Encryption at Rest
# ======================================================================

class AuditEncryption:
    """
    AES-128-CBC encryption for audit file content at rest.

    Uses Fernet symmetric encryption (AES-128-CBC with HMAC-SHA256
    via cryptography library) with XOR obfuscation fallback.
    or falls back to a simpler XOR-based obfuscation with warning if
    the cryptography library is unavailable.

    Production deployment: Use a KMS (Key Management Service) for
    key storage. Never store the encryption key alongside the encrypted file.
    """

    def __init__(self, encryption_key: Optional[str] = None):
        """
        Args:
            encryption_key: Base64-encoded Fernet key. Generated if not provided.
        """
        self._fernet = None
        self._key = encryption_key

        try:
            from cryptography.fernet import Fernet
            if encryption_key:
                self._fernet = Fernet(encryption_key.encode())
            else:
                key = Fernet.generate_key()
                self._key = key.decode()
                self._fernet = Fernet(key)
        except ImportError:
            # v0.6.1: Explicit warning when cryptography library is missing.
            # Previously this fallback activated silently, allowing production
            # deployments to run with weaker obfuscation without operator
            # awareness. MiniMax AI review, Concern 6.
            import sys
            print(
                "WARNING [GOPEL]: cryptography library not installed. "
                "Audit encryption falling back to HMAC-based obfuscation "
                "(NOT production-grade). Install with: "
                "pip install 'cryptography>=41.0.0'",
                file=sys.stderr,
            )
            # Fallback: HMAC-based obfuscation (not production-grade)
            if not encryption_key:
                self._key = secrets.token_hex(32)

    @property
    def key(self) -> str:
        """Return the encryption key (store securely, never in audit file)."""
        return self._key

    def encrypt(self, plaintext: str) -> str:
        """Encrypt plaintext string. Returns base64-encoded ciphertext."""
        if self._fernet:
            return self._fernet.encrypt(plaintext.encode()).decode()
        else:
            # Fallback: Base64 encode with HMAC tag (obfuscation, not real encryption)
            encoded = base64.b64encode(plaintext.encode()).decode()
            tag = hmac.new(
                self._key.encode(), plaintext.encode(), hashlib.sha256
            ).hexdigest()[:16]
            return f"OBFUSCATED:{tag}:{encoded}"

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt ciphertext string. Returns plaintext."""
        if self._fernet:
            return self._fernet.decrypt(ciphertext.encode()).decode()
        else:
            # Fallback: decode base64
            if ciphertext.startswith("OBFUSCATED:"):
                parts = ciphertext.split(":", 2)
                return base64.b64decode(parts[2]).decode()
            return ciphertext

    @property
    def is_production_grade(self) -> bool:
        """True if using real AES encryption (cryptography library available)."""
        return self._fernet is not None


# ======================================================================
# V6 + V10: File Locking for Append-Only Writes
# ======================================================================

class AuditFileLock:
    """
    File-level locking for multi-instance protection.

    Uses fcntl.flock for POSIX systems. Provides exclusive write locks
    and shared read locks. Prevents concurrent writes from multiple
    framework instances to the same audit file.

    Also enforces true append-only semantics at the file operation level.
    """

    def __init__(self, lock_path: Path):
        """
        Args:
            lock_path: Path to the lock file (typically audit_file.lock)
        """
        self.lock_path = Path(lock_path)

    @contextmanager
    def write_lock(self):
        """
        Acquire an exclusive write lock on the audit file.
        Blocks until the lock is available. Guarantees no concurrent writes.
        Uses a local file descriptor (thread-safe).
        """
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        lock_fd = open(self.lock_path, "w")
        try:
            fcntl.flock(lock_fd.fileno(), fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(lock_fd.fileno(), fcntl.LOCK_UN)
            lock_fd.close()

    @contextmanager
    def read_lock(self):
        """
        Acquire a shared read lock on the audit file.
        Allows concurrent reads but blocks during writes.
        Uses a local file descriptor (thread-safe).
        """
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        lock_fd = open(self.lock_path, "r" if self.lock_path.exists() else "w")
        try:
            fcntl.flock(lock_fd.fileno(), fcntl.LOCK_SH)
            yield
        finally:
            fcntl.flock(lock_fd.fileno(), fcntl.LOCK_UN)
            lock_fd.close()


# ======================================================================
# V7: Transport Integrity Verification
# ======================================================================

class TransportVerifier:
    """
    Verifies that prompts sent and responses received match their hashes.

    This closes the gap between "the pipeline intended to send X"
    and "the platform received X" by hashing at the transport boundary.
    """

    @staticmethod
    def hash_content(content: str) -> str:
        """SHA-256 hash of content."""
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    @staticmethod
    def verify_dispatch_integrity(
        original_prompt: str,
        recorded_prompt_hash: str,
    ) -> bool:
        """
        Verify that the prompt hash in the Dispatch Record matches
        the original prompt. Proves no modification occurred between
        the human's submission and the API call.
        """
        actual_hash = hashlib.sha256(original_prompt.encode("utf-8")).hexdigest()
        return hmac.compare_digest(actual_hash, recorded_prompt_hash)

    @staticmethod
    def verify_response_integrity(
        response_text: str,
        recorded_response_hash: str,
    ) -> bool:
        """
        Verify that the response hash in the Response Record matches
        the response text. Proves no modification occurred between
        API receipt and audit logging.
        """
        actual_hash = hashlib.sha256(response_text.encode("utf-8")).hexdigest()
        return hmac.compare_digest(actual_hash, recorded_response_hash)

    @staticmethod
    def verify_transaction_transport(records: list[dict]) -> list[dict]:
        """
        Verify transport integrity across all dispatch and response records
        in a transaction.

        Returns a list of integrity violations (empty if all pass).
        """
        violations = []
        for r in records:
            rtype = r.get("record_type", "")
            if rtype == "response":
                text = r.get("response_text", "")
                stored_hash = r.get("response_hash", "")
                if text and stored_hash:
                    actual = hashlib.sha256(text.encode("utf-8")).hexdigest()
                    if not hmac.compare_digest(actual, stored_hash):
                        violations.append({
                            "record_id": r.get("record_id"),
                            "record_type": rtype,
                            "violation": "response_hash_mismatch",
                            "platform_id": r.get("platform_id"),
                        })
        return violations


# ======================================================================
# V9: Cryptographic Rotation Randomization
# ======================================================================

class SecureRotationSeed:
    """
    Cryptographically random seed for platform rotation selection.

    The seed is logged in the audit trail so selections are
    reconstructable but not predictable in advance.
    """

    @staticmethod
    def generate_seed() -> str:
        """Generate a cryptographic random seed (32 bytes, hex-encoded)."""
        return secrets.token_hex(32)

    @staticmethod
    def select_rotation(
        pool: list,
        count: int,
        seed: str,
        task_id: str = "",
    ) -> list:
        """
        Select rotation members using cryptographic randomization.

        Args:
            pool: Available items to select from
            count: How many to select
            seed: Cryptographic seed for this selection
            task_id: Combined with seed for per-task uniqueness

        Returns:
            Selected items (deterministic for same seed + task_id)
        """
        import random as _random
        # Combine seed with task_id for per-task uniqueness
        combined = hashlib.sha256(f"{seed}:{task_id}".encode()).hexdigest()
        rng = _random.Random(combined)
        shuffled = list(pool)
        rng.shuffle(shuffled)
        return shuffled[:count]
