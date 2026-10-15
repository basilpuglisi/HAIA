"""
HAIA-Overwatch v2.8 - Channel Manager

Independent channel for signing and dispatching messages to multiple transports.
Implements dead-man's switch (silence detection) and transport failure tracking.

v2.5 adds StopChannelPublisher: Overwatch's one action authority over GOPEL,
stop the pipe and route to human (paper sections 8, 9 and 14; ruling R5).
Each stop is one line appended to a channel file that Overwatch owns:
{"body": <canonical JSON text>, "mac": <HMAC-SHA256 hex>}, signed with a key
scoped to the stop channel only. Overwatch never writes into GOPEL's files.

Author: Basil C. Puglisi, MPA
License: CC BY-NC 4.0
Repository: github.com/basilpuglisi/HAIA
Attribution: #AIassisted under HAIA-RECCLIN & Checkpoint-Based Governance
"""

import hashlib
import hmac
import json
import os
import stat
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional

from .structured_logger import get_logger, sanitize_log_value as _sanitize_log

logger = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class ChannelMessage:
    """Immutable message for transport over independent channel.

    Fields:
        sequence: Message sequence number
        timestamp: Unix timestamp of message creation
        kind: Message type/category
        payload: Message content dictionary
        signature: HMAC-SHA256 signature (empty until signed)
    """
    sequence: int
    timestamp: float
    kind: str
    payload: Dict
    signature: str = ""

    def _canonical_bytes(self) -> bytes:
        """Return canonical form of message for signing."""
        canonical = json.dumps({
            "sequence": self.sequence,
            "timestamp": self.timestamp,
            "kind": self.kind,
            "payload": self.payload
        }, sort_keys=True)
        return canonical.encode()

    def sign(self, key: bytes) -> str:
        """Sign the message with HMAC-SHA256.

        Args:
            key: Signing key

        Returns:
            Hexdigest signature

        Note:
            This returns a signature but cannot mutate the frozen dataclass.
            The caller should create a new instance with the signature.
        """
        canonical = self._canonical_bytes()
        return hmac.new(key, canonical, hashlib.sha256).hexdigest()

    def verify(self, key: bytes) -> bool:
        """Verify message signature.

        Args:
            key: Signing key

        Returns:
            True if signature is valid, False otherwise
        """
        if not self.signature:
            return False
        canonical = self._canonical_bytes()
        expected = hmac.new(key, canonical, hashlib.sha256).hexdigest()
        return hmac.compare_digest(self.signature, expected)


class IndependentChannelManager:
    """Manages message dispatch to multiple transports with signing and resilience.

    Maintains a sequence counter, tracks delivery failures, and provides
    dead-man's switch (silence detection) capability.
    """

    MAX_DELIVERY_FAILURES = 1000  # FIFO cap to prevent unbounded memory growth

    def __init__(self, signing_key: bytes):
        """Initialize IndependentChannelManager with a cryptographic signing key.

        Args:
            signing_key: Minimum 32-byte key for HMAC-SHA256

        Raises:
            ValueError: If key is less than 32 bytes
        """
        if len(signing_key) < 32:
            raise ValueError("Signing key must be at least 32 bytes")
        self.signing_key = signing_key
        self._transports: List[Callable[[ChannelMessage], None]] = []
        self._sequence = 0
        self._last_emit_timestamp = time.time()
        self._delivery_failures: List[Dict] = []

    def register_transport(self, transport: Callable[[ChannelMessage], None]) -> None:
        """Register a transport callble to receive messages.

        Args:
            transport: Callable that accepts a ChannelMessage as single argument
        """
        self._transports.append(transport)

    def emit(self, kind: str, payload: Dict) -> ChannelMessage:
        """Create, sign, and dispatch a message to all registered transports.

        Catches transport exceptions, logs them, and never re-raises.
        Updates sequence counter and last emit timestamp.

        Args:
            kind: Message type/category
            payload: Message content dictionary

        Returns:
            The signed ChannelMessage that was dispatched
        """
        self._sequence += 1
        now = time.time()
        self._last_emit_timestamp = now

        # Create message
        msg = ChannelMessage(
            sequence=self._sequence,
            timestamp=now,
            kind=kind,
            payload=payload,
            signature=""
        )

        # Sign message
        signature = msg.sign(self.signing_key)
        signed_msg = ChannelMessage(
            sequence=msg.sequence,
            timestamp=msg.timestamp,
            kind=msg.kind,
            payload=msg.payload,
            signature=signature
        )

        # Dispatch to all transports
        for transport in self._transports:
            try:
                transport(signed_msg)
            except Exception as e:
                logger.exception(
                    "Transport failed to deliver message sequence %d: %s",
                    self._sequence, _sanitize_log(str(e))
                )
                self._delivery_failures.append({
                    "sequence": self._sequence,
                    "timestamp": now,
                    "kind": kind,
                    "error": str(e),
                    "transport": getattr(transport, "__name__", str(transport))
                })
                # FIFO eviction: drop oldest failures when cap exceeded
                if len(self._delivery_failures) > self.MAX_DELIVERY_FAILURES:
                    self._delivery_failures = self._delivery_failures[-self.MAX_DELIVERY_FAILURES:]

        return signed_msg

    def is_silent(self, since: float) -> bool:
        """Dead-man counter: check if no message emitted since given timestamp.

        Args:
            since: Unix timestamp to check against

        Returns:
            True if no message emitted after 'since', False otherwise
        """
        return self._last_emit_timestamp <= since

    def get_delivery_failures(self) -> List[Dict]:
        """Return logged delivery failures.

        Returns:
            List of failure records with sequence, timestamp, kind, error, transport
        """
        return self._delivery_failures.copy()



# ---------------------------------------------------------------------------
# Stop channel (v2.5, plan step 20; Gate 1 shared spec sections 1 and 2)
# ---------------------------------------------------------------------------

STOP_SCHEMA_VERSION = "haia.overwatch.stop.v1"
STOP_TRIGGERS = ("CRITICAL", "HALT", "TRAJECTORY")
STOP_BODY_FIELDS = (
    "schema_version", "event_id", "issued_at", "key_id", "target_pipeline",
    "transaction_id", "trigger", "finding_ids", "gopel_record_refs",
)
STOP_KEY_MIN_LENGTH = 32


def canonical_json(obj: Any) -> str:
    """Canonical JSON text: sorted keys, no spaces, UTF-8 characters kept."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def iso_ms_utc(timestamp: Optional[float] = None) -> str:
    """ISO 8601 UTC with milliseconds and Z, e.g. 2026-10-14T16:05:09.123Z."""
    moment = datetime.fromtimestamp(time.time() if timestamp is None else timestamp, timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


class StopChannelPublisher:
    """Publishes stop lines on the Overwatch stop channel.

    Configured with the channel path, the key_id, the stop key (32 bytes or
    more, scoped to the stop channel only) and the target pipeline (GOPEL's
    PipelineIdentity.instance_id). Each publish appends exactly one line:

        {"body": "<canonical JSON of the body>", "mac": "<lowercase hex>"}

    where mac = HMAC-SHA256(stop_key, body.encode("utf-8")). The body holds
    exactly the fields in STOP_BODY_FIELDS. The file is opened for append
    only; earlier lines are never rewritten.
    """

    def __init__(self, channel_path: str, key_id: str, stop_key: bytes,
                 target_pipeline: str) -> None:
        if not isinstance(stop_key, (bytes, bytearray)) or len(stop_key) < STOP_KEY_MIN_LENGTH:
            raise ValueError(f"Stop key must be at least {STOP_KEY_MIN_LENGTH} bytes")
        if not isinstance(key_id, str) or not key_id:
            raise ValueError("Stop key_id must be a non-empty string")
        if not isinstance(target_pipeline, str) or not target_pipeline:
            raise ValueError("target_pipeline must be a non-empty string")
        if not channel_path:
            raise ValueError("channel_path must be set")
        self._channel_path = os.fspath(channel_path)
        self._key_id = key_id
        self._key = bytes(stop_key)
        self._target_pipeline = target_pipeline
        self._lock = threading.Lock()
        self._published = 0

    @classmethod
    def from_key_file(cls, channel_path: str, key_id: str, key_path: str,
                      target_pipeline: str) -> "StopChannelPublisher":
        """Load the stop key from a file readable only by its owner (mode
        0600 or stricter); refuse any other mode.

        The file holds the key's hex encoding (surrounding whitespace
        ignored), the same key file format GOPEL v0.6.3 reads, so both
        sides can be configured from one file.
        """
        mode = stat.S_IMODE(os.stat(key_path).st_mode)
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise ValueError(f"Stop key file must be readable only by its owner (mode {oct(mode)})")
        with open(key_path, "r", encoding="ascii") as f:
            text = f.read().strip()
        try:
            key = bytes.fromhex(text)
        except ValueError:
            raise ValueError("Stop key file must hold the key as hex text") from None
        return cls(channel_path, key_id, key, target_pipeline)

    @property
    def channel_path(self) -> str:
        return self._channel_path

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def target_pipeline(self) -> str:
        return self._target_pipeline

    @property
    def key_fingerprint(self) -> str:
        """SHA-256 of the stop key, for key-scope checks. Never the key."""
        return hashlib.sha256(self._key).hexdigest()

    @property
    def published_count(self) -> int:
        return self._published

    def build_body(self, transaction_id: str, trigger: str,
                   finding_ids: Iterable[str],
                   gopel_record_refs: Iterable[Mapping[str, Any]] = ()) -> Dict[str, Any]:
        if trigger not in STOP_TRIGGERS:
            raise ValueError(f"Stop trigger must be one of {STOP_TRIGGERS}, got {trigger!r}")
        ids = [str(f) for f in finding_ids]
        refs = []
        for ref in gopel_record_refs:
            record_id, chain = ref.get("record_id"), ref.get("chain_hash")
            if not isinstance(record_id, str) or not isinstance(chain, str):
                raise ValueError("gopel_record_refs entries need string record_id and chain_hash")
            refs.append({"record_id": record_id, "chain_hash": chain})
        return {
            "schema_version": STOP_SCHEMA_VERSION,
            "event_id": uuid.uuid4().hex,
            "issued_at": iso_ms_utc(),
            "key_id": self._key_id,
            "target_pipeline": self._target_pipeline,
            "transaction_id": "" if transaction_id is None else str(transaction_id),
            "trigger": trigger,
            "finding_ids": ids,
            "gopel_record_refs": refs,
        }

    def sign_body(self, body: Mapping[str, Any]) -> Dict[str, str]:
        """Return the line object {"body": canonical text, "mac": hex}."""
        body_text = canonical_json(dict(body))
        mac = hmac.new(self._key, body_text.encode("utf-8"), hashlib.sha256).hexdigest()
        return {"body": body_text, "mac": mac}

    def publish(self, transaction_id: str, trigger: str, finding_ids: Iterable[str],
                gopel_record_refs: Iterable[Mapping[str, Any]] = ()) -> Dict[str, Any]:
        """Append one signed stop line. Returns {event_id, body, line}.

        Raises OSError if the line cannot be written (the caller reports it).
        """
        body = self.build_body(transaction_id, trigger, finding_ids, gopel_record_refs)
        line_obj = self.sign_body(body)
        line = json.dumps(line_obj, ensure_ascii=False)
        data = (line + "\n").encode("utf-8")
        with self._lock:
            fd = os.open(self._channel_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
            try:
                written = 0
                while written < len(data):
                    written += os.write(fd, data[written:])
                os.fsync(fd)
            finally:
                os.close(fd)
            self._published += 1
        logger.warning(
            "Stop published on the Overwatch stop channel: event %s, trigger %s, transaction %s",
            body["event_id"], trigger, _sanitize_log(body["transaction_id"]),
        )
        return {"event_id": body["event_id"], "body": body, "line": line}
