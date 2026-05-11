"""
HAIA-Overwatch v1.0 - Channel Manager

Independent channel for signing and dispatching messages to multiple transports.
Implements dead-man's switch (silence detection) and transport failure tracking.

Author: Basil C. Puglisi, MPA
License: CC BY-NC 4.0
Repository: github.com/basilpuglisi/HAIA
Attribution: #AIassisted under HAIA-RECCLIN & Checkpoint-Based Governance
"""

import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List

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
