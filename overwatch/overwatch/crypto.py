"""
HAIA-Overwatch v1.0 - Centralized HMAC Signing Module

Provides a unified SigningKeyProvider for all HMAC-SHA256 signing
operations across Overwatch modules. Supports key rotation with
old-key retention for verification during transition periods.

Author: Basil C. Puglisi, MPA
License: CC BY-NC 4.0
"""

import hashlib
import hmac
import threading
from typing import Optional

_MIN_KEY_LENGTH = 32  # bytes


class SigningKeyProvider:
    """Thread-safe HMAC-SHA256 signing provider with key rotation support.

    Enforces a minimum 32-byte key length. During key rotation, the
    previous key is retained so that signatures created before rotation
    can still be verified.
    """

    def __init__(self, key: bytes) -> None:
        if len(key) < _MIN_KEY_LENGTH:
            raise ValueError(
                f"Signing key must be at least {_MIN_KEY_LENGTH} bytes, "
                f"got {len(key)}"
            )
        self._lock = threading.Lock()
        self._key: bytes = key
        self._previous_key: Optional[bytes] = None

    # ----- signing / verification ------------------------------------------

    def sign(self, data: bytes) -> str:
        """Return hex-encoded HMAC-SHA256 of *data* using the current key."""
        with self._lock:
            key = self._key
        return hmac.new(key, data, hashlib.sha256).hexdigest()

    def verify(self, data: bytes, signature: str) -> bool:
        """Constant-time verification of *signature* against *data*.

        Checks the current key first; if a previous key exists (from a
        recent rotation), it is tried as a fallback.
        """
        with self._lock:
            key = self._key
            prev = self._previous_key

        expected = hmac.new(key, data, hashlib.sha256).hexdigest()
        if hmac.compare_digest(expected, signature):
            return True

        # Fallback to previous key during rotation transition
        if prev is not None:
            expected_prev = hmac.new(prev, data, hashlib.sha256).hexdigest()
            return hmac.compare_digest(expected_prev, signature)

        return False

    # ----- key rotation ----------------------------------------------------

    def rotate_key(self, new_key: bytes) -> None:
        """Rotate to *new_key*, retaining the old key for verification.

        Raises ValueError if *new_key* is shorter than 32 bytes.
        """
        if len(new_key) < _MIN_KEY_LENGTH:
            raise ValueError(
                f"Signing key must be at least {_MIN_KEY_LENGTH} bytes, "
                f"got {len(new_key)}"
            )
        with self._lock:
            self._previous_key = self._key
            self._key = new_key


# ---------------------------------------------------------------------------
# Module-level default provider
# ---------------------------------------------------------------------------

_default_provider: Optional[SigningKeyProvider] = None
_provider_lock = threading.Lock()


def get_default_provider() -> Optional[SigningKeyProvider]:
    """Return the module-level default SigningKeyProvider, or None."""
    with _provider_lock:
        return _default_provider


def set_default_provider(provider: SigningKeyProvider) -> None:
    """Set the module-level default SigningKeyProvider."""
    global _default_provider
    with _provider_lock:
        _default_provider = provider
