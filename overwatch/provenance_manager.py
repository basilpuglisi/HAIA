"""
HAIA-Overwatch v1.0 - Provenance Manager

Manages provenance tag issuance, registration, and verification.
Source identity registration enforces trust tier authority bounds.

Author: Basil C. Puglisi, MPA
License: CC BY-NC 4.0
Repository: github.com/basilpuglisi/HAIA
Attribution: #AIassisted under HAIA-RECCLIN & Checkpoint-Based Governance
"""

from typing import Dict, Optional
from .models import ProvenanceTag, TrustTier


class ProvenanceManager:
    """Manages source registration, tag issuance, and signature verification.

    Enforces trust tier authority: sources cannot issue tags with higher tiers
    than they are authorized for. Unknown sources default to TIER_UNTRUSTED.
    """

    def __init__(self, signing_key: bytes):
        """Initialize ProvenanceManager with a cryptographic signing key.

        Args:
            signing_key: Minimum 32-byte key for HMAC-SHA256

        Raises:
            ValueError: If key is less than 32 bytes
        """
        if len(signing_key) < 32:
            raise ValueError("Signing key must be at least 32 bytes")
        self.signing_key = signing_key
        self._source_registry: Dict[str, TrustTier] = {}

    def register_source(self, source_identity: str, max_tier: TrustTier) -> None:
        """Register a source with a maximum allowed trust tier.

        Args:
            source_identity: Unique identifier for the source
            max_tier: Maximum TrustTier this source is authorized to issue
        """
        self._source_registry[source_identity] = max_tier

    def issue_tag(
        self,
        source_identity: str,
        ingestion_path: str,
        requested_tier: TrustTier
    ) -> ProvenanceTag:
        """Create and sign a provenance tag.

        Validates that the source is authorized for the requested tier.
        Unknown sources default to TIER_UNTRUSTED and cannot be elevated.

        Args:
            source_identity: Identity of the issuing source
            ingestion_path: How the content entered the system
            requested_tier: Desired trust tier for this content

        Returns:
            Signed ProvenanceTag

        Raises:
            ValueError: If source attempts to exceed its authorized tier
        """
        # Unknown sources default to TIER_UNTRUSTED (least privilege)
        authorized_tier = self._source_registry.get(source_identity, TrustTier.TIER_UNTRUSTED)

        # Enforce tier authority: cannot elevate beyond registered authorization.
        # Lower enum value = higher authority (TIER_0=0 is highest).
        # Sources can request their authorized tier or any LOWER authority (higher value).
        if requested_tier.value >= authorized_tier.value:
            # Requesting same or lower authority — allowed
            assigned_tier = requested_tier
        else:
            # Requesting higher authority (lower value) than authorized — reject
            raise ValueError(
                f"Source '{source_identity}' not authorized for {requested_tier.name}. "
                f"Maximum allowed: {authorized_tier.name}"
            )

        # Create and sign the tag
        tag = ProvenanceTag(
            source_identity=source_identity,
            timestamp=None,  # Let ProvenanceTag set current time
            trust_tier=assigned_tier,
            ingestion_path=ingestion_path
        )

        # Set timestamp if not already set
        import time
        if tag.timestamp is None:
            tag.timestamp = time.time()

        tag.sign(self.signing_key)
        return tag

    def verify(self, tag: ProvenanceTag) -> bool:
        """Verify a provenance tag's cryptographic signature.

        Args:
            tag: ProvenanceTag to verify

        Returns:
            True if signature is valid, False otherwise
        """
        return tag.verify(self.signing_key)
