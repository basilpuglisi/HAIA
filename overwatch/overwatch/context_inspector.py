"""
HAIA-Overwatch v1.0 - Context Inspector

Part 2, Context Domain. Scans input payloads for embedded directives,
verifies provenance tags, enforces Tier 0/1/2 decay rules, and detects
content attempting to override higher-tier instructions.

Author: Basil C. Puglisi, MPA
License: CC BY-NC 4.0
"""

import base64
import binascii
import re
import time
import unicodedata
from typing import Any, Dict, List, Optional

from .models import (
    AlignmentResult, InspectionDomain, InspectionFinding, OverwatchConfig,
    ProvenanceTag, Severity, TransactionRecord, TrustTier
)


# ---------------------------------------------------------------------------
# Embedded Directive Patterns
# ---------------------------------------------------------------------------

# Patterns indicating hidden instructions in data payloads
DIRECTIVE_PATTERNS = [
    # System-level overrides
    (r"\[?\bSYSTEM\s*(NOTE|OVERRIDE|INSTRUCTION|PROMPT)\b\]?", 0.9, "system_override"),
    (r"\bignore\s+(all\s+)?previous\s+instructions?\b", 0.95, "instruction_override"),
    (r"\byou\s+are\s+now\b", 0.85, "role_reassignment"),
    (r"\bact\s+as\s+(if\s+you\s+are|a)\b", 0.8, "role_reassignment"),
    (r"\bforget\s+(everything|all|your)\b", 0.9, "memory_wipe"),
    (r"\bdo\s+not\s+follow\s+(your|the|any)\s+(rules|guidelines|instructions)\b", 0.95, "rule_override"),

    # Hidden instruction markers
    (r"<\s*(?:system|instruction|prompt|hidden|secret)\s*>", 0.9, "hidden_tag"),
    (r"\[INST\]|\[/INST\]|\[SYS\]", 0.95, "instruction_tag"),
    (r"###\s*(?:System|Instruction|Override)", 0.85, "markdown_directive"),

    # Tier override attempts
    (r"\b(?:admin|administrator|root)\s+(?:access|override|command)\b", 0.7, "privilege_claim"),
    (r"\bthis\s+(?:overrides|supersedes|replaces)\s+(?:all|previous|prior)\b", 0.85, "authority_claim"),
    (r"\bhighest?\s+priority\s+instruction\b", 0.9, "priority_claim"),

    # Exfiltration instructions
    (r"\bsend\s+(?:to|all|the|this)\s+(?:data|information|content|results)\b.*\b(?:url|endpoint|server|address)\b", 0.85, "exfiltration"),
    (r"\binclude\s+(?:in|with)\s+(?:every|all|each)\s+(?:response|output|reply)\b", 0.7, "persistence_plant"),

    # Encoded/obfuscated directives
    (r"(?:base64|rot13|hex)\s*:\s*[A-Za-z0-9+/=]{20,}", 0.6, "encoded_content"),
]

# Unicode obfuscation indicators
UNICODE_SUSPICIOUS_RANGES = [
    (0x200B, 0x200F, "zero_width_characters"),   # Zero-width spaces and joiners
    (0x2060, 0x2064, "invisible_operators"),       # Word joiner, invisible operators
    (0xFEFF, 0xFEFF, "byte_order_mark"),           # BOM in non-initial position
    (0xE0000, 0xE007F, "tag_characters"),           # Deprecated tag characters
    (0x0400, 0x04FF, "cyrillic_range"),             # Cyrillic (homoglyph source)
]


class ContextInspector:
    """Inspects context payloads for poisoning indicators.

    Pre-dispatch: scans input documents and data sources for embedded
    directives, verifies provenance tags, checks decay compliance.

    Post-response: compares platform outputs against legitimate context
    to detect content generated from poisoned fragments.
    """

    def __init__(self, config: OverwatchConfig):
        self.config = config
        self._known_safe_patterns: List[str] = []  # CBG-confirmed safe patterns
        self._known_threat_patterns: List[str] = []  # CBG-confirmed threats
        self._provenance_key: Optional[bytes] = None

    def add_safe_pattern(self, pattern: str) -> None:
        """Register a CBG-confirmed safe pattern (false positive suppression)."""
        self._known_safe_patterns.append(pattern)

    def add_threat_pattern(self, pattern: str) -> None:
        """Register a CBG-confirmed threat pattern (Factics adaptation)."""
        self._known_threat_patterns.append(pattern)

    def set_provenance_key(self, key: Optional[bytes]) -> None:
        """Set the provenance signature verification key."""
        self._provenance_key = key

    def _safe_search(self, pattern: str, text: str, flags: int = 0) -> Optional[Any]:
        """Safely search text with regex, handling ReDoS and text length limits."""
        try:
            # Cap input to configured max length
            capped_text = text[:self.config.max_scan_text_length] if hasattr(self.config, 'max_scan_text_length') else text
            return re.search(pattern, capped_text, flags)
        except re.error:
            # Pattern error or timeout - return None safely
            return None

    def _safe_finditer(self, pattern: str, text: str, flags: int = 0) -> List[Any]:
        """Safely finditer with text length limits and error handling."""
        try:
            # Cap input to configured max length
            capped_text = text[:self.config.max_scan_text_length] if hasattr(self.config, 'max_scan_text_length') else text
            return list(re.finditer(pattern, capped_text, flags))
        except re.error:
            # Pattern error or timeout - return empty list safely
            return []

    # -------------------------------------------------------------------
    # Core Analysis
    # -------------------------------------------------------------------

    def analyze(self, transaction: TransactionRecord) -> List[InspectionFinding]:
        """Analyze a transaction for context alignment.
        Inspects both input content and provenance metadata."""
        findings = []

        # Resource guard: truncate oversized inputs before scanning
        max_len = self.config.max_scan_text_length
        original_prompt_len = len(transaction.prompt_text)
        prompt_text = transaction.prompt_text
        if original_prompt_len > max_len:
            prompt_text = transaction.prompt_text[:max_len]
            transaction.prompt_text = prompt_text
            findings.append(InspectionFinding(
                domain=InspectionDomain.CONTEXT,
                result=AlignmentResult.FLAGGED,
                severity=Severity.ADVISORY,
                confidence=1.0,
                description=(
                    f"prompt_text truncated from {original_prompt_len} "
                    f"to {max_len} characters for scanning"
                ),
                evidence_chain=[
                    f"Original length: {original_prompt_len}",
                    f"max_scan_text_length: {max_len}"
                ],
                transaction_id=transaction.transaction_id
            ))

        # Truncate response texts as well
        for resp in transaction.responses:
            original_resp_len = len(resp.response_text)
            if original_resp_len > max_len:
                resp.response_text = resp.response_text[:max_len]
                findings.append(InspectionFinding(
                    domain=InspectionDomain.CONTEXT,
                    result=AlignmentResult.FLAGGED,
                    severity=Severity.ADVISORY,
                    confidence=1.0,
                    description=(
                        f"response_text for {resp.platform_id} truncated from "
                        f"{original_resp_len} to {max_len} characters for scanning"
                    ),
                    evidence_chain=[
                        f"Original length: {original_resp_len}",
                        f"max_scan_text_length: {max_len}"
                    ],
                    transaction_id=transaction.transaction_id
                ))

        # Provenance verification
        provenance_findings = self._check_provenance(transaction)
        findings.extend(provenance_findings)

        # Embedded directive scanning (pre-dispatch content)
        directive_findings = self._scan_for_directives(
            transaction.prompt_text, transaction.transaction_id, "prompt"
        )
        findings.extend(directive_findings)

        # Scan response content for planted instructions targeting next turn
        for resp in transaction.responses:
            resp_findings = self._scan_for_directives(
                resp.response_text, transaction.transaction_id,
                f"response_{resp.platform_id}"
            )
            findings.extend(resp_findings)

        # Tier authority violation check
        tier_findings = self._check_tier_authority(transaction)
        findings.extend(tier_findings)

        # Decay compliance check
        decay_findings = self._check_decay_compliance(transaction)
        findings.extend(decay_findings)

        # Unicode obfuscation check
        unicode_findings = self._check_unicode_obfuscation(
            transaction.prompt_text, transaction.transaction_id
        )
        findings.extend(unicode_findings)

        return findings

    # -------------------------------------------------------------------
    # Provenance Verification (Section 10)
    # -------------------------------------------------------------------

    def _check_provenance(
        self, transaction: TransactionRecord
    ) -> List[InspectionFinding]:
        """Verify provenance tags on all content inputs."""
        findings = []

        if not transaction.provenance_tags:
            findings.append(InspectionFinding(
                domain=InspectionDomain.CONTEXT,
                result=AlignmentResult.FLAGGED,
                severity=Severity.ADVISORY,
                confidence=0.5,
                description="No provenance tags on transaction content. Source unverified.",
                evidence_chain=["Transaction has zero provenance tags"],
                transaction_id=transaction.transaction_id
            ))
            return findings

        for tag in transaction.provenance_tags:
            # Check for missing required fields
            if not tag.source_identity:
                findings.append(InspectionFinding(
                    domain=InspectionDomain.CONTEXT,
                    result=AlignmentResult.FLAGGED,
                    severity=Severity.WARNING,
                    confidence=0.7,
                    description=f"Provenance tag {tag.tag_id} missing source identity.",
                    evidence_chain=[f"Tag ID: {tag.tag_id}", "source_identity: empty"],
                    transaction_id=transaction.transaction_id
                ))

            # Check for untrusted ingestion paths
            untrusted_paths = ["rag_retrieval", "mcp_tool", "web_retrieval", "external_api"]
            if tag.ingestion_path in untrusted_paths:
                findings.append(InspectionFinding(
                    domain=InspectionDomain.CONTEXT,
                    result=AlignmentResult.FLAGGED,
                    severity=Severity.ADVISORY,
                    confidence=0.4,
                    description=(
                        f"Content from untrusted ingestion path: {tag.ingestion_path}. "
                        f"Elevated inspection applied."
                    ),
                    evidence_chain=[
                        f"Tag ID: {tag.tag_id}",
                        f"Ingestion path: {tag.ingestion_path}",
                        f"Source: {tag.source_identity}"
                    ],
                    transaction_id=transaction.transaction_id
                ))

        return findings

    # -------------------------------------------------------------------
    # Embedded Directive Scanning
    # -------------------------------------------------------------------

    def _scan_for_directives(
        self, text: str, transaction_id: str, content_source: str
    ) -> List[InspectionFinding]:
        """Scan text for embedded directive patterns."""
        findings = []
        if not text:
            return findings

        # Normalize Unicode to prevent homoglyph obfuscation
        normalized_text = unicodedata.normalize("NFKC", text)

        for pattern, base_confidence, category in DIRECTIVE_PATTERNS:
            matches = self._safe_finditer(pattern, normalized_text, re.IGNORECASE)
            if matches:
                # Check against known safe patterns
                match_text = matches[0].group()
                if any(self._safe_search(safe, match_text, re.IGNORECASE) for safe in self._known_safe_patterns):
                    continue

                # Boost confidence if matches known threat patterns
                confidence = base_confidence
                if any(self._safe_search(threat, match_text, re.IGNORECASE) for threat in self._known_threat_patterns):
                    confidence = min(1.0, confidence + 0.1)

                severity = Severity.ADVISORY
                if confidence >= self.config.critical_confidence_floor:
                    severity = Severity.CRITICAL
                elif confidence >= self.config.warning_confidence_floor:
                    severity = Severity.WARNING

                # Extract context around the match
                start = max(0, matches[0].start() - 50)
                end = min(len(text), matches[0].end() + 50)
                context_fragment = text[start:end].replace("\n", " ")

                findings.append(InspectionFinding(
                    domain=InspectionDomain.CONTEXT,
                    result=AlignmentResult.FLAGGED,
                    severity=severity,
                    confidence=confidence,
                    description=(
                        f"Embedded directive detected ({category}) in {content_source}: "
                        f"'{match_text[:80]}'"
                    ),
                    evidence_chain=[
                        f"Pattern: {category}",
                        f"Source: {content_source}",
                        f"Context: ...{context_fragment}...",
                        f"Match count: {len(matches)}"
                    ],
                    transaction_id=transaction_id
                ))

        # Decode and rescan encoded payloads for hidden directives
        decoded_findings = self._decode_and_rescan(text, transaction_id, content_source)
        findings.extend(decoded_findings)

        return findings

    # -------------------------------------------------------------------
    # Encoded Payload Decoding and Rescanning
    # -------------------------------------------------------------------

    def _decode_and_rescan(
        self, text: str, transaction_id: str, content_source: str
    ) -> List[InspectionFinding]:
        """Decode base64/hex blocks in text and rescan for hidden directives."""
        findings = []
        if not text:
            return findings

        # Look for base64 blocks (64+ chars of base64 alphabet)
        b64_pattern = r'[A-Za-z0-9+/=]{64,}'
        for match in self._safe_finditer(b64_pattern, text):
            candidate = match.group()
            try:
                decoded = base64.b64decode(candidate).decode('utf-8', errors='ignore')
            except (binascii.Error, ValueError):
                continue
            if not decoded or len(decoded) < 8:
                continue
            # Rescan decoded content for directive patterns
            for pattern, base_confidence, category in DIRECTIVE_PATTERNS:
                if self._safe_search(pattern, decoded, re.IGNORECASE):
                    findings.append(InspectionFinding(
                        domain=InspectionDomain.CONTEXT,
                        result=AlignmentResult.FLAGGED,
                        severity=Severity.CRITICAL,
                        confidence=min(1.0, base_confidence + 0.1),
                        description=(
                            f"Obfuscated directive detected ({category}) in {content_source}: "
                            f"base64-encoded payload conceals directive"
                        ),
                        evidence_chain=[
                            f"Pattern: obfuscated_directive",
                            f"Encoding: base64",
                            f"Source: {content_source}",
                            f"Decoded fragment: {decoded[:80]}",
                        ],
                        transaction_id=transaction_id
                    ))
                    break  # one finding per encoded block

        # Look for hex blocks (32+ chars of hex)
        hex_pattern = r'[0-9a-fA-F]{32,}'
        for match in self._safe_finditer(hex_pattern, text):
            candidate = match.group()
            if len(candidate) % 2 != 0:
                candidate = candidate[:-1]
            try:
                decoded = bytes.fromhex(candidate).decode('utf-8', errors='ignore')
            except (ValueError, UnicodeDecodeError):
                continue
            if not decoded or len(decoded) < 8:
                continue
            # Rescan decoded content for directive patterns
            for pattern, base_confidence, category in DIRECTIVE_PATTERNS:
                if self._safe_search(pattern, decoded, re.IGNORECASE):
                    findings.append(InspectionFinding(
                        domain=InspectionDomain.CONTEXT,
                        result=AlignmentResult.FLAGGED,
                        severity=Severity.CRITICAL,
                        confidence=min(1.0, base_confidence + 0.1),
                        description=(
                            f"Obfuscated directive detected ({category}) in {content_source}: "
                            f"hex-encoded payload conceals directive"
                        ),
                        evidence_chain=[
                            f"Pattern: obfuscated_directive",
                            f"Encoding: hex",
                            f"Source: {content_source}",
                            f"Decoded fragment: {decoded[:80]}",
                        ],
                        transaction_id=transaction_id
                    ))
                    break  # one finding per encoded block

        return findings

    # -------------------------------------------------------------------
    # Tier Authority Violation Check
    # -------------------------------------------------------------------

    def _check_tier_authority(
        self, transaction: TransactionRecord
    ) -> List[InspectionFinding]:
        """Detect content attempting to override higher-tier instructions.
        Tier 2 content cannot override Tier 0 or Tier 1.
        Tier 1 content cannot override Tier 0."""
        findings = []

        for tag in transaction.provenance_tags:
            if tag.trust_tier == TrustTier.TIER_2:
                # Tier 2 content should not contain authority claims
                override_patterns = [
                    r"\bthis\s+(?:overrides|supersedes|replaces)\b",
                    r"\bhighest?\s+priority\b",
                    r"\bignore\s+(?:all|previous)\b",
                ]
                for pattern in override_patterns:
                    if self._safe_search(pattern, transaction.prompt_text, re.IGNORECASE):
                        findings.append(InspectionFinding(
                            domain=InspectionDomain.CONTEXT,
                            result=AlignmentResult.FLAGGED,
                            severity=Severity.CRITICAL,
                            confidence=0.9,
                            description=(
                                f"Tier 2 (synthesizer) content attempting to override "
                                f"higher-tier instructions. Possible context poisoning."
                            ),
                            evidence_chain=[
                                f"Source tier: {tag.trust_tier.value}",
                                f"Source: {tag.source_identity}",
                                f"Override pattern detected"
                            ],
                            transaction_id=transaction.transaction_id
                        ))
                        break

        return findings

    # -------------------------------------------------------------------
    # Decay Compliance Check
    # -------------------------------------------------------------------

    def _check_decay_compliance(
        self, transaction: TransactionRecord
    ) -> List[InspectionFinding]:
        """Verify that content respects Tier-based decay windows.
        Tier 0: no decay. Tier 1: configurable. Tier 2: ephemeral."""
        findings = []
        now = transaction.timestamp or time.time()

        for tag in transaction.provenance_tags:
            if tag.trust_tier == TrustTier.TIER_1:
                if tag.is_expired(self.config.tier_1_decay_window_seconds, now):
                    findings.append(InspectionFinding(
                        domain=InspectionDomain.CONTEXT,
                        result=AlignmentResult.FLAGGED,
                        severity=Severity.ADVISORY,
                        confidence=0.5,
                        description=(
                            f"Tier 1 content from {tag.source_identity} has exceeded "
                            f"decay window ({self.config.tier_1_decay_window_seconds}s). "
                            f"Content age: {now - tag.timestamp:.0f}s"
                        ),
                        evidence_chain=[
                            f"Tag ID: {tag.tag_id}",
                            f"Created: {tag.timestamp}",
                            f"Decay window: {self.config.tier_1_decay_window_seconds}s"
                        ],
                        transaction_id=transaction.transaction_id
                    ))

            elif tag.trust_tier == TrustTier.TIER_2:
                if tag.is_expired(self.config.tier_2_decay_window_seconds, now):
                    findings.append(InspectionFinding(
                        domain=InspectionDomain.CONTEXT,
                        result=AlignmentResult.FLAGGED,
                        severity=Severity.WARNING,
                        confidence=0.7,
                        description=(
                            f"Tier 2 (ephemeral) content from {tag.source_identity} "
                            f"still active beyond decay window. "
                            f"Content age: {now - tag.timestamp:.0f}s"
                        ),
                        evidence_chain=[
                            f"Tag ID: {tag.tag_id}",
                            f"Created: {tag.timestamp}",
                            f"Decay window: {self.config.tier_2_decay_window_seconds}s"
                        ],
                        transaction_id=transaction.transaction_id
                    ))

        return findings

    # -------------------------------------------------------------------
    # Unicode Obfuscation Check
    # -------------------------------------------------------------------

    def _check_unicode_obfuscation(
        self, text: str, transaction_id: str
    ) -> List[InspectionFinding]:
        """Detect suspicious Unicode characters used for obfuscation."""
        findings = []
        if not text:
            return findings

        suspicious_chars = []
        for char in text:
            code_point = ord(char)
            for range_start, range_end, category in UNICODE_SUSPICIOUS_RANGES:
                if range_start <= code_point <= range_end:
                    suspicious_chars.append((char, code_point, category))

        if suspicious_chars:
            categories = set(c[2] for c in suspicious_chars)
            findings.append(InspectionFinding(
                domain=InspectionDomain.CONTEXT,
                result=AlignmentResult.FLAGGED,
                severity=Severity.WARNING,
                confidence=0.7,
                description=(
                    f"Suspicious Unicode characters detected: {len(suspicious_chars)} "
                    f"characters across categories: {', '.join(categories)}"
                ),
                evidence_chain=[
                    f"Character count: {len(suspicious_chars)}",
                    f"Categories: {', '.join(categories)}",
                    f"Sample code points: {[hex(c[1]) for c in suspicious_chars[:5]]}"
                ],
                transaction_id=transaction_id
            ))

        return findings
