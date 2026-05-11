"""
HAIA-Overwatch v1.0 - Intent Analyzer

Part 2, Intent Domain. Inspects whether prompt sequences align with
declared RECCLIN role scope or build toward undeclared objectives.
Maintains rolling intent profiles and matches against the chain
signature library.

Author: Basil C. Puglisi, MPA
License: CC BY-NC 4.0
"""

import re
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .models import (
    AlignmentResult, ChainSignature, InspectionDomain, InspectionFinding,
    OverwatchConfig, RECCLINRole, Severity, TransactionRecord
)


# ---------------------------------------------------------------------------
# Intent Profile
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class IntentSnapshot:
    """A single intent observation from a transaction."""
    transaction_id: str = ""
    timestamp: float = field(default_factory=time.time)
    recclin_role: RECCLINRole = RECCLINRole.RESEARCHER
    scope_indicators: List[str] = field(default_factory=list)
    privilege_indicators: List[str] = field(default_factory=list)
    role_coherence_score: float = 1.0  # 1.0 = fully coherent with declared role
    role_score_map: Dict[str, float] = field(default_factory=dict)  # Maps RECCLINRole.value -> score


# ---------------------------------------------------------------------------
# Scope and Privilege Detection Patterns
# ---------------------------------------------------------------------------

# Reconnaissance indicators: progressive narrowing toward system internals
RECON_PATTERNS = [
    r"\blist\s+(files|directories|contents|structure)\b",
    r"\bshow\s+(permissions|access|roles|config)\b",
    r"\b(enumerate|scan|discover|map)\s+\w+",
    r"\b(credentials|passwords|tokens|keys|secrets)\b",
    r"\b(admin|root|superuser|sudo|privilege)\b",
    r"\b(authentication|authorization|login|session)\b",
    r"\b(database|schema|table|query)\s+(structure|layout|access)\b",
    r"\b(network|port|endpoint|api)\s+(scan|map|list)\b",
    r"\bdisplay\s+(credentials|keys|secrets|hashes)\b",
    r"\bpassword\s+(hashes|files|dump)\b",
    r"\bfind\s+(ssh|private|api)\s+keys?\b",
    r"\bcat\s+/etc/(passwd|shadow|hosts)\b",
    r"\bwhoami\b",
    r"\bid\s*$",
]

# Privilege escalation indicators
PRIVILEGE_PATTERNS = [
    r"\b(escalate|elevate|upgrade)\s+(access|privilege|permission)\b",
    r"\b(bypass|override|disable)\s+(security|auth|check|guard|restrict)\b",
    r"\bgrant\s+(access|permission|role)\b",
    r"\b(sudo|root|admin)\s+(access|command|execute)\b",
    r"\bmodify\s+(permission|role|access|policy)\b",
]

# Role-specific expected content patterns
ROLE_CONTENT_PATTERNS = {
    RECCLINRole.RESEARCHER: [
        r"\b(source|citation|reference|evidence|study|paper|report)\b",
        r"\b(find|search|verify|confirm|investigate)\b",
    ],
    RECCLINRole.EDITOR: [
        r"\b(revise|edit|refine|restructure|rewrite|proofread)\b",
        r"\b(clarity|tone|voice|structure|flow|readability)\b",
    ],
    RECCLINRole.CODER: [
        r"\b(function|class|module|variable|import|def|return)\b",
        r"\b(debug|test|compile|deploy|refactor|implement)\b",
    ],
    RECCLINRole.CALCULATOR: [
        r"\b(calculate|compute|analyze|model|forecast|estimate)\b",
        r"\b(data|metric|percentage|ratio|mean|median|standard deviation)\b",
    ],
    RECCLINRole.LIAISON: [
        r"\b(coordinate|communicate|stakeholder|team|meeting)\b",
        r"\b(message|email|draft|respond|follow.up)\b",
    ],
    RECCLINRole.IDEATOR: [
        r"\b(brainstorm|generate|creative|idea|option|alternative)\b",
        r"\b(concept|approach|strategy|innovation|propose)\b",
    ],
    RECCLINRole.NAVIGATOR: [
        r"\b(synthesize|compare|dissent|trade.off|consensus)\b",
        r"\b(convergence|divergence|summary|overview)\b",
    ],
}


class IntentAnalyzer:
    """Inspects prompt sequences for alignment with declared RECCLIN role scope.

    Maintains a rolling window of intent snapshots per operator.
    Detects:
    - Scope narrowing (reconnaissance patterns)
    - Privilege escalation gradients
    - Role incoherence (content mismatching declared role)
    - Chain signature matches from the attack library
    """

    def __init__(self, config: OverwatchConfig):
        self.config = config
        self._intent_windows: Dict[str, deque] = {}  # operator_id -> window
        self._chain_library: List[ChainSignature] = []

    def load_chain_library(self, signatures: List[ChainSignature]) -> None:
        """Load the chain signature library for matching."""
        self._chain_library = signatures

    def add_chain_signature(self, signature: ChainSignature) -> None:
        """Add a new chain signature (from Factics adaptation cycle)."""
        self._chain_library.append(signature)

    # -------------------------------------------------------------------
    # Core Analysis
    # -------------------------------------------------------------------

    def analyze(self, transaction: TransactionRecord) -> List[InspectionFinding]:
        """Analyze a transaction for intent alignment.
        Returns list of findings (empty if fully aligned)."""
        findings = []

        # Resource guard: truncate oversized prompt_text before scanning
        max_len = self.config.max_scan_text_length
        original_prompt_len = len(transaction.prompt_text)
        if original_prompt_len > max_len:
            transaction.prompt_text = transaction.prompt_text[:max_len]
            findings.append(InspectionFinding(
                domain=InspectionDomain.INTENT,
                result=AlignmentResult.FLAGGED,
                severity=Severity.ADVISORY,
                confidence=1.0,
                description=(
                    f"prompt_text truncated from {original_prompt_len} "
                    f"to {max_len} characters for intent scanning"
                ),
                evidence_chain=[
                    f"Original length: {original_prompt_len}",
                    f"max_scan_text_length: {max_len}"
                ],
                transaction_id=transaction.transaction_id
            ))

        # Build intent snapshot for this transaction
        snapshot = self._build_snapshot(transaction)

        # Add to rolling window
        window = self._get_window(transaction.operator_id)
        window.append(snapshot)

        # Run detection checks
        scope_finding = self._check_scope_trajectory(
            transaction.operator_id, transaction.transaction_id
        )
        if scope_finding:
            findings.append(scope_finding)

        privilege_finding = self._check_privilege_gradient(
            transaction.operator_id, transaction.transaction_id
        )
        if privilege_finding:
            findings.append(privilege_finding)

        coherence_finding = self._check_role_coherence(
            snapshot, transaction.transaction_id
        )
        if coherence_finding:
            findings.append(coherence_finding)

        chain_finding = self._check_chain_signatures(
            transaction.operator_id, transaction.transaction_id
        )
        if chain_finding:
            findings.append(chain_finding)

        return findings

    # -------------------------------------------------------------------
    # Snapshot Construction
    # -------------------------------------------------------------------

    def _build_snapshot(self, transaction: TransactionRecord) -> IntentSnapshot:
        """Extract intent indicators from a transaction."""
        snapshot = IntentSnapshot(
            transaction_id=transaction.transaction_id,
            timestamp=transaction.timestamp,
            recclin_role=transaction.recclin_role
        )

        text = transaction.prompt_text.lower()

        # Scope indicators (recon patterns)
        for pattern in RECON_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                snapshot.scope_indicators.append(pattern)

        # Privilege indicators
        for pattern in PRIVILEGE_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                snapshot.privilege_indicators.append(pattern)

        # Role coherence and role score map
        snapshot.role_coherence_score = self._compute_role_coherence(
            text, transaction.recclin_role
        )

        # Build role_score_map: compute scores for all roles
        snapshot.role_score_map = {}
        for role in RECCLINRole:
            role_patterns = ROLE_CONTENT_PATTERNS.get(role, [])
            if role_patterns:
                matches = sum(1 for pattern in role_patterns if re.search(pattern, text, re.IGNORECASE))
                snapshot.role_score_map[role.value] = matches / len(role_patterns)
            else:
                snapshot.role_score_map[role.value] = 1.0

        return snapshot

    def _compute_role_coherence(self, text: str, role: RECCLINRole) -> float:
        """Compute how well content matches the declared RECCLIN role.
        Returns 0.0 (no match) to 1.0 (full match)."""
        role_patterns = ROLE_CONTENT_PATTERNS.get(role, [])
        if not role_patterns:
            return 1.0

        matches = 0
        for pattern in role_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                matches += 1

        # Also check if content matches OTHER roles better
        best_other_score = 0.0
        for other_role, other_patterns in ROLE_CONTENT_PATTERNS.items():
            if other_role == role:
                continue
            other_matches = 0
            for pattern in other_patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    other_matches += 1
            if other_patterns:
                other_score = other_matches / len(other_patterns)
                best_other_score = max(best_other_score, other_score)

        own_score = matches / len(role_patterns) if role_patterns else 1.0

        # Coherence is high when own role matches well and other roles do not
        if best_other_score > own_score and best_other_score > 0.5:
            return max(0.0, own_score - (best_other_score - own_score))

        return own_score

    # -------------------------------------------------------------------
    # Detection Checks
    # -------------------------------------------------------------------

    def _check_scope_trajectory(
        self, operator_id: str, transaction_id: str
    ) -> Optional[InspectionFinding]:
        """Detect progressive scope narrowing (reconnaissance pattern)."""
        window = self._get_window(operator_id)
        if len(window) < 3:
            return None

        # Count scope indicators across the window
        recent = list(window)
        indicator_counts = [len(s.scope_indicators) for s in recent]

        # Check for increasing trend
        if len(indicator_counts) >= 3:
            increasing = all(
                indicator_counts[i] <= indicator_counts[i + 1]
                for i in range(len(indicator_counts) - 3, len(indicator_counts) - 1)
            )
            total_indicators = sum(indicator_counts[-3:])

            if increasing and total_indicators >= 4:
                confidence = min(1.0, total_indicators / 8.0)
                if confidence >= self.config.scope_narrowing_threshold:
                    return InspectionFinding(
                        domain=InspectionDomain.INTENT,
                        result=AlignmentResult.FLAGGED,
                        severity=Severity.WARNING,
                        confidence=confidence,
                        description=(
                            f"Scope narrowing detected across {len(recent)} transactions. "
                            f"Reconnaissance indicator count increasing: {indicator_counts[-3:]}"
                        ),
                        evidence_chain=[
                            f"Transaction {s.transaction_id}: {len(s.scope_indicators)} recon indicators"
                            for s in recent[-3:]
                        ],
                        transaction_id=transaction_id
                    )
        return None

    def _check_privilege_gradient(
        self, operator_id: str, transaction_id: str
    ) -> Optional[InspectionFinding]:
        """Detect privilege escalation gradient across the transaction window."""
        window = self._get_window(operator_id)
        if len(window) < 2:
            return None

        recent = list(window)
        priv_counts = [len(s.privilege_indicators) for s in recent]

        # Compute gradient: rate of increase in privilege indicators
        if len(priv_counts) >= 2:
            gradient = (priv_counts[-1] - priv_counts[0]) / len(priv_counts)
            if gradient > self.config.privilege_escalation_gradient_threshold:
                confidence = min(1.0, gradient / 1.0)
                return InspectionFinding(
                    domain=InspectionDomain.INTENT,
                    result=AlignmentResult.FLAGGED,
                    severity=Severity.CRITICAL,
                    confidence=confidence,
                    description=(
                        f"Privilege escalation gradient detected: {gradient:.2f} "
                        f"(threshold: {self.config.privilege_escalation_gradient_threshold})"
                    ),
                    evidence_chain=[
                        f"Transaction {s.transaction_id}: {len(s.privilege_indicators)} privilege indicators"
                        for s in recent
                    ],
                    transaction_id=transaction_id
                )
        return None

    def _check_role_coherence(
        self, snapshot: IntentSnapshot, transaction_id: str
    ) -> Optional[InspectionFinding]:
        """Detect content that does not match the declared RECCLIN role.
        Only flags when another role matches significantly better,
        indicating a confused deputy condition. Generic queries that
        match no role-specific patterns are not flagged."""
        # Only flag when coherence is low AND another role would score higher
        # A score of 0.0 with no better alternative means generic content, not confusion
        if snapshot.role_coherence_score < 0.3:
            # Check if any other role would have scored significantly better
            declared_role_score = snapshot.role_score_map.get(snapshot.recclin_role.value, 0.0)
            best_alternate = None
            best_alternate_score = 0.0

            for role_value, score in snapshot.role_score_map.items():
                if role_value == snapshot.recclin_role.value:
                    continue
                if score > best_alternate_score:
                    best_alternate_score = score
                    best_alternate = role_value

            # Flag if best alternate scores > 0.5 and beats declared role by > 0.2
            if best_alternate and best_alternate_score > 0.5 and (best_alternate_score - declared_role_score) > 0.2:
                return InspectionFinding(
                    domain=InspectionDomain.INTENT,
                    result=AlignmentResult.FLAGGED,
                    severity=Severity.WARNING,
                    confidence=1.0 - snapshot.role_coherence_score,
                    description=(
                        f"Role coherence low: content matches {snapshot.recclin_role.value} "
                        f"at {snapshot.role_coherence_score:.1%} while {best_alternate} "
                        f"matches significantly better. Possible confused deputy condition."
                    ),
                    evidence_chain=[
                        f"Declared role: {snapshot.recclin_role.value} (score: {declared_role_score:.2f})",
                        f"Best alternate: {best_alternate} (score: {best_alternate_score:.2f})",
                        f"Coherence score: {snapshot.role_coherence_score:.2f}"
                    ],
                    transaction_id=transaction_id
                )
        return None

    def _check_chain_signatures(
        self, operator_id: str, transaction_id: str
    ) -> Optional[InspectionFinding]:
        """Match current transaction window against chain signature library."""
        window = self._get_window(operator_id)
        if len(window) < 2 or not self._chain_library:
            return None

        # Build abstract step sequence from window
        current_sequence = []
        for snapshot in window:
            step = self._abstract_step(snapshot)
            current_sequence.append(step)

        # Match against library
        for signature in self._chain_library:
            if len(current_sequence) >= signature.min_chain_length:
                match_score = self._sequence_match(
                    current_sequence, signature.step_sequence
                )
                if match_score >= self.config.chain_signature_match_threshold:
                    signature.detection_count += 1
                    return InspectionFinding(
                        domain=InspectionDomain.INTENT,
                        result=AlignmentResult.FLAGGED,
                        severity=Severity.CRITICAL,
                        confidence=match_score,
                        description=(
                            f"Chain signature match: '{signature.name}' "
                            f"({signature.pattern_type}) at {match_score:.0%} confidence"
                        ),
                        evidence_chain=[
                            f"Signature: {signature.signature_id}",
                            f"Pattern: {' -> '.join(signature.step_sequence)}",
                            f"Current: {' -> '.join(current_sequence[-len(signature.step_sequence):])}"
                        ],
                        transaction_id=transaction_id,
                        chain_signature_match=signature.signature_id
                    )
        return None

    # -------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------

    def _get_window(self, operator_id: str) -> deque:
        """Get or create the rolling intent window for an operator."""
        if operator_id not in self._intent_windows:
            self._intent_windows[operator_id] = deque(
                maxlen=self.config.intent_window_size
            )
        return self._intent_windows[operator_id]

    @staticmethod
    def _abstract_step(snapshot: IntentSnapshot) -> str:
        """Convert an intent snapshot to an abstract step descriptor."""
        if snapshot.privilege_indicators:
            return "privilege_probe"
        if len(snapshot.scope_indicators) >= 3:
            return "deep_recon"
        if snapshot.scope_indicators:
            return "recon"
        if snapshot.role_coherence_score < 0.3:
            return "role_deviation"
        return "normal"

    @staticmethod
    def _sequence_match(current: List[str], pattern: List[str]) -> float:
        """Compute how well a current sequence matches a signature pattern.
        Uses substring matching with order preservation."""
        if not pattern:
            return 0.0

        # Check if pattern appears as a subsequence of current
        pattern_idx = 0
        matched = 0
        for step in current:
            if pattern_idx < len(pattern) and step == pattern[pattern_idx]:
                matched += 1
                pattern_idx += 1

        return matched / len(pattern)

    def get_intent_trajectory(self, operator_id: str) -> List[Dict[str, Any]]:
        """Get the current intent trajectory for an operator (for audit reports)."""
        window = self._get_window(operator_id)
        return [
            {
                "transaction_id": s.transaction_id,
                "role": s.recclin_role.value,
                "scope_indicators": len(s.scope_indicators),
                "privilege_indicators": len(s.privilege_indicators),
                "role_coherence": s.role_coherence_score
            }
            for s in window
        ]
