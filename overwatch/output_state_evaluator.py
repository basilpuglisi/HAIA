"""
HAIA-Overwatch v1.0 - Output State Evaluator

Part 2, Output State Domain. Evaluates whether platform responses imply
state changes within the declared task scope. Detects confused deputy
conditions, unauthorized state changes, and role-behavior envelope violations.

Author: Basil C. Puglisi, MPA
License: CC BY-NC 4.0
"""

import re
from typing import Any, Dict, List, Optional

from .models import (
    AlignmentResult, DeclaredTaskScope, InspectionDomain, InspectionFinding,
    OverwatchConfig, RECCLINRole, RoleBehaviorEnvelope, Severity, TransactionRecord
)


# ---------------------------------------------------------------------------
# State Change Detection Patterns
# ---------------------------------------------------------------------------

# Code patterns indicating state changes
STATE_CHANGE_PATTERNS = {
    "network_operation": [
        r"\brequests?\.(get|post|put|delete|patch)\s*\(",
        r"\burllib\b",
        r"\bhttpx?\b",
        r"\bsocket\b",
        r"\bfetch\s*\(",
        r"\bcurl\b",
        r"\bwget\b",
        r"\bhttp[s]?://\S+",
    ],
    "file_system_modification": [
        r"\bopen\s*\([^)]*['\"][wa][+'\"]*\s*\)",
        r"\bos\.(remove|unlink|rmdir|makedirs|rename|chmod)\b",
        r"\bshutil\.(rmtree|move|copy)\b",
        r"\bpathlib.*\.(write|unlink|mkdir|rmdir)\b",
        r"\bwith\s+open\s*\(",
    ],
    "credential_access": [
        r"\b(password|passwd|credential|secret|token|api_key)\b",
        r"\bos\.environ\s*\[",
        r"\bgetenv\s*\(",
        r"\b\.env\b",
        r"\bkeyring\b",
        r"\bvault\b",
    ],
    "privilege_escalation": [
        r"\bsudo\b",
        r"\bchmod\s+[0-7]{3,4}\b",
        r"\bchown\b",
        r"\bsetuid\b",
        r"\b(su|runas)\s+",
    ],
    "code_execution": [
        r"\bexec\s*\(",
        r"\beval\s*\(",
        r"\bsubprocess\.(call|run|Popen|check_output)\b",
        r"\bos\.(system|popen|exec)\b",
        r"\b__import__\s*\(",
        r"\bcompile\s*\(",
    ],
    "database_modification": [
        r"\b(INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE)\s+",
        r"\bDROP\s+TABLE\b",
        r"\bDROP\s+DATABASE\b",
        r"\bALTER\s+TABLE\b",
    ],
}

# Default role-behavior envelopes
DEFAULT_ENVELOPES: Dict[RECCLINRole, RoleBehaviorEnvelope] = {
    RECCLINRole.RESEARCHER: RoleBehaviorEnvelope(
        role=RECCLINRole.RESEARCHER,
        expected_output_types=["citations", "source_lists", "evidence_summaries", "analysis"],
        forbidden_patterns=["subprocess", "os.system", "exec(", "eval(", "socket", "requests.post"],
    ),
    RECCLINRole.EDITOR: RoleBehaviorEnvelope(
        role=RECCLINRole.EDITOR,
        expected_output_types=["revised_text", "structural_feedback", "style_corrections"],
        forbidden_patterns=["subprocess", "os.system", "exec(", "socket", "DROP TABLE"],
    ),
    RECCLINRole.CODER: RoleBehaviorEnvelope(
        role=RECCLINRole.CODER,
        expected_output_types=["code_blocks", "function_definitions", "imports", "tests"],
        forbidden_patterns=[],  # Coder legitimately produces code, so narrower constraints
    ),
    RECCLINRole.CALCULATOR: RoleBehaviorEnvelope(
        role=RECCLINRole.CALCULATOR,
        expected_output_types=["calculations", "formulas", "data_analysis", "charts"],
        forbidden_patterns=["subprocess", "os.system", "socket", "requests", "exec("],
    ),
    RECCLINRole.LIAISON: RoleBehaviorEnvelope(
        role=RECCLINRole.LIAISON,
        expected_output_types=["messages", "summaries", "coordination_notes"],
        forbidden_patterns=["subprocess", "os.system", "exec(", "eval(", "socket", "DROP TABLE"],
    ),
    RECCLINRole.IDEATOR: RoleBehaviorEnvelope(
        role=RECCLINRole.IDEATOR,
        expected_output_types=["ideas", "concepts", "alternatives", "brainstorm_lists"],
        forbidden_patterns=["subprocess", "os.system", "exec(", "eval(", "socket"],
    ),
    RECCLINRole.NAVIGATOR: RoleBehaviorEnvelope(
        role=RECCLINRole.NAVIGATOR,
        expected_output_types=["synthesis", "trade_offs", "dissent_documentation"],
        forbidden_patterns=["subprocess", "os.system", "exec(", "eval(", "socket"],
    ),
}


# ---------------------------------------------------------------------------
# Obfuscation Normalization Patterns
# ---------------------------------------------------------------------------

# Patterns for string concatenation: 'o' + 's' → os
_STRING_CONCAT_PATTERN = re.compile(
    r"""['"]([^'"]{1,10})['"]\s*\+\s*['"]([^'"]{1,10})['"]""",
    re.DOTALL
)

# chr() sequences: chr(111)+chr(115) → os
_CHR_CALL_PATTERN = re.compile(
    r"""chr\s*\(\s*(\d+)\s*\)""",
    re.IGNORECASE
)

# getattr(__import__('os'), 'system') → os.system
_GETATTR_IMPORT_PATTERN = re.compile(
    r"""getattr\s*\(\s*__import__\s*\(\s*['"]([^'"]+)['"]\s*\)\s*,\s*['"]([^'"]+)['"]\s*\)""",
    re.IGNORECASE
)

# __import__('os') → import os
_DUNDER_IMPORT_PATTERN = re.compile(
    r"""__import__\s*\(\s*['"]([^'"]+)['"]\s*\)""",
    re.IGNORECASE
)


def _normalize_for_detection(text: str) -> str:
    """Collapse common Python obfuscation patterns before regex scanning.

    Handles:
    - String concatenation: 'o'+'s' → os
    - chr() sequences: chr(111)+chr(115) → os
    - getattr(__import__('os'), 'system') → os.system
    - __import__('os') → import os

    Returns the original text with obfuscated patterns expanded inline,
    enabling downstream regex patterns to match.
    """
    normalized = text

    # Pass 1: Resolve string concatenation (iterative, handles chains)
    for _ in range(5):  # Max 5 iterations to handle nested concat
        prev = normalized
        normalized = _STRING_CONCAT_PATTERN.sub(
            lambda m: f"'{m.group(1)}{m.group(2)}'", normalized
        )
        if normalized == prev:
            break

    # Pass 2: Resolve chr() sequences
    def _resolve_chr(match):
        try:
            code = int(match.group(1))
            if 32 <= code <= 126:
                return chr(code)
        except (ValueError, OverflowError):
            pass
        return match.group(0)

    normalized = _CHR_CALL_PATTERN.sub(_resolve_chr, normalized)

    # Pass 3: Resolve getattr(__import__(...), ...) → module.attr
    normalized = _GETATTR_IMPORT_PATTERN.sub(
        lambda m: f"{m.group(1)}.{m.group(2)}", normalized
    )

    # Pass 4: Resolve bare __import__('x') → x
    normalized = _DUNDER_IMPORT_PATTERN.sub(
        lambda m: m.group(1), normalized
    )

    return normalized


class OutputStateEvaluator:
    """Evaluates platform responses for state-change implications.

    Detects:
    - Unauthorized state changes (network, file system, credentials, privilege)
    - Role-behavior envelope violations (output type mismatch)
    - Confused deputy patterns (authorized role producing unauthorized actions)
    - Progressive context manipulation (output reframing task parameters)
    """

    def __init__(self, config: OverwatchConfig):
        self.config = config
        self._envelopes: Dict[RECCLINRole, RoleBehaviorEnvelope] = dict(DEFAULT_ENVELOPES)

    def set_envelope(self, envelope: RoleBehaviorEnvelope) -> None:
        """Set or update a role-behavior envelope (from Factics adaptation)."""
        self._envelopes[envelope.role] = envelope

    def get_envelope(self, role: RECCLINRole) -> RoleBehaviorEnvelope:
        """Get the current envelope for a role."""
        return self._envelopes.get(role, RoleBehaviorEnvelope(role=role))

    # -------------------------------------------------------------------
    # Core Analysis
    # -------------------------------------------------------------------

    def analyze(self, transaction: TransactionRecord) -> List[InspectionFinding]:
        """Analyze transaction outputs for state-change alignment."""
        findings = []

        # Handle empty responses
        if not transaction.responses:
            findings.append(InspectionFinding(
                domain=InspectionDomain.OUTPUT_STATE,
                result=AlignmentResult.FLAGGED,
                severity=Severity.ADVISORY,
                confidence=0.5,
                description="No platform responses received for inspection.",
                evidence_chain=["Transaction has zero responses"],
                transaction_id=transaction.transaction_id
            ))
            return findings

        for response in transaction.responses:
            # State change detection
            state_findings = self._detect_state_changes(
                response.response_text,
                transaction.recclin_role,
                transaction.transaction_id,
                response.platform_id,
                transaction.task_scope
            )
            findings.extend(state_findings)

            # Role-behavior envelope check
            envelope_findings = self._check_role_envelope(
                response.response_text,
                transaction.recclin_role,
                transaction.transaction_id,
                response.platform_id
            )
            findings.extend(envelope_findings)

        # Navigator output inspection (if present)
        if transaction.navigator_output:
            nav_findings = self._inspect_navigator_output(
                transaction.navigator_output,
                transaction.navigator_input,
                transaction.transaction_id
            )
            findings.extend(nav_findings)

        return findings

    # -------------------------------------------------------------------
    # State Change Detection
    # -------------------------------------------------------------------

    def _detect_state_changes(
        self, text: str, role: RECCLINRole, transaction_id: str, platform_id: str,
        task_scope: Optional[DeclaredTaskScope] = None
    ) -> List[InspectionFinding]:
        """Detect state-change patterns in output and evaluate against role scope.

        Runs obfuscation normalization before pattern matching to defeat
        string concatenation, chr() sequences, and getattr(__import__()) evasion.
        """
        findings = []
        if not text:
            return findings

        # Normalize obfuscated patterns before scanning
        scan_text = _normalize_for_detection(text)

        envelope = self.get_envelope(role)

        for change_category, patterns in STATE_CHANGE_PATTERNS.items():
            for pattern in patterns:
                matches = list(re.finditer(pattern, scan_text, re.IGNORECASE))
                if matches:
                    # ALWAYS create a finding for every detected state change
                    # but adjust severity based on role and task scope
                    match_text = matches[0].group()[:80]

                    # Determine severity based on role and task scope
                    severity = self._compute_state_change_severity(
                        change_category, role, task_scope
                    )

                    findings.append(InspectionFinding(
                        domain=InspectionDomain.OUTPUT_STATE,
                        result=AlignmentResult.FLAGGED,
                        severity=severity,
                        confidence=0.8,
                        description=(
                            f"State change detected in {role.value} output from "
                            f"{platform_id}: {change_category}"
                        ),
                        evidence_chain=[
                            f"Category: {change_category}",
                            f"Role: {role.value}",
                            f"Platform: {platform_id}",
                            f"Pattern match: {match_text}",
                            f"Match count: {len(matches)}"
                        ],
                        transaction_id=transaction_id
                    ))
                    break  # One finding per category per response

        return findings

    def _compute_state_change_severity(
        self, category: str, role: RECCLINRole,
        task_scope: Optional[DeclaredTaskScope] = None
    ) -> Severity:
        """Determine severity based on state change category, role, and task scope."""
        # Coder-specific severity mapping
        if role == RECCLINRole.CODER:
            if category == "credential_access":
                return Severity.CRITICAL
            elif category == "privilege_escalation":
                return Severity.CRITICAL
            elif category == "code_execution":
                # ADVISORY if allowed in task scope, else WARNING
                if task_scope and task_scope.allow_subprocess:
                    return Severity.ADVISORY
                return Severity.WARNING
            elif category == "network_operation":
                # ADVISORY if allowed in task scope, else WARNING
                if task_scope and task_scope.allow_network:
                    return Severity.ADVISORY
                return Severity.WARNING
            elif category == "file_system_modification":
                # ADVISORY if allowed in task scope, else WARNING
                if task_scope and task_scope.allow_file_write:
                    return Severity.ADVISORY
                return Severity.WARNING
            elif category == "database_modification":
                # ADVISORY if allowed in task scope, else WARNING
                if task_scope and task_scope.allow_database_write:
                    return Severity.ADVISORY
                return Severity.WARNING

        # Non-Coder roles
        critical_categories = {"credential_access", "privilege_escalation", "code_execution"}
        if category in critical_categories:
            return Severity.CRITICAL
        return Severity.WARNING

    # -------------------------------------------------------------------
    # Role-Behavior Envelope Check
    # -------------------------------------------------------------------

    def _check_role_envelope(
        self, text: str, role: RECCLINRole, transaction_id: str, platform_id: str
    ) -> List[InspectionFinding]:
        """Check if output matches the role's behavioral envelope."""
        findings = []
        if not text:
            return findings

        envelope = self.get_envelope(role)

        # Check for forbidden patterns in output
        for fp in envelope.forbidden_patterns:
            if fp.lower() in text.lower():
                findings.append(InspectionFinding(
                    domain=InspectionDomain.OUTPUT_STATE,
                    result=AlignmentResult.FLAGGED,
                    severity=Severity.WARNING,
                    confidence=0.75,
                    description=(
                        f"Forbidden pattern '{fp}' detected in {role.value} "
                        f"output from {platform_id}. "
                        f"Possible confused deputy condition."
                    ),
                    evidence_chain=[
                        f"Role: {role.value}",
                        f"Forbidden pattern: {fp}",
                        f"Platform: {platform_id}"
                    ],
                    transaction_id=transaction_id
                ))

        return findings

    # -------------------------------------------------------------------
    # Navigator Output Inspection
    # -------------------------------------------------------------------

    def _inspect_navigator_output(
        self, navigator_output: str, navigator_input: Optional[str],
        transaction_id: str
    ) -> List[InspectionFinding]:
        """Inspect Navigator synthesis for content divergence from inputs.
        Detects context poisoning through the synthesis path."""
        findings = []

        if not navigator_input or not navigator_output:
            return findings

        # Structural comparison: significant length changes may indicate
        # content injection or omission
        input_len = len(navigator_input)
        output_len = len(navigator_output)

        if input_len > 0:
            ratio = output_len / input_len
            # Navigator synthesis typically condenses (ratio < 1)
            # or modestly expands (ratio 1-2)
            if ratio > 3.0:
                findings.append(InspectionFinding(
                    domain=InspectionDomain.OUTPUT_STATE,
                    result=AlignmentResult.FLAGGED,
                    severity=Severity.ADVISORY,
                    confidence=0.4,
                    description=(
                        f"Navigator output significantly larger than input "
                        f"(ratio: {ratio:.1f}x). Possible content injection "
                        f"through synthesis path."
                    ),
                    evidence_chain=[
                        f"Input length: {input_len}",
                        f"Output length: {output_len}",
                        f"Expansion ratio: {ratio:.1f}x"
                    ],
                    transaction_id=transaction_id
                ))

        # Check navigator output for directive patterns
        # (cross-platform poisoning through synthesis)
        directive_patterns = [
            r"\bignore\s+previous\b",
            r"\bSYSTEM\s+OVERRIDE\b",
            r"\bact\s+as\b",
        ]
        for pattern in directive_patterns:
            if re.search(pattern, navigator_output, re.IGNORECASE):
                findings.append(InspectionFinding(
                    domain=InspectionDomain.OUTPUT_STATE,
                    result=AlignmentResult.FLAGGED,
                    severity=Severity.CRITICAL,
                    confidence=0.85,
                    description=(
                        f"Directive pattern detected in Navigator synthesis output. "
                        f"Possible cross-platform poisoning through synthesis path."
                    ),
                    evidence_chain=[
                        f"Pattern: {pattern}",
                        f"Location: Navigator output"
                    ],
                    transaction_id=transaction_id
                ))

        return findings

    # -------------------------------------------------------------------
    # Envelope Management
    # -------------------------------------------------------------------

    def record_clean_transaction(
        self, role: RECCLINRole, output_text: str
    ) -> None:
        """Record a CBG-verified clean transaction to refine the envelope."""
        envelope = self.get_envelope(role)
        envelope.sample_count += 1
        # In production, this would update output length baselines,
        # confidence ranges, and expected output type distributions

    def tighten_envelope(
        self, role: RECCLINRole, new_forbidden: str
    ) -> None:
        """Add a new forbidden pattern to a role envelope (Factics tactic)."""
        envelope = self.get_envelope(role)
        if new_forbidden not in envelope.forbidden_patterns:
            envelope.forbidden_patterns.append(new_forbidden)

    def widen_envelope(
        self, role: RECCLINRole, remove_forbidden: str
    ) -> None:
        """Remove a forbidden pattern (CBG false positive correction)."""
        envelope = self.get_envelope(role)
        if remove_forbidden in envelope.forbidden_patterns:
            envelope.forbidden_patterns.remove(remove_forbidden)
