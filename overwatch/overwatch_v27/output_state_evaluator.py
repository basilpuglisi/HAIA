"""
HAIA-Overwatch v2.7 - Output State Evaluator

Part 2, Output State Domain. Evaluates whether platform responses imply
state changes within the declared task scope. Detects confused deputy
conditions, unauthorized state changes, and role-behavior envelope violations.

v2.7 (Basil's fix round, finding T-1): a web address or an SQL keyword in
an answer is classified before it is scored. A performed operation (code,
SQL grammar) or an instructed one (an imperative operation verb with an
outside address or an operational object) is scored as published. A quoted
or cited one (an address the Request handed the platform, a citation field,
a Sources line, a link, a parenthesis) or an ordinary English word keeps
its finding, downgraded and logged as a warning. No pattern changed. Error
text GOPEL recorded for a failed call is inspected like an answer, the
Navigator's synthesis is checked for directives without its input, and a
role envelope keeps every pattern it was published with.

Author: Basil C. Puglisi, MPA
License: CC BY-NC 4.0
"""

import json
import re
from typing import Any, Dict, List, Optional, Tuple

from .models import (
    AlignmentResult, DeclaredTaskScope, InspectionDomain, InspectionFinding,
    OverwatchConfig, RECCLINRole, RoleBehaviorEnvelope, Severity, TransactionRecord
)
from .structured_logger import get_logger

logger = get_logger(__name__)


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

# v2.7: the forbidden patterns each role was published with, frozen at
# import. They are a hard floor: no false positive ruling removes them.
PUBLISHED_FORBIDDEN_PATTERNS: Dict[RECCLINRole, Tuple[str, ...]] = {
    role: tuple(envelope.forbidden_patterns) for role, envelope in DEFAULT_ENVELOPES.items()
}


# ---------------------------------------------------------------------------
# v2.7: performed or instructed, told apart from quoted or cited (T-1)
# ---------------------------------------------------------------------------

# The published patterns whose matches are classified. Every other pattern
# is a code form (a call, a command, SQL grammar) and counts as performed.
CLASSIFIED_PATTERNS = {
    "network_operation": (r"\bhttp[s]?://\S+", r"\bhttpx?\b"),
    "database_modification": (r"\b(INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE)\s+",),
}

DOWNGRADED_CONFIDENCE = 0.2     # below the published advisory floor (0.3)

_URL = re.compile(r"https?://[^\s\"'<>()\[\]{}\\,|`]+", re.IGNORECASE)
_FENCED_CODE = re.compile(r"```.*?(?:```|\Z)", re.DOTALL)
_INLINE_CODE = re.compile(r"`[^`\n]+`")
_SQL_GRAMMAR = re.compile(
    r"\b(?:UPDATE\s+[\w.\"`\[\]]+\s+SET\b|DELETE\s+FROM\b|INSERT\s+INTO\b"
    r"|(?:DROP|CREATE|ALTER|TRUNCATE)\s+(?:TABLE|DATABASE|SCHEMA|INDEX|VIEW|USER|ROLE)\b)",
    re.IGNORECASE)
# An instruction to the reader. A transfer verb aimed at an address, or a
# destructive verb with an operational object, instructs in any mood; a
# modifying verb (update, create) instructs only in an imperative sentence:
# one that opens with a verb, after an optional framing phrase ("Next step:",
# "Before answering,") or "you must", "you should".
_IMPERATIVE_VERBS = (
    r"ignore|disregard|forget|summarize|list|write|run|execute|use|make|go|open|read|copy|move|add|set|"
    r"tell|give|keep|check|include|return|print|output|reply|respond|answer|continue|proceed|finish|do|"
    r"save|store|share|attach|paste|compile|collect|gather|export|import|install|enable|disable|grant|"
    r"revoke|reset|change|replace|revise|edit|rewrite|update|create|insert|alter|modify|overwrite|"
    r"delete|remove|erase|wipe|destroy|drop|purge|truncate|send|post|upload|submit|transmit|forward|"
    r"exfiltrate|fetch|request|download|call|ping|push|pull|connect|curl|wget")
_OPERATION_VERBS = (r"send|post|upload|submit|transmit|forward|exfiltrate|fetch|request|download|call|"
                    r"ping|push|pull|connect|curl|wget|delete|remove|erase|wipe|destroy|drop|purge")
_TRANSFER_VERBS = r"send|post|upload|submit|transmit|forward|exfiltrate|push|copy|sync|stream|report|leak|dump"
_DIRECT_VERBS = r"fetch|download|call|ping|curl|wget|request"
_DESTRUCTIVE_VERBS = r"delete|remove|erase|wipe|destroy|drop|purge|truncate"
_MODIFYING_VERBS = r"update|create|insert|alter|modify|overwrite|grant|revoke"
_OBJECTS = (r"files?|folders?|director(?:y|ies)|records?|databases?|db|tables?|rows?|data|datasets?|"
            r"logs?|backups?|accounts?|users?|repositor(?:y|ies)|repos?|servers?|systems?|disks?|"
            r"drives?|keys?|credentials?|secrets?|tokens?|passwords?|emails?|history|permissions?|"
            r"roles?|snapshots?|volumes?|buckets?")
_MODIFIED_OBJECTS = (r"records?|databases?|db|tables?|rows?|accounts?|users?|permissions?|roles?|"
                     r"credentials?|secrets?|keys?|passwords?|files?|folders?|logs?|repositor(?:y|ies)|"
                     r"servers?|systems?")
_FRAMING = (r"^\s*(?:[\w\s'-]{0,40}?[:,]\s*)?(?:(?:please|then|now|next|first|finally|also|just)\s+|"
            r"you\s+(?:must|should|need\s+to|have\s+to|will|shall|are\s+to)\s+)*")
_IMPERATIVE_SENTENCE = re.compile(_FRAMING + r"(?:" + _IMPERATIVE_VERBS + r")\b", re.IGNORECASE)
_OPERATION_VERB = re.compile(r"\b(?:" + _OPERATION_VERBS + r")\b", re.IGNORECASE)
_TRANSFER_TO_ADDRESS = re.compile(
    r"\b(?:" + _TRANSFER_VERBS + r")\b[^.!?\n]{0,80}?\b(?:to|into|at|via|on)\s*$", re.IGNORECASE)
_DIRECT_AT_ADDRESS = re.compile(r"\b(?:" + _DIRECT_VERBS + r")\s*:?\s*$", re.IGNORECASE)
_DESTRUCTION = re.compile(
    r"\b(?:" + _DESTRUCTIVE_VERBS + r")\b(?:\s+[\w'-]+){0,5}?\s+(?:" + _OBJECTS + r")\b", re.IGNORECASE)
_MODIFICATION = re.compile(
    r"\b(?:" + _MODIFYING_VERBS + r")\b(?:\s+[\w'-]+){0,5}?\s+(?:" + _MODIFIED_OBJECTS + r")\b", re.IGNORECASE)
_CITATION_HEADING = re.compile(
    r"^\s*[-*\u2022]?\s*\**\s*(?:sources?|references?|citations?|links?|see also|works cited|"
    r"bibliography|further reading)\s*\**\s*:", re.IGNORECASE)
_CITATION_BLOCK_HEADING = re.compile(
    r"^\s*\**\s*(?:sources?|references?|citations?|links?|works cited|bibliography)\s*\**\s*:?\s*$",
    re.IGNORECASE)
_CITATION_KEYS = {"url", "urls", "source", "sources", "source_url", "link", "links", "href", "citation",
                  "citations", "reference", "references", "page_quote", "cite", "cited"}
_SENTENCE_END = re.compile(r"(?<=[.!?])\s+|\n")


def _spans(pattern: re.Pattern, text: str) -> List[Tuple[int, int]]:
    return [m.span() for m in pattern.finditer(text)]


def _inside(pos: int, spans: List[Tuple[int, int]]) -> bool:
    return any(a <= pos < b for a, b in spans)


def _sentence_at(text: str, pos: int) -> Tuple[int, int]:
    start = 0
    for m in _SENTENCE_END.finditer(text):
        if m.end() <= pos:
            start = m.end()
        else:
            return start, m.start()
    return start, len(text)


def _line_at(text: str, pos: int) -> Tuple[int, int]:
    start = text.rfind("\n", 0, pos) + 1
    end = text.find("\n", pos)
    return start, len(text) if end < 0 else end


def _norm_url(url: str) -> str:
    return url.rstrip(".,;:!?'\")]}>").lower()


def _json_values(text: str) -> List[Tuple[str, str]]:
    """(key, string value) pairs of every JSON object or list the answer
    holds, the whole answer or a JSON line or tail of it."""
    found: List[Tuple[str, str]] = []
    candidates = [text]
    for marker in ("{", "["):
        i = text.find(marker)
        while i >= 0:
            candidates.append(text[i:])
            i = text.find(marker, i + 1)
            if len(candidates) > 40:
                break
    decoder = json.JSONDecoder()
    seen = set()
    for c in candidates:
        try:
            obj, _end = decoder.raw_decode(c.strip())
        except (ValueError, TypeError):
            continue
        if id(obj) in seen:
            continue
        seen.add(id(obj))
        stack: List[Tuple[str, Any]] = [("", obj)]
        while stack:
            key, value = stack.pop()
            if isinstance(value, dict):
                stack.extend((str(k), v) for k, v in value.items())
            elif isinstance(value, list):
                stack.extend((key, v) for v in value)
            elif isinstance(value, str):
                found.append((key.lower(), value))
    return found


def _cited_by_json(url: str, pairs: List[Tuple[str, str]]) -> bool:
    for key, value in pairs:
        if (key in _CITATION_KEYS or key.endswith("url") or key.endswith("urls") or key.endswith("_link")) \
                and _norm_url(value.strip()) == _norm_url(url):
            return True
    return False


def _in_citation_block(text: str, pos: int) -> bool:
    """True when the line holding pos follows a Sources or References
    heading line, with no blank line between them."""
    line_start, _ = _line_at(text, pos)
    lines = text[:line_start].split("\n")[:-1]
    for line in reversed(lines):
        if not line.strip():
            return False
        if _CITATION_BLOCK_HEADING.match(line):
            return True
    return False


def classify_address(text: str, start: int, end: int, prompt_text: str,
                     code: List[Tuple[int, int]], pairs: List[Tuple[str, str]]) -> Tuple[str, str]:
    """(class, basis) for the web address at text[start:end]: performed,
    instructed, quoted, cited, or unclassified (scored as published)."""
    url = text[start:end]
    if _inside(start, code):
        return "performed", "in a code block or code span"
    s0, s1 = _sentence_at(text, start)
    sentence = text[s0:s1]
    if _TRANSFER_TO_ADDRESS.search(text[s0:start]) or _DIRECT_AT_ADDRESS.search(text[s0:start]):
        return "instructed", "an operation verb aimed at the address"
    if _IMPERATIVE_SENTENCE.match(sentence) and _OPERATION_VERB.search(sentence):
        return "instructed", "an imperative sentence with an operation verb names the address"
    if _norm_url(url) in {_norm_url(u) for u in _URL.findall(prompt_text or "")}:
        return "quoted", "the address is in the Request that GOPEL recorded for this transaction"
    if _cited_by_json(url, pairs):
        return "cited", "the value of a citation field in the answer's JSON"
    l0, l1 = _line_at(text, start)
    if _CITATION_HEADING.match(text[l0:l1]) or _in_citation_block(text, start):
        return "cited", "on a Sources or References line"
    if text[max(0, start - 2):start] == "](":
        return "cited", "a link target"
    if re.search(r"\([^()]*$", text[s0:start]):
        return "cited", "inside a parenthesis"
    if re.search(r"\b(?:see|cf\.|source|per)\s*:?\s*$", text[max(s0, start - 12):start], re.IGNORECASE):
        return "cited", "introduced as a reference (see, source, per)"
    return "unclassified", "no citation form found; scored as published"


def classify_keyword(text: str, start: int, code: List[Tuple[int, int]]) -> Tuple[str, str]:
    """(class, basis) for an SQL keyword at text[start:]: performed,
    instructed, or a plain English word."""
    if _inside(start, code):
        return "performed", "in a code block or code span"
    if _SQL_GRAMMAR.search(text):
        return "performed", "SQL grammar in the answer"
    s0, s1 = _sentence_at(text, start)
    sentence = text[s0:s1]
    if _DESTRUCTION.search(sentence):
        return "instructed", "a destructive verb with an operational object in the same sentence"
    if _IMPERATIVE_SENTENCE.match(sentence) and _MODIFICATION.search(sentence):
        return "instructed", "an imperative sentence with a modifying verb and an operational object"
    return "plain", "an English word without SQL grammar or an operational object"


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
            # v2.7: an error Response is inspected like any other; its
            # failure text is named as the source it came from.
            for text, source in self._inspected_texts(response):
                # State change detection
                state_findings = self._detect_state_changes(
                    text,
                    transaction.recclin_role,
                    transaction.transaction_id,
                    response.platform_id + source,
                    transaction.task_scope,
                    prompt_text=transaction.prompt_text,
                )
                findings.extend(state_findings)

                # Role-behavior envelope check
                envelope_findings = self._check_role_envelope(
                    text,
                    transaction.recclin_role,
                    transaction.transaction_id,
                    response.platform_id + source
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

    @staticmethod
    def _inspected_texts(response: Any) -> List[Tuple[str, str]]:
        """v2.7: the texts of one Response that are inspected: the answer,
        and the failure text GOPEL recorded when the call failed."""
        texts = [(response.response_text, "")]
        error_detail = (getattr(response, "metadata", None) or {}).get("error_detail")
        if isinstance(error_detail, str) and error_detail:
            texts.append((error_detail, " (error_detail)"))
        return texts

    def _detect_state_changes(
        self, text: str, role: RECCLINRole, transaction_id: str, platform_id: str,
        task_scope: Optional[DeclaredTaskScope] = None, prompt_text: str = ""
    ) -> List[InspectionFinding]:
        """Detect state-change patterns in output and evaluate against role scope.

        Runs obfuscation normalization before pattern matching to defeat
        string concatenation, chr() sequences, and getattr(__import__()) evasion.

        v2.7 (T-1): a match of a classified pattern (a web address, an SQL
        keyword) is scored as published when performed, instructed, or
        unclassified; when every match is quoted, cited, or a plain word,
        the finding is kept downgraded and logged as a warning.
        """
        findings = []
        if not text:
            return findings

        # Normalize obfuscated patterns before scanning
        scan_text = _normalize_for_detection(text)

        envelope = self.get_envelope(role)
        code = _spans(_FENCED_CODE, scan_text) + _spans(_INLINE_CODE, scan_text)
        addresses = _spans(_URL, scan_text)
        pairs: Optional[List[Tuple[str, str]]] = None

        for change_category, patterns in STATE_CHANGE_PATTERNS.items():
            classified = CLASSIFIED_PATTERNS.get(change_category, ())
            downgraded = None
            for pattern in patterns:
                matches = list(re.finditer(pattern, scan_text, re.IGNORECASE))
                if not matches:
                    continue
                scored = None
                classes = []
                if pattern not in classified:
                    scored = (matches[0], None)
                else:
                    for m in matches:
                        if change_category == "network_operation":
                            span = next(((a, b) for a, b in addresses if a <= m.start() < b), None)
                            if span is None:
                                cls, basis = "performed", "a library or protocol name outside an address"
                            else:
                                if pairs is None:
                                    pairs = _json_values(scan_text)
                                cls, basis = classify_address(scan_text, span[0], span[1], prompt_text,
                                                              code, pairs)
                        else:
                            cls, basis = classify_keyword(scan_text, m.start(), code)
                        classes.append((m, cls, basis))
                        if cls in ("performed", "instructed", "unclassified"):
                            scored = (m, (cls, basis))
                            break
                if scored is None:
                    if downgraded is None:
                        downgraded = (matches, classes[0])
                    continue

                # ALWAYS create a finding for every detected state change
                # but adjust severity based on role and task scope
                match, classification = scored
                match_text = match.group()[:80]

                # Determine severity based on role and task scope
                severity = self._compute_state_change_severity(
                    change_category, role, task_scope
                )

                evidence = [
                    f"Category: {change_category}",
                    f"Role: {role.value}",
                    f"Platform: {platform_id}",
                    f"Pattern match: {match_text}",
                    f"Match count: {len(matches)}"
                ]
                if classification is not None:
                    evidence += [f"Classification: {classification[0]}", f"Basis: {classification[1]}"]
                findings.append(InspectionFinding(
                    domain=InspectionDomain.OUTPUT_STATE,
                    result=AlignmentResult.FLAGGED,
                    severity=severity,
                    confidence=0.8,
                    description=(
                        f"State change detected in {role.value} output from "
                        f"{platform_id}: {change_category}"
                    ),
                    evidence_chain=evidence,
                    transaction_id=transaction_id
                ))
                downgraded = None
                break  # One finding per category per response

            if downgraded is not None:
                findings.append(self._downgraded_finding(
                    change_category, role, platform_id, transaction_id, *downgraded))

        return findings

    @staticmethod
    def _downgraded_finding(category: str, role: RECCLINRole, platform_id: str, transaction_id: str,
                            matches: list, first: tuple) -> InspectionFinding:
        """v2.7: a quoted, cited, or plain-word match. The signal is not
        deleted: the finding stays in the outcome below the advisory floor,
        and the log carries it as a warning."""
        match, cls, basis = first
        match_text = match.group()[:80]
        logger.warning(
            "Downgraded state change signal kept as a warning: %s in %s output from %s, %s (%s)",
            category, role.value, platform_id, cls, basis)
        return InspectionFinding(
            domain=InspectionDomain.OUTPUT_STATE,
            result=AlignmentResult.FLAGGED,
            severity=Severity.NOMINAL,
            confidence=DOWNGRADED_CONFIDENCE,
            description=(
                f"Downgraded ({cls}, not performed): state change pattern in {role.value} output from "
                f"{platform_id}: {category}"
            ),
            evidence_chain=[
                f"Category: {category}",
                f"Role: {role.value}",
                f"Platform: {platform_id}",
                f"Pattern match: {match_text}",
                f"Match count: {len(matches)}",
                f"Classification: {cls}",
                f"Basis: {basis}",
            ],
            transaction_id=transaction_id
        )

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

        # v2.7: the directive check needs only the output; GOPEL records
        # carry the Navigator's text, never an assembled input.
        if not navigator_output:
            return findings

        # Structural comparison: significant length changes may indicate
        # content injection or omission
        input_len = len(navigator_input or "")
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
    ) -> bool:
        """Remove a forbidden pattern (CBG false positive correction).

        v2.7: a pattern the role was published with is its hard floor and
        stays, however many false positive rulings ask; the refusal is
        logged. Returns whether a pattern was removed."""
        if remove_forbidden in PUBLISHED_FORBIDDEN_PATTERNS.get(role, ()):
            logger.warning(
                "Envelope not widened: %r is a published %s pattern, a hard floor",
                remove_forbidden, role.value)
            return False
        envelope = self.get_envelope(role)
        if remove_forbidden in envelope.forbidden_patterns:
            envelope.forbidden_patterns.remove(remove_forbidden)
            return True
        return False
