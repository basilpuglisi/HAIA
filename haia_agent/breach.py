"""
HAIA Agent Framework - Breach Detection and Notification
==========================================================
The framework's mechanism for telling humans it has failed or
been compromised. This is the answer to: "How does the agent
notify humans that it has been breached?"

Breach classification follows a five-level severity model:

    NOMINAL:   All systems operating within expected parameters.
    ADVISORY:  Minor anomalies detected. Pipeline continues.
               Human should review at next checkpoint.
    WARNING:   Significant anomalies. Pipeline continues but
               the checkpoint package is flagged for urgent review.
    CRITICAL:  Integrity violation detected. Pipeline PAUSES.
               Human must review before any output is used.
    HALT:      Unrecoverable breach. Pipeline STOPS immediately.
               No output is produced. Incident report generated.

Design constraints:
    - Detection is deterministic (counting, threshold comparison,
      pattern matching). Not cognitive.
    - The framework cannot evaluate whether AI output is "correct"
      or "manipulated." It can only detect structural anomalies,
      integrity violations, and statistical deviations.
    - The human remains the final judge of content quality.
      The breach system tells them WHEN to be extra cautious.

What this system CANNOT detect (and why the human checkpoint exists):
    - Semantically coherent manipulation (a well-crafted lie that
      passes all structural checks)
    - A compromised Navigator producing structurally valid but
      substantively corrupted synthesis
    - Slow poisoning across many transactions where each individual
      transaction looks normal
    - Coordinated platforms producing identical false consensus

These are the irreducible risks that require human judgment.
The breach system's job is to catch everything EXCEPT these,
so the human's attention is focused where it is actually needed.

Author: Basil C. Puglisi, MPA
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional, Callable


# ======================================================================
# Breach Classification
# ======================================================================

class BreachSeverity(str, Enum):
    """Five-level breach severity classification."""
    NOMINAL = "NOMINAL"
    ADVISORY = "ADVISORY"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"
    HALT = "HALT"


class BreachCategory(str, Enum):
    """Classification of what type of breach occurred."""
    INJECTION_DETECTED = "injection_detected"
    TRANSPORT_INTEGRITY = "transport_integrity"
    CHAIN_INTEGRITY = "chain_integrity"
    NAVIGATOR_FORMAT = "navigator_format"
    NAVIGATOR_ANOMALY = "navigator_anomaly"
    LOGGER_FAILURE = "logger_failure"
    WITNESS_MISMATCH = "witness_mismatch"
    SIGNATURE_FAILURE = "signature_failure"
    AUTHENTICATION_FAILURE = "authentication_failure"
    CONFIG_VIOLATION = "config_violation"
    SANITIZATION_BYPASS = "sanitization_bypass"
    DELIMITER_ATTACK = "delimiter_attack"
    METADATA_ANOMALY = "metadata_anomaly"
    RESPONSE_ANOMALY = "response_anomaly"
    CONFIDENCE_ANOMALY = "confidence_anomaly"
    UNICODE_ANOMALY = "unicode_anomaly"


@dataclass
class BreachEvent:
    """A single detected breach or anomaly."""
    category: BreachCategory
    severity: BreachSeverity
    description: str
    evidence: str = ""
    transaction_id: str = ""
    platform_id: str = ""
    timestamp: str = ""
    recommended_action: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {
            "category": self.category.value,
            "severity": self.severity.value,
            "description": self.description,
            "evidence": self.evidence,
            "transaction_id": self.transaction_id,
            "platform_id": self.platform_id,
            "timestamp": self.timestamp,
            "recommended_action": self.recommended_action,
        }


@dataclass
class BreachReport:
    """
    Complete breach report for a pipeline transaction.

    This is the document the human reads when something has gone wrong.
    It tells them: what happened, how severe it is, what they should do,
    and whether they should trust the pipeline's output.
    """
    transaction_id: str
    overall_severity: BreachSeverity = BreachSeverity.NOMINAL
    events: list[BreachEvent] = field(default_factory=list)
    pipeline_halted: bool = False
    output_trustworthy: bool = True
    human_action_required: bool = False
    generated_at: str = ""
    report_hash: str = ""

    def __post_init__(self):
        if not self.generated_at:
            self.generated_at = datetime.now(timezone.utc).isoformat()

    def add_event(self, event: BreachEvent) -> None:
        """Add an event and recalculate overall severity."""
        self.events.append(event)
        self._recalculate()

    def _recalculate(self) -> None:
        """Recalculate report-level fields from events."""
        if not self.events:
            self.overall_severity = BreachSeverity.NOMINAL
            self.output_trustworthy = True
            self.human_action_required = False
            return

        # Overall severity is the highest individual event severity
        severity_order = [
            BreachSeverity.NOMINAL,
            BreachSeverity.ADVISORY,
            BreachSeverity.WARNING,
            BreachSeverity.CRITICAL,
            BreachSeverity.HALT,
        ]
        max_severity = BreachSeverity.NOMINAL
        for e in self.events:
            if severity_order.index(e.severity) > severity_order.index(max_severity):
                max_severity = e.severity

        self.overall_severity = max_severity

        # Multiple warnings escalate to critical
        warning_count = sum(1 for e in self.events if e.severity == BreachSeverity.WARNING)
        if warning_count >= 3 and self.overall_severity == BreachSeverity.WARNING:
            self.overall_severity = BreachSeverity.CRITICAL

        # Advisory count escalation
        advisory_count = sum(1 for e in self.events if e.severity == BreachSeverity.ADVISORY)
        if advisory_count >= 5 and self.overall_severity == BreachSeverity.ADVISORY:
            self.overall_severity = BreachSeverity.WARNING

        self.pipeline_halted = self.overall_severity == BreachSeverity.HALT
        self.output_trustworthy = self.overall_severity in (
            BreachSeverity.NOMINAL, BreachSeverity.ADVISORY
        )
        self.human_action_required = self.overall_severity in (
            BreachSeverity.WARNING, BreachSeverity.CRITICAL, BreachSeverity.HALT
        )

    def finalize(self) -> None:
        """Compute the report hash for integrity verification."""
        content = json.dumps(
            [e.to_dict() for e in self.events], sort_keys=True, default=str
        )
        self.report_hash = hashlib.sha256(content.encode()).hexdigest()

    def to_dict(self) -> dict:
        return {
            "transaction_id": self.transaction_id,
            "overall_severity": self.overall_severity.value,
            "event_count": len(self.events),
            "events": [e.to_dict() for e in self.events],
            "pipeline_halted": self.pipeline_halted,
            "output_trustworthy": self.output_trustworthy,
            "human_action_required": self.human_action_required,
            "generated_at": self.generated_at,
            "report_hash": self.report_hash,
        }


# ======================================================================
# Breach Detector
# ======================================================================

class BreachDetector:
    """
    Deterministic anomaly detection for pipeline transactions.

    Every check is a comparison, a count, or a threshold. No check
    evaluates the meaning of any AI-generated content. The detector
    catches structural violations, not semantic manipulation.

    Call analyze_transaction() after a pipeline execution to produce
    a BreachReport. The pipeline checks these results and decides
    whether to deliver output or halt.
    """

    # Thresholds (configurable per deployment)
    CONFIDENCE_ALWAYS_SUSPICIOUS_ABOVE = 95
    CONFIDENCE_ALWAYS_SUSPICIOUS_BELOW = 5
    MIN_RESPONSE_LENGTH_CHARS = 50
    MAX_RESPONSE_LENGTH_RATIO = 20  # Longest vs shortest response
    MAX_UNICODE_ANOMALY_RATIO = 0.05  # 5% non-ASCII is suspicious
    DELIMITER_PATTERNS = [
        "--- SOURCE",
        "--- PLATFORM",
        "RESPONSE:",
        "STATUS:",
        "DETAIL:",
    ]

    def analyze_transaction(
        self,
        transaction_id: str,
        platform_responses: list,   # list[AdapterResponse]
        navigator_response,         # AdapterResponse
        navigator_validation,       # NavigatorValidationResult
        security_warnings: list[str],
        injection_detections: list[str],
        transport_violations: list[dict],
        logger_healthy: bool,
    ) -> BreachReport:
        """
        Analyze a completed pipeline transaction for breach indicators.

        Returns a BreachReport with all detected anomalies classified.
        """
        report = BreachReport(transaction_id=transaction_id)

        # ------ Injection Detection ------
        self._check_injections(report, injection_detections, transaction_id)

        # ------ Transport Integrity ------
        self._check_transport(report, transport_violations, transaction_id)

        # ------ Navigator Format ------
        self._check_navigator_format(report, navigator_validation, transaction_id)

        # ------ Navigator Confidence Anomaly ------
        self._check_confidence_anomaly(report, navigator_validation, transaction_id)

        # ------ Logger Health ------
        self._check_logger_health(report, logger_healthy, transaction_id)

        # ------ Response Anomalies ------
        self._check_response_anomalies(report, platform_responses, transaction_id)

        # ------ Unicode Anomalies (homoglyph attack indicator) ------
        self._check_unicode_anomalies(report, platform_responses, transaction_id)

        # ------ Delimiter Attacks ------
        self._check_delimiter_attacks(report, platform_responses, transaction_id)

        # ------ Metadata Channel Exploitation ------
        self._check_metadata_channels(report, platform_responses, transaction_id)

        # ------ Escalated Security Warnings ------
        self._check_security_warnings(report, security_warnings, transaction_id)

        report.finalize()
        return report

    def _check_injections(self, report, detections, tid):
        if not detections:
            return
        severity = BreachSeverity.WARNING if len(detections) <= 2 else BreachSeverity.CRITICAL
        report.add_event(BreachEvent(
            category=BreachCategory.INJECTION_DETECTED,
            severity=severity,
            description=(
                f"{len(detections)} prompt injection pattern(s) detected and neutralized "
                f"in platform responses before Navigator insertion."
            ),
            evidence="; ".join(d[:100] for d in detections[:5]),
            transaction_id=tid,
            recommended_action=(
                "Review raw platform responses in audit trail. Identify which platform(s) "
                "produced injection attempts. Consider removing compromised platform from rotation."
            ),
        ))

    def _check_transport(self, report, violations, tid):
        if not violations:
            return
        report.add_event(BreachEvent(
            category=BreachCategory.TRANSPORT_INTEGRITY,
            severity=BreachSeverity.CRITICAL,
            description=(
                f"{len(violations)} transport integrity violation(s). "
                "Response content does not match recorded hash. "
                "Content may have been modified in transit or by a compromised adapter."
            ),
            evidence=json.dumps(violations[:3], default=str),
            transaction_id=tid,
            recommended_action=(
                "DO NOT TRUST pipeline output for this transaction. "
                "Verify platform adapter integrity. Check for MITM proxy or SDK compromise."
            ),
        ))

    def _check_navigator_format(self, report, nav_val, tid):
        if nav_val is None:
            report.add_event(BreachEvent(
                category=BreachCategory.NAVIGATOR_FORMAT,
                severity=BreachSeverity.WARNING,
                description="Navigator validation was not performed.",
                transaction_id=tid,
                recommended_action="Review Navigator output manually.",
            ))
            return
        if not nav_val.is_valid:
            missing_count = len(nav_val.sections_missing)
            severity = BreachSeverity.ADVISORY if missing_count <= 2 else BreachSeverity.WARNING
            report.add_event(BreachEvent(
                category=BreachCategory.NAVIGATOR_FORMAT,
                severity=severity,
                description=(
                    f"Navigator output missing {missing_count} required section(s): "
                    f"{', '.join(nav_val.sections_missing)}"
                ),
                transaction_id=tid,
                recommended_action=(
                    "Compare Navigator synthesis against raw platform responses. "
                    "Missing sections may indicate Navigator truncation, refusal, or manipulation."
                ),
            ))
        if nav_val.warnings:
            for w in nav_val.warnings:
                if "truncation" in w.lower() or "refusal" in w.lower():
                    report.add_event(BreachEvent(
                        category=BreachCategory.NAVIGATOR_ANOMALY,
                        severity=BreachSeverity.WARNING,
                        description=f"Navigator anomaly: {w}",
                        transaction_id=tid,
                        recommended_action="Navigator may have refused or truncated its response.",
                    ))

    def _check_confidence_anomaly(self, report, nav_val, tid):
        if nav_val is None or not nav_val.confidence_parseable:
            return
        conf = nav_val.confidence_value
        if conf >= self.CONFIDENCE_ALWAYS_SUSPICIOUS_ABOVE:
            report.add_event(BreachEvent(
                category=BreachCategory.CONFIDENCE_ANOMALY,
                severity=BreachSeverity.ADVISORY,
                description=(
                    f"Navigator reported confidence {conf}/100. "
                    "Scores above 95 are statistically unusual for multi-source synthesis "
                    "and may indicate the Navigator is suppressing divergence."
                ),
                transaction_id=tid,
                recommended_action=(
                    "Verify divergence and dissent sections contain substantive content. "
                    "A genuinely high-confidence synthesis should have minimal divergence."
                ),
            ))
        elif conf <= self.CONFIDENCE_ALWAYS_SUSPICIOUS_BELOW:
            report.add_event(BreachEvent(
                category=BreachCategory.CONFIDENCE_ANOMALY,
                severity=BreachSeverity.ADVISORY,
                description=(
                    f"Navigator reported confidence {conf}/100. "
                    "Extremely low confidence may indicate the Navigator is unable to "
                    "synthesize the responses or is being adversarially influenced."
                ),
                transaction_id=tid,
                recommended_action="Read raw platform responses directly.",
            ))

    def _check_logger_health(self, report, healthy, tid):
        if not healthy:
            report.add_event(BreachEvent(
                category=BreachCategory.LOGGER_FAILURE,
                severity=BreachSeverity.CRITICAL,
                description=(
                    "Audit logger health check failed. "
                    "Records may not have been persisted to disk. "
                    "Governance trail for this transaction may be incomplete."
                ),
                transaction_id=tid,
                recommended_action=(
                    "Check filesystem permissions and disk space. "
                    "Verify audit file integrity. Re-run transaction if trail is incomplete."
                ),
            ))

    def _check_response_anomalies(self, report, responses, tid):
        """Check for statistical anomalies in platform response set."""
        if not responses:
            return

        successful = [r for r in responses if r.success and r.response_text]
        if len(successful) == 0:
            report.add_event(BreachEvent(
                category=BreachCategory.RESPONSE_ANOMALY,
                severity=BreachSeverity.CRITICAL,
                description="All platform responses failed. No successful responses to synthesize.",
                transaction_id=tid,
                recommended_action="Check network connectivity and API keys for all platforms.",
            ))
            return

        if len(successful) < len(responses):
            failed_count = len(responses) - len(successful)
            report.add_event(BreachEvent(
                category=BreachCategory.RESPONSE_ANOMALY,
                severity=BreachSeverity.ADVISORY,
                description=f"{failed_count} of {len(responses)} platform(s) returned errors.",
                transaction_id=tid,
                recommended_action="Synthesis based on partial platform coverage.",
            ))

        # Check for suspiciously short responses
        lengths = [len(r.response_text) for r in successful]
        for r in successful:
            if len(r.response_text) < self.MIN_RESPONSE_LENGTH_CHARS:
                report.add_event(BreachEvent(
                    category=BreachCategory.RESPONSE_ANOMALY,
                    severity=BreachSeverity.ADVISORY,
                    description=(
                        f"Platform response unusually short ({len(r.response_text)} chars). "
                        "May indicate refusal, truncation, or content filtering."
                    ),
                    platform_id=r.platform_id,
                    transaction_id=tid,
                ))

        # Check for extreme length disparity (one platform producing vastly different output)
        if len(lengths) >= 2:
            ratio = max(lengths) / max(min(lengths), 1)
            if ratio > self.MAX_RESPONSE_LENGTH_RATIO:
                report.add_event(BreachEvent(
                    category=BreachCategory.RESPONSE_ANOMALY,
                    severity=BreachSeverity.ADVISORY,
                    description=(
                        f"Response length ratio {ratio:.1f}:1 between longest and shortest. "
                        "Extreme disparity may indicate one platform was manipulated or malfunctioned."
                    ),
                    transaction_id=tid,
                ))

        # Check for identical responses (platforms may be colluding or misconfigured)
        hashes = [r.response_hash for r in successful]
        if len(set(hashes)) < len(hashes):
            report.add_event(BreachEvent(
                category=BreachCategory.RESPONSE_ANOMALY,
                severity=BreachSeverity.WARNING,
                description=(
                    "Two or more platforms returned identical responses (matching hash). "
                    "Independent platforms should produce distinct outputs. "
                    "This may indicate platform misconfiguration, response caching, "
                    "or coordinated manipulation."
                ),
                transaction_id=tid,
                recommended_action=(
                    "Verify platforms are actually independent. "
                    "Check if adapters are pointing to the same underlying model."
                ),
            ))

    def _check_unicode_anomalies(self, report, responses, tid):
        """
        Detect Unicode homoglyph attacks.

        Cognitive agents can embed Cyrillic, Greek, or other Unicode
        characters that look identical to Latin characters but bypass
        ASCII-based regex patterns. This is the primary bypass for
        the A1 sanitization layer.
        """
        for r in responses:
            if not r.success or not r.response_text:
                continue
            text = r.response_text
            total = len(text)
            if total == 0:
                continue

            # Count characters outside basic ASCII + common extended Latin
            non_ascii = sum(1 for c in text if ord(c) > 127)
            ratio = non_ascii / total

            # Check for specific homoglyph ranges
            homoglyph_ranges = [
                (0x0400, 0x04FF, "Cyrillic"),     # А looks like A
                (0x0370, 0x03FF, "Greek"),         # Ρ looks like P
                (0x2000, 0x206F, "General Punctuation"),  # zero-width chars
                (0x200B, 0x200F, "Zero-width"),    # ZWJ, ZWNJ, etc
                (0xFE00, 0xFE0F, "Variation Selectors"),
                (0xFEFF, 0xFEFF, "BOM/ZWNBSP"),
                (0x2028, 0x2029, "Line/Paragraph Separators"),
            ]

            detected_ranges = []
            for start, end, name in homoglyph_ranges:
                count = sum(1 for c in text if start <= ord(c) <= end)
                if count > 0:
                    detected_ranges.append(f"{name}({count})")

            if detected_ranges:
                report.add_event(BreachEvent(
                    category=BreachCategory.UNICODE_ANOMALY,
                    severity=BreachSeverity.WARNING,
                    description=(
                        f"Unicode anomaly in platform response: {', '.join(detected_ranges)}. "
                        "These character ranges are commonly used in homoglyph attacks "
                        "to bypass ASCII-based sanitization. A Cyrillic 'А' (U+0410) "
                        "looks identical to Latin 'A' but will not match regex patterns."
                    ),
                    platform_id=r.platform_id,
                    transaction_id=tid,
                    recommended_action=(
                        "Inspect raw response for character substitution. "
                        "Platform may be attempting to bypass injection sanitization."
                    ),
                ))
            elif ratio > self.MAX_UNICODE_ANOMALY_RATIO:
                report.add_event(BreachEvent(
                    category=BreachCategory.UNICODE_ANOMALY,
                    severity=BreachSeverity.ADVISORY,
                    description=(
                        f"High non-ASCII character ratio ({ratio:.1%}) in platform response. "
                        "May be legitimate (non-English content) or may indicate encoding attack."
                    ),
                    platform_id=r.platform_id,
                    transaction_id=tid,
                ))

    def _check_delimiter_attacks(self, report, responses, tid):
        """
        Detect delimiter injection attacks.

        A cognitive agent can embed "--- SOURCE B ---" in its response
        to confuse the Navigator about where one response ends and
        another begins. This rewrites the multi-source structure
        without triggering injection pattern detection.
        """
        for r in responses:
            if not r.success or not r.response_text:
                continue
            for pattern in self.DELIMITER_PATTERNS:
                if pattern in r.response_text:
                    report.add_event(BreachEvent(
                        category=BreachCategory.DELIMITER_ATTACK,
                        severity=BreachSeverity.WARNING,
                        description=(
                            f"Platform response contains synthesis format delimiter '{pattern}'. "
                            "This may be a delimiter injection attack where the platform "
                            "embeds fake response boundaries to manipulate Navigator synthesis. "
                            "The Navigator may misinterpret response boundaries."
                        ),
                        platform_id=r.platform_id,
                        evidence=f"Found '{pattern}' in response from {r.platform_id}",
                        transaction_id=tid,
                        recommended_action=(
                            "Compare Navigator synthesis section attributions against "
                            "the actual platform that produced each claim. "
                            "Delimiter injection can cause mis-attribution of content."
                        ),
                    ))
                    break  # One detection per response is sufficient

    def _check_metadata_channels(self, report, responses, tid):
        """
        Detect exploitation of unsanitized metadata channels.

        api_confirmation, platform_model, and raw_metadata are
        never sanitized because they do not flow to the Navigator.
        But they DO flow to the audit trail. If these contain
        executable content or injection patterns, the audit trail
        itself becomes an attack vector when read by humans or tools.
        """
        injection_keywords = [
            "SYSTEM", "OVERRIDE", "IGNORE", "INSTRUCTION",
            "<script", "javascript:", "eval(", "exec(",
        ]
        for r in responses:
            channels = {
                "api_confirmation": r.api_confirmation or "",
                "platform_model": r.platform_model or "",
            }
            for channel_name, value in channels.items():
                if not value:
                    continue
                # Check for injection patterns in metadata
                for keyword in injection_keywords:
                    if keyword.lower() in value.lower():
                        report.add_event(BreachEvent(
                            category=BreachCategory.METADATA_ANOMALY,
                            severity=BreachSeverity.WARNING,
                            description=(
                                f"Suspicious content in unsanitized metadata channel "
                                f"'{channel_name}': contains '{keyword}'. "
                                "Metadata channels are not sanitized because they do not "
                                "reach the Navigator, but they are written to the audit trail."
                            ),
                            platform_id=r.platform_id,
                            evidence=f"{channel_name}: {value[:100]}",
                            transaction_id=tid,
                            recommended_action=(
                                "Inspect audit trail entries for this platform. "
                                "Metadata channel may be used for secondary injection."
                            ),
                        ))
                        break

    def _check_security_warnings(self, report, warnings, tid):
        """Escalate pipeline security warnings into breach events."""
        for w in warnings:
            # Already handled by specific checks above
            if any(k in w.lower() for k in ["injection", "transport", "logger"]):
                continue
            report.add_event(BreachEvent(
                category=BreachCategory.CONFIG_VIOLATION,
                severity=BreachSeverity.ADVISORY,
                description=w,
                transaction_id=tid,
            ))


# ======================================================================
# Breach Report Formatter
# ======================================================================

class BreachReportFormatter:
    """
    Formats breach reports for human consumption.

    Two output modes:
        1. Summary: One-line status for each transaction
        2. Full: Complete incident report with all evidence

    Reports are designed to be read by a human under time pressure.
    Most important information first. Actionable recommendations.
    No jargon without explanation.
    """

    @staticmethod
    def format_summary(report: BreachReport) -> str:
        """One-line summary for dashboard or log."""
        icon = {
            BreachSeverity.NOMINAL: "OK",
            BreachSeverity.ADVISORY: "INFO",
            BreachSeverity.WARNING: "WARN",
            BreachSeverity.CRITICAL: "CRIT",
            BreachSeverity.HALT: "HALT",
        }[report.overall_severity]

        return (
            f"[{icon}] Transaction {report.transaction_id[:8]}... | "
            f"Severity: {report.overall_severity.value} | "
            f"Events: {len(report.events)} | "
            f"Output trustworthy: {'YES' if report.output_trustworthy else 'NO'} | "
            f"Action required: {'YES' if report.human_action_required else 'NO'}"
        )

    @staticmethod
    def format_full(report: BreachReport) -> str:
        """Complete incident report for human review."""
        lines = []
        lines.append("=" * 70)
        lines.append("HAIA AGENT FRAMEWORK - BREACH REPORT")
        lines.append("=" * 70)
        lines.append("")
        lines.append(f"Transaction ID:     {report.transaction_id}")
        lines.append(f"Generated at:       {report.generated_at}")
        lines.append(f"Report hash:        {report.report_hash}")
        lines.append("")

        # Status box
        lines.append(f"OVERALL SEVERITY:   {report.overall_severity.value}")
        lines.append(f"Pipeline halted:    {'YES' if report.pipeline_halted else 'NO'}")
        lines.append(f"Output trustworthy: {'YES' if report.output_trustworthy else 'NO'}")
        lines.append(f"Action required:    {'YES' if report.human_action_required else 'NO'}")
        lines.append(f"Events detected:    {len(report.events)}")
        lines.append("")

        if report.overall_severity == BreachSeverity.NOMINAL:
            lines.append("All systems operating within expected parameters.")
            lines.append("No anomalies detected in this transaction.")
            lines.append("=" * 70)
            return "\n".join(lines)

        # What happened
        lines.append("WHAT HAPPENED:")
        lines.append("")
        for i, event in enumerate(report.events, 1):
            lines.append(f"  Event {i}: [{event.severity.value}] {event.category.value}")
            lines.append(f"    {event.description}")
            if event.platform_id:
                lines.append(f"    Platform: {event.platform_id}")
            if event.evidence:
                lines.append(f"    Evidence: {event.evidence[:200]}")
            if event.recommended_action:
                lines.append(f"    Action:   {event.recommended_action}")
            lines.append("")

        # What to do
        lines.append("RECOMMENDED ACTIONS:")
        lines.append("")
        if report.pipeline_halted:
            lines.append(
                "  1. Pipeline has HALTED. No output was produced for this transaction."
            )
            lines.append(
                "  2. Investigate the root cause using the evidence above."
            )
            lines.append(
                "  3. After investigation, either re-run the transaction or "
                "escalate to security review."
            )
        elif report.human_action_required:
            lines.append(
                "  1. Review the checkpoint package WITH EXTRA SCRUTINY."
            )
            lines.append(
                "  2. Compare Navigator synthesis against raw platform responses."
            )
            lines.append(
                "  3. Pay special attention to any platform flagged in the events above."
            )
            lines.append(
                "  4. Consider whether the anomalies could indicate coordinated manipulation."
            )
        else:
            lines.append(
                "  1. No urgent action required. Review at your normal checkpoint."
            )
            lines.append(
                "  2. Advisory events logged for audit trail and trend analysis."
            )

        lines.append("")
        lines.append("WHAT THIS REPORT CANNOT DETECT:")
        lines.append("  This report detects structural anomalies, not semantic manipulation.")
        lines.append("  A well-crafted lie that passes all format checks will not trigger")
        lines.append("  any of these detections. Your judgment at the checkpoint is the")
        lines.append("  final defense against content-level manipulation.")
        lines.append("")
        lines.append("=" * 70)
        return "\n".join(lines)


# ======================================================================
# Circuit Breaker
# ======================================================================

class PipelineCircuitBreaker:
    """
    Determines whether the pipeline should halt based on breach severity.

    The circuit breaker is a threshold check, not a judgment call.
    It counts severity levels and compares against configurable limits.

    Three states:
        CLOSED:  Pipeline operates normally.
        OPEN:    Pipeline halts. No output produced.
        TRIPPED: Pipeline produced output but flagged it as untrusted.
    """

    def __init__(
        self,
        halt_on_critical: bool = True,
        halt_on_warning_count: int = 5,
        halt_on_injection_count: int = 3,
    ):
        self.halt_on_critical = halt_on_critical
        self.halt_on_warning_count = halt_on_warning_count
        self.halt_on_injection_count = halt_on_injection_count

    def should_halt(self, report: BreachReport) -> bool:
        """
        Determine if the pipeline should halt based on the breach report.

        Returns True if the pipeline must stop.
        """
        if report.overall_severity == BreachSeverity.HALT:
            return True

        if self.halt_on_critical and report.overall_severity == BreachSeverity.CRITICAL:
            return True

        warning_count = sum(
            1 for e in report.events if e.severity == BreachSeverity.WARNING
        )
        if warning_count >= self.halt_on_warning_count:
            return True

        injection_count = sum(
            1 for e in report.events
            if e.category == BreachCategory.INJECTION_DETECTED
        )
        if injection_count >= self.halt_on_injection_count:
            return True

        return False

    def should_flag_untrusted(self, report: BreachReport) -> bool:
        """
        Determine if output should be flagged as untrusted.

        Returns True if the human should be warned that output
        may not be reliable, even though the pipeline did not halt.
        """
        if report.overall_severity in (BreachSeverity.WARNING, BreachSeverity.CRITICAL):
            return True
        return False


# ======================================================================
# Notification Callbacks
# ======================================================================

class BreachNotifier:
    """
    Notification dispatch for breach events.

    Supports multiple notification channels through callbacks.
    Production deployment: hook into email, Slack, PagerDuty,
    SIEM, or any alerting system.

    The notifier calls registered callbacks with the breach report.
    What happens after that is deployment-specific.
    """

    def __init__(self):
        self._callbacks: list[Callable[[BreachReport], None]] = []

    def register_callback(self, callback: Callable[[BreachReport], None]) -> None:
        """Register a notification callback."""
        self._callbacks.append(callback)

    def notify(self, report: BreachReport) -> int:
        """
        Send breach report to all registered callbacks.
        Returns number of successful notifications.
        """
        if report.overall_severity == BreachSeverity.NOMINAL:
            return 0  # Don't notify on nominal

        success_count = 0
        for cb in self._callbacks:
            try:
                cb(report)
                success_count += 1
            except Exception:
                pass  # Notification failure must not crash the pipeline
        return success_count

    @staticmethod
    def console_callback(report: BreachReport) -> None:
        """Default callback: print to console."""
        formatter = BreachReportFormatter()
        if report.overall_severity in (BreachSeverity.CRITICAL, BreachSeverity.HALT):
            print(formatter.format_full(report))
        else:
            print(formatter.format_summary(report))

    @staticmethod
    def file_callback_factory(log_path: Path) -> Callable[[BreachReport], None]:
        """Create a callback that appends breach reports to a file."""
        def callback(report: BreachReport) -> None:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            with open(log_path, "a") as f:
                f.write(BreachReportFormatter.format_full(report))
                f.write("\n\n")
        return callback
