"""
HAIA Agent Framework - Navigator Validator
============================================
Structural enforcement for the cognitive boundary (Vulnerability 1).

The Navigator is a cognitive system (an AI platform). The HAIA Agent
Framework is non-cognitive infrastructure. This validator enforces the
boundary between them.

What this validator does:
    - Confirms Navigator output contains all required governance sections
    - Flags missing sections for human attention
    - Detects format deviations that may indicate manipulation or failure
    - Logs all validation results in the audit trail

What this validator does NOT do:
    - Evaluate whether the Navigator's synthesis is correct
    - Judge the quality of convergence/divergence analysis
    - Override or modify Navigator output
    - Make any cognitive determination about content

The validator checks STRUCTURE, not SUBSTANCE. Structure is deterministic.
Substance is cognitive. The human evaluates substance at the checkpoint.

Author: Basil C. Puglisi, MPA
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


# Required sections in Navigator governance output
REQUIRED_SECTIONS = [
    "CONVERGENCE",
    "DIVERGENCE",
    "DISSENT",
    "SOURCES",
    "CONFLICTS",
    "CONFIDENCE",
    "RECOMMENDATION",
    "EXPIRY",
]


@dataclass
class NavigatorValidationResult:
    """
    Result of structural validation on Navigator output.

    This is metadata about the output's format, not about its content.
    """
    is_valid: bool = False
    sections_found: list[str] = field(default_factory=list)
    sections_missing: list[str] = field(default_factory=list)
    confidence_value: Optional[int] = None
    confidence_parseable: bool = False
    response_length: int = 0
    warnings: list[str] = field(default_factory=list)
    raw_response_preserved: bool = True  # Always True: we never modify the response

    def to_dict(self) -> dict:
        return {
            "is_valid": self.is_valid,
            "sections_found": self.sections_found,
            "sections_missing": self.sections_missing,
            "confidence_value": self.confidence_value,
            "confidence_parseable": self.confidence_parseable,
            "response_length": self.response_length,
            "warnings": self.warnings,
            "raw_response_preserved": self.raw_response_preserved,
        }


class NavigatorValidator:
    """
    Structural validator for Navigator synthesis output.

    Enforces the boundary between cognitive (Navigator platform) and
    non-cognitive (HAIA Agent Framework) layers.

    The validator answers one question: does the Navigator output
    contain the required governance sections? If not, the human
    is informed. The output is never modified or suppressed.

    This is a format check, not a content check. Analogous to checking
    that a tax form has all required fields filled in, not whether
    the numbers on it are correct.
    """

    def __init__(self, required_sections: Optional[list[str]] = None):
        self.required_sections = required_sections or REQUIRED_SECTIONS

    def validate(self, navigator_output: str) -> NavigatorValidationResult:
        """
        Validate the structural format of Navigator output.

        Checks:
            1. All required sections present (header text found)
            2. Confidence value is parseable as integer 0-100
            3. Response is non-empty and above minimum length
            4. No truncation indicators (common API failure mode)

        Does NOT check:
            - Accuracy of convergence/divergence claims
            - Quality of dissent preservation
            - Correctness of source citations
            - Appropriateness of recommendation

        Args:
            navigator_output: Complete text from Navigator platform

        Returns:
            NavigatorValidationResult with structural assessment
        """
        result = NavigatorValidationResult()
        result.response_length = len(navigator_output)
        result.raw_response_preserved = True

        # Check 1: Non-empty response
        if not navigator_output or not navigator_output.strip():
            result.warnings.append("Navigator returned empty response")
            result.sections_missing = list(self.required_sections)
            return result

        # Check 2: Minimum length (governance synthesis should be substantive)
        if len(navigator_output) < 200:
            result.warnings.append(
                f"Navigator response unusually short ({len(navigator_output)} chars). "
                "May indicate truncation or API failure."
            )

        # Check 3: Required sections present
        output_upper = navigator_output.upper()
        for section in self.required_sections:
            # Look for section header with colon or as standalone line
            patterns = [
                f"{section}:",
                f"{section}\n",
                f"**{section}**",
                f"## {section}",
                f"### {section}",
            ]
            found = any(p.upper() in output_upper for p in patterns)
            # Also check for the section word at start of a line
            if not found:
                found = bool(re.search(
                    rf"^\s*\**{re.escape(section)}\**\s*[:.]",
                    navigator_output,
                    re.MULTILINE | re.IGNORECASE,
                ))
            if found:
                result.sections_found.append(section)
            else:
                result.sections_missing.append(section)

        # Check 4: Confidence value parseable
        confidence_match = re.search(
            r"CONFIDENCE[:\s]*(\d{1,3})",
            navigator_output,
            re.IGNORECASE,
        )
        if confidence_match:
            try:
                val = int(confidence_match.group(1))
                if 0 <= val <= 100:
                    result.confidence_value = val
                    result.confidence_parseable = True
                else:
                    result.warnings.append(
                        f"Confidence value {val} outside 0-100 range"
                    )
            except ValueError:
                result.warnings.append("Confidence value not parseable as integer")
        else:
            result.warnings.append("No parseable confidence value found")

        # Check 5: Truncation indicators
        truncation_markers = [
            "...",
            "[truncated]",
            "[continued]",
            "I apologize",  # Common refusal indicator
            "I cannot",
            "I'm unable",
        ]
        for marker in truncation_markers:
            if marker.lower() in navigator_output[-200:].lower():
                result.warnings.append(
                    f"Possible truncation or refusal detected near end of response: '{marker}'"
                )

        # Overall validity: all required sections present
        result.is_valid = len(result.sections_missing) == 0

        # Add warning if partially valid (some sections present)
        if not result.is_valid and len(result.sections_found) > 0:
            result.warnings.append(
                f"{len(result.sections_found)} of {len(self.required_sections)} "
                f"required sections found. Missing: {', '.join(result.sections_missing)}. "
                "Human should review whether synthesis is adequate for arbitration."
            )

        return result

    def format_validation_for_human(self, result: NavigatorValidationResult) -> str:
        """
        Format validation result as human-readable text for inclusion
        in the checkpoint governance package.

        This tells the human what structural issues exist before they
        evaluate the content.
        """
        lines = []
        lines.append("NAVIGATOR OUTPUT STRUCTURAL VALIDATION")
        lines.append(f"  Format valid: {'YES' if result.is_valid else 'NO'}")
        lines.append(f"  Response length: {result.response_length} characters")

        if result.sections_found:
            lines.append(f"  Sections present: {', '.join(result.sections_found)}")
        if result.sections_missing:
            lines.append(f"  Sections MISSING: {', '.join(result.sections_missing)}")

        if result.confidence_parseable:
            lines.append(f"  Confidence score: {result.confidence_value}/100")
        else:
            lines.append("  Confidence score: NOT PARSEABLE")

        if result.warnings:
            lines.append("  Warnings:")
            for w in result.warnings:
                lines.append(f"    - {w}")

        lines.append("")
        lines.append(
            "NOTE: This validation checks OUTPUT STRUCTURE, not OUTPUT QUALITY. "
            "The Navigator is an AI platform performing cognitive synthesis. "
            "The HAIA Agent Framework validates format compliance only. "
            "Content evaluation is the human's responsibility at this checkpoint."
        )

        return "\n".join(lines)
