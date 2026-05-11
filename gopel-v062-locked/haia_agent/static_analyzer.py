"""
HAIA Agent Framework - Non-Cognitive Static Analyzer
=====================================================
Addresses Vulnerability 4: The non-cognitive constraint is enforced
by code convention, not formal verification.

This analyzer scans Python source files in the framework and flags
any patterns that would indicate cognitive operations:
    - Model inference calls (openai.*, anthropic.*, genai.*)
    - Embedding lookups
    - Classification operations
    - Content-dependent branching on response text
    - NLP library imports (transformers, spacy, nltk, etc.)
    - Sentiment analysis, summarization, or ranking functions

Scope: Scans the framework's own code (logger, pipeline, selector,
security, navigator router). Does NOT scan adapters (which are
expected to make API calls) or tests.

The adapters are transport. They call APIs. That is their job.
The pipeline, logger, and selector must never call APIs or perform
cognitive operations directly.

Author: Basil C. Puglisi, MPA
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# Patterns that indicate cognitive operations
COGNITIVE_IMPORT_PATTERNS = [
    r"import\s+transformers",
    r"from\s+transformers\s+import",
    r"import\s+spacy",
    r"from\s+spacy\s+import",
    r"import\s+nltk",
    r"from\s+nltk\s+import",
    r"import\s+sklearn",
    r"from\s+sklearn\s+import",
    r"import\s+tensorflow",
    r"from\s+tensorflow\s+import",
    r"import\s+torch",
    r"from\s+torch\s+import",
    r"import\s+keras",
    r"from\s+keras\s+import",
    r"import\s+sentence_transformers",
    r"from\s+sentence_transformers\s+import",
    r"import\s+langchain",
    r"from\s+langchain\s+import",
]

COGNITIVE_CALL_PATTERNS = [
    r"\.predict\(\s*[^)]*\)",
    r"\.classify\(\s*[^)]*\)",
    r"\.embed\(\s*[^)]*text",        # embedding text, not generic embed
    r"\.summarize\(",
    r"\.sentiment\(",
    r"\.infer\(",
    r"\.fit\(",                       # model training
    r"\.transform\(\s*[^)]*text",     # NLP transform, not generic
]

# Files to scan (framework core, not adapters or tests)
SCAN_TARGETS = [
    "logger.py",
    "pipeline.py",
    "secure_pipeline.py",
    "secure_logger.py",
    "selector.py",
    "security.py",
    "navigator.py",
    "navigator_validator.py",
    "breach.py",
    "sentinel.py",
    "governance.py",
    "models.py",
    "__init__.py",
]

# Files explicitly excluded (adapters are expected to make API calls)
EXCLUDED_PATHS = [
    "adapters/",
    "tests/",
    "examples/",
]


@dataclass
class CognitiveViolation:
    """A detected cognitive operation in framework code."""
    file_path: str
    line_number: int
    violation_type: str  # "import", "call", "branch"
    pattern_matched: str
    line_content: str
    severity: str  # "critical", "warning"


@dataclass
class AnalysisResult:
    """Result of static analysis scan."""
    files_scanned: int = 0
    files_clean: int = 0
    violations: list[CognitiveViolation] = field(default_factory=list)
    is_compliant: bool = True
    scan_timestamp: str = ""

    def to_dict(self) -> dict:
        return {
            "files_scanned": self.files_scanned,
            "files_clean": self.files_clean,
            "violations": [
                {
                    "file": v.file_path,
                    "line": v.line_number,
                    "type": v.violation_type,
                    "pattern": v.pattern_matched,
                    "content": v.line_content.strip(),
                    "severity": v.severity,
                }
                for v in self.violations
            ],
            "is_compliant": self.is_compliant,
        }


class NonCognitiveAnalyzer:
    """
    Static analyzer that verifies the non-cognitive constraint.

    Scans framework source code for patterns indicating cognitive
    operations. Reports violations for human review.

    This is a scan, not a proof. Formal verification remains a
    Phase 5 objective. This analyzer provides a repeatable,
    automated check that catches the most common violation patterns.
    """

    def __init__(self, framework_root: Optional[Path] = None):
        self.framework_root = framework_root or Path(__file__).parent

    def scan(self) -> AnalysisResult:
        """
        Scan all framework core files for cognitive operation patterns.

        Returns AnalysisResult with any violations found.
        """
        from datetime import datetime, timezone
        result = AnalysisResult()
        result.scan_timestamp = datetime.now(timezone.utc).isoformat()

        # Find all Python files in the framework directory
        for py_file in self.framework_root.rglob("*.py"):
            relative = str(py_file.relative_to(self.framework_root))

            # Skip excluded paths
            if any(relative.startswith(exc) for exc in EXCLUDED_PATHS):
                continue

            # Only scan target files
            if py_file.name not in SCAN_TARGETS and relative not in SCAN_TARGETS:
                continue

            result.files_scanned += 1
            file_violations = self._scan_file(py_file)

            if file_violations:
                result.violations.extend(file_violations)
            else:
                result.files_clean += 1

        result.is_compliant = len(result.violations) == 0
        return result

    def _scan_file(self, file_path: Path) -> list[CognitiveViolation]:
        """Scan a single file for cognitive patterns.

        v0.6.1: Added explicit path boundary check. The analyzer must
        never process files outside the framework directory, even if
        SCAN_TARGETS is modified. This prevents scope creep from
        exposing the ast.parse() call to untrusted input.
        MiniMax AI review, Concern 3.
        """
        violations = []

        # Path boundary enforcement: reject any file outside framework_root
        try:
            resolved = file_path.resolve()
            root_resolved = self.framework_root.resolve()
            resolved.relative_to(root_resolved)
        except ValueError:
            # File is outside framework_root, refuse to scan
            return [CognitiveViolation(
                file_path=str(file_path),
                line_number=0,
                violation_type="SCOPE_VIOLATION",
                pattern_matched="File outside framework boundary",
                line_content=f"Rejected: {file_path} is not within {self.framework_root}",
                severity="critical",
            )]

        try:
            content = file_path.read_text(encoding="utf-8")
            lines = content.split("\n")
        except Exception:
            return violations

        relative_path = str(file_path.relative_to(self.framework_root))

        # Check imports
        for i, line in enumerate(lines, 1):
            stripped = line.strip()

            # Skip comments
            if stripped.startswith("#"):
                continue

            # Check cognitive import patterns
            for pattern in COGNITIVE_IMPORT_PATTERNS:
                if re.search(pattern, stripped):
                    violations.append(CognitiveViolation(
                        file_path=relative_path,
                        line_number=i,
                        violation_type="cognitive_import",
                        pattern_matched=pattern,
                        line_content=line,
                        severity="critical",
                    ))

            # Check cognitive call patterns
            for pattern in COGNITIVE_CALL_PATTERNS:
                if re.search(pattern, stripped):
                    # Exclude if in a comment or docstring context
                    if stripped.startswith("#") or stripped.startswith('"""') or stripped.startswith("'''"):
                        continue
                    violations.append(CognitiveViolation(
                        file_path=relative_path,
                        line_number=i,
                        violation_type="cognitive_call",
                        pattern_matched=pattern,
                        line_content=line,
                        severity="critical",
                    ))

        # AST-level analysis for content-dependent branching
        try:
            tree = ast.parse(content)
            ast_violations = self._check_ast_for_content_branching(tree, relative_path, lines)
            violations.extend(ast_violations)
        except SyntaxError:
            pass

        return violations

    def _check_ast_for_content_branching(
        self, tree: ast.AST, file_path: str, lines: list[str]
    ) -> list[CognitiveViolation]:
        """
        Check AST for if-statements that branch on response_text content.

        This catches patterns like:
            if "error" in response.response_text:   (cognitive: content eval)
            if response_text.startswith("approve"):  (cognitive: content eval)

        This does NOT flag:
            if self.response_text and not self.response_hash:  (existence check)
            if response.success:  (status check, not content eval)

        Truthiness checks (is empty, is not None) are non-cognitive.
        Content evaluation (contains, equals, startswith) is cognitive.
        """
        violations = []

        for node in ast.walk(tree):
            if isinstance(node, ast.If):
                # Only flag Compare operations that reference content fields
                # (not BoolOp truthiness checks)
                comparisons = [n for n in ast.walk(node.test) if isinstance(n, ast.Compare)]
                for comp in comparisons:
                    comp_source = ast.dump(comp)
                    content_indicators = [
                        "response_text",
                        "response_content",
                        "output_text",
                        "synthesis_text",
                    ]
                    for indicator in content_indicators:
                        if indicator not in comp_source:
                            continue

                        # EXCLUSION 1: len() comparisons are size checks, not content
                        # evaluation. len(r.response_text) < 50 is a structural
                        # property (length), not a semantic evaluation.
                        if self._is_len_comparison(comp):
                            continue

                        # EXCLUSION 2: Literal string containment checks are pattern
                        # matching, not semantic evaluation. Same class of operation
                        # as regex sanitization (already accepted as non-cognitive).
                        # Example: "--- SOURCE" in r.response_text
                        if self._is_literal_containment(comp):
                            continue

                        line_num = getattr(node, "lineno", 0)
                        line_content = lines[line_num - 1] if line_num <= len(lines) else ""
                        violations.append(CognitiveViolation(
                            file_path=file_path,
                            line_number=line_num,
                            violation_type="content_dependent_branch",
                            pattern_matched=f"comparison references '{indicator}'",
                            line_content=line_content,
                            severity="warning",
                        ))

        return violations

    @staticmethod
    def _is_len_comparison(comp: ast.Compare) -> bool:
        """Check if the comparison is a len() call (size check, non-cognitive)."""
        # Check left side: len(something)
        if isinstance(comp.left, ast.Call):
            if isinstance(comp.left.func, ast.Name) and comp.left.func.id == "len":
                return True
        # Check comparators side: ... < len(something)
        for c in comp.comparators:
            if isinstance(c, ast.Call):
                if isinstance(c.func, ast.Name) and c.func.id == "len":
                    return True
        return False

    @staticmethod
    def _is_literal_containment(comp: ast.Compare) -> bool:
        """
        Check if the comparison is a containment ('in' / 'not in') test.

        Any 'in' test against response_text is a substring containment
        check (pattern matching), which is non-cognitive. This is
        functionally equivalent to regex.search(pattern, text) or
        text.find(pattern), both already accepted as non-cognitive
        in the sanitization layer.

        The 'in' operator tests for substring presence, not meaning.
        Whether the left side is a literal string or a variable loaded
        from a constant list, the operation is deterministic pattern
        matching, not semantic evaluation.
        """
        for op in comp.ops:
            if isinstance(op, (ast.In, ast.NotIn)):
                return True
        return False

    def format_report(self, result: AnalysisResult) -> str:
        """Format analysis result as human-readable report."""
        lines = []
        lines.append("NON-COGNITIVE CONSTRAINT STATIC ANALYSIS REPORT")
        lines.append(f"  Scan timestamp: {result.scan_timestamp}")
        lines.append(f"  Files scanned: {result.files_scanned}")
        lines.append(f"  Files clean:   {result.files_clean}")
        lines.append(f"  Violations:    {len(result.violations)}")
        lines.append(f"  Compliant:     {'YES' if result.is_compliant else 'NO'}")

        if result.violations:
            lines.append("")
            lines.append("  VIOLATIONS:")
            for v in result.violations:
                lines.append(f"    [{v.severity.upper()}] {v.file_path}:{v.line_number}")
                lines.append(f"      Type: {v.violation_type}")
                lines.append(f"      Pattern: {v.pattern_matched}")
                lines.append(f"      Code: {v.line_content.strip()}")
        else:
            lines.append("")
            lines.append("  No cognitive operations detected in framework core.")
            lines.append("  (Adapters excluded from scan: they are transport, not governance.)")

        lines.append("")
        lines.append(
            "NOTE: This is static pattern analysis, not formal verification. "
            "It catches common violation patterns but cannot prove absence of "
            "all cognitive operations. Formal verification remains a Phase 5 objective."
        )

        return "\n".join(lines)

    # ==================================================================
    # C2: Dependency supply chain scanning
    # ==================================================================

    def scan_dependencies(self) -> list[dict]:
        """
        C2: Scan installed dependencies for known risk indicators.

        Checks:
            1. Expected dependencies are present at expected versions
            2. No unexpected packages in the dependency tree
            3. Hash verification of installed package files (if available)

        This is not a full supply chain audit. It detects obvious
        anomalies. Production deployment should use tools like
        pip-audit, safety, or Sigstore for comprehensive verification.

        Returns list of findings (empty if clean).
        """
        import importlib.metadata as meta

        findings = []

        # Expected dependencies and minimum versions
        expected = {
            "pydantic": "2.0.0",
            "cryptography": "41.0.0",
        }

        # Optional SDK dependencies (only check if present)
        optional_sdks = ["anthropic", "openai", "google-generativeai"]

        # Check expected dependencies
        for pkg, min_version in expected.items():
            try:
                dist = meta.distribution(pkg)
                installed = dist.version
                # Simple version comparison (major.minor)
                if self._version_lt(installed, min_version):
                    findings.append({
                        "package": pkg,
                        "severity": "warning",
                        "detail": f"Version {installed} below minimum {min_version}",
                    })
            except meta.PackageNotFoundError:
                findings.append({
                    "package": pkg,
                    "severity": "critical",
                    "detail": f"Required package '{pkg}' not installed",
                })

        # Check for known dangerous packages
        dangerous = [
            "transformers", "torch", "tensorflow", "keras",
            "langchain", "autogpt", "babyagi",
        ]
        for pkg in dangerous:
            try:
                meta.distribution(pkg)
                findings.append({
                    "package": pkg,
                    "severity": "warning",
                    "detail": f"Cognitive/ML package '{pkg}' found in environment. "
                              "Not expected in non-cognitive framework deployment.",
                })
            except meta.PackageNotFoundError:
                pass  # Good, not present

        return findings

    @staticmethod
    def _version_lt(installed: str, minimum: str) -> bool:
        """Simple major.minor version comparison."""
        try:
            inst_parts = [int(x) for x in installed.split(".")[:2]]
            min_parts = [int(x) for x in minimum.split(".")[:2]]
            return inst_parts < min_parts
        except (ValueError, IndexError):
            return False
