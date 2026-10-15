"""
HAIA-Overwatch v2.5 - Tests: CAIPR naming

Plan step 18. CAIPR means Cross AI Platform Review. v2.4 expanded it as
"Consensus-across-independent-platforms" (caipr_dispatcher.py:4), and the
v2.4 paper paragraph 77 printed "Consensus Across Independent Platforms
Review". v2.5 corrects the code; CHANGES_v2_5.md records the paper
correction (R9).

Author: Basil C. Puglisi, MPA
License: CC BY-NC 4.0
Repository: github.com/basilpuglisi/HAIA
Attribution: #AIassisted under HAIA-RECCLIN & Checkpoint-Based Governance
"""

import ast
import re
from pathlib import Path

import overwatch_v27
from overwatch_v27 import caipr_dispatcher
from overwatch_v27.caipr_dispatcher import CAIPRConsensus, CAIPRInspectionDispatcher
from overwatch_v27.models import (
    AlignmentResult, InspectionDomain, InspectionFinding, OverwatchConfig, Severity,
)

PACKAGE_DIR = Path(overwatch_v27.__file__).resolve().parent
CORRECT = "Cross AI Platform Review"
WRONG_EXPANSION = re.compile(r"consensus[\s_-]+across[\s_-]+independent[\s_-]+platforms?", re.I)
PARENTHETICAL = re.compile(r"CAIPR\s*\(([^)]*)\)")


def _docstrings(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    docs = [ast.get_docstring(tree) or ""]
    for node in ast.walk(tree):
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            docs.append(ast.get_docstring(node) or "")
    return docs


def test_the_dispatcher_module_says_cross_ai_platform_review():
    assert CORRECT in (caipr_dispatcher.__doc__ or "")


def test_no_docstring_expands_caipr_any_other_way():
    modules = sorted(PACKAGE_DIR.glob("*.py"))
    assert len(modules) >= 17
    for path in modules:
        for doc in _docstrings(path):
            assert not WRONG_EXPANSION.search(doc), f"{path.name}: {doc[:80]!r}"
            for expansion in PARENTHETICAL.findall(doc):
                assert expansion.strip() == CORRECT, f"{path.name}: CAIPR ({expansion})"


def test_no_module_text_expands_caipr_any_other_way():
    for path in sorted(PACKAGE_DIR.glob("*.py")):
        text = path.read_text(encoding="utf-8")
        assert not WRONG_EXPANSION.search(text), path.name
        for expansion in PARENTHETICAL.findall(text):
            assert expansion.strip() == CORRECT, f"{path.name}: CAIPR ({expansion})"


def test_review_result_class_with_alias_to_the_same_class():
    cls = getattr(caipr_dispatcher, "CAIPRReviewResult", None)
    assert cls is not None, "CAIPRReviewResult (step 18)"
    assert CAIPRConsensus is cls
    assert overwatch_v27.CAIPRReviewResult is cls
    assert overwatch_v27.CAIPRConsensus is cls
    assert "CAIPRReviewResult" in overwatch_v27.__all__
    assert "CAIPRConsensus" in overwatch_v27.__all__
    assert CORRECT in (cls.__doc__ or "")


def test_dispatch_returns_a_review_result():
    cls = getattr(caipr_dispatcher, "CAIPRReviewResult", None)
    assert cls is not None, "CAIPRReviewResult (step 18)"
    dispatcher = CAIPRInspectionDispatcher(OverwatchConfig())

    def aligned(_txn):
        return InspectionFinding(domain=InspectionDomain.INTENT,
                                 result=AlignmentResult.ALIGNED, severity=Severity.NOMINAL)

    for pid in ("p1", "p2", "p3"):
        dispatcher.register_platform(pid, aligned)
    result = dispatcher.dispatch(object())
    assert isinstance(result, cls)
    assert isinstance(result, CAIPRConsensus)
    assert result.consensus == "ALIGNED"
