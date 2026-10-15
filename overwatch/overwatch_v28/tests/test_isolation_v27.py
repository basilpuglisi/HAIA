"""
HAIA-Overwatch v2.7 - Tests: zero imports from GOPEL or the agents

Basil's fix round keeps the invariant: Overwatch has zero imports from GOPEL
or the agents, tests included, and stays read only toward GOPEL. The
carried test_isolation_v25.py scans for GOPEL; this file adds the agents
(Agent Model 1's runner and Agent Model 2's gateway) to the same
syntax-tree scan, across the v2.7 modules and tests.

Author: Basil C. Puglisi, MPA
License: CC BY-NC 4.0
Repository: github.com/basilpuglisi/HAIA
Attribution: #AIassisted under HAIA-RECCLIN & Checkpoint-Based Governance
"""

import ast
from pathlib import Path

import pytest

import overwatch_v28
from overwatch_v28.tests.test_isolation_v25 import gopel_imports_in_source

PACKAGE_DIR = Path(overwatch_v28.__file__).resolve().parent
AGENT_PREFIXES = ("cbg_gateway_model", "cbg_model1_russell", "Models1to3")


def agent_imports_in_source(source: str, filename: str = "<src>"):
    found = []
    for node in ast.walk(ast.parse(source, filename=filename)):
        names = []
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            names = [node.module]
        elif isinstance(node, ast.Call) and node.args:
            func = node.func
            name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
            last = node.args[-1]
            if name in ("__import__", "import_module", "insert", "append") and isinstance(last, ast.Constant):
                names = [last.value]
        for n in names:
            if isinstance(n, str) and any(p in n for p in AGENT_PREFIXES):
                found.append((filename, getattr(node, "lineno", 0), n))
    return found


def _files():
    return sorted(p for p in PACKAGE_DIR.rglob("*.py") if "__pycache__" not in p.parts)


def test_zero_gopel_or_agent_imports_across_modules_and_tests():
    files = _files()
    assert len([p for p in files if p.parent.name == "tests"]) >= 36
    found = []
    for path in files:
        source = path.read_text(encoding="utf-8")
        found += gopel_imports_in_source(source, str(path)) + agent_imports_in_source(source, str(path))
    assert found == []


@pytest.mark.parametrize("snippet", [
    "import cbg_model1_russell_v6 as m1",
    "from cbg_gateway_model2_v12 import Gateway",
    "import importlib\nimportlib.import_module('cbg_model1_russell_v6')",
    "import sys\nsys.path.insert(0, '/home/user/HAIA/haia_agent/Models1to3')",
])
def test_the_scanner_detects_agent_imports(snippet):
    assert agent_imports_in_source(snippet) != []
