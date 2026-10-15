"""
GOPEL v0.6.3, step 27 (addendum 7): packaging.

v0.6.1 (haia_agent.gopel), the v0.6.2 base (haia_agent.gopel_v062), and
v0.6.3 (haia_agent.gopel_v063), v0.6.4 (haia_agent.gopel_v064), and v0.6.5
(haia_agent.gopel_v065) each have their own import path.
v0.6.5's entry point is `python -m haia_agent.gopel_v065`, which prints
the version and runs the non-cognitive analyzer.

Author: Basil C. Puglisi, MPA
"""

import json
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT))

ENV = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")

RUN_V063 = r'''
import json, sys, tempfile
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import haia_agent.gopel_v065 as g
from haia_agent.gopel_v065 import (
    ArbitrationDecision, ArbitrationInput, AuditLogger, GOPELPipeline, MockAdapter,
    NavigatorRouter, OperatingModel, PlatformSelector, RECCLINRole, SecureGOPELPipeline,
    SecureArbitrationInput,
)
from haia_agent.gopel_v065.static_analyzer import NonCognitiveAnalyzer

with tempfile.TemporaryDirectory() as tmp:
    results = []
    for kind in ("base", "secure"):
        logger = AuditLogger(Path(tmp) / kind / "audit.json")
        selector = PlatformSelector()
        for pid in ("mock_a", "mock_b", "mock_c"):
            selector.register_adapter(MockAdapter(pid, pid + "-model", simulate_latency_ms=0))
        selector.set_anchor("mock_a")
        nav = NavigatorRouter(MockAdapter("mock_nav", "nav-model", simulate_latency_ms=0))
        if kind == "base":
            p = GOPELPipeline(logger, selector, nav)
            arb = ArbitrationInput(ArbitrationDecision.MODIFY, "Modified after human review.")
        else:
            p = SecureGOPELPipeline(logger, selector, nav, require_authentication=False)
            arb = SecureArbitrationInput(ArbitrationDecision.MODIFY, "Modified after human review.")
        r = p.execute("Packaging check prompt.", RECCLINRole.RESEARCHER,
                      OperatingModel.MODEL_1, "human_operator")
        p.record_arbitration(r.transaction_id, "human_operator", arb,
                             RECCLINRole.RESEARCHER, r.checkpoint_package.navigation_record_id)
        results.append(bool(r.success))
    NonCognitiveAnalyzer().scan()

bad = sorted(
    m for m in sys.modules
    if m == "haia_agent.gopel" or m.startswith("haia_agent.gopel.")
    or m.startswith("haia_agent.gopel_v062")
    or m.startswith("haia_agent.gopel_v063")
    or m.startswith("haia_agent.gopel_v064")
)
print(json.dumps({"bad": bad, "results": results, "version": g.__version__,
                  "loaded_v063": sorted(m for m in sys.modules if m.startswith("haia_agent.gopel_v065"))}))
'''


def test_import_and_run_v063_loads_no_v061_or_v062_module():
    proc = subprocess.run(
        [sys.executable, "-c", RUN_V063, str(REPO_ROOT)],
        capture_output=True, text=True, env=ENV, cwd=str(REPO_ROOT), timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout.strip().splitlines()[-1])
    assert out["bad"] == []
    assert out["results"] == [True, True]
    assert "haia_agent.gopel_v065.pipeline" in out["loaded_v063"]
    assert "haia_agent.gopel_v065.secure_pipeline" in out["loaded_v063"]


def test_entry_point_prints_version_and_runs_analyzer():
    proc = subprocess.run(
        [sys.executable, "-m", "haia_agent.gopel_v065"],
        capture_output=True, text=True, env=ENV, cwd=str(REPO_ROOT), timeout=120,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "0.6.5" in proc.stdout
    assert "NON-COGNITIVE CONSTRAINT STATIC ANALYSIS REPORT" in proc.stdout
    assert "Violations:    0" in proc.stdout
    assert "Compliant:     YES" in proc.stdout


def test_version_is_0_6_5():
    import haia_agent.gopel_v065 as g
    assert g.__version__ == "0.6.5"


def test_analyzer_scans_overwatch_stop_module():
    from haia_agent.gopel_v065 import static_analyzer as sa
    assert "overwatch_stop.py" in sa.SCAN_TARGETS
    assert (sa.Path(sa.__file__).parent / "overwatch_stop.py").exists()
    result = sa.NonCognitiveAnalyzer().scan()
    assert result.is_compliant
    assert result.violations == []
