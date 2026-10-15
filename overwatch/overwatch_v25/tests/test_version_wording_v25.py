"""
HAIA-Overwatch v2.5 - Tests: version strings and wording

Plan step 24. R9: published works stand; each correction ships with its
fix, as the next version.

- OverwatchPipeline.VERSION equals __version__, "2.5.0" (v2.4 had
  VERSION "1.0.0" at pipeline.py:56 and __version__ "2.4.0").
- Every module header line reads v2.5; author and license lines are
  carried verbatim.
- The CalibrationState docstring states the floors 0.15, 0.05 and 0.03
  without calling them GOPEL-mode values (the GOPEL-mode thresholds are
  0.2, 0.10 and 0.05, paper section 6.4). No number changes.

Author: Basil C. Puglisi, MPA
License: CC BY-NC 4.0
Repository: github.com/basilpuglisi/HAIA
Attribution: #AIassisted under HAIA-RECCLIN & Checkpoint-Based Governance
"""

import ast
import inspect
import re
from pathlib import Path

import pytest

import overwatch_v25
from overwatch_v25.models import CalibrationState, OverwatchConfig
from overwatch_v25.pipeline import OverwatchPipeline

PACKAGE_DIR = Path(overwatch_v25.__file__).resolve().parent
V24_DIR = PACKAGE_DIR.parent / "overwatch"
MODULES = sorted(p.name for p in V24_DIR.glob("*.py"))
HEADER_KEYS = ("Author:", "License:", "Repository:", "Attribution:")


def test_version_strings_agree_at_2_5_0():
    assert overwatch_v25.__version__ == "2.5.0"
    assert OverwatchPipeline.VERSION == overwatch_v25.__version__
    pipeline = OverwatchPipeline(OverwatchConfig(require_structural_inputs=False))
    assert pipeline.get_status()["version"] == "2.5.0"


def test_all_seventeen_files_are_present():
    assert len(MODULES) == 17
    for name in MODULES:
        assert (PACKAGE_DIR / name).exists(), name


@pytest.mark.parametrize("name", MODULES)
def test_module_header_reads_v2_5(name):
    doc = ast.get_docstring(ast.parse((PACKAGE_DIR / name).read_text(encoding="utf-8")))
    first = doc.strip().splitlines()[0]
    assert re.match(r"^HAIA-Overwatch v2\.5\b", first), f"{name}: {first!r}"


@pytest.mark.parametrize("name", MODULES)
def test_author_and_license_lines_are_carried_verbatim(name):
    old = (V24_DIR / name).read_text(encoding="utf-8").splitlines()
    new = (PACKAGE_DIR / name).read_text(encoding="utf-8").splitlines()
    carried = [l for l in old[:25] if l.strip().startswith(HEADER_KEYS)]
    assert carried, f"{name} has no author or license lines in v2.4"
    for line in carried:
        assert line in new[:40], f"{name}: {line!r} not carried verbatim"


def test_calibration_floor_docstring_states_the_floors():
    doc = CalibrationState.__doc__
    for value in ("0.15", "0.05", "0.03"):
        assert value in doc
    assert "GOPEL-mode values" not in doc
    assert "GOPEL mode values" not in doc
    assert not re.search(r"floor\s*\(\s*GOPEL", doc, re.I)
    source = inspect.getsource(CalibrationState)
    assert "GOPEL-mode tightest" not in source


def test_no_numbers_changed():
    state = CalibrationState()
    assert (state.scope_drift_floor, state.coherence_decay_floor,
            state.privilege_gradient_floor) == (0.15, 0.05, 0.03)
    assert (state.scope_drift_ceiling, state.coherence_decay_ceiling,
            state.privilege_gradient_ceiling) == (0.60, 0.30, 0.20)
    assert (state.scope_drift_threshold, state.coherence_decay_threshold,
            state.privilege_gradient_threshold) == (0.3, 0.15, 0.1)
    gm = OverwatchConfig(gopel_mode=True)
    assert (gm.trajectory_scope_drift_threshold, gm.trajectory_coherence_decay_threshold,
            gm.trajectory_privilege_gradient_threshold) == (0.2, 0.10, 0.05)


def test_changes_file_records_the_corrections_without_long_dashes():
    changes = PACKAGE_DIR / "CHANGES_v2_5.md"
    assert changes.exists()
    text = changes.read_text(encoding="utf-8")
    assert "\u2014" not in text and "\u2013" not in text
    for needle in ("Cross AI Platform Review", "paragraph 77", "paragraph 121",
                   "2.5.0", "stop", "keyed"):
        assert needle.lower() in text.lower(), needle
