"""
HAIA-Overwatch v2.8 - Tests: the v2.8 change log and changed checks

Change logs go in a new file for each version; the change logs of v2.5,
v2.6 and v2.7 are carried unchanged beside it. CHANGES_v2_8.md records what
v2.8 changes and why, its measured limits, and the correction to commit
afa82f1's message that every new change log carries. CHANGED_CHECKS_v2_8.md
lists every carried check that changed.

Author: Basil C. Puglisi, MPA
License: CC BY-NC 4.0
Repository: github.com/basilpuglisi/HAIA
"""

from pathlib import Path

import overwatch_v28

PACKAGE_DIR = Path(overwatch_v28.__file__).resolve().parent


def test_the_v2_8_change_log_exists_and_names_each_change():
    text = (PACKAGE_DIR / "CHANGES_v2_8.md").read_text(encoding="utf-8")
    assert "—" not in text and "–" not in text
    for needle in ("2.8.0", "choices 8 and 9", "markdown image", "any inflection", "moves data",
                   "imperative sentence that hands over data", "query string", "stated trade-off",
                   "13 of the 22", "set_chain_anchor", "restart_anchor_missing", "history_rewritten",
                   "records_replayed", "test_known_limits_v28.py", "stop the pipe, route to human"):
        assert needle.lower() in text.lower(), needle


def test_the_v2_8_change_log_records_the_afa82f1_correction():
    text = (PACKAGE_DIR / "CHANGES_v2_8.md").read_text(encoding="utf-8")
    assert "afa82f1" in text
    assert "ModuleNotFoundError" in text


def test_the_changed_checks_file_lists_the_carried_changes():
    text = (PACKAGE_DIR / "CHANGED_CHECKS_v2_8.md").read_text(encoding="utf-8")
    assert "—" not in text and "–" not in text
    for needle in ("overwatch_v27", "overwatch_v28", "gopel_v065_mock_audit_v1.json", "2.8.0",
                   "test_version_wording_v25.py", "test_calibration_v24.py", "test_overwatch.py",
                   "test_changes_v27.py"):
        assert needle in text, needle


def test_the_earlier_change_logs_are_carried_unchanged():
    for name, folder in (("CHANGES_v2_5.md", "overwatch_v25"), ("CHANGES_v2_6.md", "overwatch_v26"),
                         ("CHANGES_v2_7.md", "overwatch_v27"), ("CHANGED_CHECKS_v2_6.md", "overwatch_v26"),
                         ("CHANGED_CHECKS_v2_7.md", "overwatch_v27")):
        assert (PACKAGE_DIR / name).read_bytes() == (PACKAGE_DIR.parent / folder / name).read_bytes(), name
