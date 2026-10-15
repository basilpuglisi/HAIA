"""
HAIA-Overwatch v2.7 - Tests: the v2.7 change log and changed checks

Change logs go in a new file for each version; CHANGES_v2_5.md and
CHANGES_v2_6.md are carried unchanged beside it. CHANGES_v2_7.md records
what v2.7 changes and why, and the correction to commit afa82f1's message
that Basil's fix round asks every new change log to carry (item 6b).
CHANGED_CHECKS_v2_7.md lists every carried check that changed.

Author: Basil C. Puglisi, MPA
License: CC BY-NC 4.0
Repository: github.com/basilpuglisi/HAIA
Attribution: #AIassisted under HAIA-RECCLIN & Checkpoint-Based Governance
"""

from pathlib import Path

import overwatch_v27

PACKAGE_DIR = Path(overwatch_v27.__file__).resolve().parent


def test_the_v2_7_change_log_exists_and_names_each_change():
    text = (PACKAGE_DIR / "CHANGES_v2_7.md").read_text(encoding="utf-8")
    assert "—" not in text and "–" not in text
    for needle in ("2.7.0", "0.6.5", "T-1", "performed", "instructed", "cited", "logged warning",
                   "hard floor", "error_detail", "Navigation", "Editor", "text_escaped",
                   "stop the pipe, route to human"):
        assert needle.lower() in text.lower(), needle


def test_the_v2_7_change_log_records_the_afa82f1_correction():
    text = (PACKAGE_DIR / "CHANGES_v2_7.md").read_text(encoding="utf-8")
    assert "afa82f1" in text
    assert "ModuleNotFoundError" in text


def test_the_changed_checks_file_lists_the_carried_changes():
    text = (PACKAGE_DIR / "CHANGED_CHECKS_v2_7.md").read_text(encoding="utf-8")
    assert "—" not in text and "–" not in text
    for needle in ("overwatch_v26", "overwatch_v27", "gopel_v065_mock_audit_v1.json", "2.7.0", "0.6.5",
                   "test_version_wording_v25.py", "test_team_channel_v26.py", "gopel_fixture_support_v25.py"):
        assert needle in text, needle


def test_the_earlier_change_logs_are_carried_unchanged():
    for name, folder in (("CHANGES_v2_5.md", "overwatch_v25"), ("CHANGES_v2_6.md", "overwatch_v26"),
                         ("CHANGED_CHECKS_v2_6.md", "overwatch_v26")):
        assert (PACKAGE_DIR / name).read_bytes() == (PACKAGE_DIR.parent / folder / name).read_bytes(), name
