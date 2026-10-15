"""
HAIA-Overwatch v2.6 - Tests: the v2.6 change log

Change logs go in a new file for each version; CHANGES_v2_5.md is carried
unchanged beside it. CHANGES_v2_6.md records what v2.6 changes and why.

Author: Basil C. Puglisi, MPA
License: CC BY-NC 4.0
Repository: github.com/basilpuglisi/HAIA
Attribution: #AIassisted under HAIA-RECCLIN & Checkpoint-Based Governance
"""

from pathlib import Path

import overwatch_v28

PACKAGE_DIR = Path(overwatch_v28.__file__).resolve().parent


def test_the_v2_6_change_log_exists_and_names_each_change():
    text = (PACKAGE_DIR / "CHANGES_v2_6.md").read_text(encoding="utf-8")
    assert "—" not in text and "–" not in text
    for needle in ("2.6.0", "0.6.4", "channel_group_closed", "signed deployment manifest",
                   "local_test_unsigned_manifests", "stop the pipe, route to human"):
        assert needle.lower() in text.lower(), needle


def test_the_v2_5_change_log_is_carried_unchanged():
    v25 = PACKAGE_DIR.parent / "overwatch_v25" / "CHANGES_v2_5.md"
    assert (PACKAGE_DIR / "CHANGES_v2_5.md").read_bytes() == v25.read_bytes()
