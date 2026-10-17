"""
GOPEL v0.6.4: the non-cognitive analyzer covers every GOPEL module.

The analyzer scans a fixed list of files (static_analyzer.SCAN_TARGETS), so
a module left off the list would be skipped without any warning. This test
fails if any module of the package outside adapters/ and tests/ is not on
the list (the analyzer itself excepted), and checks that the new channel module is scanned and clean.

Author: Basil C. Puglisi, MPA
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from haia_agent.gopel_v065 import static_analyzer as sa  # noqa: E402

PKG = Path(sa.__file__).resolve().parent


# The analyzer holds the very patterns it searches for, so it is the one
# module it does not scan; every other module must be on the list.
NOT_SCANNED = {"static_analyzer.py"}


def test_every_gopel_module_outside_adapters_and_tests_is_scanned():
    modules = sorted(p.name for p in PKG.glob("*.py"))
    missing = [m for m in modules if m not in sa.SCAN_TARGETS and m not in NOT_SCANNED]
    assert missing == []


def test_the_channel_module_is_scanned_and_the_package_is_compliant():
    assert "channel.py" in sa.SCAN_TARGETS
    assert (PKG / "channel.py").exists()
    result = sa.NonCognitiveAnalyzer().scan()
    assert result.files_scanned == len(sa.SCAN_TARGETS)
    assert result.is_compliant and result.violations == []
