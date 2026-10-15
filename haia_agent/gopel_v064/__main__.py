"""
HAIA Agent Framework - GOPEL v0.6.4 Entry Point
================================================
python -m haia_agent.gopel_v064

Prints the version and runs the non-cognitive static analyzer over this
package. Exit code 0 only if the analyzer reports the package compliant.

Author: Basil C. Puglisi, MPA
"""

from __future__ import annotations

import sys

from . import __version__
from .static_analyzer import NonCognitiveAnalyzer


def main() -> int:
    print(f"GOPEL v{__version__} (haia_agent.gopel_v064)")
    analyzer = NonCognitiveAnalyzer()
    result = analyzer.scan()
    print(analyzer.format_report(result))
    return 0 if result.is_compliant else 1


if __name__ == "__main__":
    sys.exit(main())
