"""
HAIA-Overwatch v2.1 - Structured Logger

Centralised structured logging for all Overwatch modules.
Outputs JSON Lines format with consistent fields: timestamp, level,
module, event, and arbitrary structured extras.

Consolidates the _sanitize_log() helper previously duplicated across
gopel_observer.py, channel_manager.py, and pipeline.py.

Author: Basil C. Puglisi, MPA
License: CC BY-NC 4.0
Repository: github.com/basilpuglisi/HAIA
Attribution: #AIassisted under HAIA-RECCLIN & Checkpoint-Based Governance
"""

import json
import logging
import re
import time
from typing import Any, Dict, Optional


# ---------------------------------------------------------------------------
# Log sanitisation (consolidated from 3 module-level duplicates)
# ---------------------------------------------------------------------------

_ANSI_RE = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]')
_MAX_LOG_VALUE_LENGTH = 500


def sanitize_log_value(value: str) -> str:
    """Strip ANSI escapes, control characters, and truncate long values.

    Prevents log injection via crafted transaction IDs, error messages,
    or other externally influenced strings that flow into log records.

    Args:
        value: Raw string to sanitise

    Returns:
        Sanitised string safe for log output
    """
    # Strip ANSI escape sequences
    value = _ANSI_RE.sub('', value)
    # Strip control characters except tab; replace with '?'
    value = ''.join(
        c if c == '\t' or (c >= ' ' and c != '\x7f') else '?'
        for c in value
    )
    # Truncate overly long values
    if len(value) > _MAX_LOG_VALUE_LENGTH:
        value = value[:_MAX_LOG_VALUE_LENGTH] + '...[truncated]'
    return value


# ---------------------------------------------------------------------------
# JSON Lines formatter
# ---------------------------------------------------------------------------

class JSONLinesFormatter(logging.Formatter):
    """Formats log records as single-line JSON objects.

    Output fields:
        timestamp   ISO-8601 UTC string
        level       DEBUG / INFO / WARNING / ERROR / CRITICAL
        module      Logger name (e.g. "overwatch.pipeline")
        event       The log message after %-formatting
        extras      Dict of structured key/value pairs passed via `extra`

    Any extra keys attached to the LogRecord (beyond standard attributes)
    are collected into the 'extras' dict automatically.
    """

    # Standard LogRecord attributes to exclude from extras
    _STANDARD_ATTRS = frozenset({
        'name', 'msg', 'args', 'created', 'relativeCreated', 'exc_info',
        'exc_text', 'stack_info', 'lineno', 'funcName', 'pathname',
        'filename', 'module', 'levelno', 'levelname', 'msecs', 'thread',
        'threadName', 'process', 'processName', 'message', 'taskName',
    })

    def format(self, record: logging.LogRecord) -> str:
        """Format a LogRecord as a JSON Lines entry."""
        # Let the parent resolve %-formatting and exception info
        record.message = record.getMessage()

        # Collect non-standard attributes as structured extras
        extras: Dict[str, Any] = {}
        for key, val in record.__dict__.items():
            if key.startswith('_') or key in self._STANDARD_ATTRS:
                continue
            extras[key] = val

        entry: Dict[str, Any] = {
            "timestamp": time.strftime(
                "%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)
            ) + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "module": record.name,
            "event": record.message,
        }

        if extras:
            entry["extras"] = extras

        # Append exception info if present
        if record.exc_info and record.exc_info[1]:
            entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(entry, default=str)


# ---------------------------------------------------------------------------
# Logger factory
# ---------------------------------------------------------------------------

_HANDLER_INSTALLED = False


def _ensure_handler() -> None:
    """Install the JSON Lines handler on the 'overwatch' root logger once."""
    global _HANDLER_INSTALLED
    if _HANDLER_INSTALLED:
        return

    root = logging.getLogger("overwatch")
    # Only add our handler if none are present (avoids duplicate output
    # when the application has already configured logging).
    if not root.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(JSONLinesFormatter())
        root.addHandler(handler)
        root.setLevel(logging.DEBUG)

    _HANDLER_INSTALLED = True


def get_logger(name: str) -> logging.Logger:
    """Return a structured logger under the ``overwatch.*`` namespace.

    All Overwatch modules should call this instead of
    ``logging.getLogger()``. The first call installs a JSON Lines
    handler on the ``overwatch`` root logger.

    Args:
        name: Module name, typically ``__name__``. If it does not start
              with ``overwatch.``, it is prefixed automatically.

    Returns:
        A ``logging.Logger`` instance under the ``overwatch`` hierarchy.
    """
    if not name.startswith("overwatch"):
        # Convert e.g. "overwatch.gopel_observer" (from __name__ inside
        # the package) or bare "pipeline" into the canonical namespace.
        name = f"overwatch.{name}"

    _ensure_handler()
    return logging.getLogger(name)
