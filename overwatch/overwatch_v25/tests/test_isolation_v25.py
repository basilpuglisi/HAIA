"""
HAIA-Overwatch v2.5 - Tests: isolation invariant

Plan step 14c (guards). Paper sections 4.2, 4.3 and 8.

- GopelRecord is frozen.
- Overwatch never writes back into GOPEL: the observer reads only, and
  the stop publisher writes only its own channel file.
- Zero imports of haia_agent or any GOPEL module across the overwatch_v25
  modules AND tests (syntax-tree scan).

Author: Basil C. Puglisi, MPA
License: CC BY-NC 4.0
Repository: github.com/basilpuglisi/HAIA
Attribution: #AIassisted under HAIA-RECCLIN & Checkpoint-Based Governance
"""

import ast
import copy
import dataclasses
import hashlib
import json
import os
import stat
import time
from pathlib import Path

import pytest

import overwatch_v25
from overwatch_v25.gopel_observer import (
    GopelObserver, GopelRecord, GopelRecordKind, assemble_transaction,
)
from overwatch_v25.models import OverwatchConfig
from overwatch_v25.tests.gopel_fixture_support_v25 import (
    RecordingPipeline,
    alerts,
    audit_document,
    channel_with_sink,
    fixture_records,
    require,
)

try:
    from overwatch_v25.channel_manager import StopChannelPublisher
except ImportError:  # absent before step 20
    StopChannelPublisher = None

PACKAGE_DIR = Path(overwatch_v25.__file__).resolve().parent

# Top-level names that belong to GOPEL. Built from parts so this file does
# not itself spell an import of them anywhere a scanner could misread.
GOPEL_PACKAGE = "haia" + "_agent"
GOPEL_MODULE_NAMES = {
    "secure_pipeline", "secure_logger", "sentinel", "breach", "governance",
    "navigator", "navigator_validator", "selector", "static_analyzer",
    "adapters", "overwatch_stop",
}


def _is_gopel_name(dotted: str) -> bool:
    top = dotted.split(".")[0]
    return (
        top == GOPEL_PACKAGE
        or top.startswith("gopel")
        or top in GOPEL_MODULE_NAMES
    )


def gopel_imports_in_source(source: str, filename: str = "<src>"):
    """Return every import of a GOPEL module found in *source*."""
    found = []
    tree = ast.parse(source, filename=filename)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if _is_gopel_name(alias.name):
                    found.append((filename, node.lineno, alias.name))
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module and _is_gopel_name(node.module):
                found.append((filename, node.lineno, node.module))
        elif isinstance(node, ast.Call):
            func = node.func
            name = (func.id if isinstance(func, ast.Name)
                    else func.attr if isinstance(func, ast.Attribute) else "")
            if name in ("__import__", "import_module") and node.args:
                arg = node.args[0]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    if _is_gopel_name(arg.value):
                        found.append((filename, node.lineno, arg.value))
            if name in ("insert", "append") and isinstance(func, ast.Attribute):
                target = func.value
                if (isinstance(target, ast.Attribute) and target.attr == "path"
                        and isinstance(target.value, ast.Name) and target.value.id == "sys"):
                    for arg in node.args:
                        if (isinstance(arg, ast.Constant) and isinstance(arg.value, str)
                                and ("gopel" in arg.value.lower() or GOPEL_PACKAGE in arg.value)):
                            found.append((filename, node.lineno, arg.value))
    return found


def _python_files():
    return sorted(p for p in PACKAGE_DIR.rglob("*.py") if "__pycache__" not in p.parts)


class TestZeroImports:

    def test_zero_gopel_imports_across_modules_and_tests(self):
        files = _python_files()
        modules = [p for p in files if p.parent == PACKAGE_DIR]
        tests = [p for p in files if p.parent.name == "tests"]
        assert len(modules) >= 17, "16 modules plus __init__.py"
        assert len(tests) >= 16 + 9, "16 carried test files plus the new ones"
        found = []
        for path in files:
            found += gopel_imports_in_source(path.read_text(encoding="utf-8"), str(path))
        assert found == []

    @pytest.mark.parametrize("snippet", [
        "import " + GOPEL_PACKAGE,
        "from " + GOPEL_PACKAGE + ".models import AuditRecord",
        "import " + GOPEL_PACKAGE + ".gopel_v063.overwatch_stop as s",
        "from gopel_v063 import x",
        "import importlib\nimportlib.import_module('" + GOPEL_PACKAGE + ".logger')",
        "__import__('" + GOPEL_PACKAGE + "')",
        "import sys\nsys.path.insert(0, '/home/user/HAIA-overwatch/gopel-v062-locked')",
    ])
    def test_the_scanner_detects_gopel_imports(self, snippet):
        assert gopel_imports_in_source(snippet) != []

    def test_relative_overwatch_modules_are_not_flagged(self):
        assert gopel_imports_in_source("from .gopel_observer import GopelObserver") == []
        assert gopel_imports_in_source("from overwatch_v25.gopel_observer import GopelRecord") == []


class TestFrozenRecords:

    def test_legacy_gopel_record_is_frozen(self):
        record = GopelRecord(
            kind=GopelRecordKind.REQUEST, transaction_id="t", timestamp=1.0,
            payload={}, prev_hash="", this_hash="",
        )
        with pytest.raises(dataclasses.FrozenInstanceError):
            record.this_hash = "forged"
        assert not hasattr(record, "__dict__")

    def test_gopel_format_record_is_frozen(self):
        rec = next(r for r in fixture_records() if r["record_type"] == "response")
        record = GopelRecord.from_gopel_dict(rec)
        for field in ("payload", "this_hash", "prev_hash", "record_id", "content_hash", "raw_json"):
            with pytest.raises(dataclasses.FrozenInstanceError):
                setattr(record, field, None)

    def test_assembled_transaction_is_a_copy(self):
        request = GopelRecord(
            kind=GopelRecordKind.REQUEST, transaction_id="t", timestamp=1.0,
            payload={"prompt_text": "p", "metadata": {"k": ["v"]}},
            prev_hash="", this_hash="h",
        )
        txn = assemble_transaction({GopelRecordKind.REQUEST: request})
        txn.metadata["k"].append("mutated")
        assert request.payload["metadata"] == {"k": ["v"]}


class TestNoWriteBack:

    def test_observer_source_never_opens_files_for_writing(self):
        source = (PACKAGE_DIR / "gopel_observer.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        fs_modules = {"os", "shutil", "pathlib", "tempfile"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                name = (func.id if isinstance(func, ast.Name)
                        else func.attr if isinstance(func, ast.Attribute) else "")
                # writes through any receiver
                assert name not in ("write", "writelines", "write_text", "write_bytes",
                                    "unlink", "rmtree", "touch", "chmod"), name
                # filesystem changes through os / shutil / pathlib / tempfile
                if (isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name)
                        and func.value.id in fs_modules):
                    assert name not in ("remove", "rename", "replace", "makedirs", "mkdir",
                                        "open", "fdopen", "mkstemp", "move", "copy",
                                        "copyfile", "truncate"), f"{func.value.id}.{name}"
                if name == "open":
                    modes = [a.value for a in node.args[1:2] if isinstance(a, ast.Constant)]
                    modes += [k.value.value for k in node.keywords
                              if k.arg == "mode" and isinstance(k.value, ast.Constant)]
                    for mode in modes:
                        assert not set(str(mode)) & set("wax+"), f"write mode {mode!r}"

    def test_observer_has_no_write_methods(self):
        names = [n for n in dir(GopelObserver) if not n.startswith("__")]
        for bad in ("write", "modify", "delete", "update_gopel", "set_gopel"):
            assert not [n for n in names if bad in n.lower()], bad

    def test_observer_reads_a_read_only_audit_file_and_leaves_it_unchanged(self, tmp_path):
        gopel_dir = tmp_path / "gopel_runtime"
        gopel_dir.mkdir()
        audit = gopel_dir / "audit.json"
        audit.write_text(json.dumps(audit_document()), encoding="utf-8")
        os.chmod(audit, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
        before_bytes = hashlib.sha256(audit.read_bytes()).hexdigest()
        before_stat = audit.stat()
        before_listing = sorted(os.listdir(gopel_dir))
        time.sleep(0.01)

        cm, messages = channel_with_sink()
        observer = GopelObserver(RecordingPipeline(), channel_manager=cm,
                                 config=OverwatchConfig(require_structural_inputs=False))
        observer.observe_audit_file(str(audit))

        assert alerts(messages) == []
        assert observer.get_statistics()["records_parsed"] == len(fixture_records())
        assert hashlib.sha256(audit.read_bytes()).hexdigest() == before_bytes
        assert audit.stat().st_mtime_ns == before_stat.st_mtime_ns
        assert sorted(os.listdir(gopel_dir)) == before_listing

    def test_observer_never_mutates_the_records_it_is_given(self):
        doc = audit_document()
        pristine = copy.deepcopy(doc)
        observer = GopelObserver(RecordingPipeline(),
                                 config=OverwatchConfig(require_structural_inputs=False))
        observer.observe_audit_document(doc)
        assert doc == pristine

    def test_stop_publisher_writes_only_its_own_channel_file(self, tmp_path):
        publisher_cls = require(StopChannelPublisher, "StopChannelPublisher (step 20)")
        gopel_dir = tmp_path / "gopel_runtime"
        gopel_dir.mkdir()
        (gopel_dir / "audit.json").write_text("{}", encoding="utf-8")
        channel_dir = tmp_path / "overwatch_channel"
        channel_dir.mkdir()
        before = {p.name: p.read_bytes() for p in gopel_dir.iterdir()}

        publisher = publisher_cls(
            channel_path=str(channel_dir / "stops.jsonl"),
            key_id="stop-key-1",
            stop_key=b"s" * 32,
            target_pipeline="gopel-test-instance",
        )
        publisher.publish(transaction_id="t1", trigger="CRITICAL", finding_ids=["f1"],
                          gopel_record_refs=[])

        assert {p.name: p.read_bytes() for p in gopel_dir.iterdir()} == before
        assert sorted(os.listdir(channel_dir)) == ["stops.jsonl"]
