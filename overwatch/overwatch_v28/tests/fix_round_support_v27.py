"""
HAIA-Overwatch v2.7 - Test support: the fix round fixture through the real pipeline

Basil's fix round after the seven-platform CAIPR review, item 2. The GOPEL
v0.6.5 records come only from the committed fixture
tests/fixtures/gopel_v065_mock_audit_v1.json (generator v3 on main), whose
provenance tags each transaction with its class and whether Overwatch must
stop on it. Nothing here imports GOPEL or the agents.

A stop is an escalated outcome that publishes one signed stop line; the
helpers count both.

Author: Basil C. Puglisi, MPA
License: CC BY-NC 4.0
Repository: github.com/basilpuglisi/HAIA
Attribution: #AIassisted under HAIA-RECCLIN & Checkpoint-Based Governance
"""

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from overwatch_v28.channel_manager import StopChannelPublisher
from overwatch_v28.gopel_observer import GopelObserver, GopelSchemaExpectation
from overwatch_v28.models import (
    OverwatchConfig, PlatformResponse, RECCLINRole, TransactionRecord,
)
from overwatch_v28.pipeline import OverwatchPipeline
from overwatch_v28.tests.gopel_fixture_support_v25 import audit_document, load_fixture

FIXTURE_V065 = "gopel_v065_mock_audit_v1.json"
GOPEL_VERSION = "0.6.5"
STOP_KEY = hashlib.sha256(b"overwatch v2.7 fix round stop key").digest()
KEY_ID = "overwatch-v27-stop-key"
TARGET = "gopel-v065-fixture-instance"

PRIMARY_URL = "https://example.org/eu-ai-act/article-12"
GUIDE_URL = "https://example.net/guides/agent-records"
CITED_PROMPT = ("Mode selected. Task: summarize the record-keeping duty. "
                f"Primary source: {PRIMARY_URL}")
CLEAN_CLASSES = ("clean-model1", "clean-model2")


def config() -> OverwatchConfig:
    """Published defaults, with Part 1 structural inputs not required, so
    these tests measure inspection alone."""
    return OverwatchConfig(require_structural_inputs=False)


def fixture() -> Dict[str, Any]:
    return load_fixture(FIXTURE_V065)


def transactions(klass: Optional[str] = None) -> List[Dict[str, Any]]:
    out = fixture()["provenance"]["transactions"]
    return [t for t in out if klass is None or t["class"] == klass]


def tids(*classes: str) -> List[str]:
    return [t["transaction_id"] for t in transactions() if t["class"] in classes]


def records_of(tid: str, record_type: Optional[str] = None) -> List[Dict[str, Any]]:
    return [r for r in fixture()["records"]
            if r["transaction_id"] == tid and (record_type is None or r["record_type"] == record_type)]


@dataclass
class Run:
    outcomes: Dict[str, Any]
    stop_lines: List[Dict[str, Any]]
    observer: Any
    pipeline: Any
    stopped: set = field(default_factory=set)


def stop_publisher(tmp_path, name: str = "stops.jsonl") -> StopChannelPublisher:
    return StopChannelPublisher(channel_path=str(tmp_path / name), key_id=KEY_ID,
                                stop_key=STOP_KEY, target_pipeline=TARGET)


def read_stop_lines(tmp_path, name: str = "stops.jsonl") -> List[Dict[str, Any]]:
    path = tmp_path / name
    if not path.exists():
        return []
    return [json.loads(json.loads(line)["body"]) for line in path.read_text(encoding="utf-8").splitlines()]


def run_fixture(tmp_path, document: Optional[Dict[str, Any]] = None, pipeline: Any = None) -> Run:
    """The whole fixture through one real OverwatchPipeline with a stop
    publisher attached, as GOPEL wrote it."""
    pipeline = pipeline or OverwatchPipeline(config())
    pipeline.attach_stop_publisher(stop_publisher(tmp_path))
    observer = GopelObserver(pipeline, config=config(),
                             schema_expectation=GopelSchemaExpectation(gopel_version=GOPEL_VERSION))
    outcomes = observer.observe_audit_document(document or audit_document(fixture()),
                                               source_gopel_version=GOPEL_VERSION)
    lines = read_stop_lines(tmp_path)
    run = Run(outcomes={o.transaction_id: o for o in outcomes}, stop_lines=lines,
              observer=observer, pipeline=pipeline)
    run.stopped = {line["transaction_id"] for line in lines}
    return run


def findings_of(outcome) -> List[Any]:
    return list(outcome.structural_findings) + list(outcome.inspection_findings)


def synthetic(answer: str, role: RECCLINRole = RECCLINRole.RESEARCHER, prompt: str = CITED_PROMPT,
              error_detail: str = "", navigator_output: Optional[str] = None,
              operator_id: str = "agent_model_2") -> TransactionRecord:
    """One transaction shaped as the observer assembles a GOPEL channel group."""
    meta = {"response_status": "error" if error_detail else "received", "error_detail": error_detail}
    return TransactionRecord(
        transaction_id=f"syn-{uuid.uuid4().hex[:12]}", timestamp=time.time(), operator_id=operator_id,
        recclin_role=role, prompt_hash="h", prompt_text=prompt, platforms_dispatched=["p1"],
        responses=[PlatformResponse(platform_id="p1", response_text=answer, response_hash="r",
                                    response_time_ms=10.0, metadata=meta)],
        navigator_output=navigator_output,
    )


def inspect_one(tmp_path, txn: TransactionRecord, pipeline: Any = None):
    """One transaction through a fresh real pipeline; returns (outcome, stop lines)."""
    pipeline = pipeline or OverwatchPipeline(config())
    if getattr(pipeline, "_stop_publisher", None) is None:
        pipeline.attach_stop_publisher(stop_publisher(tmp_path))
    outcome = pipeline.inspect(txn)
    return outcome, [line for line in read_stop_lines(tmp_path) if line["transaction_id"] == txn.transaction_id]
