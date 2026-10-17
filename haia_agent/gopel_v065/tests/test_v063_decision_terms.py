"""
GOPEL v0.6.3, step 16 (addendum 8): decision terms accept, modify, reject.

Reading a stored record:
    1. verify its stored bytes against the chain first;
    2. then read "approve" as "accept";
    3. never rewrite the stored bytes.

The legacy fixture is written by the real v0.6.2 base package
(haia_agent.gopel_v062) in a separate process, so this test process
never imports v0.6.2.

Author: Basil C. Puglisi, MPA
"""

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT))

from haia_agent.gopel_v065 import logger as lg  # noqa: E402
from haia_agent.gopel_v065.logger import AuditLogger  # noqa: E402
from haia_agent.gopel_v065.models import ArbitrationDecision, RECCLINRole  # noqa: E402


LEGACY_WRITER = r'''
import sys
sys.path.insert(0, sys.argv[1])
from haia_agent.gopel_v062.logger import AuditLogger
from haia_agent.gopel_v062.models import ArbitrationDecision, RECCLINRole
log = AuditLogger(sys.argv[2], operator_id="system")
log.log_arbitration(
    transaction_id="legacy-tx-1",
    operator_id="human_reviewer",
    arbitration_decision=ArbitrationDecision.APPROVE,
    rationale="Legacy approval written by GOPEL v0.6.2.",
    checkpoint_role=RECCLINRole.RESEARCHER,
    navigation_record_id="nav-legacy-1",
)
log.log_decision(
    transaction_id="legacy-tx-1",
    operator_id="human_reviewer",
    final_output="Legacy authorized output.",
    is_final=True,
)
'''


def write_legacy_file(path: Path) -> None:
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    subprocess.run(
        [sys.executable, "-c", LEGACY_WRITER, str(REPO_ROOT), str(path)],
        check=True, env=env, cwd=str(REPO_ROOT),
    )


def spec_content_hash(record: dict) -> str:
    """Gate 1 Shared Spec v1, section 3 formula (independent of GOPEL code)."""
    body = {k: v for k, v in record.items() if k not in (
        "content_hash", "previous_hash", "chain_hash", "sequence_number", "operator_signature")}
    return hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def spec_chain_hash(record: dict) -> str:
    return hashlib.sha256(
        (record["content_hash"] + record["previous_hash"]).encode("utf-8")).hexdigest()


def legacy_arbitration_index(records: list) -> int:
    return next(i for i, r in enumerate(records) if r["record_type"] == "arbitration")


def test_accept_is_valid(tmp_path):
    """"accept" is a valid decision value; the decision set is accept, modify, reject."""
    assert ArbitrationDecision("accept") is ArbitrationDecision.ACCEPT
    assert {d.value for d in ArbitrationDecision} == {"accept", "modify", "reject"}

    log = AuditLogger(tmp_path / "audit.json")
    log.log_arbitration(
        transaction_id="tx-accept",
        operator_id="human_reviewer",
        arbitration_decision="accept",
        rationale="Accepted after review of all platform responses.",
        checkpoint_role=RECCLINRole.RESEARCHER,
    )
    stored = log.get_records()[-1]
    assert stored["arbitration_decision"] == "accept"
    ok, violations = log.verify_chain_integrity()
    assert ok, violations

    # Carried code that names APPROVE writes "accept" (APPROVE is an alias).
    assert ArbitrationDecision.APPROVE is ArbitrationDecision.ACCEPT
    # "approve" is never written by v0.6.3.
    with pytest.raises(ValueError):
        ArbitrationDecision("approve")


def test_stored_approve_record_verifies_reads_as_accept_bytes_and_hash_unchanged(tmp_path):
    """A stored v0.6.2 "approve" record verifies, reads as "accept", and is not rewritten."""
    path = tmp_path / "legacy_audit.json"
    write_legacy_file(path)
    before_bytes = path.read_bytes()
    stored = json.loads(before_bytes)["records"]
    i = legacy_arbitration_index(stored)
    legacy = stored[i]
    assert legacy["arbitration_decision"] == "approve"
    # The stored record verifies under the spec formulas.
    assert spec_content_hash(legacy) == legacy["content_hash"]
    assert spec_chain_hash(legacy) == legacy["chain_hash"]

    records = lg.read_audit_file(path)

    read = records[i]
    assert read["arbitration_decision"] == "accept"
    assert read["content_hash"] == legacy["content_hash"]
    assert read["chain_hash"] == legacy["chain_hash"]
    assert read["record_id"] == legacy["record_id"]
    # Stored bytes are unchanged, and the stored value is still "approve".
    assert path.read_bytes() == before_bytes
    assert json.loads(path.read_bytes())["records"][i]["arbitration_decision"] == "approve"

    # A v0.6.3 logger loads the legacy file with the chain intact, keeps the
    # stored value, and reads it as accept through the verified reader.
    log = AuditLogger(path, create_new=False)
    ok, violations = log.verify_chain_integrity()
    assert ok, violations
    assert log.get_records()[i]["arbitration_decision"] == "approve"
    assert log.read_records()[i]["arbitration_decision"] == "accept"
    assert path.read_bytes() == before_bytes
    metrics = log.generate_governance_metrics()
    assert metrics["arbitration"]["accept_count"] == 1


def test_tampered_approve_record_fails_before_it_is_mapped(tmp_path, monkeypatch):
    """A tampered "approve" record fails verification, and no mapping happens."""
    calls = []
    original = lg.map_legacy_decision_term

    def spy(value):
        calls.append(value)
        return original(value)

    monkeypatch.setattr(lg, "map_legacy_decision_term", spy)

    # Tamper 1: the rationale of the stored approve record is edited.
    path = tmp_path / "tampered.json"
    write_legacy_file(path)
    data = json.loads(path.read_bytes())
    i = legacy_arbitration_index(data["records"])
    data["records"][i]["rationale"] = "Edited after the fact."
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tampered_bytes = path.read_bytes()
    with pytest.raises(lg.ChainIntegrityError):
        lg.read_audit_file(path)
    assert calls == []
    assert path.read_bytes() == tampered_bytes

    # Tamper 2: someone rewrites the stored "approve" as "accept".
    # Silent rewriting is detected, because the stored bytes are what verify.
    path2 = tmp_path / "rewritten.json"
    write_legacy_file(path2)
    data2 = json.loads(path2.read_bytes())
    data2["records"][i]["arbitration_decision"] = "accept"
    path2.write_text(json.dumps(data2, indent=2), encoding="utf-8")
    with pytest.raises(lg.ChainIntegrityError):
        lg.read_audit_file(path2)
    assert calls == []

    # Control: the untampered file is mapped, after verification.
    path3 = tmp_path / "clean.json"
    write_legacy_file(path3)
    lg.read_audit_file(path3)
    assert calls == ["approve"]
