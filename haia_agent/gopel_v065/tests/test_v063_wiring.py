"""
GOPEL v0.6.3, step 25: wire two v0.6.2 fixes.

SEC-03: GovernanceRuntime.authorize passes transaction_id into gate.check,
        so a second approver's signature is bound to one transaction.
SEC-06: SecureAuditLogger passes witness_hmac_key through to HashWitness,
        so a tampered witness file is detected on load.

Author: Basil C. Puglisi, MPA
"""

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT))

from haia_agent.gopel_v065 import governance as gov  # noqa: E402
from haia_agent.gopel_v065.models import ArbitrationDecision, RECCLINRole  # noqa: E402
from haia_agent.gopel_v065.secure_logger import SecureAuditLogger  # noqa: E402
from haia_agent.gopel_v065.secure_pipeline import SecureArbitrationInput  # noqa: E402
from haia_agent.gopel_v065.security import OperatorIdentity, OperatorRegistry  # noqa: E402
from haia_agent.gopel_v065.tests import v063_support as sup  # noqa: E402


def _override_runtime():
    registry = OperatorRegistry()
    ann = OperatorIdentity("gov_officer_ann")
    registry.register_operator(ann)
    runtime = gov.GovernanceRuntime(operator_registry=registry)
    runtime.bootstrap_register(gov.OperatorProfile(
        operator_id="gov_officer_mark", roles={gov.OperatorRole.GOVERNANCE_OFFICER}))
    runtime.bootstrap_register(gov.OperatorProfile(
        operator_id="gov_officer_ann", roles={gov.OperatorRole.GOVERNANCE_OFFICER}))
    runtime.register_evidence_gate(
        gov.GovAction.OVERRIDE_CIRCUIT_BREAKER.value, gov.CIRCUIT_BREAKER_OVERRIDE_GATE)
    return runtime, ann


def _override_evidence(ann, signed_for_tid: str):
    approval = gov.EvidenceSubmission(
        evidence_type=gov.EvidenceType.SECOND_APPROVER,
        content="gov_officer_ann",
        submitted_by="gov_officer_ann",
    )
    approval.signature = ann.sign_record(approval.signable_payload(
        transaction_id=signed_for_tid,
        gate_name=gov.CIRCUIT_BREAKER_OVERRIDE_GATE.gate_name,
    ))
    return [
        gov.EvidenceSubmission(gov.EvidenceType.JUSTIFICATION, sup.JUSTIFICATION_TEXT, "gov_officer_mark"),
        gov.EvidenceSubmission(gov.EvidenceType.RISK_ASSESSMENT, sup.RISK_TEXT, "gov_officer_mark"),
        approval,
    ]


def test_sec03_authorize_binds_approver_signature_to_transaction():
    runtime, ann = _override_runtime()
    evidence = _override_evidence(ann, signed_for_tid="tx-001")

    granted = runtime.authorize(
        "gov_officer_mark", gov.GovAction.OVERRIDE_CIRCUIT_BREAKER,
        evidence=evidence, transaction_id="tx-001",
    )
    assert granted.authorized, granted.reason

    # The same signature replayed for a different transaction is refused.
    replayed = runtime.authorize(
        "gov_officer_mark", gov.GovAction.OVERRIDE_CIRCUIT_BREAKER,
        evidence=evidence, transaction_id="tx-002",
    )
    assert not replayed.authorized
    assert "signature verification failed" in replayed.reason


def test_sec03_secure_pipeline_passes_transaction_id_to_authorize(tmp_path):
    runtime, _ = sup.make_runtime(register_release_gate=False)
    seen = []
    original = runtime.authorize

    def spy(*args, **kwargs):
        seen.append((kwargs.get("action"), kwargs.get("transaction_id")))
        return original(*args, **kwargs)

    runtime.authorize = spy
    pipeline, _, _ = sup.make_pipeline("secure", tmp_path, with_channel=False, runtime=runtime)
    result = sup.run(pipeline)
    assert result.success, result.error
    recorded = pipeline.record_arbitration(
        transaction_id=result.transaction_id,
        human_operator_id="analyst_jane",
        arbitration=SecureArbitrationInput(
            decision=ArbitrationDecision.MODIFY,
            rationale="Modified after review of the three platform responses.",
        ),
        checkpoint_role=RECCLINRole.RESEARCHER,
        navigation_record_id=result.checkpoint_package.navigation_record_id,
    )
    assert recorded
    assert (gov.GovAction.EXECUTE_PIPELINE, result.transaction_id) in seen
    assert (gov.GovAction.RECORD_ARBITRATION, result.transaction_id) in seen


def test_sec06_secure_logger_passes_witness_hmac_key(tmp_path):
    registry = OperatorRegistry()
    registry.register_operator(OperatorIdentity("system"))
    audit_path = tmp_path / "audit_dir" / "audit.json"
    witness_path = tmp_path / "witness_dir" / "witness.json"
    key = "witness-hmac-key-for-tests-0123456789"

    logger = SecureAuditLogger(
        audit_file_path=audit_path,
        operator_registry=registry,
        witness_path=witness_path,
        witness_interval=1,
        witness_hmac_key=key,
    )
    logger.log_system_event("test_event", "witnessed record")
    data = json.loads(witness_path.read_text(encoding="utf-8"))
    assert data.get("hmac"), "witness file must carry an HMAC when a key is configured"

    # Reload with the key: verifies.
    SecureAuditLogger(
        audit_file_path=audit_path, operator_registry=registry,
        witness_path=witness_path, witness_interval=1, witness_hmac_key=key,
        create_new=False,
    )

    # Tamper with the witness file: reload with the key is refused.
    data["witnesses"][0]["chain_hash"] = "0" * 64
    witness_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    with pytest.raises(ValueError):
        SecureAuditLogger(
            audit_file_path=audit_path, operator_registry=registry,
            witness_path=witness_path, witness_interval=1, witness_hmac_key=key,
            create_new=False,
        )
