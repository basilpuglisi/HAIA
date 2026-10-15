"""
HAIA-Overwatch v2.5 - Tests: Factics persistence survives restarts

Plan step 23. Paper section 11.1: "The loop runs continuously with
persistent JSONL logs that survive pipeline restarts."

Defects in v2.4:
- reject_proposal never wrote to the log (factics_engine.py:350-369);
- rehydration reloaded pending proposals only, so approved proposals and
  their chain signatures were lost on restart (factics_engine.py:86-122);
- the pipeline built FacticsEngine() without its config, so
  proposals_log_path never reached it.

Author: Basil C. Puglisi, MPA
License: CC BY-NC 4.0
Repository: github.com/basilpuglisi/HAIA
Attribution: #AIassisted under HAIA-RECCLIN & Checkpoint-Based Governance
"""

import json

import pytest

from overwatch_v28.factics_engine import FacticsEngine
from overwatch_v28.models import (
    AlignmentResult, ChainSignature, InspectionDomain, InspectionFinding,
    OverwatchConfig, Severity, VerificationOutcome,
)
from overwatch_v28.pipeline import OverwatchPipeline


def _config(log_path, **kw):
    return OverwatchConfig(proposals_log_path=str(log_path), require_structural_inputs=False, **kw)


def _finding(tid, domain=InspectionDomain.INTENT):
    return InspectionFinding(
        domain=domain, result=AlignmentResult.FLAGGED, severity=Severity.CRITICAL,
        confidence=0.9, description=f"Multi-turn chain in {tid}",
        evidence_chain=["recon: probe", "privilege: escalate", "credential: dump"],
        transaction_id=tid,
    )


def _confirm(engine, tid):
    engine.process_confirmed_threat(_finding(tid), VerificationOutcome(transaction_id=tid), "confirmed")
    return [p for p in engine.get_pending_proposals() if p.source_finding_id][-1]


def _log_lines(path):
    with open(path, "r", encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip()]


class TestRejectIsPersisted:

    def test_reject_proposal_writes_to_the_log(self, tmp_path):
        log = tmp_path / "proposals.jsonl"
        engine = FacticsEngine(config=_config(log))
        proposal = _confirm(engine, "txn-reject")
        assert engine.reject_proposal(proposal.proposal_id, "not a real pattern")
        last = _log_lines(log)[-1]
        assert last["proposal_id"] == proposal.proposal_id
        assert last["status"] == "rejected"
        assert last["rule_approval_rationale"] == "not a real pattern"

    def test_rejected_proposal_stays_rejected_after_restart(self, tmp_path):
        log = tmp_path / "proposals.jsonl"
        engine = FacticsEngine(config=_config(log))
        proposal = _confirm(engine, "txn-reject-restart")
        engine.reject_proposal(proposal.proposal_id, "noise")
        restarted = FacticsEngine(config=_config(log))
        assert restarted.get_pending_proposals() == []
        assert [p.proposal_id for p in restarted.get_rejected_proposals()] == [proposal.proposal_id]
        assert restarted.get_rejected_proposals()[0].status == "rejected"


class TestApprovedSurviveRestart:

    def test_approved_proposals_reload_after_restart(self, tmp_path):
        log = tmp_path / "proposals.jsonl"
        engine = FacticsEngine(config=_config(log))
        proposal = _confirm(engine, "txn-approve")
        assert engine.approve_proposal(proposal.proposal_id, "confirmed by CBG")
        restarted = FacticsEngine(config=_config(log))
        approved = restarted.get_approved_proposals()
        assert [p.proposal_id for p in approved] == [proposal.proposal_id]
        assert approved[0].status == "approved"
        assert approved[0].rule_approved_by_cbg is True
        assert approved[0].rule_approval_rationale == "confirmed by CBG"
        assert restarted.get_pending_proposals() == []

    def test_chain_signatures_reload_after_restart(self, tmp_path):
        log = tmp_path / "proposals.jsonl"
        engine = FacticsEngine(config=_config(log))
        proposal = _confirm(engine, "txn-chain")
        assert isinstance(proposal.chain_signature, ChainSignature)
        engine.approve_proposal(proposal.proposal_id, "confirmed")
        before = engine.get_chain_library()
        kpis_before = engine.get_kpis()
        assert len(before) == 1

        restarted = FacticsEngine(config=_config(log))
        after = restarted.get_chain_library()
        assert len(after) == 1
        assert isinstance(after[0], ChainSignature)
        assert after[0].to_dict() == before[0].to_dict()
        assert after[0].cbg_confirmation_timestamp == before[0].cbg_confirmation_timestamp
        kpis_after = restarted.get_kpis()
        assert kpis_after["chain_library_size"] == kpis_before["chain_library_size"] == 1
        assert kpis_after["detection_coverage_rate"] == kpis_before["detection_coverage_rate"]

    def test_a_pending_proposal_keeps_its_chain_signature_across_restart(self, tmp_path):
        log = tmp_path / "proposals.jsonl"
        engine = FacticsEngine(config=_config(log))
        proposal = _confirm(engine, "txn-pending-chain")
        steps = list(proposal.chain_signature.step_sequence)
        restarted = FacticsEngine(config=_config(log))
        pending = restarted.get_pending_proposals()
        assert [p.proposal_id for p in pending] == [proposal.proposal_id]
        assert pending[0].chain_signature is not None
        assert pending[0].chain_signature.step_sequence == steps
        restarted.approve_proposal(proposal.proposal_id, "approved after restart")
        assert [s.step_sequence for s in restarted.get_chain_library()] == [steps]

    def test_reapproval_after_restart_is_not_duplicated(self, tmp_path):
        log = tmp_path / "proposals.jsonl"
        engine = FacticsEngine(config=_config(log))
        proposal = _confirm(engine, "txn-dup")
        engine.approve_proposal(proposal.proposal_id, "ok")
        restarted = FacticsEngine(config=_config(log))
        assert restarted.approve_proposal(proposal.proposal_id, "again") is False
        assert len(restarted.get_chain_library()) == 1


class TestPipelinePassesTheLogPath:

    def test_pipeline_writes_and_reloads_proposals(self, tmp_path):
        log = tmp_path / "proposals.jsonl"
        pipeline = OverwatchPipeline(_config(log))
        finding = _finding("txn-pipeline")
        pipeline.process_cbg_threat_confirmation(
            finding, VerificationOutcome(transaction_id="txn-pipeline"), "confirmed")
        assert log.exists() and _log_lines(log)
        pending = pipeline.get_factics_proposals()
        assert len(pending) == 1

        restarted = OverwatchPipeline(_config(log))
        assert [p.proposal_id for p in restarted.get_factics_proposals()] == \
            [p.proposal_id for p in pending]

    def test_restarted_pipeline_loads_approved_signatures_into_the_intent_analyzer(self, tmp_path):
        log = tmp_path / "proposals.jsonl"
        pipeline = OverwatchPipeline(_config(log))
        pipeline.process_cbg_threat_confirmation(
            _finding("txn-lib"), VerificationOutcome(transaction_id="txn-lib"), "confirmed")
        proposal = pipeline.get_factics_proposals()[0]
        pipeline.factics_engine.approve_proposal(proposal.proposal_id, "approved")

        restarted = OverwatchPipeline(_config(log))
        library = restarted.intent_analyzer._chain_library
        assert [s.signature_id for s in library] == \
            [proposal.chain_signature.signature_id]
