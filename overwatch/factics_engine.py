"""
HAIA-Overwatch v1.0 - Factics Engine

Powers the adaptation cycle using the Factics methodology
(Facts + Tactics + KPIs). Every confirmed attack decomposes into a
structural signature, a new detection rule, and a measurable improvement
metric. Every false positive refines in the other direction.

Author: Basil C. Puglisi, MPA
License: CC BY-NC 4.0
"""

import json
import os
import time
from typing import Any, Dict, List, Optional

from .models import (
    ChainSignature, FacticsRecord, InspectionDomain, InspectionFinding,
    OverwatchConfig, RuleProposal, Severity, VerificationOutcome
)


class FacticsEngine:
    """Adaptation engine powered by the Factics methodology.

    Facts + Tactics + KPIs = Factics

    Every confirmed threat produces:
    - Fact: the attack's structural signature
    - Tactic: a new detection rule
    - KPI: measurable improvement metric

    Every confirmed false positive produces:
    - Fact: the legitimate pattern misclassified
    - Tactic: exception rule or envelope expansion
    - KPI: false positive rate decrease

    The loop closes when KPI failure triggers the next cycle.
    """

    def __init__(self, config: Optional[OverwatchConfig] = None):
        self._config = config or OverwatchConfig()
        self._records: List[FacticsRecord] = []
        self._chain_library: List[ChainSignature] = []
        self._pending_proposals: List[RuleProposal] = []
        self._approved_proposals: List[RuleProposal] = []
        self._rejected_proposals: List[RuleProposal] = []

        # Configurable attack classes
        self._known_attack_classes: set = {
            "indirect_injection", "multi_turn_chain",
            "context_poisoning", "confused_deputy"
        }

        # KPI tracking
        self._kpis: Dict[str, float] = {
            "detection_coverage_rate": 0.0,
            "false_positive_rate": 0.0,
            "mean_detection_position": 1.0,  # 1.0 = end of chain, 0.0 = start
            "adaptation_cycle_count": 0,
            "chain_library_size": 0,
            "confirmed_threats": 0,
            "confirmed_false_positives": 0,
            "total_findings": 0
        }

        # JSONL persistence for proposals
        self._proposals_log_path = getattr(self._config, 'proposals_log_path', '') if self._config else ''
        if self._proposals_log_path:
            self._rehydrate_proposals()

    def _rehydrate_proposals(self):
        """Load proposals from JSONL log, deduplicating by proposal_id.
        Gracefully skips corrupted/truncated lines so valid proposals
        survive partial write failures (crash resilience)."""
        if not os.path.exists(self._proposals_log_path):
            return
        try:
            # Build a map of proposal_id -> latest record
            proposal_map = {}
            with open(self._proposals_log_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        # Skip corrupted/truncated lines gracefully
                        continue
                    pid = record.get('proposal_id', '')
                    if pid:
                        proposal_map[pid] = record

            # Only load proposals whose latest status is "pending"
            for pid, record in proposal_map.items():
                if record.get('status') == 'pending':
                    proposal = RuleProposal(
                        proposal_id=record['proposal_id'],
                        source_finding_id=record.get('source_finding_id', ''),
                        fact=record.get('fact', ''),
                        proposed_tactic=record.get('proposed_tactic', ''),
                        target_kpi=record.get('target_kpi', ''),
                        kpi_baseline=record.get('kpi_baseline', 0.0),
                        status='pending'
                    )
                    self._pending_proposals.append(proposal)
        except IOError:
            pass

    def _persist_proposal(self, proposal, status_override=None):
        """Append a proposal record to JSONL log."""
        if not self._proposals_log_path:
            return
        try:
            record = proposal.to_dict()
            if status_override:
                record['status'] = status_override
            with open(self._proposals_log_path, 'a') as f:
                f.write(json.dumps(record) + '\n')
                f.flush()
                os.fsync(f.fileno())
        except IOError:
            pass

    def set_known_attack_classes(self, classes: set) -> None:
        """Set the known attack classes for coverage measurement."""
        self._known_attack_classes = classes

    # -------------------------------------------------------------------
    # Confirmed Threat Processing
    # -------------------------------------------------------------------

    def process_confirmed_threat(
        self,
        finding: InspectionFinding,
        outcome: VerificationOutcome,
        human_rationale: str = ""
    ) -> FacticsRecord:
        """Process a CBG-confirmed threat finding through the Factics cycle.

        Decomposes the attack into Fact, Tactic, and KPI.
        Generates a chain signature if applicable.
        Produces a rule proposal for CBG approval (SEPARATE from threat confirmation).

        Threat is confirmed but rule requires SEPARATE approval before being added to library.
        """
        # FACT: describe the attack signature
        fact = self._extract_fact(finding, outcome)

        # TACTIC: generate detection rule
        tactic = self._generate_tactic(finding)

        # KPI: identify improvement metric
        kpi_name = self._identify_kpi(finding)

        record = FacticsRecord(
            fact=fact,
            tactic=tactic,
            kpi_name=kpi_name,
            kpi_baseline=self._kpis.get(kpi_name, 0.0),
            source_finding_id=finding.finding_id,
            cbg_approved=True,
            cbg_decision_timestamp=time.time(),
            cbg_rationale=human_rationale
        )

        self._records.append(record)
        self._kpis["confirmed_threats"] += 1
        self._kpis["adaptation_cycle_count"] += 1
        self._kpis["total_findings"] += 1

        # Generate chain signature if this was a multi-turn attack
        # BUT DO NOT add to library yet - proposal must be approved first
        chain_signature = None
        if finding.chain_signature_match or finding.domain == InspectionDomain.INTENT:
            chain_signature = self._extract_chain_signature(finding, outcome)

        # Generate rule proposal for CBG approval
        proposal = self._create_rule_proposal(record, finding, chain_signature)
        self._pending_proposals.append(proposal)

        # Auto-approve low-risk (ADVISORY) proposals when configured
        if (self._config.factics_auto_approve_low_risk
                and finding.severity == Severity.ADVISORY):
            self.approve_proposal(
                proposal.proposal_id,
                rationale="Auto-approved: low-risk ADVISORY finding (Grok Phase 1.3)"
            )

        # Detection coverage updated only after proposal approval
        # (see _update_detection_coverage)

        return record

    def approve_proposal(self, proposal_id: str, rationale: str = "") -> bool:
        """Approve a rule proposal, adding its chain signatures to the library."""
        # Find the proposal
        proposal = None
        for p in self._pending_proposals:
            if p.proposal_id == proposal_id:
                proposal = p
                break

        if not proposal:
            return False

        # Move to approved
        self._pending_proposals.remove(proposal)
        proposal.status = "approved"
        proposal.rule_approved_by_cbg = True
        proposal.rule_approval_timestamp = time.time()
        proposal.rule_approval_rationale = rationale
        self._approved_proposals.append(proposal)

        # Persist status update to JSONL log
        self._persist_proposal(proposal, status_override="approved")

        # Add chain signature to library if present
        if hasattr(proposal, 'chain_signature') and proposal.chain_signature:
            self._chain_library.append(proposal.chain_signature)
            self._kpis["chain_library_size"] = len(self._chain_library)

        # Update detection coverage (now counts approved proposals)
        self._update_detection_coverage()

        return True

    def reject_proposal(self, proposal_id: str, rationale: str = "") -> bool:
        """Reject a rule proposal."""
        # Find the proposal
        proposal = None
        for p in self._pending_proposals:
            if p.proposal_id == proposal_id:
                proposal = p
                break

        if not proposal:
            return False

        # Move to rejected
        self._pending_proposals.remove(proposal)
        proposal.status = "rejected"
        proposal.rule_approval_timestamp = time.time()
        proposal.rule_approval_rationale = rationale
        self._rejected_proposals.append(proposal)

        return True

    # -------------------------------------------------------------------
    # Confirmed False Positive Processing
    # -------------------------------------------------------------------

    def process_confirmed_false_positive(
        self,
        finding: InspectionFinding,
        human_rationale: str = ""
    ) -> FacticsRecord:
        """Process a CBG-confirmed false positive through the Factics cycle.

        Generates an exception rule and tracks false positive rate.
        """
        fact = (
            f"False positive in {finding.domain.value} domain: "
            f"{finding.description}. Human rationale: {human_rationale}"
        )

        tactic = (
            f"Add exception rule for pattern that triggered false positive. "
            f"Finding confidence was {finding.confidence:.2f}, "
            f"severity was {finding.severity.value}."
        )

        record = FacticsRecord(
            fact=fact,
            tactic=tactic,
            kpi_name="false_positive_rate",
            kpi_baseline=self._kpis.get("false_positive_rate", 0.0),
            source_finding_id=finding.finding_id,
            cbg_approved=True,
            cbg_decision_timestamp=time.time(),
            cbg_rationale=human_rationale
        )

        self._records.append(record)
        self._kpis["confirmed_false_positives"] += 1
        self._kpis["total_findings"] += 1

        # Update false positive rate
        if self._kpis["total_findings"] > 0:
            self._kpis["false_positive_rate"] = (
                self._kpis["confirmed_false_positives"]
                / self._kpis["total_findings"]
            )

        # If chain signature was involved, increment its false positive count
        if finding.chain_signature_match:
            for sig in self._chain_library:
                if sig.signature_id == finding.chain_signature_match:
                    sig.false_positive_count += 1
                    break

        return record

    # -------------------------------------------------------------------
    # Internal Decomposition
    # -------------------------------------------------------------------

    def _extract_fact(
        self, finding: InspectionFinding, outcome: VerificationOutcome
    ) -> str:
        """Extract the factual description of an attack."""
        parts = [
            f"Domain: {finding.domain.value}",
            f"Severity: {finding.severity.value}",
            f"Confidence: {finding.confidence:.2f}",
            f"Description: {finding.description}",
        ]
        if finding.evidence_chain:
            parts.append(f"Evidence: {'; '.join(finding.evidence_chain[:3])}")
        if finding.chain_signature_match:
            parts.append(f"Chain signature: {finding.chain_signature_match}")
        return " | ".join(parts)

    def _generate_tactic(self, finding: InspectionFinding) -> str:
        """Generate a detection tactic from a confirmed threat."""
        if finding.domain == InspectionDomain.INTENT:
            return (
                f"Add chain detection rule: flag transaction sequences matching "
                f"the pattern observed in finding {finding.finding_id}. "
                f"Increase sensitivity for {finding.severity.value}-level "
                f"intent deviations in the triggering operator's profile."
            )
        elif finding.domain == InspectionDomain.CONTEXT:
            return (
                f"Add context directive pattern: flag inputs matching the "
                f"embedded directive type observed in finding {finding.finding_id}. "
                f"Tighten provenance requirements for the triggering source."
            )
        elif finding.domain == InspectionDomain.OUTPUT_STATE:
            return (
                f"Tighten role-behavior envelope: add the triggering state-change "
                f"pattern to the forbidden list for the affected RECCLIN role. "
                f"Finding: {finding.finding_id}."
            )
        return f"Generic detection rule for finding {finding.finding_id}."

    def _identify_kpi(self, finding: InspectionFinding) -> str:
        """Identify which KPI measures improvement for this finding type."""
        if finding.domain == InspectionDomain.INTENT:
            if finding.chain_signature_match:
                return "mean_detection_position"
            return "detection_coverage_rate"
        elif finding.domain == InspectionDomain.CONTEXT:
            return "detection_coverage_rate"
        elif finding.domain == InspectionDomain.OUTPUT_STATE:
            return "detection_coverage_rate"
        return "detection_coverage_rate"

    def _extract_chain_signature(
        self, finding: InspectionFinding, outcome: VerificationOutcome
    ) -> Optional[ChainSignature]:
        """Extract an abstract chain signature from a confirmed multi-turn attack."""
        if not finding.evidence_chain:
            return None

        # Build abstract step sequence from evidence
        steps = []
        for evidence in finding.evidence_chain:
            if "recon" in evidence.lower():
                steps.append("recon")
            elif "privilege" in evidence.lower():
                steps.append("privilege_probe")
            elif "credential" in evidence.lower():
                steps.append("credential_access")
            elif "deviation" in evidence.lower():
                steps.append("role_deviation")
            elif "escalat" in evidence.lower():
                steps.append("escalation")
            else:
                steps.append("normal")

        if len(steps) < 2:
            return None

        signature = ChainSignature(
            name=f"Auto-extracted from {finding.finding_id}",
            pattern_type=finding.domain.value.lower(),
            step_sequence=steps,
            min_chain_length=max(2, len(steps) - 1),
            confirmed_by_cbg=True,
            cbg_confirmation_timestamp=time.time()
        )
        return signature

    def _create_rule_proposal(
        self, record: FacticsRecord, finding: InspectionFinding,
        chain_signature: Optional[ChainSignature] = None
    ) -> RuleProposal:
        """Package a Factics record as a typed rule proposal for CBG."""
        proposal = RuleProposal(
            proposal_id=record.record_id,
            source_finding_id=finding.finding_id,
            fact=record.fact,
            proposed_tactic=record.tactic,
            target_kpi=record.kpi_name,
            kpi_baseline=record.kpi_baseline,
            status="pending"
        )
        # Store chain signature if present (will be added to library if approved)
        if chain_signature:
            proposal.chain_signature = chain_signature

        # Persist to JSONL log
        self._persist_proposal(proposal)

        return proposal

    def _update_detection_coverage(self) -> None:
        """Update detection coverage KPI based on approved proposals only."""
        # Coverage = proportion of known attack classes with active rules
        covered = set()

        # Count chain signatures in library (already approved)
        for sig in self._chain_library:
            if sig.confirmed_by_cbg:
                covered.add(sig.pattern_type)

        # Count approved proposals only (not pending)
        for proposal in self._approved_proposals:
            fact = proposal.fact.lower() if hasattr(proposal, 'fact') else ""
            if "intent" in fact:
                covered.add("multi_turn_chain")
            if "context" in fact:
                covered.add("context_poisoning")
            if "output" in fact:
                covered.add("confused_deputy")

        if self._known_attack_classes:
            self._kpis["detection_coverage_rate"] = len(covered) / len(self._known_attack_classes)

    # -------------------------------------------------------------------
    # Queries
    # -------------------------------------------------------------------

    def get_kpis(self) -> Dict[str, float]:
        """Return current KPI values."""
        return dict(self._kpis)

    def get_chain_library(self) -> List[ChainSignature]:
        """Return the current chain signature library."""
        return list(self._chain_library)

    def get_pending_proposals(self) -> List[RuleProposal]:
        """Return pending rule proposals awaiting CBG approval."""
        return list(self._pending_proposals)

    def get_approved_proposals(self) -> List[RuleProposal]:
        """Return approved rule proposals."""
        return list(self._approved_proposals)

    def get_rejected_proposals(self) -> List[RuleProposal]:
        """Return rejected rule proposals."""
        return list(self._rejected_proposals)

    def get_records(self) -> List[FacticsRecord]:
        """Return all Factics records."""
        return list(self._records)

    def get_metrics_summary(self) -> Dict[str, Any]:
        """Return a summary for inclusion in random audit reports."""
        return {
            "kpis": self.get_kpis(),
            "chain_library_size": len(self._chain_library),
            "pending_proposals": len(self.get_pending_proposals()),
            "total_records": len(self._records),
            "confirmed_chain_signatures": sum(
                1 for s in self._chain_library if s.confirmed_by_cbg
            )
        }
