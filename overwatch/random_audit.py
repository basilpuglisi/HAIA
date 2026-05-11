"""
HAIA-Overwatch v1.0 - Random Audit Generator

Produces random audit reports during extended RAI-mode operation.
Cryptographically random selection prevents predictability.
Reports are self-contained evidence packages reviewable by
independent third parties. Hash-chained for tamper evidence.

Author: Basil C. Puglisi, MPA
License: CC BY-NC 4.0
"""

import hashlib
import json
import os
import time
from typing import Any, Dict, List, Optional

from .models import (
    InspectionFinding, OverwatchConfig, RandomAuditReport,
    TransactionRecord, VerificationOutcome
)


class RandomAuditGenerator:
    """Generates random audit reports during RAI-mode operation.

    Properties:
    - Cryptographic random selection (unpredictable timing)
    - Selection probability ratchets UP with advisory accumulation
    - Selection probability ratchets DOWN only by human decision
    - Reports are hash-chained (tamper-evident)
    - Reports are self-contained for independent third-party review
    """

    def __init__(self, config: OverwatchConfig):
        self.config = config
        self._reports: List[RandomAuditReport] = []
        self._last_report_hash: str = "genesis"
        self._advisory_count_since_last_audit: int = 0
        self._accumulated_advisories: List[InspectionFinding] = []
        self._transaction_count_since_last_audit: int = 0
        self._total_audits: int = 0

        # AUD-02: JSONL persistence
        self._audit_log_path: Optional[str] = config.audit_log_path if hasattr(config, 'audit_log_path') else None
        if self._audit_log_path:
            self._rehydrate_from_log()

    # -------------------------------------------------------------------
    # AUD-02: JSONL Persistence
    # -------------------------------------------------------------------

    def _rehydrate_from_log(self) -> None:
        """Rehydrate _last_report_hash from the last line of audit log."""
        if not self._audit_log_path or not os.path.exists(self._audit_log_path):
            return

        try:
            with open(self._audit_log_path, 'r') as f:
                lines = f.readlines()
                if lines:
                    last_line = lines[-1].strip()
                    if last_line:
                        record = json.loads(last_line)
                        self._last_report_hash = record.get('report_hash', 'genesis')
        except (IOError, json.JSONDecodeError):
            # If log is corrupted or unreadable, start fresh
            self._last_report_hash = "genesis"

    def _append_to_log(self, report: RandomAuditReport) -> None:
        """Append serialized report record to JSONL log with fsync."""
        if not self._audit_log_path:
            return

        try:
            record = {
                'report_id': report.report_id,
                'timestamp': report.timestamp,
                'report_hash': report.report_hash,
                'previous_report_hash': report.previous_report_hash,
                'transaction_id': (
                    report.selected_transaction.transaction_id
                    if report.selected_transaction else "none"
                )
            }
            with open(self._audit_log_path, 'a') as f:
                f.write(json.dumps(record) + '\n')
                f.flush()
                os.fsync(f.fileno())
        except IOError:
            # Log write failures are non-fatal
            pass

    # -------------------------------------------------------------------
    # Selection Decision
    # -------------------------------------------------------------------

    def should_audit(self) -> bool:
        """Determine whether the current transaction should be randomly audited.

        Uses os.urandom for cryptographic randomness.
        Probability increases with accumulated advisories.
        """
        self._transaction_count_since_last_audit += 1

        # Compute adjusted probability
        base_prob = self.config.random_audit_base_probability
        advisory_boost = (
            self._advisory_count_since_last_audit
            * (self.config.random_audit_advisory_multiplier - 1.0)
            * base_prob
        )
        adjusted_prob = min(1.0, base_prob + advisory_boost)

        # Cryptographic random decision
        random_bytes = os.urandom(4)
        random_value = int.from_bytes(random_bytes, "big") / (2**32)

        return random_value < adjusted_prob

    def record_advisory(self, finding: InspectionFinding) -> None:
        """Record an advisory-level finding for accumulation tracking.

        AUD-01: Advisories persist across audits until explicit reset.
        """
        self._advisory_count_since_last_audit += 1
        self._accumulated_advisories.append(finding)

    # -------------------------------------------------------------------
    # Report Generation
    # -------------------------------------------------------------------

    def generate_report(
        self,
        transaction: TransactionRecord,
        outcome: VerificationOutcome,
        structural_snapshot: Dict[str, str],
        intent_trajectory: List[Dict[str, Any]],
        factics_metrics: Dict[str, Any]
    ) -> RandomAuditReport:
        """Generate a random audit report for the selected transaction.

        The report is a self-contained evidence package that an independent
        third party can review without access to the live pipeline.

        AUD-01: Do NOT reset _accumulated_advisories; they persist until explicit reset.
        """
        report = RandomAuditReport(
            selected_transaction=transaction,
            verification_outcome=outcome,
            gopel_structural_snapshot=structural_snapshot,
            intent_trajectory=intent_trajectory,
            accumulated_advisories=list(self._accumulated_advisories),
            factics_metrics=factics_metrics,
            previous_report_hash=self._last_report_hash
        )

        # Compute hash chain link
        report.compute_hash()
        self._last_report_hash = report.report_hash

        # Store report
        self._reports.append(report)
        self._total_audits += 1

        # AUD-02: Persist to JSONL log
        self._append_to_log(report)

        # Reset only the transaction counters, NOT accumulated advisories
        self._advisory_count_since_last_audit = 0
        self._transaction_count_since_last_audit = 0

        return report

    # -------------------------------------------------------------------
    # Probability Reset (AUD-01: CBG ratchet-down)
    # -------------------------------------------------------------------

    def reset_probability(self, authorization_id: str, rationale: str) -> None:
        """Reset probability ratchet on CBG decision to lower advisory weight.

        AUD-01: Clears accumulated advisories after human confirms resolution.
        """
        self._accumulated_advisories = []
        self._advisory_count_since_last_audit = 0

    # -------------------------------------------------------------------
    # Hash Chain Verification
    # -------------------------------------------------------------------

    def verify_chain_integrity(self) -> bool:
        """Verify the hash chain across all stored reports.
        Returns True if chain is intact, False if tampered.

        TB-02: Recompute each report's hash and compare to stored hash.
        """
        if not self._reports:
            return True

        expected_previous = "genesis"
        for report in self._reports:
            # TB-02: Recompute hash from content and compare
            original_hash = report.report_hash
            report.compute_hash()
            recomputed_hash = report.report_hash
            report.report_hash = original_hash  # restore for next check

            if recomputed_hash != original_hash:
                # Content hash mismatch
                return False

            if report.previous_report_hash != expected_previous:
                # Chain linkage mismatch
                return False

            expected_previous = original_hash

        return True

    # -------------------------------------------------------------------
    # Queries
    # -------------------------------------------------------------------

    def get_report_count(self) -> int:
        return self._total_audits

    def get_last_report(self) -> Optional[RandomAuditReport]:
        return self._reports[-1] if self._reports else None

    def get_audit_statistics(self) -> Dict[str, Any]:
        """Return audit statistics for monitoring."""
        return {
            "total_audits": self._total_audits,
            "transactions_since_last_audit": self._transaction_count_since_last_audit,
            "advisories_since_last_audit": self._advisory_count_since_last_audit,
            "chain_intact": self.verify_chain_integrity(),
            "last_report_hash": self._last_report_hash
        }

    def export_report(self, report: RandomAuditReport) -> str:
        """Export a report as canonical JSON for third-party review.

        Returns full canonical JSON including all advisory to_dict() entries.
        """
        return json.dumps({
            "report_id": report.report_id,
            "timestamp": report.timestamp,
            "report_hash": report.report_hash,
            "previous_report_hash": report.previous_report_hash,
            "transaction_id": (
                report.selected_transaction.transaction_id
                if report.selected_transaction else "none"
            ),
            "verification_outcome": (
                report.verification_outcome.to_dict()
                if report.verification_outcome else {}
            ),
            "gopel_structural_snapshot": report.gopel_structural_snapshot,
            "intent_trajectory": report.intent_trajectory,
            "accumulated_advisories_count": len(report.accumulated_advisories),
            "accumulated_advisories": [
                a.to_dict() for a in report.accumulated_advisories
            ],
            "factics_metrics": report.factics_metrics
        }, indent=2)
