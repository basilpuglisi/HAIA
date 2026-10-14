"""
HAIA-Overwatch v1.0 - CAIPR Dispatcher

Consensus-across-independent-platforms inspection with asymmetric security weighting.
Any platform flagging a CRITICAL finding overrides majority consensus.

Author: Basil C. Puglisi, MPA
License: CC BY-NC 4.0
Repository: github.com/basilpuglisi/HAIA
Attribution: #AIassisted under HAIA-RECCLIN & Checkpoint-Based Governance
"""

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List

from .models import OverwatchConfig
from .structured_logger import get_logger, sanitize_log_value as _sanitize_log

logger = get_logger(__name__)

# Security-critical patterns that trigger asymmetric weighting
SECURITY_CRITICAL_PATTERNS = {
    "CRITICAL_INJECTION",
    "PRIVILEGE_ESCALATION",
    "AUTH_BYPASS",
    "DATA_EXFILTRATION",
    "MALWARE_SIGNATURE",
    "UNAUTHORIZED_ACCESS"
}


@dataclass(slots=True)
class CAIPRConsensus:
    """Consensus result from CAIPR multi-platform inspection.

    Fields:
        consensus: Overall verdict - "ALIGNED", "FLAGGED", or "DIVERGENT"
        platform_findings: Dict mapping platform_id to list of findings
        dissent_records: List of platforms that disagreed with consensus
        security_override: True if any platform flagged CRITICAL severity
    """
    consensus: str  # "ALIGNED", "FLAGGED", "DIVERGENT"
    platform_findings: Dict[str, List[Any]] = field(default_factory=dict)
    dissent_records: List[Dict[str, Any]] = field(default_factory=list)
    security_override: bool = False


class CAIPRInspectionDispatcher:
    """Dispatches inspection to multiple platforms and aggregates consensus.

    Requires odd-number quorum. Security-critical findings from any platform
    flip consensus to FLAGGED regardless of majority.
    """

    def __init__(self, config: OverwatchConfig):
        """Initialize dispatcher with configuration.

        Args:
            config: OverwatchConfig containing caipr_platform_count

        Raises:
            ValueError: If caipr_platform_count is not odd
        """
        if config.caipr_platform_count % 2 == 0:
            raise ValueError("CAIPR platform count must be odd (3/5/7)")
        self.config = config
        self._platforms: Dict[str, Callable] = {}

    def register_platform(
        self,
        platform_id: str,
        inspect_fn: Callable
    ) -> None:
        """Register an inspection provider platform.

        Args:
            platform_id: Unique platform identifier
            inspect_fn: Callable(transaction) -> inspection_result
        """
        self._platforms[platform_id] = inspect_fn

    def dispatch(self, transaction: Any) -> CAIPRConsensus:
        """Validate quorum, dispatch to all platforms, aggregate consensus.

        Security override: any single platform flagging a CRITICAL finding
        flips consensus to FLAGGED regardless of majority vote.

        Args:
            transaction: TransactionRecord to inspect

        Returns:
            CAIPRConsensus with aggregated findings and decision

        Raises:
            ValueError: If insufficient platforms registered for quorum
        """
        if len(self._platforms) < self.config.caipr_platform_count:
            raise ValueError(
                f"Insufficient platforms: have {len(self._platforms)}, "
                f"need {self.config.caipr_platform_count}"
            )

        # Dispatch to all registered platforms
        findings = {}
        aligned_count = 0
        flagged_count = 0
        critical_flags = []

        for platform_id, inspect_fn in self._platforms.items():
            try:
                result = inspect_fn(transaction)
                findings[platform_id] = result if isinstance(result, list) else [result]

                # Count aligned vs flagged and check for critical findings
                for finding in findings[platform_id]:
                    # Check if finding has severity attribute and if it's CRITICAL
                    severity_str = getattr(finding, "severity", None)
                    if severity_str:
                        severity_val = severity_str.value if hasattr(severity_str, "value") else str(severity_str)
                        if severity_val == "CRITICAL":
                            critical_flags.append({
                                "platform_id": platform_id,
                                "finding": str(finding)
                            })

                    # Check result/alignment status
                    result_attr = getattr(finding, "result", None)
                    if result_attr:
                        result_val = result_attr.value if hasattr(result_attr, "value") else str(result_attr)
                        if result_val == "FLAGGED" or result_val == "flagged":
                            flagged_count += 1
                        else:
                            aligned_count += 1

            except Exception as e:
                logger.exception("Platform %s inspection failed: %s",
                                 _sanitize_log(platform_id), _sanitize_log(str(e)))
                findings[platform_id] = [{"error": str(e)}]
                flagged_count += 1

        # Determine consensus
        quorum = (self.config.caipr_platform_count + 1) // 2
        consensus = "ALIGNED"
        dissent_records = []

        # Simple majority vote
        if flagged_count >= quorum:
            consensus = "FLAGGED"
            # Dissenters are aligned platforms
            for platform_id in self._platforms:
                result = findings.get(platform_id, [{}])[0]
                result_val = getattr(result, "result", None)
                if result_val:
                    result_str = result_val.value if hasattr(result_val, "value") else str(result_val)
                    if result_str == "ALIGNED" or result_str == "aligned":
                        dissent_records.append({
                            "platform_id": platform_id,
                            "disagreed_with": consensus
                        })
        else:
            # Aligned majority
            for platform_id in self._platforms:
                result = findings.get(platform_id, [{}])[0]
                result_val = getattr(result, "result", None)
                if result_val:
                    result_str = result_val.value if hasattr(result_val, "value") else str(result_val)
                    if result_str == "FLAGGED" or result_str == "flagged":
                        dissent_records.append({
                            "platform_id": platform_id,
                            "disagreed_with": "ALIGNED"
                        })

        # Security override: any CRITICAL finding flips to FLAGGED
        security_override = False
        if critical_flags:
            consensus = "FLAGGED"
            security_override = True
            logger.warning(
                "Security override activated: %d CRITICAL findings detected",
                len(critical_flags)
            )

        return CAIPRConsensus(
            consensus=consensus,
            platform_findings=findings,
            dissent_records=dissent_records,
            security_override=security_override
        )
