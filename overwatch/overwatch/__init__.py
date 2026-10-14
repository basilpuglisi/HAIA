"""
HAIA-Overwatch v1.1
Adaptive Security Shield for the HAIA Ecosystem

Overwatch sits beside the GOPEL channel as an external audit mirror,
not between HAIA Agent and GOPEL as a transit layer. It observes
mirrored records and content copies through read-only interfaces,
then reports findings to CBG. It does not modify GOPEL state, does
not sit in the enforcement path, and does not directly block execution.

Author: Basil C. Puglisi, MPA
License: CC BY-NC 4.0
Repository: github.com/basilpuglisi/HAIA
Attribution: #AIassisted under HAIA-RECCLIN & Checkpoint-Based Governance
"""

from .models import (
    OverwatchConfig,
    OperatingMode,
    Severity,
    TrustTier,
    RECCLINRole,
    InspectionDomain,
    TransactionRecord,
    PlatformResponse,
    ProvenanceTag,
    CalibrationState,
    ChainSignature,
    TrajectoryAlert,
    VerificationOutcome,
    Heartbeat,
    DeploymentManifest,
    RuleProposal,
    DeclaredTaskScope,
    ExecutionGraph,
    GraphNode,
    GraphEdge,
)
from .pipeline import OverwatchPipeline
from .provenance_manager import ProvenanceManager
from .channel_manager import IndependentChannelManager, ChannelMessage
from .caipr_dispatcher import CAIPRInspectionDispatcher, CAIPRConsensus
from .execution_graph import ExecutionGraphEngine
from .gopel_observer import (
    GopelObserver,
    GopelRecord,
    GopelRecordKind,
    ChainValidationError,
    validate_chain,
    assemble_transaction,
)
from .structured_logger import get_logger, sanitize_log_value

__version__ = "2.4.0"
__author__ = "Basil C. Puglisi, MPA"

__all__ = [
    "OverwatchPipeline",
    "OverwatchConfig",
    "OperatingMode",
    "Severity",
    "TrustTier",
    "RECCLINRole",
    "InspectionDomain",
    "TransactionRecord",
    "PlatformResponse",
    "ProvenanceTag",
    "CalibrationState",
    "ChainSignature",
    "TrajectoryAlert",
    "VerificationOutcome",
    "Heartbeat",
    "DeploymentManifest",
    "RuleProposal",
    "DeclaredTaskScope",
    "ExecutionGraph",
    "GraphNode",
    "GraphEdge",
    "ProvenanceManager",
    "IndependentChannelManager",
    "ChannelMessage",
    "CAIPRInspectionDispatcher",
    "CAIPRConsensus",
    "ExecutionGraphEngine",
    "GopelObserver",
    "GopelRecord",
    "GopelRecordKind",
    "ChainValidationError",
    "validate_chain",
    "assemble_transaction",
    "get_logger",
    "sanitize_log_value",
]
