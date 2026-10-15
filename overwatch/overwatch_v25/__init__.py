"""
HAIA-Overwatch v2.5
Adaptive Security Shield for the HAIA Ecosystem

Overwatch sits beside the GOPEL channel as an external audit mirror,
not between HAIA Agent and GOPEL as a transit layer. It observes
mirrored records and content copies through read-only interfaces,
then reports findings to CBG. It does not modify GOPEL state, does
not sit in the enforcement path, and does not directly block execution.
Its one action authority is to stop the pipe and route to human: on
every escalation it publishes a signed stop line on its own channel,
which GOPEL honors until a human releases it (v2.5).

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
    StructuralInputs,
    RuleProposal,
    DeclaredTaskScope,
    ExecutionGraph,
    GraphNode,
    GraphEdge,
)
from .pipeline import OverwatchPipeline
from .provenance_manager import ProvenanceManager
from .channel_manager import IndependentChannelManager, ChannelMessage, StopChannelPublisher
from .caipr_dispatcher import CAIPRInspectionDispatcher, CAIPRReviewResult, CAIPRConsensus
from .crypto import KeyScopeGuard, SigningKeyProvider
from .execution_graph import ExecutionGraphEngine
from .gopel_observer import (
    GopelObserver,
    GopelRecord,
    GopelRecordKind,
    GopelRecordError,
    GopelSchemaExpectation,
    ChainValidationError,
    validate_chain,
    assemble_transaction,
)
from .structured_logger import get_logger, sanitize_log_value

__version__ = "2.5.0"
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
    "StructuralInputs",
    "RuleProposal",
    "DeclaredTaskScope",
    "ExecutionGraph",
    "GraphNode",
    "GraphEdge",
    "ProvenanceManager",
    "IndependentChannelManager",
    "ChannelMessage",
    "StopChannelPublisher",
    "CAIPRInspectionDispatcher",
    "CAIPRReviewResult",
    "CAIPRConsensus",
    "KeyScopeGuard",
    "SigningKeyProvider",
    "ExecutionGraphEngine",
    "GopelObserver",
    "GopelRecord",
    "GopelRecordKind",
    "GopelRecordError",
    "GopelSchemaExpectation",
    "ChainValidationError",
    "validate_chain",
    "assemble_transaction",
    "get_logger",
    "sanitize_log_value",
]
