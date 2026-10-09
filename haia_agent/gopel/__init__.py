"""
HAIA Agent Framework
====================
Implementation of GOPEL (Governance Orchestrator Policy Enforcement Layer).
A non-cognitive governance infrastructure for multi-AI workflows.

Seven deterministic operations. Zero cognitive work.

Author: Basil C. Puglisi, MPA
"""

from .models import (
    AuditFileSchema,
    AuditRecord,
    ArbitrationDecision,
    ArbitrationRecord,
    DecisionRecord,
    DispatchRecord,
    NavigationRecord,
    OperatingModel,
    PlatformStatus,
    RecordType,
    RECCLINRole,
    RequestRecord,
    ResponseRecord,
    SystemRecord,
)
from .logger import (
    AuditLogger,
    ChainIntegrityError,
    ImmutabilityViolationError,
)
from .adapters import (
    AdapterResponse,
    PlatformAdapter,
)
from .adapters.anthropic_adapter import AnthropicAdapter
from .adapters.openai_adapter import OpenAIAdapter
from .adapters.google_adapter import GoogleAdapter
from .adapters.mock_adapter import MockAdapter
from .selector import PlatformSelector, PlatformSelection
from .navigator import NavigatorRouter
from .pipeline import (
    GOPELPipeline,
    CheckpointPackage,
    ArbitrationInput,
    PipelineResult,
)
from .secure_pipeline import (
    SecureGOPELPipeline,
    SecureCheckpointPackage,
    SecureArbitrationInput,
    SecurePipelineResult,
    sanitize_for_synthesis,
    sanitize_error_detail,
)
from .security import (
    AuditEncryption,
    AuditFileLock,
    HashWitness,
    OperatorIdentity,
    OperatorRegistry,
    SecureRotationSeed,
    TransportVerifier,
)
from .secure_logger import SecureAuditLogger
from .navigator_validator import NavigatorValidator, NavigatorValidationResult
from .static_analyzer import NonCognitiveAnalyzer
from .breach import (
    BreachCategory,
    BreachDetector,
    BreachEvent,
    BreachNotifier,
    BreachReport,
    BreachReportFormatter,
    BreachSeverity,
    PipelineCircuitBreaker,
)
from .sentinel import (
    HeartbeatMonitor,
    PipelineIdentity,
    Sentinel,
    SignedAlert,
)
from .governance import (
    Authorizer,
    AuthorizationResult,
    EscalationEngine,
    EscalationLevel,
    EscalationRule,
    EscalationState,
    EvidenceGate,
    EvidenceGateResult,
    EvidenceRequirement,
    EvidenceSubmission,
    EvidenceType,
    GovAction,
    GovernanceContext,
    GovernanceDecision,
    GovernanceRuntime,
    OperatorProfile,
    OperatorRole,
    Policy,
    PolicyEngine,
    PolicyEvaluationResult,
    PolicyResult,
    PolicyVerdict,
    # Pre-built policies
    POLICY_BREACH_BLOCKS_EXECUTION,
    POLICY_WARNING_REQUIRES_GOV_OFFICER,
    POLICY_MODEL2_REQUIRES_EVIDENCE,
    POLICY_OVERRIDE_REQUIRES_DUAL_APPROVAL,
    POLICY_INJECTION_THRESHOLD_ESCALATES,
    # Pre-built escalation rules
    RULE_BREACH_WARNING_ELEVATES,
    RULE_BREACH_CRITICAL_HIGH,
    RULE_BREACH_HALT_LOCKDOWN,
    RULE_INJECTION_FLOOD_CRITICAL,
    RULE_PLATFORM_FAILURE_ELEVATED,
    # Pre-built evidence gates
    ARBITRATION_GATE,
    CIRCUIT_BREAKER_OVERRIDE_GATE,
    MODEL_ESCALATION_GATE,
    EXECUTION_GATE_MODEL_2,
)

__version__ = "0.6.1"
__author__ = "Basil C. Puglisi, MPA"
__architecture__ = "GOPEL"
