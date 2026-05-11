"""
HAIA-Overwatch v1.0 - Core Data Models

Enums, dataclasses, and shared types used across all Overwatch modules.
Overwatch is explicitly cognitive by design. It operates in a separate
trust boundary from GOPEL's non-cognitive enforcement layer.

Author: Basil C. Puglisi, MPA
License: CC BY-NC 4.0
Repository: github.com/basilpuglisi/HAIA
Attribution: #AIassisted under HAIA-RECCLIN & Checkpoint-Based Governance
"""

import hashlib
import hmac
import json
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Severity(Enum):
    """Five-level escalation severity aligned with GOPEL's breach model."""
    NOMINAL = "NOMINAL"
    ADVISORY = "ADVISORY"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"
    HALT = "HALT"

    def __ge__(self, other):
        order = list(Severity)
        return order.index(self) >= order.index(other)

    def __gt__(self, other):
        order = list(Severity)
        return order.index(self) > order.index(other)

    def __le__(self, other):
        order = list(Severity)
        return order.index(self) <= order.index(other)

    def __lt__(self, other):
        order = list(Severity)
        return order.index(self) < order.index(other)


class OperatingMode(Enum):
    """Dual-mode operating model: RAI at speed, AIG at checkpoint."""
    RAI = "RESPONSIBLE_AI"
    AIG = "AI_GOVERNANCE"


class TrustTier(Enum):
    """Source-authority discrimination tiers from HAIA ecosystem."""
    TIER_0 = 0   # Human arbiter - highest authority, no decay
    TIER_1 = 1   # AI platform - configurable decay
    TIER_2 = 2   # Synthesizer/Navigator - ephemeral by default
    TIER_UNTRUSTED = 3  # Unknown/unregistered sources - least privilege


class InspectionDomain(Enum):
    """Three content-aware inspection domains."""
    INTENT = "INTENT"
    CONTEXT = "CONTEXT"
    OUTPUT_STATE = "OUTPUT_STATE"


class VerificationPart(Enum):
    """Two-part verification gate."""
    STRUCTURAL = "GOPEL_STRUCTURAL_SOUNDNESS"
    EXCHANGE = "EXCHANGE_ALIGNMENT"


class AlignmentResult(Enum):
    """Outcome of a single inspection domain check."""
    ALIGNED = "ALIGNED"
    FLAGGED = "FLAGGED"


class StructuralResult(Enum):
    """Outcome of Part 1 structural verification."""
    STABLE = "STABLE"
    FLAGGED = "FLAGGED"


class RECCLINRole(Enum):
    """Seven RECCLIN functional roles."""
    RESEARCHER = "RESEARCHER"
    EDITOR = "EDITOR"
    CODER = "CODER"
    CALCULATOR = "CALCULATOR"
    LIAISON = "LIAISON"
    IDEATOR = "IDEATOR"
    NAVIGATOR = "NAVIGATOR"


# ---------------------------------------------------------------------------
# Provenance
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class ProvenanceTag:
    """Provenance metadata attached to every content input.
    Section 10 of the specification."""
    source_identity: str
    timestamp: float
    trust_tier: TrustTier
    ingestion_path: str  # direct_input, file_upload, api_response, rag_retrieval, mcp_tool
    tag_id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    signature: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tag_id": self.tag_id,
            "source_identity": self.source_identity,
            "timestamp": self.timestamp,
            "trust_tier": self.trust_tier.value,
            "ingestion_path": self.ingestion_path
        }

    def _canonical(self) -> str:
        """Return canonical form of tag for signing."""
        return json.dumps({
            "tag_id": self.tag_id,
            "source_identity": self.source_identity,
            "timestamp": self.timestamp,
            "trust_tier": self.trust_tier.value,
            "ingestion_path": self.ingestion_path
        }, sort_keys=True)

    def sign(self, key: bytes) -> str:
        """Sign the provenance tag with HMAC-SHA256."""
        canonical = self._canonical()
        self.signature = hmac.new(key, canonical.encode(), hashlib.sha256).hexdigest()
        return self.signature

    def verify(self, key: bytes) -> bool:
        """Verify provenance tag signature."""
        canonical = self._canonical()
        expected = hmac.new(key, canonical.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(self.signature, expected)

    def is_expired(self, decay_window: float, current_time: Optional[float] = None) -> bool:
        """Check if this content has exceeded its decay window.
        Tier 0 content never decays. Tier 1 decays on configurable schedule.
        Tier 2 is ephemeral by default. TIER_UNTRUSTED is always expired."""
        if self.trust_tier == TrustTier.TIER_0:
            return False
        if self.trust_tier == TrustTier.TIER_UNTRUSTED:
            return True  # Untrusted content is always considered expired
        now = current_time or time.time()
        return (now - self.timestamp) > decay_window


# ---------------------------------------------------------------------------
# Transaction and Exchange Records
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class DeclaredTaskScope:
    """Declared scope boundaries for a task execution.
    ChatGPT #14 separation of concerns."""
    allow_network: bool = False
    allow_file_write: bool = False
    allow_subprocess: bool = False
    allow_database_write: bool = False
    allowed_domains: List[str] = field(default_factory=list)
    allowed_paths: List[str] = field(default_factory=list)
    allowed_commands: List[str] = field(default_factory=list)
    risk_tier: str = "medium"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allow_network": self.allow_network,
            "allow_file_write": self.allow_file_write,
            "allow_subprocess": self.allow_subprocess,
            "allow_database_write": self.allow_database_write,
            "allowed_domains": self.allowed_domains,
            "allowed_paths": self.allowed_paths,
            "allowed_commands": self.allowed_commands,
            "risk_tier": self.risk_tier
        }


@dataclass(slots=True)
class TransactionRecord:
    """A single transaction observed by Overwatch from GOPEL's audit trail."""
    transaction_id: str
    timestamp: float
    operator_id: str
    recclin_role: RECCLINRole
    prompt_hash: str
    prompt_text: str  # content for cognitive inspection
    platforms_dispatched: List[str]
    responses: List["PlatformResponse"]
    navigator_input: Optional[str] = None
    navigator_output: Optional[str] = None
    provenance_tags: List[ProvenanceTag] = field(default_factory=list)
    gopel_breach_report: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    task_scope: Optional[DeclaredTaskScope] = None


@dataclass(slots=True)
class PlatformResponse:
    """A single platform response within a transaction."""
    platform_id: str
    response_text: str
    response_hash: str
    response_time_ms: float
    confidence_score: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Inspection Findings
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class InspectionFinding:
    """A finding produced by any of the three inspection domains."""
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    domain: InspectionDomain = InspectionDomain.INTENT
    result: AlignmentResult = AlignmentResult.ALIGNED
    severity: Severity = Severity.NOMINAL
    confidence: float = 0.0  # 0.0 to 1.0
    description: str = ""
    evidence_chain: List[str] = field(default_factory=list)
    transaction_id: str = ""
    timestamp: float = field(default_factory=time.time)
    chain_signature_match: Optional[str] = None  # matched chain signature ID
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "domain": self.domain.value,
            "result": self.result.value,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "description": self.description,
            "evidence_chain": self.evidence_chain,
            "transaction_id": self.transaction_id,
            "timestamp": self.timestamp,
            "chain_signature_match": self.chain_signature_match
        }


@dataclass(slots=True)
class StructuralFinding:
    """A finding from Part 1 structural verification."""
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    result: StructuralResult = StructuralResult.STABLE
    severity: Severity = Severity.NOMINAL
    category: str = ""  # code_integrity, config_integrity, behavioral_baseline
    description: str = ""
    expected_value: str = ""
    actual_value: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "result": self.result.value,
            "severity": self.severity.value,
            "category": self.category,
            "description": self.description,
            "expected_value": self.expected_value,
            "actual_value": self.actual_value,
            "timestamp": self.timestamp
        }


# ---------------------------------------------------------------------------
# Verification Gate Outcome
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class VerificationOutcome:
    """Combined outcome from both verification parts for a transaction."""
    transaction_id: str
    timestamp: float = field(default_factory=time.time)
    operating_mode: OperatingMode = OperatingMode.RAI
    overall_severity: Severity = Severity.NOMINAL
    structural_result: StructuralResult = StructuralResult.STABLE
    structural_findings: List[StructuralFinding] = field(default_factory=list)
    intent_result: AlignmentResult = AlignmentResult.ALIGNED
    context_result: AlignmentResult = AlignmentResult.ALIGNED
    output_state_result: AlignmentResult = AlignmentResult.ALIGNED
    inspection_findings: List[InspectionFinding] = field(default_factory=list)
    escalated: bool = False
    escalation_reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "transaction_id": self.transaction_id,
            "timestamp": self.timestamp,
            "operating_mode": self.operating_mode.value,
            "overall_severity": self.overall_severity.value,
            "structural_result": self.structural_result.value,
            "structural_findings": [f.to_dict() for f in self.structural_findings],
            "intent_result": self.intent_result.value,
            "context_result": self.context_result.value,
            "output_state_result": self.output_state_result.value,
            "inspection_findings": [f.to_dict() for f in self.inspection_findings],
            "escalated": self.escalated,
            "escalation_reason": self.escalation_reason
        }


# ---------------------------------------------------------------------------
# Chain Signatures (Attack Library)
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class ChainSignature:
    """Abstract attack chain pattern stored in the chain signature library.
    Patterns are abstract (role sequences, scope trajectories) not
    content-specific."""
    signature_id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    name: str = ""
    pattern_type: str = ""  # reconnaissance, privilege_escalation, context_poison, confused_deputy
    step_sequence: List[str] = field(default_factory=list)  # abstract step descriptors
    min_chain_length: int = 2
    confirmed_by_cbg: bool = False
    cbg_confirmation_timestamp: Optional[float] = None
    detection_count: int = 0
    false_positive_count: int = 0
    created_timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "signature_id": self.signature_id,
            "name": self.name,
            "pattern_type": self.pattern_type,
            "step_sequence": self.step_sequence,
            "min_chain_length": self.min_chain_length,
            "confirmed_by_cbg": self.confirmed_by_cbg,
            "detection_count": self.detection_count,
            "false_positive_count": self.false_positive_count
        }


# ---------------------------------------------------------------------------
# Role Behavior Envelope
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class RoleBehaviorEnvelope:
    """Expected behavioral profile for a RECCLIN role.
    Defines the output characteristics the role should produce."""
    role: RECCLINRole
    expected_output_types: List[str] = field(default_factory=list)
    # e.g., RESEARCHER: ["citations", "source_lists", "evidence_summaries"]
    # CODER: ["code_blocks", "function_definitions", "imports"]
    forbidden_patterns: List[str] = field(default_factory=list)
    # e.g., RESEARCHER: ["subprocess", "os.system", "network_call"]
    baseline_output_length_range: tuple = (0, 100000)
    baseline_confidence_range: tuple = (0.0, 1.0)
    deviation_threshold: float = 0.15  # 15% deviation triggers flag
    sample_count: int = 0  # number of clean transactions in baseline

    def to_dict(self) -> Dict[str, Any]:
        return {
            "role": self.role.value,
            "expected_output_types": self.expected_output_types,
            "forbidden_patterns": self.forbidden_patterns,
            "deviation_threshold": self.deviation_threshold,
            "sample_count": self.sample_count
        }


# ---------------------------------------------------------------------------
# Execution Graph
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class GraphNode:
    """A node in the execution graph representing a discrete operation."""
    node_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    node_type: str = ""  # role_assignment, dispatch, response, navigator_routing,
                         # navigator_synthesis, checkpoint, human_decision
    timestamp: float = field(default_factory=time.time)
    content_hash: str = ""
    provenance: Optional[ProvenanceTag] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class GraphEdge:
    """An edge in the execution graph representing content flow."""
    source_node_id: str = ""
    target_node_id: str = ""
    content_hash: str = ""
    timestamp: float = field(default_factory=time.time)
    provenance: Optional[ProvenanceTag] = None


@dataclass(slots=True)
class ExecutionGraph:
    """Complete execution graph for a transaction sequence."""
    graph_id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    transaction_ids: List[str] = field(default_factory=list)
    nodes: List[GraphNode] = field(default_factory=list)
    edges: List[GraphEdge] = field(default_factory=list)
    created_timestamp: float = field(default_factory=time.time)
    completed: bool = False

    def add_node(self, node: GraphNode) -> None:
        self.nodes.append(node)

    def add_edge(self, edge: GraphEdge) -> None:
        self.edges.append(edge)

    def get_node_sequence(self) -> List[str]:
        """Return ordered list of node types for pattern matching."""
        sorted_nodes = sorted(self.nodes, key=lambda n: n.timestamp)
        return [n.node_type for n in sorted_nodes]


# ---------------------------------------------------------------------------
# Random Audit Report
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class RandomAuditReport:
    """Self-contained evidence package for independent third-party review.
    Section 7 of the specification."""
    report_id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    timestamp: float = field(default_factory=time.time)
    selected_transaction: Optional[TransactionRecord] = None
    verification_outcome: Optional[VerificationOutcome] = None
    gopel_structural_snapshot: Dict[str, str] = field(default_factory=dict)
    intent_trajectory: List[Dict[str, Any]] = field(default_factory=list)
    accumulated_advisories: List[InspectionFinding] = field(default_factory=list)
    factics_metrics: Dict[str, Any] = field(default_factory=dict)
    report_hash: str = ""
    previous_report_hash: str = ""  # hash chain link

    def compute_hash(self) -> str:
        """Compute SHA-256 hash of report content for chain integrity.
        Includes full serialization of accumulated_advisories, intent_trajectory,
        and factics_metrics."""
        content = json.dumps({
            "report_id": self.report_id,
            "timestamp": self.timestamp,
            "transaction_id": self.selected_transaction.transaction_id if self.selected_transaction else "",
            "verification": self.verification_outcome.to_dict() if self.verification_outcome else {},
            "structural_snapshot": self.gopel_structural_snapshot,
            "accumulated_advisories": [a.to_dict() for a in self.accumulated_advisories],
            "intent_trajectory": self.intent_trajectory,
            "factics_metrics": self.factics_metrics,
            "previous_hash": self.previous_report_hash
        }, sort_keys=True, default=str)
        self.report_hash = hashlib.sha256(content.encode()).hexdigest()
        return self.report_hash


# ---------------------------------------------------------------------------
# Factics Cycle Records
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class FacticsRecord:
    """A single Fact-Tactic-KPI cycle record from the adaptation engine."""
    record_id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    timestamp: float = field(default_factory=time.time)
    fact: str = ""           # what was observed
    tactic: str = ""         # what detection rule was generated
    kpi_name: str = ""       # what metric measures the improvement
    kpi_baseline: float = 0.0
    kpi_current: float = 0.0
    source_finding_id: str = ""  # the finding that triggered this cycle
    cbg_approved: bool = False
    cbg_decision_timestamp: Optional[float] = None
    cbg_rationale: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_id": self.record_id,
            "timestamp": self.timestamp,
            "fact": self.fact,
            "tactic": self.tactic,
            "kpi_name": self.kpi_name,
            "kpi_baseline": self.kpi_baseline,
            "kpi_current": self.kpi_current,
            "cbg_approved": self.cbg_approved
        }


# ---------------------------------------------------------------------------
# Rule Proposal
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class RuleProposal:
    """Proposed detection rule from inspection findings.
    ChatGPT #7 separation of concerns."""
    proposal_id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    source_finding_id: str = ""
    fact: str = ""
    proposed_tactic: str = ""
    target_kpi: str = ""
    kpi_baseline: float = 0.0
    status: str = "pending"  # pending, approved, rejected
    threat_confirmed_by_cbg: bool = False
    rule_approved_by_cbg: bool = False
    rule_approval_timestamp: Optional[float] = None
    rule_approval_rationale: str = ""
    chain_signature: Optional[ChainSignature] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "proposal_id": self.proposal_id,
            "source_finding_id": self.source_finding_id,
            "fact": self.fact,
            "proposed_tactic": self.proposed_tactic,
            "target_kpi": self.target_kpi,
            "kpi_baseline": self.kpi_baseline,
            "status": self.status,
            "threat_confirmed_by_cbg": self.threat_confirmed_by_cbg,
            "rule_approved_by_cbg": self.rule_approved_by_cbg,
            "rule_approval_timestamp": self.rule_approval_timestamp,
            "rule_approval_rationale": self.rule_approval_rationale,
            "chain_signature": self.chain_signature.to_dict() if self.chain_signature is not None else ""
        }


# ---------------------------------------------------------------------------
# Deployment Manifest
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class DeploymentManifest:
    """Manifest of a deployment with integrity signatures.
    Enables verification of deployment state at any point in time.
    Supports both HMAC signing (sign/verify) and content hash (compute_manifest_hash)
    for structural verifier compatibility."""
    manifest_id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    timestamp: float = field(default_factory=time.time)
    directory_path: str = ""
    file_hashes: Dict[str, str] = field(default_factory=dict)
    total_files: int = 0
    total_size_bytes: int = 0
    signature: str = ""
    # Fields required by structural_verifier for GOPEL integration
    gopel_version: str = ""
    cbg_authorization_id: str = ""
    created_timestamp: float = field(default_factory=time.time)
    config_snapshot: Dict[str, Any] = field(default_factory=dict)
    manifest_hash: str = ""

    def _canonical(self) -> str:
        """Return canonical form of manifest for signing."""
        return json.dumps({
            "manifest_id": self.manifest_id,
            "timestamp": self.timestamp,
            "directory_path": self.directory_path,
            "file_hashes": self.file_hashes,
            "total_files": self.total_files,
            "total_size_bytes": self.total_size_bytes,
            "gopel_version": self.gopel_version,
            "cbg_authorization_id": self.cbg_authorization_id,
            "created_timestamp": self.created_timestamp,
            "config_snapshot": self.config_snapshot
        }, sort_keys=True)

    def compute_manifest_hash(self) -> str:
        """Compute SHA-256 content hash of manifest for integrity verification.
        Used by structural_verifier to detect tampering."""
        content = json.dumps({
            "manifest_id": self.manifest_id,
            "gopel_version": self.gopel_version,
            "cbg_authorization_id": self.cbg_authorization_id,
            "file_hashes": self.file_hashes,
            "config_snapshot": self.config_snapshot,
            "created_timestamp": self.created_timestamp
        }, sort_keys=True, default=str)
        self.manifest_hash = hashlib.sha256(content.encode()).hexdigest()
        return self.manifest_hash

    def sign(self, key: bytes) -> str:
        """Sign the deployment manifest with HMAC-SHA256."""
        canonical = self._canonical()
        self.signature = hmac.new(key, canonical.encode(), hashlib.sha256).hexdigest()
        return self.signature

    def verify(self, key: bytes) -> bool:
        """Verify deployment manifest signature."""
        canonical = self._canonical()
        expected = hmac.new(key, canonical.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(self.signature, expected)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "manifest_id": self.manifest_id,
            "timestamp": self.timestamp,
            "directory_path": self.directory_path,
            "file_hashes": self.file_hashes,
            "total_files": self.total_files,
            "total_size_bytes": self.total_size_bytes,
            "signature": self.signature,
            "gopel_version": self.gopel_version,
            "cbg_authorization_id": self.cbg_authorization_id,
            "created_timestamp": self.created_timestamp,
            "config_snapshot": self.config_snapshot,
            "manifest_hash": self.manifest_hash
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DeploymentManifest":
        """Reconstruct a DeploymentManifest from a dictionary."""
        manifest = cls()
        manifest.manifest_id = data.get("manifest_id", manifest.manifest_id)
        manifest.timestamp = data.get("timestamp", manifest.timestamp)
        manifest.directory_path = data.get("directory_path", "")
        manifest.file_hashes = data.get("file_hashes", {})
        manifest.total_files = data.get("total_files", 0)
        manifest.total_size_bytes = data.get("total_size_bytes", 0)
        manifest.signature = data.get("signature", "")
        manifest.gopel_version = data.get("gopel_version", "")
        manifest.cbg_authorization_id = data.get("cbg_authorization_id", "")
        manifest.created_timestamp = data.get("created_timestamp", manifest.created_timestamp)
        manifest.config_snapshot = data.get("config_snapshot", {})
        manifest.manifest_hash = data.get("manifest_hash", "")
        return manifest


# ---------------------------------------------------------------------------
# Overwatch Configuration
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class OverwatchConfig:
    """Human-governor-configured parameters for Overwatch operation.
    Every parameter here is a governance decision made by the Tier 0 arbiter."""

    # Structural verification
    code_integrity_check_interval_seconds: float = 300.0  # 5 minutes
    config_snapshot_check_interval_seconds: float = 60.0   # 1 minute
    behavioral_baseline_window_size: int = 100  # transactions
    behavioral_deviation_threshold: float = 3.0  # standard deviations

    # Intent inspection
    intent_window_size: int = 10  # rolling window of transactions
    privilege_escalation_gradient_threshold: float = 0.3
    scope_narrowing_threshold: float = 0.5

    # Context inspection
    tier_1_decay_window_seconds: float = 86400.0  # 24 hours
    tier_2_decay_window_seconds: float = 3600.0   # 1 hour
    embedded_directive_confidence_threshold: float = 0.7

    # Output state inspection
    role_behavior_deviation_threshold: float = 0.15  # 15%

    # Escalation thresholds
    advisory_confidence_floor: float = 0.3
    warning_confidence_floor: float = 0.5
    critical_confidence_floor: float = 0.8
    advisory_accumulation_limit: int = 5  # advisories before auto-escalate to WARNING

    # Random audit
    random_audit_base_probability: float = 0.05  # 5% of transactions
    random_audit_advisory_multiplier: float = 1.5  # probability increases with advisories

    # CAIPR inspection
    caipr_platform_count: int = 3  # odd number required
    security_dissent_weight: float = 2.0  # weight multiplier for security-flagged dissent

    # Heartbeat
    heartbeat_interval_seconds: float = 30.0

    # GOPEL source files for integrity verification
    gopel_source_directory: str = ""
    gopel_config_path: str = ""

    # New configuration fields
    require_heartbeat_key: bool = True
    audit_log_path: str = ""
    manifest_path: str = ""
    follow_symlinks: bool = False
    integrity_scan_max_bytes: int = 50 * 1024 * 1024
    regex_scan_timeout_seconds: float = 1.0
    max_scan_text_length: int = 1_000_000
    chain_signature_match_threshold: float = 0.7
    require_structural_inputs: bool = True
    factics_auto_approve_low_risk: bool = False  # Grok Phase 1.3
    proposals_log_path: str = ""  # JSONL persistence for Factics proposals

    # GOPEL deployment mode — tightens defaults for production GOPEL monitoring
    gopel_mode: bool = False

    def __post_init__(self) -> None:
        """Apply GOPEL mode overrides when enabled."""
        if self.gopel_mode:
            self.require_structural_inputs = True
            self.require_heartbeat_key = True
            self.follow_symlinks = False
            self.advisory_accumulation_limit = min(self.advisory_accumulation_limit, 3)
            self.random_audit_base_probability = max(self.random_audit_base_probability, 0.10)
            self.max_scan_text_length = min(self.max_scan_text_length, 500_000)
            # v2.0: Tighten polling interval from 3600s default to 300s (Gemini TOCTOU fix)
            self.code_integrity_check_interval_seconds = min(
                self.code_integrity_check_interval_seconds, 300.0
            )

    def validate(self) -> List[str]:
        """Validate configuration. Returns list of errors.
        Checks all numeric fields for positive values to prevent
        silent protection disablement via zero/negative config."""
        errors = []
        if self.caipr_platform_count % 2 == 0:
            errors.append("CAIPR platform count must be odd (3/5/7)")
        if self.random_audit_base_probability <= 0 or self.random_audit_base_probability > 1.0:
            errors.append("Random audit probability must be between 0 and 1")
        if self.behavioral_deviation_threshold <= 0:
            errors.append("Behavioral deviation threshold must be positive")
        if self.heartbeat_interval_seconds <= 0:
            errors.append("Heartbeat interval must be positive")
        if self.tier_1_decay_window_seconds <= 0:
            errors.append("Tier 1 decay window must be positive")
        if self.tier_2_decay_window_seconds <= 0:
            errors.append("Tier 2 decay window must be positive")
        if self.intent_window_size <= 0:
            errors.append("Intent window size must be positive")
        # v2.0: Additional bounds checks (Kimi finding 3.4)
        if self.max_scan_text_length <= 0:
            errors.append("max_scan_text_length must be positive")
        if self.integrity_scan_max_bytes <= 0:
            errors.append("integrity_scan_max_bytes must be positive")
        if self.advisory_accumulation_limit <= 0:
            errors.append("advisory_accumulation_limit must be positive")
        if self.code_integrity_check_interval_seconds < 0:
            errors.append("code_integrity_check_interval_seconds must be non-negative")
        if self.config_snapshot_check_interval_seconds < 0:
            errors.append("config_snapshot_check_interval_seconds must be non-negative")
        if self.behavioral_baseline_window_size <= 0:
            errors.append("behavioral_baseline_window_size must be positive")
        return errors


# ---------------------------------------------------------------------------
# Heartbeat
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class Heartbeat:
    """Overwatch heartbeat emitted on the independent channel."""
    sequence_number: int = 0
    timestamp: float = field(default_factory=time.time)
    operating_mode: OperatingMode = OperatingMode.RAI
    structural_state: StructuralResult = StructuralResult.STABLE
    last_verification_timestamp: float = 0.0
    signature: str = ""  # HMAC signature for authentication

    def sign(self, key: bytes) -> str:
        """Sign the heartbeat with HMAC-SHA256."""
        content = f"{self.sequence_number}:{self.timestamp}:{self.operating_mode.value}:{self.structural_state.value}"
        self.signature = hmac.new(key, content.encode(), hashlib.sha256).hexdigest()
        return self.signature

    def verify(self, key: bytes) -> bool:
        """Verify heartbeat signature."""
        content = f"{self.sequence_number}:{self.timestamp}:{self.operating_mode.value}:{self.structural_state.value}"
        expected = hmac.new(key, content.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(self.signature, expected)
