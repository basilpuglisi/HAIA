"""
HAIA Agent Framework - Audit Record Models
===========================================
Implementation of GOPEL (Governance Orchestrator Policy Enforcement Layer)
Six audit record types as specified in the HAIA-RECCLIN Agent Architecture.

Every transaction generates six record types capturing the complete
Checkpoint-Based Governance (CBG) four-stage decision loop.

Non-cognitive constraint: These models store data. They do not evaluate,
rank, weight, prioritize, summarize, semantically transform, or filter
any content that passes through them.

Author: Basil C. Puglisi, MPA
License: Open publication for public infrastructure
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class RecordType(str, Enum):
    """The six audit record types specified in the GOPEL architecture."""
    REQUEST = "request"
    DISPATCH = "dispatch"
    RESPONSE = "response"
    NAVIGATION = "navigation"
    ARBITRATION = "arbitration"
    DECISION = "decision"
    SYSTEM = "system"  # Operational events: errors, threshold alerts, config changes


class RECCLINRole(str, Enum):
    """Seven functional roles mirroring constitutional checks and balances."""
    RESEARCHER = "researcher"
    EDITOR = "editor"
    CODER = "coder"
    CALCULATOR = "calculator"
    LIAISON = "liaison"
    IDEATOR = "ideator"
    NAVIGATOR = "navigator"


class OperatingModel(str, Enum):
    """Three operating models calibrating governance density to risk."""
    MODEL_1 = "agent_responsible_ai"      # Continue at gates, pause at final
    MODEL_2 = "agent_ai_governance"       # Pause at every gate
    MODEL_3 = "manual_human_ai_governance" # No agent automation, human orchestrates


class ArbitrationDecision(str, Enum):
    """Human checkpoint decisions."""
    APPROVE = "approve"
    MODIFY = "modify"
    REJECT = "reject"


class PlatformStatus(str, Enum):
    """API dispatch and response status tracking."""
    SENT = "sent"
    RECEIVED = "received"
    ERROR = "error"
    TIMEOUT = "timeout"


# ---------------------------------------------------------------------------
# Base Record
# ---------------------------------------------------------------------------

class AuditRecord(BaseModel):
    """
    Base record for all audit entries. Every record includes:
    - Unique record ID
    - Transaction ID (links all six record types in a single workflow step)
    - Record type identifier
    - Timestamp in UTC
    - Operator or system identity
    - Hash of this record's content
    - Hash of the previous record (chain integrity)
    - Sequence number (position in the append-only log)
    """
    record_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    transaction_id: str = Field(
        description="Links all records belonging to the same workflow step"
    )
    record_type: RecordType
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    operator_id: str = Field(
        description="Human or system identity responsible for this record"
    )
    sequence_number: int = Field(
        default=0,
        description="Position in the append-only audit log"
    )
    content_hash: str = Field(
        default="",
        description="SHA-256 hash of this record's content fields"
    )
    previous_hash: str = Field(
        default="genesis",
        description="SHA-256 hash of the previous record; 'genesis' for first record"
    )
    chain_hash: str = Field(
        default="",
        description="SHA-256 of content_hash + previous_hash for tamper detection"
    )

    def compute_content_hash(self) -> str:
        """
        Compute SHA-256 hash of the record's content fields.
        Excludes chain metadata (content_hash, previous_hash, chain_hash,
        sequence_number) to allow hash computation before chain insertion.
        """
        content = self.model_dump(
            exclude={"content_hash", "previous_hash", "chain_hash", "sequence_number"}
        )
        serialized = json.dumps(content, sort_keys=True, default=str)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def compute_chain_hash(self) -> str:
        """
        Compute the chain hash: SHA-256(content_hash + previous_hash).
        This is the tamper detection mechanism. If any record in the chain
        is modified, all subsequent chain_hash values become invalid.
        """
        combined = f"{self.content_hash}{self.previous_hash}"
        return hashlib.sha256(combined.encode("utf-8")).hexdigest()

    def finalize(self, sequence_number: int, previous_hash: str) -> None:
        """
        Finalize the record for insertion into the audit chain.
        Called by the logging engine, never by external code.
        """
        self.sequence_number = sequence_number
        self.previous_hash = previous_hash
        self.content_hash = self.compute_content_hash()
        self.chain_hash = self.compute_chain_hash()


# ---------------------------------------------------------------------------
# Record Type 1: Request Record
# ---------------------------------------------------------------------------

class RequestRecord(AuditRecord):
    """
    Documents the human's task submission.
    Contents: exact prompt text, RECCLIN role assigned, task scope,
    success criteria, operating model selection, platform selections.
    """
    record_type: RecordType = RecordType.REQUEST
    prompt_text: str = Field(description="Exact prompt text as submitted by human")
    recclin_role: RECCLINRole = Field(description="RECCLIN role assigned to this task")
    operating_model: OperatingModel = Field(description="Selected operating model")
    task_scope: str = Field(default="", description="Scope definition for this task")
    success_criteria: str = Field(default="", description="How success is measured")
    platform_selections: list[str] = Field(
        default_factory=list,
        description="Platform identifiers selected for this dispatch"
    )
    anchor_platform: str = Field(
        default="",
        description="Designated anchor platform for longitudinal consistency"
    )


# ---------------------------------------------------------------------------
# Record Type 2: Dispatch Record
# ---------------------------------------------------------------------------

class DispatchRecord(AuditRecord):
    """
    Documents each platform API call.
    Contents: platform identifier, prompt hash (proving identical prompt sent),
    timestamp, API confirmation status.
    One dispatch record per platform per task.
    """
    record_type: RecordType = RecordType.DISPATCH
    platform_id: str = Field(description="AI platform identifier")
    platform_model: str = Field(
        default="",
        description="Specific model version (e.g., claude-sonnet-4-5-20250929)"
    )
    prompt_hash: str = Field(
        description="SHA-256 hash of the prompt sent, proving identical dispatch"
    )
    is_anchor: bool = Field(
        default=False,
        description="Whether this platform is the anchor for this role"
    )
    dispatch_status: PlatformStatus = Field(default=PlatformStatus.SENT)
    api_confirmation: str = Field(
        default="",
        description="API response ID or confirmation token"
    )


# ---------------------------------------------------------------------------
# Record Type 3: Response Record
# ---------------------------------------------------------------------------

class ResponseRecord(AuditRecord):
    """
    Documents each platform's complete response.
    Contents: complete unedited response, content hash, platform metadata.
    Raw data preserved exactly as received. No filtering, ranking, or evaluation.
    """
    record_type: RecordType = RecordType.RESPONSE
    platform_id: str = Field(description="AI platform identifier")
    platform_model: str = Field(default="", description="Model version that responded")
    response_text: str = Field(
        description="Complete, unedited response from the platform"
    )
    response_hash: str = Field(
        default="",
        description="SHA-256 hash of the response text for integrity verification"
    )
    response_status: PlatformStatus = Field(default=PlatformStatus.RECEIVED)
    token_count: int = Field(default=0, description="Response token count if available")
    latency_ms: int = Field(default=0, description="Response latency in milliseconds")
    error_detail: str = Field(
        default="",
        description="Error message if response_status is ERROR or TIMEOUT"
    )

    def model_post_init(self, __context) -> None:
        """Compute response_hash on creation if not provided."""
        if self.response_text and not self.response_hash:
            self.response_hash = hashlib.sha256(
                self.response_text.encode("utf-8")
            ).hexdigest()


# ---------------------------------------------------------------------------
# Record Type 4: Navigation Record
# ---------------------------------------------------------------------------

class NavigationRecord(AuditRecord):
    """
    Documents the Navigator's synthesis.
    Contents: convergence mapping, divergence identification, dissent
    preservation, structured governance output.

    The Navigator does not resolve disagreements. It presents them.
    Resolution is a human governance decision.
    """
    record_type: RecordType = RecordType.NAVIGATION
    navigator_platform: str = Field(
        description="Platform performing Navigator synthesis"
    )
    convergence_summary: str = Field(
        default="",
        description="Where platforms agree"
    )
    divergence_summary: str = Field(
        default="",
        description="Where platforms disagree"
    )
    dissent_records: list[str] = Field(
        default_factory=list,
        description="Minority positions documented in full, not suppressed"
    )
    sources_cited: list[str] = Field(default_factory=list)
    conflicts_identified: list[str] = Field(default_factory=list)
    confidence_score: int = Field(
        default=0,
        ge=0,
        le=100,
        description="Navigator confidence 0-100"
    )
    confidence_justification: str = Field(default="")
    recommendation: str = Field(
        default="",
        description=(
            "Pass-through: platform recommendations presented to Navigator, "
            "Navigator suggests one with rationale. Agent never generates, "
            "endorses, or weights recommendations."
        )
    )
    expiry_note: str = Field(
        default="",
        description="Time sensitivity of the information"
    )
    response_record_ids: list[str] = Field(
        default_factory=list,
        description="Record IDs of the Response Records synthesized"
    )
    # FIX15: Store the complete Navigator synthesis output.
    # Without this, the audit trail cannot reconstruct what the
    # human arbiter actually saw and decided on.
    full_synthesis_text: str = Field(
        default="",
        description=(
            "Complete Navigator synthesis output as delivered to the "
            "human arbiter. Stored verbatim for audit reconstruction."
        )
    )


# ---------------------------------------------------------------------------
# Record Type 5: Arbitration Record
# ---------------------------------------------------------------------------

class ArbitrationRecord(AuditRecord):
    """
    Documents the human's decision at each checkpoint.
    Contents: approve/modify/reject, change rationale, human identity.
    This is the binding governance decision.
    """
    record_type: RecordType = RecordType.ARBITRATION
    arbitration_decision: ArbitrationDecision = Field(
        description="Human decision: approve, modify, or reject"
    )
    rationale: str = Field(
        description="Human's stated rationale for the decision"
    )
    modifications: str = Field(
        default="",
        description="If decision is MODIFY, what was changed and why"
    )
    checkpoint_role: RECCLINRole = Field(
        description="Which RECCLIN role checkpoint triggered this arbitration"
    )
    navigation_record_id: str = Field(
        default="",
        description="Record ID of the Navigation Record being arbitrated"
    )


# ---------------------------------------------------------------------------
# Record Type 6: Decision Record
# ---------------------------------------------------------------------------

class DecisionRecord(AuditRecord):
    """
    Documents the final authorized output.
    Contents: final output, linkage to all upstream records.
    Complete chain reconstructable end to end.
    """
    record_type: RecordType = RecordType.DECISION
    final_output: str = Field(description="The authorized output after arbitration")
    output_hash: str = Field(
        default="",
        description="SHA-256 hash of the final output"
    )
    upstream_record_ids: list[str] = Field(
        default_factory=list,
        description="All record IDs in this transaction's chain"
    )
    is_final: bool = Field(
        default=False,
        description="True if this is the final output of the entire workflow"
    )

    def model_post_init(self, __context) -> None:
        """Compute output_hash on creation if not provided."""
        if self.final_output and not self.output_hash:
            self.output_hash = hashlib.sha256(
                self.final_output.encode("utf-8")
            ).hexdigest()


# ---------------------------------------------------------------------------
# System Record (operational events)
# ---------------------------------------------------------------------------

class SystemRecord(AuditRecord):
    """
    Documents operational events: errors, threshold alerts,
    configuration changes. Not part of the six-record transaction chain
    but part of the audit trail.
    """
    record_type: RecordType = RecordType.SYSTEM
    event_type: str = Field(
        description="Category: error, threshold_alert, config_change, startup, shutdown"
    )
    event_detail: str = Field(description="Description of the event")
    severity: str = Field(
        default="info",
        description="info, warning, error, critical"
    )


# ---------------------------------------------------------------------------
# Schema Metadata (self-documenting header)
# ---------------------------------------------------------------------------

class AuditFileSchema(BaseModel):
    """
    Self-documenting schema header for the audit file.
    An auditor can upload this file to any AI platform and ask
    natural-language queries against the records.
    """
    schema_version: str = "1.0.0"
    framework: str = "HAIA Agent Framework"
    architecture: str = "GOPEL (Governance Orchestrator Policy Enforcement Layer)"
    author: str = "Basil C. Puglisi, MPA"
    description: str = (
        "Append-only, hash-chained audit trail for multi-AI governance workflows. "
        "Seven deterministic operations. Zero cognitive work. "
        "Every record is cryptographically linked to its predecessor."
    )
    record_types: dict[str, str] = {
        "request": "Human task submission: prompt, role, scope, platform selections",
        "dispatch": "API call to each platform: platform ID, prompt hash, status",
        "response": "Complete unedited platform response: text, hash, metadata",
        "navigation": "Navigator synthesis: convergence, divergence, dissent, recommendation",
        "arbitration": "Human checkpoint decision: approve/modify/reject with rationale",
        "decision": "Final authorized output with linkage to all upstream records",
        "system": "Operational events: errors, alerts, configuration changes",
    }
    hash_algorithm: str = "SHA-256"
    chain_mechanism: str = (
        "Each record's chain_hash = SHA-256(content_hash + previous_hash). "
        "First record uses 'genesis' as previous_hash. "
        "Any modification to any record invalidates all subsequent chain_hash values."
    )
    immutability_rule: str = (
        "Append-only. No records may be modified or deleted. "
        "Corrections are new records referencing originals."
    )
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    operating_models: dict[str, str] = {
        "model_1_agent_responsible_ai": (
            "Agent runs full pipeline. Human reviews final output at single checkpoint."
        ),
        "model_2_agent_ai_governance": (
            "Agent pauses after each functional role. Human approves before proceeding."
        ),
        "model_3_manual_human_ai_governance": (
            "No agent automation. Human orchestrates everything manually. Agent only logs."
        ),
    }
