"""
HAIA Agent Framework - GOPEL Pipeline
=======================================
The full operational pipeline implementing the 14-step agent
sequence from the HAIA-RECCLIN Agent Architecture Specification.

This is the mechanical sequence that is identical across Model 1
and Model 2. The only difference is whether checkpoint gates
pause or continue.

Steps:
     1. Receive task assignment from human
     2. Write Request Record
     3. Select platforms (anchor + rotation)
     4. Dispatch identical prompt to all selected platforms
     5. Write Dispatch Records
     6. Collect responses, record timestamps
     7. Write Response Records
     8. Route all responses to Navigator for synthesis
     9. Receive Navigation output
    10. Write Navigation Record
    11. Check checkpoint gate for current RECCLIN role
    12. If pause: deliver package, wait for arbitration
    13. If continue: store output, advance to next role
    14. At final output: deliver package, wait for arbitration

v0.6.3:
    Step 17: the Decision Record lists every upstream record ID.
    Step 20: with an Overwatch stop channel configured, GOPEL checks for
             an active stop at the start of execute() and before each
             dispatch, before finalization, and before record_arbitration.
             A dispatch in flight completes and is recorded; nothing
             further is dispatched and no synthesis is produced.
    S2:      no temperature is sent unless the operator sets one; Dispatch
             and Response records carry generation_settings.

Author: Basil C. Puglisi, MPA
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from typing import Callable, Optional

from .adapters import AdapterResponse, PlatformAdapter
from .logger import AuditLogger
from .models import (
    ArbitrationDecision,
    OperatingModel,
    PlatformStatus,
    RECCLINRole,
    build_generation_settings,
)
from .navigator import NavigatorRouter
from .overwatch_stop import (
    OverwatchReleaseResult,
    OverwatchStopChannel,
    stopped_error_message,
)
from .selector import PlatformSelector, PlatformSelection


@dataclass
class CheckpointPackage:
    """
    The governance package delivered to the human at a checkpoint gate.
    Contains everything the human needs to make an informed arbitration decision.
    """
    transaction_id: str
    recclin_role: RECCLINRole
    original_prompt: str
    platform_responses: list[AdapterResponse]
    navigator_synthesis: AdapterResponse
    navigation_record_id: str
    operating_model: OperatingModel
    is_final: bool = False


@dataclass
class ArbitrationInput:
    """Human's arbitration decision at a checkpoint."""
    decision: ArbitrationDecision
    rationale: str
    modifications: str = ""
    final_output: str = ""


@dataclass
class PipelineResult:
    """Complete result of a pipeline execution."""
    transaction_id: str
    checkpoint_package: CheckpointPackage
    arbitration: Optional[ArbitrationInput] = None
    success: bool = True
    error: str = ""
    # v0.6.3 step 20
    stopped_by_overwatch: bool = False
    active_stop_event_ids: list[str] = field(default_factory=list)


class GOPELPipeline:
    """
    The GOPEL operational pipeline.

    Orchestrates the seven deterministic operations:
        1. Dispatch  - Sends identical prompts to platforms (via adapters)
        2. Collect   - Receives responses without modification (via adapters)
        3. Route     - Delivers responses to Navigator (via NavigatorRouter)
        4. Log       - Writes audit records (via AuditLogger)
        5. Pause     - Stops at checkpoint gates (configurable per model)
        6. Hash      - Tamper detection (via AuditLogger hash chaining)
        7. Report    - Governance metrics (via AuditLogger)

    The pipeline performs ZERO cognitive work. It does not evaluate
    which response is best, does not filter responses, does not
    decide whether to proceed. It follows the mechanical sequence.
    """

    def __init__(
        self,
        logger: AuditLogger,
        selector: PlatformSelector,
        navigator: NavigatorRouter,
        operator_id: str = "haia_agent",
        overwatch_stop: Optional[OverwatchStopChannel] = None,
    ):
        self.logger = logger
        self.selector = selector
        self.navigator = navigator
        self.operator_id = operator_id
        # v0.6.3 step 20: optional Overwatch stop channel. None means no
        # Overwatch is configured and GOPEL runs normally (v2.4 section 4.2).
        if overwatch_stop is not None and overwatch_stop.audit_logger is not logger:
            raise ValueError(
                "The Overwatch stop channel must write to this pipeline's own audit logger."
            )
        self.overwatch_stop = overwatch_stop

    # ------------------------------------------------------------------
    # v0.6.3 step 20: Overwatch stop check points
    # ------------------------------------------------------------------

    def _active_overwatch_stops(self, transaction_id: str) -> list[str]:
        """Poll the stop channel; return the active stop event IDs."""
        if self.overwatch_stop is None:
            return []
        return self.overwatch_stop.poll(transaction_id=transaction_id)

    def _stopped_result(self, transaction_id: str, active_ids: list[str]) -> PipelineResult:
        return PipelineResult(
            transaction_id=transaction_id,
            checkpoint_package=None,
            success=False,
            error=stopped_error_message(active_ids),
            stopped_by_overwatch=True,
            active_stop_event_ids=list(active_ids),
        )

    def release_overwatch_stop(
        self,
        human_operator_id: str,
        stop_event_ids: list[str],
        evidence: list,
        governance_runtime=None,
    ) -> OverwatchReleaseResult:
        """
        Release named Overwatch stops: a human act through the
        RELEASE_OVERWATCH_STOP evidence gate (GovernanceRuntime.authorize).
        Refused without a governance runtime.
        """
        if self.overwatch_stop is None:
            return OverwatchReleaseResult(
                released=False, reason="Refused: no Overwatch stop channel is configured.")
        return self.overwatch_stop.release_overwatch_stop(
            human_operator_id, stop_event_ids, evidence, governance_runtime)

    def execute(
        self,
        prompt: str,
        recclin_role: RECCLINRole,
        operating_model: OperatingModel,
        human_operator_id: str,
        task_scope: str = "",
        success_criteria: str = "",
        system_prompt: Optional[str] = None,
        transaction_id: Optional[str] = None,
        max_tokens: int = 4096,
        temperature: Optional[float] = None,
    ) -> PipelineResult:
        """
        Execute the full GOPEL pipeline for a single RECCLIN role pass.

        This runs steps 1 through 11 of the 14-step sequence.
        Steps 12-14 (arbitration) require human input and are handled
        by the calling code via the returned CheckpointPackage.

        Args:
            prompt: Exact prompt text from the human
            recclin_role: RECCLIN role for this task
            operating_model: Model 1, 2, or 3
            human_operator_id: Identity of the human initiating the task
            task_scope: Scope definition
            success_criteria: How success is measured
            system_prompt: Optional system context for all platforms
            transaction_id: Optional (auto-generated if not provided)
            max_tokens: Maximum response length sent to every platform
            temperature: None (default) sends no temperature, so each
                provider's own default applies (S2); a value is sent as set

        Returns:
            PipelineResult containing the CheckpointPackage for human review
        """
        tid = transaction_id or str(uuid.uuid4())
        prompt_hash = hashlib.sha256(prompt.encode("utf-8")).hexdigest()

        try:
            # Step 20 check point (a): start of execute()
            active = self._active_overwatch_stops(tid)
            if active:
                return self._stopped_result(tid, active)

            # ==============================================================
            # Step 1: Receive task assignment from human
            # Step 2: Write Request Record
            # ==============================================================
            selection = self.selector.select(recclin_role)

            platform_ids = [a.platform_id for a in selection.all_platforms]
            anchor_id = selection.anchor.platform_id

            self.logger.log_request(
                transaction_id=tid,
                operator_id=human_operator_id,
                prompt_text=prompt,
                recclin_role=recclin_role,
                operating_model=operating_model,
                task_scope=task_scope,
                success_criteria=success_criteria,
                platform_selections=platform_ids,
                anchor_platform=anchor_id,
            )

            # ==============================================================
            # Step 3: Select platforms (already done above)
            # Step 4: Dispatch identical prompt to all selected platforms
            # Step 5: Write Dispatch Records
            # ==============================================================
            platform_responses: list[AdapterResponse] = []

            for adapter in selection.all_platforms:
                # Step 20 check point (a): before each dispatch. A dispatch
                # already completed above has its records written.
                active = self._active_overwatch_stops(tid)
                if active:
                    return self._stopped_result(tid, active)

                # Operation 1: DISPATCH
                response = adapter.send_prompt(
                    prompt=prompt,
                    system_prompt=system_prompt,
                    max_tokens=max_tokens,
                    temperature=temperature,
                )
                generation_settings = build_generation_settings(
                    adapter.default_model, max_tokens, temperature
                )

                # Step 5: Write Dispatch Record
                dispatch_status = (
                    PlatformStatus.SENT if response.success
                    else PlatformStatus.ERROR
                )
                self.logger.log_dispatch(
                    transaction_id=tid,
                    operator_id=self.operator_id,
                    platform_id=adapter.platform_id,
                    platform_model=adapter.default_model,
                    prompt_hash=prompt_hash,
                    is_anchor=(adapter.platform_id == anchor_id),
                    dispatch_status=dispatch_status,
                    api_confirmation=response.api_confirmation,
                    generation_settings=generation_settings,
                )

                # ==============================================================
                # Step 6: Collect responses, record timestamps
                # Step 7: Write Response Records
                # ==============================================================
                # Operation 2: COLLECT (the response is already collected above)
                resp_status = (
                    PlatformStatus.RECEIVED if response.success
                    else PlatformStatus.ERROR
                )
                self.logger.log_response(
                    transaction_id=tid,
                    operator_id=self.operator_id,
                    platform_id=adapter.platform_id,
                    platform_model=response.platform_model,
                    response_text=response.response_text,
                    response_status=resp_status,
                    token_count=response.token_count,
                    latency_ms=response.latency_ms,
                    error_detail=response.error_detail,
                    generation_settings=generation_settings,
                )

                platform_responses.append(response)

            # Step 20 check point (b): before finalization (the Navigator
            # synthesis dispatch and the checkpoint package)
            active = self._active_overwatch_stops(tid)
            if active:
                return self._stopped_result(tid, active)

            # ==============================================================
            # Step 8: Route all responses to Navigator for synthesis
            # Step 9: Receive Navigation output
            # ==============================================================
            # Operation 3: ROUTE
            nav_response = self.navigator.route_for_synthesis(
                original_prompt=prompt,
                recclin_role=recclin_role.value,
                platform_responses=platform_responses,
                system_prompt=system_prompt,
            )

            # Step 10: Write Navigation Record
            # FIX15: Store full synthesis text for audit reconstruction.
            full_synthesis = nav_response.response_text if nav_response.success else ""
            nav_record = self.logger.log_navigation(
                transaction_id=tid,
                operator_id=self.operator_id,
                navigator_platform=self.navigator.navigator_adapter.platform_id,
                convergence_summary="See full_synthesis_text field",
                divergence_summary="See full_synthesis_text field",
                dissent_records=[],
                recommendation=full_synthesis[:500] if full_synthesis else "",
                confidence_score=0,
                confidence_justification="Computed by Navigator in synthesis output",
                response_record_ids=[],
                full_synthesis_text=full_synthesis,
            )

            # Step 20 check point (b): a stop that arrived during the
            # synthesis call means no checkpoint package is produced.
            active = self._active_overwatch_stops(tid)
            if active:
                return self._stopped_result(tid, active)

            # ==============================================================
            # Step 11: Check checkpoint gate for current RECCLIN role
            # Build the checkpoint package for human review
            # ==============================================================
            package = CheckpointPackage(
                transaction_id=tid,
                recclin_role=recclin_role,
                original_prompt=prompt,
                platform_responses=platform_responses,
                navigator_synthesis=nav_response,
                navigation_record_id=nav_record.record_id,
                operating_model=operating_model,
            )

            return PipelineResult(
                transaction_id=tid,
                checkpoint_package=package,
                success=True,
            )

        except Exception as e:
            # Log the error as a system event
            self.logger._log_system_event(
                event_type="pipeline_error",
                detail=f"Pipeline failed for transaction {tid}: {str(e)}",
                severity="error",
            )
            return PipelineResult(
                transaction_id=tid,
                checkpoint_package=None,
                success=False,
                error=str(e),
            )

    def record_arbitration(
        self,
        transaction_id: str,
        human_operator_id: str,
        arbitration: ArbitrationInput,
        checkpoint_role: RECCLINRole,
        navigation_record_id: str,
    ) -> bool:
        """
        Record the human's arbitration decision at a checkpoint.

        Steps 12-14: The human has reviewed the CheckpointPackage
        and made a binding governance decision.

        This method logs the Arbitration Record and Decision Record.

        v0.6.3: returns True when recorded. Returns False, writing neither
        record, while an Overwatch stop is active (step 20 check point (c)).
        The Decision Record lists every upstream record ID (step 17).
        """
        # Step 20 check point (c): before release
        if self._active_overwatch_stops(transaction_id):
            return False

        # Arbitration Record
        self.logger.log_arbitration(
            transaction_id=transaction_id,
            operator_id=human_operator_id,
            arbitration_decision=arbitration.decision,
            rationale=arbitration.rationale,
            modifications=arbitration.modifications,
            checkpoint_role=checkpoint_role,
            navigation_record_id=navigation_record_id,
        )

        # Decision Record (step 17: links every upstream record)
        final_output = arbitration.final_output or arbitration.rationale
        self.logger.log_decision(
            transaction_id=transaction_id,
            operator_id=human_operator_id,
            final_output=final_output,
            upstream_record_ids=self.logger.get_upstream_record_ids(transaction_id),
            is_final=True,
        )
        return True
