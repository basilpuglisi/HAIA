"""
Shared helpers for the GOPEL v0.6.3 test files (test_v063_*.py).

The stop-line helpers re-implement the Gate 1 Shared Spec v1, section 1,
independently of haia_agent.gopel_v064.overwatch_stop, so the tests check
GOPEL against the published line format and not against its own code.

No API keys. No network. Mock adapters and stand-in objects only.

Author: Basil C. Puglisi, MPA
"""

from __future__ import annotations

import hashlib
import hmac
import importlib
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

REPO_ROOT = Path(__file__).resolve().parents[3]
PKG_DIR = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from haia_agent.gopel_v064 import governance as gov  # noqa: E402
from haia_agent.gopel_v064.adapters import AdapterResponse, PlatformAdapter  # noqa: E402
from haia_agent.gopel_v064.adapters.mock_adapter import MockAdapter  # noqa: E402
from haia_agent.gopel_v064.logger import AuditLogger  # noqa: E402
from haia_agent.gopel_v064.models import OperatingModel, RECCLINRole  # noqa: E402
from haia_agent.gopel_v064.navigator import NavigatorRouter  # noqa: E402
from haia_agent.gopel_v064.pipeline import GOPELPipeline  # noqa: E402
from haia_agent.gopel_v064.secure_pipeline import SecureGOPELPipeline  # noqa: E402
from haia_agent.gopel_v064.security import OperatorIdentity, OperatorRegistry  # noqa: E402
from haia_agent.gopel_v064.selector import PlatformSelector  # noqa: E402

STOP_SCHEMA = "haia.overwatch.stop.v1"
PIPELINE_ID = "gopel-v063-test-instance"
STOP_KEY_ID = "overwatch-stop-key-1"
STOP_KEY = hashlib.sha256(b"gate1 test stop-channel key").digest()  # 32 bytes

# Navigator mock response that satisfies structural validation (as in
# the carried test_integration.py), so the secure pipeline stays NOMINAL.
NAVIGATOR_MOCK_RESPONSE = (
    "CONVERGENCE:\nAll sources agree on the core finding.\n\n"
    "DIVERGENCE:\nSource A and Source B differ on emphasis.\n\n"
    "DISSENT:\nSource C holds a minority position, preserved here.\n\n"
    "SOURCES:\nSource A, Source B, Source C. No [PROVISIONAL] flags.\n\n"
    "CONFLICTS:\nNo direct contradictions identified between sources.\n\n"
    "CONFIDENCE: 72%\nThree sources with one methodological disagreement.\n\n"
    "RECOMMENDATION:\nProceed, subject to human review.\n\n"
    "EXPIRY:\nValid until new data becomes available.\n"
)

JUSTIFICATION_TEXT = (
    "Overwatch finding reviewed by the governance officer; the triggering "
    "condition was traced and corrected before resuming the pipe."
)
RISK_TEXT = "Residual risk accepted: the corrected run is re-reviewed at its checkpoint."


def ow():
    """Import the v0.6.3 stop intake module at call time (absent before the fix)."""
    return importlib.import_module("haia_agent.gopel_v064.overwatch_stop")


# ----------------------------------------------------------------------
# Stop lines, written the way Overwatch v2.5 writes them (spec section 1)
# ----------------------------------------------------------------------

def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def iso_ms_z(dt: Optional[datetime] = None) -> str:
    dt = dt or datetime.now(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def make_body(
    event_id: Optional[str] = None,
    key_id: str = STOP_KEY_ID,
    target_pipeline: str = PIPELINE_ID,
    issued_at: Optional[str] = None,
    trigger: str = "CRITICAL",
    transaction_id: str = "",
    finding_ids: Optional[list] = None,
    refs: Optional[list] = None,
) -> dict:
    return {
        "schema_version": STOP_SCHEMA,
        "event_id": event_id or uuid.uuid4().hex,
        "issued_at": issued_at or iso_ms_z(),
        "key_id": key_id,
        "target_pipeline": target_pipeline,
        "transaction_id": transaction_id,
        "trigger": trigger,
        "finding_ids": ["OW-F-001"] if finding_ids is None else finding_ids,
        "gopel_record_refs": [] if refs is None else refs,
    }


def make_line(body: dict, key: bytes = STOP_KEY, body_text: Optional[str] = None) -> str:
    """One channel line: {"body": <canonical JSON text>, "mac": <hex HMAC-SHA256>}."""
    text = canonical(body) if body_text is None else body_text
    mac = hmac.new(key, text.encode("utf-8"), hashlib.sha256).hexdigest()
    return json.dumps({"body": text, "mac": mac}) + "\n"


def line_sha(line: str) -> str:
    return hashlib.sha256(line.rstrip("\n").encode("utf-8")).hexdigest()


def append_line(channel_path: Path, line: str) -> None:
    """Append one line the way Overwatch does (it owns the channel directory)."""
    Path(channel_path).parent.mkdir(parents=True, exist_ok=True)
    with open(channel_path, "a", encoding="utf-8") as f:
        f.write(line)


# ----------------------------------------------------------------------
# Governance runtime and evidence
# ----------------------------------------------------------------------

def make_registry() -> tuple[OperatorRegistry, dict]:
    registry = OperatorRegistry()
    ids = {}
    for op in ("gov_officer_mark", "gov_officer_ann", "admin_sarah", "analyst_jane"):
        ident = OperatorIdentity(op)
        registry.register_operator(ident)
        ids[op] = ident
    return registry, ids


def make_runtime(register_release_gate: bool = True, with_registry: bool = True):
    registry, identities = make_registry() if with_registry else (None, {})
    runtime = gov.GovernanceRuntime(operator_registry=registry)
    runtime.bootstrap_register(gov.OperatorProfile(
        operator_id="analyst_jane", roles={gov.OperatorRole.ANALYST}))
    runtime.bootstrap_register(gov.OperatorProfile(
        operator_id="gov_officer_mark", roles={gov.OperatorRole.GOVERNANCE_OFFICER}))
    runtime.bootstrap_register(gov.OperatorProfile(
        operator_id="gov_officer_ann", roles={gov.OperatorRole.GOVERNANCE_OFFICER}))
    runtime.bootstrap_register(gov.OperatorProfile(
        operator_id="admin_sarah", roles={gov.OperatorRole.ADMINISTRATOR}))
    runtime.register_evidence_gate(gov.GovAction.RECORD_ARBITRATION.value, gov.ARBITRATION_GATE)
    if register_release_gate:
        runtime.register_evidence_gate(
            gov.GovAction.RELEASE_OVERWATCH_STOP.value, gov.RELEASE_OVERWATCH_STOP_GATE)
    return runtime, identities


def release_evidence(
    stop_event_ids: list,
    identities: dict,
    requester: str = "gov_officer_mark",
    approver: str = "gov_officer_ann",
    sign_for: Optional[list] = None,
) -> list:
    """Evidence for RELEASE_OVERWATCH_STOP: justification, risk, signed second approver.

    The approver signs the SEC-03 payload bound to the release binding of
    the named stops and to the gate name.
    """
    m = ow()
    approval = gov.EvidenceSubmission(
        evidence_type=gov.EvidenceType.SECOND_APPROVER,
        content=approver,
        submitted_by=approver,
    )
    binding = m.release_binding_id(sign_for if sign_for is not None else stop_event_ids)
    if approver in identities:
        approval.signature = identities[approver].sign_record(
            approval.signable_payload(
                transaction_id=binding,
                gate_name=gov.RELEASE_OVERWATCH_STOP_GATE.gate_name,
            )
        )
    return [
        gov.EvidenceSubmission(gov.EvidenceType.JUSTIFICATION, JUSTIFICATION_TEXT, requester),
        gov.EvidenceSubmission(gov.EvidenceType.RISK_ASSESSMENT, RISK_TEXT, requester),
        approval,
    ]


# ----------------------------------------------------------------------
# Pipelines
# ----------------------------------------------------------------------

def make_adapters(anchor: Optional[PlatformAdapter] = None):
    a = anchor or MockAdapter("mock_alpha", "alpha-model", simulate_latency_ms=0)
    b = MockAdapter("mock_beta", "beta-model", simulate_latency_ms=0)
    c = MockAdapter("mock_gamma", "gamma-model", simulate_latency_ms=0)
    return [a, b, c]


def make_selector(adapters: list) -> PlatformSelector:
    selector = PlatformSelector(min_rotation=2)
    for ad in adapters:
        selector.register_adapter(ad)
    selector.set_anchor(adapters[0].platform_id)
    return selector


def make_navigator(nav_adapter: Optional[PlatformAdapter] = None) -> NavigatorRouter:
    nav = nav_adapter or MockAdapter(
        "mock_navigator", "nav-model",
        responses=[NAVIGATOR_MOCK_RESPONSE], simulate_latency_ms=0,
    )
    return NavigatorRouter(navigator_adapter=nav)


def make_channel(tmp: Path, logger: AuditLogger, **overrides):
    m = ow()
    kwargs = dict(
        channel_path=tmp / "overwatch" / "stop_channel.jsonl",
        state_path=tmp / "gopel_state" / "overwatch_stop_state.json",
        key_id=STOP_KEY_ID,
        stop_key=STOP_KEY,
        pipeline_id=PIPELINE_ID,
        audit_logger=logger,
    )
    kwargs.update(overrides)
    return m.OverwatchStopChannel(**kwargs)


def make_pipeline(
    kind: str,
    tmp: Path,
    with_channel: bool = True,
    adapters: Optional[list] = None,
    nav_adapter: Optional[PlatformAdapter] = None,
    runtime=None,
    logger: Optional[AuditLogger] = None,
    channel=None,
    **pipeline_kwargs,
):
    """Build a base or secure pipeline over mock adapters.

    Returns (pipeline, logger, channel_or_None).
    """
    tmp = Path(tmp)
    tmp.mkdir(parents=True, exist_ok=True)
    if logger is None:
        logger = AuditLogger(tmp / "audit" / "audit.json", operator_id="pipeline_agent")
    if with_channel and channel is None:
        channel = make_channel(tmp, logger)
    adapters = adapters or make_adapters()
    selector = make_selector(adapters)
    navigator = make_navigator(nav_adapter)
    extra = {"overwatch_stop": channel} if with_channel else {}
    extra.update(pipeline_kwargs)
    if kind == "base":
        pipeline = GOPELPipeline(logger=logger, selector=selector, navigator=navigator, **extra)
    elif kind == "secure":
        if runtime is None:
            runtime, _ = make_runtime(register_release_gate=with_channel)
        pipeline = SecureGOPELPipeline(
            logger=logger, selector=selector, navigator=navigator,
            governance_runtime=runtime, **extra,
        )
    else:
        raise ValueError(kind)
    return pipeline, logger, channel


def run(pipeline, prompt: str = "Research question for the stop tests.",
        operator: str = "analyst_jane", **kwargs):
    return pipeline.execute(
        prompt=prompt,
        recclin_role=RECCLINRole.RESEARCHER,
        operating_model=OperatingModel.MODEL_1,
        human_operator_id=operator,
        **kwargs,
    )


def system_records(logger: AuditLogger, event_type: str) -> list[dict]:
    return [
        r for r in logger.get_records()
        if r.get("record_type") == "system" and r.get("event_type") == event_type
    ]


def records_of(logger: AuditLogger, tid: str, record_type: str) -> list[dict]:
    return [r for r in logger.reconstruct_transaction(tid) if r.get("record_type") == record_type]


class CountingAdapter(MockAdapter):
    """Mock adapter that counts send_prompt calls."""

    def __init__(self, platform_id: str, model: str):
        super().__init__(platform_id, model, simulate_latency_ms=0)
        self.calls = 0

    def send_prompt(self, prompt, model=None, system_prompt=None, max_tokens=4096, temperature=None):
        self.calls += 1
        return super().send_prompt(prompt, model=model, system_prompt=system_prompt,
                                   max_tokens=max_tokens, temperature=temperature)


class StopDuringDispatchAdapter(PlatformAdapter):
    """Appends a valid stop line to the channel while inside send_prompt.

    Models a stop that arrives while a dispatch is in flight.
    """

    def __init__(self, platform_id: str, channel_path: Path, body: dict,
                 response_text: str = "In-flight response text from the anchor."):
        super().__init__(platform_id=platform_id, default_model="inflight-model")
        self.channel_path = Path(channel_path)
        self.body = body
        self.response_text = response_text
        self.calls = 0

    def send_prompt(self, prompt, model=None, system_prompt=None, max_tokens=4096, temperature=None):
        self.calls += 1
        self.channel_path.parent.mkdir(parents=True, exist_ok=True)
        append_line(self.channel_path, make_line(self.body))
        return AdapterResponse(
            platform_id=self.platform_id,
            platform_model=self.default_model,
            response_text=self.response_text,
            api_confirmation="inflight_1",
        )
