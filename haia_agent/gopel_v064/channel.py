"""
HAIA Agent Framework - GOPEL Channel
====================================
GOPEL v0.6.4, Team Gate (HAIA_Update_Plan_v4, Part C2).

"Under Agent Operating Models 1 and 2, GOPEL provides the governed channel
between the human governor and the AI platforms. HAIA-Agent determines how
that channel is used." (Overwatch v2.4, Section 3.3)

The channel exposes GOPEL's seven operations one at a time, so an agent
program can use GOPEL without the fixed shape of execute():

    open_dispatch   Log: the Request record of one group. The messages are
                    frozen as canonical JSON, so every dispatch in the group
                    sends the same bytes (identical prompt by construction).
    dispatch        Dispatch and Collect: one platform of the group. Writes
                    the Dispatch and Response records; returns the reply
                    unaltered.
    route           Route: one Navigator turn. Writes Request, Dispatch,
                    Response, and Navigation records.
    close           Log: a channel_group_closed system record listing the
                    group's Response record IDs. A group also closes by
                    itself when every platform has answered, or on a stop.
    status          Report: instance, version, whether the stored chain
                    verifies, the head, active stops, releases. IDs and
                    hashes only, never text.
    Pause           Every operation checks the Overwatch stop intake first
                    (check point a), before each platform call (b), and
                    after collecting (c). A stopped call is still logged;
                    its text is withheld from the caller.
    Hash            The audit logger's hash chain.

The agent decides which platforms, which messages, and which Navigator.
The channel decides nothing: every operation is hashing, comparison,
lookup, logging, or a call to the platform the caller named.

Non-cognitive constraint: nothing here reads, ranks, edits, or judges the
text it carries.

Author: Basil C. Puglisi, MPA
License: Open publication for public infrastructure
"""

from __future__ import annotations

import hashlib
import json
import threading
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .logger import verify_record_chain
from .models import (
    ChannelRequestRecord,
    OperatingModel,
    PlatformStatus,
    RECCLINRole,
    build_generation_settings,
)
from .overwatch_stop import OverwatchReleaseResult, stopped_error_message
from .security import TransportVerifier


EVENT_GROUP_CLOSED = "channel_group_closed"
REASON_COMPLETE = "complete"
REASON_STOPPED = "stopped"
REASON_FAILED = "failed"
DEFAULT_MAX_TOKENS = 4096


class ChannelError(ValueError):
    """A call the channel refuses: an unknown caller or platform, a bad
    message list, a closed group, or a platform dispatched twice."""


def canonical_json(obj) -> str:
    """The canonical JSON form used for frozen messages and record details."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(data) -> str:
    raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
    return hashlib.sha256(raw).hexdigest()


def _ref(record) -> dict:
    return {"record_id": record.record_id, "chain_hash": record.chain_hash}


@dataclass
class Group:
    """One dispatch group: frozen messages, the platforms named, and what
    each has returned so far."""
    transaction_id: str
    caller_id: str
    operating_model: OperatingModel
    recclin_role: RECCLINRole
    canonical_messages: str
    prompt_hash: str
    images: tuple
    image_sha256: list
    platforms: tuple
    request_ref: dict
    responses: dict = field(default_factory=dict)
    in_flight: set = field(default_factory=set)
    closed: bool = False
    stopped: bool = False

    @property
    def messages(self) -> list:
        """A fresh copy of the frozen messages."""
        return json.loads(self.canonical_messages)

    def model_of(self, platform_id: str) -> Optional[str]:
        for pid, model in self.platforms:
            if pid == platform_id:
                return model
        return None


@dataclass
class ChannelResult:
    """What one channel call returns to the agent."""
    transaction_id: str = ""
    platform_id: str = ""
    model: str = ""
    success: bool = False
    stopped: bool = False
    text: Optional[str] = None
    response_id: str = ""
    stop_reason: Optional[str] = None
    completed: bool = False
    tokens: int = 0
    latency_ms: int = 0
    error: str = ""
    prompt_hash: str = ""
    response_hash: str = ""
    request_ref: Optional[dict] = None
    dispatch_ref: Optional[dict] = None
    response_ref: Optional[dict] = None
    navigation_ref: Optional[dict] = None
    active_stop_event_ids: list = field(default_factory=list)


@dataclass(frozen=True)
class ChannelStatus:
    """The Report operation: IDs and hashes only, never text."""
    instance_id: str
    version: str
    chain_ok: bool
    head_seq: int
    head_chain_hash: str
    chain_hash_at: Optional[str]
    active_stop_event_ids: list
    release_ids: list


class GOPELChannel:
    """
    The governed channel between the agents and the AI platforms.

    Args:
        logger: GOPEL's AuditLogger or SecureAuditLogger (one writer per file).
        adapters: {platform_id: MessageAdapter}. Provider keys, when real
            adapters are used, are read inside the adapters, in the process
            that hosts GOPEL (QT2).
        overwatch_stop: the OverwatchStopChannel, writing to this logger.
            None means no Overwatch is configured, and the channel runs.
        sentinel: the Sentinel whose instance_id names this GOPEL.
        callers: the agent programs allowed to open groups.
    """

    def __init__(self, logger, adapters: dict, overwatch_stop=None, sentinel=None, callers=()):
        if logger is None:
            raise ChannelError("The channel needs GOPEL's audit logger.")
        if not isinstance(adapters, dict) or not adapters:
            raise ChannelError("The channel needs at least one platform adapter.")
        for pid, adapter in adapters.items():
            if getattr(adapter, "platform_id", None) != pid or not callable(getattr(adapter, "send_messages", None)):
                raise ChannelError(f"Adapter for {pid!r} is not a message adapter with that platform_id.")
        if overwatch_stop is not None and overwatch_stop.audit_logger is not logger:
            raise ChannelError("The Overwatch stop intake must write to the channel's own audit logger.")
        if sentinel is not None and overwatch_stop is not None and sentinel.instance_id != overwatch_stop.pipeline_id:
            raise ChannelError(
                f"The stop intake targets {overwatch_stop.pipeline_id!r}, but this GOPEL is "
                f"{sentinel.instance_id!r}.")
        self.logger = logger
        self.adapters = dict(adapters)
        self.overwatch_stop = overwatch_stop
        self.sentinel = sentinel
        self.callers = frozenset(callers)
        if sentinel is not None:
            self.instance_id = sentinel.instance_id
        elif overwatch_stop is not None:
            self.instance_id = overwatch_stop.pipeline_id
        else:
            self.instance_id = ""
        self._lock = threading.RLock()
        self._groups: dict[str, Group] = {}

    # ------------------------------------------------------------------
    # Registry
    # ------------------------------------------------------------------

    def registry(self) -> dict:
        """{platform_id: service} for every platform this channel can reach."""
        return {pid: getattr(a, "service", pid) for pid, a in self.adapters.items()}

    def registry_sha256(self) -> str:
        """SHA-256 of the canonical registry, for a caller's charter to pin."""
        return sha256_hex(canonical_json(self.registry()))

    # ------------------------------------------------------------------
    # Checks (structure only)
    # ------------------------------------------------------------------

    def _check_caller(self, caller_id: str) -> None:
        if not isinstance(caller_id, str) or not caller_id:
            raise ChannelError("A caller ID is required.")
        if self.callers and caller_id not in self.callers:
            raise ChannelError(f"{caller_id!r} is not a caller this channel serves.")

    @staticmethod
    def _check_messages(messages) -> None:
        if not isinstance(messages, list) or not messages:
            raise ChannelError("Messages must be a non-empty list.")
        for m in messages:
            if not isinstance(m, dict) or set(m.keys()) != {"role", "content"} \
                    or not isinstance(m["role"], str) or not isinstance(m["content"], str):
                raise ChannelError("Each message must be exactly {\"role\": str, \"content\": str}.")

    @staticmethod
    def _check_images(images) -> tuple:
        out = []
        for item in images or ():
            if not (isinstance(item, (tuple, list)) and len(item) == 2 and isinstance(item[0], str)
                    and isinstance(item[1], (bytes, bytearray))):
                raise ChannelError("Each image must be (media_type, bytes).")
            out.append((item[0], bytes(item[1])))
        return tuple(out)

    def _check_platforms(self, platforms) -> tuple:
        out = []
        for item in platforms or ():
            if not (isinstance(item, (tuple, list)) and len(item) == 2
                    and isinstance(item[0], str) and isinstance(item[1], str)):
                raise ChannelError("Each platform must be (platform_id, model).")
            if item[0] not in self.adapters:
                raise ChannelError(f"{item[0]!r} is not a platform this channel can reach.")
            out.append((item[0], item[1]))
        if not out:
            raise ChannelError("At least one platform must be named.")
        if len({pid for pid, _ in out}) != len(out):
            raise ChannelError("A platform may be named once per group.")
        return tuple(out)

    def _stops(self, transaction_id: str) -> list:
        if self.overwatch_stop is None:
            return []
        return self.overwatch_stop.poll(transaction_id=transaction_id)

    @staticmethod
    def _stopped(transaction_id: str, active: list, **fields) -> ChannelResult:
        return ChannelResult(transaction_id=transaction_id, stopped=True, error=stopped_error_message(active),
                             active_stop_event_ids=list(active), **fields)

    def _log_request(self, transaction_id, caller_id, operating_model, recclin_role, canonical, platforms,
                     image_sha256, authority_ref):
        record = ChannelRequestRecord(
            transaction_id=transaction_id,
            operator_id=caller_id,
            prompt_text=canonical,
            recclin_role=recclin_role,
            operating_model=operating_model,
            platform_selections=[pid for pid, _ in platforms],
            caller_id=caller_id,
            image_sha256=list(image_sha256),
            authority_ref=authority_ref or "",
        )
        self.logger.log_record(record)
        return record

    def _call(self, transaction_id, caller_id, platform_id, model, canonical, prompt_hash, images,
              timeout, max_tokens, temperature):
        """One platform call, then its Dispatch and Response records."""
        if not TransportVerifier.verify_dispatch_integrity(canonical, prompt_hash):
            raise ChannelError("The frozen messages no longer match their prompt hash.")
        max_tokens = DEFAULT_MAX_TOKENS if max_tokens is None else max_tokens
        settings = build_generation_settings(model, max_tokens, temperature)
        resp = self.adapters[platform_id].send_messages(
            model, json.loads(canonical), images, timeout, max_tokens, temperature)
        dispatch = self.logger.log_dispatch(
            transaction_id=transaction_id, operator_id=caller_id, platform_id=platform_id,
            platform_model=model, prompt_hash=prompt_hash, is_anchor=False,
            dispatch_status=PlatformStatus.SENT if resp.success else PlatformStatus.ERROR,
            api_confirmation=resp.api_confirmation, generation_settings=settings)
        response = self.logger.log_response(
            transaction_id=transaction_id, operator_id=caller_id, platform_id=platform_id,
            platform_model=model, response_text=resp.response_text,
            response_status=PlatformStatus.RECEIVED if resp.success else PlatformStatus.ERROR,
            token_count=resp.token_count, latency_ms=resp.latency_ms, error_detail=resp.error_detail,
            generation_settings=settings)
        meta = resp.raw_metadata or {}
        result = ChannelResult(
            transaction_id=transaction_id, platform_id=platform_id, model=model, success=resp.success,
            text=resp.response_text if resp.success else None, response_id=resp.api_confirmation,
            stop_reason=meta.get("stop_reason"), completed=bool(meta.get("completed")) and resp.success,
            tokens=resp.token_count, latency_ms=resp.latency_ms, error=resp.error_detail,
            prompt_hash=prompt_hash, response_hash=response.response_hash,
            dispatch_ref=_ref(dispatch), response_ref=_ref(response))
        return result

    def _close(self, transaction_id: str, caller_id: str, kind: str, reason: str, response_ids: list) -> None:
        self.logger.log_system_event(
            EVENT_GROUP_CLOSED,
            canonical_json({"caller_id": caller_id, "kind": kind, "reason": reason,
                            "response_record_ids": list(response_ids)}),
            "info",
            transaction_id=transaction_id,
        )

    # ------------------------------------------------------------------
    # Operations
    # ------------------------------------------------------------------

    def open_dispatch(self, caller_id: str, operating_model: OperatingModel, recclin_role: RECCLINRole,
                      messages: list, images=(), platforms=(), authority_ref: str = "",
                      transaction_id: Optional[str] = None):
        """Freeze the messages and write the Request record of one group.
        Returns the Group, or a stopped ChannelResult (check point a)."""
        self._check_caller(caller_id)
        self._check_messages(messages)
        images = self._check_images(images)
        platforms = self._check_platforms(platforms)
        tid = transaction_id or f"ch-{uuid.uuid4().hex}"
        active = self._stops(tid)
        if active:
            return self._stopped(tid, active)
        canonical = canonical_json(messages)
        prompt_hash = sha256_hex(canonical)
        image_sha256 = [sha256_hex(b) for _, b in images]
        with self._lock:
            if tid in self._groups:
                raise ChannelError(f"Group {tid!r} already exists.")
            request = self._log_request(tid, caller_id, operating_model, recclin_role, canonical, platforms,
                                        image_sha256, authority_ref)
            group = Group(transaction_id=tid, caller_id=caller_id, operating_model=operating_model,
                          recclin_role=recclin_role, canonical_messages=canonical, prompt_hash=prompt_hash,
                          images=images, image_sha256=image_sha256, platforms=platforms,
                          request_ref=_ref(request))
            self._groups[tid] = group
        return group

    def dispatch(self, group: Group, platform_id: str, timeout: Optional[float] = None,
                 max_tokens: Optional[int] = None, temperature: Optional[float] = None) -> ChannelResult:
        """Send the group's frozen messages to one of its platforms and collect
        the reply unaltered. Check points b (before the call) and c (after)."""
        tid = getattr(group, "transaction_id", None)
        with self._lock:
            if self._groups.get(tid) is not group:
                raise ChannelError("Not a group this channel opened.")
            if group.closed:
                raise ChannelError(f"Group {tid!r} is closed.")
            model = group.model_of(platform_id)
            if model is None:
                raise ChannelError(f"{platform_id!r} is not a platform of group {tid!r}.")
            if platform_id in group.responses or platform_id in group.in_flight:
                raise ChannelError(f"{platform_id!r} was already dispatched in group {tid!r}.")
            group.in_flight.add(platform_id)
        active = self._stops(tid)
        if active:
            with self._lock:
                group.in_flight.discard(platform_id)
                self._close_group(group, REASON_STOPPED, stopped=True)
            return self._stopped(tid, active, platform_id=platform_id, model=model,
                                 prompt_hash=group.prompt_hash, request_ref=group.request_ref)
        result = self._call(tid, group.caller_id, platform_id, model, group.canonical_messages,
                            group.prompt_hash, group.images, timeout, max_tokens, temperature)
        result.request_ref = group.request_ref
        with self._lock:
            group.in_flight.discard(platform_id)
            group.responses[platform_id] = result.response_ref
            if not group.closed and len(group.responses) == len(group.platforms):
                self._close_group(group, REASON_COMPLETE)
        active = self._stops(tid)
        if active:
            with self._lock:
                self._close_group(group, REASON_STOPPED, stopped=True)
            result.stopped = True
            result.text = None
            result.active_stop_event_ids = list(active)
            result.error = stopped_error_message(active)
        return result

    def _close_group(self, group: Group, reason: str, stopped: bool = False) -> None:
        if stopped:
            group.stopped = True
        if group.closed:
            return
        group.closed = True
        ids = [group.responses[pid]["record_id"] for pid, _ in group.platforms if pid in group.responses]
        self._close(group.transaction_id, group.caller_id, "dispatch", reason, ids)

    def close(self, group: Group, reason: str) -> None:
        """Close a group the caller no longer needs; the reason is recorded once."""
        with self._lock:
            if self._groups.get(getattr(group, "transaction_id", None)) is not group:
                raise ChannelError("Not a group this channel opened.")
            self._close_group(group, str(reason or "closed by the caller"))

    def route(self, caller_id: str, operating_model: OperatingModel, navigator, messages: list,
              upstream_response_ids=(), timeout: Optional[float] = None, max_tokens: Optional[int] = None,
              temperature: Optional[float] = None, transaction_id: Optional[str] = None,
              authority_ref: str = "") -> ChannelResult:
        """One Navigator turn: Request, Dispatch, Response, and, when the call
        returned text, a Navigation record holding that text unaltered."""
        self._check_caller(caller_id)
        self._check_messages(messages)
        platforms = self._check_platforms([navigator])
        pid, model = platforms[0]
        upstream = [str(x) for x in (upstream_response_ids or ())]
        tid = transaction_id or f"ch-{uuid.uuid4().hex}"
        active = self._stops(tid)
        if active:
            return self._stopped(tid, active, platform_id=pid, model=model)
        canonical = canonical_json(messages)
        prompt_hash = sha256_hex(canonical)
        request = self._log_request(tid, caller_id, operating_model, RECCLINRole.NAVIGATOR, canonical, platforms,
                                    [], authority_ref)
        result = self._call(tid, caller_id, pid, model, canonical, prompt_hash, (), timeout, max_tokens,
                            temperature)
        result.request_ref = _ref(request)
        if result.success:
            navigation = self.logger.log_navigation(
                transaction_id=tid, operator_id=caller_id, navigator_platform=pid,
                response_record_ids=upstream + [result.response_ref["record_id"]],
                full_synthesis_text=result.text)
            result.navigation_ref = _ref(navigation)
        active = self._stops(tid)
        reason = REASON_STOPPED if active else (REASON_COMPLETE if result.success else REASON_FAILED)
        self._close(tid, caller_id, "route", reason, [result.response_ref["record_id"]])
        if active:
            result.stopped = True
            result.text = None
            result.active_stop_event_ids = list(active)
            result.error = stopped_error_message(active)
        return result

    def status(self, at_seq: Optional[int] = None) -> ChannelStatus:
        """Report: polls the stop intake, then reads the stored chain."""
        from . import __version__
        active = self._stops("system")
        records, chain_ok = self._stored_records()
        head_seq, head_hash = (0, "genesis")
        if records:
            head_seq, head_hash = records[-1].get("sequence_number", 0), records[-1].get("chain_hash", "")
        at = None
        if at_seq is not None:
            at = next((r.get("chain_hash") for r in records if r.get("sequence_number") == at_seq), None)
        releases = self.overwatch_stop.releases() if self.overwatch_stop is not None else []
        return ChannelStatus(
            instance_id=self.instance_id, version=__version__, chain_ok=chain_ok, head_seq=head_seq,
            head_chain_hash=head_hash, chain_hash_at=at, active_stop_event_ids=list(active),
            release_ids=[r.get("release_id") for r in releases])

    def _stored_records(self) -> tuple[list, bool]:
        path = Path(self.logger.audit_file_path)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return self.logger.get_records(), False
        if isinstance(data, dict) and data.get("encrypted"):
            ok, _violations = self.logger.verify_chain_integrity()
            return self.logger.get_records(), bool(ok)
        records = data.get("records", []) if isinstance(data, dict) else []
        if not isinstance(records, list):
            return [], False
        try:
            return records, verify_record_chain(records) == []
        except (TypeError, AttributeError, KeyError):
            return records, False

    def release_overwatch_stop(self, human_operator_id: str, stop_event_ids, evidence,
                               governance_runtime) -> OverwatchReleaseResult:
        """A human release through the RELEASE_OVERWATCH_STOP evidence gate."""
        if self.overwatch_stop is None:
            return OverwatchReleaseResult(released=False, reason="Refused: no Overwatch stop channel is configured.")
        return self.overwatch_stop.release_overwatch_stop(
            human_operator_id, stop_event_ids, evidence, governance_runtime)
