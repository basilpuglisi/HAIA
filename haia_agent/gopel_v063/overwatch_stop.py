"""
HAIA Agent Framework - Overwatch Stop Intake
=============================================
GOPEL v0.6.3, step 20: stop the pipe, route to human (R5).

Overwatch v2.5 appends one JSON line per stop to a channel file that it
owns and writes. GOPEL opens that file read only. Overwatch never writes
into GOPEL's files or audit chain; GOPEL writes its own records.

Each channel line is exactly:

    {"body": "<canonical JSON text of the body object>", "mac": "<hex>"}

    canonical JSON: json.dumps(obj, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=False)
    mac:            HMAC-SHA256(stop_key, body text as UTF-8), lowercase hex

GOPEL recomputes the MAC over the exact received body bytes and compares
with hmac.compare_digest. GOPEL holds exactly one stop key (key_id, bytes)
scoped to the stop channel, and accepts no other key (S6).

Line handling (in file order, each line once):
    malformed JSON, wrong outer shape        -> reject "malformed"
    missing, extra, or ill-typed body fields -> reject "schema"
    body text not in canonical form          -> reject "non_canonical"
    key_id is not the configured stop key ID -> reject "wrong_key_id"
    MAC does not verify                      -> reject "bad_mac"
    target_pipeline is not this pipeline     -> reject "wrong_pipeline"
    event_id already consumed                -> reject "replay"
    otherwise                                -> accept: the stop is active

Replay protection rests on consumed event IDs only, which the MAC covers.
A valid stop is accepted whatever its issued_at relative to any release
(S5). Only newline-terminated lines are read; a final line still being
written is read at the next poll.

Durable state (written atomically: temporary file in the same directory,
flush, fsync, os.replace, fsync of the directory) holds the active stops,
the consumed event IDs, the SHA-256 of every rejected line, the releases,
and the channel read position. It is loaded at construction, so an active
stop survives a restart. A state file that cannot be read fails closed.

Release is a separate human act: release_overwatch_stop() authorizes
through GovernanceRuntime.authorize(RELEASE_OVERWATCH_STOP), whose evidence
gate requires a justification, a risk statement, and a second approver
whose signature is bound to the release of exactly the named stops
(SEC-03). Only the named active stops are cleared.

Non-cognitive constraint: every operation here is JSON parsing, string
and set comparison, HMAC recomputation, hashing, or a file operation.
Nothing here reads or evaluates AI-generated content.

Author: Basil C. Puglisi, MPA
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
import re
import tempfile
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Union

from .governance import EvidenceSubmission, GovAction


# ======================================================================
# Constants
# ======================================================================

STOP_SCHEMA_VERSION = "haia.overwatch.stop.v1"
STATE_SCHEMA = "gopel.overwatch_stop_state.v1"
MIN_STOP_KEY_BYTES = 32

STOP_TRIGGERS = ("CRITICAL", "HALT", "TRAJECTORY")
STOP_BODY_FIELDS = frozenset({
    "schema_version",
    "event_id",
    "issued_at",
    "key_id",
    "target_pipeline",
    "transaction_id",
    "trigger",
    "finding_ids",
    "gopel_record_refs",
})
RECORD_REF_FIELDS = frozenset({"record_id", "chain_hash"})
LINE_FIELDS = frozenset({"body", "mac"})

# System record event types written by GOPEL
EVENT_STOP = "overwatch_stop"
EVENT_STOP_REJECTED = "overwatch_stop_rejected"
EVENT_STOP_RELEASED = "overwatch_stop_released"
EVENT_CHANNEL_RESET = "overwatch_channel_reset"

# Rejection reasons
REASON_MALFORMED = "malformed"
REASON_SCHEMA = "schema"
REASON_NON_CANONICAL = "non_canonical"
REASON_WRONG_KEY_ID = "wrong_key_id"
REASON_BAD_MAC = "bad_mac"
REASON_WRONG_PIPELINE = "wrong_pipeline"
REASON_REPLAY = "replay"

STOPPED_ERROR_PREFIX = "STOPPED_BY_OVERWATCH"

# Matched with fullmatch, so no trailing newline is admitted.
_EVENT_ID_RE = re.compile(r"[0-9a-f]{32}")
_ISSUED_AT_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z")
_MAC_RE = re.compile(r"[0-9a-f]{64}")


# ======================================================================
# Errors and results
# ======================================================================

class OverwatchStopError(ValueError):
    """Stop channel misconfiguration or an unusable key file."""


class OverwatchStopStateError(OverwatchStopError):
    """The durable stop state cannot be read or is not valid. Fails closed."""


@dataclass
class LineVerification:
    """The result of verifying one channel line."""
    accepted: bool
    reason: str
    line_sha256: str
    body: Optional[dict] = None
    mac: str = ""


@dataclass
class OverwatchReleaseResult:
    """The result of a release request."""
    released: bool
    reason: str
    release_id: str = ""
    cleared: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    governance_decision: Optional[object] = None


# ======================================================================
# Deterministic helpers
# ======================================================================

def canonical_json(obj) -> str:
    """The canonical JSON form shared by GOPEL and Overwatch."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def utc_now_ms() -> str:
    """ISO 8601 UTC with milliseconds and Z, for example 2026-10-14T16:05:09.123Z."""
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def line_sha256(raw_line: bytes) -> str:
    """SHA-256 of a raw channel line, without its terminating newline."""
    return hashlib.sha256(raw_line).hexdigest()


def release_binding_id(stop_event_ids) -> str:
    """
    The transaction binding of a release (SEC-03).

    A second approver signs EvidenceSubmission.signable_payload(
    transaction_id=release_binding_id(ids), gate_name="release_overwatch_stop").
    The signature then verifies only for the release of exactly these stops.
    """
    return "overwatch_stop_release:" + ",".join(sorted(set(stop_event_ids)))


def evidence_submission_id(submission: EvidenceSubmission) -> str:
    """Content-addressed ID of an evidence submission (SHA-256, M2 sources)."""
    return hashlib.sha256(canonical_json(_evidence_entry(submission)).encode("utf-8")).hexdigest()


def _evidence_entry(submission: EvidenceSubmission) -> dict:
    return {
        "evidence_type": submission.evidence_type.value,
        "content": submission.content,
        "submitted_by": submission.submitted_by,
        "submitted_at": submission.submitted_at,
        "signature": submission.signature,
    }


def _reject_constant(value):
    raise ValueError(f"non-finite number {value} is not valid JSON here")


def _loads(text: str):
    return json.loads(text, parse_constant=_reject_constant)


def load_stop_key_file(path: Union[str, Path]) -> bytes:
    """
    Load the stop-channel key from a file holding its hex encoding.

    The file must be readable only by its owner (mode 0600 or stricter)
    and the key must be at least 32 bytes.
    """
    key_path = Path(path)
    mode = key_path.stat().st_mode
    if os.name == "posix" and mode & 0o077:
        raise OverwatchStopError(
            f"Stop key file {key_path} must be readable only by its owner "
            f"(mode 0600); found mode {oct(mode & 0o777)}."
        )
    try:
        key = bytes.fromhex(key_path.read_text(encoding="ascii").strip())
    except ValueError as exc:
        raise OverwatchStopError(f"Stop key file {key_path} is not hex: {exc}") from None
    if len(key) < MIN_STOP_KEY_BYTES:
        raise OverwatchStopError(
            f"Stop key must be at least {MIN_STOP_KEY_BYTES} bytes; got {len(key)}."
        )
    return key


def _valid_body_schema(body: dict) -> bool:
    """Field presence and types per the stop schema. Structure only."""
    if set(body.keys()) != STOP_BODY_FIELDS:
        return False
    if body["schema_version"] != STOP_SCHEMA_VERSION:
        return False
    if not isinstance(body["event_id"], str) or not _EVENT_ID_RE.fullmatch(body["event_id"]):
        return False
    if not isinstance(body["issued_at"], str) or not _ISSUED_AT_RE.fullmatch(body["issued_at"]):
        return False
    if not isinstance(body["key_id"], str) or not body["key_id"]:
        return False
    if not isinstance(body["target_pipeline"], str):
        return False
    if not isinstance(body["transaction_id"], str):
        return False
    if body["trigger"] not in STOP_TRIGGERS:
        return False
    findings = body["finding_ids"]
    if not isinstance(findings, list) or not all(isinstance(f, str) for f in findings):
        return False
    refs = body["gopel_record_refs"]
    if not isinstance(refs, list):
        return False
    for ref in refs:
        if not isinstance(ref, dict) or set(ref.keys()) != RECORD_REF_FIELDS:
            return False
        if not all(isinstance(ref[k], str) for k in RECORD_REF_FIELDS):
            return False
    return True


# ======================================================================
# The stop channel
# ======================================================================

class OverwatchStopChannel:
    """
    GOPEL's read-only intake of the Overwatch stop channel, with durable
    stop state and the human release path.

    Args:
        channel_path: The channel file Overwatch writes (opened read only).
        state_path: GOPEL's own durable stop state file.
        key_id: The ID of the single stop-channel key.
        stop_key: The stop-channel key (at least 32 bytes).
        pipeline_id: This pipeline's PipelineIdentity.instance_id.
        audit_logger: The pipeline's own AuditLogger, for GOPEL's records.
    """

    def __init__(
        self,
        channel_path: Union[str, Path],
        state_path: Union[str, Path],
        key_id: str,
        stop_key: bytes,
        pipeline_id: str,
        audit_logger,
    ):
        if not isinstance(stop_key, (bytes, bytearray)) or len(stop_key) < MIN_STOP_KEY_BYTES:
            raise OverwatchStopError(
                f"Stop key must be bytes of at least {MIN_STOP_KEY_BYTES} bytes."
            )
        if not isinstance(key_id, str) or not key_id:
            raise OverwatchStopError("Stop key ID must be a non-empty string.")
        if not isinstance(pipeline_id, str) or not pipeline_id:
            raise OverwatchStopError("pipeline_id must be a non-empty string.")
        if audit_logger is None:
            raise OverwatchStopError("An audit logger is required for GOPEL's stop records.")

        self.channel_path = Path(channel_path)
        self.state_path = Path(state_path)
        self.key_id = key_id
        self._stop_key = bytes(stop_key)
        self.pipeline_id = pipeline_id
        self.audit_logger = audit_logger
        self._lock = threading.RLock()
        self._state = self._load_state()

    # ------------------------------------------------------------------
    # Durable state
    # ------------------------------------------------------------------

    @staticmethod
    def _empty_state() -> dict:
        return {
            "schema": STATE_SCHEMA,
            "active": {},
            "consumed": [],
            "rejected_line_sha256": [],
            "releases": [],
            "channel_offset": 0,
            "channel_prefix_sha256": hashlib.sha256(b"").hexdigest(),
        }

    def _load_state(self) -> dict:
        if not self.state_path.exists():
            return self._empty_state()
        try:
            data = _loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise OverwatchStopStateError(
                f"Overwatch stop state {self.state_path} cannot be read: {exc}"
            ) from None
        if not isinstance(data, dict) or data.get("schema") != STATE_SCHEMA:
            raise OverwatchStopStateError(
                f"Overwatch stop state {self.state_path} has an unknown schema."
            )
        state = self._empty_state()
        state.update(data)
        valid = (
            isinstance(state["active"], dict)
            and all(isinstance(k, str) and isinstance(v, dict) for k, v in state["active"].items())
            and isinstance(state["consumed"], list)
            and all(isinstance(e, str) for e in state["consumed"])
            and isinstance(state["rejected_line_sha256"], list)
            and all(isinstance(e, str) for e in state["rejected_line_sha256"])
            and isinstance(state["releases"], list)
            and isinstance(state["channel_offset"], int)
            and state["channel_offset"] >= 0
            and isinstance(state["channel_prefix_sha256"], str)
        )
        if not valid:
            raise OverwatchStopStateError(
                f"Overwatch stop state {self.state_path} is not valid."
            )
        return state

    def _persist_state(self) -> None:
        """Atomic write: temp file in the same directory, fsync, replace, fsync dir."""
        directory = self.state_path.parent
        directory.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(self._state, sort_keys=True, indent=2, ensure_ascii=False)
        fd, tmp_name = tempfile.mkstemp(
            prefix=self.state_path.name + ".", suffix=".tmp", dir=str(directory)
        )
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(payload.encode("utf-8"))
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_name, self.state_path)
        except BaseException:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise
        if os.name == "posix":
            dir_fd = os.open(str(directory), os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)

    # ------------------------------------------------------------------
    # Read-only views
    # ------------------------------------------------------------------

    def active_stop_ids(self) -> list[str]:
        """Event IDs of the active stops, sorted."""
        with self._lock:
            return sorted(self._state["active"].keys())

    def active_stops(self) -> dict:
        """A copy of the active stops: {event_id: body}."""
        with self._lock:
            return copy.deepcopy(self._state["active"])

    def releases(self) -> list[dict]:
        """A copy of the recorded releases."""
        with self._lock:
            return copy.deepcopy(self._state["releases"])

    # ------------------------------------------------------------------
    # Line verification
    # ------------------------------------------------------------------

    def verify_line(self, raw_line: bytes) -> LineVerification:
        """
        Verify one raw channel line (without its newline) against the spec.

        Reads the consumed event IDs for the replay check. Changes nothing.
        """
        sha = line_sha256(raw_line)

        def reject(reason: str, body: Optional[dict] = None, mac: str = "") -> LineVerification:
            return LineVerification(False, reason, sha, body, mac)

        # Outer line: {"body": <str>, "mac": <64 lowercase hex>}
        try:
            outer = _loads(raw_line.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return reject(REASON_MALFORMED)
        if not isinstance(outer, dict) or set(outer.keys()) != LINE_FIELDS:
            return reject(REASON_MALFORMED)
        body_text, mac = outer["body"], outer["mac"]
        if not isinstance(body_text, str) or not isinstance(mac, str) or not _MAC_RE.fullmatch(mac):
            return reject(REASON_MALFORMED)

        # Body: a JSON object with exactly the stop fields
        try:
            body = _loads(body_text)
        except ValueError:
            return reject(REASON_MALFORMED)
        if not isinstance(body, dict):
            return reject(REASON_MALFORMED)
        if not _valid_body_schema(body):
            return reject(REASON_SCHEMA)
        if body_text != canonical_json(body):
            return reject(REASON_NON_CANONICAL)

        # Key: exactly the configured stop key ID, then the MAC
        if body["key_id"] != self.key_id:
            return reject(REASON_WRONG_KEY_ID, body, mac)
        expected = hmac.new(self._stop_key, body_text.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, mac):
            return reject(REASON_BAD_MAC, body, mac)

        if body["target_pipeline"] != self.pipeline_id:
            return reject(REASON_WRONG_PIPELINE, body, mac)
        if body["event_id"] in self._state["consumed"]:
            return reject(REASON_REPLAY, body, mac)
        return LineVerification(True, "accepted", sha, body, mac)

    # ------------------------------------------------------------------
    # Polling (the check points call this)
    # ------------------------------------------------------------------

    def _read_channel(self) -> Optional[bytes]:
        """The channel file's bytes, opened read only; None if it does not exist."""
        try:
            with open(self.channel_path, "rb") as f:
                return f.read()
        except FileNotFoundError:
            return None

    def poll(self, transaction_id: str = "system") -> list[str]:
        """
        Read new channel lines, verify each once, persist the state, write
        GOPEL's own records, and return the active stop event IDs (sorted).

        transaction_id is the GOPEL transaction in progress, or "system".
        With no channel file, nothing is read and GOPEL runs normally.
        """
        tid = transaction_id or "system"
        with self._lock:
            data = self._read_channel()
            if data is None:
                return self.active_stop_ids()

            offset = self._state["channel_offset"]
            reset = (
                offset > len(data)
                or hashlib.sha256(data[:offset]).hexdigest() != self._state["channel_prefix_sha256"]
            )
            previous_offset = offset
            if reset:
                offset = 0

            end = data.rfind(b"\n") + 1  # end of the last complete line
            if end <= offset and not reset:
                return self.active_stop_ids()

            rejected_seen = set(self._state["rejected_line_sha256"])
            outcomes: list[LineVerification] = []
            for raw_line in data[offset:end].split(b"\n")[:-1]:
                sha = line_sha256(raw_line)
                if sha in rejected_seen:
                    continue  # one record per distinct rejected line
                outcome = self.verify_line(raw_line)
                if outcome.accepted:
                    event_id = outcome.body["event_id"]
                    self._state["active"][event_id] = outcome.body
                    self._state["consumed"].append(event_id)
                else:
                    self._state["rejected_line_sha256"].append(sha)
                    rejected_seen.add(sha)
                outcomes.append(outcome)

            self._state["channel_offset"] = max(end, offset)
            self._state["channel_prefix_sha256"] = hashlib.sha256(
                data[:self._state["channel_offset"]]
            ).hexdigest()
            # Enforcement first: the state is durable before the records.
            self._persist_state()

            received_at = utc_now_ms()
            if reset:
                self.audit_logger.log_system_event(
                    EVENT_CHANNEL_RESET,
                    canonical_json({
                        "channel_bytes": len(data),
                        "previous_offset": previous_offset,
                        "received_at": received_at,
                    }),
                    "warning",
                    transaction_id=tid,
                )
            for outcome in outcomes:
                if outcome.accepted:
                    self.audit_logger.log_system_event(
                        EVENT_STOP,
                        canonical_json({
                            "body": outcome.body,
                            "line_sha256": outcome.line_sha256,
                            "mac": outcome.mac,
                            "received_at": received_at,
                        }),
                        "critical",
                        transaction_id=tid,
                    )
                else:
                    self.audit_logger.log_system_event(
                        EVENT_STOP_REJECTED,
                        canonical_json({
                            "line_sha256": outcome.line_sha256,
                            "reason": outcome.reason,
                            "received_at": received_at,
                        }),
                        "warning",
                        transaction_id=tid,
                    )
            return self.active_stop_ids()

    # ------------------------------------------------------------------
    # Release (a separate human act through the evidence gate)
    # ------------------------------------------------------------------

    def release_overwatch_stop(
        self,
        human_operator_id: str,
        stop_event_ids,
        evidence,
        governance_runtime,
    ) -> OverwatchReleaseResult:
        """
        Release the named active stops through GovernanceRuntime.authorize(
        RELEASE_OVERWATCH_STOP). Clears only the named stops.

        Refused if there is no governance runtime, if no stop is named, if
        any named event ID is not active, or if authorization is denied.
        """
        with self._lock:
            self.poll("system")
            if isinstance(stop_event_ids, str):
                stop_event_ids = [stop_event_ids]
            ids = sorted(set(stop_event_ids or []))
            evidence = list(evidence or [])

            if governance_runtime is None:
                return OverwatchReleaseResult(
                    released=False,
                    reason=(
                        "Refused: no governance runtime. A release requires "
                        "authorization through the RELEASE_OVERWATCH_STOP evidence gate."
                    ),
                )
            if not ids:
                return OverwatchReleaseResult(
                    released=False, reason="Refused: no stop event IDs named.")
            not_active = [i for i in ids if i not in self._state["active"]]
            if not_active:
                return OverwatchReleaseResult(
                    released=False,
                    reason=f"Refused: not active: {', '.join(not_active)}.",
                )

            decision = governance_runtime.authorize(
                operator_id=human_operator_id,
                action=GovAction.RELEASE_OVERWATCH_STOP,
                evidence=evidence,
                transaction_id=release_binding_id(ids),
            )
            if not decision.authorized:
                return OverwatchReleaseResult(
                    released=False,
                    reason=f"Refused: authorization denied: {decision.reason}",
                    governance_decision=decision,
                )

            release_id = uuid.uuid4().hex
            released_at = utc_now_ms()
            evidence_ids = [evidence_submission_id(e) for e in evidence]
            for event_id in ids:
                del self._state["active"][event_id]
            entry = {
                "release_id": release_id,
                "cleared": ids,
                "operator_id": human_operator_id,
                "evidence_ids": evidence_ids,
                "released_at": released_at,
            }
            self._state["releases"].append(entry)
            self._persist_state()

            detail = dict(entry)
            detail["binding_id"] = release_binding_id(ids)
            detail["gate_passed"] = bool(decision.evidence_gate_passed)
            detail["evidence"] = [
                dict(_evidence_entry(e), evidence_id=evidence_submission_id(e))
                for e in evidence
            ]
            self.audit_logger.log_system_event(
                EVENT_STOP_RELEASED,
                canonical_json(detail),
                "info",
                transaction_id="system",
            )
            return OverwatchReleaseResult(
                released=True,
                reason="Released by a human act through the RELEASE_OVERWATCH_STOP evidence gate.",
                release_id=release_id,
                cleared=list(ids),
                evidence_ids=evidence_ids,
                governance_decision=decision,
            )


def stopped_error_message(active_ids: list[str]) -> str:
    """The error text of a stopped result; it starts with STOPPED_BY_OVERWATCH."""
    return (
        f"{STOPPED_ERROR_PREFIX}: active Overwatch stop event(s): "
        f"{', '.join(active_ids)}. GOPEL halted this transaction. A human "
        f"release through the RELEASE_OVERWATCH_STOP evidence gate is required."
    )
