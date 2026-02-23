"""
HAIA Agent Framework - Sentinel (Pipeline Identity Verification)
=================================================================
Prevents a rogue AI or agent from impersonating the GOPEL pipeline.

The problem: If an adversary replaces or intercepts the GOPEL's output,
they can send the human a fake "NOMINAL" breach report and the human
never knows they are compromised. The pipeline's own output channel
is the attack surface.

The solution has four layers:

    1. PIPELINE IDENTITY
       The GOPEL instance has its own HMAC-SHA256 signing key, separate
       from operator keys. Every output (breach report, checkpoint
       package, notification) is signed. A rogue agent cannot forge
       a valid signature without possessing the key.

    2. HEARTBEAT (DEAD MAN'S SWITCH)
       The pipeline emits a signed heartbeat at a configurable interval.
       If the human's monitoring system stops receiving heartbeats,
       the ABSENCE of the signal IS the alert. A silenced GOPEL is
       detected by silence.

    3. CHALLENGE-RESPONSE
       The human can challenge the pipeline at any time with a random
       nonce. The pipeline must return the nonce signed with its key.
       A rogue agent that intercepts the output channel cannot answer
       the challenge because it does not possess the signing key.

    4. OUT-OF-BAND ALERTS
       Critical breach notifications are dispatched through a secondary
       channel (separate from the pipeline's primary output). If the
       primary channel is compromised, the secondary channel still
       delivers the alert.

Non-cognitive constraint maintained:
    Signing is HMAC computation (mathematical).
    Heartbeat is a timer-based emission (mechanical).
    Challenge-response is nonce comparison (deterministic).
    None of these evaluate AI-generated content.

What this does NOT protect against:
    - Physical theft of the signing key from the process's memory
      (requires infrastructure-level protection: HSM, SGX, etc.)
    - Compromise of the monitoring system itself (requires separate
      monitoring-of-monitoring, turtles-all-the-way-down boundary)
    - An adversary that gains root access to the host machine
      (out of scope for application-level security)

Author: Basil C. Puglisi, MPA
"""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
import json
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from threading import Thread, Event
from typing import Optional, Callable

from .breach import BreachReport, BreachSeverity


# ======================================================================
# Pipeline Identity
# ======================================================================

class PipelineIdentity:
    """
    Cryptographic identity for the GOPEL pipeline instance.

    Separate from operator identities. Operators authenticate humans.
    PipelineIdentity authenticates the framework itself.

    The key is generated at instance creation and must be:
        1. Stored securely (KMS, HSM, encrypted file, not plaintext)
        2. Shared with the human's verification tooling
        3. Rotated periodically

    A rogue agent that does not possess this key cannot produce
    valid signatures on breach reports or checkpoint packages.
    """

    def __init__(self, instance_id: str, signing_key: Optional[str] = None):
        """
        Args:
            instance_id: Human-readable identifier for this GOPEL instance.
                         Example: "gopel-prod-east-1" or "haia-agent-v0.4.0"
            signing_key: HMAC secret key (hex). Generated if not provided.
        """
        self.instance_id = instance_id
        self.created_at = datetime.now(timezone.utc).isoformat()
        if signing_key:
            self._key = bytes.fromhex(signing_key)
        else:
            self._key = secrets.token_bytes(32)
        # Compute a public fingerprint (hash of the key, safe to share)
        self.fingerprint = hashlib.sha256(self._key).hexdigest()[:16]

    @property
    def signing_key_hex(self) -> str:
        """Return signing key as hex for secure storage (never log this)."""
        return self._key.hex()

    def sign(self, payload: str) -> str:
        """
        Sign an arbitrary string payload with this pipeline's key.
        Returns hex-encoded HMAC-SHA256.
        """
        return hmac_mod.new(
            self._key,
            payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def verify(self, payload: str, signature: str) -> bool:
        """
        Verify a payload's signature against this pipeline's key.
        Returns True if authentic.
        """
        expected = self.sign(payload)
        return hmac_mod.compare_digest(expected, signature)

    def sign_dict(self, data: dict) -> str:
        """Sign a dict (JSON-serialized, sorted keys)."""
        payload = json.dumps(data, sort_keys=True, default=str)
        return self.sign(payload)

    def verify_dict(self, data: dict, signature: str) -> bool:
        """Verify a dict's signature."""
        payload = json.dumps(data, sort_keys=True, default=str)
        return self.verify(payload, signature)


# ======================================================================
# Signed Alert Envelope
# ======================================================================

@dataclass
class SignedAlert:
    """
    An alert envelope that carries cryptographic proof of origin.

    Every output from the GOPEL pipeline to the human is wrapped
    in a SignedAlert. The human's verification tool checks the
    signature before trusting the content.

    Fields:
        pipeline_instance: Which GOPEL instance produced this
        pipeline_fingerprint: Public fingerprint for key identification
        alert_type: What kind of output this is
        payload: The actual content (breach report, checkpoint, etc.)
        timestamp: When this was produced
        sequence_number: Monotonic counter (detects dropped/replayed alerts)
        signature: HMAC-SHA256 of all above fields
    """
    pipeline_instance: str
    pipeline_fingerprint: str
    alert_type: str  # "breach_report" | "checkpoint" | "heartbeat" | "challenge_response"
    payload: dict
    timestamp: str = ""
    sequence_number: int = 0
    signature: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    def signable_content(self) -> dict:
        """Content that gets signed (everything except the signature itself)."""
        return {
            "pipeline_instance": self.pipeline_instance,
            "pipeline_fingerprint": self.pipeline_fingerprint,
            "alert_type": self.alert_type,
            "payload": self.payload,
            "timestamp": self.timestamp,
            "sequence_number": self.sequence_number,
        }

    def to_dict(self) -> dict:
        """Full envelope including signature."""
        d = self.signable_content()
        d["signature"] = self.signature
        return d


# ======================================================================
# Sentinel (the guardian that authenticates the guardian)
# ======================================================================

class Sentinel:
    """
    The Sentinel wraps all pipeline outputs in signed envelopes
    and provides heartbeat, challenge-response, and out-of-band
    alert capabilities.

    Usage:
        identity = PipelineIdentity("gopel-prod-east-1")
        sentinel = Sentinel(identity)

        # Wrap a breach report
        alert = sentinel.sign_breach_report(breach_report)

        # Verify at the receiving end
        is_authentic = sentinel.verify_alert(alert)

        # Start heartbeat
        sentinel.start_heartbeat(interval_seconds=60)

        # Human challenges the pipeline
        response = sentinel.answer_challenge("random-nonce-from-human")
        is_real = sentinel.verify_challenge_response("random-nonce-from-human", response)
    """

    def __init__(self, identity: PipelineIdentity):
        self._identity = identity
        self._sequence = 0
        self._heartbeat_thread: Optional[Thread] = None
        self._heartbeat_stop = Event()
        self._heartbeat_callbacks: list[Callable[[SignedAlert], None]] = []
        self._oob_callbacks: list[Callable[[SignedAlert], None]] = []

    @property
    def instance_id(self) -> str:
        return self._identity.instance_id

    @property
    def fingerprint(self) -> str:
        return self._identity.fingerprint

    # ==================================================================
    # Layer 1: Signed Output Wrapping
    # ==================================================================

    def _next_sequence(self) -> int:
        """Monotonic sequence counter. Detects dropped or replayed alerts."""
        self._sequence += 1
        return self._sequence

    def _create_signed_alert(self, alert_type: str, payload: dict) -> SignedAlert:
        """Create and sign an alert envelope."""
        alert = SignedAlert(
            pipeline_instance=self._identity.instance_id,
            pipeline_fingerprint=self._identity.fingerprint,
            alert_type=alert_type,
            payload=payload,
            sequence_number=self._next_sequence(),
        )
        alert.signature = self._identity.sign_dict(alert.signable_content())
        return alert

    def sign_breach_report(self, report: BreachReport) -> SignedAlert:
        """
        Wrap a breach report in a signed envelope.

        The human receives this instead of the raw report.
        Their verification tool checks the signature before
        displaying the report content.
        """
        return self._create_signed_alert("breach_report", report.to_dict())

    def sign_checkpoint_package(self, package_data: dict) -> SignedAlert:
        """
        Wrap a checkpoint package in a signed envelope.

        Every governance package the human reviews is signed.
        A rogue agent sending fake "approved" packages cannot
        produce a valid signature.
        """
        return self._create_signed_alert("checkpoint", package_data)

    def sign_custom(self, alert_type: str, payload: dict) -> SignedAlert:
        """Sign any custom payload for extensibility."""
        return self._create_signed_alert(alert_type, payload)

    def verify_alert(self, alert: SignedAlert) -> bool:
        """
        Verify that an alert was produced by this pipeline instance.

        The human's verification tool calls this with the received
        alert. Returns True only if the signature matches this
        pipeline's key.

        A rogue agent's alert will fail verification.
        """
        expected = self._identity.sign_dict(alert.signable_content())
        return hmac_mod.compare_digest(expected, alert.signature)

    def verify_alert_dict(self, alert_dict: dict) -> bool:
        """
        Verify an alert from its dict representation.

        Used when the alert was serialized (sent over a network,
        written to a file, etc.) and needs re-verification.
        """
        signature = alert_dict.get("signature", "")
        signable = {k: v for k, v in alert_dict.items() if k != "signature"}
        expected = self._identity.sign_dict(signable)
        return hmac_mod.compare_digest(expected, signature)

    # ==================================================================
    # Layer 2: Heartbeat (Dead Man's Switch)
    # ==================================================================

    def register_heartbeat_callback(self, callback: Callable[[SignedAlert], None]) -> None:
        """
        Register a callback that receives heartbeat alerts.

        The monitoring system should:
            1. Verify the heartbeat signature
            2. Check the sequence number is incrementing
            3. Raise alarm if no heartbeat arrives within 2x the interval

        The absence of heartbeats IS the alert.
        """
        self._heartbeat_callbacks.append(callback)

    def start_heartbeat(self, interval_seconds: int = 60) -> None:
        """
        Start the heartbeat thread.

        Emits a signed heartbeat to all registered callbacks
        at the specified interval. If the pipeline is killed or
        replaced, the heartbeats stop. The monitoring system
        detects the silence.
        """
        if self._heartbeat_thread and self._heartbeat_thread.is_alive():
            return  # Already running

        self._heartbeat_stop.clear()

        def _heartbeat_loop():
            while not self._heartbeat_stop.is_set():
                heartbeat = self._create_signed_alert("heartbeat", {
                    "status": "alive",
                    "uptime_seconds": self._sequence,  # Proxy for uptime
                    "instance_id": self._identity.instance_id,
                    "fingerprint": self._identity.fingerprint,
                })
                for cb in self._heartbeat_callbacks:
                    try:
                        cb(heartbeat)
                    except Exception:
                        pass  # Callback failure must not stop heartbeat
                self._heartbeat_stop.wait(interval_seconds)

        self._heartbeat_thread = Thread(target=_heartbeat_loop, daemon=True)
        self._heartbeat_thread.start()

    def stop_heartbeat(self) -> None:
        """Stop the heartbeat thread."""
        self._heartbeat_stop.set()
        if self._heartbeat_thread:
            self._heartbeat_thread.join(timeout=5)

    def emit_single_heartbeat(self) -> SignedAlert:
        """
        Emit a single heartbeat (for testing or manual triggering).
        Returns the signed heartbeat alert.
        """
        return self._create_signed_alert("heartbeat", {
            "status": "alive",
            "uptime_seconds": self._sequence,
            "instance_id": self._identity.instance_id,
            "fingerprint": self._identity.fingerprint,
        })

    # ==================================================================
    # Layer 3: Challenge-Response Authentication
    # ==================================================================

    def answer_challenge(self, nonce: str) -> SignedAlert:
        """
        Answer a human challenge with a signed response.

        The human sends a random nonce (any string they choose).
        The pipeline signs it and returns the signed alert.
        The human verifies the signature using the shared key
        or the Sentinel's verify method.

        A rogue agent intercepting the challenge cannot produce
        a valid signature for the nonce.
        """
        return self._create_signed_alert("challenge_response", {
            "nonce": nonce,
            "nonce_hash": hashlib.sha256(nonce.encode()).hexdigest(),
            "response": "authenticated",
            "instance_id": self._identity.instance_id,
        })

    def verify_challenge_response(self, nonce: str, response: SignedAlert) -> bool:
        """
        Verify a challenge response is authentic.

        Checks:
            1. Signature is valid (proves possession of key)
            2. Nonce in payload matches the challenge nonce (proves
               the response is to THIS challenge, not a replay)
            3. Alert type is "challenge_response"
        """
        if not self.verify_alert(response):
            return False
        if response.alert_type != "challenge_response":
            return False
        if response.payload.get("nonce") != nonce:
            return False
        return True

    # ==================================================================
    # Layer 4: Out-of-Band Alert Channel
    # ==================================================================

    def register_oob_callback(self, callback: Callable[[SignedAlert], None]) -> None:
        """
        Register an out-of-band notification callback.

        OOB callbacks are used for CRITICAL and HALT severity alerts.
        They should route through a DIFFERENT channel than the
        pipeline's primary output:

            - Primary channel: API response, web UI, stdout
            - OOB channel: Email, SMS, Slack webhook, PagerDuty, file

        If the primary channel is intercepted by a rogue agent,
        the OOB channel still delivers the alert.
        """
        self._oob_callbacks.append(callback)

    def dispatch_oob_alert(self, report: BreachReport) -> int:
        """
        Send a breach report through the out-of-band channel.

        Only dispatches for WARNING, CRITICAL, and HALT severity.
        NOMINAL and ADVISORY use the primary channel only.

        Returns number of successful OOB dispatches.
        """
        if report.overall_severity in (BreachSeverity.NOMINAL, BreachSeverity.ADVISORY):
            return 0

        signed = self.sign_breach_report(report)
        success_count = 0
        for cb in self._oob_callbacks:
            try:
                cb(signed)
                success_count += 1
            except Exception:
                pass  # OOB failure must not crash pipeline
        return success_count

    # ==================================================================
    # Convenience: File-based OOB channel
    # ==================================================================

    @staticmethod
    def file_oob_factory(alert_path: Path) -> Callable[[SignedAlert], None]:
        """
        Create an OOB callback that writes signed alerts to a file.

        The file should be on a DIFFERENT filesystem or monitored
        by a SEPARATE process. If it's on the same filesystem as
        the pipeline, an attacker with filesystem access can
        suppress it (same problem as H1 witness separation).
        """
        def callback(alert: SignedAlert) -> None:
            alert_path.parent.mkdir(parents=True, exist_ok=True)
            with open(alert_path, "a") as f:
                entry = json.dumps(alert.to_dict(), default=str)
                f.write(entry + "\n")
        return callback


# ======================================================================
# Heartbeat Monitor (runs on the human's side, not the pipeline's side)
# ======================================================================

class HeartbeatMonitor:
    """
    Monitors heartbeats from a GOPEL instance and raises alarm on silence.

    This runs OUTSIDE the pipeline, on the human's monitoring infrastructure.
    It is the human's verification tool, not part of the GOPEL itself.

    The separation is critical: if the monitor ran inside the pipeline,
    a rogue agent that replaces the pipeline also replaces the monitor.
    The monitor must be an independent process.

    Usage:
        monitor = HeartbeatMonitor(
            expected_fingerprint="abc123...",
            max_silence_seconds=120,
            alarm_callback=lambda msg: send_sms("Pipeline may be compromised: " + msg),
        )
        # Called by the monitoring system when a heartbeat arrives
        monitor.receive_heartbeat(heartbeat_alert)
        # Called periodically by the monitoring system
        monitor.check_silence()
    """

    def __init__(
        self,
        expected_fingerprint: str,
        max_silence_seconds: int = 120,
        alarm_callback: Optional[Callable[[str], None]] = None,
    ):
        self.expected_fingerprint = expected_fingerprint
        self.max_silence_seconds = max_silence_seconds
        self.alarm_callback = alarm_callback or (lambda msg: None)
        self._last_heartbeat_time: Optional[datetime] = None
        self._last_sequence: int = 0
        self._alarm_raised: bool = False
        self._history: list[dict] = []

    def receive_heartbeat(self, alert: SignedAlert) -> dict:
        """
        Process a received heartbeat.

        Returns a status dict with verification results.
        """
        now = datetime.now(timezone.utc)
        status = {
            "received_at": now.isoformat(),
            "fingerprint_match": alert.pipeline_fingerprint == self.expected_fingerprint,
            "sequence_number": alert.sequence_number,
            "sequence_advancing": alert.sequence_number > self._last_sequence,
            "alert_type_correct": alert.alert_type == "heartbeat",
            "authenticated": False,  # Caller must verify signature separately
        }

        # Fingerprint check
        if not status["fingerprint_match"]:
            self.alarm_callback(
                f"IMPERSONATION ALERT: Heartbeat received with fingerprint "
                f"'{alert.pipeline_fingerprint}' but expected "
                f"'{self.expected_fingerprint}'. A different entity is "
                f"claiming to be the GOPEL pipeline."
            )
            status["alarm"] = "fingerprint_mismatch"
            self._history.append(status)
            return status

        # Sequence check (detects replayed heartbeats)
        if not status["sequence_advancing"]:
            self.alarm_callback(
                f"REPLAY ALERT: Heartbeat sequence {alert.sequence_number} "
                f"is not greater than last seen {self._last_sequence}. "
                f"Heartbeats may be replayed by an adversary."
            )
            status["alarm"] = "sequence_not_advancing"
            self._history.append(status)
            return status

        # Valid heartbeat
        self._last_heartbeat_time = now
        self._last_sequence = alert.sequence_number
        self._alarm_raised = False
        status["alarm"] = "none"
        self._history.append(status)
        return status

    def check_silence(self) -> dict:
        """
        Check if the pipeline has gone silent.

        Call this periodically (e.g., every 30 seconds).
        If no heartbeat has been received within max_silence_seconds,
        the alarm fires.

        Returns status dict.
        """
        now = datetime.now(timezone.utc)
        if self._last_heartbeat_time is None:
            # Never received a heartbeat
            return {"status": "waiting_for_first_heartbeat", "alarm": "none"}

        elapsed = (now - self._last_heartbeat_time).total_seconds()
        if elapsed > self.max_silence_seconds:
            if not self._alarm_raised:
                self._alarm_raised = True
                self.alarm_callback(
                    f"SILENCE ALERT: No heartbeat received for {elapsed:.0f} seconds "
                    f"(threshold: {self.max_silence_seconds}s). "
                    f"Last heartbeat at {self._last_heartbeat_time.isoformat()}. "
                    f"The GOPEL pipeline may have been killed, replaced, or silenced. "
                    f"DO NOT TRUST any governance outputs received through the "
                    f"primary channel until pipeline identity is re-verified."
                )
            return {
                "status": "silent",
                "elapsed_seconds": elapsed,
                "threshold_seconds": self.max_silence_seconds,
                "alarm": "silence_detected",
            }

        return {
            "status": "active",
            "elapsed_seconds": elapsed,
            "threshold_seconds": self.max_silence_seconds,
            "alarm": "none",
        }

    @property
    def history(self) -> list[dict]:
        """Return heartbeat reception history for audit."""
        return list(self._history)
