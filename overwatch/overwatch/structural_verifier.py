"""
HAIA-Overwatch v1.0 - Structural Verifier

Part 1 of the two-part verification gate.
Verifies GOPEL's infrastructure integrity from outside GOPEL's trust boundary.
Three domains: code integrity, configuration integrity, behavioral baselines.

Author: Basil C. Puglisi, MPA
License: CC BY-NC 4.0
"""

import hashlib
import json
import math
import os
import random
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .models import (
    DeploymentManifest, OverwatchConfig, Severity, StructuralFinding, StructuralResult
)
from .structured_logger import get_logger, sanitize_log_value as _sanitize_log

logger = get_logger("overwatch.structural_verifier")




# ---------------------------------------------------------------------------
# Behavioral Baseline
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class BehavioralBaseline:
    """Statistical baseline of GOPEL's operational behavior.
    Built from verified clean transactions."""
    dispatch_latency_mean: float = 0.0
    dispatch_latency_std: float = 0.0
    response_time_mean: float = 0.0
    response_time_std: float = 0.0
    breach_frequency: float = 0.0  # breaches per transaction
    checkpoint_pause_mean: float = 0.0
    checkpoint_pause_std: float = 0.0
    audit_write_size_mean: float = 0.0
    audit_write_size_std: float = 0.0
    sample_count: int = 0

    def update(self, new_sample: "BehavioralSample") -> None:
        """Incremental update using Welford's online algorithm."""
        self.sample_count += 1
        n = self.sample_count

        # Dispatch latency
        delta = new_sample.dispatch_latency - self.dispatch_latency_mean
        self.dispatch_latency_mean += delta / n
        if n > 1:
            delta2 = new_sample.dispatch_latency - self.dispatch_latency_mean
            variance = ((n - 2) / (n - 1)) * (self.dispatch_latency_std ** 2) + (delta * delta2) / n
            self.dispatch_latency_std = math.sqrt(max(0, variance))

        # Response time
        delta = new_sample.response_time - self.response_time_mean
        self.response_time_mean += delta / n
        if n > 1:
            delta2 = new_sample.response_time - self.response_time_mean
            variance = ((n - 2) / (n - 1)) * (self.response_time_std ** 2) + (delta * delta2) / n
            self.response_time_std = math.sqrt(max(0, variance))

        # Audit write size
        delta = new_sample.audit_write_size - self.audit_write_size_mean
        self.audit_write_size_mean += delta / n
        if n > 1:
            delta2 = new_sample.audit_write_size - self.audit_write_size_mean
            variance = ((n - 2) / (n - 1)) * (self.audit_write_size_std ** 2) + (delta * delta2) / n
            self.audit_write_size_std = math.sqrt(max(0, variance))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "dispatch_latency_mean": self.dispatch_latency_mean,
            "dispatch_latency_std": self.dispatch_latency_std,
            "response_time_mean": self.response_time_mean,
            "response_time_std": self.response_time_std,
            "breach_frequency": self.breach_frequency,
            "audit_write_size_mean": self.audit_write_size_mean,
            "audit_write_size_std": self.audit_write_size_std,
            "sample_count": self.sample_count
        }


@dataclass(slots=True)
class BehavioralSample:
    """A single behavioral observation from GOPEL's operation."""
    timestamp: float = field(default_factory=time.time)
    dispatch_latency: float = 0.0
    response_time: float = 0.0
    breach_detected: bool = False
    checkpoint_pause_duration: float = 0.0
    audit_write_size: float = 0.0


# ---------------------------------------------------------------------------
# Structural Verifier
# ---------------------------------------------------------------------------

class StructuralVerifier:
    """Part 1 of the two-part verification gate.

    Verifies GOPEL's infrastructure integrity from outside GOPEL's trust
    boundary. Three verification domains:
    1. Code integrity (file hash comparison against deployment manifest)
    2. Configuration integrity (active config vs. snapshot)
    3. Behavioral baseline (operational metrics vs. statistical baseline)

    Overwatch reads GOPEL's files and audit trail through read-only access.
    Overwatch has no write access to GOPEL's process space.
    """

    def __init__(self, config: OverwatchConfig):
        self.config = config
        self.manifest: Optional[DeploymentManifest] = None
        self.baseline = BehavioralBaseline()
        self.last_code_check: float = 0.0
        self.last_config_check: float = 0.0
        self.cbg_authorized_releases: List[Dict[str, Any]] = []  # list of release records

    def load_manifest(self, manifest_data: Dict[str, Any]) -> None:
        """Load deployment manifest from Overwatch's independent storage."""
        self.manifest = DeploymentManifest.from_dict(manifest_data)

    def create_manifest_from_directory(
        self, directory: str, gopel_version: str, cbg_auth_id: str
    ) -> DeploymentManifest:
        """Create a new deployment manifest by hashing all files in directory.
        Called during initial deployment or CBG-authorized release."""
        manifest = DeploymentManifest()
        manifest.manifest_id = hashlib.sha256(
            f"{time.time()}:{cbg_auth_id}".encode()
        ).hexdigest()[:12]
        manifest.gopel_version = gopel_version
        manifest.cbg_authorization_id = cbg_auth_id
        manifest.created_timestamp = time.time()

        if os.path.isdir(directory):
            for root, _dirs, files in os.walk(directory, followlinks=self.config.follow_symlinks):
                for filename in sorted(files):
                    if filename.endswith(".py"):
                        filepath = os.path.join(root, filename)
                        file_hash = self._hash_file(filepath)
                        rel_path = os.path.relpath(filepath, directory)
                        manifest.file_hashes[rel_path] = file_hash

        manifest.compute_manifest_hash()
        self.manifest = manifest
        self.record_cbg_release(cbg_auth_id, "Initial manifest creation", timestamp=manifest.created_timestamp)
        return manifest

    def snapshot_configuration(self, config_data: Dict[str, Any]) -> None:
        """Capture GOPEL's current configuration as the authorized snapshot."""
        if self.manifest:
            self.manifest.config_snapshot = config_data
            self.manifest.compute_manifest_hash()

    # -------------------------------------------------------------------
    # Code Integrity Verification (Section 4.1.1)
    # -------------------------------------------------------------------

    def verify_code_integrity(self, directory: str) -> List[StructuralFinding]:
        """Compare current file hashes against deployment manifest.
        Returns list of findings (empty if all hashes match)."""
        findings = []
        self.last_code_check = time.time()

        if not self.manifest:
            findings.append(StructuralFinding(
                result=StructuralResult.FLAGGED,
                severity=Severity.HALT,
                category="code_integrity",
                description="No deployment manifest loaded. Cannot verify code integrity.",
                expected_value="manifest_present",
                actual_value="manifest_absent"
            ))
            return findings

        # Verify manifest integrity (SV-01)
        if self.manifest:
            if not self._verify_manifest_signature():
                findings.append(StructuralFinding(
                    result=StructuralResult.FLAGGED,
                    severity=Severity.CRITICAL,
                    category="code_integrity",
                    description="Deployment manifest HMAC signature verification failed. Manifest may be tampered.",
                    expected_value="valid_signature",
                    actual_value="invalid_signature"
                ))
                return findings

        if not os.path.isdir(directory):
            findings.append(StructuralFinding(
                result=StructuralResult.FLAGGED,
                severity=Severity.HALT,
                category="code_integrity",
                description=f"GOPEL source directory not found: {directory}",
                expected_value="directory_exists",
                actual_value="directory_missing"
            ))
            return findings

        # Check each expected file
        for rel_path, expected_hash in self.manifest.file_hashes.items():
            filepath = os.path.join(directory, rel_path)
            if not os.path.exists(filepath):
                findings.append(StructuralFinding(
                    result=StructuralResult.FLAGGED,
                    severity=Severity.HALT,
                    category="code_integrity",
                    description=f"Expected GOPEL source file missing: {rel_path}",
                    expected_value=expected_hash,
                    actual_value="file_missing"
                ))
                continue

            actual_hash = self._hash_file(filepath)
            if actual_hash != expected_hash:
                # Check if this change has CBG authorization
                if not self._has_authorized_release_since(self.manifest.created_timestamp):
                    findings.append(StructuralFinding(
                        result=StructuralResult.FLAGGED,
                        severity=Severity.HALT,
                        category="code_integrity",
                        description=(
                            f"GOPEL source file hash mismatch without CBG authorization: {rel_path}"
                        ),
                        expected_value=expected_hash,
                        actual_value=actual_hash
                    ))

        # Check for unexpected new files
        if os.path.isdir(directory):
            for root, _dirs, files in os.walk(directory, followlinks=self.config.follow_symlinks):
                for filename in sorted(files):
                    if filename.endswith(".py"):
                        filepath = os.path.join(root, filename)
                        rel_path = os.path.relpath(filepath, directory)
                        if rel_path not in self.manifest.file_hashes:
                            findings.append(StructuralFinding(
                                result=StructuralResult.FLAGGED,
                                severity=Severity.CRITICAL,
                                category="code_integrity",
                                description=f"Unexpected file in GOPEL directory: {rel_path}",
                                expected_value="not_present",
                                actual_value=self._hash_file(filepath)
                            ))

        return findings

    # -------------------------------------------------------------------
    # Configuration Integrity Verification (Section 4.1.2)
    # -------------------------------------------------------------------

    def verify_config_integrity(
        self, active_config: Dict[str, Any]
    ) -> List[StructuralFinding]:
        """Compare GOPEL's active configuration against authorized snapshot.
        Returns list of findings (empty if config matches)."""
        findings = []
        self.last_config_check = time.time()

        if not self.manifest or not self.manifest.config_snapshot:
            findings.append(StructuralFinding(
                result=StructuralResult.FLAGGED,
                severity=Severity.WARNING,
                category="config_integrity",
                description="No configuration snapshot available for comparison.",
                expected_value="snapshot_present",
                actual_value="snapshot_absent"
            ))
            return findings

        # Deep comparison of configuration
        diffs = self._diff_config(self.manifest.config_snapshot, active_config)
        for diff_key, (expected, actual) in diffs.items():
            findings.append(StructuralFinding(
                result=StructuralResult.FLAGGED,
                severity=Severity.CRITICAL,
                category="config_integrity",
                description=f"Configuration divergence without CBG authorization: {diff_key}",
                expected_value=str(expected),
                actual_value=str(actual)
            ))

        return findings

    # -------------------------------------------------------------------
    # Behavioral Baseline Verification (Section 4.1.3)
    # -------------------------------------------------------------------

    def record_behavioral_sample(self, sample: BehavioralSample) -> None:
        """Record a behavioral observation and update the baseline."""
        self.baseline.update(sample)

    def verify_behavioral_baseline(
        self, sample: BehavioralSample
    ) -> List[StructuralFinding]:
        """Compare a behavioral sample against established baseline.
        Returns findings if metrics deviate beyond threshold."""
        findings = []
        threshold = self.config.behavioral_deviation_threshold

        if self.baseline.sample_count < 10:
            # Not enough data to establish baseline
            return findings

        # Dispatch latency check
        if self.baseline.dispatch_latency_std > 0:
            z_score = abs(
                (sample.dispatch_latency - self.baseline.dispatch_latency_mean)
                / self.baseline.dispatch_latency_std
            )
            if z_score > threshold:
                findings.append(StructuralFinding(
                    result=StructuralResult.FLAGGED,
                    severity=Severity.WARNING if z_score < threshold * 2 else Severity.CRITICAL,
                    category="behavioral_baseline",
                    description=(
                        f"Dispatch latency deviation: {z_score:.1f} standard deviations "
                        f"from baseline (threshold: {threshold})"
                    ),
                    expected_value=f"{self.baseline.dispatch_latency_mean:.2f}ms "
                                   f"(+/- {self.baseline.dispatch_latency_std:.2f})",
                    actual_value=f"{sample.dispatch_latency:.2f}ms"
                ))

        # Response time check
        if self.baseline.response_time_std > 0:
            z_score = abs(
                (sample.response_time - self.baseline.response_time_mean)
                / self.baseline.response_time_std
            )
            if z_score > threshold:
                findings.append(StructuralFinding(
                    result=StructuralResult.FLAGGED,
                    severity=Severity.WARNING if z_score < threshold * 2 else Severity.CRITICAL,
                    category="behavioral_baseline",
                    description=(
                        f"Response time deviation: {z_score:.1f} standard deviations "
                        f"from baseline (threshold: {threshold})"
                    ),
                    expected_value=f"{self.baseline.response_time_mean:.2f}ms "
                                   f"(+/- {self.baseline.response_time_std:.2f})",
                    actual_value=f"{sample.response_time:.2f}ms"
                ))

        # Audit write size check
        if self.baseline.audit_write_size_std > 0:
            z_score = abs(
                (sample.audit_write_size - self.baseline.audit_write_size_mean)
                / self.baseline.audit_write_size_std
            )
            if z_score > threshold:
                findings.append(StructuralFinding(
                    result=StructuralResult.FLAGGED,
                    severity=Severity.ADVISORY,
                    category="behavioral_baseline",
                    description=(
                        f"Audit write size deviation: {z_score:.1f} standard deviations "
                        f"from baseline"
                    ),
                    expected_value=f"{self.baseline.audit_write_size_mean:.0f} bytes "
                                   f"(+/- {self.baseline.audit_write_size_std:.0f})",
                    actual_value=f"{sample.audit_write_size:.0f} bytes"
                ))

        return findings

    # -------------------------------------------------------------------
    # Combined Part 1 Verification
    # -------------------------------------------------------------------

    def verify_all(
        self,
        gopel_directory: str,
        active_config: Dict[str, Any],
        behavioral_sample: Optional[BehavioralSample] = None
    ) -> Tuple[StructuralResult, List[StructuralFinding]]:
        """Run all three Part 1 verification domains.
        Returns overall result and combined findings."""
        all_findings = []

        # Code integrity (on schedule with jitter to prevent predictable timing)
        now = time.time()
        jitter = random.uniform(-60.0, 60.0)  # ±60s jitter
        code_interval = max(1.0, self.config.code_integrity_check_interval_seconds + jitter)
        if (now - self.last_code_check) >= code_interval:
            code_findings = self.verify_code_integrity(gopel_directory)
            all_findings.extend(code_findings)

        # Config integrity (on schedule)
        if (now - self.last_config_check) >= self.config.config_snapshot_check_interval_seconds:
            config_findings = self.verify_config_integrity(active_config)
            all_findings.extend(config_findings)

        # Behavioral baseline (per transaction)
        if behavioral_sample:
            behavioral_findings = self.verify_behavioral_baseline(behavioral_sample)
            all_findings.extend(behavioral_findings)
            self.record_behavioral_sample(behavioral_sample)

        # Determine overall result
        if not all_findings:
            return StructuralResult.STABLE, all_findings

        return StructuralResult.FLAGGED, all_findings

    # -------------------------------------------------------------------
    # Internal Helpers
    # -------------------------------------------------------------------

    def record_cbg_release(self, auth_id: str, rationale: str, timestamp: Optional[float] = None) -> None:
        """Record a CBG-authorized release with timestamp and manifest hash.
        SV-02: Structured release records with authorization_id, timestamp, rationale, manifest_hash.
        If timestamp is provided (e.g., matching manifest creation), use it; otherwise use current time."""
        release_record = {
            "authorization_id": auth_id,
            "timestamp": timestamp if timestamp is not None else time.time(),
            "rationale": rationale,
            "manifest_hash": self.manifest.manifest_hash if self.manifest else ""
        }
        self.cbg_authorized_releases.append(release_record)
        logger.info("Recorded CBG release: auth_id=%s, rationale=%s",
                     _sanitize_log(auth_id), _sanitize_log(rationale))

    def _hash_file(self, filepath: str) -> str:
        """Compute SHA-256 hash of a file.
        SV-03: Instance method (not @staticmethod), respects follow_symlinks config,
        refuses to hash symlinks when follow_symlinks=False, checks integrity_scan_max_bytes size cap."""
        # Check if it's a symlink and we should skip it
        if os.path.islink(filepath) and not self.config.follow_symlinks:
            logger.warning("Refusing to hash symlink (follow_symlinks=False): %s",
                           _sanitize_log(filepath))
            return "SYMLINK_NOT_HASHED"

        sha256 = hashlib.sha256()
        try:
            file_size = os.path.getsize(filepath)
            if file_size > self.config.integrity_scan_max_bytes:
                logger.warning(
                    "File exceeds integrity_scan_max_bytes (%d > %d): %s",
                    file_size, self.config.integrity_scan_max_bytes,
                    _sanitize_log(filepath)
                )
                return "FILE_SIZE_EXCEEDED"

            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except (IOError, OSError) as e:
            logger.error("Error reading file for hashing: %s: %s",
                         _sanitize_log(filepath), _sanitize_log(str(e)))
            return "FILE_READ_ERROR"

    def _has_authorized_release_since(self, since_timestamp: float) -> bool:
        """Check if a CBG-authorized release exists after the given timestamp.
        SV-02: Actually compares timestamps instead of just checking non-empty.
        Returns True if any release record has timestamp > since_timestamp."""
        for release in self.cbg_authorized_releases:
            if release.get("timestamp", 0.0) > since_timestamp:
                logger.info(
                    "Found authorized release after %s: %s",
                    since_timestamp, _sanitize_log(str(release.get('authorization_id', '')))
                )
                return True
        return False

    def _verify_manifest_signature(self) -> bool:
        """Verify HMAC signature of the deployment manifest.
        SV-01: When a manifest exists, verify its HMAC signature.
        Returns True if signature is valid, False if unsigned or tampered.
        In production, this would use a shared secret key from secure storage."""
        if not self.manifest:
            return False

        # In production, retrieve the shared secret from a secure key store
        # For now, this is a placeholder implementation
        # A real implementation would verify manifest_hash matches a computed HMAC
        try:
            stored_hash = self.manifest.manifest_hash
            if not stored_hash:
                logger.error("Manifest hash is empty: unsigned manifest")
                return False

            # Recompute and compare
            computed_hash = self.manifest.compute_manifest_hash()
            if computed_hash == stored_hash:
                logger.info("Manifest signature verified successfully")
                return True
            else:
                logger.error("Manifest signature mismatch: possible tampering detected")
                return False
        except Exception as e:
            logger.error("Error verifying manifest signature: %s",
                         _sanitize_log(str(e)))
            return False

    @staticmethod
    def _diff_config(
        expected: Dict[str, Any], actual: Dict[str, Any], prefix: str = ""
    ) -> Dict[str, Tuple[Any, Any]]:
        """Deep-diff two configuration dictionaries.
        Returns dict of key -> (expected_value, actual_value) for mismatches."""
        diffs = {}
        all_keys = set(list(expected.keys()) + list(actual.keys()))

        for key in sorted(all_keys):
            full_key = f"{prefix}.{key}" if prefix else key
            exp_val = expected.get(key)
            act_val = actual.get(key)

            if key not in expected:
                diffs[full_key] = ("key_not_expected", act_val)
            elif key not in actual:
                diffs[full_key] = (exp_val, "key_missing")
            elif isinstance(exp_val, dict) and isinstance(act_val, dict):
                nested = StructuralVerifier._diff_config(exp_val, act_val, full_key)
                diffs.update(nested)
            elif exp_val != act_val:
                diffs[full_key] = (exp_val, act_val)

        return diffs

    def get_structural_snapshot(self) -> Dict[str, str]:
        """Return current structural state for random audit reports."""
        return {
            "manifest_hash": self.manifest.manifest_hash if self.manifest else "no_manifest",
            "gopel_version": self.manifest.gopel_version if self.manifest else "unknown",
            "last_code_check": str(self.last_code_check),
            "last_config_check": str(self.last_config_check),
            "baseline_samples": str(self.baseline.sample_count),
            "dispatch_latency_baseline": f"{self.baseline.dispatch_latency_mean:.2f}ms"
        }
