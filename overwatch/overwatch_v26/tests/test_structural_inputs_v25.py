"""
HAIA-Overwatch v2.5 - Tests: structural inputs and the keyed manifest

Plan step 21, addendum item 3, settlement S1. Paper section 5.2: the
Structural Verifier "computes SHA-256 hashes of every source file and
compares them against signed deployment manifests".

Defects in v2.4:
- the observer passed no structural inputs into inspect(), so default
  settings escalated every GOPEL transaction as
  STRUCTURAL_VERIFICATION_NOT_PERFORMED (pipeline.py:153-164, :418-426);
- the manifest "signature" was an unkeyed SHA-256 that anyone can
  recompute, and the verifier logged "Manifest signature verified
  successfully" for it (structural_verifier.py:494-497, models.py:809-821).

Uses temporary directories with fake GOPEL files, as the carried
structural tests do. Nothing here imports GOPEL.

Author: Basil C. Puglisi, MPA
License: CC BY-NC 4.0
Repository: github.com/basilpuglisi/HAIA
Attribution: #AIassisted under HAIA-RECCLIN & Checkpoint-Based Governance
"""

import ast
import hashlib
import logging
import os
import sys
from pathlib import Path

import pytest

import overwatch_v26
from overwatch_v26.gopel_observer import GopelObserver
from overwatch_v26.models import DeploymentManifest, OverwatchConfig, Severity, StructuralResult
from overwatch_v26.pipeline import OverwatchPipeline
from overwatch_v26.structural_verifier import StructuralVerifier
from overwatch_v26.tests.gopel_fixture_support_v25 import (
    RecordingPipeline,
    alerts,
    audit_document,
    channel_with_sink,
    fixture_records,
    require,
    transaction_ids,
)

try:
    from overwatch_v26.models import StructuralInputs
except ImportError:  # absent before step 21
    StructuralInputs = None

PACKAGE_DIR = Path(overwatch_v26.__file__).resolve().parent
MANIFEST_KEY = b"overwatch-manifest-scoped-key-0001-x"
OTHER_KEY = b"some-other-key-that-is-not-the-mf-01"
NOT_PERFORMED = "STRUCTURAL_VERIFICATION_NOT_PERFORMED"
GOPEL_CONFIG = {"max_tokens": 4096, "platforms": ["mock_alpha", "mock_beta", "mock_gamma"],
                "require_authentication": True}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fake_gopel(tmp_path):
    gopel_dir = tmp_path / "gopel_v063"
    (gopel_dir / "adapters").mkdir(parents=True)
    for name in ("pipeline.py", "secure_pipeline.py", "logger.py", "overwatch_stop.py",
                 "adapters/mock_adapter.py"):
        (gopel_dir / name).write_text(f"# fake GOPEL module {name}\nVALUE = 1\n", encoding="utf-8")
    return gopel_dir


def _signed_manifest(gopel_dir, key=MANIFEST_KEY):
    """The deployment authority's act: hash every file and sign with the
    manifest-scoped key."""
    authority = StructuralVerifier(OverwatchConfig())
    require(getattr(authority, "set_manifest_key", None), "StructuralVerifier.set_manifest_key (step 21)")
    authority.set_manifest_key(key)
    manifest = authority.create_manifest_from_directory(str(gopel_dir), "0.6.4", "CBG-AUTH-GATE1")
    authority.snapshot_configuration(dict(GOPEL_CONFIG))
    return manifest.to_dict()


def _pipeline(manifest_key=MANIFEST_KEY):
    pipeline = OverwatchPipeline(OverwatchConfig())          # default settings
    if manifest_key is not None:
        require(getattr(pipeline, "set_manifest_key", None), "OverwatchPipeline.set_manifest_key (step 21)")
        pipeline.set_manifest_key(manifest_key)
    return pipeline


def _observer(pipeline, gopel_dir, manifest, config=GOPEL_CONFIG):
    inputs_cls = require(StructuralInputs, "StructuralInputs (step 21)")
    cm, messages = channel_with_sink()
    observer = GopelObserver(
        pipeline, channel_manager=cm,
        structural_inputs=inputs_cls(
            gopel_directory=str(gopel_dir),
            deployment_manifest=manifest,
            active_gopel_config=dict(config) if config is not None else None,
        ),
    )
    return observer, messages


def _first_outcome(observer):
    outcomes = observer.observe_audit_document(audit_document())
    assert outcomes, "the fixture must finalize at least one transaction"
    return outcomes[0]


def _descriptions(outcome):
    return [f.description for f in outcome.structural_findings]


# ===========================================================================
# Clean path
# ===========================================================================

class TestCleanPath:

    def test_clean_transaction_with_a_valid_signed_manifest_does_not_escalate(self, tmp_path):
        gopel_dir = _fake_gopel(tmp_path)
        manifest = _signed_manifest(gopel_dir)
        pipeline = _pipeline()
        observer, messages = _observer(pipeline, gopel_dir, manifest)
        outcome = _first_outcome(observer)
        assert alerts(messages) == []
        assert NOT_PERFORMED not in _descriptions(outcome)
        assert outcome.structural_result == StructuralResult.STABLE
        assert outcome.structural_findings == []
        assert outcome.escalated is False

    def test_default_settings_without_inputs_still_flag_not_performed(self):
        """Carried behavior stays: verify_transaction with no inputs is flagged."""
        pipeline = OverwatchPipeline(OverwatchConfig())
        cm, _messages = channel_with_sink()
        observer = GopelObserver(pipeline, channel_manager=cm)
        outcome = observer.observe_audit_document(audit_document())[0]
        assert NOT_PERFORMED in _descriptions(outcome)
        assert outcome.escalated is True

    def test_observer_passes_the_structural_inputs_into_inspect(self, tmp_path):
        inputs_cls = require(StructuralInputs, "StructuralInputs (step 21)")
        recorder = RecordingPipeline()
        manifest = {"manifest_id": "m1"}
        observer = GopelObserver(
            recorder, config=OverwatchConfig(require_structural_inputs=False),
            structural_inputs=inputs_cls(gopel_directory=str(tmp_path), deployment_manifest=manifest,
                                         active_gopel_config={"a": 1}),
        )
        observer.observe_audit_document(audit_document())
        assert recorder.calls
        for _txn, kwargs in recorder.calls:
            assert kwargs["gopel_directory"] == str(tmp_path)
            assert kwargs["deployment_manifest"] == manifest
            assert kwargs["active_gopel_config"] == {"a": 1}


# ===========================================================================
# Keyed manifest signature (S1)
# ===========================================================================

class TestKeyedManifest:

    def test_a_manifest_rehashed_without_the_key_is_refused(self, tmp_path):
        gopel_dir = _fake_gopel(tmp_path)
        manifest = _signed_manifest(gopel_dir)
        # Attacker replaces a GOPEL file, then rewrites the manifest to match
        # and recomputes the unkeyed content hash. No manifest key.
        backdoor = b"# fake GOPEL module pipeline.py\nVALUE = 1\nimport os  # backdoor\n"
        (gopel_dir / "pipeline.py").write_bytes(backdoor)
        manifest["file_hashes"]["pipeline.py"] = hashlib.sha256(backdoor).hexdigest()
        forged = DeploymentManifest.from_dict(manifest)
        forged.compute_manifest_hash()
        forged_dict = forged.to_dict()

        pipeline = _pipeline()
        observer, _messages = _observer(pipeline, gopel_dir, forged_dict)
        outcome = _first_outcome(observer)
        assert outcome.escalated is True
        refused = [f for f in outcome.structural_findings
                   if "signature verification failed" in f.description]
        assert refused and refused[0].severity == Severity.CRITICAL
        assert pipeline.structural_verifier._verify_manifest_signature() is False

    @pytest.mark.parametrize("signature", ["", "0" * 64, "sign-with-other-key"])
    def test_unsigned_or_wrongly_signed_manifest_is_refused(self, tmp_path, signature):
        gopel_dir = _fake_gopel(tmp_path)
        manifest = _signed_manifest(gopel_dir)
        if signature == "sign-with-other-key":
            m = DeploymentManifest.from_dict(manifest)
            m.sign(OTHER_KEY)
            manifest = m.to_dict()
        else:
            manifest["signature"] = signature
        pipeline = _pipeline()
        observer, _messages = _observer(pipeline, gopel_dir, manifest)
        outcome = _first_outcome(observer)
        assert outcome.escalated is True
        assert any("signature verification failed" in d for d in _descriptions(outcome))

    def test_the_manifest_key_is_scoped_to_manifests(self, tmp_path):
        gopel_dir = _fake_gopel(tmp_path)
        manifest = _signed_manifest(gopel_dir, key=MANIFEST_KEY)
        pipeline = _pipeline(manifest_key=OTHER_KEY)
        observer, _messages = _observer(pipeline, gopel_dir, manifest)
        outcome = _first_outcome(observer)
        assert any("signature verification failed" in d for d in _descriptions(outcome))

    def test_keyed_verification_logs_a_verified_keyed_signature(self, tmp_path, caplog):
        gopel_dir = _fake_gopel(tmp_path)
        verifier = StructuralVerifier(OverwatchConfig())
        require(getattr(verifier, "set_manifest_key", None), "StructuralVerifier.set_manifest_key (step 21)")
        verifier.set_manifest_key(MANIFEST_KEY)
        verifier.create_manifest_from_directory(str(gopel_dir), "0.6.4", "CBG-AUTH-LOG")
        with caplog.at_level(logging.DEBUG):
            assert verifier._verify_manifest_signature() is True
        text = " ".join(r.getMessage() for r in caplog.records).lower()
        assert "keyed signature verified" in text

    def test_without_a_manifest_key_no_signature_is_claimed(self, tmp_path, caplog):
        """S1: with no manifest key, log the content-hash match as unsigned and
        keep the carried outcome (no new finding)."""
        gopel_dir = _fake_gopel(tmp_path)
        # v2.6: an unsigned manifest is accepted only in the named local test setting.
        verifier = StructuralVerifier(OverwatchConfig(local_test_unsigned_manifests=True))
        verifier.create_manifest_from_directory(str(gopel_dir), "0.6.4", "CBG-AUTH-UNSIGNED")
        with caplog.at_level(logging.DEBUG):
            assert verifier._verify_manifest_signature() is True
            findings = verifier.verify_code_integrity(str(gopel_dir))
        assert findings == []
        messages = [r.getMessage().lower() for r in caplog.records]
        assert any("unsigned" in m for m in messages)
        assert not any("signature verified" in m for m in messages)

    def test_content_hash_check_does_not_rewrite_the_stored_hash(self):
        manifest = DeploymentManifest(gopel_version="0.6.4", cbg_authorization_id="a")
        original = manifest.compute_manifest_hash()
        verifier = StructuralVerifier(OverwatchConfig())
        verifier.manifest = manifest
        manifest.file_hashes["x.py"] = "tampered"
        assert verifier._verify_manifest_signature() is False
        assert manifest.manifest_hash == original
        assert verifier._verify_manifest_signature() is False, "tampering stays detected"


# ===========================================================================
# Changed GOPEL file
# ===========================================================================

class TestChangedGopelFile:

    def test_a_changed_gopel_file_is_flagged(self, tmp_path):
        gopel_dir = _fake_gopel(tmp_path)
        manifest = _signed_manifest(gopel_dir)
        (gopel_dir / "logger.py").write_text("# changed after the signed release\n", encoding="utf-8")
        pipeline = _pipeline()
        observer, _messages = _observer(pipeline, gopel_dir, manifest)
        outcome = _first_outcome(observer)
        assert outcome.escalated is True
        assert outcome.overall_severity == Severity.HALT
        mismatch = [f for f in outcome.structural_findings
                    if f.category == "code_integrity" and "logger.py" in f.description]
        assert mismatch and mismatch[0].severity == Severity.HALT

    def test_an_added_gopel_file_is_flagged(self, tmp_path):
        gopel_dir = _fake_gopel(tmp_path)
        manifest = _signed_manifest(gopel_dir)
        (gopel_dir / "injected.py").write_text("print('x')\n", encoding="utf-8")
        pipeline = _pipeline()
        observer, _messages = _observer(pipeline, gopel_dir, manifest)
        outcome = _first_outcome(observer)
        assert outcome.escalated is True
        assert any("Unexpected file" in d for d in _descriptions(outcome))


# ===========================================================================
# The Structural Verifier stays read-only, with no imports of GOPEL
# ===========================================================================

class TestReadOnly:

    def test_structural_verifier_imports_only_stdlib_and_overwatch(self):
        tree = ast.parse((PACKAGE_DIR / "structural_verifier.py").read_text(encoding="utf-8"))
        stdlib = set(getattr(sys, "stdlib_module_names", ()))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name.split(".")[0] in stdlib, alias.name
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                assert node.module.split(".")[0] in stdlib, node.module

    def test_verification_leaves_the_gopel_directory_unchanged(self, tmp_path):
        gopel_dir = _fake_gopel(tmp_path)
        manifest = _signed_manifest(gopel_dir)
        before = {str(p): (p.read_bytes(), p.stat().st_mtime_ns) for p in gopel_dir.rglob("*")
                  if p.is_file()}
        pipeline = _pipeline()
        observer, _messages = _observer(pipeline, gopel_dir, manifest)
        observer.observe_audit_document(audit_document())
        after = {str(p): (p.read_bytes(), p.stat().st_mtime_ns) for p in gopel_dir.rglob("*")
                 if p.is_file()}
        assert after == before
