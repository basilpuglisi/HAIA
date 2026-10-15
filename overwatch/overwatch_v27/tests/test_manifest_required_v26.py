"""
HAIA-Overwatch v2.6 - Tests: a signed deployment manifest is required

Basil's ruling X3, October 14, 2026 (HAIA_Update_Plan_v4), carried into
v2.6 by the Tier 0 ruling that pushed files are never rewritten. Overwatch
v2.4, Section 5.2, names "signed deployment manifests"; an unkeyed hash
falls short of that text (S1).

- By default a manifest that does not verify with the manifest-scoped key
  is refused, and with no key configured every manifest is refused. The
  refusal is the CRITICAL structural finding, which escalates and stops
  the pipe.
- A named local test setting (local_test_unsigned_manifests) may accept an
  unsigned manifest by its content hash. It says so at start, reports it
  in health, and marks every outcome it produces as unsigned. A changed
  GOPEL file is still flagged.

Uses temporary directories with fake GOPEL files. Nothing here imports GOPEL.

Author: Basil C. Puglisi, MPA
License: CC BY-NC 4.0
Repository: github.com/basilpuglisi/HAIA
Attribution: #AIassisted under HAIA-RECCLIN & Checkpoint-Based Governance
"""

import logging

from overwatch_v27.gopel_observer import GopelObserver
from overwatch_v27.models import DeploymentManifest, OverwatchConfig, Severity, StructuralInputs
from overwatch_v27.pipeline import OverwatchPipeline
from overwatch_v27.structural_verifier import StructuralVerifier
from overwatch_v27.tests.gopel_fixture_support_v25 import audit_document, channel_with_sink

MANIFEST_KEY = b"overwatch-manifest-scoped-key-v26-0001"
OTHER_KEY = b"some-other-key-that-is-not-the-mf-v26"
REFUSED = "signature verification failed"
UNSIGNED = "unsigned (local test setting)"


def _fake_gopel(tmp_path):
    gopel_dir = tmp_path / "gopel_v064"
    (gopel_dir / "adapters").mkdir(parents=True)
    for name in ("pipeline.py", "channel.py", "logger.py", "overwatch_stop.py", "adapters/mock_adapter.py"):
        (gopel_dir / name).write_text(f"# fake GOPEL module {name}\nVALUE = 1\n", encoding="utf-8")
    return gopel_dir


def _manifest(gopel_dir, key=None):
    authority = StructuralVerifier(OverwatchConfig())
    if key is not None:
        authority.set_manifest_key(key)
    return authority.create_manifest_from_directory(str(gopel_dir), "0.6.5", "CBG-AUTH-V26").to_dict()


def _outcomes(pipeline, gopel_dir, manifest):
    cm, _messages = channel_with_sink()
    observer = GopelObserver(pipeline, channel_manager=cm, structural_inputs=StructuralInputs(
        gopel_directory=str(gopel_dir), deployment_manifest=manifest, active_gopel_config=None))
    return observer.observe_audit_document(audit_document())


def _refusals(outcome):
    return [f for f in outcome.structural_findings if REFUSED in f.description]


def test_default_settings_refuse_an_unsigned_manifest_when_no_key_is_configured(tmp_path):
    gopel_dir = _fake_gopel(tmp_path)
    pipeline = OverwatchPipeline(OverwatchConfig())
    outcome = _outcomes(pipeline, gopel_dir, _manifest(gopel_dir))[0]
    assert outcome.escalated is True
    assert _refusals(outcome) and _refusals(outcome)[0].severity == Severity.CRITICAL
    assert outcome.to_dict()["manifest_status"] == "refused"


def test_default_settings_refuse_unsigned_or_wrongly_signed_manifests_with_a_key(tmp_path):
    gopel_dir = _fake_gopel(tmp_path)
    for manifest in (_manifest(gopel_dir), _manifest(gopel_dir, key=OTHER_KEY)):
        pipeline = OverwatchPipeline(OverwatchConfig())
        pipeline.set_manifest_key(MANIFEST_KEY)
        outcome = _outcomes(pipeline, gopel_dir, manifest)[0]
        assert outcome.escalated is True and _refusals(outcome)
        assert outcome.to_dict()["manifest_status"] == "refused"


def test_the_local_test_setting_says_so_at_start_and_marks_every_outcome(tmp_path, caplog):
    gopel_dir = _fake_gopel(tmp_path)
    with caplog.at_level(logging.WARNING):
        pipeline = OverwatchPipeline(OverwatchConfig(local_test_unsigned_manifests=True))
    assert any("LOCAL TEST SETTING" in r.getMessage() for r in caplog.records)
    assert pipeline.get_health()["manifest_mode"] == "local test: unsigned manifests accepted"
    outcomes = _outcomes(pipeline, gopel_dir, _manifest(gopel_dir))
    assert outcomes
    for outcome in outcomes:
        assert not _refusals(outcome)
        assert outcome.to_dict()["manifest_status"] == UNSIGNED
        assert outcome.manifest_status == UNSIGNED


def test_the_local_test_setting_still_flags_a_changed_gopel_file(tmp_path):
    gopel_dir = _fake_gopel(tmp_path)
    manifest = _manifest(gopel_dir)
    (gopel_dir / "channel.py").write_text("# changed after the manifest\nVALUE = 2\n", encoding="utf-8")
    pipeline = OverwatchPipeline(OverwatchConfig(local_test_unsigned_manifests=True))
    outcome = _outcomes(pipeline, gopel_dir, manifest)[0]
    assert any(f.category == "code_integrity" and "channel.py" in f.description
               for f in outcome.structural_findings)
    assert outcome.escalated is True


def test_a_valid_signed_manifest_with_default_settings_does_not_escalate(tmp_path):
    gopel_dir = _fake_gopel(tmp_path)
    pipeline = OverwatchPipeline(OverwatchConfig())
    pipeline.set_manifest_key(MANIFEST_KEY)
    outcome = _outcomes(pipeline, gopel_dir, _manifest(gopel_dir, key=MANIFEST_KEY))[0]
    assert not _refusals(outcome)
    assert outcome.escalated is False
    assert outcome.to_dict()["manifest_status"] == "signed"


def test_default_health_reports_a_signed_manifest_required():
    pipeline = OverwatchPipeline(OverwatchConfig())
    assert pipeline.get_health()["manifest_mode"] == "signed manifest required"


def test_a_manifest_object_keeps_its_signature_through_to_dict(tmp_path):
    gopel_dir = _fake_gopel(tmp_path)
    data = _manifest(gopel_dir, key=MANIFEST_KEY)
    assert data["signature"]
    assert DeploymentManifest.from_dict(data).signature == data["signature"]
