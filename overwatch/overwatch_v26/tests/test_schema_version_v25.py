"""
HAIA-Overwatch v2.5 - Tests: declared GOPEL version and schema refusal

Plan step 14f. The tests declare the GOPEL version and audit schema they
expect; the observer is configured with that expectation and refuses
records whose schema or version does not match it, with an alert, never
a silent pass.

GOPEL's audit file carries schema.schema_version ("1.0.0" in v0.6.2 and
v0.6.3) and no GOPEL version string. The GOPEL version is therefore
declared alongside the document: by the fixture's provenance block in
these tests, or by the signed deployment manifest's gopel_version in a
deployment. No header field that GOPEL does not write is assumed.

Author: Basil C. Puglisi, MPA
License: CC BY-NC 4.0
Repository: github.com/basilpuglisi/HAIA
Attribution: #AIassisted under HAIA-RECCLIN & Checkpoint-Based Governance
"""

import pytest

from overwatch_v26.gopel_observer import GopelObserver
from overwatch_v26.models import OverwatchConfig
from overwatch_v26.tests import gopel_fixture_support_v25 as support
from overwatch_v26.tests.gopel_fixture_support_v25 import (
    RecordingPipeline,
    alerts,
    audit_document,
    channel_with_sink,
    declared_gopel_version,
    expected_finalized,
    fixture_records,
    load_fixture,
    require,
)

try:
    from overwatch_v26.gopel_observer import GopelSchemaExpectation
except ImportError:  # absent before step 14f
    GopelSchemaExpectation = None

try:
    from overwatch_v26.models import StructuralInputs
except ImportError:  # absent before step 21
    StructuralInputs = None

# ---------------------------------------------------------------------------
# Declaration (step 14f): the GOPEL release and audit schema these tests
# are written against.
# ---------------------------------------------------------------------------
EXPECTED_GOPEL_VERSION = "0.6.4"
EXPECTED_AUDIT_SCHEMA_VERSION = "1.0.0"


def _expectation(gopel_version=EXPECTED_GOPEL_VERSION,
                 audit_schema_version=EXPECTED_AUDIT_SCHEMA_VERSION):
    cls = require(GopelSchemaExpectation, "GopelSchemaExpectation (step 14f)")
    return cls(gopel_version=gopel_version, audit_schema_version=audit_schema_version)


def _observer(expectation=None, structural_inputs=None):
    cm, messages = channel_with_sink()
    pipeline = RecordingPipeline()
    kwargs = {}
    if expectation is not None:
        kwargs["schema_expectation"] = expectation
    if structural_inputs is not None:
        kwargs["structural_inputs"] = structural_inputs
    observer = GopelObserver(pipeline, channel_manager=cm,
                             config=OverwatchConfig(require_structural_inputs=False),
                             **kwargs)
    return observer, pipeline, messages


class TestDeclaration:

    def test_the_tests_declare_one_expected_gopel_version(self):
        assert EXPECTED_GOPEL_VERSION == support.EXPECTED_GOPEL_VERSION
        assert EXPECTED_AUDIT_SCHEMA_VERSION == support.EXPECTED_AUDIT_SCHEMA_VERSION

    def test_the_fixture_provenance_declares_the_expected_version(self):
        fixture = load_fixture()
        assert fixture["provenance"]["gopel_version"] == EXPECTED_GOPEL_VERSION
        assert fixture["schema"]["schema_version"] == EXPECTED_AUDIT_SCHEMA_VERSION

    def test_the_audit_header_carries_no_gopel_version(self):
        """The version cannot come from the header: GOPEL does not write one."""
        assert "gopel_version" not in load_fixture()["schema"]

    def test_the_observer_default_expectation_matches_the_declaration(self):
        observer, _p, _m = _observer()
        expectation = observer.get_schema_expectation()
        assert expectation.gopel_version == EXPECTED_GOPEL_VERSION
        assert expectation.audit_schema_version == EXPECTED_AUDIT_SCHEMA_VERSION


class TestMatchingIsAccepted:

    def test_declared_expectation_accepts_the_fixture(self):
        observer, pipeline, messages = _observer(_expectation())
        observer.observe_audit_document(audit_document(),
                                        source_gopel_version=declared_gopel_version())
        assert alerts(messages) == []
        assert [m.kind for m in messages if m.kind == "GOPEL_VERSION_UNDECLARED"] == []
        assert observer.get_statistics()["records_parsed"] == len(fixture_records())
        assert len(pipeline.calls) == len(expected_finalized(fixture_records()))

    def test_a_signed_manifest_can_declare_the_version(self):
        inputs_cls = require(StructuralInputs, "StructuralInputs (step 21)")
        inputs = inputs_cls(gopel_directory="", deployment_manifest={"gopel_version": "0.6.4"})
        observer, _pipeline, messages = _observer(_expectation(), structural_inputs=inputs)
        observer.observe_audit_document(audit_document())
        assert alerts(messages) == []
        assert observer.get_statistics()["records_parsed"] == len(fixture_records())

    def test_an_undeclared_version_is_read_with_one_advisory_alert(self):
        observer, _pipeline, messages = _observer(_expectation())
        observer.observe_audit_document(audit_document())
        observer.observe_audit_document(audit_document())
        assert alerts(messages) == []
        undeclared = [m for m in messages if m.kind == "GOPEL_VERSION_UNDECLARED"]
        assert len(undeclared) == 1
        assert undeclared[0].payload["expected_gopel_version"] == EXPECTED_GOPEL_VERSION


class TestMismatchIsRefusedWithAlerts:

    def _assert_refused(self, observer, pipeline, messages, reason, n):
        found = alerts(messages)
        assert len(found) == n, "one VALIDATION_ERROR per refused record"
        assert {m.payload["reason"] for m in found} == {reason}
        stats = observer.get_statistics()
        assert stats["records_parsed"] == 0
        assert stats["schema_refusals"] == n
        assert stats["validation_errors"] == n
        assert pipeline.calls == []

    def test_mismatched_audit_schema_version_is_refused(self):
        doc = audit_document()
        doc["schema"]["schema_version"] = "2.0.0"
        observer, pipeline, messages = _observer(_expectation())
        observer.observe_audit_document(doc, source_gopel_version=declared_gopel_version())
        self._assert_refused(observer, pipeline, messages,
                             "schema_version_mismatch", len(doc["records"]))

    def test_missing_schema_header_is_refused(self):
        doc = audit_document()
        del doc["schema"]
        observer, pipeline, messages = _observer(_expectation())
        observer.observe_audit_document(doc, source_gopel_version=declared_gopel_version())
        self._assert_refused(observer, pipeline, messages,
                             "schema_missing", len(doc["records"]))

    def test_a_declared_older_gopel_release_is_refused(self):
        observer, pipeline, messages = _observer(_expectation())
        observer.observe_audit_document(audit_document(), source_gopel_version="0.6.2")
        self._assert_refused(observer, pipeline, messages,
                             "gopel_version_mismatch", len(fixture_records()))

    def test_an_observer_expecting_another_schema_refuses_the_fixture(self):
        observer, pipeline, messages = _observer(_expectation(audit_schema_version="1.1.0"))
        observer.observe_audit_document(audit_document(),
                                        source_gopel_version=declared_gopel_version())
        self._assert_refused(observer, pipeline, messages,
                             "schema_version_mismatch", len(fixture_records()))

    def test_an_observer_expecting_another_gopel_release_refuses_the_fixture(self):
        observer, pipeline, messages = _observer(_expectation(gopel_version="0.7.0"))
        observer.observe_audit_document(audit_document(),
                                        source_gopel_version=declared_gopel_version())
        self._assert_refused(observer, pipeline, messages,
                             "gopel_version_mismatch", len(fixture_records()))

    def test_a_manifest_declaring_another_release_is_refused(self):
        inputs_cls = require(StructuralInputs, "StructuralInputs (step 21)")
        inputs = inputs_cls(gopel_directory="", deployment_manifest={"gopel_version": "0.6.2"})
        observer, pipeline, messages = _observer(_expectation(), structural_inputs=inputs)
        observer.observe_audit_document(audit_document())
        self._assert_refused(observer, pipeline, messages,
                             "gopel_version_mismatch", len(fixture_records()))
