# HAIA-Overwatch v2.6: carried checks that changed

Every test of Overwatch v2.5 (`overwatch/overwatch_v25/tests/`, unchanged) is carried into `overwatch/overwatch_v26/tests/` under the same file name. Three kinds of change were made; no other line differs. The v2.5 fixture `gopel_v063_mock_audit_v1.json` is replaced in v2.6 by `gopel_v064_mock_audit_v1.json` (GOPEL v0.6.4, generator v2).

## 1. Import path only

Every `overwatch_v25` import and module path became `overwatch_v26`, in all 28 carried files. No expectation changed with it.

## 2. Version labels (same expectation, the version moved)

| File | Check or line | v2.5 | v2.6 |
|---|---|---|---|
| `test_version_wording_v25.py` | `test_version_strings_agree_at_2_6_0` (was `..._2_5_0`) | `"2.5.0"` | `"2.6.0"` |
| `test_version_wording_v25.py` | `test_module_header_reads_v2_6` (was `..._v2_5`) | header matches `v2.5` | header matches `v2.6` |
| `test_calibration_v24.py` | `TestCalibrationExport.test_version_bumped` | `"2.5.0"` | `"2.6.0"` |
| `test_overwatch.py` | `TestPipelineIntegration.test_PI3_status_tracking` | `"2.5.0"` | `"2.6.0"` |
| `gopel_fixture_support_v25.py` | `EXPECTED_GOPEL_VERSION`, `FIXTURE_NAME` | `"0.6.3"`, the v0.6.3 fixture | `"0.6.4"`, the v0.6.4 fixture |
| `gopel_fixture_support_v25.py` | `FINALIZING_SYSTEM_EVENTS` (the test-side spec) | three stop and halt events | the same three plus `channel_group_closed` |
| `test_gopel_records_v25.py` | the module-level version assertion | `"0.6.3"` | `"0.6.4"` |
| `test_schema_version_v25.py` | `EXPECTED_GOPEL_VERSION`; the manifest's declared version in one check | `"0.6.3"` | `"0.6.4"` |
| `test_stop_the_pipe_v25.py`, `test_structural_inputs_v25.py` | manifest version labels passed to `create_manifest_from_directory` and `DeploymentManifest` | `"0.6.3"` | `"0.6.4"` |

The checks that a mismatched GOPEL version is refused still use `"0.6.2"` and are unchanged.

## 3. Signed manifest required (Basil's ruling X3): moved to the named local test setting, same expectation

v2.6 refuses an unsigned manifest by default. These carried checks build a manifest without the manifest key and test something else (code integrity, a missing directory, a HALT trigger) or test the unsigned path itself. Each now runs with `local_test_unsigned_manifests=True`, and its assertions are unchanged:

| File | Check |
|---|---|
| `test_overwatch.py` | `TestStructuralVerifier` (setUp): `test_SV2_code_integrity_clean`, `test_SV3_code_integrity_modified_file`, `test_SV4_code_integrity_missing_file`, `test_SV5_code_integrity_unexpected_file` |
| `test_gopel_v17.py` | `TestStructuralVerifierHandlesMissingGopelDirectory.test_structural_verifier_handles_missing_gopel_directory` |
| `test_stop_the_pipe_v25.py` | `TestStopLine.test_halt_escalation_trigger_is_halt` |
| `test_structural_inputs_v25.py` | `TestKeyedManifest.test_without_a_manifest_key_no_signature_is_claimed` (it still checks that the log says "unsigned" and never "signature verified") |
| `test_v11_review_fixes.py` | `TestManifestSignatureVerification.test_verify_manifest_signature_returns_true_for_valid_hash` |

The refusal itself is proved by the new `test_manifest_required_v26.py`.
