# HAIA-Overwatch v2.7: carried checks that changed

Every test of Overwatch v2.6 (`overwatch/overwatch_v26/tests/`, unchanged) is carried into `overwatch/overwatch_v27/tests/` under the same file name. Two kinds of change were made; no other line differs. No expectation changed. The v2.6 fixture `gopel_v064_mock_audit_v1.json` is replaced in v2.7 by `gopel_v065_mock_audit_v1.json` (GOPEL v0.6.5, generator v3, commit `c5f42d1`).

## 1. Import path only

Every `overwatch_v26` import and module path in the carried test files became `overwatch_v27`. The carried change logs (`CHANGES_v2_5.md`, `CHANGES_v2_6.md`, `CHANGED_CHECKS_v2_6.md`) are byte for byte those of v2.6.

## 2. Version labels (same expectation, the version moved)

| File | Check or line | v2.6 | v2.7 |
|---|---|---|---|
| `test_version_wording_v25.py` | `test_version_strings_agree_at_2_7_0` (was `..._2_6_0`) | `"2.6.0"` | `"2.7.0"` |
| `test_version_wording_v25.py` | `test_module_header_reads_v2_7` (was `..._v2_6`) | header matches `v2.6` | header matches `v2.7` |
| `test_calibration_v24.py` | `TestCalibrationExport.test_version_bumped` | `"2.6.0"` | `"2.7.0"` |
| `test_overwatch.py` | `TestPipelineIntegration.test_PI3_status_tracking` | `"2.6.0"` | `"2.7.0"` |
| `gopel_fixture_support_v25.py` | `EXPECTED_GOPEL_VERSION`, `FIXTURE_NAME` | `"0.6.4"`, the v0.6.4 fixture | `"0.6.5"`, the v0.6.5 fixture |
| `test_gopel_records_v25.py` | the module-level version assertion | `"0.6.4"` | `"0.6.5"` |
| `test_schema_version_v25.py` | `EXPECTED_GOPEL_VERSION`; the manifest's declared version in one check | `"0.6.4"` | `"0.6.5"` |
| `test_team_channel_v26.py` | `test_the_default_expectation_is_gopel_0_6_4`: the default expectation and the fixture's declared version | `"0.6.4"` | `"0.6.5"` (the test keeps its name) |
| `test_manifest_required_v26.py`, `test_stop_the_pipe_v25.py`, `test_structural_inputs_v25.py` | manifest version labels passed to `create_manifest_from_directory` and `DeploymentManifest` | `"0.6.4"` | `"0.6.5"` |

The checks that a mismatched GOPEL version is refused still use `"0.6.2"` and are unchanged.

## 3. The carried timing requirement

`test_gopel_v12.py::TestGopel10000TransactionsUnder5sP99` is carried unchanged, with its limits (60 s for 10,000 transactions, 50 ms p99). On the host of this build it fails for v2.6 as well as v2.7, so it depends on the host, as Gate 1 recorded (settlement Q3: the limit stays and the result is reported). The final run reports the measured figures for v2.4, v2.6, and v2.7 on one host.
