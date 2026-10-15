# HAIA-Overwatch v2.8: carried checks that changed

Every test of Overwatch v2.7 (`overwatch/overwatch_v27/tests/`, unchanged) is carried into `overwatch/overwatch_v28/tests/` under the same file name, with the same fixture, `gopel_v065_mock_audit_v1.json`. Two kinds of change were made; no other line differs. No expectation changed.

## 1. Import path only

Every `overwatch_v27` import and module path in the carried test files became `overwatch_v28`. One line the replacement also reached is not an import, and it keeps its v2.7 text:

- `test_changes_v27.py`, `test_the_changed_checks_file_lists_the_carried_changes`, checks that `CHANGED_CHECKS_v2_7.md` names `overwatch_v27`. The needle stays `"overwatch_v27"`, because that file is carried byte for byte.

The carried change logs are byte for byte those of v2.7:

- `CHANGES_v2_5.md`
- `CHANGES_v2_6.md`
- `CHANGES_v2_7.md`
- `CHANGED_CHECKS_v2_6.md`
- `CHANGED_CHECKS_v2_7.md`

## 2. Version labels (same expectation, the version moved)

| File | Check or line | v2.7 | v2.8 |
|---|---|---|---|
| `test_version_wording_v25.py` | `test_version_strings_agree_at_2_8_0` (was `..._2_7_0`) | `"2.7.0"` | `"2.8.0"` |
| `test_version_wording_v25.py` | `test_module_header_reads_v2_8` (was `..._v2_7`) | header matches `v2.7` | header matches `v2.8` |
| `test_calibration_v24.py` | `TestCalibrationExport.test_version_bumped` | `"2.7.0"` | `"2.8.0"` |
| `test_overwatch.py` | `TestPipelineIntegration.test_PI3_status_tracking` | `"2.7.0"` | `"2.8.0"` |

The GOPEL version Overwatch expects stays `"0.6.5"`.

## 3. Checks v2.8 could have changed and did not

v2.8 changes how a web address in an answer is classified, and how a restart reads the trail. Every carried check passed without change, including all of these:

- every T-1 check of `test_t1_context_v27.py`;
- the fix round checks of v2.7;
- the floor checks;
- the GOPEL record and chain checks of `test_gopel_records_v25.py`, among them `history_rewritten` on a re-read document.

The full v2.8 suite, timing test aside, is 788 passed and 1 expected failure before `test_residual_forms_v28.py`, `test_known_limits_v28.py`, and `test_changes_v28.py` were added. The final count is in the final run.
