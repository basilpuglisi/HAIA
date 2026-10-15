# GOPEL v0.6.5: carried checks that changed

The 297 checks of GOPEL v0.6.4 are carried in `tests/` with their import path changed from `haia_agent.gopel_v064` to `haia_agent.gopel_v065`. Seven carried checks change their expectation or input:

| File | Check | v0.6.4 expectation | v0.6.5 expectation | Why |
|---|---|---|---|---|
| `test_v061_fixes.py` | `TestVersionBump` | `__version__ == "0.6.4"` | `__version__ == "0.6.5"` | the version moved |
| `test_v063_packaging.py` | `test_version_is_0_6_5` (was `test_version_is_0_6_4`) | `"0.6.4"` | `"0.6.5"` | the version moved |
| `test_v063_packaging.py` | `test_entry_point_prints_version_and_runs_analyzer` | output names `0.6.4` | output names `0.6.5` | the version moved |
| `test_v063_packaging.py` | `test_import_and_run_v063_loads_no_v061_or_v062_module` | no v0.6.1, v0.6.2, or v0.6.3 module loaded | also no `gopel_v064` module loaded | v0.6.5 must load no earlier version |
| `test_v063_adapters.py` | `test_requirements_pin_sdk_ranges` | reads `requirements_v0_6_4.txt` | reads `requirements_v0_6_5.txt` | the file carries the version in its name; the pins are unchanged |
| `test_v064_channel.py` | `test_status_reports_ids_and_hashes_only` | `status().version == "0.6.4"` | `"0.6.5"` | the version moved |
| `test_v064_channel.py` | `test_a_failed_call_logs_its_error_and_returns_no_text` | the failed call's Dispatch record says `"error"` | it says `"sent"`; the Response record still says `"error"` with the provider's text | fix round item 1a: the Dispatch record is written before the call, so it records the send, and the failure is on the Response record |

No other carried check changed.
