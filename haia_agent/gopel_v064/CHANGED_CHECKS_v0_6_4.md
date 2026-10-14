# GOPEL v0.6.4: carried checks that changed

The 276 checks of GOPEL v0.6.3 are carried in `tests/` with their import path changed from `haia_agent.gopel_v063` to `haia_agent.gopel_v064`. Five carried checks change their expectation or input, all because the version moved:

| File | Check | v0.6.3 expectation | v0.6.4 expectation | Why |
|---|---|---|---|---|
| `test_v061_fixes.py` | `TestVersionBump` | `__version__ == "0.6.3"` | `__version__ == "0.6.4"` | the version moved |
| `test_v063_packaging.py` | `test_version_is_0_6_4` (was `test_version_is_0_6_3`) | `"0.6.3"` | `"0.6.4"` | the version moved |
| `test_v063_packaging.py` | `test_entry_point_prints_version_and_runs_analyzer` | output names `0.6.3` | output names `0.6.4` | the version moved |
| `test_v063_packaging.py` | `test_import_and_run_v063_loads_no_v061_or_v062_module` | no `haia_agent.gopel` or `gopel_v062` module loaded | also no `gopel_v063` module loaded | v0.6.4 must load no earlier version, v0.6.3 included |
| `test_v063_adapters.py` | `test_requirements_pin_sdk_ranges` | reads `requirements_v0_6_3.txt` | reads `requirements_v0_6_4.txt` | the file carries the version in its name; the pins are unchanged |

No other carried check changed.
