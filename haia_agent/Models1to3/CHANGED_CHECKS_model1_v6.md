# CBG Model 1 Runner v6: carried checks that changed

`test_cbg_model1_russell_v6.py` carries every check of `test_cbg_model1_russell_v5.py` (unchanged beside it) and adds section 30, the checks of Basil's fix round (items 1 and 3). This file lists every carried line that differs. No limit, threshold, or count in a carried check changed.

## 1. Path, name, and the channel every runner is handed (no expectation changed)

| Where | v5 | v6 |
|---|---|---|
| docstring | names v5 | names v6, sections 28 to 30, and GOPEL v0.6.5 (kept short so the license lines stay in the first 20 lines, which a carried guard reads) |
| imports | `cbg_model1_russell_v5`; section 29 imports `haia_agent.gopel_v064` | `cbg_model1_russell_v6`; `haia_agent.gopel_v065` |
| `ROOT` prefix, image tool script | `m1v5_`, imports v5 | `m1v6_`, imports v6 |
| `build()` | hands the runner its providers and the providers file's hash | builds a GOPEL v0.6.5 channel over the same canned platforms, as the hosting process, pins it in the charter, and hands it to the runner, which gets no providers |
| section 29 `team_demo` | reads GOPEL's audit beside the ledger (`.gopel.json`) | reads the handed channel's audit file |
| section 29 `build_external` pin | version `"0.6.4"` | version `"0.6.5"` |
| `runner key: another key refused` | the second runner is given provider connections | it is given `{}` and the channel, so the runner key is what refuses it |
| `charter: two seats on one service and model refused`, `charter: alias of the same service and model refused` | change the runner's providers | change the channel's adapters (`build(extra=...)` adds the alias as a GOPEL adapter) |
| `brainstorm: repeat refused`, `brainstorm: new concept accepted` | swap the runner's Navigator provider between runs | swap the channel adapter's call between runs |
| closing summary | counts section 29 as new | counts sections 28 and 29 as carried and section 30 as new |

## 2. The version moved (same check, new version)

| Check | v5 expectation | v6 expectation |
|---|---|---|
| `v4 version: RUNNER_VERSION, the ledger rules line, and the docstring title name v4` | "CBG Model 1 Runner v5" | "CBG Model 1 Runner v6" |
| `v5 version: RUNNER_VERSION, the ledger rules line, and the docstring title name v5, and a ledger started by v4 is refused` | "CBG Model 1 Runner v5" | "CBG Model 1 Runner v6" |

## 3. Expectations that changed with the fix round

| Check | v5 | v6 | Basis |
|---|---|---|---|
| `v8: a providers file the charter does not pin is refused` | a providers file whose hash differs is refused, naming the providers | a GOPEL channel whose registry hash differs from the charter's pin is refused, naming GOPEL | item 3b: the runner reads no providers file; the QT8 pin is always checked |
| `v8: a charter without providers_sha256 is not valid` | not valid | valid: the field is optional, and checked for form when given | item 3b, as above |
| `v5 team (QT9): GOPEL Request records carry the RECCLIN role of each group` | score as calculator | score as editor | item 3a: HAIA-SMART Copy v2.1 and HAIA-CORE v3.10, Section 0, name the Editor role; Basil assigns Editor to SMART Creative scoring too |

## 4. New checks (section 30, 13)

Scoring groups labeled Editor (SMART Copy and SMART Creative); no run without a handed GOPEL channel, and no GOPEL hosted by the runner; provider connections refused; the GOPEL pin always checked (guard); the demo hands a channel and pins it; the run command refuses; the connection wrapper hands GOPEL the answer as it arrived; a lone-surrogate answer recorded escaped by GOPEL while the item goes on; an uncalled seat withdrawn from its group; version, header, and the receipt's fields (guard).

## 5. Runs on host C

- Before, against an unchanged copy of v5 saved as `cbg_model1_russell_v6.py`: carried 441 passed, 4 failed (items 2 and 3 above); new 2 passed (the two guards), 11 failed. 443 passed, 15 failed.
- After: carried 445 passed, 0 failed; new 13 passed, 0 failed. 458 passed, 0 failed.

## A correction to the record

The message of commit `afa82f1` (GOPEL v0.6.4) quotes an error, `ModuleNotFoundError: No module named 'haia_agent.gopel_v064.channel'`, that the saved before-run evidence cannot confirm: that file kept only the failing tests' names.
