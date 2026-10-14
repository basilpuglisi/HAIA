# CBG Model 1 Runner v5: carried checks that changed

`test_cbg_model1_russell_v5.py` carries every check of `test_cbg_model1_russell_v4.py` (unchanged beside it) and adds section 29, the Team Gate checks of HAIA_Update_Plan_v4. This file lists every carried line that differs. No limit, threshold, or count in a carried check changed.

## 1. Path and name only (no expectation changed)

| Line in v5 test | v4 | v5 |
|---|---|---|
| docstring, lines 2 and 6 to 12 | names v4 and section 28 | names v5, sections 28 and 29, and where GOPEL v0.6.4 sits |
| `import cbg_model1_russell_v4 as m` | v4 module | `import cbg_model1_russell_v5 as m` |
| `ROOT = tempfile.mkdtemp(prefix=...)` | `"m1v4_"` | `"m1v5_"` |
| the image tool test script's import | `import cbg_model1_russell_v4 as m` | `import cbg_model1_russell_v5 as m` |
| the closing summary | counts section 28 as new | counts section 28 as carried and section 29 as new |

## 2. The version moved (same check, new version)

| Check | v4 expectation | v5 expectation |
|---|---|---|
| `v4 version: RUNNER_VERSION, the ledger rules line, and the docstring title name v4` | "CBG Model 1 Runner v4" in all three | "CBG Model 1 Runner v5" in all three |

## 3. The run-path ledger read guard gains one integrity read

| Check | Change |
|---|---|
| `v4 step 19: every ledger read on the run path is on the allowlist` | `ALLOWED_KIND_READS` gains `("_uncovered_head_failure", "head_write_failed")`: Basil's ruling X4 (no deployment without the head) reads the latest failed head write, an integrity record. No other entry changed, and the denied kinds (`outcome`, `post_release`, `engagement`, `metric`, and the rest) are unchanged, so R6 holds: Model 1 still learns nothing from AI output or from its own deployments. |

## 4. New checks (section 29, 18 checks)

- X4: a failed head write blocks the next deployment, which goes to the human as `head_unwritten` and ends the run; a later signed head that covers it clears the block; an unreachable handoff still freezes the runner; a forged head does not clear it.
- Every AI platform call goes through GOPEL v0.6.4: one Dispatch and Response record per call, one group per CAIPR dispatch with one prompt hash, the Navigator through `route` with a Navigation record, the RECCLIN role of each group (QT9), and no GOPEL id or hash in any prompt.
- The GOPEL integrity watch: a stop before the item, a stop during a seat's call, and a chain that no longer verifies each freeze the runner, once.
- An outside channel must be pinned by the charter (QT8).
- After the human release through GOPEL's evidence gate, the runner stays frozen until its governor signs a resume dated after the freeze (QT6 A, the published rule).
- Version, header text, and the receipt's fields (unchanged from v4).

## 5. Runs on host C

- Before, against an unchanged copy of v4 saved as `cbg_model1_russell_v5.py`: carried 426 passed, 1 failed (the version check in item 2); new 2 passed, 16 failed. 428 passed, 17 failed.
- After: carried 427 passed, 0 failed; new 18 passed, 0 failed. 445 passed, 0 failed.
