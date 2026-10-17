# CBG Model 1 Runner v8: carried checks that changed

`test_cbg_model1_russell_v8.py` carries every check of `test_cbg_model1_russell_v7.py` (unchanged beside it) and adds section 32, the checks of the independent review of v7, run on October 17, 2026. This file lists every carried line that differs. No limit, threshold, or count in a carried check changed.

## Why v8

v7 was reviewed by a separate agent that had not seen it built. The review confirmed two defects and raised three concerns, each against Basil's ruling "Person A as the deployer, 2nd party as witness (any Company A representative or if Person A is a Consultant or 3rd Party a witness)". v7 is published on the branch, so the fixes are a new version:

| Finding | v7 | v8 |
|---|---|---|
| C1, confirmed defect | The deployer's own key, written with spaces between its bytes, passed as the witness at load, in the audit, and in verify-receipt: keys were compared as strings, and the key reader accepted spaces | A public key is exactly 64 hexadecimal characters (case and surrounding whitespace aside), and two keys are compared as key bytes, so no spelling makes the deployer's key a second party |
| C2, confirmed defect (low) | Given a bare charter body, verify-receipt labeled the deployment record compared and never mentioned the witness, though its docstring said the witness signature must verify | The label's basis says the witness was not checked, and the docstring says so |
| C3, concern | The runner's own key was accepted as the witness | Refused at load, before every stage, in the audit, in verify-receipt, and in verify-handoff |
| C4, concern | The witness signature did not cover the deployer's key, so it carried over to the same charter signed by another key | The witness also signs the deployer's key, and the check requires it to be the charter's signer |
| C5, concern | verify-handoff took no charter or witness key | It takes both, in code and on the command line |
| Header | Ruling 1 was quoted in part under the word verbatim | Ruling 1 is quoted in full, with the channel wording Basil confirmed the same day: "moral, professional, civil, and criminal is correct" |

One review concern is not changed here, because it is Basil's to rule on: `follow_up` records `none` or `audit_review` (the deployer reviewing outputs as part of an audit), so a follow-up the company runs through someone else has no value to record.

## 1. Path, name, and the witness helper (no expectation changed)

| Where | v7 | v8 |
|---|---|---|
| docstring | names v7 and section 31 | names v8, sections 28 to 31 as carried, and section 32 |
| imports | `cbg_model1_russell_v7` | `cbg_model1_russell_v8` |
| `ROOT` prefix, image tool script | `m1v7_`, imports v7 | `m1v8_`, imports v8 |
| `witness_env` | the witness signs the charter id, its hash, and the witness name | it also signs the deployer's key, as v8's witness command does |

## 2. The version moved (same check, new version)

| Check | v7 expectation | v8 expectation |
|---|---|---|
| `v4 version: RUNNER_VERSION, the ledger rules line, and the docstring title name v4` | "CBG Model 1 Runner v7" | "CBG Model 1 Runner v8" |
| `v5 version: ... and a ledger started by v4 is refused` | "CBG Model 1 Runner v7" | "CBG Model 1 Runner v8" |
| `v6 version: ... and a ledger started by v5 is refused` | "CBG Model 1 Runner v7" | "CBG Model 1 Runner v8" |
| `v7 version: ... the rules name the witness, and a ledger started by v6 is refused` | "CBG Model 1 Runner v7" | "CBG Model 1 Runner v8" |

## 3. New checks (section 32, 11)

The deployer's key written with spaces refused as the witness; the strict key reader; the witness check refusing the deployer's key however written; the runner's key refused as the witness, at the run and in verify-receipt; the witness bound to the deployer's key; a bare charter body named as unwitnessed; verify-handoff against the charter and the witness key, in code and on the command line; the version; and the header's full quotation of ruling 1.

Two checks were rewritten after the first before run, before any v8 code existed: the test file's header was shortened so the carried license guard finds the license block in its first 20 lines, and a check that called the audit with a key other than the one the ledger recorded was replaced, because it passed on v7 for that other reason; the replacement calls the witness check itself.

## 4. Runs on host D (2 CPUs, Intel Xeon @ 2.80 GHz, Python 3.13.16), October 17, 2026

- Before, against an unchanged copy of v7 saved as `cbg_model1_russell_v8.py`, with the final test file: carried 483 passed, 4 failed (the four version checks in section 2); new 0 passed, 11 failed. 483 passed, 15 failed.
- After: carried 487 passed, 0 failed; new 11 passed, 0 failed. 498 passed, 0 failed.
- The reviewer's four reproductions against v8: the spaced deployer key is refused when the runner is built, the runner's key and a witness signature carried to another deployer are refused at load, and the bare-body case is covered by the new check above, since the reproduction's own charter, signed without the deployer's key, is now refused before it deploys.
