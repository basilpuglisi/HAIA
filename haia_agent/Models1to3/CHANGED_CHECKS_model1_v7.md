# CBG Model 1 Runner v7: carried checks that changed

`test_cbg_model1_russell_v7.py` carries every check of `test_cbg_model1_russell_v6.py` (unchanged beside it) and adds section 31, the checks of Basil's rulings of October 17, 2026. This file lists every carried line that differs. No limit, threshold, or count in a carried check changed.

## The rulings

- "Model 1 is designed to hold the person who created the agent to account, the risk is assumed in Model 1." Whether the company or the person answers turns on the assignment: deploy only, or the "management" and ongoing work.
- "Model 1 Code should include the records"
- Who signs: "Person A as the deployer, 2nd party as witness (any Company A representative or if Person A is a Consultant or 3rd Party a witness)"
- What each receipt carries: "Facts only"

## 1. Path, name, and the witness every runner is given (no expectation changed)

| Where | v6 | v7 |
|---|---|---|
| docstring | names v6 and section 30 | names v7, sections 28 to 30 as carried, and section 31 |
| imports | `cbg_model1_russell_v6` | `cbg_model1_russell_v7` |
| `ROOT` prefix, image tool script | `m1v6_`, imports v6 | `m1v7_`, imports v7 |
| new helpers | none | `DEPLOYMENT` (the test's record, the same values as the demo's), `takes`, `witness_env`, `witness_kw` |
| `build()` | signs the charter with the governor key | adds `DEPLOYMENT` to a charter that has none, signs it with the governor key, adds a second key's witness signature, and hands the runner that witness key; returns `"witness"`. Options `witness=False`, `witness_sign=False`, and `witness_key=` serve section 31 |
| `audit()` | runner key and governor key | also the witness key |
| section 9, `charter: alias of the same service and model refused` | re-signs the changed charter with the governor key | re-signs it and adds the witness signature again, so it is refused for the alias, as before |
| section 29, `build_external` | signs the charter with the governor key | adds `DEPLOYMENT`, signs, adds a witness signature, and hands the runner the witness key |
| section 30, `refuses_without_channel` | an unwitnessed charter and no witness key | a witnessed charter and its witness key, so the refusal is for the missing GOPEL channel, as before |

`build()`, `audit()`, and `refuses_without_channel` pass the witness key only when the runner or the audit takes one (`takes`). That lets the same file run against an unchanged copy of v6 for the before runs below; against v7 the witness key is always passed.

## 2. The version moved (same check, new version)

| Check | v6 expectation | v7 expectation |
|---|---|---|
| `v4 version: RUNNER_VERSION, the ledger rules line, and the docstring title name v4` | "CBG Model 1 Runner v6" | "CBG Model 1 Runner v7" |
| `v5 version: ... and a ledger started by v4 is refused` | "CBG Model 1 Runner v6" | "CBG Model 1 Runner v7" |
| `v6 version: ... and a ledger started by v5 is refused` | "CBG Model 1 Runner v6" | "CBG Model 1 Runner v7" |

## 3. Expectations that changed with the rulings

| Check | v6 | v7 | Basis |
|---|---|---|---|
| `v4 S3: the receipt format is unchanged: the v3 fields, no more and no fewer` | the v3 fields | the v3 fields plus `deployment` and `witness_key` | "Model 1 Code should include the records" and "Facts only": every receipt carries the record |
| `v5 guard: the deployment receipt's fields are v4's, unchanged` | v4's `RECEIPT_FIELDS` | v4's, then `deployment` and `witness_key` | as above |
| `v6 guard: the deployment receipt's fields are v4's, unchanged` | v4's `RECEIPT_FIELDS` | v4's, then `deployment` and `witness_key` | as above |
| `v4 step 19: every ledger read on the run path is on the allowlist` | the allowlist | the allowlist plus `("_pin_witness", "witness_key")`, the witness key pinned at first start, as the governor key is | "Person A as the deployer, 2nd party as witness" |

## 4. New checks (section 31, 29)

The deployment record in the charter: required, present in the demo, the deployer is the signing governor, the value sets, the witness roles, the witness never the deployer. The witness signature at the run: no witness key, no witness signature, the deployer's own key, a record changed after the witness signed, another witness named, an untrusted key, the key pinned in the ledger, and a signature that stops verifying mid-run. The facts on every receipt: the record and the witness key on the deployment receipt, compared offline against the charter and the witness key, a shifted record refused, a broken witness signature refused, facts only, the record on every handoff message and receipt and in the handoff file, a shifted handoff message refused. The audit: the witness signature checked, a shifted bundle refused. The command line: the witness command and the audit's witness key. The demo, the version, and the two doc checks.

One new check was narrowed after the first run on v7, before any code changed for it: the facts-only check's word list matched `uniform_answer`, a carried gate field that records whether every scorer gave the same total. It is about the scorers, not the deployer, so the list now looks for answers, answerable, accountable, liable, responsible, finding, culpable, blame, and at_fault. The before run below was taken again with the final file.

## 5. Runs on host D (2 CPUs, Intel Xeon @ 2.80 GHz, Python 3.13.16), October 17, 2026

- Before, against an unchanged copy of v6 saved as `cbg_model1_russell_v7.py`, with the final test file: carried 452 passed, 6 failed (the six checks in sections 2 and 3 that expect v7's names and receipt fields); new 0 passed, 29 failed. 452 passed, 35 failed.
- After: carried 458 passed, 0 failed; new 29 passed, 0 failed. 487 passed, 0 failed.
- The v6 suite on the same host, as a baseline: 458 passed, 0 failed.
