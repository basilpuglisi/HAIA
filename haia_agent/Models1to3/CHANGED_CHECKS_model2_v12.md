# CBG Gateway, Agent Model 2 edition v12: carried checks that changed

`test_cbg_gateway_model2_v12.py` and `test_cbg_gateway_model2_browser_v12.py` carry every check of the v11 suites (unchanged beside them) and add the checks of Basil's fix round of October 15, 2026, items 1 and 4. This file lists every carried line that differs. No limit, threshold, or count in a carried check changed.

## 1. Path and name only (no expectation changed)

| File | v11 | v12 |
|---|---|---|
| unit test docstring | names v11 and its files | names v12, the v11, v10, and v9 files beside it, GOPEL v0.6.5, and the v12 checks |
| unit test import | `import cbg_gateway_model2_v11 as cg` | `import cbg_gateway_model2_v12 as cg` |
| unit test `gopel_setup` and `gopel_release` | import `haia_agent.gopel_v064` | import `haia_agent.gopel_v065`, the GOPEL the gateway now hosts; the docstring names v0.6.5 |
| unit test `main()` | runs the v11 groups | runs the same groups, then `v12_checks` |
| browser test docstring | names v11 | names v12 and the hold screen check |
| browser test imports | `cbg_gateway_model2_v11` | `cbg_gateway_model2_v12`, plus `dataclasses`, `hmac`, `uuid`, and `datetime` for the new check |

## 2. The version moved (same check, new version)

| Check | v11 expectation | v12 expectation |
|---|---|---|
| `v10 version: GATEWAY_VERSION is CBG Gateway v10, ...` | "CBG Gateway v11", rules starting "CBG Gateway v11 rules: " | "CBG Gateway v12", rules starting "CBG Gateway v12 rules: " |
| `v11 version: GATEWAY_VERSION is CBG Gateway v11, ...` | "CBG Gateway v11", rules starting "CBG Gateway v11 rules: " | "CBG Gateway v12", rules starting "CBG Gateway v12 rules: "; the GOPEL hold record kinds unchanged |
| `v11 header: the title names v11, ...` | title "CBG Gateway, Agent Model 2 edition, v11" | title "CBG Gateway, Agent Model 2 edition, v12"; the key holder line, "Every AI platform and Navigator call goes through GOPEL", and "WHAT V11 ADDS" unchanged |

## 3. Expectations that changed with the fix round

| Check | v11 | v12 | Basis |
|---|---|---|---|
| `A provider key from the providers file never reaches the ledger in an error` | the key is absent and the ledger's error says "key removed" (the gateway's bridge redacted it) | the key is absent and the error says "secret removed" (GOPEL's adapter redacted it before GOPEL recorded the failure; the gateway records GOPEL's text) | item 1b: redaction happens inside GOPEL's adapters, and agents no longer alter text before GOPEL records it |

## 4. Same expectation, a named local test setting added to the input

v12's serve refuses to start without an Overwatch stop intake outside the named local test setting (item 4a). Two carried checks run check-deployment on a local test setup and expect it to pass; their environment now names that setting, `CBG_LOCAL_TEST_NO_OVERWATCH=1`, beside the anchor local test setting they already named:

- `check-deployment passes a local test setup with five mock connections and warns about it`
- `check-deployment counts the providers file's four connections`

## 5. New checks

- **Unit, 29:**
  - version and header (4);
  - the Overwatch stop intake serve attaches, S-1 (10);
  - the hold lifted only by a new release ID (5);
  - the screens during a stop, choice 17 (3);
  - redaction inside GOPEL's adapters, the gateway's own ledger, the escaped answer, and the bridge guard (6);
  - the withdrawn platform (1).
- **Browser, 3:** the GOPEL hold screen during a stop, with the stops gone and no new release, and after a release.

## 6. Runs on host C

`lscpu` reported Intel Xeon @ 2.80 GHz for these runs.

- **Unit, before:** against an unchanged copy of v11 saved as `cbg_gateway_model2_v12.py`, 461 of 481.
  - The carried checks: 458 passed, 3 failed. Two are the version moves of item 2. The third, `v11 hold: after the release, the withheld platform is sent the same messages again`, failed because the unchanged module imports GOPEL v0.6.4 while the carried test helper builds a v0.6.5 channel; it passes on v12.
  - The new checks: 3 guards passed and 17 failed. The intake group stopped at its first line, on the missing `serve_gateway`, and counts as one.
- **Unit, after:** 490 of 490 (461 carried, 29 new).
- **Browser, before:** against the same unchanged copy, 30 of 33. The carried checks pass and the 3 new ones fail.
- **Browser, after:** 33 of 33.

## A correction to the record

The message of commit `afa82f1` (GOPEL v0.6.4) quotes an error, `ModuleNotFoundError: No module named 'haia_agent.gopel_v064.channel'`, that the saved before-run evidence cannot confirm: that file kept only the failing tests' names.
