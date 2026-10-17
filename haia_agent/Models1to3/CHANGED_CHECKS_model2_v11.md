# CBG Gateway, Agent Model 2 edition v11: carried checks that changed

`test_cbg_gateway_model2_v11.py` and `test_cbg_gateway_model2_browser_v11.py` carry every check of the v10 suites (unchanged beside them). This file lists every carried line that differs. No limit, threshold, or count in a carried check changed.

## 1. Path and name only (no expectation changed)

| File | v10 | v11 |
|---|---|---|
| unit test docstring | names v10 and its files | names v11, the v10 and v9 files beside it, where GOPEL v0.6.4 sits, and this file |
| unit test import | `import cbg_gateway_model2_v10 as cg` | `import cbg_gateway_model2_v11 as cg` |
| unit test `main()` | runs the v10 groups | runs the same groups, then `v11_checks` |
| browser test docstring | names v10 | names v11, and says the v10 browser checks are carried unchanged |
| browser test import | `import cbg_gateway_model2_v10 as cg` | `import cbg_gateway_model2_v11 as cg` |

## 2. The version moved (same check, new version)

| Check | v10 expectation | v11 expectation |
|---|---|---|
| `v10 version: GATEWAY_VERSION is CBG Gateway v10, POLICY_VERSION stays CBG v5.1, and LEDGER_RULES names the v10 rules and its new record kinds` | "CBG Gateway v10" and rules starting "CBG Gateway v10 rules: " | "CBG Gateway v11" and rules starting "CBG Gateway v11 rules: "; POLICY_VERSION and the two pause record kinds unchanged |

## 3. One static guard retargeted to the channel (HAIA_Update_Plan_v4, Part C3)

| Check | Change |
|---|---|
| `v10 step 19: every platform and Navigator call takes its provider and model from the signed manifest, read through task_state` | The label gains ", and goes through GOPEL (v11)". v10 required the connection given to `_stream` to be `self.providers.get(X["provider"])`; v11 requires it to be `self._via_gopel(handle, X["provider"], result)`, GOPEL's channel. The rest is unchanged: the provider and the model still come from the signed manifest read through `task_state`, at two or more call sites. |

The other step 19 guards are unchanged and pass as written: the connections are still read only in `__init__`, `_platform`, `_service`, `_apply_authorize`, `authorize_form`, and `main`; no ledger kind names an outcome; the routing functions read no release, correction, or telemetry record; and the prompt builders read no receipt id, nonce, hash, seal, or anchor.

## 4. QT4 A, the one-chunk bridge: carried timing checks

Basil's answer QT4 A asked that every changed v10 timing check be listed. None changed. Every carried check of a stop or restart while a platform runs, of the time limit, of the size limit, of text that is not Unicode, and of a stream that ends without saying it finished passes as written on v11: GOPEL reads the answer to its end, the limits and refusals run with v10's words inside the bridge, and an answer a stop or restart cut off is still discarded and recorded as `stopped_output_discarded`. What changed is when a stop takes effect: once the platform's answer has arrived, not during it.

## 5. New checks (24)

- Version and header (4), and the receipt guard: the v11 receipt carries exactly v10's keys (R7).
- B1 (3): a head read before a failed act on another high-risk task does not lift that task's pause (a guard, which passes on v10); the pause names `act_seq`; the resume names `act_seq` and the head seq.
- Every AI platform and Navigator call through GOPEL (7): GOPEL references in every sealed answer and turn; one Dispatch per call a connection received; one group per step with the step's messages and RECCLIN role; the Navigator through `route`; no GOPEL id or hash in any prompt; a clean audit; a restart in its own one-platform group (QT7 a).
- The GOPEL hold (8): a decision refused and the task held while Overwatch has GOPEL stopped; the screen shows it; a task authorized during the stop is not dispatched; one human release through GOPEL's evidence gate resumes every held task, naming the release; decisions go on; the undispatched task goes out with the same messages; a stop during a platform's call withholds its answer; that platform is sent the same messages again after the release; a clean audit.
- A guard that no gateway method calls a connection directly.

## 6. Runs on host C

- Before, against an unchanged copy of v10 saved as `cbg_gateway_model2_v11.py`: 438 of 448. The carried checks: 435 passed, 2 failed (items 2 and 3). The new checks: 3 guards passed; 6 failed; the channel and hold groups stopped at their first line (`AttributeError: module 'cbg_gateway_model2_v11' has no attribute 'GOPEL_AUDIT_SUFFIX'`, and `... 'stream_as_channel_call'`).
- After: 461 of 461 (437 carried, 24 new). Browser: 30 of 30.
