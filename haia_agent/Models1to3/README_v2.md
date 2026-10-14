# Agent Models 1 to 3, README v2

This README describes the folder after the Team Gate of HAIA_Update_Plan_v4, approved by Basil C. Puglisi on October 14, 2026. `README.md` beside it describes the first published files, runner v3 and gateway v9, and stays as published. Every earlier version stays in the folder unchanged; each new version is a new file.

The Team Gate's purpose, in Basil's words: "make sure these all worked together as a team with a specific individual function. make it an example of the HAIA Ecosystem made functional code."

| Agent Model | Designation | Current program | Earlier versions, kept | Checks, one run on host C, October 14, 2026 |
|---|---|---|---|---|
| 1 | Responsible AI | `cbg_model1_russell_v5.py`, the CBG Model 1 Runner v5 | v4 (Gate 1), v3 (published) | v5: 445 of 445 checks; v4: 427 of 427 checks; v3: 379 of 379 checks |
| 2 | Hybrid: the machine runs through to AI Governance | `cbg_gateway_model2_v11.py`, the CBG Gateway v11 | v10 (Gate 1), v9 (published) | v11: 461 of 461, browser 30 of 30; v10: 437 of 437, browser 30 of 30; v9.1: 386 of 386, browser 22 of 22 |
| 3 | Manual Human AI Governance | None, by design | None | None |

The changed checks of each new version are listed in `CHANGED_CHECKS_model1_v5.md` and `CHANGED_CHECKS_model2_v11.md`.

## The team, and each part's one job

- **GOPEL v0.6.4** (`haia_agent/gopel_v064/`) is the governed channel. It dispatches, collects, routes, logs, pauses, hashes, and reports, and does no cognitive work.
- **Agent Model 2, the CBG Gateway v11,** lets no role advance and releases nothing without the named governor's passkey signature. Its process hosts GOPEL, and the provider connections are GOPEL's adapters there, so the platform keys stay in the gateway's process.
- **Agent Model 1, the CBG Model 1 Runner v5,** is machine checks machine: it deploys only through its gates, with no human review of any output.
- **Overwatch v2.6** (on the `claude/overwatch-v25` branch) has one action: stop the pipe, route to human. It reads GOPEL's audit trail read only and imports nothing from GOPEL or the agents.
- **The human governor** decides at every Model 2 checkpoint, signs Model 1's charter and its stops and resumes, and alone releases an Overwatch stop, through GOPEL's evidence gate.

## What v5 and v11 add

- **Every AI platform call goes through GOPEL.** Each CAIPR dispatch, each Model 2 step, and each substitution, escalation, and scoring dispatch is one GOPEL group that sends the same messages to every platform. A Model 2 restart with a signed direction runs in its own one-platform group. Every Navigator turn goes through GOPEL's route operation. Each agent record names the GOPEL Request, Dispatch, and Response records by id and chain hash.
- **Model 2 holds on a GOPEL stop.** While Overwatch has GOPEL stopped, every open task is held: decisions, the next role, and release wait, and work GOPEL withholds is recorded. One human release through GOPEL's evidence gate resumes every held task, and the withheld work is sent again with the same messages. A GOPEL stop is never a governor's stop. Model 2's human acts are not mirrored into GOPEL.
- **Model 1 watches GOPEL.** Its GOPEL integrity watch freezes the runner when GOPEL's status cannot be read, names another instance or version than the charter pins, shows a chain that does not verify or that moved back, or shows an active Overwatch stop. The freeze lifts by the published rule: after the human release, the governor signs a resume dated after the freeze.
- **Model 1's charter pins its GOPEL** by instance ID, version, and the SHA-256 of the platform registry, when the runner is given a GOPEL channel hosted outside it.
- **Basil's Gate 1 rulings, carried into the new versions:** Model 1 deploys nothing after a failed head write until a signed head covers it (X4), and a Model 2 pause lifts only on a head that covers the act whose anchor send failed (X2).
- **Receipts are unchanged.** Model 1's deployment receipt and Model 2's release receipt and bundle are those of v4 and v10.
- **Model 2 shows an answer once it has fully arrived** (the one-chunk bridge, ruling QT4 A): a stop or restart signed while a platform runs takes effect when its answer arrives, which is then discarded. No carried timing check changed.

## The team suite

`haia_agent/e2e/test_e2e_team_v1.py` runs GOPEL, both agents, and Overwatch as one system: a Model 2 task through GOPEL; an Overwatch stop on an injected answer; both agents held; one human release; both agents resumed as ruled; everything verified offline. On host C it passed 26 passed. It is pinned by `haia_agent/e2e/overwatch_pin_team_v1.json`.

## Finding T-1, for Basil's ruling

Overwatch v2.6 at its published defaults stops the pipe on Model 1's clean item. Its state-change patterns read any web address in an answer as a network operation, which is a WARNING for every role but Coder and escalates, and Model 1's gates need sources named by web address. It also read Model 1's scoring group, under the calculator role, as low role coherence. The same patterns read the English words update, create, delete, insert, alter, drop, and truncate before a space as database changes. The team suite asserts this rather than hiding it. No code was changed for it; a fix belongs to a later Overwatch version.

## Not yet routed through GOPEL

Model 1's image tool, a local program a charter may name, is not yet routed through GOPEL.

## Deferred to a later session

- **Model 1's network path to the gateway-hosted GOPEL** (Part E step 6 of HAIA_Update_Plan_v4). In this release both agents share one GOPEL channel inside one process, as the team suite runs them. Without a channel handed to it, the runner hosts its own GOPEL over its providers file, so its provider keys stay in its own process, as in v4, until that path lands.
- **Gates 2 to 4** of HAIA_Update_Plan_v4.

## What Alpha means

The code runs and passes its own checks. Neither program has been deployed, neither has called a live AI provider in the build record, and live provider testing is not authorized yet. Neither has had a professional security review. Every test uses mock or canned platforms. Provider keys are read from environment variables named in the providers file, and the threat model is kept as a project file. The header of each program states what it needs, how to run it, and what it cannot do.

## Running the checks

From this folder, with GOPEL v0.6.4's requirements installed (`pip install -r ../gopel_v064/requirements_v0_6_4.txt`) beside each program's own:

```
python test_cbg_model1_russell_v5.py
python test_cbg_gateway_model2_v11.py
python test_cbg_gateway_model2_browser_v11.py
```

The tests for v3, v4, v9.1, and v10 run the same way and test their own files.

Basil C. Puglisi, MPA | basilpuglisi.com

#AIassisted using the HAIA Ecosystem | CC BY-NC-SA 4.0

Free for personal, educational, and noncommercial research use with attribution. Commercial exploitation, paid productization, and enterprise commercialization require separate permission and licensing.
