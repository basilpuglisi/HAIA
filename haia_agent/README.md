# HAIA Agents

This folder holds the HAIA agent layer. HAIA Agents is the name for the agent models and GOPEL taken together, and each one keeps its own folder here so that neither is mistaken for the other.

| Folder | What it holds | Status |
|---|---|---|
| [gopel/](gopel/) | GOPEL, the Governance Orchestrator Policy Enforcement Layer: a non-cognitive enforcement layer that dispatches, collects, routes, logs, pauses, hashes, and reports, with its adapters, tests, and amendments | Reference code, version 0.6.1, not deployed |
| [Models1to3/](Models1to3/) | Alpha code for Agent Model 1 and Agent Model 2, with the checks each one passes, and a note on Agent Model 3, which has no code by design | Alpha, not deployed |

Readers who arrive from "GOPEL: The Code Behind the Policy" (February 23, 2026) will find the GOPEL reference code in [gopel/](gopel/). Its code is unchanged. Only its location and its import path moved in October 2026, when the Alpha code for the agent models joined it here.

## The three Agent Models

- **Agent Model 1** is Responsible AI: automation in which machines check machines and no human reviews an output before it goes out. The CBG Model 1 Runner is its Alpha.
- **Agent Model 2** is the hybrid in which the machine runs through to AI Governance, because a named human signs at a checkpoint after every role. The CBG Gateway is its Alpha.
- **Agent Model 3** is Manual Human AI Governance. It has no agent and no code, since the human dispatches the work, collects the answers, routes them to synthesis, and decides at every step.

## Why GOPEL and the agent models sit in separate folders

GOPEL performs zero cognitive work by design, and its static analyzer checks every file in gopel/ against that constraint. Agent Model 1 makes AI judgment calls by design, so it lives outside the folder the analyzer scans. Neither program in Models1to3/ imports GOPEL, and GOPEL imports neither program.

## Running the checks

From the repository root, for GOPEL:

```
python -m pytest haia_agent/gopel
```

Each GOPEL test file also runs on its own, for example `python haia_agent/gopel/tests/test_pipeline.py`.

From inside haia_agent/Models1to3/, for the agent models:

```
python test_cbg_model1_russell_v3.py
python test_cbg_gateway_model2_v9_1.py
python test_cbg_gateway_model2_browser_v9.py
```

On October 9, 2026, after the move, GOPEL passed all 183 of its tests, the same count its February 2026 patch reported, Agent Model 1 passed 379 checks, and Agent Model 2 passed 386 checks and 22 browser checks.

GOPEL now imports as `from haia_agent.gopel import AuditLogger`.

## The paper

The paper [HAIA Agents: From the Definition Problem to Running Code](../HAIA%20Agents%20From%20the%20Definition%20Problem%20to%20Running%20Code.docx), at the repository root, traces the path from the definition problem that opened 2026 to this code.

Basil C. Puglisi, MPA | basilpuglisi.com

#AIassisted using the HAIA Ecosystem | CC BY-NC-SA 4.0

Free for personal, educational, and noncommercial research use with attribution. Commercial exploitation, paid productization, and enterprise commercialization require separate permission and licensing.
