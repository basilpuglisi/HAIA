# HAIA Agents, README v2

This README describes the agent layer after the Team Gate of HAIA_Update_Plan_v4, approved by Basil C. Puglisi on October 14, 2026. `README.md` beside it describes the folder as first published, with GOPEL v0.6.1 and the first agent programs, and stays as published. Each GOPEL version keeps its own folder, and no earlier version was changed.

| Folder | What it holds | Checks on host C, October 14, 2026 |
|---|---|---|
| [gopel/](gopel/) | GOPEL v0.6.1, the reference code of "GOPEL: The Code Behind the Policy" (February 23, 2026), unchanged | 183 passed |
| [gopel_v062/](gopel_v062/) | GOPEL v0.6.2 from `gopel-v062-locked` on the `basilpuglisi-overwatch` branch: modules and documents byte for byte, tests changed only in their import lines (Gate 1) | 218 passed |
| [gopel_v063/](gopel_v063/) | GOPEL v0.6.3: the Overwatch stop intake and its human release through an evidence gate, versioned records, and generation settings (Gate 1) | 276 passed; analyzer 15 files, 0 violations |
| [gopel_v064/](gopel_v064/) | GOPEL v0.6.4, current: the channel through which Agent Models 1 and 2 send every AI platform call, with message adapters (the Team Gate) | 297 passed; analyzer 16 files, 0 violations |
| [Models1to3/](Models1to3/) | Agent Model 1 (runner v3, v4, v5) and Agent Model 2 (gateway v9, v10, v11); see `Models1to3/README_v2.md` | see that README |
| [e2e/](e2e/) | The end-to-end suites: v1 (GOPEL v0.6.3 and Overwatch v2.5) and the team suite v1 (GOPEL v0.6.4, Overwatch v2.6, and both agents), with their pins and the Overwatch fixture generators | v1: 13 passed; team: 26 passed |

## How the parts fit together now

GOPEL v0.6.4 is the governed channel between the agents and the AI platforms. Agent Model 2's gateway hosts it in its own process, and the provider connections are GOPEL's adapters there, so the keys stay in the gateway's process. Agent Model 1 v5 and Agent Model 2 v11 import GOPEL v0.6.4 and send every AI platform call through it. GOPEL imports neither agent, and its static analyzer scans every GOPEL v0.6.4 module but the analyzer itself; Agent Model 1, which makes AI judgment calls by design, stays outside the folder the analyzer scans. Overwatch v2.6, on the `claude/overwatch-v25` branch, reads GOPEL's audit trail read only, imports nothing from GOPEL or the agents, and has one action: stop the pipe, route to human. A human releases a stop through GOPEL's evidence gate.

The team suite shows the whole loop: one Overwatch stop holds Agent Model 2's open tasks and freezes Agent Model 1; one human release resumes GOPEL and Agent Model 2; Agent Model 1 resumes on its governor's signed resume, dated after that release; and every record verifies offline.

## Finding T-1, for Basil's ruling

Overwatch v2.6 at its published defaults stops the pipe on Agent Model 1's clean item: it reads any web address in an answer as a network operation, and Agent Model 1's gates need sources named by web address. The team suite asserts this rather than hiding it; `Models1to3/README_v2.md` gives the detail. No code was changed for it.

## Not yet routed through GOPEL

Agent Model 1's image tool, a local program a charter may name, is not yet routed through GOPEL.

## Deferred to a later session

- Agent Model 1's network path to the gateway-hosted GOPEL (Part E step 6). In this release both agents share one GOPEL channel inside one process.
- Gates 2 to 4 of HAIA_Update_Plan_v4.

## Running the checks

From the repository root:

```
python -m pytest haia_agent/gopel_v064/tests
python -m haia_agent.gopel_v064
HAIA_OVERWATCH_TEAM_TREE=<checkout of the Overwatch commit in e2e/overwatch_pin_team_v1.json> \
    PYTHONDONTWRITEBYTECODE=1 python -m pytest -p no:cacheprovider haia_agent/e2e/test_e2e_team_v1.py
```

The earlier GOPEL versions run the same way from their own folders, and `e2e/test_e2e_gopel_overwatch_v1.py` runs with `HAIA_OVERWATCH_TREE` naming the commit in `e2e/overwatch_pin_v1.json`. Every count above was taken in one run on one host, in one sequence, with outbound network blocked (host C: 4 vCPU Intel(R) Xeon(R) Processor @ 2.10GHz, 16 GB, Linux 6.18.44, Python 3.13.16). The container was re-provisioned during the build: Gate 1's counts were taken when it reported a Xeon @ 2.80GHz, and every Team Gate count, before and after, comes from the host named here.

Alpha: nothing here is deployed, every test uses mock or canned platforms, and live provider testing is not authorized yet.

Basil C. Puglisi, MPA | basilpuglisi.com

#AIassisted using the HAIA Ecosystem | CC BY-NC-SA 4.0

Free for personal, educational, and noncommercial research use with attribution. Commercial exploitation, paid productization, and enterprise commercialization require separate permission and licensing.
