# Agent Models 1 to 3

This folder holds the Alpha code for the HAIA Agent Models, released October 2026. Each program is a single Python file that runs on its own, and each test loads the program that sits beside it, so the files stay together.

| Agent Model | Designation | Program | Checks |
|---|---|---|---|
| 1 | Responsible AI | `cbg_model1_russell_v3.py`, the CBG Model 1 Runner | `test_cbg_model1_russell_v3.py`: 379 checks |
| 2 | Hybrid: the machine runs through to AI Governance | `cbg_gateway_model2_v9.py`, the CBG Gateway | `test_cbg_gateway_model2_v9_1.py`: 386 checks; `test_cbg_gateway_model2_browser_v9.py`: 22 checks |
| 3 | Manual Human AI Governance | None, by design | None |

## Agent Model 1: the CBG Model 1 Runner

The runner works one lane, such as a daily column, a stream of social posts, or images, with no human review of any output before it goes out. Every output carries the label "Responsible AI: automated, machine checks machine, no human review of this output." A named human signs a charter that fixes the lane, its scope, the scoring instruments, the AI platforms, the budget, the targets, and the conditions for a stop, and the runner cannot change it. Each item runs through a brainstorm, a parallel review across three or more platforms, verification, a support check, creation, code checks, and scoring, and it deploys only when every gate passes. A piece that cannot pass goes to the human, and the runner moves to the next item.

Needs `pip install httpx cryptography`. An offline run with canned platforms, search, and pages: `python cbg_model1_russell_v3.py demo`.

## Agent Model 2: the CBG Gateway

The gateway is the only program that holds the AI platform keys. It sends each RECCLIN role word for word to three to seven platforms, keeps every answer in full, and lets the named governor accept, modify, or reject each answer and each synthesis with a passkey signature made on the governor's own device. High-risk work needs a second governor's countersignature, and every release writes a signed receipt that can be checked offline.

Needs `pip install fastapi uvicorn httpx "webauthn>=3.0.1" "cryptography>=40"`. The tests also need `cbor2`, and the browser test needs Playwright with a Chromium build it can launch.

## Agent Model 3

Agent Model 3 has no agent and no code. The human dispatches the work, collects the answers, routes them to the synthesis platform, and decides at every step. It remains the default in use, and both programs in this folder were built under it.

## What Alpha means

The code runs and passes its own checks. Neither program has been deployed, neither has called a live AI provider in the build record, and neither has had a professional security review. The header of each program states what it needs, how to run it, and what it cannot do.

Basil C. Puglisi, MPA | basilpuglisi.com

#AIassisted using the HAIA Ecosystem | CC BY-NC-SA 4.0

Free for personal, educational, and noncommercial research use with attribution. Commercial exploitation, paid productization, and enterprise commercialization require separate permission and licensing.
