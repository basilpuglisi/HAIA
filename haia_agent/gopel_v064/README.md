# GOPEL v0.6.4

**Implementation of GOPEL (Governance Orchestrator Policy Enforcement Layer)**

**Author:** Basil C. Puglisi, MPA
**Architecture:** GOPEL
**Version:** 0.6.4 (`haia_agent.gopel_v064.__version__ == "0.6.4"`)
**Import path:** `haia_agent.gopel_v064`
**Entry point:** `python -m haia_agent.gopel_v064` prints the version and runs the non-cognitive static analyzer; the exit code is 0 only if the analyzer reports the package compliant.
**Built on:** GOPEL v0.6.3 (`haia_agent/gopel_v063/`), which is unchanged. v0.6.4 imports no other GOPEL version.
**License:** see `LICENSE` (carried from v0.6.2).
**Dependencies:** `requirements_v0_6_4.txt` (the same pins as v0.6.3).

Seven deterministic operations. Zero cognitive work. Every field v0.6.4 adds is deterministic.

## What v0.6.4 adds: the channel (Team Gate)

v0.6.4 is the GOPEL step of the Team Gate in HAIA_Update_Plan_v4, approved by Basil C. Puglisi on October 14, 2026, with the answers QT1 to QT11.

"Under Agent Operating Models 1 and 2, GOPEL provides the governed channel between the human governor and the AI platforms. HAIA-Agent determines how that channel is used." (Overwatch v2.4, Section 3.3)

`channel.py` exposes the seven operations one at a time, because neither agent fits the fixed shape of `execute()` (three or more platforms, then a Navigator synthesis, every time). `execute()` is unchanged.

| Operation | Channel call | Records |
|---|---|---|
| Log | `open_dispatch(caller_id, operating_model, recclin_role, messages, images, platforms)` | One Request record (`ChannelRequestRecord`) holding the canonical JSON of the frozen messages, the caller, and the SHA-256 of each image. Images are never stored. |
| Dispatch, Collect | `dispatch(group, platform_id)` | A Dispatch record and a Response record for that platform. The reply comes back unaltered. |
| Route | `route(caller_id, operating_model, navigator, messages, upstream_response_ids)` | Request, Dispatch, Response, and a Navigation record holding the Navigator's text unaltered. |
| Log | `close(group, reason)`, or automatically when every platform has answered or on a stop | One `channel_group_closed` system record listing the group's Response record IDs. Overwatch finalizes a transaction on it. |
| Pause | every operation | The Overwatch stop intake is checked before the group or turn (a), before each platform call (b), and after collecting (c). A call already in flight is logged; its text is withheld from the caller. |
| Hash | the audit logger | Unchanged hash chain. |
| Report | `status(at_seq)` | Instance ID, version, whether the stored chain verifies, the head, the chain hash at a sequence number, active stops, releases. IDs and hashes only, never text. |

- **Identical prompts by construction.** `dispatch` takes no prompt. Every dispatch in a group sends the group's frozen messages, so every Dispatch record in it carries the same `prompt_hash`.
- **The agent decides, the channel does not.** The caller names the platforms, the messages, and the Navigator. The channel has no platform-count rule; each agent keeps its own.
- **Message adapters** (`adapters/message_adapter.py`): `MessageAdapter`, `CallableMessageAdapter` (wraps a call supplied by the process that hosts GOPEL, where provider keys are read), and `MessageMockAdapter` (tests).
- **Hosting (QT1 C, QT2 b).** In deployment, GOPEL is hosted in the Agent Model 2 gateway process, which alone holds the provider keys, as paper v1.4, Section 7.1, and Threat Model v3, deployment requirements 1 and 2, state. In this release both agents share one channel inside one process; the network path from Agent Model 1 to the gateway-hosted channel is deferred to a later session.
- **Static analyzer.** `channel.py` joins the scan list. A new test fails if any module outside `adapters/` and `tests/` is left unscanned (the analyzer itself excepted, since it holds the patterns it searches for).
- **Tests.** `tests/test_v064_channel.py` (19) and `tests/test_v064_scan_coverage.py` (2). Before the build, against an unchanged copy of v0.6.3: 20 failed, 1 passed (the coverage guard). After: 297 passed (276 carried, 21 new); the analyzer scans 16 files, 0 violations. Carried checks that changed are listed in `CHANGED_CHECKS_v0_6_4.md`.

The sections below describe v0.6.3 and remain true of v0.6.4.

## What changed in v0.6.3, and why

v0.6.3 is Gate 1 of HAIA_Update_Plan_v3, approved by Basil C. Puglisi on October 14, 2026, with settlements S1 to S9. The step numbers below are the plan's.

### Step 16. Decision terms: accept, modify, reject (addendum 8)

- `ArbitrationDecision` values are `"accept"`, `"modify"`, `"reject"`. v0.6.2 used `"approve"`, and `"accept"` raised.
- `ArbitrationDecision.APPROVE` stays as an alias of `ACCEPT` (same value), so code written against v0.6.2 runs and writes `"accept"`. v0.6.3 never writes `"approve"`.
- A stored v0.6.2 `"approve"` is read as `"accept"` only through `logger.read_verified_records`, `logger.read_audit_file`, or `AuditLogger.read_records()`. These verify every stored record against the hash chain first (content_hash, previous_hash link, chain_hash), raise `ChainIntegrityError` on any violation without mapping anything, and then return copies with the mapped term. Stored bytes are never rewritten.
- Governance metrics report `accept_count` and `accept_rate`. `approve_count` and `approve_rate` remain as legacy alias keys with the same values. A stored `"approve"` counts as accept only if its record verifies; otherwise it counts in `unverified_legacy_count`.

### Step 17. The Decision Record links every upstream record

`DecisionRecord.upstream_record_ids` lists, in chain order, every request, dispatch, response, navigation, and arbitration record ID of the transaction, in both `GOPELPipeline.record_arbitration` and `SecureGOPELPipeline.record_arbitration` (`AuditLogger.get_upstream_record_ids`). v0.6.1 and v0.6.2 wrote an empty list.

### Step 20. Stop the pipe, route to human (R5; S5; S6; addendum 1 and 2)

New module `overwatch_stop.py` (`OverwatchStopChannel`). It is in the static analyzer's scan targets.

- **The channel.** Overwatch v2.5 owns and writes a channel file, one JSON line per stop. GOPEL opens it read only. Each line is `{"body": "<canonical JSON text>", "mac": "<lowercase hex HMAC-SHA256>"}`. Canonical JSON is `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`.
- **Verification.** GOPEL recomputes HMAC-SHA256 over the exact received body bytes with its single stop-channel key and compares with `hmac.compare_digest`. It refuses a non-canonical body. It holds exactly one stop key (`key_id`, at least 32 bytes) and accepts no other key (S6). `load_stop_key_file` refuses a key file readable by anyone but its owner (mode 0600).
- **Rejection reasons**, checked in this order: `malformed`, `schema`, `non_canonical`, `wrong_key_id`, `bad_mac`, `wrong_pipeline`, `replay`.
- **Replay.** Refused by consumed event ID only, which the MAC covers. A valid stop is accepted whatever its `issued_at` relative to any release (S5).
- **Durable state.** Active stops, consumed event IDs, the SHA-256 of every rejected line, the releases, and the channel read position are written atomically (temporary file in the same directory, flush, `os.fsync`, `os.replace`, `fsync` of the directory) and loaded at construction, so an active stop survives a restart. A state file that cannot be read fails closed: the channel, and so the pipeline, cannot be constructed.
- **Check points,** in both `GOPELPipeline` and `SecureGOPELPipeline`: (a) at the start of `execute()` and before each adapter dispatch; (b) before finalization, that is before the Navigator synthesis and again before the checkpoint package; (c) before `record_arbitration`, which then returns `False` and writes neither record.
- **Work in flight.** A dispatch already in progress completes and its Dispatch and Response records are written. No further dispatch starts and no checkpoint package is produced. The result has `success=False`, `stopped_by_overwatch=True`, `active_stop_event_ids`, and an `error` starting `STOPPED_BY_OVERWATCH` that lists the active event IDs.
- **Release.** `release_overwatch_stop(human_operator_id, stop_event_ids, evidence, governance_runtime)` (on the channel and on both pipelines) authorizes through `GovernanceRuntime.authorize(GovAction.RELEASE_OVERWATCH_STOP, ...)`. `RELEASE_OVERWATCH_STOP_GATE` is built like `CIRCUIT_BREAKER_OVERRIDE_GATE`: a justification (50 or more characters), a risk statement (30 or more), and a second approver. When the runtime holds an operator registry, the second approver must sign the SEC-03 payload bound to `release_binding_id(stop_event_ids)` and to the gate name, so the signature releases exactly the named stops. The gate applies even when a deployment registers no gate for the action. Only the named active stops are cleared. A release is refused with no governance runtime, with no stop named, when any named stop is not active, or when authorization is denied. Governance officers and administrators hold the action by default; analysts do not.
- **`acknowledge_breach`** never clears an Overwatch stop.
- **No Overwatch.** With no channel configured (`overwatch_stop=None`, the default), or when the channel file does not exist, GOPEL runs normally.

### Step 25. Two v0.6.2 fixes wired

- **SEC-03.** `GovernanceRuntime.authorize` takes `transaction_id` and passes it into `EvidenceGate.check`, so a second approver's signature verifies only for the transaction it was made for. `SecureGOPELPipeline` passes the transaction ID when it authorizes execution and arbitration.
- **SEC-06.** `SecureAuditLogger` takes `witness_hmac_key` and passes it to `HashWitness`, so the witness file carries an HMAC and a tampered witness file is refused on load.

### Step 26. Adapter repair (addendum 15) and the temperature change (S2, Q6 Option A)

- **Pins** in `requirements_v0_6_3.txt`: `anthropic>=1.13,<2`, `openai>=3.30,<4`, `google-genai>=2.30,<3`, with `pydantic>=2.14` and `cryptography>=50.0.2`.
- **No default model.** `AnthropicAdapter`, `OpenAIAdapter`, and `GoogleAdapter` raise `ValueError` when constructed without a model. v0.6.2 defaulted to `claude-sonnet-4-5-20250929`, `gpt-4o`, and `gemini-2.0-flash`.
- **Temperature (S2).** v0.6.2 sent `temperature=0.7` to every adapter by default (`secure_pipeline.py` CONFIG_BOUNDS and the adapter signatures). v0.6.3 sends no temperature unless the operator sets one, and each provider's own default applies. An explicit temperature is refused, before any SDK call, where the SDK or the configured model does not accept it: always for Anthropic (the Anthropic SDK 1.x `messages.create` has no temperature parameter), and for OpenAI or Google models configured with `accepts_temperature=False`. The refusal is recorded as an error response whose detail starts `UNSUPPORTED_CONFIGURATION`. Cost: OpenAI and Google calls that used to receive 0.7 by default now use the provider's default.
- **Anthropic:** `messages.create(model, max_tokens, messages, system if given)`.
- **OpenAI:** `chat.completions.create` with `max_completion_tokens`; temperature only if set.
- **Google:** moves from the deprecated `google-generativeai` to `google-genai`: `Client(api_key).models.generate_content(model, contents, config=types.GenerateContentConfig(...))`. The provider's real `response_id` is recorded as `api_confirmation`, replacing the timestamp-based value.
- **Incomplete responses are not success.** Anthropic stop reasons other than `end_turn` or `stop_sequence` (for example `max_tokens` or `refusal`), an OpenAI `finish_reason` other than `stop` or any refusal, and a Google finish reason other than `STOP` give `success=False` with an `INCOMPLETE_RESPONSE` detail. The text received is kept verbatim.
- **Records (S2c).** Dispatch and Response records carry `generation_settings`: `{"model", "max_tokens", "temperature", "temperature_source"}`, where `temperature_source` is `"operator"` or `"provider_default"`.
- **Why the defaults went.** Anthropic retires `claude-sonnet-4-5-20250929` on November 30, 2026, and names `claude-sonnet-5-5` as its replacement. Google has deprecated `google-generativeai` since November 30, 2025, and points to `google-genai`. v0.6.3 names no model at all; the operator sets one in configuration.
- The adapters were tested against stand-in SDK modules only. Live testing needs separate authorization.

### Step 27. Packaging (addendum 7)

v0.6.1 (`haia_agent.gopel`), the v0.6.2 base (`haia_agent.gopel_v062`), and v0.6.3 (`haia_agent.gopel_v063`) each have their own import path. Importing and running v0.6.3 loads no module from the other two (tested in a separate process). `__main__.py` is the entry point.

## Records a consumer will see

- **Dispatch and Response:** `generation_settings` (above). It is `null` only on a record logged directly through `AuditLogger.log_dispatch` or `log_response` without it; both pipelines always set it.
- **Arbitration:** `arbitration_decision` is `"accept"`, `"modify"`, or `"reject"`.
- **Decision:** `upstream_record_ids` is filled.
- **System records carrying the real `transaction_id`** (or `"system"` when no transaction is in progress): `overwatch_stop` (severity `critical`; detail is canonical JSON `{"body", "line_sha256", "mac", "received_at"}`), `overwatch_stop_rejected` (severity `warning`; detail `{"line_sha256", "reason", "received_at"}`), `total_dispatch_failure`, `pipeline_halted`. `overwatch_stop_released` (severity `info`; detail `{"release_id", "cleared", "operator_id", "evidence_ids", "released_at", "binding_id", "gate_passed", "evidence"}`) carries `"system"`. `overwatch_channel_reset` (severity `warning`) is written if the channel file shrinks or its already-read part changes.
- `AuditLogger.log_system_event` takes an optional `transaction_id` (default `"system"`).

## Test results (measured)

Python 3.13.16, pytest 9.1.1, pydantic 2.14.1, cryptography 50.0.2. Provider SDKs not installed; stand-in modules only. Run with `PYTHONDONTWRITEBYTECODE=1 python -m pytest -p no:cacheprovider` from the repository root.

| Suite | Result |
|---|---|
| GOPEL v0.6.2 base, `haia_agent/gopel_v062/tests` | 218 passed |
| GOPEL v0.6.3, `haia_agent/gopel_v063/tests` | 276 passed, 0 skipped |
| of which carried from v0.6.2 (10 files) | 218 passed |
| of which new: `test_v063_decision_terms.py` | 3 passed |
| `test_v063_upstream_links.py` | 2 passed |
| `test_v063_overwatch_stop.py` | 32 passed |
| `test_v063_wiring.py` | 3 passed |
| `test_v063_adapters.py` | 14 passed |
| `test_v063_packaging.py` | 4 passed |
| Both base and v0.6.3 suites in one session | 494 passed |
| Non-cognitive static analyzer on `haia_agent/gopel_v063` | 15 files scanned, 0 violations, compliant |

One carried check changed its expectation: `test_v061_fixes.py::TestVersionBump::test_version_is_0_6_2` now expects `"0.6.3"` (the version bump of this release). No other carried test line differs from v0.6.2 except the import path.

## Corrections to published statements (R9)

- **Version line.** The README published with the v0.6.2 code (`gopel-v062-locked/README.md`, carried byte-identical as `haia_agent/gopel_v062/README.md`) is the v0.6.1 README text. Its version line reads `**Version:** 0.6.1` and it reports 183 tests, while the v0.6.2 code declares `__version__ = "0.6.2"` and its suite measures 218 passed. This README states version 0.6.3 and the counts measured above.
- **"The Decision Record links the final authorized output to every upstream record in the chain."** The v0.6.1 README (`haia_agent/gopel/README.md`, line 100) makes this claim. In v0.6.1 and v0.6.2 both pipelines wrote `upstream_record_ids=[]` (`pipeline.py:319` in both; `secure_pipeline.py:988` in v0.6.1 and `:989` in v0.6.2). v0.6.3 meets the claim in code (step 17).

## What did not change

`breach.py`, `navigator.py`, `navigator_validator.py`, `security.py`, `selector.py`, and `sentinel.py` are byte-identical to v0.6.2. `MockAdapter` keeps its `"mock-v1"` default model: it is a test stand-in with no provider behind it, and the carried suites construct it without a model.
