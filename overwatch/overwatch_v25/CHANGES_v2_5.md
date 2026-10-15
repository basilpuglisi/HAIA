# Overwatch v2.5.0: changes from v2.4

Overwatch v2.5 is Gate 1 of HAIA_Update_Plan_v3 (approved by Basil on October 14, 2026, with settlements S1 to S9). It is an add-only copy of Overwatch v2.4 (`overwatch/overwatch/`, branch `basilpuglisi-overwatch` at b19811c) in the new package `overwatch/overwatch_v25/`. No v2.4 file, v2.2 file, or committed `.pyc` file was changed.

- **Package:** the same 16 modules plus `__init__.py`, with relative imports, version 2.5.0.
- **Tests:** the 16 v2.4 test files, re-pointed from `overwatch.` to `overwatch_v25.` (import lines and module path strings only), plus 11 new test files, a fixture support module (`tests/gopel_fixture_support_v25.py`), and the committed GOPEL fixture `tests/fixtures/gopel_v063_mock_audit_v1.json`.
- **Isolation:** Overwatch v2.5 imports nothing from GOPEL, tests included. GOPEL records reach the tests only through the committed JSON fixture.

## Changes by plan step

### Steps 13 and 14a: every GOPEL record parses or alerts (`gopel_observer.py`)

- **The defect:** v2.4 read only an Overwatch-format record (`kind`, `payload`, `prev_hash`, `this_hash`). GOPEL's own audit records failed in `recompute_hash`, and `gopel_observer.py:304-308` caught the error, counted it, and emitted no alert. Records were dropped silently.
- **Versioned translation:** v2.5 adds `GOPEL_AUDIT_TRANSLATION_VERSION = "gopel-audit-translation-v1"` and `GopelRecord.from_gopel_dict()`. It reads GOPEL's record dicts:
  - lowercase `record_type` (`request`, `dispatch`, `response`, `navigation`, `arbitration`, `decision`, `system`);
  - ISO 8601 timestamps, which must carry a UTC offset;
  - flat fields, type-checked per kind.
- **Hash formulas, re-implemented here and never imported:**
  - `content_hash` is SHA-256 of the record without `content_hash`, `previous_hash`, `chain_hash`, `sequence_number` and `operator_signature`, serialized with sorted keys;
  - `chain_hash` is SHA-256 of `content_hash + previous_hash`.
- **The chain is global across the file:** `previous_hash` must equal the previous record's `chain_hash` (`"genesis"` for sequence 1), and `sequence_number` must increase by one.
- **Every record parses and validates, or raises a `VALIDATION_ERROR` alert on the channel.** The broad exception branch now alerts too. Every alert also goes to a bounded in-observer history (`get_alerts()`), so an observer without a channel manager does not lose it. Reasons include `missing_field`, `unknown_record_type`, `bad_timestamp`, `bad_type`, `bad_role`, `bad_decision`, `bad_generation_settings`, `bad_event_detail`, `content_hash_mismatch`, `chain_hash_mismatch`, `previous_hash_mismatch`, `sequence_mismatch`, `history_rewritten`, `schema_version_mismatch`, `gopel_version_mismatch`, `schema_missing`, `malformed_json` and `unexpected_error`.
- **Buffers hold a list per kind**, not one record per kind, so every dispatch and response of a transaction is inspected.
- **Finalization:** a transaction finalizes on a DECISION record, or on a SYSTEM record whose `event_type` is `overwatch_stop`, `pipeline_halted` or `total_dispatch_failure` and whose `transaction_id` names a transaction that has a REQUEST.
  - A system record written for a transaction before its request (for example `overwatch_channel_reset`) is held and joins the transaction when it starts.
  - System records with `transaction_id` `"system"` are kept in the system-record history.
- **Roles map case-insensitively** (GOPEL `"researcher"` is Overwatch `RESEARCHER`). An unknown role raises an alert instead of falling back.
- **v0.6.3 additions are accepted:**
  - `generation_settings` on dispatch and response records, which may be null;
  - `accept`, `modify` and `reject` decisions;
  - real transaction IDs on halt and stop system records;
  - `upstream_record_ids`.
- **Stop-protocol system events:** the canonical JSON details of `overwatch_stop`, `overwatch_stop_rejected`, `overwatch_stop_released` and `overwatch_channel_reset` are parsed and checked. A malformed detail raises `bad_event_detail`. A rejected stop line raises `STOP_LINE_REJECTED_BY_GOPEL`, and a channel reset raises `STOP_CHANNEL_RESET`.
- **Legacy `approve`:** a stored `approve` is read as `accept` only in the assembled view, after the record's hashes verify. The stored record is never rewritten.
- **The frozen `GopelRecord` interface changed in a versioned way:**
  - new defaulted fields: `record_format` (`overwatch.legacy.v1` or `gopel.audit.v1`), `record_id`, `sequence_number`, `content_hash`, `raw_json`;
  - new kind: `GopelRecordKind.SYSTEM`.
  - The legacy constructor and the legacy path are unchanged.
- **Read only:** the observer adds `observe_gopel_record()`, `observe_audit_document()` and `observe_audit_file()`. The last opens the audit file read only. Re-reading a grown document observes only new records, after checking that the last seen record's `chain_hash` is unchanged.

### Step 14b: receipt fields (`test_receipt_fields_v25.py`)

- **The Gate 3 test** (receipt fields visible to the observer) carries `pytest.mark.xfail(strict=True, reason="Gate 3 receipt fields")` per S9.
- **Negative cases pass:** fields not versioned into the observer stay invisible to inspection, and the hash chain still covers them.

### Step 14c: isolation (`test_isolation_v25.py`)

- `GopelRecord` is frozen, and the observer never writes back.
- The stop publisher writes only its own channel file.
- A syntax-tree scan finds zero imports of `haia_agent` or any GOPEL module across the v2.5 modules and tests.

### Step 14d: calibration record (`test_calibration_record_v25.py`)

These tests record current behavior: the Factics calibration loop is within the published v2.4 scope (R4). It adjusts only Overwatch's three trajectory thresholds within the published bounds, and it never names or touches GOPEL routing, scoring or dispatch.

### Step 14f: declared GOPEL version and schema refusal (`test_schema_version_v25.py`)

- **The expectation:** the observer takes a `GopelSchemaExpectation(gopel_version="0.6.3", audit_schema_version="1.0.0")`.
- **Schema check:** an audit document whose `schema.schema_version` differs is refused, with one `VALIDATION_ERROR` per record.
- **Version check:** GOPEL's audit file carries no GOPEL version string. The source GOPEL version is therefore declared by the caller (`source_gopel_version`, from the fixture's provenance in the tests) or taken from the signed deployment manifest's `gopel_version`. A declared version that differs is refused the same way. An undeclared version is read with one `GOPEL_VERSION_UNDECLARED` alert.

### Step 15: the timing test

`test_gopel_10000_transactions_under_5s_p99` is carried unchanged, with its 60 s and 50 ms limits. Per A7 it is reported as a failed nonfunctional requirement when it exceeds 60 s on the host, and the suite is not described as fully passing.

### Step 18: CAIPR naming (`caipr_dispatcher.py`)

- The docstrings say "Cross AI Platform Review".
- The result class is `CAIPRReviewResult`, and `CAIPRConsensus` is kept as an alias of the same class.

### Step 20: stop the pipe, route to human (`channel_manager.py`, `pipeline.py`)

- **`StopChannelPublisher`:** each stop appends exactly one line `{"body": <canonical JSON text>, "mac": <HMAC-SHA256 hex>}` followed by one `"\n"`. The file is opened with `O_APPEND`, and each write is followed by `fsync`.
  - Canonical JSON is `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`.
  - The body has exactly `schema_version` (`haia.overwatch.stop.v1`), `event_id` (uuid4 hex), `issued_at` (ISO 8601 UTC with milliseconds and `Z`), `key_id`, `target_pipeline`, `transaction_id`, `trigger`, `finding_ids` and `gopel_record_refs`.
- **When it publishes:** `OverwatchPipeline.verify_transaction()` and `inspect()` publish one stop for every outcome with `escalated=True`.
  - The trigger is `TRAJECTORY` for a trajectory alert, then `HALT`, then `CRITICAL`.
  - `finding_ids` are the structural and inspection finding IDs and, for a trajectory escalation, the trajectory alert's own `alert_id`, so a stop raised by a trajectory alert alone still names its source (M2).
  - `gopel_record_refs` are the record IDs and chain hashes of the GOPEL records the observer assembled.
  - The outcome carries `stop_event_id`.
- **Without a publisher** nothing raises, and `get_health()` reports `stop_channel: "not configured"`. A failed write is logged and counted (`stop_publish_failures`), never raised.
- **Key scope:** the stop key must be 32 bytes or more and is scoped to the stop channel only. A new `KeyScopeGuard` (`crypto.py`) refuses the same key in two scopes (stop, heartbeat, calibration, manifest, provenance).
- **Key file:** `StopChannelPublisher.from_key_file()` reads the key as hex text from a file readable only by its owner, the format GOPEL v0.6.3 reads.

### Step 21: structural inputs and the keyed manifest (`structural_verifier.py`, `models.py`, `pipeline.py`, `gopel_observer.py`)

- **The defect:** the observer passed no structural inputs into `inspect()`, so default settings escalated every GOPEL transaction as `STRUCTURAL_VERIFICATION_NOT_PERFORMED`.
- **The fix:** the observer takes `StructuralInputs(gopel_directory, deployment_manifest, active_gopel_config)` and passes them into `inspect()`, which now accepts them.
- **The signature (S1):** the deployment manifest carries a keyed signature. It is HMAC-SHA256 over the manifest's signing bytes, made through Overwatch's existing `SigningKeyProvider` with a manifest-scoped key (`set_manifest_key`).
  - The Structural Verifier verifies that signature.
  - An unsigned manifest, a re-hashed manifest, or one signed with another key is refused (CRITICAL finding).
- **With no manifest key configured,** the verifier compares the unkeyed content hash, logs the manifest as unsigned, and claims no signature. The carried outcomes do not change.
- **Content hash check:** it no longer overwrites the stored `manifest_hash` (v2.4 rewrote it, so tampering was detected only once).
- The Structural Verifier stays read-only and imports nothing from GOPEL.

### Step 22: GOPEL-mode thresholds hold (`pipeline.py`)

- **The fix:** `FacticsEngine` receives the pipeline config.
- **The effect:** the GOPEL-mode trajectory thresholds (0.2, 0.10, 0.05; paper section 6.4) hold after the first transaction. In v2.4 they reset to 0.3, 0.15 and 0.1 (`pipeline.py:73`, `:186-187`).

### Step 23: Factics persistence (`factics_engine.py`, `models.py`, `pipeline.py`)

- **Rejections:** `reject_proposal` writes to the JSONL log.
- **Reload:** the latest status of each proposal decides where it reloads: pending, approved or rejected.
  - Approved proposals reload with their chain signatures, so the chain signature library is rebuilt, and a restarted pipeline loads it into the Intent Analyzer.
  - Pending proposals keep their chain signature.
- **Timestamps:** `ChainSignature.to_dict()` now includes `cbg_confirmation_timestamp` and `created_timestamp`, and `ChainSignature.from_dict()` rebuilds a signature.
- **The pipeline** passes `proposals_log_path` (through its config).

### Step 24: version and wording

- **Versions:** `OverwatchPipeline.VERSION` and `__version__` are both "2.5.0", and every module header line reads v2.5.
- **Wording:** the `CalibrationState` docstring states the floors 0.15, 0.05 and 0.03 as calibration bounds and does not call them GOPEL-mode values.
- **No number changed.**

### Other changes made to keep carried behavior

- **Logger namespace:** `structured_logger.get_logger()` maps a versioned package name such as `overwatch_v25.pipeline` under the `overwatch` logger, so the JSON Lines handler still applies. v2.4 matched any name starting with "overwatch".
- **Two carried checks:** the carried version checks in `test_calibration_v24.py` and `test_overwatch.py` now expect "2.5.0". This is recorded in Gate 1 evidence `CHANGED_CHECKS.md`.

## R9 corrections to the published Overwatch v2.4 paper

Published works stand (R9). Each correction below ships with its fix in this version.

1. **Paragraph 77, the CAIPR expansion.**
   - The paper reads "The CAIPR Dispatcher (Consensus Across Independent Platforms Review)", and the v2.4 code read "Consensus-across-independent-platforms" (`caipr_dispatcher.py:4`).
   - CAIPR is Cross AI Platform Review. v2.5 code uses that expansion (step 18).
2. **Paragraph 121, the floor label.**
   - The paper reads "The floor is the GOPEL mode value (the tightest the system should ever run): scope drift 0.15, coherence decay 0.05, privilege gradient 0.03."
   - The GOPEL-mode thresholds are 0.2, 0.10 and 0.05 (section 6.4 table, paragraph 113). The floors 0.15, 0.05 and 0.03 are the calibration bounds, the tightest calibration may set.
   - The numbers are unchanged. The v2.5 docstring and comment no longer call the floors GOPEL-mode values (step 24).
3. **Version strings.**
   - The paper describes v2.4, but the v2.4 code reported `OverwatchPipeline.VERSION` "1.0.0" in `get_status()`. `__version__` was "2.4.0", and the module headers read v1.0, v1.1 or v2.1.
   - v2.5 reports "2.5.0" everywhere and every header reads v2.5 (step 24).
4. **The stop implementation.**
   - Sections 1, 8, 9 and 14 give Overwatch one action, stop the pipe and route to human, and section 9 says escalation to AIG mode activates GOPEL's evidence gates.
   - The v2.4 code had no stop: escalation held AIG mode and alerted (`escalation_engine.py:168-213`).
   - In v2.5 every AIG escalation publishes a signed stop line. GOPEL v0.6.3 honors it until a human releases it through the `RELEASE_OVERWATCH_STOP` evidence gate (step 20; ruling R5).
5. **The keyed manifest signature (S1).**
   - Sections 5.2 and 7.2 say the Structural Verifier compares file hashes "against signed deployment manifests".
   - The v2.4 code compared an unkeyed SHA-256 that anyone can recompute, and logged "Manifest signature verified successfully" (`structural_verifier.py:494-497`; `models.py:809-821`).
   - v2.5 verifies a keyed HMAC made with a manifest-scoped key, and with no key configured it logs the manifest as unsigned (step 21).
6. **Claims the v2.4 code did not meet, now met.**
   - **Section 5.2 (GOPEL Observer):** the observer could not read GOPEL's own audit records (steps 13 and 14a).
   - **Section 6.4:** the GOPEL-mode thresholds reset after the first transaction (step 22).
   - **Section 11.1:** the JSONL logs lost approved proposals, chain signatures and rejections on restart (step 23).
7. **Test pass rate (A7).**
   - **The claim:** sections 10 and 12 report 390 tests, 100% passing.
   - **The measurement:** on the Gate 1 host the untouched v2.4 suite gives 389 passing and 1 failing. The failure is the 10,000-transaction test, a nonfunctional requirement with a 60 s limit, which ran in 60.99 s at the start of Gate 1.
   - **The rule:** the limit is kept. The suite is not described as fully passing until that test passes or Basil changes the limit.

## Fixture

- **Source:** `tests/fixtures/gopel_v063_mock_audit_v1.json` was produced by `haia_agent/e2e/make_overwatch_fixtures_v1.py` on main (`basilpuglisi/HAIA`, source commit 7b71680, clean tree). That run used GOPEL v0.6.3 with mock adapters only.
- **Shape:** `{"provenance": {...}, "schema": ..., "records": [...]}`. Its provenance records the GOPEL version, the commit and the command.
- **Use:** the tests read the GOPEL version they expect from the provenance block, since GOPEL's audit header carries none.
