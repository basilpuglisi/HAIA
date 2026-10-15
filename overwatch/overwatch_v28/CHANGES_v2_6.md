# HAIA-Overwatch v2.6: changes

Version 2.6.0 (`overwatch_v26.__version__`, `OverwatchPipeline.VERSION`). Built on Overwatch v2.5 (`overwatch/overwatch_v25/`, unchanged) as the Overwatch step of the Team Gate in HAIA_Update_Plan_v4, approved by Basil C. Puglisi on October 14, 2026. `CHANGES_v2_5.md` is carried unchanged beside this file, because change logs go in a new file for each version.

Overwatch's single action is unchanged: stop the pipe, route to human (Overwatch v2.4, Section 14). Overwatch still imports nothing from GOPEL, tests included, reads GOPEL's audit trail read only, and writes only its own stop channel.

## 1. Watching the GOPEL both agents use (Part C5)

GOPEL v0.6.4 adds the channel through which Agent Models 1 and 2 send every AI platform call. Overwatch v2.6 reads its records:

- **Finalizing on `channel_group_closed`.** GOPEL closes each channel group and each routed Navigator turn with a `channel_group_closed` system record. v2.6 finalizes a transaction on it, as it does on a Decision record or a stop or halt record, so every agent call is inspected. Without it, an agent transaction would be dropped after its time-to-live, uninspected.
- **Its detail is checked.** The detail is canonical JSON with exactly `caller_id`, `kind`, `reason`, and `response_record_ids`. Anything else raises a `VALIDATION_ERROR` alert (`bad_event_detail`).
- **Channel Request fields.** `caller_id`, `image_sha256`, and `authority_ref` are read and carried in the transaction metadata. Images are known only by their SHA-256; GOPEL never stores them.
- **Expected GOPEL version.** `GopelSchemaExpectation` now expects GOPEL "0.6.4" by default. A document declaring another version is refused record by record, as in v2.5.
- **The fixture.** Tests read `tests/fixtures/gopel_v064_mock_audit_v1.json`, produced on main by `haia_agent/e2e/make_overwatch_fixtures_v2.py` from GOPEL v0.6.4 with mock adapters only. Its provenance names the commit and the command.

## 2. A signed deployment manifest is required (Basil's ruling X3)

Overwatch v2.4, Section 5.2, names "signed deployment manifests," and an unkeyed hash falls short of that text (S1). v2.5 still accepted an unsigned manifest by its content hash when no manifest key was configured. The Tier 0 ruling that pushed files are never rewritten moves the fix into v2.6.

- **Default.** A manifest that carries a signature, with the manifest-scoped key configured, is verified by its keyed signature (HMAC-SHA256). Every other manifest is refused: an unsigned one, and any manifest when no manifest key is configured. The refusal is the CRITICAL structural finding "Deployment manifest HMAC signature verification failed," which escalates and so stops the pipe.
- **The named local test setting, `local_test_unsigned_manifests`.**
  - It accepts an unsigned manifest by its content hash only. A changed GOPEL file is still flagged.
  - It says so at start: a WARNING beginning "LOCAL TEST SETTING".
  - `get_health()["manifest_mode"]` reports "local test: unsigned manifests accepted"; by default it reports "signed manifest required".
  - Every outcome produced while that manifest is loaded carries `manifest_status: "unsigned (local test setting)"`.
- **`VerificationOutcome.manifest_status`,** in `to_dict()`, records how the loaded manifest stood: "signed", "refused", "unsigned (local test setting)", or "" when none was checked.
- **Stop lines are unchanged.** The stop schema is fixed, and GOPEL refuses extra fields.
- **v2.4 and v2.5 and their tests are untouched (R9).** In v2.6, carried tests that relied on an unsigned manifest are moved to the local test setting, with the same expectation; `CHANGED_CHECKS_v2_6.md` lists each one.

## 3. Version and wording

- Version 2.6.0. Every module header reads v2.6. Author and license lines are carried verbatim.
- No threshold, limit, or number changed.

## 4. Tests

- New: `test_team_channel_v26.py` (7), `test_manifest_required_v26.py` (7), `test_changes_v26.py` (2).
- Before the build, against the v2.5 modules copied unchanged (tests re-pointed, fixture v0.6.4): 14 failed, 2 passed (the two guards).
- The carried checks that changed are listed in `CHANGED_CHECKS_v2_6.md`.
- The carried nonfunctional requirement `TestGopel10000TransactionsUnder5sP99` (10,000 transactions within 60 s) keeps its limit and is reported as measured (A7).
