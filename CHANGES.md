# HAIA-Overwatch Changelog

## v2.2 — `__slots__` Optimization and Type Hint Completion

**Author:** Basil C. Puglisi, MPA
**Date:** 2026-05-09
**License:** CC BY-NC 4.0
**Attribution:** #AIassisted under HAIA-RECCLIN & Checkpoint-Based Governance

This release completes the two remaining deferred items from the Kimi v1.9 audit: `__slots__` optimization for all dataclasses (MEDIUM priority) and type hints for all public API methods (LOW priority). The `__slots__` migration exposed and fixed a latent bug in `factics_engine.py`.

### `__slots__` Optimization (22 dataclasses)

Added `slots=True` to all 22 dataclasses across 6 modules, reducing per-instance memory by ~30-40% and enabling faster attribute access. Python 3.10+ `@dataclass(slots=True)` is used throughout.

| Module | Dataclasses |
|--------|-------------|
| `models.py` | ProvenanceTag, DeclaredTaskScope, TransactionRecord, PlatformResponse, InspectionFinding, StructuralFinding, VerificationOutcome, ChainSignature, RoleBehaviorEnvelope, GraphNode, GraphEdge, ExecutionGraph, RandomAuditReport, FacticsRecord, RuleProposal, DeploymentManifest, OverwatchConfig, Heartbeat |
| `gopel_observer.py` | GopelRecord (frozen+slots) |
| `channel_manager.py` | ChannelMessage (frozen+slots) |
| `intent_analyzer.py` | IntentSnapshot |
| `escalation_engine.py` | EscalationState |
| `caipr_dispatcher.py` | CAIPRConsensus |
| `structural_verifier.py` | BehavioralBaseline, BehavioralSample |

### Bug Fix: FacticsEngine Dynamic Attribute Assignment

The `__slots__` migration exposed a latent bug in `factics_engine.py` where `approve_proposal()` and `reject_proposal()` wrote to undeclared attributes (`proposal.approval_timestamp`, `proposal.approval_rationale`, `proposal.rejection_timestamp`, `proposal.rejection_rationale`). Without `__slots__`, Python silently created these as ad-hoc `__dict__` entries, meaning the actual `RuleProposal` fields (`rule_approval_timestamp`, `rule_approval_rationale`) were never populated. Fixed by correcting to the declared field names.

### Type Hint Completion

Audited all public methods across 15 modules. Only one missing annotation found and fixed: `pipeline.py: attach_gopel_observer(observer)` now typed as `attach_gopel_observer(observer: Any)`.

### Test Compatibility Fixes

Four test helper methods in `test_v11_new_modules.py` used `record.__dict__.copy()` on `GopelRecord` to reconstruct frozen instances. Since `GopelRecord` is now `frozen=True, slots=True`, `__dict__` no longer exists. Replaced with explicit field-by-field reconstruction.

### Test Scorecard (329 total, 0 regressions)

| Suite | Tests | Status |
|-------|-------|--------|
| All suites (v1.0 through v2.1) | 329 | ALL PASS |

### Deferred Items

None. All items from the Kimi v1.9 Comprehensive Test & Audit Report have been implemented.

---

## v2.1 — Structured Logging Migration

**Author:** Basil C. Puglisi, MPA
**Date:** 2026-05-09
**License:** CC BY-NC 4.0
**Attribution:** #AIassisted under HAIA-RECCLIN & Checkpoint-Based Governance

This release completes the structured logging migration identified as HIGH priority by Kimi's v1.9 Comprehensive Test & Audit Report. All 7 modules with logging are migrated from ad-hoc `logging.getLogger()` calls with f-string formatting to a centralised JSON Lines structured logger. The 3 duplicate `_sanitize_log()` helper functions are consolidated into a single shared module.

### New Module: `structured_logger.py`

Central structured logging facility providing:
- `sanitize_log_value()`: consolidated log injection prevention (replaces 3 module-level duplicates)
- `JSONLinesFormatter`: formats log records as single-line JSON with fields: timestamp, level, module, event, extras, exception
- `get_logger(name)`: factory that returns loggers under the `overwatch.*` namespace with the JSON Lines handler auto-installed on first call

### Source Changes (8 files modified, 1 file created)

| File | Changes |
|------|---------|
| `structured_logger.py` | **NEW**: Centralised JSON Lines formatter, `sanitize_log_value()`, `get_logger()` factory |
| `gopel_observer.py` | Removed local `_sanitize_log()`, removed `import logging`; imports from `structured_logger` |
| `channel_manager.py` | Removed local `_sanitize_log()`, removed `import logging`; imports from `structured_logger` |
| `pipeline.py` | Removed local `_sanitize_log()`, removed `import logging`; imports from `structured_logger` |
| `execution_graph.py` | Removed `import logging`; imports from `structured_logger`; 2 f-string log calls converted to %s format with sanitisation |
| `escalation_engine.py` | Removed `import logging`; imports from `structured_logger`; 2 f-string log calls converted to %s format with sanitisation |
| `caipr_dispatcher.py` | Removed `import logging`; imports from `structured_logger`; 2 f-string log calls converted to %s format with sanitisation |
| `structural_verifier.py` | Removed `import logging`; imports from `structured_logger`; 8 f-string log calls converted to %s format with sanitisation |
| `__init__.py` | Version bumped to 2.1.0; exports `get_logger` and `sanitize_log_value` |

### Migration Summary

- **Modules migrated:** 7 (gopel_observer, execution_graph, escalation_engine, channel_manager, caipr_dispatcher, structural_verifier, pipeline)
- **Log call sites migrated:** ~22
- **Duplicate helpers eliminated:** 3 (gopel_observer, channel_manager, pipeline each had identical `_sanitize_log()`)
- **f-string log calls converted:** 14 (all replaced with %-format + sanitise)
- **Backward compatibility:** Module-level `_sanitize_log` name preserved via import alias for any code importing it from original modules

### Test Scorecard (39 new tests, 329 total)

| Suite | Tests | Status |
|-------|-------|--------|
| `test_structured_logging_v21.py` | 39 | ALL PASS |
| All existing suites (v1.0 through v2.0) | 290 | ALL PASS |

### Test Coverage

- `TestSanitizeLogValue` (8 tests): ANSI stripping, null bytes, newlines, tab preservation, truncation, clean passthrough, complex ANSI, DEL character
- `TestJSONLinesFormatter` (10 tests): valid JSON output, required fields, level mapping, module field, %-format message, extras collection, no-extras omission, single-line guarantee, exception info, ISO-8601 timestamp
- `TestGetLogger` (4 tests): namespace prefixing, auto-prefix bare names, no double-prefix, handler installation
- `TestModuleMigration` (8 tests): each of 7 modules imports from structured_logger, none calls logging.getLogger() directly
- `TestNoFStringLogging` (4 tests): execution_graph, escalation_engine, caipr_dispatcher, structural_verifier have no f-string log calls
- `TestLogOutputIntegration` (2 tests): actual JSON Lines output is parseable, sanitised values produce clean output
- `TestExportedFromPackage` (3 tests): get_logger and sanitize_log_value exported, version bumped to 2.1.0

### Deferred Items

- `__slots__` optimisation for high-frequency dataclasses (Kimi MEDIUM)
- Type hints for all public API methods (Kimi LOW)

---

## v2.0 — Consolidated Cross-Platform Hardening (Gemini + Kimi + Claude)

**Author:** Basil C. Puglisi, MPA
**Date:** 2026-05-08
**License:** CC BY-NC 4.0
**Attribution:** #AIassisted under HAIA-RECCLIN & Checkpoint-Based Governance

This release implements 8 hardening items identified through CAIPR cross-platform review by Gemini (Engineering Stress Test & Vulnerability Report) and Kimi (Comprehensive Test & Audit Report), triaged by Claude (Navigator role). All items are additive security and production-readiness improvements. One latent bug was fixed (ProvenanceManager tier comparison logic was inverted).

### Source Changes (7 files modified)

| File | Changes |
|------|---------|
| `models.py` | Added `TIER_UNTRUSTED = 3` to TrustTier; `ProvenanceTag.is_expired()` returns True for TIER_UNTRUSTED; config `validate()` adds 6 new bounds checks; `__post_init__` gopel_mode caps `code_integrity_check_interval_seconds` at 300s |
| `provenance_manager.py` | Default for unknown sources changed from TIER_2 to TIER_UNTRUSTED; tier comparison logic corrected (lower value = higher authority) |
| `gopel_observer.py` | Added `threading.RLock` protecting `observe()` and `flush_stale()`; broadened exception catch from `ChainValidationError` to `Exception`; added `_sanitize_log()` for log injection prevention |
| `channel_manager.py` | Added `MAX_DELIVERY_FAILURES = 1000` FIFO cap; added `_sanitize_log()` |
| `execution_graph.py` | Added `prune_stale(max_age_seconds)` for TTL-based graph eviction |
| `output_state_evaluator.py` | Added `_normalize_for_detection()` pre-pass collapsing string concatenation, `chr()` sequences, `getattr(__import__())`, and `__import__()` before regex scan |
| `pipeline.py` | Wrapped `correlate_cross_operator()` temp window in `try/finally`; added `_sanitize_log()` |
| `structural_verifier.py` | Added `random.uniform(-60, 60)` jitter to code integrity check scheduling |

### Bug Fix: ProvenanceManager Tier Comparison

The original tier authority comparison allowed sources to REQUEST higher authority tiers (lower enum values) than their registration. For example, a TIER_2 source could issue TIER_0 tags. The corrected logic enforces: sources can request their authorized tier or any LOWER authority tier (higher enum value). Two existing tests updated to match corrected behavior.

### Test Scorecard (38 new tests, 290 total)

| Test Class | Tests | Category | Source |
|------------|-------|----------|--------|
| TestTierUntrusted | 6 | Governance | Gemini |
| TestGopelObserverThreadSafety | 3 | Thread safety | Kimi |
| TestBoundedMemory | 3 | Scalability | Gemini |
| TestStringNormalization | 8 | Security | Gemini+Claude |
| TestConfigValidationBounds | 7 | Config safety | Kimi |
| TestCrossOperatorCleanup | 2 | Exception handling | Kimi |
| TestGopelModePollingInterval | 3 | TOCTOU mitigation | Gemini+Claude |
| TestLogSanitization | 6 | Log injection | Kimi |
| **Total new** | **38** | | |
| **Total suite** | **290** | **100% PASS** | |

### Items Deferred to v2.1

- Full structured logging migration (Kimi HIGH) — larger scope
- `__slots__` optimization for high-frequency dataclasses (Kimi MEDIUM) — Python 3.10+ validation needed
- Full AST parsing in OutputStateEvaluator (Gemini majority view) — CAIPR platform responsibility per minority dissent
- Async fsync in RandomAuditGenerator (Gemini) — monitor only, low audit cadence
- Type hints for public APIs (Kimi LOW) — ongoing housekeeping

---

## v1.4–v1.9 — Grok Spec Implementation (Supply Chain through Governance Invariants)

**Author:** Basil C. Puglisi, MPA
**Date:** 2026-05-08
**License:** CC BY-NC 4.0
**Attribution:** #AIassisted under HAIA-RECCLIN & Checkpoint-Based Governance

This release implements all 34 tests specified in the Grok v1.4–v1.9 implementation log. After deduplication against existing v1.0–v1.3 coverage, 44 new test methods were built across 6 test files. One minimal feature fix was applied (per-line error handling in JSONL rehydration). All other tests validate existing behavior.

### v1.4 — Supply Chain, Persistence & Observability (7 tests)

| Test | Status |
|------|--------|
| test_malicious_gopel_manifest_with_symlink_bomb_or_oversized_file | PASS |
| test_factics_persistence_after_crash_during_rehydration | PASS |
| test_cross_operator_correlation_respects_operator_isolation | PASS |
| test_gopel_observer_emits_structured_metrics_for_external_monitoring | PASS |
| test_gopel_record_with_null_bytes | PASS |
| test_gopel_record_with_zero_width_characters | PASS |
| test_gopel_record_with_surrogate_characters | PASS |

### v1.5 — Manifest Tampering & Mixed Traffic (4 tests)

| Test | Status |
|------|--------|
| test_malicious_manifest_with_tampered_cbg_signature | PASS |
| test_manifest_verify_with_wrong_key | PASS |
| test_high_volume_gopel_traffic_with_mixed_clean_and_malicious | PASS |
| test_observer_statistics_update_correctly_after_mixed_operations | PASS |

### v1.6 — Trust Boundary, Evasion & Multi-GOPEL Isolation (10 tests)

| Test | Status |
|------|--------|
| test_gopel_record_is_frozen | PASS |
| test_pipeline_has_no_gopel_write_methods | PASS |
| test_observer_only_reads_records | PASS |
| test_all_fields_are_frozen | PASS |
| test_assemble_transaction_deep_copies_payload | PASS |
| test_hidden_directive_in_code_comment | PASS |
| test_credential_access_pattern_in_response | PASS |
| test_separate_gopel_instances_do_not_interfere | PASS |
| test_partial_caipr_failure_still_produces_outcome | PASS |
| test_structured_finding_contains_correlation_id | PASS |

### v1.7 — Chaos, Drift & Compliance (8 tests)

| Test | Status |
|------|--------|
| test_pipeline_survives_random_platform_timeouts | PASS |
| test_structural_verifier_handles_missing_gopel_directory | PASS |
| test_behavioral_drift_detection_over_time | PASS |
| test_compromised_cbg_release_still_requires_validation | PASS |
| test_overwatch_never_escalates_without_evidence | PASS |
| test_escalation_invariant_holds_across_many_transactions | PASS |
| test_transaction_never_mutates_original_gopel_record | PASS |
| test_random_audit_report_is_siem_friendly | PASS |

### v1.8 — Cryptographic Assurance, Governance & Scale (6 tests)

| Test | Status |
|------|--------|
| test_detects_inconsistent_platform_responses | PASS |
| test_critical_stays_pending_with_default_config | PASS |
| test_advisory_auto_approved_when_enabled | PASS |
| test_critical_stays_pending_even_with_auto_approve_enabled | PASS |
| test_sustained_gopel_load_performance | PASS |
| test_audit_report_contains_required_compliance_fields | PASS |

### v1.9 — Governance, Explainability & Adaptive Defense (9 tests)

| Test | Status |
|------|--------|
| test_critical_findings_always_require_human_approval | PASS |
| test_findings_contain_actionable_evidence | PASS |
| test_correlates_with_known_attack_patterns | PASS |
| test_false_positives_increase_kpi | PASS |
| test_approved_proposals_increase_detection_coverage | PASS |
| test_severity_ordering_is_consistent | PASS |
| test_transitivity | PASS |
| test_transaction_id_is_always_preserved | PASS |
| test_transaction_id_preserved_for_malicious_transactions | PASS |

### Feature Change

**factics_engine.py** — Per-line error handling in `_rehydrate_proposals()`: moved JSONDecodeError catch from outer loop to inner per-line scope, enabling graceful degradation when JSONL logs contain truncated lines from crash scenarios.

### Grok Recommendations Addressed

| Recommendation | Status |
|----------------|--------|
| Full Factics JSONL persistence | Already implemented (v1.2) |
| Complete correlate_cross_operator() | Already implemented (v1.3) |
| Strengthen advanced evasion detection | Already implemented (v1.3 decode_and_rescan) |
| Improve evidence quality | Validated (v1.9 actionable evidence test) |
| Key rotation support | Already implemented (v1.1.1 crypto.py) |
| Behavioral drift detection | Validated (v1.7 drift test via existing envelopes) |
| External threat intel correlation | Validated (v1.9 chain signature correlation test) |

**Total suite: 252 tests, 100% passing** (59 v1.0 + 76 new modules + 37 review fixes + 19 red-team + 8 v1.2 + 9 v1.3 + 44 v1.4–v1.9)

---

## v1.3.0 — Obfuscation Detection, Persistence Stress, Cross-Operator Correlation

**Author:** Basil C. Puglisi, MPA
**Date:** 2026-05-08
**License:** CC BY-NC 4.0
**Attribution:** #AIassisted under HAIA-RECCLIN & Checkpoint-Based Governance

This release closes three real adversarial gaps in the observation layer. All changes preserve the non-interference invariant.

### New Features

**Obfuscation Decode and Rescan (context_inspector.py)** — New `_decode_and_rescan()` method automatically detects base64 blocks (64+ chars) and hex blocks (32+ chars) in scanned content, attempts decoding, and re-runs all directive patterns against decoded payloads. Obfuscated directives are flagged CRITICAL with "obfuscated_directive" evidence. Prevents encoded "ignore previous instructions" or "SYSTEM OVERRIDE" payloads from evading the context inspector.

**Factics Proposal Deduplication (factics_engine.py)** — Upgraded `_rehydrate_proposals()` to deduplicate by proposal_id during JSONL log replay. Builds a proposal_map tracking the latest status per proposal_id, ensuring approved proposals do not reload as pending after restart. Stress tested at 500 proposals with < 2s rehydration.

**Cross-Operator Correlation (pipeline.py)** — New `correlate_cross_operator()` method merges intent windows from multiple operator_ids, sorts by timestamp, and runs scope trajectory and privilege gradient checks on the combined window. Detects multi-turn attacks split across separate operator sessions to evade per-operator windowing. Findings tagged with "[CROSS-OPERATOR]" and include correlated operator names in evidence chain. Temporary correlation state is cleaned up after analysis.

### v1.3 Test Scorecard

| Test | Status |
|------|--------|
| test_base64_encoded_directive_detected | PASS |
| test_hex_encoded_directive_detected | PASS |
| test_cyrillic_homoglyph_detected_by_unicode_check | PASS |
| test_clean_base64_not_false_positive | PASS |
| test_high_volume_persistence_and_rehydration | PASS |
| test_individual_operators_do_not_trigger | PASS |
| test_cross_operator_correlation_detects_attack | PASS |
| test_execution_graph_has_both_operators | PASS |
| test_cross_correlation_cleanup | PASS |

**Total suite: 208 tests, 100% passing** (59 v1.0 + 76 new modules + 37 review fixes + 19 red-team + 8 v1.2 hardening + 9 v1.3 hardening)

---

## v1.2.0 — GOPEL Hardening Validation (Recommended Next Tests)

**Author:** Basil C. Puglisi, MPA
**Date:** 2026-05-08
**License:** CC BY-NC 4.0
**Attribution:** #AIassisted under HAIA-RECCLIN & Checkpoint-Based Governance

This release implements all five Grok-recommended v1.2 hardening tests plus the minimal feature code to support them. All changes preserve the non-interference invariant.

### New Features

**Factics JSONL Persistence (factics_engine.py)** — New `proposals_log_path` config option enables append-only JSONL logging of rule proposals with fsync. Pending proposals rehydrate on engine restart, surviving pipeline recycles without data loss.

**Observer Buffer Depth in Health Metrics (pipeline.py)** — New `attach_gopel_observer()` method and `observer_buffer_depth` field in `get_health()`. Enables external monitors to detect stalled or backlogged GOPEL record processing.

**OverwatchConfig Extension (models.py)** — Added `proposals_log_path: str = ""` for Factics persistence configuration.

### v1.2 Test Scorecard

| Test | Status |
|------|--------|
| test_gopel_10000_transactions_under_5s_p99 | PASS |
| test_overwatch_random_audit_detects_blinded_caipr | PASS |
| test_factics_proposals_survive_pipeline_restart | PASS |
| test_approved_proposals_not_reloaded_as_pending | PASS |
| test_multi_turn_confused_deputy_across_gopel_navigator_synthesis | PASS |
| test_gopel_mode_heartbeat_includes_pending_proposals_and_buffer_depth | PASS |
| test_health_without_observer_shows_zero_buffer_depth | PASS |
| test_health_reflects_pending_proposals_count | PASS |

**Total suite: 199 tests, 100% passing** (59 v1.0 + 76 new modules + 37 review fixes + 19 red-team + 8 v1.2 hardening)

---

## v1.1.1 — Grok Red-Team Hardening

**Author:** Basil C. Puglisi, MPA
**Date:** 2026-05-08
**License:** CC BY-NC 4.0
**Attribution:** #AIassisted under HAIA-RECCLIN & Checkpoint-Based Governance

This patch incorporates findings from a Grok red-team assessment (4 phases, 10 action items). All changes preserve the non-interference invariant.

### Phase 1: Immediate Hardening

**Fixed flush_stale crash (gopel_observer.py)** — The original code deleted `_timestamps[txn_id]` then accessed it on the next line for the alert payload. Refactored to capture age before deletion using safe `.pop()` operations. Concurrent flush+observe no longer crashes.

**inspect() as first-class pipeline method (pipeline.py)** — Added `inspect(transaction)` that delegates to `verify_transaction`. GopelObserver calls this on DECISION finalization, ensuring every GOPEL-assembled transaction flows through full Part 2 inspection.

**Concurrent finalization tested** — 100-transaction threaded test confirms no lost records or exceptions under concurrent GOPEL record submission.

### Phase 2: Structural and Type Safety

**RuleProposal.chain_signature type fix (models.py)** — Changed from `str` to `Optional[ChainSignature]`. Updated `to_dict()` to call `.to_dict()` on the object. Eliminates static analysis and refactoring risk.

**crypto.py module** — Centralized `SigningKeyProvider` with thread-safe HMAC-SHA256 signing, constant-time verification, key rotation with old-key retention for transition period verification.

**Factics auto-approve for low-risk (factics_engine.py)** — New `factics_auto_approve_low_risk` config option (default False). When enabled, ADVISORY-severity proposals are auto-approved to reduce adaptation latency.

### Phase 3: GOPEL Resilience and Observability

**Resource guards (context_inspector.py, intent_analyzer.py)** — Prompt and response text truncated to `max_scan_text_length` before scanning, with ADVISORY findings on truncation. Prevents ReDoS and memory exhaustion from malicious GOPEL records.

**Execution graph auto-wiring (pipeline.py)** — Every `verify_transaction` call now records role_assignment, dispatch, and response nodes in the execution graph. No manual wiring required.

**Internal health monitoring (pipeline.py)** — New `get_health()` method exposes pending_proposals_count, last_factics_cycle, execution_graph_operators, and pipeline statistics. Included in `get_status()` for heartbeat self-monitoring.

### Phase 4: GOPEL Deployment Profile

**gopel_mode config (models.py)** — New `OverwatchConfig.gopel_mode: bool = False`. When True, tightens: `require_structural_inputs=True`, `require_heartbeat_key=True`, `follow_symlinks=False`, `advisory_accumulation_limit<=3`, `random_audit_base_probability>=0.10`, `max_scan_text_length<=500000`.

### Grok Red-Team Test Scorecard

| Test | Status |
|------|--------|
| test_gopel_observer_concurrent_finalization | PASS |
| test_flush_stale_does_not_crash_on_race | PASS |
| test_flush_stale_concurrent_with_observe | PASS |
| test_novel_attack_during_pending_proposal_window | PASS |
| test_real_hmac_signing_roundtrip_for_gopel_heartbeat | PASS |
| test_crypto_module_signing_and_rotation | PASS |
| test_malicious_long_gopel_prompt_does_not_cause_dos | PASS |
| test_truncation_produces_advisory_finding | PASS |
| test_every_gopel_transaction_creates_execution_graph_node | PASS |
| test_graph_records_dispatch_and_response | PASS |
| test_overwatch_heartbeat_reports_internal_health | PASS |
| test_gopel_mode_config_applies_correct_defaults | PASS |
| test_gopel_mode_does_not_override_explicit_settings | PASS |
| test_gopel_mode_false_leaves_defaults_unchanged | PASS |
| test_rule_proposal_chain_signature_type_safety | PASS |
| test_rule_proposal_chain_signature_none_by_default | PASS |
| test_rule_proposal_type_safety_after_approve | PASS |
| test_inspect_delegates_to_verify_transaction | PASS |
| test_inspect_used_by_gopel_observer | PASS |

**Total suite: 191 tests, 100% passing** (59 v1.0 + 76 new modules + 37 review fixes + 19 red-team)

---

## v1.1.0 — Cross-Platform Review Rebuild

**Author:** Basil C. Puglisi, MPA
**Date:** 2026-05-08
**License:** CC BY-NC 4.0
**Attribution:** #AIassisted under HAIA-RECCLIN & Checkpoint-Based Governance

This release incorporates findings from two independent AI platform code reviews (ChatGPT, 15 findings; MiniMax, 10 findings) plus new modules for GOPEL v1.5 integration. All changes preserve the non-interference invariant: Overwatch observes GOPEL through read-only interfaces and never writes back into GOPEL's process space.

---

### New Modules

**provenance_manager.py** — Centralized provenance tag issuance with HMAC-SHA256 signing, 32-byte minimum key enforcement, and tier-authority hierarchy (Tier 0 human arbiter, Tier 1 AI platform, Tier 2 synthesizer).

**channel_manager.py** — Independent communication channel with ChannelMessage signing, multi-transport dispatch, delivery failure tracking, and dead-man's switch silence detection for heartbeat monitoring.

**caipr_dispatcher.py** — Cross-AI Platform Review with odd-number quorum enforcement, majority-vote consensus, and security-critical dissent override (any single CRITICAL flag overrides majority ALIGNED).

**execution_graph.py** — DAG-based execution graph engine recording role assignments, dispatches, responses, navigator routing, synthesis steps, checkpoints, and human decisions for full audit trail reconstruction.

**gopel_observer.py** — Read-only GOPEL adapter with frozen GopelRecord dataclass, hash-chain validation, stale record flushing, and transaction assembly from GOPEL's seven audit record types.

---

### ChatGPT Review Fixes (15 Findings)

| # | Finding | Status | Module |
|---|---------|--------|--------|
| 1 | Heartbeat signing missing | Resolved (v1.0) | models.py |
| 2 | Mandatory structural verification | Resolved | pipeline.py |
| 3 | Provenance tag signing | Resolved | models.py, provenance_manager.py |
| 4 | Trust tier decay enforcement | Resolved (v1.0) | models.py |
| 5 | Chain signature false-positive tracking | Resolved (v1.0) | models.py |
| 6 | Independent channel manager | Resolved | channel_manager.py |
| 7 | Two-gate rule proposal (threat vs. rule) | Resolved | factics_engine.py |
| 8 | Execution graph tracking | Resolved | execution_graph.py |
| 9 | CAIPR odd-number quorum | Resolved | caipr_dispatcher.py |
| 10 | CAIPR security-critical dissent override | Resolved | caipr_dispatcher.py |
| 11 | Context inspector regex safety | Resolved | context_inspector.py |
| 12 | Context inspector unicode normalization | Resolved | context_inspector.py |
| 13 | Coder output false-clean suppression | Resolved | output_state_evaluator.py |
| 14 | DeclaredTaskScope for scope-aware evaluation | Resolved | models.py, output_state_evaluator.py |
| 15 | Intent analyzer new recon patterns | Resolved | intent_analyzer.py |

### MiniMax Review Fixes (10 Findings)

| # | Finding | Status | Module |
|---|---------|--------|--------|
| 1 | Advisory accumulation AIG hold bug | Resolved | escalation_engine.py |
| 2 | Callback exception logging (AUD-03) | Resolved | escalation_engine.py |
| 3 | Missing manifest severity HALT | Resolved | structural_verifier.py |
| 4 | JSONL audit persistence (AUD-02) | Resolved | random_audit.py |
| 5 | Advisory persistence across audits (AUD-01) | Resolved | random_audit.py |
| 6 | Hash chain recompute verification (TB-02) | Resolved | random_audit.py |
| 7 | Heartbeat key 32-byte minimum (PIPE-01) | Resolved | pipeline.py |
| 8 | Manifest HMAC signature (SV-01) | Resolved | structural_verifier.py |
| 9 | Structured CBG releases (SV-02) | Resolved | structural_verifier.py |
| 10 | Symlink/size policy (SV-03) | Resolved | structural_verifier.py |

---

### Models Changes (models.py)

Added dataclasses: `DeclaredTaskScope`, `RuleProposal`, `GraphNode`, `GraphEdge`, `ExecutionGraph`.

Extended `DeploymentManifest` with `gopel_version`, `cbg_authorization_id`, `created_timestamp`, `config_snapshot`, `manifest_hash`, plus `compute_manifest_hash()` and `from_dict()` methods.

Extended `ProvenanceTag` with `sign()` and `verify()` HMAC-SHA256 methods.

Extended `TransactionRecord` with `task_scope` field.

Extended `OverwatchConfig` with `require_heartbeat_key`, `audit_log_path`, `manifest_path`, `follow_symlinks`, `integrity_scan_max_bytes`, `regex_scan_timeout_seconds`, `max_scan_text_length`, `chain_signature_match_threshold`, `require_structural_inputs`.

---

### Test Suite

59 original v1.0 tests updated and passing.
76 new module tests (test_v11_new_modules.py).
37 review fix regression tests (test_v11_review_fixes.py).
**Total: 172 tests, 100% passing.**

---

### Architecture Notes

Overwatch v1.1 sits beside the GOPEL channel as an external audit mirror, not between HAIA Agent and GOPEL as a transit layer. It observes mirrored records and content copies through read-only interfaces, then reports findings to CBG. It does not modify GOPEL state, does not sit in the enforcement path, and does not directly block execution.

GOPEL's seven deterministic operations (Dispatch, Collect, Route, Log, Pause, Hash, Report) are observable but not modifiable by Overwatch. The GopelObserver module consumes GOPEL's six audit record types (Request, Dispatch, Response, Navigation, Arbitration, Decision) through a frozen dataclass interface that enforces immutability at the Python level.
