# HAIA Agent Framework

**Implementation of GOPEL (Governance Orchestrator Policy Enforcement Layer)**

Seven deterministic operations. Zero cognitive work. The agent performs no evaluation, ranking, weighting, prioritization, summarization, semantic transformation, or filtering of any content that passes through it.

**Non-cognitive boundary definition:** The framework performs deterministic security operations (regex pattern sanitization of injection attacks, structural pattern matching for delimiter and metadata channel detection, format completeness checks for Navigator output). These are bounded, auditable, and do not evaluate meaning, quality, or relevance. Original platform responses are preserved verbatim in the audit trail. Sanitized copies are used only for Navigator injection defense. The static analyzer exempts these named security operations and reports the exemptions explicitly.

**Author:** Basil C. Puglisi, MPA
**Architecture:** GOPEL
**Version:** 0.6.0
**Status:** Working concept showing promise. Theories in development. Observable operational behaviors.

## What This Is

The HAIA Agent Framework is governance infrastructure for multi-AI workflows. It is the software implementation of the GOPEL architecture specified in the AI Provider Plurality congressional package and the HAIA-RECCLIN Agent Architecture Specification.

The framework dispatches identical prompts to multiple AI platforms, collects responses (originals preserved verbatim in the audit trail; sanitized copies used for Navigator injection defense), routes them to a Navigator for synthesis, logs every operation in a tamper-evident audit trail, pauses at preconfigured checkpoint gates for human arbitration, and reports governance metrics. It does nothing else.

The non-cognitive constraint is a security architecture decision. If the agent cannot evaluate content, it cannot be manipulated through adversarial inputs, prompt injection, or model poisoning. The attack surface is reduced to message transport and logging, both of which are deterministic operations amenable to formal verification.

## What This Is Not

This is not a competing AI. It generates no content. It is not a filter. It blocks no content based on meaning, quality, or relevance. It is not a regulator. It enforces no content standards. It is infrastructure. The circuit breaker halts execution only on process integrity failures (breach severity reaching HALT), not on content evaluation.

## Framework Modules

### Core Pipeline

**logger.py** provides the hash-chained audit trail with six record types (Request, Dispatch, Response, Navigation, Arbitration, Decision). Every record carries a SHA-256 chain hash computed from its content plus the previous record's chain hash. Any modification invalidates all subsequent hashes.

**pipeline.py** implements the base 14-step GOPEL pipeline: authentication, request logging, platform selection, prompt hashing, dispatch, response collection, integrity verification, Navigator routing, validation, checkpoint packaging, arbitration recording, and decision logging.

**secure_pipeline.py** extends the base pipeline with integrated security modules. This is the production pipeline. All security, breach detection, and sentinel systems are wired into the execution path. The base pipeline exists for reference and testing.

**selector.py** implements anchor-plus-rotation platform selection with cryptographic seed generation (V9) preventing adversarial prediction of rotation patterns.

**navigator.py** routes collected platform responses to a designated Navigator platform for synthesis. The Navigator is the only cognitive component. It produces the synthesis that the human reviews at the checkpoint.

**navigator_validator.py** performs structural validation of Navigator output. Checks for required governance sections (CONVERGENCE, DIVERGENCE, DISSENT, SOURCES, CONFLICTS, CONFIDENCE, RECOMMENDATION, EXPIRY), parseable confidence values, truncation indicators, and minimum response length. This is format checking, not content evaluation.

**models.py** defines the Pydantic data models for all six audit record types plus the governance enumerations (RECCLINRole, OperatingModel, OperatingModelTier, ArbitrationDecision, PlatformStatus).

### Security Modules

**security.py** provides cryptographic operator identity (HMAC-SHA256 signing), operator registry with key persistence (H2), transport integrity verification (V7), hash chain witness files for tamper detection, secure rotation seed generation, and audit trail encryption.

**secure_logger.py** extends the base logger with signed records, encrypted storage with reload continuity across restarts (FIX6), witness file separation verification on initialization (FIX8, warns if witness and audit file are colocated), chain integrity verification on load (FIX19), and dual-lock thread safety (H6) combining fcntl file locks (cross-process) with threading locks (cross-thread).

**static_analyzer.py** scans all framework source files for violations of the non-cognitive constraint. Detects cognitive imports (transformers, langchain, openai.chat), cognitive function calls (model.generate, embeddings), and content-dependent branching on response text. Excludes legitimate non-cognitive operations: len() comparisons (size checks) and containment tests (pattern matching equivalent to regex). Exempted operations are explicitly named: injection sanitization (A1), delimiter detection (CA2), metadata channel detection (CA6). These are deterministic security pattern checks, not semantic evaluation. Also scans Python dependencies for unexpected ML packages (C2 supply chain check).

### Breach Detection and Response

**breach.py** implements the framework's mechanism for telling humans it has been compromised. Five-severity classification: NOMINAL (all clean), ADVISORY (minor anomalies), WARNING (significant, flag for review), CRITICAL (integrity violation, pause), HALT (unrecoverable, stop immediately). The BreachDetector runs deterministic checks across ten categories: injection patterns, transport integrity, Navigator format, confidence anomalies, logger health, response statistical anomalies, Unicode homoglyphs, delimiter injection, metadata channel exploitation, and security warning escalation. The PipelineCircuitBreaker halts the pipeline when configurable thresholds are exceeded. The BreachNotifier dispatches reports to registered callbacks (console, file, or any external alerting system).

### Enterprise Governance Runtime

**governance.py** implements five-layer governance enforcement: role-based authorization (who can act), action permissions (what they can do), evidence gates (what proof they must provide), policy engine (what conditions must hold), and escalation engine (what posture the system is in). Six operator roles from Observer to Administrator. Eleven governance actions from pipeline execution to circuit breaker override. Evidence gates require typed submissions (rationale, scope statement, risk assessment, second approver) and validate against self-approval and phantom operator attacks. The policy engine aggregates ALLOW/DENY/ESCALATE verdicts with single-veto blocking. The escalation engine enforces ratchet-only posture changes from NORMAL to LOCKDOWN, requiring authority and minimum justification for de-escalation. The GovernanceRuntime orchestrates all five layers and is wired into the production pipeline at both execute() and record_arbitration() entry points.

### Pipeline Identity (Sentinel)

**sentinel.py** prevents a rogue AI or agent from impersonating the GOPEL pipeline. Four layers of defense. Layer 1: PipelineIdentity gives the GOPEL instance its own HMAC-SHA256 signing key, separate from operator keys. Every output is wrapped in a SignedAlert envelope with cryptographic proof of origin. Layer 2: Heartbeat dead-man's switch emits signed heartbeats at configurable intervals. If the pipeline is killed or replaced, the absence of heartbeats IS the alert. Layer 3: Challenge-response authentication allows the human to verify the pipeline's identity on demand by sending a random nonce. Layer 4: Out-of-band alerts dispatch critical breach notifications through a secondary channel (file, email, SMS, webhook) so that compromising the primary output channel does not silence all alerts. The HeartbeatMonitor runs on the human's side as an independent process, detecting impersonation (wrong fingerprint), replay attacks (stale sequence numbers), and silence (pipeline killed).

### Platform Adapters

**adapters/** contains the transport layer connecting the framework to AI platforms. Each adapter translates the framework's generic dispatch interface into a platform-specific API call. Adapters are excluded from non-cognitive constraint scanning because they are transport, not governance. Current adapters: OpenAI (GPT-4), Anthropic (Claude), Google (Gemini), and Mock (testing).

## Installation

```bash
pip install pydantic>=2.0.0 cryptography>=41.0.0
```

For live API dispatch (optional, not required for testing):

```bash
pip install openai anthropic google-generativeai
```

## Quick Start

### Minimal: Audit Logging Only

```python
from haia_agent import AuditLogger, RECCLINRole, OperatingModel, ArbitrationDecision

logger = AuditLogger(
    audit_file_path="audit_trail.json",
    operator_id="your.name"
)

logger.log_request(
    transaction_id="unique-id",
    operator_id="your.name",
    prompt_text="Your prompt here",
    recclin_role=RECCLINRole.RESEARCHER,
    operating_model=OperatingModel.MODEL_2,
    platform_selections=["claude", "chatgpt", "gemini"],
    anchor_platform="claude",
)

is_valid, violations = logger.verify_chain_integrity()
metrics = logger.generate_governance_metrics()
```

### Full Secure Pipeline with Sentinel

```python
from pathlib import Path
from haia_agent import (
    AuditLogger, PlatformSelector, MockAdapter, RECCLINRole,
    OperatingModel, OperatorIdentity, OperatorRegistry,
    SecureGOPELPipeline, PipelineIdentity, Sentinel,
    BreachNotifier, PipelineCircuitBreaker,
)
from haia_agent.navigator import NavigatorRouter

# Operator authentication
registry = OperatorRegistry()
registry.register_operator(OperatorIdentity("analyst_jane"))
registry.register_operator(OperatorIdentity("haia_agent"))

# Audit trail
logger = AuditLogger(Path("audit_trail.json"), operator_id="haia_agent")

# Platform selection
selector = PlatformSelector()
selector.register_adapter(MockAdapter(platform_id="claude"))
selector.register_adapter(MockAdapter(platform_id="chatgpt"))
selector.register_adapter(MockAdapter(platform_id="gemini"))
selector.set_anchor("claude")

# Navigator
nav = NavigatorRouter(MockAdapter(platform_id="navigator"))

# Pipeline identity and sentinel
identity = PipelineIdentity("gopel-prod-east-1")
sentinel = Sentinel(identity)
sentinel.register_oob_callback(
    Sentinel.file_oob_factory(Path("oob_alerts.jsonl"))
)

# Circuit breaker
breaker = PipelineCircuitBreaker(
    halt_on_critical=True,
    halt_on_warning_count=5,
    halt_on_injection_count=3,
)

# Build pipeline
pipeline = SecureGOPELPipeline(
    logger=logger,
    selector=selector,
    navigator=nav,
    operator_registry=registry,
    sentinel=sentinel,
    circuit_breaker=breaker,
)

# Execute
result = pipeline.execute(
    prompt="Analyze the governance implications of EU AI Act Article 14",
    recclin_role=RECCLINRole.RESEARCHER,
    operating_model=OperatingModel.MODEL_2,
    human_operator_id="analyst_jane",
)

# Check results
if result.breach_halted:
    print("Pipeline halted. Review breach report.")
elif result.signed_alert:
    print(f"Verified: {sentinel.verify_alert(result.signed_alert)}")
    print(result.checkpoint_package.breach_report_text)
```

## Running Tests

```bash
# Individual suites
python tests/test_logging_engine.py     # 10 tests: audit schema and hash chain
python tests/test_pipeline.py           # 10 tests: 14-step pipeline execution
python tests/test_security.py           # 20 tests: V1-V10 first-pass hardening
python tests/test_security_pass2.py     # 23 tests: A1-A5, H1-H6, C1-C3 second-pass
python tests/test_cognitive_attack.py   # 18 tests: CA1-CA8 cognitive agent attacks + breach system
python tests/test_sentinel.py           # 18 tests: IMP1-IMP7 impersonation + sentinel system

# All suites
for t in tests/test_*.py; do python "$t"; done
```

171 tests. Zero failures. All framework source files pass non-cognitive constraint static analysis.

## Security Hardening Summary

### First Pass (v0.3.0): 10 Vulnerabilities Addressed

V1 through V6 cover operator authentication, audit integrity, witness files, record signing, encryption at rest, and hash chain verification. V7 covers transport integrity (dispatch and response hash verification). V8 is deferred to integration phase (live API validation). V9 provides cryptographic rotation seeds preventing adversarial platform prediction. V10 addresses multi-instance file locking.

### Second Pass (v0.3.1): 14 Vulnerabilities Addressed

AI adversary attacks (A1 through A5): prompt injection sanitization with pattern-matching regex (not content evaluation), single-Navigator point-of-failure warning, governance architecture exposure minimization (anonymized platform labels, stripped terminology), response ordering randomization, and error message sanitization.

Human adversary attacks (H1 through H6): witness file separation enforcement, key persistence across restarts, API key exposure documentation (residual risk requiring KMS), configuration bounds checking, logger health verification, and secure logger dual-lock threading fix.

Combined attacks (C1 through C3): security modules integrated into execution path (the critical fix), dependency supply chain scanning, and pipeline entry authentication.

### Third Pass (v0.4.0): Cognitive Agent Attacks and Breach Detection

Cognitive agent attacks (CA1 through CA8): Unicode homoglyph detection (Cyrillic, Greek, zero-width characters), format delimiter injection detection, semantic manipulation documentation (provably undetectable, human checkpoint is the defense), coordinated identical response detection, Navigator confidence inflation flagging, metadata channel exploitation detection, transport warning behavior documentation, and live pipeline collusion detection.

Breach detection system: five-severity classification, ten-category anomaly detection, automatic severity escalation (3 warnings become CRITICAL, 5 advisories become WARNING), circuit breaker with configurable halt thresholds, notification callbacks, and formatted incident reports with actionable recommendations.

### Fourth Pass (v0.4.1): Pipeline Identity (Sentinel)

Impersonation attacks (IMP1 through IMP7): unsigned alert rejection, wrong-key alert rejection, replayed heartbeat detection, wrong fingerprint detection, pipeline silence detection (dead-man's switch), authentic challenge-response verification, and rogue challenge-response rejection.

Sentinel system: pipeline identity with HMAC-SHA256 signing, signed alert envelopes with monotonic sequence numbers, heartbeat dead-man's switch, challenge-response authentication, out-of-band alert dispatch, and human-side heartbeat monitoring.

### Fifth Pass (v0.5.0): Enterprise Governance Runtime

Governance runtime (governance.py, 1,537 lines) implementing five enforcement layers: (1) role-based authorization with six operator roles (Administrator, Governance Officer, Analyst, Auditor, Observer, System), (2) action permission matrix with 11 governance actions, (3) evidence gates requiring typed evidence submissions (rationale, scope statement, risk assessment, second approver) before high-consequence actions, (4) policy engine evaluating governance preconditions with ALLOW/DENY/ESCALATE verdicts, (5) escalation engine with ratchet-only five-level posture (NORMAL through LOCKDOWN) requiring authority for de-escalation.

Security hardening (GV1 through GV12): self-approval blocked on dual-authorization evidence, phantom approver detection against registered operator list, evidence submitter attribution verification, permission modification gated behind MODIFY_POLICY authorization, crashing policies fail closed (DENY not ALLOW), bounded decision log with eviction tracking, callback failure recording instead of silent swallowing, operator ID format validation, minimum justification length for de-escalation, duplicate acknowledgment rejection, and profile registration authorization after bootstrap.

### Sixth Pass (v0.5.1): Pipeline Integration and Troubleshooting

Critical bug fixes: Model 2 policy compared string literal "MODEL_2" against OperatingModel enum value "agent_ai_governance" (dead code, never triggered). GovernanceContext changed to use proper OperatingModel and RECCLINRole enum types. Unused imports (hashlib, json) removed from governance module.

Pipeline integration: GovernanceRuntime wired into SecureGOPELPipeline.execute() replacing legacy C3 binary authentication. Five-layer authorization at pipeline entry. Evidence assembly from execution parameters (scope statements auto-submitted). Breach detection feeds back into governance escalation engine for persistent posture across transactions. Governance decision attached to SecurePipelineResult for audit trail. Backward compatibility maintained: pipeline falls back to C3 binary check when governance_runtime is None. Arbitration path gated by evidence gates requiring minimum rationale length.

Identity coordination: OperatorIdentity (signing keys, security.py) and OperatorProfile (roles, governance.py) coexist on shared operator_id strings. Pipeline accepts both systems simultaneously. Integration test proves Observer with valid signing key but wrong governance role is blocked.

Dispatch validation (SYNTX 8.2): External semantic deep-sweep identified that total provider failure produced silent degradation where the human received a checkpoint package that looked normal but was built from incomplete data. Three-tier dispatch validation added. FULL: two or more platforms returned usable responses, cross-validation occurred. DEGRADED: exactly one platform returned a usable response, Navigator synthesis has no independent comparison point, security warnings flag the single-source condition. NONE (total dispatch failure): zero usable responses, pipeline halts immediately, logs a total_dispatch_failure system event at critical severity, builds a HALT-severity breach report, feeds the failure into governance escalation, and returns the transaction to the human operator with explicit notification that no cross-validation occurred and no synthesis was attempted. The checkpoint package carries total_dispatched, usable_responses, and cross_validation_status fields so the human arbiter always knows whether the output was cross-validated, degraded, or impossible.

## Non-Cognitive Constraint

The framework performs zero cognitive work. This is enforced by:

1. **Architecture**: GOPEL's seven operations (dispatch, collect, route, log, pause, hash, report) are defined as deterministic. The Navigator is the only cognitive component, and it runs on an external platform, not inside the framework.

2. **Static analysis**: The NonCognitiveAnalyzer scans all framework source files for cognitive imports, cognitive function calls, and content-dependent branching. Two categories of operations on response_text are excluded as non-cognitive: len() comparisons (size measurement, a structural property) and containment tests (substring pattern matching, functionally equivalent to regex which is already accepted).

3. **Testing**: Every test suite verifies that framework operations are deterministic. The static analyzer runs as part of the CI validation.

### Static Analyzer Exclusion Rationale (CBG Audit Record)

The static analyzer was refined in v0.4.0 to exclude two categories of operations from content-dependent branching violations. This is a deliberate design decision, not a weakening of the constraint.

**len() comparisons excluded**: `len(r.response_text) < 50` measures byte count, a structural property of the data, not its meaning. Measuring the size of a container does not require understanding its contents. This is the same class of operation as checking file size or counting records.

**Containment tests excluded**: `"--- SOURCE" in r.response_text` performs literal substring matching. This is functionally identical to `re.search(r"--- SOURCE", r.response_text)`, which was already accepted as non-cognitive in the A1 sanitization layer. The `in` operator for strings is syntactic sugar for the same deterministic pattern-matching operation. Whether the left operand is a string literal or a variable loaded from a constant list, the operation remains a character-by-character comparison with no semantic evaluation.

### Seventh Pass (v0.5.2): External Adversarial Review Fixes

External adversarial code audit (ChatGPT) produced 21 findings across 7 categories. 20 confirmed valid. Fixes applied in three tiers.

**Tier 1 (security and audit integrity):** FIX5: Authentication misconfiguration fail-closed. Pipeline constructor raises ValueError when require_authentication is True but no auth backend (governance_runtime or operator_registry) is provided. Previously the condition silently passed. FIX6: Encrypted audit logger reload. SecureAuditLogger overrides _load_existing to detect the encrypted wrapper, decrypt, and restore records and chain state. Previously restart under encryption dropped all prior records. FIX7: Algorithm label corrected from AES-256 to AES-128-CBC-HMAC-SHA256 (Fernet). FIX8: Witness separation verification invoked on SecureAuditLogger init. Previously the verify_separation method existed but was never called. FIX19: Chain integrity verified on load. _load_existing now calls verify_chain_integrity after loading records and stores validation status. Previously tampered files loaded without detection.

**Tier 2 (governance and audit completeness):** FIX11: Evidence submitter enforcement. Governance runtime blocks authorization when evidence claims submission by an unregistered operator. Previously this produced warnings only. FIX15: Full Navigator synthesis persistence. NavigationRecord now includes full_synthesis_text field containing the complete Navigator output. Previously only a 500-character snippet was stored, preventing audit reconstruction of what the human arbiter actually saw.

**Tier 3 (definition tightening):** Non-cognitive boundary definition added to README header. Core claims refined: "collects responses" now specifies originals preserved verbatim with sanitized copies for Navigator injection defense. "Blocks nothing" now specifies "blocks no content based on meaning, quality, or relevance" with circuit breaker scoped to process integrity failures.

**Internal review (Claude):** Fresh adversarial review after ChatGPT fixes applied. CLAUDE-R8: Base AuditLogger silently loaded encrypted files as empty with chain_valid_on_load=True. Fixed to detect encrypted wrapper and set chain_valid_on_load=False with explicit warning. Three additional minor findings documented as known limitations: brief unencrypted window during SecureAuditLogger initialization (overwritten by first log_record), evidence submitter enforcement validates registration but not actual approval (would require signed approval workflow), and _initialize_file uses base _write_file before encrypted log_record overwrites.

### Eighth Pass (v0.6.0): Multi-AI Adversarial Review Fixes

External adversarial code review across four independent AI platforms (Gemini, Grok, Kimi, DeepSeek) produced convergent findings. Two findings identified independently by multiple platforms.

**Tier 1 (governance and security):** T1-A: GovernanceContext now populated with persistent breach state (severity, injection count, platform failures) from prior transactions. Previously defaulted to NOMINAL at every entry, rendering POLICY_BREACH_BLOCKS_EXECUTION dead code at pre-execution. DeepSeek CRITICAL, verified. T1-B: SECOND_APPROVER evidence now requires HMAC-SHA256 signature from the approving operator's signing key when OperatorRegistry is provided. Previously accepted a bare operator ID string. Gemini CRITICAL + DeepSeek MEDIUM, verified independently. Backward compatible when no registry present. T1-C: Logger health check strengthened from existence+size to include JSON parse and chain integrity verification. Previously a corrupted file passed. Kimi HIGH + DeepSeek LOW, verified independently.

**Tier 2 (audit hardening):** T2-B: Encrypted audit file wrapper now carries HMAC over the outer JSON envelope. Prevents attacker from modifying wrapper fields (removing "encrypted" flag) to force unencrypted load path. Gemini MEDIUM, verified. T2-D: Version string corrected. T4-A: Append-only documentation corrected to distinguish logical append-only (no record removal) from physical file replacement (temp+rename for atomicity).

**Claude internal review (post-fix):** CLAUDE-R9: T1-A introduced a deadlock where CRITICAL breach state permanently blocked all pipeline execution with no authorized reset path. Added acknowledge_breach() method requiring ACKNOWLEDGE_BREACH governance authorization to clear breach state while preserving escalation posture. CLAUDE-R10 (documented, v0.6.0): Second-approver signature payload does not include transaction context, enabling cross-gate replay. Mitigant: include transaction_id in signable payload.

## Defended Attack Surfaces (171 tests)

| Attack Class | Vectors | Detection Method |
|-------------|---------|-----------------|
| Prompt injection | SYSTEM OVERRIDE, INST tags, role hijacking | Regex pattern matching (A1) |
| Unicode bypass | Cyrillic homoglyphs, zero-width characters | Character range scanning (CA1) |
| Delimiter injection | Fake response boundaries | Literal substring detection (CA2) |
| Platform collusion | Identical responses across platforms | Response hash comparison (CA4) |
| Confidence manipulation | Inflated or suppressed confidence scores | Threshold comparison (CA5) |
| Metadata exploitation | Injection via api_confirmation, platform_model | Keyword scanning in unsanitized channels (CA6) |
| Transport tampering | Response modification in transit | SHA-256 hash verification (V7) |
| Audit trail tampering | Record modification after write | Hash chain verification, witness files (V3, V4) |
| Pipeline impersonation | Rogue agent sending fake NOMINAL reports | HMAC-SHA256 signed envelopes (IMP1, IMP2) |
| Heartbeat replay | Captured heartbeat re-sent by adversary | Monotonic sequence verification (IMP3) |
| Pipeline silence | GOPEL killed or replaced by adversary | Dead-man's switch heartbeat monitor (IMP5) |
| Unauthorized access | Unregistered operator executing pipeline | Operator registry authentication (C3) |
| Self-approval bypass | Operator names self as second approver | Cross-reference against requesting operator (GV1) |
| Permission escalation | Analyst modifies own permission matrix | MODIFY_POLICY authorization gate (GV4) |
| Governance fail-open | Crashing policy produces ALLOW | Exception handling forces DENY (GV5) |
| Rogue registration | External code registers admin operator | Bootstrap pattern with REGISTER_OPERATOR gate (GV12) |
| Total provider failure | All dispatch platforms return errors | Total dispatch failure halt with NONE cross-validation (SYNTX 8.2) |
| Silent degradation | Single-source output packaged as cross-validated | DEGRADED cross-validation flag with security warning (SYNTX 8.2) |
| Auth misconfiguration | require_authentication=True with no auth backend | ValueError raised at construction, fail-closed (FIX5) |
| Encrypted audit restart | Encrypted logger drops records on reload | Override _load_existing decrypts before restoring chain (FIX6) |
| Witness colocation | Witness and audit file in same directory | verify_separation called on init, warning emitted (FIX8) |
| Evidence spoofing | Evidence claims submission by unregistered operator | Blocked at governance runtime, not just warned (FIX11) |
| Audit reconstruction gap | Navigator synthesis truncated in audit trail | full_synthesis_text field stores complete output (FIX15) |
| Tampered audit reload | Modified audit file loads without detection | Chain integrity verified on load, violations reported (FIX19) |
| Encrypted file misload | Base logger loads encrypted file as empty | Encrypted wrapper detection with warning (CLAUDE-R8) |
| Breach policy bypass | GovernanceContext defaults NOMINAL at entry | Persistent breach state carried across transactions (T1-A) |
| Second approver spoofing | Operator claims another's approval by string | HMAC signature required from approving operator's key (T1-B) |
| Logger health false positive | Corrupted file passes existence check | Chain integrity verification in health check (T1-C) |
| Encrypted wrapper tampering | Attacker modifies outer JSON envelope | HMAC over wrapper verified before trusting fields (T2-B) |
| Breach state deadlock | CRITICAL breach permanently blocks all execution | Authorized breach acknowledgment clears policy block (CLAUDE-R9) |

## Irreducible Limitations

**Semantic manipulation** (CA3): A well-crafted lie that contains no injection patterns, no unicode anomalies, no delimiter tricks, and passes all structural checks is undetectable by any deterministic system. The test suite proves this explicitly. The human checkpoint is the only defense. The breach report states this in every report.

**API key exposure** (H3): API keys stored as plaintext on adapter objects. Inherent to SDK usage patterns. Requires external KMS integration at deployment.

**Physical key theft**: HMAC signing keys in process memory. Requires hardware security modules (HSM) or trusted execution environments (SGX) at infrastructure level.

**Monitoring-of-monitoring**: If the HeartbeatMonitor is also compromised, the recursion has no application-level termination. This is the organizational security boundary.

**Governance state persistence** (GV5/GV6): The decision log and escalation state live in process memory. A crash resets escalation posture to NORMAL and erases the decision history. The decision log has configurable size bounds with eviction tracking, but evicted entries require external persistent storage for full audit reconstruction. Integration with the SecureAuditLogger for persistent governance state is a future phase.

**Caller-supplied context** (GV8): The GovernanceContext breach_severity and injection_count fields are assembled by the pipeline and passed to the governance runtime. A compromised pipeline module could supply false context values. Full mitigation requires signed context assembly within a trusted execution boundary.

**O(N) persistence scaling** (T2-A): Both logger.py and secure_logger.py serialize the entire record array on every log_record call, producing O(N) write amplification. With thousands of transactions, memory consumption grows linearly and I/O latency grows with file size. Production deployments should migrate to JSONL append-mode or a WAL (Write-Ahead Log) pattern. The current implementation is correct for prototype-scale validation. Identified independently by Gemini.

**Transport verification timing** (T2-C): Transport integrity verification runs after dispatch/response records are already written to the audit trail. If verification fails, potentially corrupted records exist in the log. This is intentional: raw data preservation is correct for forensic purposes. The violation is flagged in security_warnings and reflected in the breach report. Future versions may add an "unverified" marker at write time. Identified by Kimi.

**Key rotation** (T3-A): No automated rotation mechanism for operator signing keys (OperatorIdentity) or pipeline identity keys (PipelineIdentity). Compromised keys remain valid indefinitely until manually replaced. Requires external KMS integration with rotation cadence enforcement. Identified independently by Kimi and Grok.

**Windows portability** (T3-B): AuditFileLock uses fcntl.flock (POSIX only). No Windows fallback. Framework requires Linux or macOS for file-level locking. Windows deployments would need portalocker or win32event integration. Identified independently by DeepSeek and Grok.

**Witness file race condition** (T3-C): HashWitness._persist() uses temp-file-then-rename without file locking. Concurrent multi-process writes could lose witness entries. Low probability: witness writes are infrequent and individually fast. Single-process deployments are unaffected. Identified by Kimi.

**Arbitration trust boundary** (T3-F): Human arbitration input (modifications, final_output) is not injection-sanitized before logging. This is by design: the human is the trust anchor and human authority is absolute. However, if the human's workstation is compromised, this provides an unsanitized path into finalized output. The trust boundary is at the human-machine interface. Identified by Gemini.

**Orphan arbitration records** (T3-E): record_arbitration accepts any transaction_id without verifying a matching transaction exists in the audit trail. Could produce orphaned arbitration records for non-existent transactions. Low severity: does not affect pipeline execution, only audit trail cleanliness. Identified by DeepSeek.

## Three Operating Models

| Model | Name | Checkpoint Behavior |
|-------|------|---------------------|
| 1 | Agent Responsible AI | Continue at gates, pause at final output |
| 2 | Agent AI Governance | Pause at every RECCLIN role gate |
| 3 | Manual Human AI Governance | No automation. Human orchestrates. Agent only logs |

## Seven Deterministic Operations

| # | Operation | What It Does | What It Does Not Do |
|---|-----------|-------------|---------------------|
| 1 | Dispatch | Sends identical prompts to platforms via API | Does not modify or sequence prompts |
| 2 | Collect | Receives all responses without modification | Does not filter, rank, or evaluate |
| 3 | Route | Delivers responses to Navigator | Does not choose which to forward |
| 4 | Log | Writes structured audit records | Does not summarize or interpret |
| 5 | Pause | Stops at checkpoint gates | Does not decide whether to pause |
| 6 | Hash | Computes SHA-256 for tamper detection | Does not evaluate content |
| 7 | Report | Counts approval rates, reversal rates | Does not interpret what counts mean |

## Implementation Roadmap

| Phase | Name | Status |
|-------|------|--------|
| 0 | Manual governance (Model 3) | Operational. Published book and case studies |
| 1 | Audit file schema | Complete (v0.1.0) |
| 2 | Logging engine | Complete (v0.1.0) |
| 3 | API dispatch, synthesis, security hardening | Complete (v0.2.0 through v0.4.1) |
| 3.5 | Enterprise governance runtime | Complete (v0.5.0 through v0.6.0) |
| 4 | Checkpoint gates (operating model enforcement) | Next |
| 5 | Compliance validation and formal verification | Planned |

## Evidence Discipline

This software is a **Tier 2 Working Concept**: a theory showing promise in development with observable operational behaviors. It is not proven. It is not validated. It is not benchmarked. Those are Tier 1 claims that require independent verification through pilot programs.

## License

Open publication for public infrastructure.
