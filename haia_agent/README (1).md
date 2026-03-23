# HAIA Agent Framework

**Implementation of GOPEL (Governance Orchestrator Policy Enforcement Layer)**

Seven deterministic operations. Zero cognitive work. The agent performs no evaluation, ranking, weighting, prioritization, summarization, semantic transformation, or filtering of any content that passes through it.

**Non-cognitive boundary definition:** The framework performs deterministic security operations (regex pattern sanitization of injection attacks, structural pattern matching for delimiter and metadata channel detection, format completeness checks for Navigator output). These are bounded, auditable, and do not evaluate meaning, quality, or relevance. Original platform responses are preserved verbatim in the audit trail. Sanitized copies are used only for Navigator injection defense. The static analyzer exempts these named security operations and reports the exemptions explicitly.

**Author:** Basil C. Puglisi, MPA
**Architecture:** GOPEL Canonical Public v1.5
**Code Version:** 0.6.1
**CBG Authority:** Checkpoint-Based Governance v5.0
**Framework:** HAIA-RECCLIN 2026 Edition
**Repository:** github.com/basilpuglisi/HAIA · CC BY-NC 4.0
**Book:** Governing AI: When Capability Exceeds Control · ISBN 9798349677687
**Attribution:** #AIassisted under HAIA-RECCLIN & Checkpoint-Based Governance

---

## What This Is

The HAIA Agent Framework is governance infrastructure for multi-AI workflows. It is the software implementation of the GOPEL architecture specified in the GOPEL Canonical Public v1.5 specification, the AI Provider Plurality congressional package, and the HAIA-RECCLIN Agent Architecture Specification.

The framework dispatches identical prompts to multiple AI platforms, collects responses (originals preserved verbatim in the audit trail; sanitized copies used for Navigator injection defense), routes them to a Navigator for synthesis, logs every operation in a tamper-evident audit trail, pauses at preconfigured checkpoint gates for human arbitration, and reports governance metrics. It does nothing else.

The non-cognitive constraint is a security architecture decision. If the agent cannot evaluate content, it cannot be manipulated through adversarial inputs, prompt injection, or model poisoning. The attack surface is reduced to message transport and logging, both of which are deterministic operations amenable to formal verification.

## What This Is Not

This is not a competing AI. It generates no content. It is not a filter. It blocks no content based on meaning, quality, or relevance. It is not a regulator. It enforces no content standards. It is infrastructure. The circuit breaker halts execution only on process integrity failures (breach severity reaching HALT), not on content evaluation.

---

## The Governing Specifications

The code in this repository is v0.6.1, a reference implementation that proves feasibility. The specifications governing the architecture and its future development are published separately and represent the canonical governance layer above the code. The code implements the specifications; the specifications are not derived from the code.

### GOPEL Canonical Public v1.5 (March 2026)

The governing specification for the entire architecture. GOPEL is a non-cognitive multi-AI governance layer, also termed Deterministic Multi-AI Governance Control. GOPEL is a pre-inference enforcement layer for governed multi-AI workflows.

All governance artifacts that GOPEL executes, including trust anchors, endpoint capability flags, data sensitivity labels, measurement allowlists, routing matrices, threshold configurations, and platform anchor assignments, are established by human or enterprise governance authority outside GOPEL and loaded into GOPEL as configuration inputs. GOPEL executes configured policy. GOPEL does not generate, evaluate, or modify the policies it enforces.

The Navigator is a cognitive function that lives outside GOPEL entirely in all three operating models. In Model 3 the human arbiter is the Navigator. In Model 2 the human selects and supervises a designated Navigator entity. In Model 1 all platforms in the dispatch pool serve as navigators through iterated cross-platform exchange. GOPEL never performs synthesis, generates recommendations, or evaluates content.

### Published Extensions

Four specification extensions govern capabilities beyond the base architecture. Each extension preserves the non-cognitive constraint and does not alter the seven deterministic operations.

**Checkpoint Information Chain Extension (CICE) v1.2.** Addresses the checkpoint information chain gap: how governance signals flow from platform response through Navigator synthesis to human checkpoint. Three connected specifications: Deterministic Metadata Comparison (DMC) produces pre-checkpoint anomaly summaries by comparing structured field values across Response Records and Navigation Records; Navigator Plurality Protocol (NPP) dispatches the Navigator synthesis task to multiple independent platforms and cross-validates their syntheses; Explicit Delegation Boundaries (EDB) forces any reduction in checkpoint review depth at production scale into an explicit, auditable CBG decision with mandatory rationale, expiry, and escalation triggers. Statistical Process Control monitors the governance system itself for drift and triggers automatic escalation when configured ceilings are exceeded. The extension names the constitutional wall between AI Governance and Responsible AI: at production scale, volume pressure silently converts governance checkpoints into rubber stamps without anyone making an explicit decision to accept that trade-off, and the extension forces that decision into the open with an auditable record. Gaps surfaced through external architectural review by Krzysztof Olbiński, Founder of Homo Digital. Three-platform CAIPR review (Kimi, Grok, ChatGPT) with zero rejections and 3-of-3 approval convergence. Code implementation scoped as a separate development target. Convergence with Olbiński's Tesseract Protocol (homodigital.io) confirmed architecturally compatible; joint mapping of Tesseract-QGED signal fields to RECCLIN structured fields is an active collaboration target using the locked Tesseract-QGED Interface Specification v1.1 as the source schema.

**Confidential Processing Extension (CPE) v1.1.** Addresses the privacy-during-computation gap. After GOPEL dispatches a prompt and before GOPEL collects the response, the data is inside an AI platform's inference stack with zero GOPEL visibility. CPE classifies every dispatch into exactly one of four profiles before any data moves, based on two deterministic inputs: the endpoint capability flag and the data sensitivity label. Profile 0 (Standard API) applies when the platform provides no confidential computing capability. Profile 1 (Attested TEE) applies when the platform supports hardware-attested trusted execution environments. Profile 2 (Tokenized Minimization) applies data minimization through pattern-matched tokenization before dispatch. Profile 3 (Cryptographic Inference) covers experimental FHE/SMPC workloads. Six-platform CAIPR review (Claude, Gemini, Grok, DeepSeek, Kimi, ChatGPT) with all platforms confirming architectural soundness.

**Post-Quantum Cryptographic Agility Amendment v1.2.** Extends the signature architecture to remain valid across multi-decade retention obligations. ECDSA P-256 and Ed25519 are vulnerable to Shor's algorithm on a cryptographically relevant quantum computer. The amendment adds a three-tier signature classification (Tier A classical-only, Tier B hybrid composite with ML-DSA-65, Tier C post-quantum-only), external hash chain anchoring, and NIST milestone-based cutover triggers consistent with FIPS 203, 204, and 205. Ten-platform CAIPR review across both rounds with all platforms confirming the amendment is sound. No platform rejected.

**HAIA-CAIPR Specification v1.1.** The cross-platform review protocol governing how a human governor dispatches identical prompts to multiple independent AI platforms, collects their RECCLIN-structured outputs, compares those outputs for convergence and divergence, detects hallucinations and fabrications through cross-validation, and governs the AI synthesizing multiple platform outputs. CAIPR introduces source-authority discrimination (Tier 0 human arbiter, Tier 1 raw platform output, Tier 2 synthesizer output under highest scrutiny), seven documented synthesizer failure modes, dual-signed inclusion manifests, and convergence-without-dissent as a red flag requiring escalation. CAIPR sits between RECCLIN and CBG in the adoption ladder and is the protocol under which every specification extension in this repository was reviewed.

### Constitutional Authority

**Checkpoint-Based Governance (CBG) v5.0** is the constitutional authority layer above GOPEL. Four constitutional properties, three checkpoint functions, four-stage decision loop, and the Asimov harm boundary. CBG produces the checkpoint record. GOPEL produces the audit material. When and how that material is reviewed is determined by the human, the organization, or the applicable industry and regulatory context (Discretionary Audit Policy). CBG authority allows the human governor to disregard any AI signal entirely if human judgment requires it.

### Legislative Work

The **AI Provider Plurality Congressional Package** (submitted to the 119th Congress) provides the federal policy framework. Five documents: Summary Flyer, Ethics for Oversight, Legislative Framework, Technical Appendix, and the Verified AI Inference Standards Act (VAISA) v6. VAISA establishes attestation API requirements for AI inference transparency and requires post-quantum cryptographic readiness for all attestation and audit signing.

---

## Three Agent Operating Models

The agent is distinct from GOPEL. GOPEL is the infrastructure. The agent is the mode of operation that determines how GOPEL's outputs flow and where CBG checkpoints interrupt the workflow. Choosing the operating model is a CBG decision made by the human arbiter before any workflow begins, and the model selection is logged as part of the Request Record.

| Model | Name | Checkpoint Behavior | Appropriate For |
|-------|------|---------------------|-----------------|
| 1 | Agent Responsible AI | Continue at gates, pause at final output. One CBG checkpoint at workflow end. | Low to moderate risk. Routine operations with established patterns. |
| 2 | Agent AI Governance | Pause at every RECCLIN role gate. Human approves before proceeding. | High-risk decisions: employment, credit, healthcare, law enforcement. |
| 3 | Manual Human AI Governance | No automation. Human dispatches, collects, routes manually. | Highest-consequence decisions. Novel situations. Framework validation. |

Model selection is itself a CBG decision, documented in the audit file with risk classification rationale. All published work and case studies in the HAIA corpus were produced under Model 3, because GOPEL has not yet moved from proof of concept to production. Model 3 is the gold standard because no automated intermediary touched the evidence.

---

## Seven Deterministic Operations

| # | Operation | What It Does | What It Does Not Do |
|---|-----------|-------------|---------------------|
| 1 | Dispatch | Sends identical prompts to platforms via API | Does not modify or sequence prompts based on content |
| 2 | Collect | Receives all responses without modification | Does not filter, rank, or evaluate responses |
| 3 | Route | Delivers responses to Navigator | Does not choose which responses to forward |
| 4 | Log | Writes structured audit records | Does not summarize or interpret logged content |
| 5 | Pause | Stops at checkpoint gates, delivers governance package to human | Does not decide whether to pause (gates are preconfigured) |
| 6 | Hash | Computes SHA-256 for tamper detection | Does not evaluate content being hashed |
| 7 | Report | Counts approval rates, reversal rates, threshold triggers | Does not interpret what the counts mean |

All arithmetic GOPEL performs is limited to string hashing (SHA-256) and integer counting. Both operations are architecture-independent across any processor implementation. This integer-only arithmetic constraint is a formal design requirement.

---

## Six Audit Record Types

Every governed transaction produces six record types through the seven deterministic operations: Request Record, Dispatch Record, Response Record, Navigation Record, Arbitration Record, and Decision Record. The Arbitration Record proves that a human decided, not merely that a human was present. The Decision Record links the final authorized output to every upstream record in the chain.

The audit trail is append-only, hash-chained, and digitally signed. Append-only means nothing is overwritten. Hash-chained means each record contains the SHA-256 hash of the previous record, and any alteration to any record breaks the chain. This is cryptographic chain of custody that produces forensically useful evidence suitable for regulatory audit and legal proceedings.

---

## Framework Modules

### Core Pipeline

**logger.py** provides the hash-chained audit trail with six record types. Every record carries a SHA-256 chain hash computed from its content plus the previous record's chain hash. Any modification invalidates all subsequent hashes.

**pipeline.py** implements the base 14-step GOPEL pipeline: authentication, request logging, platform selection, prompt hashing, dispatch, response collection, integrity verification, Navigator routing, validation, checkpoint packaging, arbitration recording, and decision logging.

**secure_pipeline.py** extends the base pipeline with integrated security modules. This is the production pipeline. All security, breach detection, and sentinel systems are wired into the execution path.

**selector.py** implements anchor-plus-rotation platform selection with cryptographic seed generation (V9) preventing adversarial prediction of rotation patterns.

**navigator.py** routes collected platform responses to a designated Navigator platform for synthesis. The Navigator is the only cognitive component. It produces the synthesis that the human reviews at the checkpoint.

**navigator_validator.py** performs structural validation of Navigator output. Checks for required governance sections (CONVERGENCE, DIVERGENCE, DISSENT, SOURCES, CONFLICTS, CONFIDENCE, RECOMMENDATION, EXPIRY), parseable confidence values, truncation indicators, and minimum response length. This is format checking, not content evaluation.

**models.py** defines the Pydantic data models for all six audit record types plus the governance enumerations (RECCLINRole, OperatingModel, OperatingModelTier, ArbitrationDecision, PlatformStatus).

### Security Modules

**security.py** provides cryptographic operator identity (HMAC-SHA256 signing), operator registry with key persistence (H2), transport integrity verification (V7), hash chain witness files for tamper detection, secure rotation seed generation, and audit trail encryption.

**secure_logger.py** extends the base logger with signed records, encrypted storage with reload continuity across restarts (FIX6), witness file separation verification on initialization (FIX8), chain integrity verification on load (FIX19), and dual-lock thread safety (H6) combining fcntl file locks (cross-process) with threading locks (cross-thread).

**static_analyzer.py** scans all framework source files for violations of the non-cognitive constraint. Detects cognitive imports (transformers, langchain, openai.chat), cognitive function calls (model.generate, embeddings), and content-dependent branching on response text. Excludes legitimate non-cognitive operations: len() comparisons (size checks) and containment tests (pattern matching equivalent to regex). Exempted operations are explicitly named: injection sanitization (A1), delimiter detection (CA2), metadata channel detection (CA6). Also scans Python dependencies for unexpected ML packages (C2 supply chain check).

### Breach Detection and Response

**breach.py** implements the framework's mechanism for telling humans it has been compromised. Five-severity classification: NOMINAL, ADVISORY, WARNING, CRITICAL, HALT. The BreachDetector runs deterministic checks across ten categories: injection patterns, transport integrity, Navigator format, confidence anomalies, logger health, response statistical anomalies, Unicode homoglyphs, delimiter injection, metadata channel exploitation, and security warning escalation. The PipelineCircuitBreaker halts the pipeline when configurable thresholds are exceeded. The BreachNotifier dispatches reports to registered callbacks.

### Enterprise Governance Runtime

**governance.py** implements five-layer governance enforcement: role-based authorization (who can act), action permissions (what they can do), evidence gates (what proof they must provide), policy engine (what conditions must hold), and escalation engine (what posture the system is in). Six operator roles from Observer to Administrator. Eleven governance actions from pipeline execution to circuit breaker override. Evidence gates require typed submissions (rationale, scope statement, risk assessment, second approver) and validate against self-approval and phantom operator attacks. The policy engine aggregates ALLOW/DENY/ESCALATE verdicts with single-veto blocking. The escalation engine enforces ratchet-only posture changes from NORMAL to LOCKDOWN.

### Pipeline Identity (Sentinel)

**sentinel.py** prevents a rogue AI or agent from impersonating the GOPEL pipeline. Four layers of defense: PipelineIdentity with HMAC-SHA256 signing, heartbeat dead-man's switch, challenge-response authentication, and out-of-band alert dispatch through secondary channels. The HeartbeatMonitor runs on the human's side as an independent process, detecting impersonation (wrong fingerprint), replay attacks (stale sequence numbers), and silence (pipeline killed).

### Platform Adapters

**adapters/** contains the transport layer connecting the framework to AI platforms. Each adapter translates the framework's generic dispatch interface into a platform-specific API call. Adapters are excluded from non-cognitive constraint scanning because they are transport, not governance. Current adapters: OpenAI (GPT-4), Anthropic (Claude), Google (Gemini), and Mock (testing).

---

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

183 tests. Zero failures. All framework source files pass non-cognitive constraint static analysis.

---

## Security Hardening Summary

### First Pass (v0.3.0): 10 Vulnerabilities Addressed

V1 through V6 cover operator authentication, audit integrity, witness files, record signing, encryption at rest, and hash chain verification. V7 covers transport integrity (dispatch and response hash verification). V8 is deferred to integration phase (live API validation). V9 provides cryptographic rotation seeds preventing adversarial platform prediction. V10 addresses multi-instance file locking.

### Second Pass (v0.3.1): 14 Vulnerabilities Addressed

AI adversary attacks (A1 through A5): prompt injection sanitization with pattern-matching regex (not content evaluation), single-Navigator point-of-failure warning, governance architecture exposure minimization (anonymized platform labels, stripped terminology), response ordering randomization, and error message sanitization.

Human adversary attacks (H1 through H6): witness file separation enforcement, key persistence across restarts, API key exposure documentation (residual risk requiring KMS), configuration bounds checking, logger health verification, and secure logger dual-lock threading fix.

Combined attacks (C1 through C3): security modules integrated into execution path (the critical fix), dependency supply chain scanning, and pipeline entry authentication.

### Third Pass (v0.4.0): Cognitive Agent Attacks and Breach Detection

Cognitive agent attacks (CA1 through CA8): Unicode homoglyph detection, format delimiter injection detection, semantic manipulation documentation (provably undetectable, human checkpoint is the defense), coordinated identical response detection, Navigator confidence inflation flagging, metadata channel exploitation detection, transport warning behavior documentation, and live pipeline collusion detection.

Breach detection system: five-severity classification, ten-category anomaly detection, automatic severity escalation, circuit breaker with configurable halt thresholds, notification callbacks, and formatted incident reports.

### Fourth Pass (v0.4.1): Pipeline Identity (Sentinel)

Impersonation attacks (IMP1 through IMP7): unsigned alert rejection, wrong-key alert rejection, replayed heartbeat detection, wrong fingerprint detection, pipeline silence detection (dead-man's switch), authentic challenge-response verification, and rogue challenge-response rejection.

### Fifth Pass (v0.5.0): Enterprise Governance Runtime

Five-layer governance enforcement with role-based authorization, action permissions, evidence gates, policy engine, and escalation engine. Security hardening (GV1 through GV12) covering self-approval blocking, phantom approver detection, evidence submitter verification, permission modification gates, crash-safe fail-closed policies, bounded decision log, callback failure recording, operator ID validation, de-escalation minimum justification, duplicate acknowledgment rejection, and post-bootstrap registration authorization.

### Sixth Pass (v0.5.1): Pipeline Integration

Critical bug fixes: Model 2 policy enum comparison, GovernanceContext typing, unused imports. Pipeline integration: five-layer authorization at pipeline entry, evidence assembly from execution parameters, breach detection feedback into governance escalation, backward compatibility with C3 binary check. Dispatch validation (SYNTX 8.2): three-tier validation (FULL, DEGRADED, NONE) preventing silent degradation when providers fail.

### Seventh Pass (v0.5.2): External Adversarial Review

External adversarial code audit (ChatGPT) produced 21 findings across 7 categories. 20 confirmed valid. Critical fixes: authentication misconfiguration fail-closed (FIX5), encrypted audit reload (FIX6), witness separation on init (FIX8), chain integrity on load (FIX19), evidence submitter enforcement (FIX11), full Navigator synthesis persistence (FIX15). Internal review (Claude): encrypted file detection in base logger (CLAUDE-R8).

### Eighth Pass (v0.6.0): Multi-AI Adversarial Review

Four independent AI platforms (Gemini, Grok, Kimi, DeepSeek) reviewed concurrently. Critical fixes: persistent breach state across transactions (T1-A), HMAC-signed second-approver evidence (T1-B), strengthened logger health check (T1-C), encrypted wrapper HMAC (T2-B). Internal review: breach state deadlock resolution with authorized acknowledge_breach() method (CLAUDE-R9).

### Ninth Pass (v0.6.1): MiniMax AI Review

Seventh independent AI platform review. MiniMax identified 12 findings: 5 already documented, 7 new. Zero new security vulnerabilities. All critical and high-severity issues from prior six platforms confirmed fixed. Code fixes: explicit fallback warning (FIX-MM1), per-transaction witness override (FIX-MM2), analyzer path boundary enforcement (FIX-MM3).

---

## Defended Attack Surfaces (183 tests)

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
| Silent encryption fallback | Cryptography library missing, weaker obfuscation used | Explicit stderr warning on fallback activation (FIX-MM1) |
| Witness interval rigidity | High-value transactions use same witness frequency | Per-transaction force=True witness override (FIX-MM2) |
| Analyzer scope creep | Static analyzer parses untrusted files | Path boundary enforcement rejects files outside framework_root (FIX-MM3) |

---

## Non-Cognitive Constraint

The framework performs zero cognitive work. This is enforced by architecture (GOPEL's seven operations are defined as deterministic, and the Navigator runs on an external platform, not inside the framework), static analysis (the NonCognitiveAnalyzer scans all framework source files for cognitive imports, cognitive function calls, and content-dependent branching), and testing (every test suite verifies deterministic operations, and the static analyzer runs as part of CI validation).

### Static Analyzer Exclusion Rationale (CBG Audit Record)

**len() comparisons excluded**: `len(r.response_text) < 50` measures byte count, a structural property of the data, not its meaning. Measuring the size of a container does not require understanding its contents.

**Containment tests excluded**: `"--- SOURCE" in r.response_text` performs literal substring matching, functionally identical to regex. The `in` operator for strings is syntactic sugar for the same deterministic pattern-matching operation.

---

## Known Limitations

### Architectural (Irreducible at Any Scale)

**Semantic manipulation** (CA3): A well-crafted lie that contains no injection patterns, no unicode anomalies, no delimiter tricks, and passes all structural checks is undetectable by any deterministic system. The human checkpoint is the only defense.

**Monitoring-of-monitoring**: If the HeartbeatMonitor is also compromised, the recursion has no application-level termination.

**Arbitration trust boundary** (T3-F): Human arbitration input is not injection-sanitized before logging. The human is the trust anchor and human authority is absolute. If the human's workstation is compromised, this provides an unsanitized path into finalized output. Identified by Gemini.

**Transport verification timing** (T2-C): Transport integrity verification runs after dispatch/response records are already written to the audit trail. Raw data preservation is correct for forensic purposes, and violations are flagged in security_warnings. Identified by Kimi.

### Requires Deployment Infrastructure

**API key exposure** (H3): API keys stored as plaintext on adapter objects. Requires external KMS integration at deployment.

**Physical key theft**: HMAC signing keys in process memory. Requires hardware security modules (HSM) or trusted execution environments at infrastructure level.

**Key rotation** (T3-A): No automated rotation mechanism for operator or pipeline identity signing keys. Requires external KMS integration with rotation cadence enforcement. Identified independently by Kimi and Grok.

**Caller-supplied context** (GV8): GovernanceContext breach fields are assembled by the pipeline. A compromised pipeline module could supply false context values. Full mitigation requires signed context assembly within a trusted execution boundary. Identified by MiniMax AI.

**Windows portability** (T3-B): AuditFileLock uses fcntl.flock (POSIX only). Identified independently by DeepSeek and Grok.

### Development Targets (Specified, Not Yet Implemented)

**Navigator plurality**: Now specified in CICE v1.2 Section 4 (Navigator Plurality Protocol). Dispatching the Navigator task to multiple platforms simultaneously and cross-validating their syntheses. Applies the same provider plurality architecture used for primary prompt dispatch. Specification complete; code implementation is a separate development target.

**Deterministic Metadata Comparison**: Specified in CICE v1.2 Section 3. Pre-checkpoint anomaly summaries comparing structured field values across Response Records and Navigation Records with GREEN/YELLOW/RED classification. Code implementation is a separate development target.

**Statistical Process Control**: Specified in CICE v1.2 Section 3.5. Cross-cutting monitoring of data quality drift, triage misclassification, NPP divergence, and timeout frequency with automatic escalation. Code implementation is a separate development target.

**Explicit Delegation Boundaries**: Specified in CICE v1.2 Section 5. Auditable AIG-to-RAI conversion through Delegation Records with mandatory rationale, expiry, and sampling protocol. Code implementation is a separate development target.

**Confidential Processing Extension**: Specified in CPE v1.1. Four-profile classification with RFC 9334 RATS attestation for hardware-attested environments. Code implementation is a separate development target.

**Post-Quantum Cryptographic Agility**: Specified in the Post-Quantum Amendment v1.2. Hybrid composite signatures with ML-DSA-65, external hash chain anchoring, and NIST milestone-based cutover triggers. Code implementation is a separate development target.

**Governance state persistence**: The decision log and escalation state live in process memory. A crash resets escalation posture. Integration with SecureAuditLogger for persistent governance state is a future phase.

**O(N) persistence scaling** (T2-A): Both loggers serialize the entire record array on every log_record call. Production deployments should migrate to JSONL append-mode or a WAL pattern. Identified by Gemini.

**Governance module decomposition**: governance.py at 1,500+ lines would benefit from decomposition into authorization, policies, and escalation submodules. Identified by MiniMax AI.

---

## Implementation Roadmap

| Phase | Name | Status |
|-------|------|--------|
| 0 | Manual governance (Model 3) | Operational. Published book and case studies. |
| 1 | Audit file schema | Complete (v0.1.0) |
| 2 | Logging engine | Complete (v0.1.0) |
| 3 | API dispatch, synthesis, security hardening | Complete (v0.2.0 through v0.4.1) |
| 3.5 | Enterprise governance runtime | Complete (v0.5.0 through v0.6.1) |
| 4 | CICE implementation (DMC, NPP, EDB, SPC) | Specified (CICE v1.2). Code development next. |
| 5 | CPE and PQ Amendment implementation | Specified (CPE v1.1, PQ v1.2). Follows Phase 4. |
| 6 | Checkpoint gates (operating model enforcement) | Planned |
| 7 | Compliance validation and formal verification | Planned |

---

## Provider Plurality Evidence

Seven independent AI platforms reviewed this codebase across nine security passes. Each found things others missed. No single platform found everything. The pattern holds across every review: early adversarial reviews catch structural vulnerabilities, later reviews surface code quality refinements. The convergence of findings across independent platforms with different training data, different architectures, and different analytical approaches is the strongest evidence available that multi-AI review produces better governance outcomes than single-platform review. This is not a theoretical claim. It is an operational result documented across 183 tests with zero failures.

Reviewing platforms: Claude (Anthropic), ChatGPT (OpenAI), Gemini (Google), Grok (xAI), Kimi (Moonshot AI), DeepSeek, MiniMax AI.

CAIPR specification review platforms (governance documents): Claude, ChatGPT, Gemini, Grok, Kimi, DeepSeek.

External architectural review: Krzysztof Olbiński, Founder of Homo Digital (CICE v1.2 catalyst).

---

## Evidence Discipline

This software operates under a three-tier evidence discipline applied consistently across all publications.

**Tier 1** evidence is proven by others: peer-reviewed research, government reports, published standards. The automation bias research supporting the case for human checkpoints is Tier 1. The NIST AI Risk Management Framework and EU AI Act compliance requirements are Tier 1.

**Tier 2** evidence is built and operated as working concepts. GOPEL v0.6.1 is Tier 2. The adversarial review findings are Tier 2. The 183 test results are Tier 2. The published specification extensions (CICE, CPE, PQ Amendment) are Tier 2. These are not proven at institutional scale. They are working concepts with documented operational evidence showing promise.

**Tier 3** evidence is proposed for development. Code implementation of CICE, CPE, and the PQ Amendment is Tier 3. Production deployment with live API connections is Tier 3. Formal verification of the non-cognitive constraint is Tier 3.

No Tier 2 evidence is presented as Tier 1. No Tier 3 aspiration is presented as Tier 2 accomplishment.

---

## Related Documents

All published works are available at basilpuglisi.com, with supporting materials distributed across GitHub, SSRN, and Academia.edu.

**GOPEL:** GOPEL Canonical Public v1.5; GOPEL Proof of Concept v3.1; Checkpoint Information Chain Extension (CICE) v1.2; Confidential Processing Extension (CPE) v1.1; Post-Quantum Cryptographic Agility Amendment v1.2

**HAIA-RECCLIN:** HAIA-RECCLIN Multi-AI Framework, Third Edition; HAIA-RECCLIN Agent Architecture CBG Case Study v1.1; Case Studies 001 through 007

**HAIA-CAIPR:** HAIA-CAIPR Specification v1.1; HAIA-RECCLIN Case Study 006 v7; HAIA-CAIPR Publication

**CBG:** Checkpoint-Based Governance v5.0; The Missing Governor: Anthropic's Constitution and Essay Acknowledge What They Cannot Provide

**HEQ:** HEQ Enterprise White Paper v4.3.3; Measuring Augmented Intelligence: HEQ to AIS; From Measurement to Mastery; From Metrics to Meaning

**Legislative:** AI Provider Plurality Congressional Package (One Pager, Policy Brief, Legislative Framework, Technical Appendix, VAISA); distributed to the 119th Congress

**Books:** Governing AI: When Capability Exceeds Control (ISBN 9798349677687); Digital Factics; The Minds That Bend the Machine (anticipated April 2026)

---

## License

Open publication for public infrastructure.

---

Basil C. Puglisi, MPA
Digital Strategy Consultant & Responsible AI² Governance
A Human & AI Collaboration

Contact: me@basilpuglisi.com

#AIassisted
