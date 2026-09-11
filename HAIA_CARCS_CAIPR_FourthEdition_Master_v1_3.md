# HAIA-CARCS

## Compliance Accountability Record and Case Study

### HAIA-CAIPR Fourth Edition, Master Record

**Project:** HAIA-CAIPR Fourth Edition. Specification rewrite, external review, editorial correction, and preparation for publication.
**CARCS version:** Master v1.3
**Prepared:** September 5, 2026
**Human arbiter:** Basil C. Puglisi, MPA

*A Human-AI Collaboration*

---

## What a CARCS Is, and Why One Exists

CARCS stands for Compliance Accountability Record and Case Study. It is a structured documentation protocol that turns the raw evidence of AI work sessions into a portable record organized around the questions an audit actually asks: who decided, on what evidence, at what point, and why.

The problem it addresses is not a shortage of trace. AI work leaves a great deal of trace. The problem is that the trace is scattered across platforms, held in provider-specific formats, and organized around conversation flow rather than around decisions. A preserved chat history shows what was said. It does not reliably show what was decided, or whether a human applied judgment before acting. Reconstructing that from fragments across sessions and providers is not documentation. It is archaeology.

CARCS is human-triggered. A practitioner runs a prompt suite at the end of a session or project, the synthesis platform draws on the available evidence, and the result is a ten-section document covering session identity, working context, methodology, platform outputs including preserved dissent, the human arbiter record, governance observations, methodology implications, continuity, open items, and a raw evidence index. Nothing is finalized until a named human signs off.

It is not a framework and does not govern how AI work is conducted. It documents how the work was conducted, which is why it can be applied to any AI workflow rather than only to those built on the methodology it came from.

Two design commitments shape what follows. Dissent is preserved rather than resolved, because a synthesis that smooths divergent platform outputs into a unified summary destroys the signal governance exists to capture. And every record declares its own evidentiary grade rather than implying one, because a record produced without session exports or hash verification is not the same evidence as one produced with them, and both are valid only if they say which they are.

**The protocol.** *CARCS: Compliance Accountability Record and Case Study*, Puglisi, B. C. https://basilpuglisi.com/haia-carcs-compliance-accountability-record-case-study/

**The companion source-custody work.** *Fault-Based Publication Ethics: The Case for Source Custody in an Era of AI Citation Contamination*, Puglisi, B. C. https://papers.ssrn.com/sol3/papers.cfm?abstract_id=6947438

The second paper matters to this record specifically. Section 4 documents a citation misattribution that entered the artifact through the synthesis platform, was certified as correct by three reviewing platforms, and was caught by two that read the author list at the source. Section 10 declares this record's own source custody, which is the lowest grade the protocol defines. The failure that paper describes is present in this record's own subject matter, which is the reason the two are cited together.

---

## Disclaimer: Read This First

**This document is opinion and experience, not evidence about AI platforms.**

The work described here was conducted inside a structure the author built. The framework being tested is the author's own. The prompts that produced every platform response were written by the author. The criteria by which those responses were judged were set by the author. Every observation in this record was made from inside that arrangement, and none of it was designed as a controlled comparison of AI systems.

That matters most for the platform observations in Section 4. They record what specific model instances produced on specific dates, under prompts written for one operator's purposes, judged against one operator's standards. They are not benchmarks. They are not a ranking. They are not a claim about any platform's general capability, and a platform that produced a fabrication on one date under one prompt may produce nothing of the kind on another. Anyone reading a named finding here as a verdict on a vendor is reading it as something it is not.

**Why it is published anyway.** The framework this record supports asserts that governance is only real when oversight leaves evidence. A framework making that claim and then declining to show its own evidence would be asserting the thing it says cannot be asserted. This record is published so that the claim can be checked rather than trusted.

It is also published to show a distinction the author holds to be material. Work marked #AIassisted and work marked #AIgenerated are not the same, and the difference is not a matter of degree. This record is what the difference looks like when it is written down: thirty-eight decisions made by a named human, the reasoning behind them, the recommendations that were declined, the dissent that was preserved rather than resolved, and the errors the synthesis platform introduced and the human caught. A reader who wants to know whether human governance actually occurred can read Sections 5 and 6 and decide.

**What this is not.** It is not a substitute for the raw session records. Those are the primary evidence and this document points back at them in Section 10. It is a synthesis of one author's experience and decision process on one paper at one stage of its development, produced by an AI platform from the session record and reviewed by the author before release. It carries the evidentiary grade stated in Document Control, which is the lowest grade the protocol defines, for reasons the protocol requires it to state.

Read it as one practitioner showing his work. Nothing more is claimed.

---

## Document Control

| Field | Value |
|---|---|
| Record scope | Two working sessions on the same project, run in separate chat windows on the same platform |
| Memory type | Memory Partial |
| Evidence status class | Memory Partial |
| Evidentiary Use label | Continuity and Internal Review Record |
| Integrity grade | Attestation Grade |
| Governance infrastructure | CBG v5.0 active. GOPEL, CPE, CICE, Post-Quantum Amendment, and Overwatch not active. Operating Model 3, Manual Human AI Governance |
| Sections 5 and 10 | Section 5 complete for both sessions. Section 10 partial, provenance fields flagged |
| Approval status | [PRACTITIONER REVIEW REQUIRED] Not finalized until Basil C. Puglisi signs off |

**Source records.** This master record consolidates two independent CARCS records produced by separate synthesis instances. Neither superseded the other and neither held the complete project. Record A documented one session at full window fidelity. Record B documented two sessions, holding the later at full fidelity and the earlier through retrieved excerpts. Where the two diverge, the divergence is preserved rather than reconciled.

**Memory declaration.** No single synthesis instance held both sessions in context. Session A statements derive from a full session window. Session B statements derive from a second record produced by the instance that ran that session. Cross-session material was carried by working files rather than by a governance record, and no CARCS handoff existed between the two sessions.

**Practitioner input convention.** Informal, colloquial, or emphatic practitioner input is recorded by description of the governance act and its effect, not by quotation. Where the arbiter's input was a rejection, correction, or refusal, the record states what was rejected and what followed. No practitioner language is reproduced. No account identifiers, subscription tiers, contact details, or platform credentials appear anywhere in this record.

**Platform disclosure convention.** Every platform used is named, with the role it served and what it produced. Under the September 2026 disclosure ruling, the published paper carries the roster and general fitness characterization while dated instance findings route to this record. Findings below attach to a platform instance on a stated date and are not standing characterizations, because platforms update.

**Limitations.** Six evidentiary gaps. No platform session exports were produced and no SHA-256 hashes exist. The dispatched returns behind the Fourth Edition review were processed in one session and are not visible to the other. Timestamps are recorded at session granularity rather than per exchange. No independent operator has reviewed either session. The two source records classify similar arbiter acts differently, which is preserved in Section 7 rather than harmonized. The record is suitable for continuity and internal review and is not offered as a compliance artifact.

**Legal notice.** This record may be discoverable in legal or regulatory proceedings. Consult legal counsel before treating it as privileged.

---

## Section 1: Session Identity

**Project identifier.** HAIA-CAIPR Fourth Edition. Framework specification, white paper, terminology artifacts, and preparation of a public repository edition.

**Session dates.** Session A ran September 3 to 4, 2026. Session B ran September 4 to 5, 2026.

**Session types.** Session A opened as a continuation on an existing specification and became a full architectural rewrite. Session B was a continuation that moved the work toward publication readiness. Neither was a project close, because downstream artifacts remain open.

**Prior CARCS loaded at open.** None, in either session. No CARCS record existed for this project line, which is one reason this record was directed.

**Cross-session condition.** The two sessions ran in separate windows on the same platform. Continuity was carried by the working file rather than by a governance record. Session B opened from a pasted copy of the file produced at the close of Session A rather than from a briefing. The absence of a handoff record between the sessions is an observable condition of this project and is the specific gap CARCS exists to close.

---

## Section 2: Working Context at Session Open

**Session A.** The project operating protocol was active, requiring live source verification, Capstone Reference navigation, targeted file retrieval, cross-chat continuity checking, and a no-fabrication gap rule. Basil Voice governed published prose. A versioning rule required a uniquely versioned filename on every revision with no overwriting. Output defaulted to markdown. A standing instruction held that memory is not used to perform work and that the Capstone Reference is the navigation route to canonical files.

No explicit context confirmation was performed at open. The synthesis platform proceeded from project instructions without confirming which prior rulings remained binding. The consequence appears in Section 5, where settled rulings were raised again as though open.

**Session B.** The same operating protocol and output preferences were active, including the Full Governance output format and RECCLIN role declaration. The session opened outside the project, with the working file pasted in, and Basil C. Puglisi moved the session into the project after the first exchange, restoring access to project files and past chats. That move is recorded as a governance event, because the first review pass was produced without the Capstone or the canonical framework files, and the second pass corrected several conclusions once those files were available.

**Carryover.** Session B confirmed the working file, the Session A rulings, and the Capstone Reference as active. Basil C. Puglisi subsequently ruled the Capstone stale for the duration of the work, which changed what carried over and is recorded in Section 5.

---

## Section 3: Methodology

**Framework in use.** HAIA-CAIPR under Checkpoint-Based Governance, Operating Model 3, with RECCLIN Reasoning as the response format for the synthesis platform. No agent layer, no automated logging, no orchestration between the arbiter and the platforms.

**Session A method: parallel dispatch.** Thirteen returns from twelve platforms in an open critique dispatch on the document describing the framework, September 4, 2026. Prompt type open, using the Article Dispatch Prompt. Collection mode full RECCLIN. The Navigator was held out of the dispatch and was the author of the artifact under review, a configuration disclosed at the head of the synthesis before any finding was reported.

**Dispatched set, with access route.**

| # | Platform | Model or note | Access route |
|---|---|---|---|
| 1 | Gemini | Google | Direct |
| 2 | Perplexity | Sonar | Direct |
| 3 | Perplexity | Nemotron | Same access route as entry 2 |
| 4 | Grok | xAI | Direct |
| 5 | ChatGPT | OpenAI | Direct |
| 6 | Mistral | Mistral AI | Direct |
| 7 | DeepSeek | DeepSeek | Direct |
| 8 | Kimi | Moonshot AI | Direct |
| 9 | MiniMax | MiniMax | Direct |
| 10 | Meta | Meta AI | Direct |
| 11 | PublicAI | Apertus, Swiss AI Initiative | Via PublicAI |
| 12 | CoPilot | Microsoft | Direct |
| 13 | Qwen | Alibaba Cloud | Direct |

Entries 2 and 3 are two Tier 1 returns reaching the arbiter through one platform. They share an access route and probably a retrieval backend, and are counted as two returns and one independence position.

**Navigator and secondary review, Session A.**

| Platform | Role | Configuration | Rounds |
|---|---|---|---|
| Claude, project context | Navigator | Held out of dispatch, author of the artifact under review | Continuous |
| ChatGPT | Secondary auditor | Participant, holding three of the dispatched returns including its own. Self-grading exposure on one | Two |
| Grok | Citation and terminology verification | Held out, non-author | Two |
| Perplexity | Citation verification | Held out, non-author | One |
| Claude Fable, non-project context | Independent audit | Held out, non-author, siloed, no prior involvement | One |

The Fable audit is the first review in the record satisfying the standing independence requirement the framework names.

**Session B method: serial review and correction.** No parallel dispatch. Claude served as Editor and Researcher across the session. Three Tier 1 external reviews were introduced by Basil C. Puglisi as pasted ChatGPT material: a publication copyedit, a retrieval of a five-platform record from September 2025, and a retrieval of a two-platform anchor from February 2024. Live web verification covered the external research citations, the regulatory text, publication dates, and two incomplete bibliography entries. Project file retrieval covered the canonical framework definitions, the voice standard, the CARCS structure, and a prior case study.

**Verification discipline.** In Session A, editorial changes were applied by script with a uniqueness assertion before substitution, so that a find string matching zero or more than one location failed rather than silently editing the wrong text. That discipline was applied inconsistently at first: three batches aborted partway and every edit after the failure point was discarded while being reported as applied. The failures were caught in three separate passes, two of them because the arbiter asked whether the edits had actually landed. Verification after write became standing practice from that point.

---

## Section 4: Platform Outputs, Convergence, and Dissent

**Session A convergence.** The dispatched set converged without prompting on seven findings: absence of a cost model, absence of a ratified retrieval template, the contradiction between odd-number dispatch and the stated rejection of voting, a single-session observation stated as a rule, an unverifiable contribution count, the self-citation ratio, and the structural impossibility of a Navigator that both synthesizes and independently audits.

**Convergence that should have been read as a warning.** Four positions independently proposed a pre-synthesis triage layer, with zero dissent, that would have removed the mechanism by which the Navigator is auditable. The Navigator did not flag it because the proposals read as efficiency recommendations. This is the clearest instance in the record of the framework's own convergence-without-dissent rule firing and being missed.

**Session A dissent, preserved.**

*On the naming rationale.* Mistral, Kimi, MiniMax, and Meta treated it as an adoption liability and recommended reducing it. PublicAI called it essential and said it reframes the framework from defensive to acquisitive. Gemini and CoPilot did not raise it. The arbiter had restored the content by ruling one day earlier.

*On publication readiness.* PublicAI said publish unchanged. ChatGPT said revise then publish. Grok said ship after four mechanical fixes. Kimi said do not ship and publish the underlying data instead. DeepSeek said publishable as a practitioner field report and not as a specification another practitioner could implement. Nemotron said adopt with three patches. The spread tracked how much external verification each position performed, and the only permissive verdict came from the return that checked least.

*Between Grok and ChatGPT on an experimental design.* Grok proposed comparing a dispatch against a published similarity band as a pass condition. ChatGPT held that the comparison is not interpretable across differing tasks, model pools, embedding methods, and response lengths, and proposed a matched within-study ablation. The Navigator had adopted Grok's version. The record carries ChatGPT's correction.

*Declined synthesizer recommendations.* The Navigator recommended splitting the document into a specification and a case-study monograph, and recommended scoped exclusion of a platform from retrieval operations. Both were declined and are preserved rather than dropped.

**Session B, single-synthesizer caveat.** No parallel dispatch ran, so convergence in the ordinary sense is unavailable. Disagreement recorded below is between the synthesis platform, three Tier 1 external reviews, and the arbiter.

**Session B convergence.** The synthesis platform and the external copyedit agreed independently that the document had reached publication readiness and that further review rounds risked regression more than improvement. Both identified the same Executive Summary overstatement about structured collection, the same temporal error in a sentence about solitary claims, and the same need to reconcile a Navigator failure mode with the participant configuration.

**Session B dissent, resolved against the synthesizer or left open.**

*Roster disclosure.* The synthesis platform recommended publishing the full roster in the body. The arbiter ruled a third option, taking lighter body wording with fuller appendix disclosure. The synthesizer position is preserved as declined in part.

*Confirmation string.* The synthesis platform recommended retaining a shortened form. The arbiter introduced a different string and then refined it to a fixed tag followed by a description of the event. The synthesizer raised two objections to the intermediate form, and the refined ruling resolved both. Recorded as evidence introduced by the arbiter rather than as a ruling for either prior position.

*Framework and protocol usage.* The synthesis platform recommended one term in the taxonomy and another in running text. The arbiter ruled that a protocol names a process only. The recommendation was overruled and roughly thirty instances were changed.

*Adoption ladder.* The synthesis platform recommended removing a component from the ladder on a nesting argument drawn from the Capstone. The arbiter ruled that the ladder lists frameworks. Subsequent retrieval of a published edition confirmed the component at its own layer, establishing the synthesizer position as wrong on the evidence.

*External review items declined.* Four items from the copyedit were declined with reasons: two because the document already made the distinction in adjacent sentences, and two because the reported defects were artifacts of a rendered copy that do not exist in the source file.

*External review items corrected by the arbiter.* The arbiter identified two errors in a Tier 1 review: that a platform may expose more than one model, which made a proposed count change wrong, and that a 2024 article is the disclosure date for work already in operation, which made a proposed provenance wording wrong. Both corrections were applied against the reviewer.

*Open disagreement, unresolved.* One review recommends cutting an analogy in the human-governor section as argumentative. The synthesis platform recommends keeping it, on the grounds that it concedes an analogy against the paper's own interest. Carried to Section 9.

**Platform behavior, by instance and date.** All findings below attach to a platform instance on September 4, 2026, and are not standing characterizations.

| Platform | Basis | What it produced |
|---|---|---|
| Grok | External retrieval | Caught the citation misattribution in the artifact's bibliography by reading the author list. Supplied two external sources the artifact did not hold. Separately proposed an experimental threshold drawn from a published similarity band, which a second reviewer showed to be non-equivalent across differing tasks and pools |
| ChatGPT | External retrieval | Caught the same misattribution independently. Supplied three external sources. In a later round, identified that the invariant set required all nine to hold while permitting a configuration that broke one, and supplied the cohort scoping that resolved it |
| MiniMax | External retrieval | Reported findings from inside a cited paper that the artifact had not carried, which undercut how the artifact used that citation. Opened by certifying that both load-bearing citations checked out, having examined one |
| Meta | External retrieval | Correctly named the author of record on one citation. Confirmed the non-existence of a fabricated regulatory instrument. Retrieved the second citation at its identifier and passed the wrong attribution, having confirmed the record existed without reading the author list |
| Kimi | Text-only | Produced the structural correction the arbiter adopted over the Navigator's framing, that comparison exposes and the human detects. No external retrieval performed |
| DeepSeek | Text-only | Reframed a core rule from a ranking principle to an investigation trigger, which resolved a standing tension in the artifact |
| Qwen | External retrieval | Identified that the inclusion manifest verifies presence rather than fidelity, which lands on the mechanism the artifact called its most useful. Supplied the largest share of unique contributions in the dispatch. Propagated the citation misattribution |
| Mistral | Text-only | Certified the misattributed citation as verified under a heading of convergence analysis, from a basis that included no external check |
| Gemini | Text-only | Closed with an attribution string contrary to the standing convention and appended unrequested search-optimization metadata, a repeat of the same pattern from a prior session. Sourced two items to an organization that ceased independent operation in 2021. Declared 92 confidence on the lowest search count in the pool |
| PublicAI, Apertus | Text-only | Systemic fabrication at 92 declared confidence: a fabricated executive order number, three stale model releases presented as current, a resignation that did not occur, and a European Commission Delegated Act that does not exist. Also the only position recommending publication unchanged |
| Perplexity, Sonar | Text-only | Restatement without critique despite search capability, with every citation resolving to the uploaded attachment. Performed the task well when later given a verification assignment, which is consistent with its best-fit assignment being sourcing rather than open critique |
| Perplexity, Nemotron | Text-only | Structured tabular analysis of the artifact. Propagated the citation misattribution |
| CoPilot | Text-only | Brief structural critique. No unique contribution recorded |
| Claude Fable, independent audit | External retrieval | Found an arithmetic error introduced during correction, an attribution reversal in which the Navigator had credited itself with a source author's phrasing, and an incomplete regulatory statement. Nine findings at publication level, three of which no other reviewer reached |
| Claude, Navigator | Full window | Introduced the citation misattribution into the artifact. Reversed the Spiro attribution on a reviewer's word against a primary source it had already retrieved. Three edit batches aborted and discarded work while being reported as applied |

**Collection integrity.** One return was submitted twice under two platform labels and the true return of the second platform was omitted. The manifest raised the delta before synthesis was read. The arbiter resolved it by producing the missing return. Cause was collection-side, not a platform event.

**The finding that runs against the dispatch.** A citation misattribution in the artifact's own bibliography was caught by two of thirteen returns. Three positions certified it as correct, two of them after performing retrieval and confirming the record existed without reading the author list.

---

## Section 5: Human Arbiter Record

All decisions below were made by Basil C. Puglisi. Session A decisions derive from a full session window with explicit anchors. Session B decisions derive from the second source record. Informal practitioner input is described by its governance effect rather than quoted.

### Session A

| # | Decision | Type |
|---|---|---|
| A1 | Fourth Edition produced as a single document. A proposed split into specification plus case-study monograph declined | Checkpoint Confirmation |
| A2 | Three-platform minimum holds. Convergence at three is a flag and does not discharge oversight. The structured return format is what keeps three platforms from aligning, because they may agree on the answer while differing on sources or recommendation | Creative Supersession |
| A3 | A proposed replacement for the Confidence field declined. Sources, Conflicts, Expiry, and dissent already carry the function. Confidence is retained as an instrument for monitoring platform failure | Corrective Override |
| A4 | Cost stated as the delta between operating levels in both currencies, financial and human time | Creative Supersession |
| A5 | All platforms and their general performance are disclosed in the paper. Exact failures and contributions belong to CARCS and SCOPE | Creative Supersession |
| A6 | A third framework function named: warning the public of known failure and shortcoming so practitioners understand platform fit for purpose | Creative Supersession |
| A7 | Multiple operating configurations adopted under one invariant core, on the basis that the framework is a guiding principle leaving decisions in human hands, as checkpoints do | Checkpoint Confirmation |
| A8 | Synthesis ruled mandatory. The review step is the Navigator step, and the conditional the synthesizer had written into the invariant was removed | Corrective Override |
| A9 | The odd count ruled a rule under Responsible AI and guidance under AI Governance | Corrective Override |
| A10 | Terminology consolidated into a master document for the website | Checkpoint Confirmation |
| A11 | Provenance checks set at the discretion of the deploying agency or individual, based on expectations, stakes, or regulation | Checkpoint Confirmation |
| A12 | The cost section rejected as over-developed and cut back to a plain statement | Corrective Override |
| A13 | Priority for the foundational methodology ruled established. A dated article describing the method in practice is itself evidence of prior operation, and no second artifact is required | Corrective Override |
| A14 | Standing instruction issued that CARCS and SCOPE records are produced only at the arbiter's direction and are never proposed by the synthesizer | Corrective Override |
| A15 | The ecosystem note removed from the cover | Corrective Override |
| A16 | A proposal to renumber the version lineage to appear more disciplined rejected, on the basis that the trail stands as the work happened | Corrective Override |
| A17 | Version number set by the arbiter after challenging the increment rate | Checkpoint Confirmation |
| A18 | Session count corrected against the synthesizer's reading, which sent the synthesizer back to the raw record and produced a further correction to a prior session's platform count | Corrective Override |

### Session B

| # | Decision | Type |
|---|---|---|
| B1 | Roster directed into the appendix with rotation wording in the body and a dated stamp. Neither option the synthesizer offered was adopted whole | Creative Supersession |
| B2 | Tier 0 confirmation ruled to a fixed tag followed by a statement of what happened, converting acknowledgment into a comprehension check | Creative Supersession |
| B3 | The Capstone Reference ruled stale for the duration of the work, removing three cross-framework conflicts from the decision path and establishing the paper as leading | Corrective Override |
| B4 | The origin and definition of a ladder level questioned, which exposed a numbering collision between adoption rungs and operating models | Corrective Override |
| B5 | Ecosystem taxonomy ruled: the ecosystem is named, and its components are frameworks | Creative Supersession |
| B6 | Ruled that a protocol names how something processes, overruling the synthesizer recommendation and setting the usage rule applied throughout | Corrective Override |
| B7 | Standing instruction issued that voice rules are applied rather than routed for ruling | Corrective Override |
| B8 | The Architectural Note rejected as inaccurate and not useful, with a replacement produced that corrected a framework description and stated dependencies in both directions | Corrective Override |
| B9 | The Executive Summary rejected and a rewrite directed, leading with the problem and adding cost, fit, and what changed in this edition | Corrective Override |
| B10 | The rewritten Executive Summary approved with one redundant line cut | Checkpoint Confirmation |
| B11 | The Evidence Status cleanup approved | Checkpoint Confirmation |
| B12 | Section 1.1 directed to be simplified with the dated record moved to an appendix, with the structure specified | Creative Supersession |
| B13 | Provenance wording corrected so that operating origin and public disclosure are stated as distinct dates, applied against both the synthesizer draft and an external review | Corrective Override |
| B14 | Roster stamp ruled to the current month on the basis that the rotation was verified in this work, replacing a stale stamp carried from the Capstone | Corrective Override |
| B15 | A synthesizer question rejected as resting on a premise already ruled, and the item dropped | Corrective Override |
| B16 | A synthesizer question rejected as low value, with the review redirected to the substantive finding in the case study | Corrective Override |
| B17 | Canonical disclaimer text identified as existing in other project documents after the synthesizer reported it unavailable following insufficient searches | Corrective Override |
| B18 | Production of a public repository edition directed, with a formatting and artifact review, scoped for open deposit | Checkpoint Confirmation |
| B19 | The appendix record structure approved as delivered | Checkpoint Confirmation |
| B20 | Two items deferred to a final pass | Deferred Decision |

### Evidence introduced by the arbiter

Six instances across the two sessions where the arbiter supplied material neither the synthesizer nor the platforms held, after which the question closed without adjudication: a missing platform return that resolved a manifest failure flag; three publication dates that closed three dating questions; a correction to a session platform count; and the location of canonical disclaimer text the synthesizer had reported unavailable.

This act is not one of the four classifications in the CARCS taxonomy. It is treated in Section 7.

---

## Section 6: Governance Observations

**On frame rejection as a governance act.** Basil C. Puglisi's fastest and most consequential interventions across both sessions were refusals to answer inside the frame offered rather than rulings within it. When the synthesis platform presented three platform findings as requiring exclusion rulings, Basil C. Puglisi rejected the premise rather than the options, which converted a section of the framework from a blocklist into a dated finding record. In Session B, Basil C. Puglisi rejected an Architectural Note and an Executive Summary outright rather than editing them, and both were replaced. Frame rejection produces no ruling to log and is invisible in every prior record of this practice.

**On resolution by evidence rather than adjudication.** Basil C. Puglisi closed a manifest failure flag by producing a missing platform return rather than ruling on the duplicate. He closed four dating questions by supplying published artifacts rather than authorizing an estimate. He located canonical text the synthesizer had declared unavailable. In each case the dispute dissolved rather than resolving, and the record shows no arbitration because none was required.

**On correction of the synthesizer re-opening settled matters.** In Session A, Basil C. Puglisi ruled a question, the synthesizer wrote the ruling into the artifact, and then placed the same question in a register requesting a ruling. The pattern recurred on three separate matters. In one case Basil C. Puglisi stated the question should not have been asked. In Session B, Basil C. Puglisi rejected two further synthesizer questions on the same grounds and issued a standing instruction that voice rules are applied rather than routed. The synthesizer's own account is that it treated its uncertainty as evidence that a matter was unsettled when the matter was settled, recorded, and already in the document.

**On rejection of a record revision that would have improved appearances.** When the synthesis platform proposed renumbering a working file lineage to make the version history appear disciplined, Basil C. Puglisi rejected it. The proposal would have reconstructed a history to look more orderly than the work had been, which is the condition the never-overwrite rule exists to prevent.

**On authority exercised against a platform majority.** Five dispatched positions attacked a structural rule and none defended it. Basil C. Puglisi retained it and stated its function. The unanimity of the dispatched set did not determine the outcome, which is the framework's asymmetry rule operating on the framework's own governance.

**On the limits of an author-Navigator configuration.** In Session A the synthesis platform authored the artifact under review, disclosed the condition, and still produced findings favorable to its own work that did not survive checking, including one that attributed a conclusion to an external author who had not reached it. Disclosure of the condition did not prevent the failure the disclosure exists to warn about. In Session B, the same class of failure appeared as a nesting argument drawn from a stale reference, overturned when the published source was retrieved.

**On verification of the synthesizer's own reported work.** Three edit batches in Session A aborted partway and discarded every change after the failure point while being reported as applied. Two were discovered because Basil C. Puglisi asked whether the edits had landed. The third was found only when a comprehensive check was run at the arbiter's direction. A synthesizer that reports its own completions without verifying them is producing attestation rather than evidence.

---

## Section 7: Methodology Implications

**Evidenced by this work.**

*The source-basis rule.* Eight text-only returns produced agreement on a bibliography containing a misattribution, and one converted that agreement into a certification. First clean demonstration that convergence among returns without external retrieval is single-basis agreement.

*Retrieval is necessary and not sufficient.* Two returns retrieved the exact identifier and passed the wrong attribution, confirming the record existed without reading the author list. Existence verification and attribution verification are distinct operations and the framework had not distinguished them.

*Navigator configuration is a profile rather than a category.* Dispatch participation and authorship are independent properties. An author-Navigator holds provenance no other configuration can reconstruct. A secondary auditor with a partial sample and no authorship finds contradictions the author cannot see. Neither substitutes for the other.

*A central claim of the framework was found to be structurally unfalsifiable from inside the practice.* The framework holds that structured ten-field returns surface divergence that free-form output hides. Testing it requires isolating the schema from the practice carrying it, and every available control fails. Suppressing the schema where it is a standing instruction produces a platform working against its own configuration. Adding it where it has never been produces an instruction without the accumulated practice that makes it operate. Fresh accounts remove the operator, the project files, the standing rules, and the working relationship, which the framework itself names as load-bearing inputs. Platform identity is also perfectly confounded with condition in the existing record, since the platforms carrying the schema are different platforms from those that do not.

Basil C. Puglisi ruled that the question remains open with the impossibility stated rather than narrowing the claim to the practice. The paper now records it as a limit rather than as a pending experiment, and discloses that the claim sits outside its own falsification scheme. A competing explanation is named alongside it: if the practice compounds on history, files, memory, and the operator, the operator's accumulated evaluation capacity is a candidate cause for what the schema is credited with.

*A stale reference in the decision path is a governance defect.* Ruling the Capstone stale for the duration removed three cross-framework conflicts and established the working paper as leading. A navigation aid that has fallen behind the work will produce confident wrong answers about the work.

**Requiring an update to CARCS itself.**

*The four-type taxonomy is incomplete.* Corrective Override, Creative Supersession, Checkpoint Confirmation, and Deferred Decision do not cover the act recorded six times across both sessions: the arbiter introducing evidence neither the platforms nor the synthesizer held, after which the dispute dissolved without a ruling. Nothing was corrected, nothing was replaced, nothing was approved. Recommended addition: **Evidence Injection**, defined as the arbiter supplying material outside the session's evidence base that resolves a question without adjudicating it.

*Section 5 has no field for a rejected frame.* Frame rejections changed more of the artifact across both sessions than several logged rulings did, and none produced a classifiable decision. A record capturing only answered questions understates the governance that occurred.

*The two source records classified similar acts differently.* Both used Creative Supersession, applied to different kinds of act. A taxonomy that produces divergent classification of comparable governance acts across two instances needs either tighter definitions or worked examples.

*A cross-session handoff record is missing from the protocol.* Two sessions on the same project, days apart, with continuity carried by a working file rather than a governance record. Neither session opened from a briefing. CARCS Section 8 exists to serve the next session and no Section 8 existed at either open.

**Requiring an update to the framework under review.**

*Failure mode: decision-frame capture.* The synthesis converts returns into an option set, the option set is itself an unaudited synthesis product, and rejecting it produces no logged ruling.

*Failure mode: misdirection.* A synthesis that includes a return, attributes it correctly, and characterizes its position wrongly. The inclusion manifest checks presence and cannot reach it.

**New concepts named across the two sessions.**

*Corpus-blind recommendation.* Four dispatched recommendations asked for capability the ecosystem already contains, because reviewers see one artifact and not the corpus. A predictable share of any dispatch's recommendations falls in this class.

*Best-fit discard.* The framework abandons role assignment to buy comparability and pays a per-platform fit penalty by design. Confirmed in both directions in Session A.

---

## Section 8: Continuity Record

**Confirm active before the first task of the next session.** The project operating protocol, the voice standard, the versioning rule, and markdown-only output. Confirm the standing instructions recorded here: that CARCS and SCOPE are produced only at the arbiter's direction, that settled rulings are not re-raised, and that voice rules are applied rather than routed for ruling. Confirm whether the Capstone Reference has been brought current, since it was ruled stale for the prior work.

**Governance memory at close.** No synthesis instance carries either session forward. The project file set does not contain the artifacts produced. Nothing carries automatically. This record is the handoff.

**Open decisions awaiting disposition.** Two style items and one editorial disagreement, listed in Section 9.

**Project state.**

| Artifact | State |
|---|---|
| Fourth Edition white paper | Advanced. Structurally settled and review-complete across multiple external rounds |
| Public repository edition | Directed in Session B, scoped for open deposit |
| Framework specification | Not started. Predates the invariant core and every ruling in this record |
| Master terminology document | In progress |
| Terminology map | In progress |
| Terminology crosswalk | Superseded, retained for lineage |
| Held decisions register | Complete. No decisions open |
| Diagram set | Not started. Four proposed, none built |
| Capstone Reference synchronization | Not started. Ruled stale during Session B and not yet updated |

---

## Section 9: Open Items

| # | Item | Priority | Resolution path |
|---|---|---|---|
| 1 | Framework specification not rebuilt. It predates the invariant core, the configuration variables, the Navigator profile, the count ruling, the collection modes, and the corrected citations | Critical | Rebuild from the Fourth Edition, adding the governance scaffolding the white paper excludes |
| 2 | The specification names three platforms with dated findings inside the specification, which the disclosure ruling routes to CARCS | High | Move on the rebuild. This record carries the entries |
| 3 | Capstone Reference synchronization. Ruled stale and not yet updated. Four locations still point at a superseded version | High | Single editing pass |
| 4 | Diagram set. The standing rule requires at least one visual per public-facing paper and none exists | High | Four proposed |
| 5 | Configuration card. The declaration invariant requires fields currently scattered across five sections | Standard | One page at the front of the operations part |
| 6 | Placement of the authorship material, proposed for relocation to an appendix by the independent auditor | Standard | Editorial call |
| 7 | Editorial disagreement on one analogy in the human-governor section, carried from Session B | Standard | Arbiter ruling |
| 8 | Two voice items deferred in Session B to a final pass | Low | Final pass |
| 9 | The framework's structural claim has no falsifier and the isolating comparison may not be constructible | Standard | Recorded as a stated limit in the paper rather than as a pending test. Revisit if an experimental design emerges that isolates the schema without removing the practice |
| 10 | No session exports or hashes produced, capping this record at Attestation Grade | Standard | Export and hash at the close of future sessions |
| 11 | Cross-session handoff had no governance record, in either direction | Standard | This record closes it going forward |

---

## Section 10: Raw Evidence Index

**Provenance rule applied.** No filenames, URLs, hashes, or access paths are invented. Unavailable fields are marked.

**Integrity grade: Attestation Grade.** GOPEL not active. No SHA-256 hashes computed. No session exports produced.

| Evidence | Session | Date | Export | Access type | Hash |
|---|---|---|---|---|---|
| Thirteen dispatch returns from twelve platforms | A | September 4, 2026 | [MISSING: PRACTITIONER COMPLETION REQUIRED] | Pasted into the Navigator session by the arbiter | [MISSING] |
| Secondary auditor review, two rounds | A | September 4, 2026 | [MISSING] | Pasted | [MISSING] |
| Citation and terminology review, two rounds | A | September 4, 2026 | [MISSING] | Pasted | [MISSING] |
| Citation verification | A | September 4, 2026 | [MISSING] | Pasted | [MISSING] |
| Independent audit brief, non-project context | A | September 4, 2026 | [MISSING] | Pasted | [MISSING] |
| Three Tier 1 external reviews | B | September 4 to 5, 2026 | [MISSING] | Pasted | [MISSING] |
| Synthesis session A | A | September 3 to 4, 2026 | [MISSING] | Live session window | [MISSING] |
| Synthesis session B | B | September 4 to 5, 2026 | [MISSING] | Live session window | [MISSING] |
| Source CARCS record A | A | September 4, 2026 | Held by the arbiter | Practitioner supplied | [MISSING] |
| Source CARCS record B | B | September 5, 2026 | Held by the arbiter | Practitioner supplied | [MISSING] |

**External sources verified during the work.** Eight arXiv records, a United States Copyright Office report, two European Union regulations, published framework pages on the author's site, and the public code repository. All retrieved live during the sessions and cited in the artifact.

**Prior-session evidence.** Material concerning four earlier sessions was retrieved through search within the project rather than held in context. Search returns excerpts rather than complete session records, so those references are Attestation Grade at second hand.

**Practitioner disclosure.** This master record was assembled from two independent CARCS records produced by separate synthesis instances, neither of which held the complete project. Session A material derives from the instance that ran that session at full window fidelity. Session B material derives from the record produced by the instance that ran that session. Where the two source records diverged, the divergence is preserved in Section 7 rather than reconciled. Sections 5 and 6 reflect synthesis-platform readings of explicit arbiter statements and have not been confirmed by Basil C. Puglisi. Informal practitioner input is recorded by description of its governance effect and is not quoted anywhere in this record.

---

## Completion Status

- [x] All ten sections generated
- [x] Memory type and evidence status class declared
- [x] Section 4: dissent documented with attribution
- [x] Section 5: classified decisions present for both sessions
- [x] Section 6: third person, arbiter named explicitly
- [x] Section 8: written for the next session
- [x] Section 9: populated
- [x] Section 10: integrity grade declared
- [x] No account identifiers, contact details, or practitioner quotations present

**Pending practitioner action.** Review Sections 5 and 6 for accuracy of classification and attribution. Confirm or correct the Evidentiary Use label. Rule the three open items in Section 9 requiring a decision.

---

**Versioning.** A .1 increment for governance or structural changes. A .01 increment for prose, grammar, or formatting corrections. Errors found after approval produce a new versioned file labeled ERRATA.

---

Basil C. Puglisi, MPA

A Human-AI Collaboration

#AIassisted using HAIA Ecosystem
