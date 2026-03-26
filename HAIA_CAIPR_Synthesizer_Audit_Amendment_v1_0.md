# HAIA-CAIPR Synthesizer Audit Amendment v1.0

**Extension to:** HAIA-CAIPR Specification v1.1, Sections 3.5, 3.6, 3.7
**Date:** March 2026
**Status:** Amendment (to be incorporated into CAIPR v1.2)
**Attribution:** #AIassisted under HAIA-RECCLIN and Checkpoint-Based Governance

---

## Purpose

This amendment specifies how an auditor evaluates the Navigator-Synthesizer using the RECCLIN structured fields present in each platform output. The RECCLIN output (Sources, Conflicts, Confidence, Expiry, Fact→Tactic→KPI) is the audit trail. The Navigator is the subject of the audit. The human auditor is the authority.

---

## 1. Source-Overlap Mapping (Required Synthesizer Step)

Before producing score-level convergence, the synthesizer must build a source table from every platform's RECCLIN Sources field.

The table classifies each platform's evidence basis as one of three types:

- **Text-only:** platform cited only the supplied input with no external retrieval.
- **External-sourced:** platform independently retrieved and cited at least one source outside the supplied input.
- **Shared-external:** two or more platforms independently cited the same external source.

Convergence from text-only platforms is single-basis agreement. Convergence from external-sourced platforms with independent sources is multi-basis agreement. The synthesizer must state which type supports each convergence finding.

---

## 2. Dissent-Source Verification (Required Synthesizer Step)

When platforms diverge by more than one point on any dimension, the synthesizer must:

1. Pull the RECCLIN Sources and Conflicts fields from each dissenting platform.
2. Identify whether the dissent cites specific passages, external evidence, or unsupported assessment.
3. Run independent verification against the cited evidence where feasible.
4. State in the synthesis which dissent is evidence-grounded and which is not.

The Factics structure applies: the dissent is the claim, the RECCLIN Sources field is the fact, the independent verification is the tactic, and the resolution (confirmed, refuted, or unresolvable) is the KPI.

---

## 3. Auditor Evaluation Path

The auditor evaluates the Navigator-Synthesizer by comparing the synthesis output against raw RECCLIN outputs from each platform. The auditor checks:

- **Source-overlap accuracy:** Did the synthesizer correctly identify which platforms used external sources versus text-only?
- **Dissent preservation with evidence:** Did the synthesizer preserve dissent and cite the RECCLIN evidence each dissenting platform provided?
- **Convergence weighting:** Did the synthesizer weight multi-basis convergence differently from single-basis convergence?
- **Conflict resolution rationale:** When the synthesizer resolved a divergence, did it state which platform's evidence was stronger and why?

A synthesis that cannot be traced back to specific RECCLIN fields in specific platform outputs fails audit.

---

## 4. Relationship to Existing Spec

This amendment extends, and does not replace, the following CAIPR v1.1 sections:

- **Section 3.5 (Convergence Analysis):** adds source-basis classification to the existing factual, analytical, and recommendation convergence types.
- **Section 3.6 (Synthesizer Oversight):** adds source-overlap mapping and dissent-source verification to the existing seven failure modes and governance requirements.
- **Section 3.7 (Source-Authority Discrimination):** adds the auditor evaluation path as the mechanism by which Tier 0 authority verifies Tier 2 synthesizer compliance.

---

## Origin

This amendment originated from operational practice during a seven-platform CAIPR review of the article "The Evocative Audit: What Metrics Cannot Carry" (March 2026). The synthesizer performed score-level convergence analysis without mapping source overlap across platform RECCLIN outputs, without comparing the evidence basis of dissenting platforms, and without distinguishing single-basis from multi-basis convergence. An independent review by the synthesizer platform (Claude) caught a factual gap (*Unmasking AI*, 2023) that all seven dispatched platforms missed, validating the need for independent source verification as a formal synthesizer requirement. The Tier 0 human arbiter identified that the RECCLIN structured output on each platform response is the material the auditor uses to evaluate the Navigator, not a formatting convention, and directed this amendment.

#AIassisted
