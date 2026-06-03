# SCOPE

## SOURCE CUSTODY OBSERVABLE PUBLICATION EVIDENCE

*A Structured Documentation Protocol for External Source Verification in Published Work*

Version 1.0 · June 2026

**Basil C. Puglisi, MPA**

*A Human-AI Collaboration*

basilpuglisi.com

*Working paper released for feedback and collaboration · Published under Open Access*

*#AIassisted using HAIA Ecosystem*

---

## The Source Custody Gap in Published Work

Organizations and practitioners are publishing at scale, and most publication integrity discussion still centers on whether citations are accurate, whether AI generated them, and which enforcement should follow when they are not. What receives far less attention is the practical question that arrives after a citation is challenged: what record exists of what the author verified, when the author verified it, and whether the source supported the claim at the time of use?

This question is no longer theoretical. Automated citation-verification pipelines are entering scholarly workflows. AI-detection tools flag submissions for suspected fabricated references. Platforms impose bans. Ethics bodies assign blanket responsibility. When a citation is challenged, the author has no standardized evidentiary record to produce in rebuttal, because no publication system asks authors to document what they verified at the time of use and no mechanism exists to produce that documentation on challenge.

The problem is not lack of verification. Many authors verify carefully. The problem is that verification effort is invisible. An author who checked every citation against the primary record, ran status queries, and archived the source occupies the same position as an author who never opened a single reference. No framework records the difference. No mechanism produces it.

SCOPE exists to close that gap.

---

## What SCOPE Is

SCOPE stands for Source Custody Observable Publication Evidence. It is a structured documentation protocol that records what an author verified about each cited source at the time of use, creating a private evidentiary record that can be produced when a citation is challenged or the work's credibility is questioned.

SCOPE is human-triggered. The author creates a SCOPE record at the point of citation, when a source is first added to the manuscript's reference list. The author decides which sources to document, at which depth, based on their own assessment of the claim's stakes and the source's stability. Nothing in the record is produced or shared unless the author chooses to produce it.

SCOPE is not a framework and does not govern how research is conducted. It documents what external sources were verified during the research process, and the distinction matters because SCOPE can apply to any publication workflow, not only those operating under HAIA methodology. Any author, researcher, journalist, or practitioner who cites external sources and wants a record of what they verified can use SCOPE. The field template in the appendix to this paper is deliberately designed without framework-specific terminology so it functions across any context.

Within the HAIA ecosystem, SCOPE serves as the external-source verification layer alongside HAIA-CARCS. CARCS documents how AI work was conducted (sessions, decisions, arbitration, platform outputs). SCOPE documents what external sources were verified at time of use (citations, archives, status checks, claim-support assessments). They serve different functions and answer different questions. A complete governed record of published work that cites external sources includes both.

Outside the HAIA ecosystem, SCOPE applies wherever published work cites sources and the author wants a private record of what was checked. The adoption channels described in this specification (author prerogative, publisher requirement, insurance condition) operate independently of any governance framework.

---

## How SCOPE Relates to CARCS

CARCS and SCOPE are complementary, not overlapping. The relationship is:

**CARCS documents the session.** How the work was produced, what AI platforms contributed, what the human arbiter decided, what dissent was preserved, and what comes next. CARCS answers: how was this work done?

**SCOPE documents the sources.** What external references were cited, whether each source was verified at time of use, what the source said, whether it supported the claim, and where the preserved copy resides. SCOPE answers: what did the author verify about what they cited?

**CARCS Section 10 (Raw Evidence Index) depends on external provenance data the synthesis platform cannot generate independently.** This was identified as a limitation in CARCS v1.4. SCOPE fills that gap. When a CARCS record references external sources, the SCOPE ledger provides the verification evidence that CARCS Section 10 cannot produce on its own.

**Standalone use:** SCOPE can be produced without CARCS. An author writing a traditional research paper without AI collaboration has no need for a CARCS session record but may want a SCOPE ledger for their citations. SCOPE operates independently.

**Integrated use:** When both CARCS and SCOPE are produced for the same project, SCOPE attaches to the CARCS record as a companion document. The CARCS record references the SCOPE ledger in Section 10. The SCOPE ledger references the CARCS record in its project metadata. Together they form a complete governed record: session governance (CARCS) and source governance (SCOPE).

---

## Why Source Custody Matters

Source custody matters first at the evidentiary level. When an author is asked to show that a cited source was verified before publication, the citation itself is thin evidence. It shows what was cited but not whether the author opened the source, read the relevant passage, confirmed the content supported the claim, or checked whether the source had been retracted or corrected. A SCOPE record that documents the access date, the archived snapshot, the claim-support classification, and the status check result belongs to a different evidentiary category. It is not just a reference list but verification made legible.

It matters just as much at the operational level. Citation verification during manuscript preparation is real work that takes real time. When that work is invisible, it cannot be distinguished from its absence. A SCOPE record created at the point of citation preserves the verification contemporaneously, which is stronger evidence than reconstruction from memory after a challenge arrives.

It also matters at the institutional level. A publisher that requires submitting authors to maintain a SCOPE ledger producible on request reduces the publisher's exposure to retraction disputes, misconduct allegations, and the administrative cost of adjudicating citation challenges without documentation. An insurance carrier that conditions coverage on source custody records creates a market-driven incentive for verification without mandating the process.

---

## How SCOPE Works

SCOPE produces a structured record at the point of citation. Each entry documents one cited source. The author selects the documentation depth based on the stakes of the claim the citation supports.

### Three Tiers

The author decides which tier applies to each citation. No external party makes this decision.

**Tier 1: Basic Source Check.** Applied to all references regardless of claim type. Documents that the source exists, the metadata matches, and the author confirmed access. Fields: source title, author or organization, DOI or URL or persistent identifier, date accessed, existence confirmed (the URL resolved to a live page with matching title and author). Estimated time: under one minute per citation.

**Tier 2: Claim Support Record.** Applied to references supporting factual, statistical, medical, policy, legal, or accusatory claims. Documents what the source is cited to prove and whether the source actually supports that claim. Fields: all Tier 1 fields plus the exact claim the citation supports (one sentence), the page or section where the supporting evidence appears, a claim-support classification (direct support, indirect support, background only, or does not support), and the source type (primary research, secondary source, commentary, data, opinion, news reporting). Estimated time: two to three minutes per citation.

The claim-support field addresses a risk the UK Research Integrity Office identifies directly: AI tools may provide real-looking references that do not support the claim being made. Existence verification alone is insufficient. The author must confirm that the source says what the citation attributes to it.

**Tier 3: Full Source Custody Record.** Applied to high-risk claims where challenge is anticipated or consequences of error are significant. Documents the full verification chain including archived evidence, status checks, and the author's reasoning. Fields: all Tier 1 and Tier 2 fields plus an archive link (Internet Archive or Perma.cc where institutional access exists), retraction or correction status at time of access (documented through Crossmark, Retraction Watch, or publisher status check), the status check method, a later review date for time-sensitive sources, any later status change discovered after publication, and a one-sentence author diligence note explaining why the source was considered reliable at time of use. Estimated time: three to five minutes per citation.

### Time Cost

For a manuscript with 60 references, of which 20 support factual claims at Tier 2 and 5 carry high-risk claims at Tier 3, the estimated total documentation time is approximately 60 to 90 minutes. This is comparable to the time researchers spend formatting reference lists and often less than the time spent writing the manuscript itself.

### Verification Gate

Before including any source in a manuscript's reference list, the following steps apply at the selected tier.

At Tier 1: Open the source URL. Confirm the page loads with content. Confirm the title and author match. Record the access date.

At Tier 2: Complete all Tier 1 steps. Read the relevant passage. Record the specific claim and its location in the source. Classify the claim support.

At Tier 3: Complete all Tier 1 and Tier 2 steps. Check the retraction and correction status through Crossmark, Retraction Watch, or the publisher's correction page. Create an archive snapshot through the Internet Archive or Perma.cc (where institutional access exists), or capture a local PDF. Write a one-sentence diligence note. If the source cannot be opened, does not match the metadata, does not support the claim, or has been retracted or corrected, exclude it from the reference list or document the reason for its inclusion.

---

## How to Create a SCOPE Record

A SCOPE record does not require specialized software, institutional subscriptions, or technical infrastructure. It requires a browser, a screenshot tool, and a folder. The implementation scales from a basic visual record that any author can create in minutes to a full-text custody archive suitable for high-stakes publications.

### Basic Implementation (Tier 1)

The minimum viable SCOPE record is a collection of screenshots.

**Step 1: Open each cited source in a browser.** Navigate to the URL, DOI, or persistent identifier listed in the reference. The browser's address bar must be visible in the screenshot.

**Step 2: Take a screenshot of each source page.** The screenshot must show the browser address bar (proving the URL), the page title, the author or organization name, and enough visible content to confirm the page is live and matches the citation metadata. Any system screenshot tool works: Snipping Tool on Windows, Screenshot on Mac, or a browser extension such as GoFullPage for long pages.

**Step 3: Name each screenshot file.** Use the citation's author and year: Topaz_2026.png, Hsiao_Schneider_2021.png, COPE_Position_2023.png. Consistent naming makes the record navigable.

**Step 4: Store the screenshots.** Two options, choose one or both.

**Option A: File folder.** Create a folder named SCOPE followed by the project name and date (for example, SCOPE_Fault_Based_Ethics_2026_06_02). Place all screenshots in the folder. This is the author's private archive.

**Option B: Compiled PDF.** Combine all screenshots into a single PDF document, six per page, with the source citation labeled beneath each screenshot. This produces a single portable file that can be stored, shared, or attached as a supplementary document if the author chooses to produce it.

The compiled PDF is what Appendix D of the companion SSRN paper (6872038) demonstrates. That appendix is a working example of a basic SCOPE record created using this method.

**Time cost for basic implementation:** Under one minute per source for the screenshot. For a manuscript with 20 to 25 references, the entire basic SCOPE record takes 20 to 30 minutes including file organization.

### Standard Implementation (Tier 2)

The standard implementation adds claim-support documentation to the basic visual record.

**Step 5: For each claim-bearing citation, annotate the screenshot or create a companion note.** Identify the specific passage in the source that supports the claim the citation is intended to prove. This can be done by highlighting the passage in the screenshot (using any image markup tool), by adding a text annotation to the screenshot, or by creating a separate text document that lists each citation with its exact claim, the page or section where the supporting evidence appears, and the claim-support classification (direct, indirect, background only, or does not support).

**The companion note can be as simple as a spreadsheet or text file with three columns:** citation, claim it supports, and where in the source the evidence appears.

**Time cost for standard implementation:** Two to three minutes per claim-bearing citation beyond the basic screenshot. For a manuscript with 20 claim-bearing citations, the standard SCOPE record adds 40 to 60 minutes.

### Advanced Implementation (Tier 3)

The advanced implementation adds full-text preservation and status verification to the visual and claim-support record.

**Step 6: Download or copy the full text of each cited source.** For each source, save a local copy of the full content as it appeared at the time of access. Three methods, ranked by evidentiary strength.

**Method A (strongest): Internet Archive snapshot.** Go to web.archive.org/save/ and paste the source URL. The Internet Archive creates a timestamped copy with a permanent URL. The timestamp is third-party verified and cannot be fabricated retroactively. This method is free and requires no institutional affiliation.

**Method B: Save as PDF.** Use the browser's "Print to PDF" or "Save as PDF" function to save the full page. This creates a local copy with a file creation timestamp from the operating system. The timestamp is self-attested (the author's own machine), not third-party verified.

**Method C: Copy and paste into a document.** Copy the full text of the source page into a Word document or text file. Label it with the source citation and access date. This preserves the content but loses the visual layout and creates no independent timestamp.

For the strongest record, use Method A (Internet Archive) for the third-party timestamp and Method B (PDF) for the local copy. Together they provide both external verification and a readable local archive.

**Step 7: Run status checks.** For each source, check whether it has been retracted, corrected, or flagged.

Retraction Watch (retractionwatch.com): Search by author name or paper title. Free, no account required.

Crossmark: Look for the Crossmark button on the publisher's page. Click it to see whether corrections, retractions, or expressions of concern have been issued. No account required.

Publisher correction page: Check the journal's or publisher's page for the specific article to see if any notices have been posted.

Record the result: "Retraction Watch: no entry found. Crossmark: no updates. Checked [date]."

**Step 8: Write the diligence note.** One sentence per source explaining why the source was considered reliable at the time of use. Examples:

"Peer-reviewed article in The Lancet, accessed directly via DOI, findings verified against the abstract and results section."

"Official COPE guidance page, accessed at the published URL, content matched the quoted language."

"arXiv preprint, not peer-reviewed, labeled as preprint throughout the manuscript, accessed directly."

**Step 9: Compile the full record.** The advanced SCOPE record for each source consists of: the screenshot (from Step 2), the full-text copy (from Step 6), the claim-support annotation (from Step 5), the status check result (from Step 7), and the diligence note (from Step 8). Store in the project folder alongside the basic screenshots. If compiling into a PDF, the full-text copies can be included as additional pages following each source's screenshot.

**Time cost for advanced implementation:** Three to five minutes per citation beyond the standard implementation. For a manuscript with 5 to 10 high-risk citations at Tier 3, the advanced layer adds 15 to 50 minutes.

### Total Time by Publication Type

| Publication type | Typical references | Recommended tiers | Estimated SCOPE time |
|---|---|---|---|
| Blog post or opinion editorial | 5 to 10 | None or Tier 1 for key claims | 0 to 10 minutes |
| Working paper or preprint | 15 to 30 | Tier 1 all, Tier 2 for factual claims | 30 to 60 minutes |
| Research paper for journal submission | 30 to 60 | Tier 1 all, Tier 2 factual, Tier 3 high-risk | 60 to 120 minutes |
| Book manuscript | 50 to 200 | Tier 1 all, Tier 2 factual, Tier 3 for load-bearing claims | 2 to 5 hours across drafting period |

The author decides. These estimates are guidelines, not requirements. A blog post with a single controversial claim may warrant Tier 3 for that one citation and nothing else. A book manuscript may warrant Tier 1 only if the author judges the risk as low. The tiers are tools, not mandates.

---

## The SCOPE Record Is Private

The SCOPE ledger is not submitted with the manuscript. It is maintained by the author as part of their research governance practice. The author owns the record the way a researcher owns raw data and a journalist owns source files.

**Production on challenge.** The record is produced at the author's discretion when a citation is challenged, when the work's credibility is questioned, when a publisher or institution requests it, or when legal process compels it.

**Right to decline.** If the author chooses not to produce the record, that is the author's right. The absence of a produced record is discretionary unless a publisher, institution, or legal process requires production.

**Confidentiality protections.** If a challenge proceeds before a private institution (journal, publisher, university review board), the author can decide whether to share the ledger, what portions to share, and under what conditions. The author should have the right to require a non-disclosure agreement or request that the ledger remain confidential beyond the review board to protect intellectual property, methodology, or source relationships. A reviewing body can request the full ledger for all disputed citations. The author can decline, but declining after being asked is information the adjudicator may weigh.

**Legal production.** If allegations are brought before a legal entity, production may be compelled through legal process, subject to the same protections that govern any evidentiary production.

**Protected content.** Parts of the record may be unproducible regardless of the author's willingness, because of HIPAA protections (where applicable), privacy regulations, anonymous data-collection protocols, or other legal constraints on the underlying source material. The diligence note can document that a source was verified under conditions that prevent full disclosure without specifying the protected content.

**Right not to create.** The author can choose not to produce a SCOPE record for any piece of work, for any reason, without that choice carrying automatic negative inference. The reason can be as simple as "this was an opinion editorial" or "this was a blog post" or "I did not expect this work to attract that level of scrutiny." The decision belongs to the author.

---

## Three Channels of Adoption

SCOPE adoption is voluntary for authors. Three independent channels create incentives for its use.

**Author prerogative.** The author decides which outputs warrant governed documentation based on their own assessment of stakes. A personal blog carries no expectation of a SCOPE record. A book manuscript approaching final publication warrants thorough documentation. The cost of maintaining the record is borne by the person who benefits from having it. The author can choose not to maintain a SCOPE ledger for any piece of work, for any reason.

**Publisher requirement.** Journals and platforms can require that submitting authors maintain a SCOPE ledger for any work they submit, producible on request if a citation is challenged. This is analogous to existing submission requirements for data availability statements, ethics declarations, and conflict-of-interest disclosures. The journal does not review the ledger at submission. It requires the author to attest that one exists and can be produced. A journal can calibrate: require attestation for research articles, recommend it for reviews, waive it for editorials. This requirement reduces risk to the publishing entity by ensuring documentation exists before a dispute arises.

**Insurance condition.** Errors-and-omissions or directors-and-officers insurance policies covering publication-related claims can condition coverage on the maintenance of source custody records. If a citation dispute produces a claim and the policyholder maintained a SCOPE ledger, the claim could be covered. If the policyholder did not maintain one, coverage could be denied or limited. The insurer does not mandate verification. The insurer prices the risk. This pattern is established in medical malpractice, legal malpractice, and financial services errors-and-omissions coverage, where record-keeping affects both insurability and claim outcomes.

---

## What SCOPE Produces at Each Fault Level

SCOPE integrates with the five-level fault ladder proposed in the companion SSRN paper (Puglisi, 2026, SSRN Abstract 6872038).

**Level 1 (Fabrication) and Level 2 (Failure to Verify).** The inability to produce any SCOPE entry is consistent with the absence of verification. An author who never checked cannot produce evidence of checking. The mechanism is asymmetric: only the author who maintained a record can produce one. A careless author cannot easily recreate contemporaneous third-party timestamps retroactively.

**Level 3 (Negligent Verification).** A SCOPE entry showing the author accessed the source and recorded the passage they relied on, but misinterpreted its meaning, is evidence of good-faith engagement. Correction is warranted. The record distinguishes misinterpretation from non-engagement.

**Level 4 (Downstream Contamination).** A SCOPE entry showing the source was not retracted or flagged at time of access, documented through a Crossmark or Retraction Watch check, is evidence that the author verified and the source status changed after verification. The fault lies upstream.

**Level 5 (Source Decay).** A SCOPE entry with an archive link or local copy is evidence that the source existed and supported the claim. The medium failed. The author did not.

The SCOPE record does not immunize an author. It creates reviewable evidence of what the author checked, when the author checked it, and whether the author's reliance was reasonable under the conditions available at the time.

---

## Limitations and Current Status

SCOPE v1.0 has been field-validated through one documented use. Appendix D of the companion SSRN paper (6872038) constitutes the first SCOPE record: 26 source verification screenshots captured on the day of submission, compiled into a five-page contact sheet, and published as part of the working paper. The specification has not yet been tested by external users, adopted by any publisher, or produced during a post-publication citation challenge. No publisher has adopted the tiered field template. No insurance carrier has conditioned coverage on source custody records.

The specification is derived from the evidence base documented in the companion SSRN paper, which draws on peer-reviewed retraction-persistence studies, reference-rot measurements, AI-fabricated citation audits, and established precedents for private production-on-challenge in law, medicine, journalism, and financial services.

The fault ladder referenced in this specification has not been adopted by any publisher, ethics body, or repository. It is a proposed framework, not an established standard.

SCOPE v1.0 is released for feedback, testing, and challenge. The validation roadmap proposes three stages: pilot testing with a single journal or preprint server, retrospective testing against known retraction cases, and integration testing with citation manager plugins.

---

## Version History

| Version | Date | Change | Authority |
|---------|------|--------|-----------|
| v0.1 | June 2026 | Initial specification. Three-tier field template, verification gate, three-channel adoption model, private-record-on-challenge architecture, CARCS integration layer. Companion to SSRN 6872038. | Tier 0 |
| v1.0 | June 2026 | Field validation complete. SSRN 6872038 Appendix D constitutes the first documented SCOPE record: 26 source verification screenshots compiled into a five-page contact sheet PDF, produced by the author during the paper's own submission process. How to Create section added with basic, standard, and advanced implementation paths. Bumped from v0.1 to v1.0. | Tier 0 |

---

## Appendix: SCOPE Field Template

### Tier 1: Basic Source Check

| Field | Description |
|-------|-------------|
| Source title | Full title as it appears on the source page |
| Author or organization | Author names or institutional publisher |
| DOI, URL, or persistent identifier | Persistent identifier or full URL accessed |
| Date accessed | Date the citing author opened and reviewed the source |
| Existence confirmed | The URL resolved to a live page with matching title and author |

### Tier 2: Claim Support Record

| Field | Description |
|-------|-------------|
| All Tier 1 fields | As above |
| Exact claim used | The specific assertion the citation supports, stated in one sentence |
| Page, paragraph, section, or timestamp | Location within the source where the supporting evidence appears |
| Claim support classification | Direct support, indirect support, background only, or does not support |
| Source type | Primary research, secondary source, commentary, data, opinion, or news reporting |

### Tier 3: Full Source Custody Record

| Field | Description |
|-------|-------------|
| All Tier 1 and Tier 2 fields | As above |
| Archive link | Internet Archive link, Perma.cc link (where institutional access exists), or local file hash |
| Retraction or correction status at time of access | Result of Crossmark, Retraction Watch, or publisher status check |
| Status check method | Which tool or method was used to verify current status |
| Later review date | Scheduled recheck date for high-risk or time-sensitive sources |
| Later status change | Any correction, retraction, or removal discovered after publication |
| Author diligence note | One sentence explaining why the source was considered reliable at time of use |

---

## Sources

Puglisi, B. C. (2026). Fault-based publication ethics: The case for source custody in an era of AI citation contamination. SSRN Working Paper. https://papers.ssrn.com/abstract=6872038

Puglisi, B. C. (2026). HAIA-CARCS: Compliance accountability record and case study (v1.4). basilpuglisi.com.

Puglisi, B. C. (2026). The AI risk economy: Insurance governance as the missing enforcement layer for responsible AI. SSRN Working Paper. https://papers.ssrn.com/abstract=6823580

UK Research Integrity Office. (n.d.). AI in research. https://ukrio.org/ukrio-resources/ai-in-research/

Glynn, A. (2025). Guarding against artificial intelligence-hallucinated citations: The case for full-text reference deposit. European Science Editing, 51. https://doi.org/10.3897/ese.2025.e153973

---

SCOPE v1.0 · Basil C. Puglisi, MPA · basilpuglisi.com · June 2026

*#AIassisted using HAIA Ecosystem*

*Open-source governance work: github.com/basilpuglisi/HAIA*
