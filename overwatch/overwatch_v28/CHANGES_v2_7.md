# HAIA-Overwatch v2.7: changes

Version 2.7.0 (`overwatch_v27.__version__`, `OverwatchPipeline.VERSION`). Built on Overwatch v2.6 (`overwatch/overwatch_v26/`, unchanged) as item 2 of Basil C. Puglisi's fix round of October 15, 2026, after a seven-platform CAIPR review. `CHANGES_v2_5.md`, `CHANGES_v2_6.md`, and `CHANGED_CHECKS_v2_6.md` are carried unchanged beside this file, because change logs go in a new file for each version.

Overwatch's single action is unchanged: stop the pipe, route to human (Overwatch v2.4, Section 14). Overwatch still imports nothing from GOPEL or the agents, tests included, reads GOPEL's audit trail read only, and writes only its own stop channel.

## 1. Finding T-1: performed or instructed, told apart from quoted or cited (item 2a)

The Team Gate's suite showed v2.6 stopping the pipe on Agent Model 1's clean item. Escalation follows a finding's confidence, and every state change match carried 0.8, the critical floor. So any web address in an answer read as a network operation, and English words such as update and create, followed by a space, read as database changes.

v2.7 does not loosen a pattern and allowlists no agent's phrasing. `STATE_CHANGE_PATTERNS`, the role envelopes, the directive patterns, the role content patterns, and every confidence floor are those of v2.6. What changed is that a match of the two patterns at issue is classified before it is scored, from the structure of the GOPEL record it came from:

- **Classified patterns** (`CLASSIFIED_PATTERNS`): the web address pattern and the `http` and `httpx` name in `network_operation`, and the SQL keyword pattern in `database_modification`. Every other pattern is a code form (a call, a command, SQL grammar such as `DROP TABLE`) and counts as performed, as published.
- **Performed:** the match sits in a code block or code span, or the answer holds SQL grammar (`UPDATE x SET`, `DELETE FROM`, `INSERT INTO`, `DROP`, `CREATE`, `ALTER`, or `TRUNCATE` of a `TABLE`, `DATABASE`, `SCHEMA`, `INDEX`, `VIEW`, `USER`, or `ROLE`). Scored as published.
- **Instructed:** a transfer verb aimed at the address ("send the records to <address>"), a fetch verb directly before it, or an imperative sentence with an operation verb that names the address. For a keyword: a destructive verb with an operational object in the same sentence ("delete all files in the shared folder"), or an imperative sentence with a modifying verb and an operational object ("update all user accounts"). Scored as published.
- **Quoted or cited:**
  - the address is in the Request GOPEL recorded for the transaction (the address the caller handed the platform);
  - it is the value of a citation field in the answer's JSON (`url`, `urls`, `source`, `sources`, `link`, `href`, `citation`, `page_quote`, or a key ending in `url`);
  - it sits on a Sources or References line, or in the list under such a heading;
  - it is a link target, inside a parenthesis, or introduced by see, source, or per.
- **Plain word:** an SQL keyword with no SQL grammar in the answer and no operational object, as in "update the opening line" or "drop the adverb".
- **Unclassified:** an address with none of the forms above is scored as published. Only a positive citation form downgrades.

A category's finding is scored as published when any match in it is performed, instructed, or unclassified. When every match is quoted, cited, or a plain word, the signal is downgraded, never deleted:

- the finding stays in the outcome, FLAGGED, at severity NOMINAL and confidence 0.2, below the published advisory floor of 0.3, so it neither escalates nor feeds the advisory accumulator;
- its description opens "Downgraded (<class>, not performed)", and its evidence names the classification and its basis;
- it is written to the log as a logged warning.

Agent Model 1's clean items cause zero stops, and so do Agent Model 2's cited answers. The same address that a clean item cites still stops the pipe when an answer instructs a request to it.

## 2. Role coherence against Model 1's scoring labeled Editor (item 2b)

The role coherence check is unchanged. Agent Model 1 v6 labels every scoring group Editor (item 3a: HAIA-SMART Copy v2.1 and HAIA-CORE v3.10, Section 0, name the Editor role; Basil assigns Editor to SMART Creative scoring too). Model 1's scoring prompt reads as fully coherent under Editor. The same prompt under Model 1 v5's calculator label (QT9) still reads as low role coherence and stops, and a Coder prompt under Model 1's labels still stops.

## 3. Hard floors under false positive rulings (item 2c)

A human ruling that a finding was a false positive is recorded and feeds the Factics cycle, but no number of rulings takes a signal below its hard floor:

- **Directives.** `HARD_FLOOR_DIRECTIVE_CATEGORIES` holds every directive category whose published confidence reaches the published critical floor, the ten that stop the pipe at the defaults. A safe pattern never suppresses them; the attempt is logged. A directive below the floor that a safe pattern matches is kept downgraded and logged, where v2.6 deleted it.
- **Role envelopes.** `PUBLISHED_FORBIDDEN_PATTERNS` freezes each role's published patterns at import. `widen_envelope` refuses to remove one, logs the refusal, and returns False; a pattern added later by `tighten_envelope` can still be removed (True).
- **Calibration.** Trajectory thresholds stay within their published ceilings, as in v2.6; tests now hold that under repeated rulings.
- The injected directive, an instructed request to an outside address, an instructed deletion, and an off-role answer still stop after a dozen rulings that each of their findings was a false positive.

## 4. Error Responses and route Responses inspected like any other (item 2d)

- **Error text.** GOPEL records a failed call's failure text in `error_detail`, with secrets already redacted inside its adapters. v2.7 inspects that text as it inspects an answer: state changes, the role envelope, and embedded directives. Findings name the source as `(error_detail)` or `error_detail_<platform>`.
- **Navigation records.** GOPEL records carry the Navigator's text, never an assembled Navigator input. v2.6 skipped its synthesis checks when the input was absent, which it always was. v2.7 runs the synthesis directive check on the output alone, keeps the length ratio check for when an input exists, and scans the Navigation record's text for embedded directives as `navigation_record`. A route's Response record was already inspected as an answer.

## 5. GOPEL v0.6.5 records (item 1)

- `GopelSchemaExpectation` expects GOPEL "0.6.5" by default; another declared version is refused record by record, as before.
- **Escaped answers.** GOPEL v0.6.5 records an answer that cannot be encoded, a lone surrogate for one, escaped without loss and flagged. The Response schema reads the new fields `text_escaped`, `escapes`, `error_escapes`, and `redaction_applied`, and the flags travel with the response in its metadata. The escaped record is read and inspected, not skipped.
- **Withdrawn groups.** GOPEL v0.6.5 closes a group as soon as no further send is planned for it, with a reason that begins "withdrawn: ". The group is finalized and every answer that arrived is inspected.
- **The fixture.** Tests read `tests/fixtures/gopel_v065_mock_audit_v1.json`, produced on main by `haia_agent/e2e/make_overwatch_fixtures_v3.py` (commit `c5f42d1`). It runs GOPEL v0.6.5 with mock adapters only and holds the following, each transaction tagged in provenance with its class and whether Overwatch must stop on it:
  - Agent Model 1 v6's own runner on that channel;
  - Agent Model 2 shaped answers;
  - the four attack kinds;
  - the record shapes above.

## 6. Version and wording

- Version 2.7.0. Every module header reads v2.7. Author and license lines are carried verbatim.
- No threshold, limit, or number changed.

## 7. Tests

- **New, 117 checks:**
  - `test_t1_context_v27.py` (55)
  - `test_role_coherence_v27.py` (6)
  - `test_floors_v27.py` (27)
  - `test_error_route_v27.py` (11)
  - `test_channel_v065_v27.py` (9)
  - `test_changes_v27.py` (4)
  - `test_isolation_v27.py` (5)
- **Shared helpers:** `fix_round_support_v27.py`.
- **Before the build:** against the v2.6 modules copied unchanged (imports re-pointed, fixture v0.6.5): 61 failed, 56 passed. The passes are guards: attacks that v2.6 already stopped, Model 1 v6's Editor-labeled scoring, the unchanged patterns, and isolation.
- The carried checks that changed are listed in `CHANGED_CHECKS_v2_7.md`.

## A correction to the record

The message of commit `afa82f1` (GOPEL v0.6.4, on main) quotes an error, `ModuleNotFoundError: No module named 'haia_agent.gopel_v064.channel'`, that the saved before-run evidence cannot confirm: that file kept only the failing tests' names.
