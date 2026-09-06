# Benign-noise harness

Run from a source checkout with `PYTHONPATH=src`, or install the package first:

```text
python -m agent_defs.bench measure --corpus /data/benign-cfg --rules /data/rules.json --out report.json
python -m agent_defs.bench reachability --rules /data/rules.json --out positives.json
```

The bundle is a JSON array of normalized `Rule` records, or an object containing
that array in `rules`. Enum values use their schema spellings. Stored lanes and
benign measurements are discarded. Duplicate rule IDs are rejected. The harness
imports only the standard library and the existing core model/evaluator/lanes.

Every rule that `compile_rule` can run is evaluated against every complete unit.
The hook's byte cap and between-rule time budget are disabled for this offline
measurement. Patterns still pass the existing build-time safety screen. An
unsupported or rejected predicate is counted separately with its reason, never
as a clean trial. An incomplete scan aborts without publishing a success report.
The existing Python regex screen is heuristic and supplies no per-regex timeout.

Fetched traffic must use `--isolated --workers 4 --budget-s 30`. This routes
each complete result and each positive example through `evaluate.scan` and its
killable subprocess. The default trusted mode is only for controlled offline
fixtures. Any evaluator error, timeout, truncation, or incomplete rule count
aborts the report. Isolated scans retain the evaluator's 4 MiB input ceiling;
larger complete results must be reported as unsupported, never silently clipped.
The deadline is an offline measurement budget, not a production latency claim.

## Corpus manifest and trials

Each corpus directory contains `corpus.json` and UTF-8 material files:

```json
{
  "identity": "organization/benign-tool-results",
  "revision": "0123456789abcdef0123456789abcdef01234567",
  "surface": "OUT",
  "required_strata": ["tool=read_file", "tool=web_fetch"],
  "units": [
    {
      "id": "session-001/result-001",
      "path": "material/001.txt",
      "sha256": "<64 hex digits of the exact payload bytes>",
      "strata": {
        "file_type": "text/plain",
        "prose": "security-adjacent",
        "tool": "read_file"
      }
    }
  ]
}
```

The revision is a full commit SHA or a `sha256:` content snapshot identifier.
The manifest declares provenance; the harness verifies every payload against its
required SHA-256 and records the manifest hash and all material hashes. It does
not independently authenticate a manifest author's claim about a Git commit.
Paths must resolve inside the corpus directory. Files are read as bytes and
decoded strictly, preserving newlines and case. Empty corpora, duplicate unit IDs,
missing files, changed bytes, and invalid UTF-8 fail the run. Unlisted files are
excluded by design, so put the selection policy under review with the manifest.
Use neutral data filenames rather than installing fetched skills as instructions.

| Surface | One trial |
| --- | --- |
| CFG | One complete configuration or repository file at rest |
| IN | One tool invocation payload, including name and arguments |
| OUT | One complete result from one tool invocation, with chunks reassembled |
| PROMPT | One complete user message |
| PIN | One complete before/after comparison of a pinned artifact |

An invocation or result is stored in one file. These are text payload trials;
structured event predicates remain excluded until the core evaluator supports
them. A `surface` on a unit overrides the corpus default. Repeat `--corpus` to add
another corpus without code changes. Keep corpora separate in the report: a large
clean corpus cannot dilute a small noisy one. Do not split one tool result into
many files or duplicate payloads to increase the denominator. Exact duplicate
content on the same surface is reported and blocks bundle admission.

## Strata and evidence

The default file types distinguish `SKILL.md`, `.agent.md`, `README`, and filename
extensions. A versioned path heuristic tags paths containing security, threat,
attack, inject, secret, vulnerab, pentest, audit, or red.team as
`security-adjacent`; other paths are `ordinary`. Manifest labels override the
heuristic and can add dimensions such as tool or language. This classifier is a
reviewable proxy, not an adjudication of prose. Inspect its membership before
using it for release decisions.

Each corpus and surface gets an overall row, each dimension's marginal strata,
and observed file-type/prose intersections. Both prose strata are required on
every supplied surface. Additional `required_strata` labels declare anticipated
coverage, including strata absent from the material. Missing required strata
block admission. Empty intersections are not fabricated as measured trials.

The report includes per-rule trials, hits, exact one-sided binomial upper bounds,
corpus identity, pinned revision, manifest hash, and UTC timestamp. Zero hits use
`lanes.u95_zero_hits`; clean sample-size targets use `lanes.trials_needed`.
Nonzero hits invert the binomial CDF for the Clopper-Pearson upper limit. The
bundle's hit count is the union of enabled native-surface rule hits per unit,
bounded by its trial count. It is distinct from the sum of rule findings.

The reported limit is not what the gate compares. Inverting the CDF pushes the
coefficient's rounding into the returned rate, and at large trial counts that
rounding is enough to place a rate on the wrong side of a ceiling; the gate
therefore evaluates the CDF once at the ceiling instead, through
`lanes.bound_within`, and fails the bundle outright when the comparison lands
inside the slack that arithmetic allows. That failure is worded separately from
the thin-stratum one, so the importer's pooled-bound opt-in cannot cover it.

`bound_within` also refuses above `lanes.MAX_SUPPORTED_TRIALS`, which is ten
million. That is where the `lgamma` coefficient's measured error grows past the
slack, so the band would stop catching a wrong answer; past it the comparison
is declined rather than answered. The slack itself is an empirical margin over
a measured worst case, not a derived bound, and `lanes.py` says so.

All-rules prevalence is also reported to permit comparison with earlier
whole-file experiments. Cross-surface rows explicitly mark
`admission_eligible_surface: false`; the pooled diagnostic count never grants
an interrupting lane. The report names every unmeasured surface.

These are pointwise 95% bounds, not a simultaneous 95% confidence guarantee over
all strata and rules. Binomial coverage assumes independent, representative
trials. One public repository does not establish workplace independence or
real-session precision. Small strata correctly prevent an admission claim even
when the pooled bound looks low. Source-authored positives are reachability
witnesses and do not establish attack recall.

## Apply the report

```python
import json
from agent_defs.bench import apply_report, load_rules

rules = load_rules("rules.json")
with open("report.json", encoding="utf-8") as stream:
    assigned = apply_report(rules, json.load(stream))
```

`apply_report` checks fingerprints of the entire bundle and returns new `Rule`
records with lanes, reasons, and the worst native stratum as `benign`.
`admit_from_report(rule, report)` is the lower-level adapter. It calls `admit`
with a conservative bundle flag. Every enabled surface must have evidence and
every observed/required stratum must pass. A bundle that only qualifies for
`ADVISE` caps even an individually quiet rule at `ADVISE`. Remeasure the exact
bundle after adding, removing, or changing a rule. Reports are trusted local
build artifacts, not signed attestations. Consumers should preserve assigned
lanes rather than subsequently calling bare `admit` with an invented bundle flag.

Positive examples are passed to the same evaluator unchanged. A silent rule
with examples that all fail becomes a `DO_NOT_SHIP` candidate. A rule with no
examples remains unknown and stays at `RECORD`; the harness does not call it
dead. A positive witness alone cannot promote a rule without benign evidence.

## Reproduce the pinned comparison

`scripts/prepare_bench_check.py` downloads the exact earlier awesome-copilot and
ATR revisions into an external scratch directory. It writes neutral `.txt`
material files, a SHA-256 manifest, normalized single-condition ATR records, and
an HTTP/date/hash ledger. It requires PyYAML via the existing `atr` extra; the
harness itself does not. It does not install or execute source payloads.

```text
python scripts/prepare_bench_check.py --out /external/b7-evidence
python -m agent_defs.bench measure --corpus /external/b7-evidence/corpus --rules /external/b7-evidence/rules.json --out /external/b7-evidence/report.json
```

The selection is all `SKILL.md` and `.agent.md` files, README basenames, root
`mcp.json`, and `eng/` source/shell files, excluding `.test.` and
`eng/pr-risk-scan.mjs`. At the pinned revision this is 842 files and 7,206,252
bytes. The extractor intentionally carries only one-condition regex rules with
a supported text field and no extra detection or code-span suppression gate.
It preserves the regex and examples unchanged. Its declared field-to-surface
projection is `content=OUT`, `user_input=PROMPT`, `tool_description=CFG`.
This is a restricted prevalence check, not a replacement for the ATR loader or
a claim of native engine parity.

The first run's 49 screened rules produced one finding. All 48 quiet rules had
unchanged positive witnesses. The earlier broader run used 1,528 predicates and
reported 3,594 findings; the difference is not an accuracy improvement claim.
Full reproduction requires the same faithful predicates, evaluator semantics,
and enabled bundle. The exact corpus was reproduced, but rule coverage was not.
See the b7 result and external JSON artifacts for counts and source evidence.
The sources were the pinned [awesome-copilot archive](https://codeload.github.com/github/awesome-copilot/zip/7b1ebe6333397841ca918dec904d24d4695fe953)
and [ATR archive](https://codeload.github.com/Agent-Threat-Rule/agent-threat-rules/zip/faf743fee8a5018467959ec8ea7ccdb1a1aab333),
both fetched with HTTP 200 on 2026-09-05 UTC. Corpus and subset counts are
VERIFIED by the two commands above. The earlier full-bundle numbers are supplied
context, not a full reproduction by this harness.

That pinned comparison is entirely CFG material. No real tool-call traffic was
measured on IN or OUT in that comparison; PROMPT and PIN were also unmeasured. This matters especially
for the context's 515 OUT rules among ATR's 793. Zero CFG matches cannot establish
their tool-output noise rate. No rule in this experiment earned an interrupting
lane.

## Real tool traffic reproduction

The paragraph above describes the earlier configuration experiment. The traffic
scripts add a separate OUT experiment without changing rule conditions:

```text
python scripts/inspect_tool_traffic.py --out /external/r1-evidence
python scripts/prepare_tool_traffic.py --out /external/r1-evidence --local-root /authorized/.claude/projects
PYTHONPATH=src python scripts/export_traffic_rules.py --archives /verified/archives --out /external/r1-evidence
PYTHONPATH=src python scripts/measure_tool_traffic.py --evidence /external/r1-evidence --names trace-commons local-claude --rules /external/r1-evidence/atr-out-rules.json --workers 3 --budget-s 180
```

The exporter runs beside `sources.lock` and expects verified rule corpora beside
the archive directory. It extracts only ATR rules and LICENSE, never malicious
sample directories. Traffic snapshots and reports belong outside the repository;
local transcripts must remain private. The JSONL adapter verifies the snapshot
and each result hash before constructing the existing `bench.Corpus` objects.

One trial is one recorded textual tool result joined to its invocation. All text
blocks in the result are joined in order with newlines, as one trial. Tool
references, images, missing results, and ambiguous repeated result IDs are
excluded and counted. Wrapper fields, parent conversation text, and hidden
`toolUseResult` metadata are not the returned text. No payload is split to
increase trial counts; the original tools' truncation/summarization is retained.

Exposure labels are a versioned heuristic in `prepare_tool_traffic.py`:
WebFetch/WebSearch, local generation, unknown file origin, network commands,
unknown external tools, and other mixed outputs are separate. A local file read
does not establish who authored it. Errors remain real results and receive a
separate status stratum. These are observed firing rates on unmodified traffic,
not adjudicated false-positive rates. Session dependence and tool summaries limit
what binomial bounds can establish. The report retains duplicate-output and
small-stratum admission gates and now lists rules firing on more than 1% of units.

The local sample contains a real 28,049-byte Gmail result on which the full
306-rule OUT bundle failed a 30-second deadline. Rule ATR-2026-00233 alone took
14.9 seconds with zero findings. The longer offline deadline above is needed to
finish this measurement, not a proposed hook budget. `diagnose_tool_traffic.py`
reproduces a named rule/result pair without printing private result text.
