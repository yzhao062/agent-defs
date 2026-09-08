# Claude Code hook

Install the package in a persistent Python environment, then register the hook:

```console
python -m pip install -e .
python -m agent_defs.hooks.claude_code install
python -m agent_defs.hooks.claude_code install --yes
```

The installer appends one command hook to each of `PreToolUse` and `PostToolUse`
in `~/.claude/settings.json`. It preserves existing handlers, including `guard.py`,
and repeated installs are idempotent. The first command prints a diff and does
not write; `--yes` explicitly accepts the edit and still prints the diff before
writing. Every changing install or uninstall first saves the existing bytes to
an exclusive `settings.json.agent-defs-*.bak` file. Existing handlers and unknown
JSON values retain their original bytes, including numeric spelling, escapes,
UTF-8 BOM, and line endings. A small installer receipt records which empty
containers we created so uninstall can preserve pre-existing empty containers.

The installed command quotes each argument for Claude's POSIX hook shell,
including Git Bash on Windows. A shell wrapper converts interpreter startup
failures and nonzero exits into an exit-zero diagnostic. This transport was
verified with Claude Code 2.1.261. Restart Claude Code after changing hook
registration. The captured absolute interpreter and package paths must remain
available. A temporary checkout is suitable for testing, not a lasting install.
The registered interpreter uses `-I -S`: no project import path, user site, or
site initialization is needed because the hook has no third-party dependencies.

Edit **`~/.claude/agent-defs.json`** for all agent-defs configuration. Each source
has a lane: `DO_NOT_SHIP` disables it, `RECORD` logs findings, `ADVISE` adds a
fixed advisory, and `DENY` blocks matching tool inputs or withholds matching tool
result text. The advisory is fixed per surface and there are two of them, because
a tool result and a tool call give the reader different things to do. Enabled
surfaces are `IN` and `OUT`; other surfaces require other adapters. Four
package-authored OUT rules ship in the package itself, and `bundle.json` carries
216 ATR rules, 205 on `OUT` and 11 on `IN`. The other five corpora reserve their
configuration names and are not loaded yet.

First install is RECORD. Completed findings cause no prompts, blocks, advisories, or output
rewrites. Findings are JSON lines in `~/.claude/agent-defs/findings.jsonl`, with
rule IDs, effective lanes, JSON paths, original character spans, and text hashes. Raw tool text is not
logged. A complete scan with no finding causes no log write. Incomplete coverage produces a log
record and fixed user and model warnings, including in RECORD. The log is local and is never
included in the model context. A truncated value has `text_sha256: null`; a value
without byte truncation receives its full-content digest even if later checks fail.

Changing a source to ADVISE or DENY requests that lane but cannot grant admission.
The running hook calls `lanes.admit()` with the validated per-rule measurement
and bundle bound. A loader's `Rule.lane=DENY` grants nothing. Missing, stale,
invalid, or insufficient measurement keeps a runnable rule in RECORD.
Run an offline measurement on files you have established are benign:

```console
python -m agent_defs.hooks.claude_code calibrate --benign-dir /path/to/benign/files --corpus-label "reviewed local baseline"
```

Calibration scans distinct UTF-8 `.py`, `.md`, `.rst`, `.txt`, and `.tex` files,
deduplicates exact contents, skips files over 4 MiB, and records both rule and
bundle hit counts in the same config file. It never changes requested lanes.
Zero hits in at least 598 trials admit ADVISE, and 2,995 admit DENY, provided the
whole enabled bundle also qualifies. This first adapter refuses positive-hit
measurements. A changed rule or enabled surface invalidates the measurement.
Setting a lane after calibration is a separate, explicit edit by the person.

A directory of correlated source files does not establish independent trials or
representative web/issue traffic. The binomial bound is conditional on those
assumptions. Review the baseline and deployment domain before treating a local
demo measurement as a production claim. Measurements are trusted local data,
not authenticated evidence against an actor who can edit the config itself.

When DENY matches output, the hook withholds the entire matched string value,
preserving surrounding JSON structure and other values. This sacrifices benign
text in the same value to avoid retaining the rest of an instruction after
removing only its matched phrase. PreToolUse DENY does not rewrite input. Advice
never includes matched text or upstream rule descriptions.

The hook returns `{}` for complete clean scans, completed RECORD findings, or disabled
surfaces and sources. This abstention preserves normal permission
checks and other hooks' decisions. An explicit `permissionDecision: allow` would
grant permission and is therefore inappropriate for a scanner's clean result.
No-op PostToolUse responses omit `updatedToolOutput`, because an identity
replacement can undo another parallel hook's redaction. Other output-replacing
hooks can still overwrite this hook; Claude Code does not run a redaction
pipeline.

Payload reads are capped at 1 MiB, scanned text at 4 MiB per event, and traversal
at 4,096 nodes and 64 levels. Every string value of one event is scanned in **one**
isolated worker, under a one-second event budget covering preparation and worker
startup, with up to 100 ms additional cleanup. The installed command has a
three-second harness timeout. The hook budget is defined once as `SCAN_BUDGET_S`;
the standalone evaluator still defaults to 250 ms. These are resource limits, not
promises of complete coverage or latency. Neither budget completes the full measured
ATR OUT bundle on all real traffic: r1 observed a 28 KB Gmail result with unfinished
rules even at 30 seconds.

One worker per event replaces one worker per string value. A worker screens and
compiles the whole bundle before it matches anything, and that cost is paid once per
process: 341 ms of a 492 ms per-value floor was compilation, against 4.2 ms of
matching. Under the old shape a three-value tool result exhausted the budget before
the third value was reached, and 32.67% of measured tool results returned an
incomplete scan, including every result carrying three or more values. The byte
allowance is one running total across the values of an event, spent in traversal
order; a value the allowance no longer covers is declined rather than sent, and the
diagnostic log names it.

Rules sweep rule-major: each rule is compiled once, then run against every value
before the next rule begins. The honest cost is that under a timeout the first value
is checked by fewer rules than it was, because each rule now finishes its whole
sweep before the next starts. Every other value goes from unchecked to that same
prefix. "The first value is checked most deeply" was the starvation rather than a
security property. An attacker shapes the payload, so under the old order he could
pad three values and keep every rule off the fourth while knowing nothing about the
bundle. Under rule-major the schedule depends on the rule set alone, and evading it
means reading the bundle for a hazard only a late rule detects.

The evaluator searches each bounded string in full, preserving anchors, lookarounds, and
substring conjunctions across the old 256 KiB boundary. Each value crosses to the
worker as its own string and each rule searches that string alone. Nothing is
joined, so a conjunction cannot be satisfied across two values, and an anchor still
means the edge of its own value.

The reader checks batch completeness, worker and rule errors, per-value truncation,
unresolved (value, rule) pairs, and whether the scan scheduled every runnable rule it
was handed. It explicitly consumes `partial_findings`
so completed findings remain effective when later work fails. Incomplete coverage is
logged and reported with fixed `systemMessage` text for the person and `INCOMPLETE`
text in `additionalContext` for the model whenever the event is known. An incomplete
event also writes one `scan_coverage` record naming how many values were seen,
scheduled, declined and truncated, with the JSON Pointer path of each declined and
each truncated value up to 32 of each; the counts beside those lists stay exact and
`paths_elided` says when a list was cut. These warnings and records
contain no payload excerpts or rule prose. PreToolUse asks for approval only if an
enabled rule already qualifies for DENY; RECORD and ADVISE cannot acquire blocking
power through a timeout. A completed DENY match still denies. PostToolUse keeps
completed measured redactions and reports incomplete coverage without rewriting
unscanned text. A logging failure does not discard a completed decision.

**The admission evidence is still a joined-text measurement.** The shipped OUT
benign bound, 1 hit in 1,743 trials, was measured over each unit's whole text rather
than over the values a hook walks, and `docs/calibration.md` already records that
neither leaf diagnostic bounds the deployed hook. Reaching every value inside the
byte allowance enlarges that gap rather than creating it, because budget exhaustion
used to skip values on about a third of tool results. Closing it needs an OUT corpus
of the values themselves, which does not exist yet: the extractor never rendered
`tool_response` string values into `tool_result.content`, and re-extracting would
re-select from transcripts that have since changed. That extraction is the work that
would make a real gate possible.

Malformed input, argument errors, package imports, scanner exceptions, and
broken stdout all remain behind an exit-zero boundary. There is no argparse in
the hook entry point. The outer shell also catches a missing interpreter,
Python option errors, and an immediate native exit. Launcher failures are logged
beside the config in `CONFIG.launcher-errors.jsonl`; other diagnostics use the
configured findings log, with stderr as the fallback when logging fails.
Exit code 2 blocks even with malformed JSON in the tested harness. Exit code 1
with malformed JSON abstains there, but the adapter deliberately returns zero
for both. A missing shell, OS termination of the whole process tree, or an
unavailable filesystem remains outside the program's exit guarantee.

Remove only agent-defs hook handlers with:

```console
python -m agent_defs.hooks.claude_code uninstall
python -m agent_defs.hooks.claude_code uninstall --yes
```

Uninstall keeps configuration and logs so the person retains their measurements.
Use `--settings PATH --config PATH` on install/uninstall for an isolated test.
Settings writes use an exclusive installer lock, detect intervening file edits,
and atomically replace the settings file after backup. A concurrent editor that
ignores the lock can still race the final replacement. Invalid, duplicate-key,
or partly written settings are refused with an explanation and left untouched.
Without a receipt, uninstall conservatively leaves empty containers in place.
Administrative commands also exit zero and emit `agent_defs: error` with an
explanation on failure; only an `agent_defs: installed`, `uninstalled`, or
`measured` response confirms success.

Run the demonstration with `PYTHONPATH=src python examples/demo_injection.py`.
It prints the before/after RECORD result. Add `--benign-dir PATH` to measure
actual files and demonstrate admission and opt-in DENY using temporary config.
The fixture includes an inert `.invalid` URL and never executes its text.

`examples/verify_claude_harness.py` runs the installed Claude Code executable
against a deterministic loopback API, with isolated hook settings, and captures
the next request the model would receive. No live model is involved.
`examples/verify_hook_safety.py` additionally verifies the actual shell launcher
with a missing interpreter, a parallel redacting hook, and a measured output
decision. Its measurement is a protocol fixture, not benign-performance evidence.
`examples/benchmark_claude_hook.py` separately measures interpreter startup,
isolated scans, the complete warm handler, and fresh-process hook calls.
Its optional ATR workload is a predicate microbenchmark and does not convert
compound corpus rules or grant them admission.

Historical measurements before worker isolation, not current evaluator timings: on the reference
Windows host (2026-09-04 local date, Python 3.12.12, Claude Code
2.1.261), a 64 KiB result with four starter rules took 0.223 ms p50 and 1.396 ms
p99 for the precompiled scan. Both fresh hook processes for one tool call took
604 ms p50 and 1,755 ms p99 over 100 pairs. This command transport therefore
missed a 100 ms p99 total overhead target on that host. These are historical
measurements, not timings for the current isolated scanner. A persistent local HTTP
hook could remove per-call process startup; it is not implemented here.
