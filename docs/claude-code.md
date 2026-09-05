# Claude Code hook

Install the package in a persistent Python environment, then register the hook:

```console
python -m pip install -e .
python -m agent_defs.hooks.claude_code install
```

The installer appends one command hook to each of `PreToolUse` and `PostToolUse`
in `~/.claude/settings.json`. It preserves existing handlers, including `guard.py`,
and repeated installs are idempotent. It uses direct executable/argument form,
so paths pass through without a shell quoting or expansion step. This form was
verified with Claude Code 2.1.261. Restart Claude Code after changing hook
registration. The captured absolute interpreter and package paths must remain
available. A temporary checkout is suitable for testing, not a lasting install.
The registered interpreter uses `-I -S`: no project import path, user site, or
site initialization is needed because the hook has no third-party dependencies.

Edit **`~/.claude/agent-defs.json`** for all agent-defs configuration. Each source
has a lane: `DO_NOT_SHIP` disables it, `RECORD` logs findings, `ADVISE` adds a
fixed advisory, and `DENY` blocks matching tool inputs or withholds matching tool
result text. Enabled surfaces are `IN` and `OUT`; other surfaces require other
adapters. This starter release contains four package-authored OUT rules. Entries
for the six corpora reserve their configuration names and do not load those
corpora yet.

First install is RECORD. Completed findings cause no prompts, blocks, advisories, or output
rewrites. Findings are JSON lines in `~/.claude/agent-defs/findings.jsonl`, with
rule IDs, effective lanes, JSON paths, original character spans, and text hashes. Raw tool text is not
logged. A complete scan with no finding causes no log write. Incomplete coverage produces a log
record and fixed user and model warnings, including in RECORD. The log is local and is never
included in the model context.

Changing a source to ADVISE or DENY requests that lane but cannot grant admission.
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

The hook returns `{}` for complete clean scans, completed RECORD findings, or disabled scans. This is
fail-open by abstention: it introduces no veto and preserves normal permission
checks and other hooks' decisions. An explicit `permissionDecision: allow` would
grant permission and is therefore inappropriate for a scanner's clean result.
No-op PostToolUse responses omit `updatedToolOutput`, because an identity
replacement can undo another parallel hook's redaction. Other output-replacing
hooks can still overwrite this hook; Claude Code does not run a redaction
pipeline.

Payload reads are capped at 1 MiB, scanned text at 4 MiB per event, traversal
at 4,096 nodes, and scanning at 250 ms total, including preparation and worker startup.
Matching stays in disposable subprocesses with up to 100 ms additional cleanup time.
The evaluator searches each bounded string in full, preserving anchors, lookarounds, and
substring conjunctions across the old 256 KiB boundary. It currently launches a worker for
each string value, so a result with many values can exhaust the total budget.
Oversized inputs, unfinished rules, rejected rules, and worker failures produce a fixed
`systemMessage` for the person and `additionalContext` for the model when the event is known.
These warnings include no attacker text and do not block a tool solely for incomplete coverage.
The installed command has a 2 second
harness timeout. The public entry point catches package import failures,
malformed JSON, bad arguments, scanner errors, and logging failures, exits zero,
and keeps stdout to one JSON response. It does not use argparse. An unavailable
interpreter, broken package bootstrap before module execution, OS termination,
or a hanging external filesystem cannot be repaired by Python exception
handling. Native process failures are subject to the harness's fail-open rules.

Remove only agent-defs hook handlers with:

```console
python -m agent_defs.hooks.claude_code uninstall
```

Uninstall keeps configuration and logs so the person retains their measurements.
Use `--settings PATH --config PATH` on install/uninstall for an isolated test.
Settings writes use an exclusive installer lock, detect intervening file edits,
and atomically replace the settings file. A concurrent editor that ignores the
lock can still race the final replacement. Invalid settings are left untouched.
Administrative commands also exit zero and emit `{}` on failure; only an
`agent_defs: installed`, `uninstalled`, or `measured` response confirms success.

Run the demonstration with `PYTHONPATH=src python examples/demo_injection.py`.
It prints the before/after RECORD result. Add `--benign-dir PATH` to measure
actual files and demonstrate admission and opt-in DENY using temporary config.
The fixture includes an inert `.invalid` URL and never executes its text.

`examples/verify_claude_harness.py` runs the installed Claude Code executable
against a deterministic loopback API, with isolated hook settings, and captures
the next request the model would receive. No live model is involved.
`examples/benchmark_claude_hook.py` separately measures interpreter startup,
isolated scans, the complete warm handler, and fresh-process hook calls.
Its optional ATR workload is a predicate microbenchmark and does not convert
compound corpus rules or grant them admission.

Historical measurements before worker isolation, not current evaluator timings: on the reference
Windows host (2026-09-04 local date, Python 3.12.12, Claude Code
2.1.261), a 64 KiB result with four starter rules took 0.223 ms p50 and 1.396 ms
p99 for the precompiled scan. Both fresh hook processes for one tool call took
604 ms p50 and 1,755 ms p99 over 100 pairs. This command transport therefore
misses a 100 ms p99 total overhead target on that host. A persistent local HTTP
hook could remove per-call process startup; it is not implemented here.
