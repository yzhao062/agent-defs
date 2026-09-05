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
result text. Enabled surfaces are `IN` and `OUT`; other surfaces require other
adapters. This starter release contains four package-authored OUT rules. Entries
for the six corpora reserve their configuration names and do not load those
corpora yet.

First install is RECORD. Rule matches produce no prompts, blocks, model
advisories, or output rewrites. Operational failures produce a fixed user-visible
warning. Findings are JSON lines in `~/.claude/agent-defs/findings.jsonl`, with
rule IDs, effective lanes, JSON paths, and text hashes. Raw tool text is not
logged. A complete scan with no findings makes no log write. The log is local and is never included in
the model context.

Changing a source to ADVISE or DENY requests that lane but cannot grant admission.
The running hook calls `lanes.admit()` with the validated per-rule measurement
and bundle bound. A loader's `Rule.lane=DENY` grants nothing. Missing, stale,
invalid, or insufficient measurement keeps a runnable rule in RECORD.
Run an offline measurement on files you have established are benign:

```console
python -m agent_defs.hooks.claude_code calibrate --benign-dir /path/to/benign/files --corpus-label "reviewed local baseline"
```

Calibration scans distinct UTF-8 `.py`, `.md`, `.rst`, `.txt`, and `.tex` files,
deduplicates exact contents, skips files over 256 KiB, and records both rule and
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

The hook returns `{}` for complete clean scans, RECORD findings, or disabled
surfaces and sources. This abstention preserves normal permission
checks and other hooks' decisions. An explicit `permissionDecision: allow` would
grant permission and is therefore inappropriate for a scanner's clean result.
No-op PostToolUse responses omit `updatedToolOutput`, because an identity
replacement can undo another parallel hook's redaction. Other output-replacing
hooks can still overwrite this hook; Claude Code does not run a redaction
pipeline.

Payload reads are capped at 1 MiB, scanned text at 256 KiB per event, and traversal
at 4,096 nodes and 64 levels. Each string value is scanned in an isolated worker, under a
shared one-second event budget. The previous 50 ms budget expired during worker
startup on the reference host. The installed command has a three-second harness
timeout. This allows worker startup and cleanup; it is not a latency guarantee.

The reader checks `ScanResult.complete`, worker and rule errors, truncation,
skipped rules, and the evaluated-rule count. Completed findings remain effective
when later work fails. Incomplete coverage is logged and reported with fixed
`systemMessage` text. PreToolUse asks for approval only if an enabled rule already
qualifies for DENY; RECORD and ADVISE cannot acquire blocking power through a
timeout. A completed DENY match still denies. PostToolUse cannot block: it keeps
completed measured redactions and reports incomplete coverage, without rewriting
unscanned text. A logging failure does not discard a completed decision.

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
precompiled scans, the complete warm handler, and fresh-process hook calls.
Its optional ATR workload is a predicate microbenchmark and does not convert
compound corpus rules or grant them admission.

Before isolated worker scanning was integrated, on the reference Windows host
(2026-09-04 local date, Python 3.12.12, Claude Code
2.1.261), a 64 KiB result with four starter rules took 0.223 ms p50 and 1.396 ms
p99 for the precompiled scan. Both fresh hook processes for one tool call took
604 ms p50 and 1,755 ms p99 over 100 pairs. This command transport therefore
missed a 100 ms p99 total overhead target on that host. These are historical
measurements, not timings for the current isolated scanner. A persistent local HTTP
hook could remove per-call process startup; it is not implemented here.
