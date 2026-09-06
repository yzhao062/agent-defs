# agent-defs

Definitions for agent security: public rule sets and risk corpora, normalized, carrying where each
rule came from, watched for changes, and preserved after the source disappears. Install it and your
own agent checks the text it reads before the model acts on it.

**Status: pre-alpha, nothing published beyond a name reservation.** `0.0.1` on PyPI and npm holds the
name and carries no rules.

## What it is for

An agent reads tens of thousands of tokens you never see: web pages, issues, files, tool responses. If
any of that carries instructions, the model may follow them, and you have no way to notice. That is
the one threat here an individual cannot defend against alone, and it is what this package is aimed
at.

It acts at the moment the text arrives rather than producing a report you have to read. Three moments
are reachable in principle; one is wired.

| Moment | What is caught | State here |
|---|---|---|
| A tool result comes back | instructions addressed to your agent, carried in the returned text | **wired and measured.** 206 rules on Claude Code's `PostToolUse`, calibrated on real traffic; see [`docs/calibration.md`](docs/calibration.md) |
| A tool call is about to run | the call does something you did not authorise | scanner reachable, no measured rules. The 57 `IN` rules in the corpus have no benign corpus to calibrate against, so none ships |
| A skill or server is added | an install step piping a download into a shell, a plaintext secret, a declaration of no `tools` beside authority over all of them | `cfg.py` scans a document, and nothing calls it. No installer hook, and `read_config` accepts no surface but `IN` and `OUT` |

Claude Code, Codex and Copilot each expose all three interception points. Only Claude Code has an
adapter here, and that is a statement about this package rather than about those harnesses.

## What it will not do

Fire on ordinary work. A security hook that interrupts normal use gets switched off within a day, and
then nothing runs at all. Every executable rule starts in a record-only lane, and it leaves that lane
only on a measured benign firing rate with an exact binomial bound behind it. The policy is in
[`SCHEMA.md`](SCHEMA.md) and the arithmetic is in `agent_defs/lanes.py`.

## Layout

| Path | What |
|---|---|
| `src/agent_defs/model.py` | the normalized record every loader emits |
| `src/agent_defs/evaluate.py` | bounded predicate evaluation, with build-time pattern screening |
| `src/agent_defs/hazards.json` | the measured regex timings the screen refuses on |
| `src/agent_defs/cfg.py` | the configuration channel: a rule run the way its source runs it |
| `src/agent_defs/lanes.py` | the four admission lanes and the binomial bound behind them |
| `src/agent_defs/bundle.py` | the distribution format: normalized records frozen into one file |
| `src/agent_defs/bundle.json` | the pinned rules the hook loads, written by `scripts/build_bundle.py` |
| `src/agent_defs/cli.py` | the `agent-defs` command: install, calibrate, report state |
| `SCHEMA.md` | the loader contract |
| `docs/hazards.md` | why the screen refuses on measurement rather than on shape |

## Using it

```sh
agent-defs install --settings ~/.claude/settings.json    # prints the diff
agent-defs install --settings ~/.claude/settings.json --yes
agent-defs status                                        # what it would do next call
```

Everything starts in `RECORD`. A completed `RECORD` finding is written to the
local log and changes nothing the model sees. Two other paths still speak: a
scan that could not finish adds a line to the model's context and a warning to
yours, and so does a diagnostic log that could not be written. Letting a source
act takes a measurement of the set you actually have installed, and then saying
so once:

```sh
agent-defs export-bundle --out enabled.json      # the exact enabled set
python scripts/measure_tool_traffic.py --evidence <dir> --names <corpus> \
    --surface OUT --rules enabled.json --workers 4
agent-defs calibrate --report <corpus>-out-report.json
agent-defs promote --source atr --lane ADVISE
```

`promote` refuses a lane the evidence does not support and prints what the
change does. The shipped bundle fired once on 1,743 held-out tool results, an
exact upper bound of 0.272%, which reaches `ADVISE` and not `DENY`.
[`docs/calibration.md`](docs/calibration.md) has the procedure, the corpora, and
the two gates that disagree about it.

## Seeing what an install is doing

`agent-defs status` answers it without guesswork: which bundle loaded, how many
rules that leaves enabled on each surface, the lane each of them can reach on
today's measurement, and whether a harness is registered to call any of it.

The hook reads `bundle.json` and never a loader, because the machine running it
has neither the pinned corpora nor a YAML parser, and a corpus fetched from
inside a tool-call hook would be a network request on the critical path of
every tool call.

## The rule is the pattern plus its dispatcher

A pattern lifted out of the engine that dispatches it is a different artifact from
the rule its authors shipped. Measured on ATR's own skill benchmark: the same
patterns matched flat against a skill document flag 155 of 466 benign documents,
and run through ATR's own admission gates they flag 1, which is what ATR itself
flags. Each record therefore carries its source's dispatch beside its pattern.
[`docs/cfg.md`](docs/cfg.md) has the gates, where each was read from, and the
before-and-after numbers.

## Sources

Six public corpora, each pinned by commit. Redistribution terms are recorded per source and per field,
and a source whose terms are unresolved ships no bytes until they are.

## Licence

MIT for this package's own code. Rule content carries its source's licence, recorded per record.
