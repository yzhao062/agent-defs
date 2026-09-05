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

It acts at three moments rather than producing a report you have to read.

| Moment | What is caught |
|---|---|
| A skill or server is added | an install step piping a download into a shell, a plaintext secret, a declaration of no `tools` beside authority over all of them |
| A tool call is about to run | the call does something you did not authorise |
| A tool result comes back | instructions addressed to your agent, carried in the returned text |

All three interception points exist today in Claude Code, Codex and Copilot. Two of the three can
remove hostile content before the model reads it.

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
| `src/agent_defs/lanes.py` | the four admission lanes and the binomial bound behind them |
| `SCHEMA.md` | the loader contract |

## Sources

Six public corpora, each pinned by commit. Redistribution terms are recorded per source and per field,
and a source whose terms are unresolved ships no bytes until they are.

## Licence

MIT for this package's own code. Rule content carries its source's licence, recorded per record.
