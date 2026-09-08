# agent-defs

Definitions for agent security: public rule sets and risk corpora, normalized, carrying where each
rule came from, watched for changes, and preserved after the source disappears. Install it and your
own agent checks the text it reads before the model acts on it.

**Status: pre-alpha, nothing published beyond a name reservation.** `0.0.1` on PyPI and npm holds the
name and carries no rules. An earlier 186-rule bundle caught 1.945% of a held-out attack pool, and
today's bundle has not had its catch rate remeasured. [Measured attack catch
rate](#measured-attack-catch-rate) has that result and its limits.

## What it is for

An agent reads tens of thousands of tokens you never see: web pages, issues, files, tool responses. If
any of that carries instructions, the model may follow them, and you have no way to notice. That is
the one threat here an individual cannot defend against alone, and it is what this package is aimed
at.

It acts at the moment the text arrives rather than producing a report you have to read. Three moments
are reachable in principle; two are wired.

| Moment | What is caught | State here |
|---|---|---|
| A tool result comes back | instructions addressed to your agent, carried in the returned text | **wired.** 209 rules on Claude Code's `PostToolUse`, being 205 from the corpus plus 4 starter rules; see [`docs/calibration.md`](docs/calibration.md) |
| A tool call is about to run | the call does something you did not authorise | **wired.** 11 rules on `PreToolUse`. Of the corpus's 57 `IN` rules, 43 do not run and 3 are held back after firing on selection-stage tool *results*, which is not the surface they run on |
| A skill or server is added | an install step piping a download into a shell, a plaintext secret, a declaration of no `tools` beside authority over all of them | **not reachable.** `cfg.py` and the worker's `cfg` mode implement it and the tests exercise it, but no harness path arrives there: there is no installer hook, and `read_config` refuses any surface but `IN` and `OUT` |

Claude Code, Codex and Copilot each expose all three interception points. Only Claude Code has an
adapter here, and that is a statement about this package rather than about those harnesses.

Wired does not yet mean acting. A registered hook scans and writes matches to the local log from the
first call, and every rule starts in a record-only lane, so a completed match changes nothing the
model sees until you explicitly promote its source to a lane a measurement supports.

Benign firing and attack catch rate answer different questions, and a project like this can quietly
report only the first. Measurements on selected traffic produced low observed firing rates and
nominal binomial bounds, with their limits set out under [Using it](#using-it). A historical attack
measurement produced a low catch rate on its test pool, described under [Measured attack catch
rate](#measured-attack-catch-rate). Read them together rather than either alone.

## What it will not do

Let unmeasured rules act on completed matches. A security hook that interrupts normal use gets
switched off within a day, and then nothing runs at all. Every executable rule starts in a record-only
lane, and it leaves that lane only on a measured benign firing rate with an exact binomial bound
behind it. That bound is not zero: `lanes.py` admits `ADVISE` at 0.5% and `DENY` at 0.1%, so what a
promoted rule carries is a ceiling on how often it may interrupt you rather than a promise that it
never will. The policy is in [`SCHEMA.md`](SCHEMA.md) and the arithmetic is in `agent_defs/lanes.py`.

## Measured attack catch rate

One measurement exists and it is not a current one. Held out by origin, the 186 rules shipping when
that run happened caught **417 of a 21,442-sample attack pool, 1.945%**. Across the whole historical
306-rule set the figure was 1,003, 4.678%. A preregistration written before the run predicted 40% to
75%, and the result is recorded as violating that prediction rather than as an occasion to
reinterpret it. 228 of the 306 caught nothing on that pool, 74.5%. The run, its pinned corpora and
the predictions it was scored against live in a research record outside this repository, so the
attack experiments and the corpus census described here cannot be reproduced from what is in it.

Three things bound what the number means.

The pool is not this hook's surface, and the direction of that mismatch is unknown. Public attack
corpora carry attacks delivered through the prompt: of the seventeen in the upstream source's own
evaluation, sixteen are prompt-channel and the seventeenth is a document, with none being tool
output. That evaluation is a different collection from the 21,442-sample pool, which was assembled
here from six corpora and whose denominator also includes harmful-content benchmarks and many garak
variants. Either way, rules watching returned text were scored against samples that mostly arrive
somewhere else. What that does to the number is not established: matched data could raise the catch
rate or lower it, and no matched-data measurement is reported here.

The bundle has moved since. It carried 186 rules for that run and carries 216 now, 220 with the
starter set. Today's bundle has no attack measurement at all, so the figure above is the available
historical result rather than a reading of what is installed.

An increment is sitting refused. On the same historical pool and the same 306-rule analysis, 42 rules
that do catch attacks are held out of the bundle because their benign firing rate is unmeasured, which
is the admission policy working as written. Adding them to the 186 would have reached 980 of 21,442,
4.570%, which is 980 of the 1,003 the whole historical set caught. That is a property of that run, not
a prediction for today's 216 rules, and the decision is open.

Quiet rules do not improve any of this. A bundle that matches nothing has zero observed benign hits
and zero attack hits, and its benign upper bound still depends on the trial count: `lanes.binomial_u95`
returns 25.887% for 0 hits in 10 trials and 0.172% for 0 in 1,743. Silence lowers the bound at a fixed
sample size rather than making it good.

## How much of an event it reads

At most one worker process runs per tool event. Eligible non-empty string leaves of `tool_input` or
`tool_response` go in a single request, within the traversal and byte limits, and the worker compiles
each rule once and runs it against every leaf. The alternative was one worker per leaf, and each leaf
then paid the compilation again: 341 ms of a 492 ms per-leaf floor was compilation, against 4.2 ms of
matching. On the shipped 209-rule `OUT` bundle that left 32.67% of measured tool results with an
incomplete scan, and every result carrying three or more leaves was incomplete.

Largest number of leaves still scanned completely inside the scan budget, measured by bisection over
real `OUT` leaves against that bundle, moved from a median of 1 to a median of 72. That unit is the
wrong one and is kept because it is what was measured. On the Windows machine this was measured on,
the resource deciding the outcome is total scanned text, around 45 to 55 KB an event, so an event of
long leaves runs out sooner than a leaf count suggests. Treat that as a reading for one machine,
bundle and traffic sample rather than a threshold for the platform.

A scan that does not finish says so. It never reports the leaves it did not reach as clean, and the
completeness verdict is checked against the per-leaf record rather than against a summary count. The
1.0 s is the scan budget and not an end-to-end hook guarantee: traversal and worker startup come out
of it, while parsing the response and turning a large set of findings into records is caller-side work
that sits outside it.

## Layout

| Path | What |
|---|---|
| `src/agent_defs/model.py` | the normalized record every loader emits |
| `src/agent_defs/evaluate.py` | bounded predicate evaluation, with build-time pattern screening |
| `src/agent_defs/_scan_worker.py` | the disposable child that compiles and matches, killed at an absolute deadline |
| `src/agent_defs/hooks/_core.py` | the traversal: which strings of an event get scanned, and what is rewritten |
| `src/agent_defs/hooks/claude_code.py` | the command hook itself: the exception boundary and the zero exit |
| `src/agent_defs/hooks/_claude_code_impl.py` | the Claude Code adapter, and the only harness wired |
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
local log and changes nothing the model sees. Two other paths still speak, and
they do not speak to the same audience: a scan that could not finish adds a
line to the model's context and a warning to yours, while a diagnostic log that
could not be written warns you alone. Letting a source act takes a measurement
of the set you actually have installed, and then saying so once:

```sh
agent-defs export-bundle --out enabled.json      # the exact enabled set
python scripts/measure_tool_traffic.py --evidence <dir> --names <corpus> \
    --surface OUT --surface IN --rules enabled.json --workers 4
agent-defs calibrate --report <corpus>-out-in-report.json --accept-pooled-bound
agent-defs promote --source atr --lane ADVISE
```

Both surfaces go in one report. A bundle that enables `IN` and `OUT` is refused
whole if either is unmeasured, so measuring one at a time produces a report
`calibrate` will not take. The lane is then gated on whichever surface bounds
worse, and `calibrate` prints both so you can see which one that was.

`--accept-pooled-bound` is there because a personal corpus will not carry the
roughly 600 clean trials per stratum the benchmark's own gate wants for a
rarely used tool, so its report arrives refused and the flag is where a caller
takes the weaker pooled claim in writing. Drop it and the step above will
refuse.

`promote` refuses a lane the imported evidence does not support and prints what
the change does. The shipped bundle fired once on 1,743 held-out tool results
and on none of the 1,738 tool invocations from the same episodes. Treating those
as independent representative trials gives a nominal one-sided 95% bound of
0.272% on `OUT` and 0.172% on `IN`, and the worse of the two decides the lane:
the importer maps 0.272% to `ADVISE` and not `DENY`. That sampling, and a rule
removed from the bundle after the evaluation was read, are both reasons the
number is not established as a bound on what the deployed hook does. [`docs/calibration.md`](docs/calibration.md) has the procedure, the
corpora, the two gates that disagree about it, and what none of it settles.

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
