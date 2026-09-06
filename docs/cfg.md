# The CFG channel: scanning configuration somebody else wrote

A skill document, an agent file, an MCP server manifest. Somebody else wrote the
text and the person installing it will not read every line. That asymmetry is the
reason this channel is worth defending, and it is the only entry channel with a
public labelled corpus that has a negative class.

## What was wrong

Round three measured this package against ATR's own skill benchmark, 32 malicious
and 466 benign documents. At the shipped pin it detected 28 of the 32 and also
flagged **155 of the 466 benign documents**, a 33.3% false-positive rate against
upstream's published zero. On the June 108-rule snapshot the same harness detects
31 and flags **445 of 466**, which is the figure round three reported and which
this harness reproduces exactly.

The rules were not the problem. Running them was. A rule is a pattern plus the
dispatcher that decides when the pattern runs, and this package shipped only the
pattern. ATR admits a small minority of its rules to the skill path and this
package admitted all of them.

## What the source actually does

`scanSkill()` builds one event with `scanContext: 'skill'`, no trace, no fields
and no session, and hands the whole document to `evaluate()`. Inside, four things
happen that the flat path did not do:

| Gate | Where | Effect at the pinned revision |
|---|---|---|
| Status skip | `src/engine.ts:407` | `draft` and `deprecated` rules never run |
| Lane | `src/enforcement.ts:106`, `src/quality/rule-contract.ts:62` | the default `hunt` lane admits every maturity except `deprecated` |
| Skill compound gate | `src/engine.ts:466` | a rule whose `scan_target` is neither `skill` nor `both` must match `max(2, ceil(0.3 x conditions))` conditions |
| Field resolution | `src/engine.ts:1394` | every condition field resolves to the whole document |

The compound gate is the one that matters, and its effect is larger than it
looks. `evaluateArrayConditions` stops at the first matching condition when the
logic is `any`, so an `any` rule can never report more than one matched
condition, and the gate's floor is two. **For an `any` rule without a skill scan
target the gate is an unconditional reject.** 789 of the 793 pinned rules declare
`any`. Upstream says so itself, in a comment above the gate that calls the
behavior load-bearing and records what happens when the threshold is made
reachable: the benign corpus goes from 1 flagged document to 265.

Two more restrictions run below that. Matches inside a fenced code block are
suppressed for the 20 rules that set `tags.suppress_in_code_blocks`, deciding on
the first match position alone. And base64 blocks in the document are decoded, up
to five of them, and scanned as if they were text.

## Where the gates come from

`agent_defs/loaders/atr_skill_gates.py` reads every value above out of the
checkout and records the file and line it came from. Nothing in this package
types a threshold in from memory, and a gate whose shape has moved upstream
raises `GateReadError` rather than falling back to a default. That failure mode is
deliberate: a silently defaulted gate is exactly the defect this module exists to
remove. It is also already exercised. Run the reader against the June snapshot
`a8a4146`, where the compound gate has a different shape, and it refuses to read
rather than guessing; that checkout produces no CFG bindings and records the
reason. Repinning ATR means extending the reader, and the cost of not noticing is
a failed read rather than a restored false-positive rate.

Of the 793 pinned rules, **136 carry an executable binding**. The gates refuse the
rest: 654 at the compound gate, 7 on status, 6 on method, and 2 whose every
condition the pattern screen refuses. Rules can be refused by more than one gate,
and each one is recorded.

Each rule then carries a `ChannelBinding` on its record, listing every gate that
was consulted, its verdict, and the line it was read from. A rule the dispatcher
refuses keeps its binding, so the record distinguishes a rule this package
dropped from a rule its own author excluded.

## The denylist upstream declares and does not apply

`src/engine.ts:69` defines `SKILL_CONTEXT_DENYLIST`, 22 rule ids with upstream's
own false-positive note beside each. The pinned engine never reads the set;
`engines/typescript/INTERFACE-CONTRACT.md:151` still says a conforming engine
must honor it. Upstream's own audit, `docs/research/clawhub-benign-fp-2026-08-19.md`,
calls the set dead code and names the single consequence: 21 of the 22 are
`scan_target: mcp` and the compound gate already excludes them, while
`ATR-2026-00123` carries `scan_target: skill` and runs.

Both facts travel on the record, and the default follows the engine rather than
the contract, because the engine is what produced the figures being reproduced.
The cost is exactly one benign document. Honoring the declared list instead
removes that document and reproduces upstream's published 0% precisely.

## Two execution models, and the source's own is the wider one

`predicate_kind` describes a flat, field-agnostic predicate. The binding describes
the source's dispatcher. They refuse different things, and 42 rules that have no
flat predicate carry an executable binding:

- The flat predicate refuses a rule naming two condition fields, because one text
  payload does not preserve their boundaries. In skill context every field
  resolves to the whole document, so the boundary does not exist to lose.
- The flat predicate composes an `any` rule's conditions into one alternation and
  screens the result. `ATR-2026-00121`, the rule that fires on 15 of the 32
  malicious documents, fails that screen as a composition. Upstream never
  composes; seven of its eight conditions pass the screen individually and run.

A condition the pattern screen refuses on safety is dropped from an `any` rule
and recorded on the binding, which can only lose matches because `any` fires on
one branch. An `all` rule loses its whole binding instead: dropping a branch there
would fire the rule on less evidence than its author required. Three residual
disagreements with upstream all have this shape, and all three are the same
nested-quantifier refusal.

## The result

Measured against ATR's own `scanSkill()` at the pinned revision, over all 498
documents. Upstream detects 32 of 32 and flags 1 of 466 benign.

| Step | Recall | Benign flagged | Precision |
|---|---|---|---|
| Flat: every runnable pinned rule on raw text | 28/32 | 155/466 | 15.3% |
| Admission gates only | 30/32 | 1/466 | 96.8% |
| Gates plus code-block suppression | 30/32 | 1/466 | 96.8% |
| Gates plus suppression plus base64 blocks | **31/32** | **1/466** | **96.9%** |
| The above plus the declared denylist | 31/32 | **0/466** | **100%** |

**495 of the 498 documents produce a matched-rule-id set identical to upstream's
own engine, and no rule fires that upstream's engine does not.** The three
differences are all under-firing. Two do not change a verdict. The third,
`ATR-2026-00129` on an ASCII-smuggling sample, is the single remaining false
negative and has a located cause outside this channel: the rule writes Unicode tag
characters as UTF-16 surrogate pairs, which JavaScript matches in its own string
representation and Python does not.

## How this was measured

Every number above comes from ATR's own benchmark, scored on Linux because the 32
malicious documents must not touch a Windows host. `PYTHONPATH=src python
scripts/audit_atr.py <atr-checkout>` reproduces the admission side from any
checkout: which rules the dispatcher admits, which gate refused each of the rest,
and every partial binding with the conditions it dropped.

The scoring scripts and their outputs are preserved at
`spark-37f2:~/agent-defs-work/round4-cfg/`: `upstream-skill.mts` runs ATR's
unmodified `scanSkill()` through `tsx` to produce the reference,
`measure-cfg.py` produces the five steps in the table, `compare-upstream.py`
diffs the two document by document, and `crosscheck-a8a4146.py` reproduces round
three's 445-of-466 figure on the June snapshot. All of it matched in process,
through `agent_defs.evaluate.scan_trusted` and the function now called
`agent_defs.cfg.scan_cfg_trusted`, never through an isolated path.

## The isolated path

`evaluate.scan` runs a flat predicate in a disposable worker because a regex that
backtracks cannot be interrupted once it starts, and the skill document a person
is about to install was written by whoever wrote the attack. `scan_cfg_isolated`
now gives this channel the same treatment over the same worker and supervisor.

The worker protocol carries a `cfg` mode: each rule's conditions in the source's
order, its condition logic and its code-block suppression flag, which a flat
predicate cannot express. The document crosses raw, so the base64 decode and the
code-fence scan run inside the process that can be killed rather than in the
caller's; both read attacker text and neither is free.

Measured on a pattern the shape screen admits and the table has never timed,
`a*a*a*a*a*a*b` against 200 characters: budgets of 0.25 s, 1.0 s and 2.0 s return
in 0.27 s, 1.01 s and 2.02 s, each reporting `complete=False` with `worker
deadline exceeded`, and `findings` raises so a timeout cannot be read as a clean
document. The same call through `scan_cfg_trusted` does not return. On ordinary input the
two paths agree finding for finding, span for span, including which condition
matched and whether it came from the document or a decoded block.

The plain name is the bounded one. `scan_cfg` is `scan_cfg_isolated`, and the
in-process path is `scan_cfg_trusted`: no isolation, no deadline, for measurement
and for material the caller wrote. `evaluate` already spelled the unprotected
entry point `scan_trusted`, so this module spelling the plain name the other way
round was a trap: a caller reaching for the obvious function by analogy got the
one with no deadline, on the channel whose whole input is written by someone
else.

## What is not built

Unicode normalization. Upstream tests each pattern against
`foldConfusables(normalizeUnicode(text))` and then against the raw text, so
omitting it moves verdicts in both directions. Upstream builds its code-block ranges on the
normalized text, so a fence written with U+FF40 FULLWIDTH GRAVE ACCENT folds to a backtick
there and suppresses, while the raw port sees no fence and fires. Omitting normalization
therefore loses matches in one place and adds them in another. It is not a free addition: two of the
conditions upstream matches and this package does not are zero-width-character
detectors, and NFKC normalization removes the very characters they look for. The
raw fallback is why upstream can run both.
