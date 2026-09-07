# Calibrating a bundle on real tool traffic

A rule leaves `RECORD` only on a measured benign firing rate. This is the
procedure that produced the first such measurement, the numbers it produced,
and the parts of it that are weaker than they look.

## The trial has to be the thing the rule sees

`OUT`'s trial definition is one complete tool result payload from one
invocation. `agent-defs calibrate --benign-dir` walks a directory and keeps its
`.py`, `.md`, `.rst`, `.txt` and `.tex` files, which is a different population:
a repository is not a stream of tool results, and a rate measured on one does
not transfer to the other. So the measurement runs through `agent_defs.bench`
over tool results extracted from real sessions, and
`agent-defs calibrate --report` reads what it produced.

## The loop

```sh
agent-defs export-bundle --out enabled.json      # the exact enabled set
python scripts/measure_tool_traffic.py \
    --evidence <dir> --names <corpus> --surface OUT --surface IN \
    --rules enabled.json --workers 4             # on the corpus host
agent-defs calibrate --report <corpus>-out-in-report.json --accept-pooled-bound
agent-defs promote --source atr --lane ADVISE
```

The third step needs `--accept-pooled-bound` on a corpus like this one and will
refuse without it. Why, and what taking it gives up, is the last section.

`export-bundle` exists because `calibrate` refuses a report that does not cover
every enabled rule. The enabled set is the starter rules plus the bundle minus
whatever the config gates out, and nothing else reproduces it, so measuring
anything else produces a report `calibrate` rejects.

Every enabled surface goes in one report for the same kind of reason. `bench`
refuses a whole report when a bundle enables a surface its corpora do not cover,
so measuring `OUT` and `IN` in two runs produces two reports, each refused for
missing the other's surface. The lane then rests on whichever surface bounds
worse, and `calibrate` prints both so a reader can see which one that was.

## Two corpora, three stages

Content deduplication reduced `trace-commons` from 4,198 to 2,937 distinct
payloads and `local-claude` from 4,000 to 3,556. **These are not counts of
independent invocations.** Repeated text can come from separate calls, and
different results from one session can stay dependent. The measurement does not
weight payloads by their recorded occurrence counts, so collapsing changed the
population from invocations to distinct payloads. The two corpora share 5
payloads, and the splitter does not exclude them, so their allocation across the
held-out half has not been audited.

Choosing which rules to ship by watching which ones fire, and then quoting a
bound from the same material, states a number the selection already guaranteed.
So `scripts/split_traffic_corpus.py` cuts `local-claude` by digest into a half
used for choosing and a half nothing consults until the end. That removes the
circularity and nothing else: the split is by payload rather than by session, so
one session appears on both sides, and no code can establish that the rule set
and the admission criterion were fixed before anyone read the held-out outcome.

| Stage | Corpus | Trials | Rules | Findings | Rules that fired |
|---|---|---:|---:|---:|---:|
| Select | trace-commons | 2,937 | 231 | 119 | 8 |
| Select | local-claude, selection half | 1,813 | 216 | 7 | 6 |
| **Verify** | **local-claude, held-out half** | **1,743** | **209** | **1** | **1** |
| **Verify** | **held-out half, the same episodes' tool calls** | **1,738** | **11** | **0** | **0** |

The last row is the `IN` surface and is read in [The tool-call surface](#the-tool-call-surface)
below; the rest of this section is about `OUT`.

The third row describes the enabled set **as revised**, which is 205 ATR rules
plus 4 starter rules after the build filter described below removed
`ATR-2026-02010`. The count is the same either way, because that rule never
fired on joined text; it was found by a different procedure. The revision still
has to be declared, because the row was recomputed after it. What carries
across the revision is one specific thing: deleting rules cannot increase a
union of predicate hits, so the bound established for the larger set stays a
conservative bound for the subset that shipped. Recomputing a *tighter* number
from post-removal counts would not carry across, and nothing here does that.

The held-out stage is the one that matters, and the reason is in the second
row. The 8 rules that fired on `trace-commons` and the 6 that fired on the
selection half are **disjoint sets**: each corpus surfaced rules the other
never touched. A bundle selected on one corpus and reported on the same corpus
would have claimed zero, and 6 rules would have been shipped that fire on
ordinary work. That is a reason to expect poor transfer to a third corpus and
to go collect one. It is not a demonstration that the tail thins: the three
rows count firing rules across changing candidate sets on different corpora, so
they are not comparable quantities, and it does not falsify the bound below,
which already allows future hits.

Every **selection-stage** rule that fired is held back in
`scripts/bundle-held-back.json` with the count and corpus that condemned it,
and `build_bundle.py` carries that list into the bundle's own metadata, so an
omission is visible in the artifact rather than implicit in its size. The one
rule that fired on the held-out half is deliberately still shipped: removing it
would make the held-out number a selection result like the other two.

## The result

The artifact declares 216 ATR rules at ATR `faf743fe`: 205 on `OUT`, which with
the 4 starter rules is the 209 measured here, and 11 on `IN`. The evaluation
recorded one bundle hit among 1,743 distinct payloads on `OUT`. Treating those
as independent representative Bernoulli trials gives a
nominal one-sided 95% Clopper-Pearson upper bound of **0.272%**. The importer
maps that to an `ADVISE` ceiling and refuses `DENY`, and `agent-defs promote`
will not set a source higher.

That is the code's threshold result, and it is a result about the procedure
`bench` ran. The deduplication and the payload split do **not** establish that
it is a 95% bound on future invocation traffic, on other users, or on any tool
taken separately, and the section below is why it is not established as a bound
on what the deployed hook does either.

The comparison itself is made without inverting the bound. Asking whether a
rate is at or below a ceiling is the same question as whether
`P[Binomial(trials, ceiling) <= hits] <= 0.05`, which takes one evaluation at
the ceiling; inverting instead concentrates the coefficient's rounding into the
returned rate, and near a ceiling that rounding decides the lane. At 4,907 hits
in 5,023,741 trials the exact bound is above 0.001, while the inverted value is
0.0009999999999418658 on glibc and on Windows, so a float comparison reads
`DENY` where the arithmetic does not support it.

The same call returns 0.001000000000146392 on macOS, above the ceiling. **Which
side of a ceiling that value falls on depends on the host's libm**, so a lane
decided by comparing it is a lane decided by the machine that ran the import.
CI caught this by disagreeing with itself across runners.
`lanes.bound_within` answers True, False, or **neither**, every caller takes the
stricter lane on neither, and that refusal is the same on every platform.

## The tool-call surface

Every unit in the corpus carries two things: the tool result the hook sees at
`PostToolUse`, and the invocation it sees at `PreToolUse`. So `IN` is measured
on the same episodes as `OUT`, with nothing new collected. Three things had to
change before that measurement meant anything, and two more can only be stated,
because the material to fix them no longer exists.

**The material is the leaves, not the envelope.** The snapshot stores an
invocation as `{"name": ..., "arguments": ...}`, and the first version of this
measurement matched that serialization. The hook does not: at `PreToolUse` it
walks the string values inside `tool_input` and scans each one on its own,
never the serialization, the object keys, or the tool name. The difference is
not cosmetic. `ATR-2026-02525` looks for a parameter expansion at the start of
a command, so it matches `${!VAR} /tmp/x` as the hook sees it and does not
match the same command inside `{"command": "..."}`, where the character in
front of it is a quote rather than a line start. Matching the envelope was
answering a question nobody asks at runtime. The unit is still one invocation
and one trial, with the serialization as its identity; what is matched is each
argument string, and a rule hits the unit when it hits any of them. Round 5 of
the review found this, and also established that it does not change the number:
1,738 invocations, 3,401 argument leaves, zero hits either way.

**The trial count is not the same.** A tool result is unique here because the
snapshot was deduplicated on it. An invocation is not: the same call can be made
twice and return different bytes, which happened five times, across three
distinct commands. Those five are one piece of `PreToolUse` material, so the
`IN` corpus holds **1,738** trials against `OUT`'s 1,743. That satisfies
`bench`'s distinct-material contract, which is what its refusal is about, and
that refusal is one `calibrate` has no standing to relax. It is not a claim
that repeated bytes would be invalid draws: if the population of interest were
invocation occurrences rather than distinct invocations, they would be valid.
Deduplicating narrows the zero-hit denominator, so it widens the interval.

A second selection sits underneath it. These 1,738 invocations are what
survived deduplication **on their results**, so two different calls that
returned identical bytes were already collapsed before this stage saw them.
What the number describes is distinct invocation serializations retained
through an output-selected sample, which is a further reason it is not a
sample of what a user's tool calls look like.

**One stratum was labelled from the wrong text.** `exposure` and `tool` are
classified from the call name and its arguments, so they already describe an
invocation. `prose` was classified from the result. On an `IN` unit that labels
text nobody scans, and over this corpus the two labels disagree on 10.1% of
units, so it is now classified on the invocation. It moves a lot of them:
`prose=security-adjacent` holds 186 units on `OUT` and 42 on `IN`. It does not
move which stratum is worst, on either surface. That is decided by the tools
called once or twice in the whole corpus, the same way it is for `OUT`.
`result_status` is left as it stands: it describes the episode rather than the
call, and it cuts the corpus more finely, which can only make the worst stratum
worse. Read it as a label on the episode that was retained rather than as a
property of the command: no duplicate group here mixed an error with a success,
but if one did, the surviving row would carry only its own status.

**There is no selection half for `IN`, and one cannot be reconstructed.** The
two selection corpora were working files and are gone from disk; only the
held-out half survives, because a script exists that replays it from a report.
So the three `IN` rules held back in `scripts/bundle-held-back.json` were
condemned by their firing on *tool results* in the selection stage, which is not
the surface they would run on. That is prior selection rather than selection on
the held-out half, so it does not make the number below a selection result. It
is still weaker evidence than the `OUT` rules have, and it cannot be re-derived:
the counts in that file are the whole record. Reading the held-out outcome and
then dropping an `IN` rule would have made the number worthless, so no rule was
dropped after it was read.

What that exclusion was worth can be measured, and round 5 of the review asked
for it, so it was: all fourteen runnable `IN` rules over the same 1,738
invocations, prespecified to be reported whatever it showed and not to change
which rules ship. Adding predicates cannot lower a union, so this is a
conservative envelope around the eleven.

| Rule | Held back on | Hits |
|---|---|---:|
| `ATR-2026-00111`, Shell Metacharacter Injection in Tool Arguments | 4 of 2,937 tool results | **45 of 1,738** |
| `ATR-2026-00064`, Over-Permissioned MCP Skill | 81 of 2,937 tool results | **17 of 1,738** |
| `ATR-2026-00110`, RCE via eval() and Dynamic Code Injection | 27 of 2,937 tool results | **1 of 1,738** |
| **Fourteen-rule union** | | **61 of 1,738, u95 4.33%** |

Read this in both directions. The exclusion was right: 4.33% is eight times the
`ADVISE` ceiling, so shipping those three would have held the whole bundle in
`RECORD`, and the cross-surface evidence pointed the correct way even though it
came from the wrong surface. `ATR-2026-00111` looks for shell metacharacters in
tool arguments, and an agent's own `Bash` calls are full of them.

The exclusion was also **load-bearing**, which the zero on its own does not
show. The eleven rules are quiet partly because three noisy ones were taken out
first, on evidence from another surface that no longer exists to re-derive. That
is prior selection rather than selection on the held-out half, and it is still
selection. A reader who wants the number for the runnable `IN` surface as a
whole should take 4.33%, not 0.172%.

**This is the second reading of the held-out half.** The first established the
`OUT` bound. Adding `IN` is a new question asked of the same held-out material,
which is the cost this split was set up to control and not a cost it removes.

### The result

The 11 `IN` rules fired on none of the 1,738 invocations, a nominal one-sided
95% Clopper-Pearson upper bound of **0.172%**. The lane is gated on whichever
surface bounds worse, which is `OUT` at 0.272%, so admitting `IN` did not move
what the bundle may do.

Three rule-and-surface pairs fired across surfaces, and none of them counts:

| Rule | Its surface | Fired on | Hits |
|---|---|---|---:|
| `ATR-2026-00118` | `IN` | `OUT` | 1 of 1,743 |
| `ATR-2026-02106` | `OUT` | `IN` | 1 of 1,738 |
| `ATR-2026-00296` | `OUT` | `IN` | 2 of 1,738 |

A fourth, `ATR-2026-00554` on `IN`, was there while the envelope was being
matched and is gone now that the leaves are. It was matching the serialization
rather than any string the hook would scan, which is the defect above showing
itself in the one place it was visible from outside.

The hook evaluates a rule only on its own surface, so none of these would have
run where it matched, and `bench` counts a bundle hit only when the rule's
surface matches the unit's. They are recorded because the alternative is a
reader assuming the number covers something it does not. What they do show is
that the two bodies of text are not interchangeable: a rule written for one
finds things in the other, at rates that would matter if either set were ever
run against both.

## Two gates, and the one this uses

`bench` and the hook do not compute the same thing, and a reader should know
which number a lane is resting on.

`bench` gates on the **worst per-stratum** bound. Strata include one per tool,
so `tool=WebSearch` can hold 6 units and `exposure=attacker-reachable` 19, and
19 clean trials bound a rate at 14.7%. Its bundle gate reports
`worst bundle stratum u95=0.950000 exceeds 0.005` and refuses, whatever the
hits are. Reaching it needs about 600 clean trials in every stratum, which a
personal corpus will not have for a rarely used tool.

`calibrate --report` selects the worst whole-corpus row per surface, then the
worst of those. It does not sum across corpora. It recomputes the bound it
stores, and it records the benchmark's refusal separately under
`evidence.bench`.

**Relaxing that refusal is an explicit act, and only one of the three is
relaxable.** `bench` refuses a corpus for three different reasons and they are
not interchangeable. Repeated material and missing required coverage say the
trial count is not what it claims, which no choice of statistic repairs, so
`calibrate --report` refuses them outright and refuses any refusal it does not
recognise. The thin-stratum width is a disagreement about which statistic to
gate on, and `--accept-pooled-bound` is where a caller takes responsibility for
it in writing. What was relaxed is written into `evidence.bench.relaxed`.

Taking the pooled bound is a weaker claim, not an equivalent one. It concerns a
specified traffic mixture and certifies nothing about a rarely used tool. Note
also that `bench`'s per-stratum bounds are pointwise and are not a simultaneous
95% guarantee across every stratum either.

There is now a fourth refusal, and it is not relaxable by anything. When the
worst stratum's bound cannot be placed on one side of the ceiling in double
precision, `bench` fails the bundle with a message naming that specifically,
which the importer does not recognise as the relaxable one and therefore treats
as fatal.

## What this measurement does not establish

It is one user's selected distinct payloads on two corpora. It does not
establish a confidence bound for ordinary work generally, for other users, or
for future traffic, and it does not measure attack recall at all.

### The report and the hook do not evaluate text the same way

`bench` scans one string per result, built by joining the result's text blocks
with newlines. `process` walks the payload and scans each string leaf on its
own. A rule fingerprint records neither procedure, so a measurement taken under
the first does not automatically describe the second.

This gap is **not closed**, and the earlier claim that it was has been
withdrawn. `scripts/bound_leaf_discrepancy.py` measures part of it, and three
limits are worth stating before the numbers.

The first version of that script simulated a per-leaf scan by recompiling
anchored patterns with `re.MULTILINE`, and that was unsound. `\A` and `\Z`
ignore the flag; `(?<!\n)X` and `X(?!\n)` flip at a boundary the flag does not
reach; `^X$(?![\s\S])` keeps a lookahead that still sees the joined suffix; and
`(?-m:^X$)` turns the flag back off inside the pattern. The script now performs
a real split rather than simulating one.

Performing it removed the simulation and did not produce a bound, for two
further reasons the third review round established. **Splitting at every
newline is not the hook's decomposition:** the extractor joined blocks with
newlines, but a block can contain newlines of its own, so the real cuts are a
subset of the newline positions and cutting at all of them destroys a match
lying across lines inside one block. And **an assertion is not the only thing
that can make a match vanish** once a leaf sits inside more text: an atomic
group or possessive quantifier commits, and removing an assertion that carries
a quantifier moves the quantifier onto the token before it. The script names
those constructs and probes such a rule without pruning it, and the quantifier
it looks for need not sit against the assertion: verbose-mode whitespace and
comment groups can come between. None of the 216 shipped rules carries one.

The last limit is the one no computation on this corpus can lift. The corpus
records `tool_result.content` from a transcript. The hook walks `tool_response`,
a different object, and scans every string value in it, down to a block's own
`"text"` type tag and whatever paths, statuses and metadata a tool returns.
Those strings were never extracted, so nothing here bounds what a rule finds in
them. Only re-extraction reaches them, and re-extraction would re-select from
transcripts that have changed since, which is what the held-out split exists to
prevent.

So the two numbers below **are diagnostics rather than bounds on the deployed
hook, and they are not admission evidence.** They compare two evaluation
procedures over one fixed body of retained text.

On the held-out corpus, over the bundle's 205 `OUT` rules, 102 of which carry a
zero-width assertion (`scripts/leaf-traversal-diagnostic.json`). The 11 `IN`
rules are left out because the units are tool results and an `IN` rule never
sees one:

| Procedure | Hits in 1,743 | Nominal u95 |
|---|---:|---:|
| joined, as `bench` measured it | 1 | 0.272% |
| joined, unioned with an all-lines probe | 1 | 0.272% |
| joined, unioned with an assertion-removal rewrite | 489 | 29.9% |

The middle row unions joined hits with the all-lines probe. No rule gained a
hit in this run. That does not establish an exact leaf count and does not cover
every decomposition whose cuts are a subset of the newline positions. One thing
about it is settled rather than observed: ninety-eight of the shipped rules
carry `\b`, and a word boundary alone cannot gain from a newline split, because
it is a position with `\w` on exactly one side, counting off-the-end as
not-`\w`, and a newline is not a word character. That is a fact about `\b`, not
about those 98 rules, since a rule carrying one can carry something else too.

The bottom row records an experimental assertion-removal rewrite. For a pattern
free of atomic groups, possessive quantifiers, conditionals, quantified
lookarounds and backreferences the rewrite only widens what matches, so it
over-approximates arbitrary substring decompositions; a pattern carrying one of
the first four is counted as a candidate on every unit instead. Backreferences
are absent by screening rather than by detection: removing a lookahead can
renumber the groups after it, and the evaluator rejects backreferences before a
rule can reach this. The quantifier that makes a lookaround unsafe need not sit
against it, since verbose-mode whitespace and comment groups can come between,
which is how round 4 of the review reached past the first version of this check. Read the aggregate with its breakdown,
because one rule contributes 485 of the 489. `ATR-2026-02007` looks for a leaf
that is *entirely* a bare key label,
`^\W{0,5}(?:the\s+)?(?:secret[_ ]?key|key|…)\W{0,5}:?\W{0,5}$`. Without its
anchors it matches the word "key" anywhere, which ordinary text supplies
constantly, so the number mostly measures how wide that decomposition class is
rather than how loud the rule is. The other two contribute two hits and one.

That said, the rule underneath it is a real question this corpus cannot answer.
An anchored rule fires on a *short whole leaf*, and a JSON string value is a
whole leaf whether or not it is a whole line: `{"fields": ["key", "value"]}` is
an ordinary shape for a tool result. The newline pass is the wrong instrument
for that, because a leaf need not be a line, and the substring pass is too
blunt for it, because it also allows cuts no JSON payload produces. Answering
it takes `tool_response` payloads, which is the extraction gap above.

### A rule was removed after that diagnostic was read

`ATR-2026-02010` looks for a string made entirely of emoji and invisible
characters, which is a real attack shape, but `\s` inside its character class
means every blank leaf matches it. Over joined results it looked quiet, because
a whole result is rarely blank. The diagnostic reported it matching 348 of the
1,743 retained texts, which is a count of that procedure's hits and not a count
of hook events.

`build_bundle.py` then gained a filter that rejects a rule matching any of the
whitespace-only fixtures in its `CONTENT_FREE` list, and the rule is out.

**This was a build policy change informed by an evaluation result, so the lower
post-change diagnostic is descriptive rather than an untouched validation of
the revised detector.** Writing the criterion as a property of the pattern does
not repair that. The decision to look for this property came from seeing which
rule inflated the diagnostic, and a feature can be selected adaptively exactly
as an identifier can; the general problem is adaptive reuse of evaluation
feedback (Dwork et al., [Generalization in Adaptive Data Analysis and Holdout
Reuse](https://arxiv.org/abs/1506.02629)). A fresh untouched claim needs a
protocol frozen before the outcome is read and material nobody has looked at.

The fixture list is also narrower than its name. It is a list, not a decision
procedure: `^ {7}$` and a pattern matching a run of U+2028 both pass the screen and both fire on a
blank leaf, and neither is on it. The first version contained no single space
at all, because the builder's list and the test's list were maintained
separately and drifted; the builder probed three spaces and never one, while
the test probed one and never U+00A0. `CONTENT_FREE` now says all of this where
it is defined, it has grown from 7 fixtures to 20, and the test imports it
rather than restating it.

The shipped artifact has since been rebuilt against the 20-fixture list, in the
build that added the `IN` rules, and its `screen_refusals` metadata names the
single-space witness the wider list found. `tests/test_shipped_bundle.py` runs
all 20 fixtures against the committed bundle as well, so the list is both the
build filter and a check on the artifact that filter produced.

Trimming sample text out of the bundle also means `bench` can no longer verify
reachability at measurement time, and reports `no_examples` for the 216 ATR
rules. The reachability result is checked at build time instead and travels in
each record under `extra.reachability`, per `SAMPLES.md` rule 3.

`SAMPLES.md` rule 5, scanning the built artifact before publishing, has now
run. One Windows Defender on-demand scan reported no threats, and the copy was
still on disk three seconds after being written, on a machine registering both
Windows Defender and Bitdefender. That is weaker than "two scanners cleared
it", and `SAMPLES.md` says why. The record is `scripts/artifact-scan.json`,
keyed by the artifact's digest, and `tests/test_shipped_bundle.py` fails if
that record is missing or describes different bytes.
