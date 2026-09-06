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
    --evidence <dir> --names <corpus> --surface OUT \
    --rules enabled.json --workers 4             # on the corpus host
agent-defs calibrate --report <corpus>-out-report.json --accept-pooled-bound
agent-defs promote --source atr --lane ADVISE
```

The third step needs `--accept-pooled-bound` on a corpus like this one and will
refuse without it. Why, and what taking it gives up, is the last section.

`export-bundle` exists because `calibrate` refuses a report that does not cover
every enabled rule. The enabled set is the starter rules plus the bundle minus
whatever the config gates out, and nothing else reproduces it, so measuring
anything else produces a report `calibrate` rejects.

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

The last row describes the enabled set **as revised**, which is 205 ATR rules
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

The artifact declares 205 ATR rules on `OUT`, plus the 4 starter rules, at ATR
`faf743fe`. The evaluation recorded one bundle hit among 1,743 distinct
payloads. Treating those as independent representative Bernoulli trials gives a
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
in 5,023,741 trials the inverted value is 0.0009999999999418658 while the exact
bound is above 0.001, so a float comparison reads `DENY` where the arithmetic
does not support it. `lanes.bound_within` answers True, False, or **neither**,
and every caller takes the stricter lane on neither.

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
those constructs and probes such a rule without pruning it; the shipped 205
contain none of them.

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

On the held-out corpus, over the shipped 205-rule set, 102 of which carry a
zero-width assertion (`scripts/leaf-traversal-diagnostic.json`):

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
free of atomic groups, possessive quantifiers, conditionals and quantified
lookarounds the rewrite only widens what matches, so it over-approximates
arbitrary substring decompositions; a pattern carrying one of those is counted
as a candidate on every unit instead. Read the aggregate with its breakdown,
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

The shipped artifact was built against the 7-fixture list. It has not been
rebuilt, because rebuilding needs the pinned archive on the corpus host, and it
does not need to be: `tests/test_shipped_bundle.py` runs all 20 fixtures
against the committed bundle and no rule fires on any of them. The wider list
is a policy for the next build and a check on this one.

Trimming sample text out of the bundle also means `bench` can no longer verify
reachability at measurement time, and reports `no_examples` for the 205 ATR
rules. The reachability result is checked at build time instead and travels in
each record under `extra.reachability`, per `SAMPLES.md` rule 3.

`SAMPLES.md` rule 5, scanning the built artifact before publishing, has now
run. One Windows Defender on-demand scan reported no threats, and the copy was
still on disk three seconds after being written, on a machine registering both
Windows Defender and Bitdefender. That is weaker than "two scanners cleared
it", and `SAMPLES.md` says why. The record is `scripts/artifact-scan.json`,
keyed by the artifact's digest, and `tests/test_shipped_bundle.py` fails if
that record is missing or describes different bytes.
