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
agent-defs calibrate --report <corpus>-out-report.json
agent-defs promote --source atr --lane ADVISE
```

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
| **Verify** | **local-claude, held-out half** | **1,743** | **210** | **1** | **1** |

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

The artifact declares 206 ATR rules on `OUT`, plus the 4 starter rules, at ATR
`faf743fe`. The evaluation recorded one bundle hit among 1,743 distinct
payloads. Treating those as independent representative Bernoulli trials gives a
nominal one-sided 95% Clopper-Pearson upper bound of **0.272%**. The importer
maps that to an `ADVISE` ceiling and refuses `DENY`, and `agent-defs promote`
will not set a source higher.

That is the code's threshold result. The deduplication and the payload split do
**not** establish that it is a 95% bound on future invocation traffic, on other
users, or on any tool taken separately.

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

## What this measurement does not establish

It is one user's selected distinct payloads on two corpora. It does not
establish a confidence bound for ordinary work generally, for other users, or
for future traffic, and it does not measure attack recall at all.

The report and the hook also do not evaluate the same thing. The extractor
joins a result's text blocks with newlines and `bench` scans one string, while
`process` walks the payload and scans each string leaf separately under a
one-second budget rather than the benchmark's thirty. A rule fingerprint does
not capture that difference. Read the number as a firing rate over flattened
result text, not as the frequency with which the hook will advise.

Trimming sample text out of the bundle also means `bench` can no longer verify
reachability at measurement time, and reports `no_examples` for the 206 ATR
rules. The reachability result is checked at build time instead and travels in
each record under `extra.reachability`, per `SAMPLES.md` rule 3.

`SAMPLES.md` rule 5, scanning the built artifact before publishing, has still
never run against this bundle.
