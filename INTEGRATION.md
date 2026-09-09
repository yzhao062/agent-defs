# Integration State

## Five-way repair integration, 2026-09-04

The r1, r3, r4 and r5 branches are merged with the already-integrated r2 work.
The Windows Miniforge py312 suite now has **458 passing, 5 skipped, and no failing
tests**, compared with 270 passing and two failing tests at the start of this
integration. The five skips require the six real corpora and their pinned archives;
fixture tests do not replace that release gate. All worker test functions remain
present. The nine interface disagreements listed below are historical and resolved.

The hook retains r3's additive installer, exit-zero launcher, measured decisions,
depth guard and strict evaluated-rule count. It also retains r2's bounded stdin,
4 MiB text allowance, metadata-only partial findings, bounded byte accounting,
null hashes for truncated values, and model-visible incomplete-coverage warnings.
The event budget is defined once as `SCAN_BUDGET_S = 1.0`; the standalone evaluator
still defaults to 250 ms. This selects r3's startup allowance over r2's shorter
hook deadline. It does not promise that the enabled bundle will finish, and r1
measured unfinished work on a 28 KB Gmail result even at a 30-second budget. The
traversal has changed since this section was written. One worker per event replaced
one worker per string value in `45e6689` on 2026-09-07, after 32.67% of measured
tool results returned an incomplete scan under the old shape. The 2026-09-08
remeasurement then completed all 21,442 `OUT` trials with no truncation and no
budget-skipped pair. Those samples carried one string value each and reached
12,240 bytes at most. Events near the 45 to 55 KB per-event capacity that motivated
the change are still unmeasured. Timeout can request approval only for
already-admitted PreToolUse DENY protection.

r4's flat regex conjunctions run as independent searches under r2's isolation and
completeness contract. r1's isolated traffic measurements retain their diagnostics
and reject incomplete coverage. r5's restrictions, path exclusions and payload-source
lineage survive normalization. The checked-in corpus census and distribution audit
remain the workers' measurements; they were not rerun on full corpora here.

One release workflow incompatibility remains: `scripts/audit_distribution.py`
requires ATR `data/test-corpora/` members on disk, while `sources.fetch()` deliberately
never extracts that directory. A safely fetched cache cannot satisfy that audit.
The gate must inspect excluded members in archive memory before it can be run on
such a cache. No exclusion was relaxed and no sample directory was extracted.

## Historical state before the repair units

Seven units built this package in parallel on 2026-09-04, each in its own clone off the same base
commit. Merging them is done; reconciling where two of them disagree is not. **The suite is 230
passing and 9 failing**, and every failure is a place where two units made different, defensible calls
about the same interface. None is a bug in the sense of a slip; each needs a decision.

Run it with `PYTHONPATH=src python -m pytest tests -q` from the repository root.

## What was already reconciled

**`evaluate.py`: b5 wins outright.** b2 changed one line of the original screen; b5 rewrote the module
after writing 37 adversarial tests that all failed against the version written that afternoon. The
one-line fix is inside code b5 replaced.

**Bulk measurement gets its own entry point.** b5 puts every match in a worker process, because the
payload is attacker-controlled and a backtracking pattern cannot be interrupted once it starts. That
is one process launch per call, which is right for a hook running once per tool call and fatal for a
benchmark scanning 842 files: the suite hung. `scan_trusted()` now does the same matching in this
process, with no isolation and no deadline, documented for offline measurement over material the
caller controls and never reachable from a hook. `bench.py` uses it. This is a security boundary
rather than a performance switch, which is why it is a separate function with its own warning instead
of a keyword argument.

**`pyproject.toml`:** b4's three source extras and b6's `claude-code` extra both kept.
**`loaders/__init__.py`:** three units wrote near-identical docstrings; b4's kept.

## The nine that are still open

| Test | The disagreement | Who should probably win |
|---|---|---|
| `test_atr.py::test_screening_disables_the_entire_rule_and_lists_every_rejection` | b5's screen rejects patterns b2's rejection list did not expect | b5 on the screen, b2 re-runs its audit against it |
| `test_atr.py::test_conjunction_and_backreferences_keep_their_meaning` | b2 ports a conjunction to a predicate shape b5's evaluator no longer accepts | needs a call: either b5 accepts the shape or b2 emits `predicate_kind=NONE` and counts it |
| `test_bench.py::test_incomplete_evaluation_aborts_instead_of_reporting_zero` | `scan_trusted` cannot report skipped rules, so the abort path it tests no longer exists | b7's intent is right and its mechanism must move to `errors` and `rules_evaluated` |
| `test_claude_code_hook.py` (4 tests) | b6 built the response against the original `ScanResult`; `KeyError: 'hookSpecificOutput'` and `KeyError: 'lane'` say the hook now falls open where it used to decide | b6's protocol is verified against the live harness, so adapt its reader to b5's result shape |
| `test_evaluate.py::test_findings_carry_the_span_so_a_person_can_see_why` | the original span test against b5's capped match text | b5, and the test should assert the cap rather than the raw span |
| `test_json_loaders.py::test_reachability_uses_each_rules_own_examples` | b4's reachability calls a `bench` attribute that b7 named differently | b7 owns the name; b4 adapts |

Two of these are more than renames. The conjunction case decides whether the evaluator grows a
construct or the loader reports a loss, and that choice belongs to the same rule that says never widen
a condition to make it runnable. The hook case decides what a hook does when a scan comes back
incomplete, and "fall open silently" is the answer the red team already flagged as wrong.

## The red-team findings, and which of them this round closed

The red team returned 30 findings, 9 critical, recorded in the research repository under
`research/build-2026-09-04/wf-redteam.md`. Four of the five that blocked any use by another person are
now closed by the repair units, and the remaining one is the product's open question rather than a
defect.

| Finding | State |
|---|---|
| `admit()` returns `RECORD` for every rule under our own measurement | **still open, and now measured.** `r1` ran 306 runnable `OUT` rules over 8,198 real tool results and got 306 `RECORD`, 90 `DO_NOT_SHIP`, zero promotions. The gate is right; the evidence that would open it does not exist yet, because every stratum is smaller than the 598 clean trials a 0.5% claim needs |
| The measured surface and the defended surface are disjoint | **closed by `r1`.** The measurement now runs on real tool output rather than configuration material |
| `Finding.matched` copies attacker text into a channel that reaches the model | **closed by `r2`.** Findings are metadata only: rule id, span, and a digest that is null when the value was truncated. There is no payload-bearing field left to shorten |
| The installer must be proven not to remove hooks already there | **closed by `r3`**, against temporary copies of the real `guard.py` settings rather than a stand-in |
| `Rule.lane` is never bound to `admit()` | **closed by `r3`**, in the path the hook actually runs |

Two things this round did not close, both recorded because they are easy to lose:

**A release-workflow incompatibility, created by a safety guard.** `scripts/audit_distribution.py`
requires ATR's `data/test-corpora/` members on disk, and `sources.fetch()` deliberately never extracts
them. A safely fetched cache therefore cannot pass the release gate. The audit needs to read excluded
members from archive memory. `m1` left this explicit rather than relaxing the exclusion, which was the
right call: no sample directory was extracted and no exclusion was weakened to make a suite look
complete.

**The hook budget is unresolved rather than chosen.** `SCAN_BUDGET_S` is 1.0 second, taking `r3`'s
startup allowance over `r2`'s 250 ms, and that is not evidence the bundle completes. `r1` measured 132
of 306 rules finishing at 250 ms and 257 of 306 at 30 seconds on one 28 KB Gmail result. The latency
and coverage decision is a product question with no measured answer.

ATR ships only once its third-party notices exist, which they now do, and the 25 AgentHarm records are
marked `restricted` and excluded from the default bundle. See `THIRD-PARTY-NOTICES` and the research
repository's rights record.

## What an audit of the round found, 2026-09-04

Twenty agents audited the repair claims against their own evidence. Full record in the research
repository at `research/measure-2026-09-04/wf-audit.md`. Three results belong here.

**Verified against the real machine, not a stand-in.** `r3`'s installer preserves an existing
`settings.json` byte for byte, requires explicit confirmation, backs up, and contains interpreter
failure behind an exit-zero boundary. The auditor ran the exact command string `hook_spec()` writes,
against a copy of the real `guard.py` wiring. These hold.

**`r2`'s headline does not hold at the hook.** Content past the old 256 KiB cap is scanned within a
bounded window, but the operative limit through the hook is 1 MiB rather than 4 MiB. Padding a hostile
page out of the scan became four times more expensive rather than impossible. The completeness and
containment properties, which were the other two thirds of that unit, did hold.

**Nothing measured is what would run.** `hooks/_claude_code_impl.py` defaults to
`builtin.STARTER_RULES`, four hand-written rules, and no code path loads the 306 measured `OUT` rules
into a hook. Every number the measurement round produced describes a bundle this package cannot
currently assemble at runtime. **This is the first thing to fix**, ahead of any further measurement,
because until it is closed the measurement and the product are separate artifacts sharing a
repository.

Two audit findings were stale on arrival, because the audit ran while this integration was still
going. The four unmerged branches are merged, and the claim that 36 of `r3`'s 76 regressions fail on
the merged tree does not reproduce: the three `r3` suites report 146 passing and none failing here.
