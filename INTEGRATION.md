# Integration State

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

## Not yet done at all

The red team returned 30 findings, 9 critical, recorded in the research repository under
`research/build-2026-09-04/wf-redteam.md`. None is fixed here. The ones that block any use by another
person:

1. `admit()` returns `RECORD` for every rule under our own measurement, so no rule can reach an
   interrupting lane. The gate is right; the measurement that would open it does not exist.
2. The benign corpus is configuration material while 515 of ATR's rules sit on tool output. The
   measured surface and the defended surface are disjoint.
3. `Finding.matched` copies attacker-controlled text, and the channel that reports it reaches the
   model. b5 capped the copy at 512 characters, which shortens the channel without closing it.
4. The installer merges into `~/.claude/settings.json` and must be proven not to remove hooks that are
   already there, against a settings file carrying a real one.
5. `Rule.lane` is never bound to `admit()`, so lane discipline is currently advisory.

ATR is also held out of any release until the third-party notices exist and the 25 AgentHarm rules are
decided. See the research repository's rights record.
