"""The traversal after collect/scan/materialize, at the seam a harness uses.

Three things moved and each has a way of failing quietly. One worker now serves
a whole event, so a test that counts processes is the headline regression check.
The answer is put back through a skeleton rather than by walking the payload
again, because a second bounded walk would re-read a budget the scan has just
spent and drop redactions in silence. And a leaf nothing reached is now named in
the log, where before a four-leaf payload of ordinary text produced one record
and a reader could not tell two unscanned leaves from none.
"""

from dataclasses import replace
import hashlib
import time

import pytest

from agent_defs import PredicateKind
import agent_defs.evaluate as evaluate
from agent_defs.evaluate import BatchScanResult, Finding, LeafScanResult
from agent_defs.hooks import _core
from agent_defs.model import Lane
from test_evaluate import rule

LIMITS = _core.Limits(max_bytes=1 << 20, max_nodes=4096, max_depth=64, budget_s=10.0)
ANY = rule("t:any", PredicateKind.REGEX, ".+")


def run(value, rules=(ANY,), *, lane=Lane.RECORD, surface="OUT", limits=LIMITS, scanner=None,
        event="PostToolUse"):
    options = {} if scanner is None else {"scanner": scanner}
    return _core.scan_payload(value, rules=list(rules),
                              lanes={r.id: (lane, "fixture") for r in rules},
                              surface=surface, event=event, limits=limits,
                              location="/tool_response", **options)


def record(outcome, status):
    return next((r for r in outcome.records if r.get("status") == status), None)


def counting_popen(monkeypatch):
    children = []
    real = evaluate.subprocess.Popen

    def capture(*args, **kwargs):
        proc = real(*args, **kwargs)
        children.append(proc)
        return proc

    monkeypatch.setattr(evaluate.subprocess, "Popen", capture)
    return children


def batch_of(leaves, findings_for=lambda index: (), **kwargs):
    """A complete batch over every offered leaf, with per-leaf findings."""
    rules_scheduled = kwargs.pop("rules_scheduled", 1)
    per_leaf = tuple(LeafScanResult(findings_for(index), rules_scheduled, False, True)
                     for index in range(len(leaves)))
    fields = dict(leaves=per_leaf, leaves_offered=len(leaves), leaves_scheduled=len(leaves),
                  rules_scheduled=rules_scheduled,
                  pairs_scheduled=rules_scheduled * len(leaves),
                  pairs_resolved=rules_scheduled * len(leaves), pairs_rejected=0, elapsed_s=0.0)
    fields.update(kwargs)
    return BatchScanResult(**fields)


def test_exactly_one_worker_per_event(monkeypatch):
    """The headline: a nine-leaf tool result costs one process, not nine."""
    children = counting_popen(monkeypatch)
    payload = {"stdout": "a", "stderr": "b",
               "structuredPatch": [{"lines": ["c", "d", "e"]}, {"lines": ["f", "g"]}],
               "meta": {"path": "h", "mode": "i"}}
    outcome = run(payload)
    assert len(children) == 1, f"one event launched {len(children)} workers"
    assert not outcome.incomplete
    assert sum(1 for r in outcome.records if "rule_id" in r) == 9, "a leaf went unscanned"


def test_the_event_budget_is_not_multiplied_by_the_leaf_count(monkeypatch):
    """Fifty leaves, one call, one budget, and one deadline's worth of waiting."""
    calls = []

    def scanner(leaves, rules, **kwargs):
        calls.append((len(leaves), kwargs["budget_s"]))
        return batch_of(leaves)

    outcome = run(["leaf %d" % index for index in range(50)], scanner=scanner,
                  limits=replace(LIMITS, budget_s=0.3))
    assert len(calls) == 1 and calls[0][0] == 50
    assert 0 < calls[0][1] <= 0.3, "the scanner got other than the remaining event budget"
    assert not outcome.incomplete

    real = evaluate.subprocess.Popen
    monkeypatch.setattr(evaluate.subprocess, "Popen", lambda command, **kwargs: real(
        [command[0], "-I", "-S", "-c", "import time; time.sleep(30)"], **kwargs))
    started = time.perf_counter()
    hung = run(["leaf %d" % index for index in range(50)], limits=replace(LIMITS, budget_s=0.3))
    elapsed = time.perf_counter() - started
    assert hung.incomplete
    assert elapsed < 3, f"a hung worker cost {elapsed:.2f}s, near 50 deadlines rather than one"


@pytest.mark.parametrize("state", ["zero_bytes", "spent_budget", "no_string_leaves"])
def test_no_scanner_call_when_there_is_nothing_to_scan(state):
    """Three ways to have nothing to hand over, and only two of them are gaps.

    A payload of numbers is not a coverage gap: nothing was skipped, so the
    outcome stays complete, which ``test_a_non_string_leaf_is_returned_untouched``
    in ``test_hook_core.py`` pins from the other side. A zero allowance and a
    spent budget are gaps, and both say so.
    """
    seen = []

    def scanner(leaves, rules, **kwargs):
        seen.append(list(leaves))
        return batch_of(leaves)

    if state == "zero_bytes":
        outcome = run({"a": "text"}, scanner=scanner, limits=replace(LIMITS, max_bytes=0))
    elif state == "spent_budget":
        outcome = run({"a": "text"}, scanner=scanner, limits=replace(LIMITS, budget_s=0.0))
    else:
        outcome = run({"n": 1, "b": True, "z": None, "f": 1.5}, scanner=scanner)
    assert seen == [], "the traversal scanned when it had nothing to scan"
    assert outcome.incomplete == (state != "no_string_leaves")


def test_a_non_runnable_rule_does_not_make_every_scan_incomplete():
    """A NONE rule is not scheduled work, and comparing to ``len(rules)`` said it was.

    The traversal used to read ``rules_evaluated != len(rules)``, which is wrong
    for any rule the scan never schedules. It was safe only because the adapter
    filters on ``runnable`` before this sees the list, and the second adapter
    this module exists for would not have.
    """
    reference = replace(rule("t:none", PredicateKind.REGEX, "x"),
                        predicate_kind=PredicateKind.NONE, predicate=None,
                        not_runnable_reason="reference only")
    outcome = run({"a": "text"}, rules=(ANY, reference))
    assert not outcome.incomplete
    assert record(outcome, "scan_incomplete") is None
    assert sum(1 for r in outcome.records if "rule_id" in r) == 1


def test_a_rule_that_vanishes_before_the_schedule_is_incomplete():
    """A runnable rule the wire refused is coverage the caller asked for and lost."""
    broken = rule("t:broken", PredicateKind.SUBSTRING_ANY, "not a list")
    outcome = run({"a": "text"}, rules=(ANY, broken))
    assert outcome.incomplete
    coverage = record(outcome, "scan_coverage")
    assert coverage["rules_expected"] == 2
    assert coverage["rules_scheduled"] == 1
    assert coverage["rejected_rules"] == ["t:broken"]


def test_withholding_lands_on_the_matched_leaf_only():
    """A DENY on one leaf replaces that leaf, and no sentinel survives the pass."""
    payload = {"a": "ordinary", "b": "ordinary", "c": "MATCH me", "d": "ordinary"}
    deny = rule("t:deny", PredicateKind.REGEX, "MATCH")
    outcome = run(payload, rules=(deny,), lane=Lane.DENY)
    assert outcome.updated == {"a": "ordinary", "b": "ordinary", "c": _core.WITHHELD,
                               "d": "ordinary"}
    assert outcome.changed and Lane.DENY in outcome.lanes_fired
    assert not any(isinstance(v, (_core._LeafRef, _core._Kept))
                   for v in outcome.updated.values())


def test_a_clean_batch_rebuilds_an_equal_payload():
    payload = {"z": "one", "a": [1, "two", None], "m": {"n": True, "o": 1.5}, "e": ""}
    outcome = run(payload, rules=(rule("t:no", PredicateKind.REGEX, "ABSENT"),))
    assert not outcome.incomplete and not outcome.changed
    assert outcome.updated == payload
    assert list(outcome.updated) == list(payload), "dict key order was not preserved"
    assert outcome.updated["a"][0] is payload["a"][0]

    # The documented quirk: ``json.loads`` accepts the nonstandard ``NaN``
    # token, and a NaN compares unequal to itself, so such a payload reports
    # changed with nothing redacted. It surfaces where the comparison reaches
    # the float directly; inside a container, dict and list equality take an
    # identity shortcut first and the quirk stays hidden. Both readings are
    # unchanged from the per-leaf traversal.
    quiet = run({"x": float("nan")}, rules=(rule("t:no", PredicateKind.REGEX, "ABSENT"),))
    assert not quiet.changed
    loud = run(float("nan"), rules=(rule("t:no", PredicateKind.REGEX, "ABSENT"),))
    assert loud.changed, "the documented NaN inequality quirk changed"


def test_a_scan_that_consumes_the_budget_still_materializes_redactions(monkeypatch):
    """The trap a second bounded walk would have set.

    The clock jumps past the budget while the scanner runs. A materialize pass
    that re-checked the budget would stop and hand back the attacker's text with
    the redaction silently dropped.
    """
    now = [0.0]
    monkeypatch.setattr(_core.time, "perf_counter", lambda: now[0])
    finding = Finding("t:deny", "OUT", 0, 5)

    def scanner(leaves, rules, **kwargs):
        now[0] += 99.0
        return batch_of(leaves, findings_for=lambda index: (finding,) if index == 1 else ())

    outcome = run({"a": "keep", "b": "MATCH"}, rules=(rule("t:deny", PredicateKind.REGEX, "M"),),
                  lane=Lane.DENY, scanner=scanner)
    assert now[0] >= LIMITS.budget_s, "the fixture did not spend the budget"
    assert outcome.updated == {"a": "keep", "b": _core.WITHHELD}


def test_one_event_writes_a_digest_for_one_leaf_and_not_the_other():
    """Per-leaf truncation, which one request-level flag could not answer."""
    outcome = run(["abcd", "efgh"], limits=replace(LIMITS, max_bytes=6))
    findings = [r for r in outcome.records if "rule_id" in r]
    assert [r["truncated"] for r in findings] == [False, True]
    assert findings[0]["text_sha256"] == hashlib.sha256(b"abcd").hexdigest()
    assert findings[1]["text_sha256"] is None
    assert outcome.incomplete


def test_every_declined_leaf_is_named():
    """Four ordinary leaves, two scanned, and the other two named rather than absent."""
    outcome = run(["abcd", "efgh", "ijkl", "mnop"], limits=replace(LIMITS, max_bytes=8))
    coverage = record(outcome, "scan_coverage")
    assert (coverage["leaves_offered"], coverage["leaves_scheduled"],
            coverage["leaves_declined"]) == (4, 2, 2)
    assert coverage["declined_paths"] == ["/tool_response/2", "/tool_response/3"]
    assert coverage["paths_elided"] is False
    covered = run(["abcd", "efgh"])
    assert not covered.incomplete
    assert record(covered, "scan_coverage") is None, "a covered event wrote a coverage record"


def test_an_empty_leaf_is_not_reported_as_unscanned():
    """An empty leaf carries no attack text, so it is skipped and counted apart."""
    outcome = run({"stdout": "abcd", "stderr": "", "extra": "", "tail": "efgh"},
                  limits=replace(LIMITS, max_bytes=4))
    coverage = record(outcome, "scan_coverage")
    assert coverage["leaves_empty"] == 2
    assert coverage["leaves_seen"] == 2
    assert coverage["leaves_offered"] == 2
    assert coverage["leaves_declined"] == 1
    assert coverage["declined_paths"] == ["/tool_response/tail"]


def test_the_coverage_record_closes():
    """Every count in the record is recoverable from the others."""
    outcome = run(["abcd", "efgh", "ijkl"], rules=(ANY, rule("t:2", PredicateKind.REGEX, "z")),
                  limits=replace(LIMITS, max_bytes=8))
    coverage = record(outcome, "scan_coverage")
    assert coverage["leaves_offered"] == coverage["leaves_scheduled"] + coverage["leaves_declined"]
    assert coverage["pairs_scheduled"] == coverage["rules_scheduled"] * coverage["leaves_scheduled"]
    assert coverage["pairs_resolved"] == coverage["rules_swept"] * coverage["leaves_scheduled"]
    # What a reader recovers per leaf: how many rules checked each scheduled one.
    assert coverage["rules_swept"] - len(coverage["rejected_rules"]) == 2
    assert coverage["worker_failed"] is False


def test_the_path_list_is_bounded_and_says_so():
    """A log line a person reads, with the counts beside it still exact."""
    leaves = ["abcdefgh"] * (_core._MAX_LOGGED_PATHS + 20)
    outcome = run(leaves, limits=replace(LIMITS, max_bytes=8))
    coverage = record(outcome, "scan_coverage")
    assert coverage["leaves_declined"] == len(leaves) - 1
    assert len(coverage["declined_paths"]) == _core._MAX_LOGGED_PATHS
    assert coverage["paths_elided"] is True


@pytest.mark.parametrize("fault", ["declined", "worker", "scan_error"])
def test_the_terminal_incomplete_record_survives(fault):
    """The line the adapter tests grep for, still last and still spelled the same."""
    if fault == "declined":
        outcome = run(["abcd", "efgh"], limits=replace(LIMITS, max_bytes=4))
    elif fault == "worker":
        outcome = run(["abcd"], scanner=lambda leaves, rules, **kw: batch_of(
            leaves, worker_error="crash"))
    else:
        def explode(leaves, rules, **kwargs):
            raise MemoryError("worker died")

        outcome = run(["abcd"], scanner=explode)
    assert outcome.incomplete
    assert outcome.records[-1] == {"event": "PostToolUse", "status": "scan_incomplete"}
    assert record(outcome, "scan_coverage") is not None


@pytest.mark.parametrize("state", ["worker_error", "already_withheld"])
def test_a_last_writer_keeps_another_hooks_redaction_through_the_batch_seam(tmp_path, monkeypatch,
                                                                           state):
    """The parallel-hook property, re-pinned where the fault now has to be injected.

    ``test_parallel_last_writer_keeps_other_redaction_when_we_changed_nothing``
    in ``test_claude_hook_failures.py`` injects these two faults into
    ``hook.scan``, which the adapter no longer calls. Both of its cases still
    pass there, but for a reason unrelated to the fault: the real scan runs and
    finds nothing. This asserts the same property through the seam the adapter
    uses, so the two states are covered by something that would notice.
    """
    from agent_defs.builtin import STARTER_RULES
    from agent_defs.hooks import _claude_code_impl as hook
    from test_claude_hook_failures import evidence

    config = hook.default_config()
    config["log_path"] = str(tmp_path / "findings.jsonl")
    config["sources"]["builtin"] = "DENY"
    starter = STARTER_RULES[0]
    # Asking for DENY does not grant it. Without a benign measurement
    # effective_lanes returns RECORD for "no benign measurement", nothing is
    # admitted to withhold, and the assertions below then hold for a reason
    # unrelated to the last-writer safeguard they exist to pin. The first
    # version of this replacement did exactly that.
    evidence(config, [starter])
    admitted, why = hook.effective_lanes(config, [starter])[starter.id]
    assert admitted is Lane.DENY, f"the fault needs an admitted DENY, got {admitted}: {why}"
    original = {"content": "ordinary", "other": "keep"}
    calls = []

    def scanner(leaves, rules, **kwargs):
        calls.append(list(leaves))
        if state == "worker_error":
            return batch_of(leaves, worker_error="failed")
        return batch_of(leaves, findings_for=lambda index: (
            (Finding(starter.id, "OUT", 0, 1),) if index == 0 else ()),
            rules_scheduled=len(rules))

    if state == "already_withheld":
        original = {"content": hook.WITHHELD}
    monkeypatch.setattr(hook, "scan_leaves", scanner)
    response = hook.process({"hook_event_name": "PostToolUse", "tool_response": original},
                            config, [starter])
    assert calls, "the injected batch scanner was not the one that ran"
    assert "updatedToolOutput" not in response.get("hookSpecificOutput", {})
    other_redaction = {"content": "REDACTED_BY_OTHER"}
    final = response.get("hookSpecificOutput", {}).get("updatedToolOutput", other_redaction)
    assert final == other_redaction
    if state == "worker_error":
        # Name the fault rather than only its absence of a rewrite, so the case
        # cannot pass by producing nothing at all.
        assert response.get("hookSpecificOutput", {}).get("additionalContext") == hook.INCOMPLETE


def test_a_single_payload_result_is_type_rejected_rather_than_read_as_a_batch():
    """The retired contract fails closed instead of being read for its first field."""
    outcome = run(["abcd"], scanner=lambda leaves, rules, **kw: evaluate.ScanResult(
        (), 1, 0, 0.0, False))
    assert outcome.incomplete
    assert record(outcome, "scan_error")["kind"] == "AttributeError"
    assert outcome.updated == ["abcd"]
