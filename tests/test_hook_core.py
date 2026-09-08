"""The harness-agnostic traversal, tested without going through an adapter.

The point of this module existing is that a second adapter does not copy the
first. These pin the parts a copy would get wrong, and the two injection
contracts, which is what stops a future refactor from quietly making an
adapter's own tests patch something nothing calls.
"""

from dataclasses import replace

import pytest

from agent_defs.evaluate import BatchScanResult, LeafScanResult
from agent_defs.hooks import _core
from agent_defs.model import Lane

LIMITS = _core.Limits(max_bytes=1024, max_nodes=64, max_depth=8, budget_s=1.0)


class Finding:
    def __init__(self, rule_id, start=0, end=4):
        self.rule_id, self.start, self.end = rule_id, start, end


class Leaf:
    """One leaf's share of a batch, in the shape ``_core`` reads."""

    def __init__(self, findings=(), *, evaluated=1, truncated=False, scheduled=True):
        self.partial_findings = list(findings)
        self.rules_evaluated = evaluated
        self.truncated_input = truncated
        self.scheduled = scheduled


class Batch:
    """A batch result, injected in place of one.

    ``complete`` is settable independently of the pair counts, because the
    verdict a caller acts on and the accounting it logs are two claims and a
    fake that derived one from the other could not express a worker that
    terminated fewer rows than it scheduled.
    """

    def __init__(self, count, findings=(), *, complete=True, evaluated=1, truncated=False,
                 rules_scheduled=1):
        self.leaves = [Leaf(findings, evaluated=evaluated, truncated=truncated)
                       for _ in range(count)]
        self.complete = complete
        self.leaves_offered = count
        self.leaves_scheduled = count
        self.rules_scheduled = rules_scheduled
        self.pairs_scheduled = rules_scheduled * count
        self.pairs_resolved = self.pairs_scheduled
        self.pairs_rejected = 0
        self.rows_terminated = rules_scheduled
        self.errors = ()
        self.worker_error = None


class Rule:
    id = "t:1"
    runnable = True


def scanner_for(*findings, **kwargs):
    seen = []

    def scanner(leaves, rules, **_):
        # The whole event's leaves per call, so an assertion on ``seen`` pins
        # both which text was scanned and that it took exactly one scan.
        seen.append(list(leaves))
        return Batch(len(leaves), findings, **kwargs)
    scanner.seen = seen
    return scanner


def run(value, scanner, lanes=None, surface="OUT", limits=LIMITS):
    return _core.scan_payload(
        value, rules=[Rule()], lanes=lanes or {"t:1": (Lane.RECORD, "why")},
        surface=surface, event="PostToolUse", limits=limits, location="/x",
        scanner=scanner)


def test_the_injected_scanner_is_the_one_that_runs():
    """The contract 61 adapter tests failed on when this defaulted silently."""
    scanner = scanner_for()
    run({"a": "text"}, scanner)
    assert scanner.seen == [["text"]], "the traversal used something other than the injected scanner"


def test_limits_come_from_the_caller_not_from_this_module():
    scanner = scanner_for()
    run({"a": "abcdefgh"}, scanner, limits=replace(LIMITS, max_bytes=0))
    assert scanner.seen == [], "a zero byte budget still scanned"
    assert run({"a": "abcdefgh"}, scanner, limits=replace(LIMITS, max_bytes=0)).incomplete


def test_an_empty_leaf_is_skipped_but_a_blank_one_is_not():
    scanner = scanner_for()
    run({"stdout": "out", "stderr": ""}, scanner)
    assert scanner.seen == [["out"]]
    scanner = scanner_for()
    run({"stdout": " "}, scanner)
    assert scanner.seen == [[" "]], "a whitespace leaf carries content and must be scanned"


def test_deny_withholds_the_whole_leaf_on_out_and_nothing_on_in():
    lanes = {"t:1": (Lane.DENY, "measured")}
    out = run({"a": "attack text here"}, scanner_for(Finding("t:1")), lanes)
    assert out.updated == {"a": _core.WITHHELD}
    assert out.changed and Lane.DENY in out.lanes_fired

    inbound = run({"a": "attack text here"}, scanner_for(Finding("t:1")), lanes, surface="IN")
    assert inbound.updated == {"a": "attack text here"}, "IN has nothing to redact"
    assert not inbound.changed and Lane.DENY in inbound.lanes_fired


def test_a_scanner_that_raises_is_recorded_as_incomplete_rather_than_clean():
    def explode(*args, **kwargs):
        raise MemoryError("worker died")

    outcome = run({"a": "text"}, explode)
    assert outcome.incomplete
    assert outcome.updated == {"a": "text"}
    kinds = [r.get("kind") for r in outcome.records if r.get("status") == "scan_error"]
    assert kinds == ["MemoryError"]
    assert not outcome.lanes_fired


def test_an_evaluated_count_below_the_rule_count_is_incomplete():
    """Short coverage is short pairs now, and the arithmetic decides it.

    A real ``BatchScanResult`` rather than a fake, so nothing here can set
    ``complete`` by hand: one rule scheduled over one leaf and no pair resolved
    is the state a worker killed mid-row reports, and it must not be clean.
    """
    seen = []

    def scanner(leaves, rules, **_):
        seen.append(list(leaves))
        return BatchScanResult(
            leaves=tuple(LeafScanResult((), 0, False, True) for _ in leaves),
            leaves_offered=len(leaves), leaves_scheduled=len(leaves), rules_scheduled=1,
            pairs_scheduled=len(leaves), pairs_resolved=0, pairs_rejected=0, elapsed_s=0.0)

    outcome = run({"a": "text"}, scanner)
    assert seen == [["text"]], "the injected batch scanner was not the one that ran"
    assert outcome.incomplete
    assert any(r.get("status") == "scan_incomplete" for r in outcome.records)


def test_a_truncated_scan_does_not_hash_the_value():
    outcome = run({"a": "text"}, scanner_for(Finding("t:1"), truncated=True))
    finding = next(r for r in outcome.records if r.get("rule_id") == "t:1")
    assert finding["text_sha256"] is None and finding["truncated"] is True


def test_paths_are_json_pointers_with_the_awkward_characters_escaped():
    scanner = scanner_for(Finding("t:1"))
    outcome = run({"a/b": ["x"], "c~d": "y"}, scanner)
    paths = {r["path"] for r in outcome.records if "path" in r}
    assert paths == {"/x/a~1b/0", "/x/c~0d"}


@pytest.mark.parametrize("limit,field", [(0, "max_nodes"), (0, "max_depth"), (0.0, "budget_s")])
def test_every_budget_stops_the_walk_and_says_so(limit, field):
    scanner = scanner_for()
    outcome = run({"a": {"b": "text"}}, scanner, limits=replace(LIMITS, **{field: limit}))
    assert outcome.incomplete
    assert outcome.updated == {"a": {"b": "text"}}
    # Without this the test passes on a walk that sets `incomplete` and then
    # keeps scanning: a clean scanner leaves the payload unchanged either way.
    assert scanner.seen == [], "the walk continued past its own limit"


def test_a_non_string_leaf_is_returned_untouched():
    outcome = run({"n": 1, "b": True, "z": None, "f": 1.5}, scanner_for())
    assert outcome.updated == {"n": 1, "b": True, "z": None, "f": 1.5}
    assert not outcome.changed and not outcome.incomplete
