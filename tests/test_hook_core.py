"""The harness-agnostic traversal, tested without going through an adapter.

The point of this module existing is that a second adapter does not copy the
first. These pin the parts a copy would get wrong, and the two injection
contracts, which is what stops a future refactor from quietly making an
adapter's own tests patch something nothing calls.
"""

from dataclasses import replace

import pytest

from agent_defs.hooks import _core
from agent_defs.model import Lane

LIMITS = _core.Limits(max_bytes=1024, max_nodes=64, max_depth=8, budget_s=1.0)


class Finding:
    def __init__(self, rule_id, start=0, end=4):
        self.rule_id, self.start, self.end = rule_id, start, end


class Result:
    def __init__(self, findings=(), *, complete=True, evaluated=1, truncated=False):
        self.partial_findings = list(findings)
        self.complete = complete
        self.rules_evaluated = evaluated
        self.rules_skipped_budget = 0
        self.errors = ()
        self.worker_error = None
        self.truncated_input = truncated


class Rule:
    id = "t:1"


def scanner_for(*findings, **kwargs):
    seen = []

    def scanner(text, rules, **_):
        seen.append(text)
        return Result(findings, **kwargs)
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
    assert scanner.seen == ["text"], "the traversal used something other than the injected scanner"


def test_limits_come_from_the_caller_not_from_this_module():
    scanner = scanner_for()
    run({"a": "abcdefgh"}, scanner, limits=replace(LIMITS, max_bytes=0))
    assert scanner.seen == [], "a zero byte budget still scanned"
    assert run({"a": "abcdefgh"}, scanner, limits=replace(LIMITS, max_bytes=0)).incomplete


def test_an_empty_leaf_is_skipped_but_a_blank_one_is_not():
    scanner = scanner_for()
    run({"stdout": "out", "stderr": ""}, scanner)
    assert scanner.seen == ["out"]
    scanner = scanner_for()
    run({"stdout": " "}, scanner)
    assert scanner.seen == [" "], "a whitespace leaf carries content and must be scanned"


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
    outcome = run({"a": "text"}, scanner_for(evaluated=0))
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


def test_a_non_string_leaf_is_returned_untouched():
    outcome = run({"n": 1, "b": True, "z": None, "f": 1.5}, scanner_for())
    assert outcome.updated == {"n": 1, "b": True, "z": None, "f": 1.5}
    assert not outcome.changed and not outcome.incomplete
