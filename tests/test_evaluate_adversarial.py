"""Regressions established against the original evaluator before changing it."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys

import pytest

from agent_defs import PredicateKind
from agent_defs.evaluate import UnsafePattern, _has_nested_quantifier, scan, screen_pattern
from test_evaluate import rule


@pytest.mark.parametrize("pattern", [
    r"(a|a)*$", r"(a|aa)+$", r"^(a?){1,40}a{40}$", r"^(a?){40}a{40}$",
    r"^((?:a+))+$", "(?x)(a+) # comment\n +$",
    r"^(a|aa)+\1$", r"(?=(a|aa)+$).",
])
def test_screen_rejects_missed_hazards(pattern):
    with pytest.raises(UnsafePattern):
        screen_pattern(pattern)


@pytest.mark.parametrize("pattern", [
    r"^((?:a+))+$", r"^(a?){1,40}a{40}$", r"^(a?){40}a{40}$", "(?x)(a+) # comment\n +$",
])
def test_nested_quantifiers_survive_wrappers_and_verbose_syntax(pattern):
    assert _has_nested_quantifier(pattern)


@pytest.mark.parametrize("pattern", [
    r"(a+)", r"(?i:a+)", r"([]+a])+", "(?x)a # (a+)+\n b",
])
def test_safe_syntax_is_not_a_nested_quantifier(pattern):
    assert not _has_nested_quantifier(pattern)
    screen_pattern(pattern)


@pytest.mark.parametrize("pattern", [
    r"a{99999999999999999999999999}", "(" * 1000 + "a" + ")" * 1000,
])
def test_compiler_failures_are_reported_as_unsafe(pattern):
    with pytest.raises(UnsafePattern):
        screen_pattern(pattern)


@pytest.mark.parametrize("payload,needle,start,end", [
    ("\u0130xTARGET", "target", 2, 8),
    ("\u0131", "i", 0, 1), ("\u017f", "s", 0, 1),
    ("\u03c2", "\u03c3", 0, 1),
])
def test_substrings_follow_regex_case_semantics_with_original_offsets(payload, needle, start, end):
    result = scan(payload, [rule("unicode", PredicateKind.SUBSTRING_ANY, [needle])], budget_s=2)
    assert len(result.findings) == 1
    hit = result.findings[0]
    assert (hit.start, hit.end) == (start, end)


def test_truncation_does_not_delete_surrogates_and_join_text():
    result = scan("a\ud800b" + "x" * 20, [rule("surrogate", PredicateKind.REGEX, "ab")],
                  max_bytes=3, budget_s=2)
    assert result.truncated_input
    assert not result.partial_findings


def test_surrogates_count_towards_the_byte_cap():
    result = scan("\ud800" * 100, [], max_bytes=3)
    assert result.truncated_input


def test_cached_rule_id_cannot_substitute_a_different_predicate():
    cache = {}
    scan("first", [rule("same", PredicateKind.REGEX, "first")], compiled=cache, budget_s=2)
    result = scan("second", [rule("same", PredicateKind.REGEX, "second")], compiled=cache, budget_s=2)
    assert [(hit.start, hit.end) for hit in result.findings] == [(0, 6)]


def test_simple_backreferences_are_explicitly_refused():
    with pytest.raises(UnsafePattern):
        screen_pattern(r"(a)\1")


@pytest.mark.parametrize("predicate", ["(", r"a{9999999999999999999999}"])
def test_bad_rule_does_not_crash_or_prevent_other_findings(predicate):
    result = scan("needle", [rule("bad", PredicateKind.REGEX, predicate),
                             rule("good", PredicateKind.SUBSTRING_ANY, ["needle"])], budget_s=2)
    assert [hit.rule_id for hit in result.partial_findings] == ["good"]
    assert [error.rule_id for error in result.errors] == ["bad"]
    assert not result.complete


@pytest.mark.parametrize("budget", [float("nan"), float("inf"), -1])
def test_invalid_deadline_is_rejected(budget):
    with pytest.raises(ValueError):
        scan("", [], budget_s=budget)


def test_order_is_deterministic_and_cheaper_predicates_go_first():
    rules = [rule("z", PredicateKind.REGEX, "needle"),
             rule("b", PredicateKind.SUBSTRING_ANY, ["needle"]),
             rule("a", PredicateKind.SUBSTRING_ANY, ["needle"])]
    for ordered in (rules, list(reversed(rules))):
        result = scan("needle", ordered, budget_s=2)
        assert [hit.rule_id for hit in result.findings] == ["a", "b", "z"]


def test_large_match_evidence_is_bounded_and_marked():
    payload = "a" * 100000
    result = scan(payload, [rule("large", PredicateKind.REGEX, ".+")], budget_s=2)
    hit = result.findings[0]
    assert (hit.start, hit.end) == (0, len(payload))
    assert not hasattr(hit, "matched")


@pytest.mark.parametrize("pattern", [r"a+b", r"^a+a+$", r"(?=a+b)a", r"^a{0,50000}a{0,50000}$"])
def test_one_pattern_cannot_hold_the_hook_past_its_deadline(pattern):
    # The outer process protects pytest when this test runs against the old code.
    source = '''
import json, time
from agent_defs import Rule, PredicateKind, Surface
from agent_defs.evaluate import scan
r = Rule(id="slow", source="t", source_id="slow", source_rev="0"*40,
         source_path="p", upstream_url="", surface=Surface.OUT,
         predicate_kind=PredicateKind.REGEX, predicate=PATTERN)
started = time.perf_counter()
out = scan("a"*100000 + "!", [r], budget_s=0.15)
print(json.dumps({"elapsed":time.perf_counter()-started,
                  "skipped":out.rules_skipped_budget, "evaluated":out.rules_evaluated}))
'''.replace("PATTERN", repr(pattern))
    try:
        out = subprocess.run([sys.executable, "-c", source], capture_output=True,
                             timeout=3, env=os.environ.copy(), check=True)
    except subprocess.TimeoutExpired:
        pytest.fail("one pattern held scan() for more than 3 seconds with a 150 ms budget")
    result = json.loads(out.stdout)
    assert result["elapsed"] < 1
    assert result["skipped"] == 1
    assert result["evaluated"] == 0


@pytest.mark.parametrize("pattern", [
    r"^([a]+)+$", r"^(a{1,3}){1,20}$", r"([[]+)+$", r"(\[+)+$", r"(\\+)+$",
    r"(?=(a|aa)+$)", "(", "a" * 4097,
])
def test_attacks_the_original_screen_already_stopped(pattern):
    with pytest.raises(UnsafePattern):
        screen_pattern(pattern)


@pytest.mark.parametrize("pattern,payload,expected", [
    ("\u00e9", "e\u0301", False), ("ss", "\u00df", False),
    ("k", "\u212a", True), ("\U0001f600", "\U0001f600", True),
    ("\U0001f600", "\ud83d\ude00", False),
])
def test_regex_unicode_semantics_are_not_silently_normalized(pattern, payload, expected):
    result = scan(payload, [rule("unicode", PredicateKind.REGEX, pattern)], budget_s=2)
    assert bool(result.findings) is expected
