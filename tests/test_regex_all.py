from dataclasses import replace
import time

import pytest

from agent_defs import PredicateKind
from agent_defs import evaluate
from test_evaluate import rule


def conjunction(patterns, **kwargs):
    return rule("all", PredicateKind.STRUCTURED, {"regex_all": patterns}, **kwargs)


@pytest.mark.parametrize("scan", [evaluate.scan, evaluate.scan_trusted])
def test_regex_all_preserves_independent_searches_and_first_witness(scan):
    r = conjunction([r"(?m)^alpha$", r"(?P<label>beta)"])
    for text, expected in (("ALPHA", False), ("beta", False), ("beta\nALPHA", True),
                           ("ALPHA\nbeta", True), ("prefix ALPHA\nbeta", False)):
        out = scan(text, [r])
        assert out.complete and out.rules_evaluated == 1
        assert bool(out.findings) is expected
        if expected:
            f = out.findings[0]
            assert text[f.start:f.end] == "ALPHA"
            assert not hasattr(f, "matched")
    assert not scan("ALPHA\nbeta", [replace(r, case_sensitive=True)]).findings


def test_regex_all_screens_each_original_leaf_with_the_rule_case_mode(monkeypatch):
    screened = []
    original = evaluate.screen_pattern

    def screen(pattern, flags):
        screened.append((pattern, flags))
        original(pattern, flags)

    monkeypatch.setattr(evaluate, "screen_pattern", screen)
    patterns = [r"(?P<same>alpha)", r"(?P<same>beta)"]
    runtime = evaluate.compile_rule(conjunction(patterns, case_sensitive=True))
    assert screened == [(p, 0) for p in patterns]
    assert runtime.search("beta alpha")


@pytest.mark.parametrize("scan", [evaluate.scan, evaluate.scan_trusted])
def test_regex_all_keeps_conjunction_across_the_old_input_cap(scan):
    text = "FIRST" + "x" * 300_000 + "LAST"
    options = {"budget_s": 2} if scan is evaluate.scan else {}
    result = scan(text, [conjunction([r"\AFIRST", r"LAST\Z"])], **options)
    assert result.complete and result.rules_evaluated == 1
    assert [(f.start, f.end) for f in result.findings] == [(0, 5)]
    assert not hasattr(result.findings[0], "matched")


@pytest.mark.parametrize("scan", [evaluate.scan, evaluate.scan_trusted])
@pytest.mark.parametrize("pattern", [r"(a+)+$", r"(a)\1", "["])
def test_regex_all_rejects_unsafe_leaves_even_after_a_missing_leaf(scan, pattern):
    result = scan("plain text", [conjunction(["absent", pattern])])
    assert not result.complete and not result.partial_findings
    with pytest.raises(evaluate.IncompleteScanError):
        result.findings
    assert result.rules_evaluated == 0
    assert [e.rule_id for e in result.errors] == ["all"]


@pytest.mark.parametrize("scan", [evaluate.scan, evaluate.scan_trusted])
@pytest.mark.parametrize("predicate", [
    {}, {"all": ["a", "b"]}, {"regex_all": []}, {"regex_all": "ab"},
    {"regex_all": ["a", None]}, {"regex_all": ["a"] * 65},
    {"regex_all": ["a" * 4097]}, {"regex_all": ["a"], "ignore": True},
])
def test_regex_all_rejects_malformed_or_oversized_conditions(scan, predicate):
    result = scan("ab", [rule("all", PredicateKind.STRUCTURED, predicate)])
    assert not result.complete and not result.partial_findings
    with pytest.raises(evaluate.IncompleteScanError):
        result.findings
    assert result.rules_evaluated == 0 and len(result.errors) == 1


def test_regex_all_cannot_bypass_bundle_character_limit():
    r = conjunction(["a" * 4096] * 64)
    result = evaluate.scan("a", [replace(r, id=str(i)) for i in range(5)])
    assert not result.complete and "predicate characters" in result.worker_error


def test_regex_all_matching_stays_inside_the_scan_deadline():
    start = time.perf_counter()
    result = evaluate.scan("a" * 200_000 + "!", [conjunction(["a", "a+b"])], budget_s=0.15)
    assert not result.complete and not result.partial_findings
    with pytest.raises(evaluate.IncompleteScanError):
        result.findings
    assert result.rules_skipped_budget == 1
    assert time.perf_counter() - start < 1.5
