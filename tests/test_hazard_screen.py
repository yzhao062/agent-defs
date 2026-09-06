"""The screen refuses on measurement first and on shape only where none exists.

Round three timed every pattern in the pinned ATR corpus. It found 296 of 793
rules crossing one second, 220 of them shipped, while the shape screen refused 86
for a nested quantifier of which 44 never crossed at any length up to 1 MiB.
These tests pin the resulting rule: a recorded crossing refuses, a recorded
non-crossing admits and overrides the shape screen, and a pattern nobody timed
keeps the shape screen and says so.
"""

import json
import re

import pytest

from agent_defs import PredicateKind
from agent_defs import evaluate
from agent_defs.evaluate import (Measurement, UnsafePattern, compile_rule, measurement_for_pattern,
                                 measurement_for_rule, port_utf16_surrogates, scan_trusted,
                                 screen_pattern)
from test_evaluate import rule

NESTED = r"^(a?){1,40}a{40}$"
PLAIN = r"needle\s+in\s+a\s+haystack"


@pytest.fixture
def table(tmp_path, monkeypatch):
    """Point the screen at a table this test owns."""

    def install(patterns=None, rules=None, **top):
        payload = {"budget_s": 1.0, "method": "unit fixture", "measured_at": "2026-09-05",
                   "patterns": patterns or {}, "rules": rules or {}}
        payload.update(top)
        path = tmp_path / "hazards.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        monkeypatch.setattr(evaluate, "HAZARD_TABLE_PATH", path)
        monkeypatch.setattr(evaluate, "_HAZARD_CACHE", None)
        return payload

    monkeypatch.setattr(evaluate, "_HAZARD_CACHE", None)
    yield install
    evaluate._HAZARD_CACHE = None


def digest(text):
    return evaluate._fingerprint(text)


def test_a_measured_crossing_refuses_a_pattern_the_shape_screen_would_have_passed(table):
    table(patterns={digest(PLAIN): ["slow", 16384, 22.8, True]})
    with pytest.raises(UnsafePattern) as caught:
        screen_pattern(PLAIN)
    message = str(caught.value)
    assert "measured 22.80 s on 16384 bytes" in message
    assert "1 s budget" in message
    assert "still running at 60 s" in message


def test_a_measured_non_crossing_admits_a_pattern_the_shape_screen_would_have_refused(table):
    table(patterns={digest(NESTED): ["fast"]})
    screen_pattern(NESTED)
    assert evaluate._has_nested_quantifier(NESTED)


def test_an_unmeasured_pattern_keeps_the_shape_screen_and_says_it_was_not_measured(table):
    table()
    with pytest.raises(UnsafePattern, match="unmeasured"):
        screen_pattern(NESTED)
    with pytest.raises(UnsafePattern, match="unmeasured"):
        screen_pattern(r"(?:ab|cd)+x")


def test_a_capability_limit_outranks_a_timing_that_would_not_change_the_answer(table):
    table(patterns={digest(r"(a)\1"): ["fast"]})
    with pytest.raises(UnsafePattern, match="backreferences"):
        screen_pattern(r"(a)\1")


def test_a_missing_or_broken_table_falls_back_to_shape_rather_than_admitting(tmp_path, monkeypatch):
    for content in (None, "{", '["not an object"]', '{"patterns": "text"}',
                    '{"patterns": {}, "budget_s": "soon"}'):
        path = tmp_path / "absent.json"
        if content is not None:
            path.write_text(content, encoding="utf-8")
        monkeypatch.setattr(evaluate, "HAZARD_TABLE_PATH", path)
        monkeypatch.setattr(evaluate, "_HAZARD_CACHE", None)
        with pytest.raises(UnsafePattern, match="unmeasured"):
            screen_pattern(NESTED)
    evaluate._HAZARD_CACHE = None


def test_a_rule_verdict_needs_the_condition_text_that_was_measured(table):
    patterns = ["alpha", "beta"]
    table(rules={"atr:ATR-2026-99999": [digest("\n".join(patterns)), "slow", 1024, 4.5, False]})
    found = measurement_for_rule("atr", "ATR-2026-99999", patterns)
    assert found is not None and found.slow and found.crossing_bytes == 1024
    assert measurement_for_rule("atr", "ATR-2026-99999", ["alpha", "beta", "gamma"]) is None
    assert measurement_for_rule("atr", "ATR-2026-00001", patterns) is None


def test_a_malformed_row_is_read_as_no_measurement_rather_than_as_fast(table):
    for row in ([], ["slow"], ["slow", None, None], ["quick"], "fast"):
        table(patterns={digest(NESTED): row})
        assert measurement_for_pattern(NESTED) is None
        with pytest.raises(UnsafePattern, match="unmeasured"):
            screen_pattern(NESTED)


def test_a_caller_supplied_verdict_covers_a_string_the_table_cannot_carry(table):
    table()
    composed = f"(?:{NESTED})|(?:{PLAIN})"
    with pytest.raises(UnsafePattern, match="unmeasured"):
        screen_pattern(composed)
    screen_pattern(composed, measurement=Measurement(verdict="fast", budget_s=1.0))
    with pytest.raises(UnsafePattern, match="measured"):
        screen_pattern(PLAIN, measurement=Measurement(verdict="slow", budget_s=1.0,
                                                      crossing_bytes=241, wall_s=1.4))


# --- the table this package ships -------------------------------------------------

def test_the_shipped_table_is_a_measurement_and_not_an_assertion():
    shipped = evaluate.hazard_table()
    assert shipped["policy"] == "agent-defs.hazards"
    assert shipped["budget_s"] == 1.0
    assert shipped["measurement_id"] and shipped["method"] and shipped["measured_at"]
    assert shipped["provenance"]["corpora"]["atr"] == "faf743fee8a5018467959ec8ea7ccdb1a1aab333"
    counts = shipped["counts"]
    assert counts["rules"] == len(shipped["rules"]) == 793
    # Derived rather than pinned. 296 rules came from unit e3's per-pattern sweep;
    # ATR-2026-02351 was added afterwards by cross-pattern witness replay, which is
    # why the table carries a cross_pattern_replay note.
    rows = list(counts_rows := shipped["rules"].values())
    assert counts["rules_slow"] == sum(1 for r in rows if r[1] == "slow")
    assert counts["rules_fast"] == sum(1 for r in rows if r[1] == "fast")
    assert counts["rules_slow"] + counts["rules_fast"] == 793
    assert shipped["rules"]["atr:ATR-2026-02351"][1] == "slow"
    assert shipped["provenance"]["cross_pattern_replay"]
    assert counts["patterns"] == len(shipped["patterns"])
    for row in shipped["rules"].values():
        assert row[1] in ("slow", "fast")
        assert (len(row) == 5) is (row[1] == "slow")
    # Three verdicts, and the third is what keeps the title of this test true.
    # ``inferred-fast`` marks a string this loader derives and nobody timed: a
    # surrogate port or a scoped alternation, carrying no verdict of its own so
    # it cannot certify itself on its origin's timing. It yields no measurement,
    # which is what sends it to the shape screen instead.
    for key, row in shipped["patterns"].items():
        assert re.fullmatch(r"[0-9a-f]{16}", key)
        assert row[0] in ("slow", "fast", "inferred-fast")
        if row[0] == "slow":
            assert isinstance(row[1], int) and row[1] > 0 and row[2] > 1.0
        if row[0] == "inferred-fast":
            assert len(row) == 1
    inferred = [key for key, row in shipped["patterns"].items() if row[0] == "inferred-fast"]
    assert inferred, "the table should still distinguish derived strings from timed ones"
    assert all(evaluate._measurement_from_row(shipped["patterns"][key], shipped) is None
               for key in inferred)


def test_no_measured_crossing_survives_into_a_runnable_rule():
    from agent_defs.loaders.atr import load
    from pathlib import Path
    loaded = load(Path(__file__).parent / "fixtures" / "atr")
    slow = [r for r in loaded.rules
            if measurement_for_rule("atr", r.source_id,
                                    [c["value"] for c in r.extra["upstream"]["detection"]["conditions"]
                                     if isinstance(c, dict) and isinstance(c.get("value"), str)])
            and measurement_for_rule("atr", r.source_id,
                                     [c["value"] for c in r.extra["upstream"]["detection"]["conditions"]
                                      if isinstance(c, dict) and isinstance(c.get("value"), str)]).slow]
    assert {r.source_id for r in slow} == {"ATR-2026-00040", "ATR-2026-00070", "ATR-2026-00120",
                                           "ATR-2026-01756", "ATR-2026-02260", "ATR-2026-02261"}
    for r in slow:
        assert not r.runnable
        assert "refused on measurement" in r.not_runnable_reason
        assert "bytes against a 1 s budget" in r.not_runnable_reason
        assert "agent-defs.hazards" in r.not_runnable_reason
        assert len(r.not_runnable_reason) < 400, "a refusal reason is read, not archived"
    for r in loaded.rules:
        if r.runnable:
            assert r.extra["execution"]["measurement"]["verdict"] in ("fast", "unmeasured")
    backref = next(r for r in loaded.rules if r.source_id == "ATR-2026-02261")
    assert "backreferences" in backref.not_runnable_reason
    assert "refused on measurement" in backref.not_runnable_reason


# --- the UTF-16 dialect port ------------------------------------------------------

def esc(*codes):
    """The literal ``\\uXXXX`` escape text a JavaScript-dialect regex carries.

    Written this way rather than as a source literal so that an editor or a tool
    that normalizes text cannot fold the pair into the character it encodes,
    which is the very thing under test.
    """
    return "".join("\\u%04X" % code for code in codes)


@pytest.mark.parametrize("source,ported", [
    (r"(?:\uDB40[\uDC00-\uDC7F]){3,}", r"(?:[\U000E0000-\U000E007F]){3,}"),
    (esc(0xD83D, 0xDE00), r"\U0001F600"),
    (r"[\uD800-\uDBFF][\uDC00-\uDFFF]", r"[\U00010000-\U0010FFFF]"),
    (r"\uDB40[\uDC00-\uDC0F\uDC20-\uDC2F]", r"[\U000E0000-\U000E000F\U000E0020-\U000E002F]"),
    (r"[\uDB40\uDB41][\uDC00-\uDC7F]", r"[\U000E0000-\U000E007F\U000E0400-\U000E047F]"),
])
def test_a_surrogate_pair_becomes_the_code_point_it_encodes(source, ported):
    assert port_utf16_surrogates(source)[0] == ported
    screen_pattern(ported)


@pytest.mark.parametrize("source", [
    r"\d+\s*ignore", "plain text", "[" + esc(0x200B, 0x200C) + "]{2,}", "",
    r"\\uDB40\\uDC00", r"\x41A", r"\uDB40" + "-" + r"\uDC00",
])
def test_the_port_leaves_everything_it_cannot_pair_byte_for_byte(source):
    assert port_utf16_surrogates(source)[0] == source


@pytest.mark.parametrize("source", [
    r"\d+\s*ignore", "plain text", "[" + esc(0x200B, 0x200C) + "]{2,}", "",
    r"\\uDB40\\uDC00", r"\x41A",
])
def test_the_port_is_silent_when_there_is_nothing_to_port(source):
    assert port_utf16_surrogates(source) == (source, [])


@pytest.mark.parametrize("source", [
    r"\uDB40x", r"a\uDB40", r"\uDC00\uDB40", r"[\uDB40a]",
    esc(0xD83D, 0xDE00) + "+", esc(0xD83D, 0xDE00) + "{2,}",
    r"[\uD800-\uDBFF][\uDC00-\uDFFF]*",
])
def test_an_unpaired_surrogate_is_reported_and_then_refused(source):
    ported, notes = port_utf16_surrogates(source)
    assert ported == source
    assert notes and notes[-1]["unpaired"] is True
    with pytest.raises(UnsafePattern, match="unpaired UTF-16 surrogate"):
        screen_pattern(ported)


def test_the_ported_pattern_matches_the_tag_block_the_original_could_not():
    tags = "".join(chr(0xE0000 + code) for code in (0x01, 0x48, 0x49, 0x7F))
    payload = f"# Skill\n\nDo the task{tags} and report back."
    original = r"(?:\uDB40[\uDC00-\uDC7F]){3,}"
    ported, notes = port_utf16_surrogates(original)
    assert notes and not any(note.get("unpaired") for note in notes)
    assert re.search(original, payload) is None
    assert re.search(ported, payload) is not None
    assert len(payload.encode("utf-16-le")) // 2 == len(payload) + len(tags)


def test_the_loader_ports_the_one_rule_in_the_corpus_that_needs_it():
    from agent_defs.loaders.atr import load
    from pathlib import Path
    loaded = load(Path(__file__).parent / "fixtures" / "atr")
    assert loaded.delta.dialect_ports == {"detection.conditions.regex.utf16_surrogate_pair": 1}
    r = next(x for x in loaded.rules if x.source_id == "ATR-2026-00129")
    port, = r.extra["execution"]["utf16_port"]
    assert port["condition_index"] == 0
    assert port["notes"][0]["from"] == r"\uDB40[\uDC00-\uDC7F]"
    assert port["notes"][0]["to"] == r"[\U000E0000-\U000E007F]"
    assert r.extra["upstream"]["detection"]["conditions"][0]["value"] == r"(?:\uDB40[\uDC00-\uDC7F]){3,}"
    tags = "".join(chr(0xE0000 + code) for code in (0x01, 0x48, 0x49))
    assert scan_trusted(f"skill body {tags} tail", [r]).partial_findings
    assert not scan_trusted("skill body tail", [r]).partial_findings


# --- the composition that no longer decides whether a rule ships -------------------

def test_a_composition_over_the_length_limit_keeps_the_branches():
    from agent_defs.loaders.atr import load
    from pathlib import Path
    loaded = load(Path(__file__).parent / "fixtures" / "atr")
    assert loaded.delta.composition_fallbacks == {"pattern longer than 4096 characters": 1}
    r = next(x for x in loaded.rules if x.source_id == "ATR-2026-00005")
    assert r.runnable and r.predicate_kind is PredicateKind.STRUCTURED
    upstream = [c["value"] for c in r.extra["upstream"]["detection"]["conditions"]]
    assert r.predicate == {"regex_any": upstream}
    assert len("|".join(upstream)) > evaluate._MAX_PATTERN_LEN
    assert "alternation not carried" in r.extra["execution"]["composition"]
    for example in r.examples_positive:
        assert scan_trusted(example, [r]).partial_findings, example[:60]
    for example in r.examples_negative:
        assert not scan_trusted(example, [r]).partial_findings, example[:60]


@pytest.mark.parametrize("scan", [evaluate.scan, evaluate.scan_trusted])
def test_regex_any_answers_where_the_alternation_would_have(scan):
    from agent_defs.loaders.atr import _scoped
    patterns = [r"beta", r"(?m)^alpha$", r"gamma"]
    disjunction = rule("any", PredicateKind.STRUCTURED, {"regex_any": patterns})
    union = rule("union", PredicateKind.REGEX, "|".join(_scoped(p) for p in patterns))
    for text in ("nothing here", "alpha", "beta", "say gamma then alpha", "alpha beta gamma",
                 "beta\nalpha", "ALPHA"):
        left, right = scan(text, [disjunction]), scan(text, [union])
        assert left.complete and right.complete
        assert [(f.start, f.end) for f in left.findings] == [(f.start, f.end) for f in right.findings], text


def test_regex_any_refuses_a_leaf_the_screen_refuses():
    result = scan_trusted("plain", [rule("any", PredicateKind.STRUCTURED,
                                         {"regex_any": ["safe", r"(a+)+$"]})])
    assert not result.complete and [e.rule_id for e in result.errors] == ["any"]


def test_the_bundle_finishes_inside_the_hook_budget_on_the_input_that_froze_it():
    """The witness round three found for ATR-2026-00233: 16 KB of plain ASCII.

    Against the pinned corpus's 306-rule OUT bundle that input took 283 seconds,
    142 of them in ATR-2026-00233 alone and 140 in ATR-2026-00228. Both are now
    refused on measurement. This runs the fixture's own bundle, which carries six
    rules the same measurement refuses, under the hook's one-second budget.
    """
    from agent_defs.loaders.atr import load
    from pathlib import Path
    loaded = load(Path(__file__).parent / "fixtures" / "atr")
    runnable = [r for r in loaded.rules if r.runnable]
    assert len(runnable) == 7
    result = evaluate.scan("a:" * 8191 + "!", runnable, budget_s=1.0)
    assert result.complete
    assert result.rules_evaluated == len(runnable)
    assert result.rules_skipped_budget == 0


def test_the_length_limit_still_bounds_one_upstream_pattern():
    with pytest.raises(UnsafePattern, match="longer than"):
        screen_pattern("a" * (evaluate._MAX_PATTERN_LEN + 1))
    result = scan_trusted("a", [rule("wide", PredicateKind.STRUCTURED,
                                     {"regex_any": ["a" * (evaluate._MAX_PATTERN_LEN + 1)]})])
    assert not result.complete
