"""The CFG channel: ATR's skill dispatcher, ported and executed.

The test that matters here is the first one. A real benign skill document out of
ATR's own benign corpus fires a rule when the flat predicate scans it and fires
nothing once the rule runs the way ATR runs it. That single document is the whole
95.49% false-positive result in miniature.
"""

from pathlib import Path
import json
import re
import time

import pytest

from agent_defs import cfg as cfg_module
from agent_defs.cfg import (
    _code_block_ranges,
    _decoded_blocks,
    cfg_bindings,
    scan_cfg,
    scan_cfg_isolated,
    scan_cfg_trusted,
)
from agent_defs.evaluate import IncompleteScanError, scan_trusted
from agent_defs.lanes import admit
from agent_defs.loaders import atr
from agent_defs.loaders.atr_skill_gates import (
    GateReadError,
    gate_summary,
    read_skill_gates,
)
from agent_defs.model import ChannelBinding, Lane, PredicateKind, Rule, Surface

FIXTURES = Path(__file__).parent / "fixtures"
SKILL = FIXTURES / "atr_skill"
PLAIN = FIXTURES / "atr"
PIN = "faf743fee8a5018467959ec8ea7ccdb1a1aab333"


@pytest.fixture(scope="module")
def loaded():
    return atr.load(SKILL)


@pytest.fixture(scope="module")
def gates():
    return read_skill_gates(SKILL, source_rev=PIN)


def rule(loaded, number):
    return next(r for r in loaded.rules if r.source_id == f"ATR-2026-{number}")


def cfg_ids(document, rules, **kw):
    result = scan_cfg_trusted(document, rules, **kw)
    assert result.complete, result.errors
    return set(result.rule_ids)


def flat_ids(document, rules):
    result = scan_trusted(document, rules)
    return {finding.rule_id for finding in result.findings}


# --- the result this module exists for ----------------------------------------

def test_a_real_benign_skill_document_stops_firing(loaded):
    """ATR's own benign corpus, one document, before and after the gates.

    ``real-apify--apify-actor-development.md`` is a published Apify skill. The
    flat predicate reads it as a rule match. ATR does not, because
    ``ATR-2026-00111`` is not eligible on its skill path at all.

    The earlier carrier here was ``real-prisma--prisma-cli-db-execute.md`` with
    ``ATR-2026-00040``. The measurement screen now refuses that rule outright, so
    that document no longer fires on either path and the contrast this test exists
    to show was gone. The property is unchanged; only the carrier moved.
    """
    document = (SKILL / "benign" / "real-apify--apify-actor-development.md").read_text(
        encoding="utf-8")
    runnable = [r for r in loaded.rules if r.runnable]

    fired_flat = flat_ids(document, runnable)
    assert "atr:ATR-2026-00111" in fired_flat

    assert cfg_ids(document, loaded.rules) == set()


def test_the_gate_that_refused_it_is_named_on_the_record(loaded):
    refused = rule(loaded, "00040").binding(Surface.CFG)
    assert refused.eligible is False
    assert refused.conditions == ()
    blocked = [g for g in refused.gates if g.verdict == "block"]
    assert [g.name for g in blocked] == ["skill_compound"]
    assert "scan_target='mcp'" in blocked[0].detail
    assert blocked[0].read_from.startswith("src/engine.ts:")


# --- the gates, read rather than typed ----------------------------------------

def test_every_gate_value_comes_from_the_checkout_with_a_line_number(gates):
    summary = gate_summary(gates)
    json.dumps(summary)
    assert summary["entry_point"] == "scanSkill"
    assert gates.event_type == "mcp_exchange"
    assert gates.scan_context == "skill"
    assert gates.exempt_scan_targets == frozenset({"skill", "both"})
    assert (gates.min_conditions_floor, gates.min_conditions_ratio) == (2, 0.3)
    assert gates.skipped_statuses == frozenset({"deprecated", "draft"})
    assert gates.lane_default == "hunt"
    assert gates.lane_blocked_maturities == frozenset({"deprecated"})
    assert (gates.base64_max_blocks, gates.base64_min_block_chars) == (5, 32)
    assert gates.base64_min_printable_ratio == 0.7
    assert gates.base64_max_decoded_chars == 100_000
    for name, source in gates.provenance.items():
        assert source.line > 0, name
        assert source.path.endswith((".ts", ".md")), name
        assert source.excerpt.strip(), name


def test_the_denylist_is_read_whole_with_upstream_own_note_on_each_entry(gates):
    assert len(gates.denylist) == 22
    assert gates.denylist["ATR-2026-00111"].startswith("Shell Escape")
    assert "70% FP" in gates.denylist["ATR-2026-00111"]
    assert gates.denylist["ATR-2026-00123"].startswith("Over-Privileged Skill")


def test_the_denylist_is_declared_and_the_pinned_engine_does_not_apply_it(gates):
    """Upstream's contract and upstream's code disagree; both facts travel.

    ``engines/typescript/INTERFACE-CONTRACT.md`` says a conforming engine must
    honor the set. ``src/engine.ts`` declares it and never reads it. Choosing
    one of those quietly would be us asserting something upstream does not.
    """
    assert gates.denylist_applied is False
    assert gates.denylist_required_by_interface_contract is True


def test_a_missing_gate_fails_loudly_rather_than_defaulting(tmp_path):
    for rel in ("src/engine.ts", "src/enforcement.ts", "src/quality/rule-contract.ts"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text((SKILL / rel).read_text(encoding="utf-8"),
                                    encoding="utf-8")
    engine = tmp_path / "src/engine.ts"
    engine.write_text(re.sub(r"const minRequired[^\n]*\n", "", engine.read_text(encoding="utf-8")),
                      encoding="utf-8")
    with pytest.raises(GateReadError, match="compound gate"):
        read_skill_gates(tmp_path, source_rev=PIN)


def test_the_scanner_bounds_are_the_ones_read_from_the_source(gates):
    """The scanner holds these as constants; the source is where they came from.

    Pinning them here is what keeps the two from drifting apart quietly, which is
    the failure that produced this module in the first place.
    """
    assert cfg_module.BASE64_MAX_BLOCKS == gates.base64_max_blocks
    assert cfg_module.BASE64_MIN_BLOCK_CHARS == gates.base64_min_block_chars
    assert cfg_module.BASE64_MIN_DECODED_CHARS == gates.base64_min_decoded_chars
    assert cfg_module.BASE64_MIN_PRINTABLE_RATIO == gates.base64_min_printable_ratio
    assert cfg_module.BASE64_MAX_DECODED_CHARS == gates.base64_max_decoded_chars
    assert cfg_module.SOURCE_MAX_EVAL_CHARS == gates.max_eval_chars
    assert cfg_module.BASE64_BLOCK.pattern.startswith(
        f"[A-Za-z0-9+/]{{{gates.base64_min_block_chars},}}")


def test_a_document_over_the_source_limit_is_unfinished_not_clean(loaded):
    """ATR evaluates no pattern above MAX_EVAL_LENGTH, so it reports clean.

    Reproducing that would let a 101 KB skill document pass by being long. The
    divergence is recorded on the result instead, and it costs nothing measured:
    the largest document in ATR's benchmark is 44,684 characters.
    """
    carrier = rule(loaded, "00120")
    payload = carrier.examples_positive[2]
    document = payload + "\n" + "filler text. " * 9000
    assert len(document) > cfg_module.SOURCE_MAX_EVAL_CHARS
    result = scan_cfg_trusted(document, [carrier])
    assert result.over_source_eval_limit is True
    assert result.complete is False
    assert [f.rule_id for f in result.partial_findings] == ["atr:ATR-2026-00120"]
    with pytest.raises(IncompleteScanError) as raised:
        result.findings
    assert any("evaluation limit" in error.reason for error in raised.value.result.errors)


def test_the_compound_gate_arithmetic_is_the_source_own(gates):
    assert gates.min_required_conditions(1) == 2      # the floor decides
    assert gates.min_required_conditions(0) == 2      # a missing list counts as one
    assert gates.min_required_conditions(2) == 2
    assert gates.min_required_conditions(7) == 3      # ceil(7 * 0.3)


# --- admission, per rule -------------------------------------------------------

def test_any_logic_can_never_clear_the_gate_without_a_skill_target(loaded):
    """The short circuit is why, and it is read from the source, not assumed."""
    for number in ("00040", "00111"):
        binding = rule(loaded, number).binding(Surface.CFG)
        assert binding.eligible is False
        assert "can report at most 1 matched" in binding.reason


def test_all_logic_with_two_conditions_clears_the_gate_without_a_skill_target(loaded):
    binding = rule(loaded, "02377").binding(Surface.CFG)
    assert binding.condition_logic == "all"
    assert binding.eligible is True
    assert len(binding.conditions) == 2


def test_a_skill_target_is_exempt_from_the_compound_gate(loaded):
    binding = rule(loaded, "00120").binding(Surface.CFG)
    assert binding.eligible is True
    assert [g.verdict for g in binding.gates if g.name == "skill_compound"] == ["pass"]


def test_the_denylisted_rule_the_pinned_engine_still_runs_is_recorded_as_such(loaded):
    binding = rule(loaded, "00123").binding(Surface.CFG)
    assert binding.eligible is True
    listed = next(g for g in binding.gates if g.name == "skill_denylist")
    assert listed.verdict == "declared-not-applied"
    assert "must honor it" in listed.detail


def test_the_dispatcher_runs_rules_the_flat_predicate_refuses(loaded):
    """Two different execution models, and the source's own is the wider one.

    ``ATR-2026-00121`` has no flat predicate because composing its eight
    conditions into one alternation trips the pattern screen. ATR never composes
    them, so seven of the eight run here unchanged.

    This count was 6 while it was a prediction. The measurement sweep then timed
    every condition, and the prediction was wrong in both directions at once:
    the condition the shape screen had refused measures fast and is readmitted,
    while condition 1, which the shape screen passed, crosses at 3.91 s on
    65,536 bytes and is still running at 60 s. One is refused either way, so the
    count that was guessed at 6 measures 7.
    """
    carrier = rule(loaded, "00121")
    assert carrier.predicate_kind is PredicateKind.NONE
    binding = carrier.binding(Surface.CFG)
    assert binding.eligible is True
    assert len(binding.conditions) == 7
    assert carrier.lane is Lane.RECORD
    assert admit(carrier)[0] is Lane.RECORD


def test_a_refused_condition_is_dropped_from_any_and_recorded(loaded):
    """The carrier has moved twice, and the second move is the interesting one.

    It left ``00276`` when the measurement admitted a condition the shape screen
    had refused, leaving that rule with no screen gate to read. It leaves
    ``00162`` now for the opposite reason: all four of that rule's conditions
    cross the budget, between 2.71 s and 6.29 s with three still running at 60 s,
    so its gate reads ``block`` and it carries no surviving condition to drop one
    from. A rule with nothing left cannot show that losing one condition is
    survivable.

    ``00120`` is picked by rule rather than by search: it is the lowest-numbered
    rule in this fixture that is still CFG-eligible with exactly one condition
    refused. Sixty CFG-eligible rules in the full corpus carry the same shape.
    """
    binding = rule(loaded, "00120").binding(Surface.CFG)
    screen = next(g for g in binding.gates if g.name == "screen")
    assert screen.verdict == "pass"
    assert "1 of 5 conditions refused" in screen.detail
    assert "can only lose matches" in screen.detail
    assert len(binding.conditions) == 4


def test_a_semantic_rule_without_a_pattern_fallback_never_reaches_the_channel(loaded):
    """The synchronous skill path has no judge, so it returns no match.

    Built rather than found: no pinned rule pairs a skill scan target with a
    semantic method, and admitting one would fire a rule where ATR does not.
    """
    gates_read = read_skill_gates(SKILL, source_rev=PIN)
    raw = json.loads(json.dumps(rule(loaded, "00120").extra["upstream"]))
    raw["detection"]["method"] = "semantic"
    refused = atr._cfg_binding(raw, gates_read)
    assert refused.eligible is False
    assert "no pattern fallback" in refused.reason

    raw["detection"]["semantic"] = {"fallback_method": "pattern"}
    allowed = atr._cfg_binding(raw, gates_read)
    assert allowed.eligible is True
    assert "declared pattern fallback" in next(
        g.detail for g in allowed.gates if g.name == "method")


def test_a_refused_condition_voids_an_all_rule_instead_of_weakening_it(loaded):
    """Dropping a branch of ``all`` would fire on less evidence than was required.

    Built rather than found: no pinned rule pairs ``condition: all`` with a
    condition the screen refuses, and the direction of that failure is the one
    that must never be wrong.
    """
    raw = json.loads(json.dumps(rule(loaded, "02377").extra["upstream"]))
    raw["detection"]["conditions"][1]["value"] = r"(\w+\s?)+$"
    binding = atr._cfg_binding(raw, read_skill_gates(SKILL, source_rev=PIN))
    assert binding.eligible is False
    assert binding.conditions == ()
    assert "less evidence than its author required" in binding.reason


def test_a_checkout_without_engine_sources_yields_no_binding_at_all():
    """Silence beats a flat predicate wearing the dispatcher's name."""
    result = atr.load(PLAIN)
    assert result.delta.skill_gates["read"] is False
    assert "src/engine.ts not found" in result.delta.skill_gates["reason"]
    assert all(r.bindings == () for r in result.rules)
    assert cfg_bindings(result.rules) == []


def test_bindings_are_channel_addressed(loaded):
    carrier = rule(loaded, "00120")
    assert carrier.binding(Surface.CFG) is carrier.bindings[0]
    assert carrier.binding("CFG") is carrier.bindings[0]
    assert carrier.binding(Surface.OUT) is None


# --- execution -----------------------------------------------------------------

def test_code_block_suppression_follows_the_source_shape():
    text = "prose one\n```\nfenced two\n```\nprose `inline` tail\n| a | \"quoted\" |\n"
    ranges = _code_block_ranges(text)
    inside = [text[a:b] for a, b in ranges]
    assert any(chunk.startswith("```") and "fenced two" in chunk for chunk in inside)
    assert "`inline`" in inside
    assert '"quoted"' in inside


def test_an_unterminated_fence_runs_to_the_end_of_the_document():
    text = "intro\n```\nnever closed\nmore\n"
    (start, end), = [r for r in _code_block_ranges(text) if text[r[0]:r[0] + 3] == "```"]
    assert end == len(text)


def test_suppression_applies_only_to_the_rules_that_declare_it(loaded):
    """And it reads the first match only, which is what ``isInsideCodeBlock`` does."""
    flagged = rule(loaded, "00162")
    assert flagged.binding(Surface.CFG).suppress_in_code_blocks is True
    plain = rule(loaded, "00120")
    assert plain.binding(Surface.CFG).suppress_in_code_blocks is False

    payload = plain.examples_positive[0]
    fenced = f"# Title\n\n```\n{payload}\n```\n"
    assert "atr:ATR-2026-00120" in cfg_ids(fenced, [plain])


def test_a_flagged_rule_stops_firing_inside_a_fence(loaded):
    """``00421`` carries the suppression tag; ``00162`` used to and no longer runs.

    Every one of ``00162``'s four conditions crosses the budget, so it is refused
    before it reaches this channel and cannot demonstrate anything about
    suppression. ``00421`` is the lowest-numbered CFG-eligible rule in the corpus
    that still declares ``tags.suppress_in_code_blocks``, and it was added to the
    fixture for that. Eleven rules in the full corpus carry the same tag, so the
    behaviour is upstream's rather than this one rule's.
    """
    flagged = rule(loaded, "00421")
    payload = next(text for text in flagged.examples_positive
                   if cfg_ids(text, [flagged]))
    assert cfg_ids(f"```\n{payload}\n```\n", [flagged]) == set()
    assert cfg_ids(f"```\n```\n{payload}\n", [flagged]) == {"atr:ATR-2026-00421"}


def test_turning_suppression_off_is_a_measurement_switch_not_a_setting(loaded):
    flagged = rule(loaded, "00421")
    payload = next(text for text in flagged.examples_positive
                   if cfg_ids(text, [flagged]))
    fenced = f"```\n{payload}\n```\n"
    assert cfg_ids(fenced, [flagged]) == set()
    assert cfg_ids(fenced, [flagged], suppress_code_blocks=False) == {"atr:ATR-2026-00421"}


def test_a_payload_hidden_in_base64_is_read(loaded):
    import base64

    carrier = rule(loaded, "00120")
    payload = next(text for text in carrier.examples_positive if cfg_ids(text, [carrier]))
    encoded = base64.b64encode(payload.encode("utf-8")).decode("ascii")
    document = f"# Helper\n\nRun the setup blob:\n\n{encoded}\n"
    assert cfg_ids(document, [carrier], decode_base64=False) == set()
    result = scan_cfg_trusted(document, [carrier])
    assert result.rule_ids == ("atr:ATR-2026-00120",)
    assert [f.origin for f in result.findings] == ["base64"]


def test_base64_decoding_keeps_the_source_bounds():
    import base64

    blocks = [base64.b64encode(f"instruction number {n} for the agent".encode()).decode()
              for n in range(8)]
    decoded = _decoded_blocks("\n\n".join(blocks))
    assert len(decoded) == 5
    assert decoded[0] == "instruction number 0 for the agent"
    assert _decoded_blocks(base64.b64encode(b"\x00\x01\x02\x03" * 16).decode()) == []
    assert _decoded_blocks("A" * 31) == []


def test_findings_carry_the_condition_that_matched(loaded):
    carrier = rule(loaded, "00120")
    payload = carrier.examples_positive[2]
    result = scan_cfg_trusted(payload, [carrier])
    finding, = result.findings
    # Derived: the index addresses the binding's condition list, and that list
    # shortens whenever a condition is refused. Pinning the literal made this
    # test fail on a merge that changed nothing it was written to check.
    conditions = carrier.binding(Surface.CFG).conditions
    assert 0 <= finding.condition_index < len(conditions)
    assert re.search(conditions[finding.condition_index], payload) is not None
    assert finding.origin == "document"
    assert payload[finding.start:finding.end]
    assert finding.as_finding().rule_id == "atr:ATR-2026-00120"


def _spans(result):
    return [(f.rule_id, f.start, f.end, f.condition_index, f.origin) for f in result.findings]


def test_the_isolated_path_decides_what_the_in_process_path_decides(loaded):
    """Isolation must not change the verdict, only who pays if it runs away."""
    flagged = rule(loaded, "00421")
    payload = next(text for text in flagged.examples_positive
                   if scan_cfg_trusted(text, [flagged]).findings)
    for rules in ([flagged], loaded.rules):
        here = scan_cfg_trusted(payload, rules)
        there = scan_cfg_isolated(payload, rules, budget_s=20.0)
        assert here.complete and there.complete
        assert _spans(here) == _spans(there)
        assert here.rules_evaluated == there.rules_evaluated
    fenced = f"```\n{payload}\n```\n"
    assert scan_cfg_isolated(fenced, [flagged], budget_s=20.0).findings == ()
    empty = scan_cfg_isolated(payload, [], budget_s=20.0)
    assert empty.empty_bundle and not empty.complete


def test_the_isolated_path_kills_a_match_the_deadline_outlives(loaded):
    """The reason this path exists, on a pattern the screen cannot catch.

    ``a*a*a*a*a*a*b`` carries no group under a quantifier and no alternation
    under repetition, so the shape screen admits it, and no measurement has ever
    timed it. Against 200 characters it does not finish in any time a person
    waits. Through ``scan_cfg_trusted`` this call does not return; here it returns at the
    deadline, says it is incomplete, and refuses to hand over findings.
    """
    binding = ChannelBinding(channel="CFG", entry_point="test", eligible=True, reason="",
                             condition_logic="any", conditions=("a*a*a*a*a*a*b",),
                             suppress_in_code_blocks=False)
    runaway = Rule(id="test:redos", source="test", source_id="redos", source_rev="0",
                   source_path="", upstream_url="", surface=Surface.CFG,
                   predicate_kind=PredicateKind.NONE, predicate=None, case_sensitive=False,
                   not_runnable_reason="dispatcher only", bindings=(binding,),
                   lane=Lane.RECORD, lane_reason="test")
    started = time.perf_counter()
    result = scan_cfg_isolated("a" * 200, [runaway], budget_s=1.0)
    elapsed = time.perf_counter() - started
    assert elapsed < 5.0, "the deadline did not bound the call"
    assert not result.complete
    assert any("deadline" in error.reason for error in result.errors)
    assert result.partial_findings == ()
    with pytest.raises(IncompleteScanError):
        result.findings


def test_scan_cfg_rejects_a_non_string_document(loaded):
    with pytest.raises(TypeError):
        scan_cfg_trusted(b"bytes", loaded.rules)


def test_a_truncated_document_is_not_a_clean_one(loaded):
    """An empty result must never be readable as "this file is clean"."""
    carrier = rule(loaded, "00120")
    payload = carrier.examples_positive[2]
    document = "x" * 4096 + payload
    result = scan_cfg_trusted(document, [carrier], max_bytes=64)
    assert result.truncated_input is True
    assert result.complete is False
    assert result.partial_findings == ()
    with pytest.raises(IncompleteScanError):
        result.findings
    with pytest.raises(TypeError):
        bool(result)
