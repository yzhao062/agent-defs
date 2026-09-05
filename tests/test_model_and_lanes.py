import math

import pytest

from agent_defs import Breadth, Lane, PredicateKind, Rule, Surface
from agent_defs.lanes import ADVISE_MAX_U95, DENY_MAX_U95, admit, trials_needed, u95_zero_hits
from agent_defs.model import BenignFiring


def make(**kw):
    base = dict(
        id="atr:X-1", source="atr", source_id="X-1", source_rev="deadbeef",
        source_path="rules/x.yml", upstream_url="https://example.invalid",
        surface=Surface.OUT, breadth=Breadth.NARROW,
        predicate_kind=PredicateKind.REGEX, predicate=r"ignore previous instructions",
    )
    base.update(kw)
    return Rule(**base)


def test_bound_matches_the_published_thresholds():
    assert u95_zero_hits(598) == pytest.approx(0.005, abs=5e-6)
    assert u95_zero_hits(2995) == pytest.approx(0.001, abs=5e-6)
    assert u95_zero_hits(10) == pytest.approx(0.259, abs=1e-3)
    assert trials_needed(0.005) == 598
    assert trials_needed(0.001) == 2995


def test_a_rule_with_no_measurement_cannot_leave_record():
    lane, why = admit(make(), bundle_ok=True)
    assert lane is Lane.RECORD
    assert "no benign measurement" in why


def test_ten_clean_fixtures_do_not_buy_an_interrupting_lane():
    rule = make(benign=BenignFiring(10, 0, u95_zero_hits(10), "fixtures", "2026-09-05"))
    lane, _ = admit(rule, bundle_ok=True)
    assert lane is Lane.RECORD


def test_deny_needs_the_tighter_bound_and_a_measured_bundle():
    clean = BenignFiring(3000, 0, u95_zero_hits(3000), "awesome-copilot", "2026-09-05")
    assert admit(make(benign=clean), bundle_ok=True)[0] is Lane.DENY
    assert admit(make(benign=clean), bundle_ok=False)[0] is Lane.RECORD

    advise_only = BenignFiring(700, 0, u95_zero_hits(700), "awesome-copilot", "2026-09-05")
    assert DENY_MAX_U95 < u95_zero_hits(700) <= ADVISE_MAX_U95
    assert admit(make(benign=advise_only), bundle_ok=True)[0] is Lane.ADVISE


def test_a_rule_that_cannot_run_is_never_shipped_as_a_detector():
    rule = make(predicate_kind=PredicateKind.NONE, predicate=None,
                not_runnable_reason="condition needs a model judgement")
    assert admit(rule, bundle_ok=True)[0] is Lane.DO_NOT_SHIP
    assert not rule.runnable


def test_not_runnable_without_a_reason_is_rejected():
    with pytest.raises(ValueError):
        make(predicate_kind=PredicateKind.NONE, predicate=None)


def test_a_restricted_record_never_reaches_the_default_bundle():
    from agent_defs.model import default_bundle

    ordinary = make(id="atr:OK-1")
    agentharm = make(id="atr:ATR-2026-01837", restricted=True,
                     restricted_reason="embeds AgentHarm text; field-of-use restriction")

    assert ordinary.shippable
    assert not agentharm.shippable
    assert [r.id for r in default_bundle([ordinary, agentharm])] == ["atr:OK-1"]


def test_a_restricted_record_keeps_its_place_in_the_record():
    agentharm = make(id="atr:ATR-2026-01837", restricted=True,
                     restricted_reason="embeds AgentHarm text; field-of-use restriction")
    assert agentharm.source_id == "X-1" or agentharm.id.startswith("atr:")
    assert agentharm.restricted_reason
    assert agentharm.runnable
