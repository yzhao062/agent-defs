"""The lane comparison must not be decided by the inverted bound's rounding.

Every case here was found by the round 2 review, which built them by searching
for counts whose Clopper-Pearson bound sits a few parts in 1e10 from a ceiling.
The reference values come from summing the binomial CDF in ``Decimal`` with an
exact ``math.comb`` coefficient, which shares no arithmetic with the code under
test.
"""
from decimal import Decimal, getcontext
import math

import pytest

from agent_defs.lanes import (ADVISE_MAX_U95, DENY_MAX_U95, LOG_CDF_SLACK,
                              MAX_SUPPORTED_TRIALS, Lane, admit, binomial_u95,
                              bound_within, u95_zero_hits)
from agent_defs.model import BenignFiring, PredicateKind, Rule, Surface

#: (trials, hits, ceiling). The inverted bound lands just under each ceiling
#: while the exact bound is above it.
NEAR_CEILING = [(5023741, 4907, DENY_MAX_U95),
                (1268982, 6214, ADVISE_MAX_U95),
                (9733435, 48305, ADVISE_MAX_U95)]


def exact_cdf(trials, hits, p, digits=40):
    """P[Binomial(trials, p) <= hits], with an exact binomial coefficient."""
    getcontext().prec = digits + 20
    dp, dq = Decimal(p), Decimal(1) - Decimal(p)
    top = Decimal(math.comb(trials, hits)) * dp ** hits * dq ** (trials - hits)
    total, term = Decimal(1), Decimal(1)
    for k in range(hits, 0, -1):
        term *= Decimal(k) / Decimal(trials - k + 1) * dq / dp
        total += term
        if term < total * Decimal(10) ** -(digits + 10):
            break
    getcontext().prec = digits
    return +(top * total)


def rule_with(measurement):
    return Rule(id="t:1", source="t", source_id="1", source_rev="rev",
                source_path="rules/t.yaml", upstream_url="https://example.test",
                title="t", predicate_kind=PredicateKind.REGEX, predicate="needle",
                surface=Surface.OUT, benign=measurement)


@pytest.mark.parametrize("trials,hits,ceiling", NEAR_CEILING)
def test_the_inverted_bound_reads_the_wrong_side_of_the_ceiling(trials, hits, ceiling):
    """The defect this exists for, stated as a fact about the reported value."""
    assert binomial_u95(trials, hits) <= ceiling
    assert exact_cdf(trials, hits, ceiling) > Decimal("0.05")


@pytest.mark.parametrize("trials,hits,ceiling", NEAR_CEILING)
def test_the_comparison_refuses_rather_than_certifying_the_wrong_side(trials, hits, ceiling):
    assert bound_within(trials, hits, ceiling) is not True


@pytest.mark.parametrize("trials,hits,ceiling", NEAR_CEILING)
def test_admit_does_not_reach_the_lane_the_float_comparison_would_have(trials, hits, ceiling):
    benign = BenignFiring(trials, hits, binomial_u95(trials, hits), "c@r:OUT:all",
                          "2026-09-06T00:00:00+00:00")
    lane, reason = admit(rule_with(benign), bundle_ok=True)
    if ceiling == DENY_MAX_U95:
        assert lane is not Lane.DENY, reason
    else:
        assert lane is Lane.RECORD, reason


def test_a_bound_clear_of_a_ceiling_still_resolves():
    """The slack must not swallow ordinary measurements."""
    assert bound_within(1743, 1, ADVISE_MAX_U95) is True
    assert bound_within(1743, 1, DENY_MAX_U95) is False
    assert bound_within(3556, 0, ADVISE_MAX_U95) is True
    assert bound_within(10, 0, ADVISE_MAX_U95) is False


def test_the_zero_hit_ceiling_is_the_closed_form_and_agrees_with_it():
    for threshold in (ADVISE_MAX_U95, DENY_MAX_U95):
        limit = math.ceil(math.log(0.05) / math.log1p(-threshold))
        assert bound_within(limit, 0, threshold) is True
        assert u95_zero_hits(limit) <= threshold
        assert bound_within(limit - 1, 0, threshold) is False
        assert u95_zero_hits(limit - 1) > threshold


def test_a_point_estimate_at_or_above_the_ceiling_is_refused_without_summing():
    assert bound_within(1000, 5, 0.005) is False
    assert bound_within(1000, 900, 0.005) is False
    assert bound_within(1000, 1000, 0.005) is False


def test_an_unresolved_comparison_is_reported_as_none_not_as_a_side():
    """Constructed so the CDF at the ceiling sits inside the slack."""
    trials, hits, ceiling = 5023741, 4907, DENY_MAX_U95
    delta = abs(math.log(exact_cdf(trials, hits, ceiling)) - math.log(0.05))
    assert delta < LOG_CDF_SLACK
    assert bound_within(trials, hits, ceiling) is None


def test_the_arguments_are_checked():
    for bad in [(-1, 0, 0.005), (10, 11, 0.005), (10.0, 1, 0.005), (10, 1.0, 0.005)]:
        with pytest.raises(ValueError):
            bound_within(*bad)
    for bad_threshold in (0.0, 1.0, -0.1, 2.0):
        with pytest.raises(ValueError):
            bound_within(1000, 1, bad_threshold)


#: Counts above the supported domain whose float log-CDF lands outside the
#: refusal band on the wrong side. Round 3 built these; the mechanism is the
#: lgamma coefficient, whose measured error against a 60-digit loggamma reaches
#: 3.9e-6 at a billion trials and 9.7e-6 at 4.6 billion, against a 1e-6 band.
OUTSIDE_DOMAIN = [(4550422216, 4546915, DENY_MAX_U95),
                  (1589620769, 7943478, ADVISE_MAX_U95)]


@pytest.mark.parametrize("trials,hits,ceiling", OUTSIDE_DOMAIN)
def test_counts_above_the_supported_domain_are_refused_not_answered(trials, hits, ceiling):
    assert trials > MAX_SUPPORTED_TRIALS
    assert bound_within(trials, hits, ceiling) is None


@pytest.mark.parametrize("trials,hits,ceiling", OUTSIDE_DOMAIN)
def test_admit_does_not_certify_a_lane_outside_the_supported_domain(trials, hits, ceiling):
    """The cap has to live in the arithmetic, not only in one adapter's reader.

    Before this, only the Claude Code evidence reader capped trials, so admit
    and the benchmark answered for counts the slack was never measured over.
    """
    benign = BenignFiring(trials, hits, binomial_u95(trials, hits), "c@r:OUT:all",
                          "2026-09-06T00:00:00+00:00")
    lane, reason = admit(rule_with(benign), bundle_ok=True)
    assert lane is Lane.RECORD, reason
    assert "not certified" in reason


def test_the_domain_boundary_itself_still_answers():
    assert bound_within(MAX_SUPPORTED_TRIALS, 0, ADVISE_MAX_U95) is True
    assert bound_within(MAX_SUPPORTED_TRIALS + 1, 0, ADVISE_MAX_U95) is None
