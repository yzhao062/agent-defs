"""Admission lanes and the statistics behind them.

A detector that has never been measured on benign material does not get to
interrupt anybody. The bound below is what makes that rule enforceable rather
than a slogan.
"""

from __future__ import annotations

from functools import lru_cache
import math

from .model import BenignFiring, Lane, Rule

#: ``Lane.ADVISE`` needs the true benign firing rate bounded at or below this.
ADVISE_MAX_U95 = 0.005
#: ``Lane.DENY`` needs it bounded at or below this.
DENY_MAX_U95 = 0.001


def u95_zero_hits(trials: int) -> float:
    """Exact binomial 95% upper bound on a rate given zero hits in ``trials``.

    Solves ``(1 - p) ** trials = 0.05``. At 598 trials this returns 0.005, at
    2,995 it returns 0.001, and at ten trials it returns 0.259, which is why a
    handful of authored fixtures proves nothing.
    """
    if trials <= 0:
        return 1.0
    return 1.0 - 0.05 ** (1.0 / trials)


def trials_needed(target_u95: float) -> int:
    """Smallest clean trial count whose bound reaches ``target_u95``."""
    if not 0.0 < target_u95 < 1.0:
        raise ValueError("target_u95 must be in (0, 1)")
    return math.ceil(math.log(0.05) / math.log(1.0 - target_u95))


def log_binomial_cdf(trials: int, hits: int, p: float) -> float:
    """``ln P[Binomial(trials, p) <= hits]``, summed downwards from ``hits``.

    Summing down from the top term is stable whenever ``p`` is at or above
    ``hits / trials``, which is where every use here evaluates it.
    """
    coefficient = math.lgamma(trials + 1) - math.lgamma(hits + 1) - math.lgamma(trials - hits + 1)
    term = total = 1.0
    for k in range(hits, 0, -1):
        term *= k / (trials - k + 1) * (1 - p) / p
        total += term
        if term < total * 1e-16:
            break
    return coefficient + hits * math.log(p) + (trials - hits) * math.log1p(-p) + math.log(total)


#: The largest trial count :func:`bound_within` will answer for.
#:
#: This is a property of the arithmetic, not of any corpus. The dominant error
#: in a log-CDF comparison is the ``lgamma`` coefficient, and it grows with the
#: trial count: measured against a 60-digit ``loggamma``, it stays near 2.7e-8
#: at ten million and reaches 3.9e-6 at one billion and 9.7e-6 at 4.6 billion.
#: Past the cap it exceeds :data:`LOG_CDF_SLACK`, so the refusal band no longer
#: catches a wrong answer and the comparison is refused outright instead.
#: Benign corpora here are in the thousands.
MAX_SUPPORTED_TRIALS = 10_000_000

#: Slack on a log-CDF comparison. A comparison landing inside it is refused.
#:
#: **This is an empirical margin, not a derived bound.** An earlier version of
#: this comment derived roughly 5e-8 at the cap by treating each ``math.lgamma``
#: result as correctly rounded and counting three representational errors. That
#: derivation is wrong: CPython evaluates a Lanczos expression whose own
#: logarithms, products and sums carry error, and at 49,095 hits in 9,892,023
#: trials the coefficient's measured error is -8.36e-8, already larger than the
#: figure the derivation produced. What is measured, against a 60-digit
#: ``mpmath.loggamma`` over a sweep of trial counts and rates at or below
#: :data:`MAX_SUPPORTED_TRIALS`, is a worst absolute coefficient error near
#: 2.7e-8, so this value carries roughly thirty-fold headroom over what was
#: observed. No search has produced a wrong resolved decision inside the cap,
#: and none of that is a proof. Treat the pair as a fail-closed device: the
#: domain is capped where the error is known to grow past the band, and a
#: comparison inside the band is not answered.
LOG_CDF_SLACK = 1e-6


@lru_cache(maxsize=8192, typed=True)
def binomial_u95(trials: int, hits: int) -> float:
    """One-sided exact Clopper-Pearson upper limit, solved numerically.

    For nonzero hits, invert P[Binomial(n, p) <= hits] = .05.

    This lives here rather than in the benchmark because an adapter reading a
    stored measurement has to recompute the bound to check it, and it must be
    able to do that without importing the benchmark onto a hook's hot path.

    **This value is for reporting, and is not the thing to compare against a
    lane ceiling.** Inverting the CDF concentrates the coefficient's rounding
    error into the returned rate, and near a ceiling that error decides the
    lane. At 4,907 hits in 5,023,741 trials the exact bound is above 0.001,
    while this returns 0.0009999999999418658 on glibc and on Windows, so a
    direct comparison reads DENY where the arithmetic does not support it.

    It is worse than one wrong answer. The same call returns
    0.001000000000146392 on macOS, above the ceiling, so **which side of a
    ceiling this value falls on depends on the host's libm** and a lane decided
    by comparing it is a lane decided by the machine. :func:`bound_within`
    answers the comparison without inverting, and refuses when it cannot, which
    is the same refusal on every platform.

    No domain is enforced here, because a reported rate that is wrong in its
    last digits is a display problem rather than an admission one. The accuracy
    still degrades with the trial count in the same way, so a caller quoting
    this above :data:`MAX_SUPPORTED_TRIALS` is quoting more digits than the
    arithmetic carries.
    """
    if type(trials) is not int or type(hits) is not int or not 0 <= hits <= trials:
        raise ValueError("require integer 0 <= hits <= trials")
    if hits == 0:
        return u95_zero_hits(trials)
    if hits == trials:
        return 1.0
    low, high = hits / trials, 1.0
    for _ in range(64):
        p = (low + high) / 2
        if p == high or p == low:
            break
        if log_binomial_cdf(trials, hits, p) > math.log(0.05):
            low = p
        else:
            high = p
    return high


def bound_within(trials: int, hits: int, threshold: float):
    """Is the exact 95% upper bound at or below ``threshold``?

    Returns True, False, or None when double precision cannot resolve it.
    Every lane ceiling goes through here rather than through a float
    comparison against :func:`binomial_u95`, because the question is a
    single-point one: the bound is at or below ``threshold`` exactly when
    ``P[Binomial(trials, threshold) <= hits] <= 0.05``. Evaluating the CDF once
    at the threshold keeps the coefficient's error in the CDF, where
    :data:`LOG_CDF_SLACK` bounds it, instead of moving it into an inverted rate
    where nothing bounds it.

    A None is a refusal to certify, and every caller is expected to take the
    stricter lane on it. Two things produce one: a comparison whose log-CDF
    lands within :data:`LOG_CDF_SLACK` of ``log(0.05)``, and any trial count
    above :data:`MAX_SUPPORTED_TRIALS`.

    The domain is enforced here rather than by the callers. An earlier version
    capped trials only in the Claude Code adapter's evidence reader, which left
    this function and :func:`admit` certifying counts the slack was never
    measured over: at 4,546,915 hits in 4,550,422,216 trials the coefficient's
    error is near 1e-5, ten times the band, so a wrong side can be returned
    without ever landing inside it.
    """
    if type(trials) is not int or type(hits) is not int or not 0 <= hits <= trials:
        raise ValueError("require integer 0 <= hits <= trials")
    if not 0.0 < threshold < 1.0:
        raise ValueError("threshold must be in (0, 1)")
    if trials > MAX_SUPPORTED_TRIALS:
        return None
    if hits == trials:
        return False
    if hits == 0:
        # 1 - 0.05 ** (1 / n) <= t rearranges to n >= log(0.05) / log1p(-t),
        # both logs being negative. The quotient is small enough that only a
        # near-integer limit is unresolved.
        limit = math.log(0.05) / math.log1p(-threshold)
        return None if abs(trials - limit) < 1e-6 else trials >= limit
    if hits / trials >= threshold:
        # The bound is above the point estimate, so it is above the threshold,
        # and the downward sum is outside the range where it stays stable.
        return False
    delta = log_binomial_cdf(trials, hits, threshold) - math.log(0.05)
    return None if abs(delta) < LOG_CDF_SLACK else delta < 0.0


def u95_from(measurement: BenignFiring) -> float:
    """Bound implied by a measurement, using the stored value when hits > 0.

    An adapter is expected to have checked that stored value against
    :func:`binomial_u95` before it got here; this does not re-derive it.
    """
    if measurement.hits == 0:
        return u95_zero_hits(measurement.trials)
    return measurement.u95


def admit(rule: Rule, *, bundle_ok: bool = False) -> tuple[Lane, str]:
    """Return the highest lane ``rule`` qualifies for, and why.

    ``bundle_ok`` records that the whole enabled bundle passed its noise test
    together. One quiet rule inside a loud bundle still produces a loud tool.
    """
    # A rule with no flat predicate can still run through its source's own
    # dispatcher: ATR's skill path resolves every condition field to the whole
    # document and never composes conditions, so constructs the flat predicate
    # refuses are expressible there. Such a rule is measurable, and therefore
    # admissible, on the channel that binding names.
    if not rule.runnable and not any(bound.executable for bound in rule.bindings):
        return Lane.DO_NOT_SHIP, f"not mechanically runnable: {rule.not_runnable_reason}"
    if rule.benign is None:
        return Lane.RECORD, "no benign measurement"

    bound = u95_from(rule.benign)
    if not bundle_ok:
        return Lane.RECORD, f"u95={bound:.4f} but the bundle was not measured together"
    trials, hits = rule.benign.trials, rule.benign.hits
    advise = bound_within(trials, hits, ADVISE_MAX_U95)
    if advise is None:
        return Lane.RECORD, (f"u95={bound:.4f} sits within {LOG_CDF_SLACK} of the advise "
                             f"ceiling {ADVISE_MAX_U95} in this arithmetic; not certified")
    if advise is False:
        return Lane.RECORD, f"u95={bound:.4f} exceeds the advise ceiling {ADVISE_MAX_U95}"
    deny = bound_within(trials, hits, DENY_MAX_U95)
    if deny is not True:
        return Lane.ADVISE, f"u95={bound:.4f} within the advise ceiling"
    return Lane.DENY, f"u95={bound:.4f} within the deny ceiling"
