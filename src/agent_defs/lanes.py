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


@lru_cache(maxsize=8192, typed=True)
def binomial_u95(trials: int, hits: int) -> float:
    """One-sided exact Clopper-Pearson upper limit, solved numerically.

    For nonzero hits, invert P[Binomial(n, p) <= hits] = .05. Summing
    downwards from hits is stable because the root is above hits / trials.

    This lives here rather than in the benchmark because an adapter reading a
    stored measurement has to recompute the bound to check it, and it must be
    able to do that without importing the benchmark onto a hook's hot path.
    """
    if type(trials) is not int or type(hits) is not int or not 0 <= hits <= trials:
        raise ValueError("require integer 0 <= hits <= trials")
    if hits == 0:
        return u95_zero_hits(trials)
    if hits == trials:
        return 1.0
    low, high = hits / trials, 1.0
    coefficient = math.lgamma(trials + 1) - math.lgamma(hits + 1) - math.lgamma(trials - hits + 1)
    for _ in range(64):
        p = (low + high) / 2
        if p == high or p == low:
            break
        term = total = 1.0
        for k in range(hits, 0, -1):
            term *= k / (trials - k + 1) * (1 - p) / p
            total += term
            if term < total * 1e-16:
                break
        log_cdf = coefficient + hits * math.log(p) + (trials - hits) * math.log1p(-p) + math.log(total)
        if log_cdf > math.log(0.05):
            low = p
        else:
            high = p
    return high


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
    if bound > ADVISE_MAX_U95:
        return Lane.RECORD, f"u95={bound:.4f} exceeds the advise ceiling {ADVISE_MAX_U95}"
    if bound > DENY_MAX_U95:
        return Lane.ADVISE, f"u95={bound:.4f} within the advise ceiling"
    return Lane.DENY, f"u95={bound:.4f} within the deny ceiling"
