"""Bounded evaluation of normalized predicates.

Three properties this module owes its caller, in order of how badly a failure
would hurt:

1. **It never executes source content.** A corpus record is data. Nothing here
   compiles a rule into code, renders it into a file an agent reads, or passes
   it to a shell. The corpora carry jailbreak payloads, so a design that let
   rule text reach an instruction file would be an injection channel rather
   than a defence.
2. **It is bounded.** A hook sits in front of the user's tool calls. It gets a
   byte cap on what it reads and a wall-clock budget across the whole scan, and
   it returns what it has when the budget runs out rather than running long.
3. **It is deterministic and it shows its work.** Every hit records the rule,
   the offset and the matched span, so a person can see why something fired.

``re`` offers no timeout, so the budget is enforced between rules rather than
inside one. That is the reason patterns are screened at build time: a pattern
that can backtrack catastrophically must be rejected before it ships, because
once it is running nothing here can interrupt it.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Iterable, Sequence

from .model import PredicateKind, Rule

#: Most bytes of one payload that will be scanned. A tool result larger than
#: this is truncated, and the finding records that it was.
DEFAULT_MAX_BYTES = 256 * 1024
#: Wall-clock budget for a whole scan, in seconds.
DEFAULT_BUDGET_S = 0.25


@dataclass(frozen=True)
class Finding:
    rule_id: str
    surface: str
    start: int
    end: int
    matched: str
    truncated_input: bool = False


@dataclass(frozen=True)
class ScanResult:
    findings: Sequence[Finding]
    rules_evaluated: int
    rules_skipped_budget: int
    elapsed_s: float
    truncated_input: bool


class UnsafePattern(ValueError):
    """Raised when a pattern is rejected before it can ever run."""


_MAX_PATTERN_LEN = 4096
_QUANTIFIERS = "*+{"


def _has_nested_quantifier(pattern: str) -> bool:
    """True when a quantified group is itself under a quantifier.

    ``(a+)+`` and ``(a*)*`` are the shape that turns a linear match into an
    exponential one. Finding them needs a paren stack rather than a regex,
    because a regex cannot count nesting and a character class can hold a
    parenthesis that means nothing.
    """
    stack: list[bool] = []          # per open group: did it contain a quantifier
    in_class = False
    i = 0
    n = len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == "\\":
            i += 2
            continue
        if in_class:
            if ch == "]":
                in_class = False
            i += 1
            continue
        if ch == "[":
            in_class = True
        elif ch == "(":
            stack.append(False)
        elif ch == ")":
            had_quantifier = stack.pop() if stack else False
            follower = pattern[i + 1] if i + 1 < n else ""
            if had_quantifier and follower in _QUANTIFIERS:
                return True
        elif ch in _QUANTIFIERS:
            if stack:
                stack[-1] = True
        i += 1
    return False


def screen_pattern(pattern: str) -> None:
    """Reject a pattern that must not be compiled into a shipped bundle.

    Screening happens at build time, never in the hot path. The checks are
    deliberately blunt: a pattern this module cannot vouch for stays out of the
    bundle rather than being handed a budget it cannot be held to.
    """
    if len(pattern) > _MAX_PATTERN_LEN:
        raise UnsafePattern(f"pattern longer than {_MAX_PATTERN_LEN} characters")
    if _has_nested_quantifier(pattern):
        raise UnsafePattern("quantified group under an outer quantifier")
    try:
        re.compile(pattern)
    except re.error as exc:
        raise UnsafePattern(f"does not compile: {exc}") from exc


def compile_rule(rule: Rule) -> object:
    """Return the runtime object for ``rule``'s predicate, or None."""
    if rule.predicate_kind is PredicateKind.NONE:
        return None
    flags = 0 if rule.case_sensitive else re.IGNORECASE
    if rule.predicate_kind is PredicateKind.REGEX:
        screen_pattern(str(rule.predicate))
        return re.compile(str(rule.predicate), flags)
    if rule.predicate_kind in (PredicateKind.SUBSTRING_ANY, PredicateKind.SUBSTRING_ALL):
        needles = [str(n) for n in rule.predicate]  # type: ignore[union-attr]
        if not rule.case_sensitive:
            needles = [n.lower() for n in needles]
        return needles
    raise NotImplementedError(f"{rule.predicate_kind} has no runtime yet")


def _search_substrings(rule: Rule, needles: Sequence[str], hay: str) -> Finding | None:
    probe = hay if rule.case_sensitive else hay.lower()
    if rule.predicate_kind is PredicateKind.SUBSTRING_ALL:
        first: Finding | None = None
        for needle in needles:
            at = probe.find(needle)
            if at < 0:
                return None
            if first is None:
                first = Finding(rule.id, rule.surface.value, at, at + len(needle), hay[at:at + len(needle)])
        return first
    for needle in needles:
        at = probe.find(needle)
        if at >= 0:
            return Finding(rule.id, rule.surface.value, at, at + len(needle), hay[at:at + len(needle)])
    return None


def scan(
    payload: str,
    rules: Iterable[Rule],
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
    budget_s: float = DEFAULT_BUDGET_S,
    compiled: dict | None = None,
) -> ScanResult:
    """Run ``rules`` over ``payload`` under a byte cap and a time budget.

    Rules are evaluated in the order given. When the budget runs out the
    remaining rules are counted and skipped, so the caller can tell a clean
    empty result from a truncated one.
    """
    truncated = False
    if len(payload.encode("utf-8", "ignore")) > max_bytes:
        payload = payload.encode("utf-8", "ignore")[:max_bytes].decode("utf-8", "ignore")
        truncated = True

    cache = compiled if compiled is not None else {}
    findings: list[Finding] = []
    evaluated = 0
    skipped = 0
    started = time.perf_counter()

    rules = list(rules)
    for index, rule in enumerate(rules):
        if time.perf_counter() - started > budget_s:
            skipped = len(rules) - index
            break
        runtime = cache.get(rule.id)
        if runtime is None:
            runtime = compile_rule(rule)
            cache[rule.id] = runtime
        if runtime is None:
            continue
        evaluated += 1
        if rule.predicate_kind is PredicateKind.REGEX:
            hit = runtime.search(payload)
            if hit:
                findings.append(
                    Finding(rule.id, rule.surface.value, hit.start(), hit.end(), hit.group(0), truncated)
                )
        else:
            hit_f = _search_substrings(rule, runtime, payload)
            if hit_f is not None:
                findings.append(
                    Finding(hit_f.rule_id, hit_f.surface, hit_f.start, hit_f.end, hit_f.matched, truncated)
                )

    return ScanResult(
        findings=tuple(findings),
        rules_evaluated=evaluated,
        rules_skipped_budget=skipped,
        elapsed_s=time.perf_counter() - started,
        truncated_input=truncated,
    )
