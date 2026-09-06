"""Bounded, dependency-free evaluation of normalized predicates.

Screening refuses a pattern on measurement where a measurement exists and on
shape where none does; neither is a linearity proof. All compilation and
matching for scan() runs in a disposable process killed at the scan deadline.
Results distinguish completed checks, rejected rules, unfinished work and worker
failure. OS scheduling and cleanup are not real-time operations.

**Why measurement outranks shape.** The shape screen recognises two AST forms.
Round three timed all 3,320 patterns in the pinned ATR corpus and found 296 of
793 rules crossing one second, 220 of them shipped, against 86 refused for a
nested quantifier of which 44 never crossed at any length up to 1 MiB. A test
that is wrong in both directions is not evidence, and where a direct measurement
of the same property exists it decides. The two directions are not symmetric: a
found witness proves slowness, so a slow verdict refuses; a search that found no
witness is evidence rather than proof, so a fast verdict admits and leaves the
runtime deadline as the backstop. Nothing here removes that backstop. Python's
``re`` cannot be interrupted mid-match, so ``scan`` still kills its worker at the
deadline, and a pattern nobody measured is still screened on shape and says so
in its refusal.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from itertools import islice
from typing import Iterable, Mapping, Sequence

from .model import PredicateKind, Rule

DEFAULT_MAX_BYTES = 4 * 1024 * 1024
DEFAULT_BUDGET_S = 0.25
# Bounds one upstream-authored pattern, never a string this package composes.
# The longest pattern any of the six pinned corpora publishes is 2,213
# characters (ATR-2026-02502) and the largest condition count is 46
# (ATR-2026-00001), so both limits carry real headroom over the input. A
# composition that would exceed them is split, never dropped: a length limit is
# a representability filter and may not decide whether a rule ships.
_MAX_PATTERN_LEN = 4096
_MAX_RULES = 4096
_MAX_NEEDLES = 64
_MAX_BUNDLE_CHARS = 1024 * 1024
_MAX_INPUT_BYTES = 4 * 1024 * 1024
_CLEANUP_S = 0.1
_SUPERVISORS = threading.BoundedSemaphore(4)
HAZARD_TABLE_PATH = Path(__file__).with_name("hazards.json")
_HIGH_SURROGATES = (0xD800, 0xDBFF)
_LOW_SURROGATES = (0xDC00, 0xDFFF)
_MAX_PORTED_RANGES = 64


@dataclass(frozen=True)
class Finding:
    """Coordinates only. Recover evidence from the original input outside the model."""

    rule_id: str
    surface: str
    start: int
    end: int


@dataclass(frozen=True)
class RuleError:
    rule_id: str
    reason: str


@dataclass(frozen=True)
class ScanResult:
    partial_findings: Sequence[Finding]
    rules_evaluated: int
    rules_skipped_budget: int
    elapsed_s: float
    truncated_input: bool
    errors: Sequence[RuleError] = ()
    worker_error: str | None = None

    @property
    def complete(self) -> bool:
        return not (self.truncated_input or self.rules_skipped_budget or self.errors or self.worker_error)

    def require_complete(self) -> ScanResult:
        if not self.complete:
            raise IncompleteScanError(self)
        return self

    @property
    def findings(self) -> Sequence[Finding]:
        """A negative result is meaningful only after every required check finished."""
        self.require_complete()
        return self.partial_findings

    def __bool__(self):
        raise TypeError("use result.complete and result.findings explicitly")


class IncompleteScanError(RuntimeError):
    def __init__(self, result: ScanResult):
        super().__init__("incomplete scan; use partial_findings only with an explicit incomplete-scan policy")
        self.result = result


class UnsafePattern(ValueError):
    """A pattern failed syntax validation or conservative hazard screening."""


@dataclass(frozen=True)
class Measurement:
    """One pattern's timed backtracking behaviour, carried as build-time data.

    ``verdict`` is ``"slow"`` when a witness was found that held a single
    ``re.search`` past ``budget_s``, and ``"fast"`` when the search found no such
    witness at any tested length. ``crossing_bytes`` and ``wall_s`` describe the
    smallest crossing found, so a caller that caps its input below
    ``crossing_bytes`` can see the headroom it has.
    """

    verdict: str
    budget_s: float
    crossing_bytes: int | None = None
    wall_s: float | None = None
    over_60s: bool = False
    method: str = ""
    measured_at: str = ""
    label: str = ""

    @property
    def slow(self) -> bool:
        return self.verdict == "slow"

    def refusal(self) -> str:
        """A one-line reason. ``method`` stays in the record rather than the message."""
        return (f"measured {self.wall_s:.2f} s on {self.crossing_bytes} bytes against a "
                f"{self.budget_s:g} s budget"
                + (" and still running at 60 s" if self.over_60s else "")
                + (f" ({self.label})" if self.label else ""))


_HAZARD_CACHE: dict | None = None


def _hazard_table() -> Mapping[str, object]:
    """Load the measurement table once. A missing or broken table screens on shape."""
    global _HAZARD_CACHE
    if _HAZARD_CACHE is None:
        try:
            data = json.loads(HAZARD_TABLE_PATH.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("hazard table must be an object")
            for key in ("patterns", "rules"):
                if not isinstance(data.get(key), dict):
                    data[key] = {}
            data["budget_s"] = float(data.get("budget_s", 1.0))
        except (OSError, ValueError, TypeError):
            data = {"patterns": {}, "rules": {}, "budget_s": 1.0, "method": "", "measured_at": ""}
        _HAZARD_CACHE = data
    return _HAZARD_CACHE


def hazard_table() -> Mapping[str, object]:
    """The loaded measurement table, for reporting and tests."""
    return _hazard_table()


def _fingerprint(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()[:16]


def _measurement_from_row(row, table) -> Measurement | None:
    if not isinstance(row, (list, tuple)) or not row:
        return None
    verdict = row[0]
    if verdict not in ("slow", "fast"):
        return None
    crossing = row[1] if len(row) > 1 else None
    wall = row[2] if len(row) > 2 else None
    over = bool(row[3]) if len(row) > 3 else False
    if verdict == "slow" and not (isinstance(crossing, int) and isinstance(wall, (int, float))):
        return None
    return Measurement(verdict=verdict, budget_s=float(table.get("budget_s", 1.0)),
                       crossing_bytes=crossing, wall_s=wall, over_60s=over,
                       method=str(table.get("method", "")),
                       measured_at=str(table.get("measured_at", "")),
                       label=str(table.get("measurement_id", "")))


def measurement_for_pattern(pattern: str) -> Measurement | None:
    """The recorded verdict for this exact pattern text, or None if unmeasured."""
    if not isinstance(pattern, str):
        return None
    table = _hazard_table()
    return _measurement_from_row(table["patterns"].get(_fingerprint(pattern)), table)


def measurement_for_rule(source: str, source_id: str, patterns: Sequence[str]) -> Measurement | None:
    """The recorded verdict for a whole rule, keyed by identity and content.

    The identity alone is not enough: a source can edit a rule's conditions
    without changing its id, and the stale verdict would then decide a pattern
    nobody timed. The stored digest covers the rule's own condition texts in
    order, so an edited rule falls back to shape screening.
    """
    table = _hazard_table()
    row = table["rules"].get(f"{source}:{source_id}")
    if not isinstance(row, (list, tuple)) or len(row) < 2:
        return None
    if row[0] != _fingerprint("\n".join(patterns)):
        return None
    return _measurement_from_row(row[1:], table)


def _surrogate_class_items(body: str):
    """Ranges in a class body written only as ``\\uXXXX`` literals and ranges."""
    if body.startswith("^"):
        return None
    items, index, size = [], 0, len(body)
    while index < size:
        if body[index:index + 2] != "\\u" or not re.fullmatch(r"[0-9a-fA-F]{4}", body[index + 2:index + 6]):
            return None
        low = high = int(body[index + 2:index + 6], 16)
        index += 6
        if (body[index:index + 1] == "-" and body[index + 1:index + 3] == "\\u"
                and re.fullmatch(r"[0-9a-fA-F]{4}", body[index + 3:index + 7])):
            high = int(body[index + 3:index + 7], 16)
            index += 7
        if high < low:
            return None
        items.append((low, high))
    return items or None


def _scan_regex_tokens(pattern: str):
    """Split a pattern into ``\\uXXXX`` escapes, character classes and everything else."""
    tokens, index, size = [], 0, len(pattern)
    while index < size:
        char = pattern[index]
        if char == "\\":
            if (pattern[index + 1:index + 2] == "u"
                    and re.fullmatch(r"[0-9a-fA-F]{4}", pattern[index + 2:index + 6])):
                tokens.append({"kind": "u", "raw": pattern[index:index + 6],
                               "items": [(int(pattern[index + 2:index + 6], 16),) * 2]})
                index += 6
                continue
            tokens.append({"kind": "raw", "raw": pattern[index:index + 2]})
            index += 2
            continue
        if char == "[":
            cursor = index + 1
            if pattern[cursor:cursor + 1] == "^":
                cursor += 1
            if pattern[cursor:cursor + 1] == "]":
                cursor += 1
            while cursor < size and pattern[cursor] != "]":
                cursor += 2 if pattern[cursor] == "\\" else 1
            if cursor >= size:  # unterminated; leave it for re to report
                tokens.append({"kind": "raw", "raw": pattern[index:]})
                break
            body = pattern[index + 1:cursor]
            tokens.append({"kind": "class", "raw": pattern[index:cursor + 1],
                           "items": _surrogate_class_items(body)})
            index = cursor + 1
            continue
        tokens.append({"kind": "raw", "raw": char})
        index += 1
    return tokens


def _within(items, bounds) -> bool:
    return bool(items) and all(bounds[0] <= low and high <= bounds[1] for low, high in items)


def _surrogate_escapes(text: str) -> list[str]:
    """Every ``\\uXXXX`` escape naming a surrogate, class bodies included.

    Walks the source with the same backslash parity a regex engine uses, so an
    escaped backslash before ``uDB40`` stays the two characters it is.
    """
    found, index, size = [], 0, len(text)
    while index < size:
        if text[index] != "\\":
            index += 1
            continue
        if text[index + 1:index + 2] == "u" and re.fullmatch(r"[0-9a-fA-F]{4}", text[index + 2:index + 6]):
            code = int(text[index + 2:index + 6], 16)
            if _HIGH_SURROGATES[0] <= code <= _LOW_SURROGATES[1]:
                found.append(text[index:index + 6])
            index += 6
            continue
        index += 2
    return found


def _combine_surrogates(highs, lows):
    """Code-point ranges for every high/low pair, or None when it would explode."""
    ranges = []
    for high_low, high_high in highs:
        for low_low, low_high in lows:
            if (low_low, low_high) == _LOW_SURROGATES:
                ranges.append((0x10000 + (high_low - 0xD800) * 0x400,
                               0x10000 + (high_high - 0xD800) * 0x400 + 0x3FF))
                continue
            if high_high - high_low + len(ranges) >= _MAX_PORTED_RANGES:
                return None
            for high in range(high_low, high_high + 1):
                base = 0x10000 + (high - 0xD800) * 0x400
                ranges.append((base + low_low - 0xDC00, base + low_high - 0xDC00))
    return ranges if len(ranges) <= _MAX_PORTED_RANGES else None


def _render_ranges(ranges) -> str:
    if len(ranges) == 1 and ranges[0][0] == ranges[0][1]:
        return "\\U%08X" % ranges[0][0]
    body = "".join("\\U%08X" % low if low == high else "\\U%08X-\\U%08X" % (low, high)
                   for low, high in ranges)
    return f"[{body}]"


def port_utf16_surrogates(pattern: str) -> tuple[str, list[dict]]:
    """Rewrite UTF-16 surrogate pairs as the code points they encode.

    A regex authored against a JavaScript engine matches UTF-16 code units, so
    ``\\uDB40[\\uDC00-\\uDC7F]`` there means the Unicode tag block. Python matches
    code points and sees two unpaired surrogates, which no well-formed text
    contains, so the same pattern silently returns nothing. This is a dialect
    port and it belongs to the loader that knows which engine wrote the rule;
    it changes what the pattern is written in, never what it means.

    A quantifier immediately after a pair is left alone. ``\\uD83D\\uDE00+`` means
    one high surrogate and one or more low ones, which no sequence of code points
    says, so folding the pair would quietly change the pattern. The surrogates
    then stay unpaired and are refused, which is the fail-closed direction.

    Returns the ported pattern and one note per rewrite. Surrogates left unpaired
    afterwards are reported in a final note with ``"unpaired": True``; those are a
    representability limit rather than a defect this function can fix, and
    ``screen_pattern`` refuses them rather than shipping a pattern that cannot match.
    """
    if not isinstance(pattern, str) or "\\u" not in pattern.lower():
        return pattern, []
    tokens = _scan_regex_tokens(pattern)
    out, notes, index = [], [], 0
    while index < len(tokens):
        token = tokens[index]
        nxt = tokens[index + 1] if index + 1 < len(tokens) else None
        after = tokens[index + 2] if index + 2 < len(tokens) else None
        highs = token.get("items")
        lows = nxt.get("items") if nxt else None
        quantified = bool(after) and after["raw"][:1] in ("*", "+", "?", "{")
        if not quantified and _within(highs, _HIGH_SURROGATES) and _within(lows, _LOW_SURROGATES):
            ranges = _combine_surrogates(highs, lows)
            if ranges is not None:
                ported = _render_ranges(ranges)
                notes.append({"from": token["raw"] + nxt["raw"], "to": ported,
                              "reason": "UTF-16 surrogate pair read as one code point"})
                out.append(ported)
                index += 2
                continue
        out.append(token["raw"])
        index += 1
    result = "".join(out)
    leftover = _surrogate_escapes(result)
    if leftover:
        notes.append({"unpaired": True, "escapes": sorted(set(leftover)),
                      "reason": "unpaired UTF-16 surrogate has no code-point image"})
    return result, notes


def _parse_pattern(pattern: str, flags: int):
    if not isinstance(pattern, str):
        raise UnsafePattern("pattern must be a string")
    if len(pattern) > _MAX_PATTERN_LEN:
        raise UnsafePattern(f"pattern longer than {_MAX_PATTERN_LEN} characters")
    # Python exposes no public regex AST. Keep the version dependency in one place.
    if sys.version_info >= (3, 11):
        from re import _parser as parser
    else:
        import sre_parse as parser
    try:
        return parser.parse(pattern, flags)
    except (re.error, OverflowError, RecursionError, ValueError) as exc:
        raise UnsafePattern(f"does not compile: {exc}") from exc


def _hazards(tree) -> tuple[bool, bool, bool]:
    nested = branching = reference = False
    pending = [(tree, False)]
    while pending:
        nodes, repeated = pending.pop()
        for op, arg in nodes:
            name = str(op)
            if name in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"):
                low, high, child = arg
                nested |= repeated and (high > 1 or low != high)
                pending.append((child, repeated or high > 1))
            elif name == "SUBPATTERN":
                pending.append((arg[-1], repeated))
            elif name == "BRANCH":
                branching |= repeated
                pending.extend((child, repeated) for child in arg[1])
            elif name in ("ASSERT", "ASSERT_NOT"):
                pending.append((arg[1], repeated))
            elif name == "ATOMIC_GROUP":
                pending.append((arg, repeated))
            elif name.startswith("GROUPREF"):
                reference = True
    return nested, branching, reference


def _has_nested_quantifier(pattern: str, flags: int = 0) -> bool:
    """Inspect Python's parsed syntax, including flags, escapes and classes.

    An optional outer group is allowed; repeating a variable or repeated child
    more than once is rejected conservatively, even through group wrappers.
    """
    return _hazards(_parse_pattern(pattern, flags))[0]


def _has_surrogate_literal(tree) -> bool:
    pending = [tree]
    while pending:
        for op, arg in pending.pop():
            name = str(op)
            if name in ("LITERAL", "NOT_LITERAL"):
                if _HIGH_SURROGATES[0] <= arg <= _LOW_SURROGATES[1]:
                    return True
            elif name == "RANGE":
                if arg[0] <= _LOW_SURROGATES[1] and arg[1] >= _HIGH_SURROGATES[0]:
                    return True
            elif name == "IN":
                pending.append(arg)
            elif name in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"):
                pending.append(arg[-1])
            elif name == "SUBPATTERN":
                pending.append(arg[-1])
            elif name == "BRANCH":
                pending.extend(arg[1])
            elif name in ("ASSERT", "ASSERT_NOT"):
                pending.append(arg[1])
            elif name == "ATOMIC_GROUP":
                pending.append(arg)
    return False


def screen_pattern(pattern: str, flags: int = re.IGNORECASE, *,
                   measurement: "Measurement | None" = None,
                   require_measurement: bool = False) -> None:
    """Refuse a pattern on measurement first, on shape only where none exists.

    ``measurement`` lets a loader supply the verdict recorded for the whole rule
    this pattern belongs to; without it the pattern's own text is looked up in
    the shipped table. A slow verdict refuses, because a witness that crossed the
    budget is proof. A fast verdict admits, because a search that found no
    witness is evidence and the runtime deadline still bounds the cost of being
    wrong; it therefore overrides the shape screen, whose refusals reproduce at
    49% precision against this corpus. Unmeasured patterns keep the shape screen
    and say so in the refusal, so a reader can tell a measured refusal from a
    guessed one.

    Neither path is a linearity proof. scan() validates again inside its isolated
    worker so stale or unscreened data cannot bypass this, and matching must
    still be isolated after this passes.
    """
    tree = _parse_pattern(pattern, flags)
    nested, branching, reference = _hazards(tree)
    # The unconditional capability limits are reported first. A backreference is
    # refused whatever it costs, so naming its timing instead would tell a reader
    # less; a caller that also wants the timing reads it from the measurement.
    if reference:
        raise UnsafePattern("backreferences and conditional references are not supported")
    # The exact row for this pattern text is consulted first and always. A caller
    # may supply the verdict recorded for the whole rule, but timing independent
    # branches does not time their composition, and timing an unported surrogate
    # expression says little about its port, so a supplied fast verdict must never
    # defeat an exact slow one.
    recorded = measurement_for_pattern(pattern)
    if recorded is not None and recorded.slow:
        raise UnsafePattern(recorded.refusal())
    if measurement is not None and measurement.slow:
        raise UnsafePattern(measurement.refusal())
    if require_measurement and recorded is None:
        raise UnsafePattern("pattern has no exact measurement; unmeasured")
    measurement = recorded if recorded is not None else measurement
    if measurement is None:
        if nested:
            raise UnsafePattern("quantified group under an outer quantifier, unmeasured")
        if branching:
            raise UnsafePattern("alternation under repetition, unmeasured")
    if _has_surrogate_literal(tree):
        raise UnsafePattern("unpaired UTF-16 surrogate cannot match well-formed text; "
                            "port the source dialect's surrogate pairs first")
    try:
        re.compile(pattern, flags)
    except (re.error, OverflowError, RecursionError, ValueError) as exc:
        raise UnsafePattern(f"does not compile: {exc}") from exc


_STRUCTURED_MODES = ("regex_all", "regex_any")
MAX_STRUCTURED_PATTERNS = _MAX_NEEDLES


def _structured_patterns(predicate) -> tuple[str, Sequence[str]]:
    """Read a STRUCTURED predicate: one ``regex_all`` or ``regex_any`` list.

    ``regex_any`` exists so that a source's disjunction of conditions stays a
    disjunction of the conditions its authors wrote. Joining them into one
    alternation is this package's own rewrite, and when the join no longer fits a
    limit that bounds upstream text the branches are kept instead of the rule
    being dropped.
    """
    if not isinstance(predicate, dict) or len(predicate) != 1 or set(predicate) - set(_STRUCTURED_MODES):
        raise ValueError("STRUCTURED requires exactly one regex_all or regex_any list")
    mode = next(iter(predicate))
    patterns = predicate[mode]
    if not isinstance(patterns, (list, tuple)) or not 1 <= len(patterns) <= _MAX_NEEDLES:
        raise ValueError(f"{mode} requires 1 to {_MAX_NEEDLES} patterns")
    if any(not isinstance(p, str) or len(p) > _MAX_PATTERN_LEN for p in patterns):
        raise ValueError(f"{mode} patterns must be strings of at most {_MAX_PATTERN_LEN} characters")
    return mode, patterns


def _regex_all_patterns(predicate) -> Sequence[str]:
    """Back-compatible accessor for the conjunction form."""
    mode, patterns = _structured_patterns(predicate)
    if mode != "regex_all":
        raise ValueError("STRUCTURED requires exactly a regex_all list")
    return patterns


@dataclass(frozen=True)
class _RegexAll:
    patterns: Sequence[re.Pattern]

    def search(self, payload: str):
        first = None
        for pattern in self.patterns:
            hit = pattern.search(payload)
            if hit is None:
                return None
            if first is None:
                first = hit
        return first


@dataclass(frozen=True)
class _RegexAny:
    """Alternation semantics without the alternation: leftmost hit, earliest branch."""

    patterns: Sequence[re.Pattern]

    def search(self, payload: str):
        best = None
        for pattern in self.patterns:
            hit = pattern.search(payload)
            if hit is not None and (best is None or hit.start() < best.start()):
                best = hit
                if best.start() == 0:
                    break
        return best


def compile_rule(rule: Rule) -> object:
    """Build a runtime predicate. Call at build time or inside the scan worker.

    The returned re objects do not themselves enforce a deadline. Use scan() for
    untrusted payloads. Substrings use escaped literals and Python re case rules;
    neither normalization nor full multi-character Unicode folding is applied.
    """
    if rule.predicate_kind is PredicateKind.NONE:
        return None
    flags = 0 if rule.case_sensitive else re.IGNORECASE
    if rule.predicate_kind is PredicateKind.REGEX:
        screen_pattern(rule.predicate, flags,
                       require_measurement=(rule.source == "atr"))
        return re.compile(rule.predicate, flags)
    if rule.predicate_kind is PredicateKind.STRUCTURED:
        mode, patterns = _structured_patterns(rule.predicate)
        for pattern in patterns:
            screen_pattern(pattern, flags,
                           require_measurement=(rule.source == "atr"))
        compiled = tuple(re.compile(pattern, flags) for pattern in patterns)
        return _RegexAll(compiled) if mode == "regex_all" else _RegexAny(compiled)
    if rule.predicate_kind in (PredicateKind.SUBSTRING_ANY, PredicateKind.SUBSTRING_ALL):
        if not isinstance(rule.predicate, (list, tuple)) or not 1 <= len(rule.predicate) <= _MAX_NEEDLES:
            raise ValueError(f"substrings require 1 to {_MAX_NEEDLES} needles")
        if any(not isinstance(n, str) or not n or len(n) > _MAX_PATTERN_LEN for n in rule.predicate):
            raise ValueError("needles must be nonempty strings of at most 4096 characters")
        return tuple(re.compile(re.escape(n), flags) for n in rule.predicate)
    raise NotImplementedError(f"{rule.predicate_kind} has no runtime yet")


def _search_substrings(rule: Rule, needles: Sequence[re.Pattern], hay: str) -> Finding | None:
    first = None
    for needle in needles:
        hit = needle.search(hay)
        if hit is None:
            if rule.predicate_kind is PredicateKind.SUBSTRING_ALL:
                return None
        else:
            if first is None:
                first = Finding(rule.id, rule.surface.value, hit.start(), hit.end())
            if rule.predicate_kind is PredicateKind.SUBSTRING_ANY:
                return first
    return first


def _cap_payload(payload: str, max_bytes: int) -> tuple[str, bool]:
    # Every code point takes at least one byte, including preserved lone surrogates.
    prefix = payload[:max_bytes]
    raw = prefix.encode("utf-8", "surrogatepass")
    if len(raw) <= max_bytes:
        return prefix, len(prefix) < len(payload)
    raw = raw[:max_bytes]
    try:
        prefix = raw.decode("utf-8", "surrogatepass")
    except UnicodeDecodeError as exc:
        prefix = raw[:exc.start].decode("utf-8", "surrogatepass")
    return prefix, True


def _wire_rule(rule: Rule) -> dict:
    kind = rule.predicate_kind
    pred = rule.predicate
    if kind is PredicateKind.REGEX:
        if not isinstance(pred, str) or len(pred) > _MAX_PATTERN_LEN:
            raise ValueError("regex must be a string of at most 4096 characters")
    elif kind is PredicateKind.STRUCTURED:
        mode, patterns = _structured_patterns(pred)
        pred = {mode: list(patterns)}
    elif kind in (PredicateKind.SUBSTRING_ANY, PredicateKind.SUBSTRING_ALL):
        if not isinstance(pred, (list, tuple)) or not 1 <= len(pred) <= _MAX_NEEDLES:
            raise ValueError(f"substrings require 1 to {_MAX_NEEDLES} needles")
        if any(not isinstance(n, str) or not n or len(n) > _MAX_PATTERN_LEN for n in pred):
            raise ValueError("needles must be nonempty strings of at most 4096 characters")
        pred = list(pred)
    else:
        raise ValueError(f"{kind} has no runtime yet")
    if not isinstance(rule.id, str) or len(rule.id) > 512:
        raise ValueError("rule id must be a string of at most 512 characters")
    # source travels because the isolated worker re-screens, and the strict
    # measurement policy is keyed on it. Dropping it made the worker's second
    # look weaker than the loader's first.
    return dict(id=rule.id, source=rule.source, kind=kind.value, predicate=pred,
                case_sensitive=rule.case_sensitive, surface=rule.surface.value)


def _schedule_key(item: dict) -> tuple:
    pred = item["predicate"]
    if item["kind"] == PredicateKind.STRUCTURED.value:
        mode = next(iter(pred))
        patterns = pred[mode]
        return (2, sum(map(len, patterns)), item["id"], mode, tuple(patterns),
                item["case_sensitive"], item["surface"])
    if item["kind"] == PredicateKind.REGEX.value:
        # A reproducible cost hint, never a safety claim or severity ranking.
        cost = len(pred) + 32 * sum(pred.count(ch) for ch in "*+?{|(")
        return (1, cost, item["id"], pred, item["case_sensitive"], item["surface"])
    return (0, len(pred), sum(map(len, pred)), item["id"], tuple(pred),
            item["case_sensitive"], item["surface"])


def _run_worker(request: bytes, deadline: float) -> tuple[bytes, bool, int | None, str | None]:
    # Bound pending OS launches too: repeated timeouts must not accumulate threads.
    if not _SUPERVISORS.acquire(blocking=False):
        return b"", False, None, "worker supervision capacity exhausted"
    finished = threading.Event()
    cancelled = threading.Event()
    state = {"output": b"", "returncode": None, "error": None, "process": None}

    def supervise():
        proc = None
        watchdog = None
        try:
            if cancelled.is_set():
                return
            command = [sys.executable, "-I", "-S", str(Path(__file__).with_name("_scan_worker.py"))]
            proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL,
                                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
            state["process"] = proc

            def expire():
                if proc.poll() is None:
                    cancelled.set()
                    proc.kill()

            # Windows communicate(input=...) writes synchronously before checking
            # its timeout. The watchdog also interrupts a blocked stdin write.
            watchdog = threading.Timer(max(0, deadline - time.perf_counter()), expire)
            watchdog.daemon = True
            watchdog.start()
            if cancelled.is_set() or time.perf_counter() >= deadline:
                cancelled.set()
                proc.kill()
                data = None
            else:
                data = request
            try:
                output, _ = proc.communicate(data, timeout=max(0, deadline - time.perf_counter()))
            except subprocess.TimeoutExpired:
                cancelled.set()
                proc.kill()
                try:
                    output, _ = proc.communicate(timeout=_CLEANUP_S)
                except subprocess.TimeoutExpired as exc:
                    output = exc.output or b""
                    state["error"] = "worker cleanup exceeded 100 ms"
                    state["output"] = output
                    # Keep the supervision slot until the OS reaps the process.
                    # The caller has its own bounded wait and can already return.
                    proc.wait()
            state["output"] = output
            state["returncode"] = proc.returncode
        except Exception as exc:
            phase = "startup" if proc is None else "communication"
            state["error"] = f"worker {phase} failed: {type(exc).__name__}: {exc}"
            if proc is not None:
                proc.kill()
                proc.wait()
        finally:
            if watchdog is not None:
                watchdog.cancel()
            finished.set()
            _SUPERVISORS.release()

    supervisor = threading.Thread(target=supervise, daemon=True, name="agent-defs-scan")
    try:
        supervisor.start()
    except RuntimeError as exc:
        _SUPERVISORS.release()
        return b"", False, None, f"worker supervision failed: {exc}"
    try:
        if not finished.wait(max(0, deadline - time.perf_counter())):
            cancelled.set()
            # A late launch receives no input and is killed by its supervisor.
            # Only wait for cleanup when there is already a process to reap.
            if state["process"] is not None and not finished.wait(_CLEANUP_S):
                state["error"] = "worker cleanup exceeded 100 ms"
    except BaseException:
        cancelled.set()
        if state["process"] is not None:
            state["process"].kill()
        raise
    return state["output"], cancelled.is_set(), state["returncode"], state["error"]


def scan(
    payload: str,
    rules: Iterable[Rule],
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
    budget_s: float = DEFAULT_BUDGET_S,
    compiled: dict | None = None,
) -> ScanResult:
    """Scan in deterministic cost-hint order, continuing after every finding.

    The deadline includes preparation, startup, compilation and matching. The
    worker is killed on timeout. Process creation and I/O run in a bounded
    supervisor thread. Bounded preparation, OS scheduling, and up to 100 ms of
    cleanup can overshoot the caller deadline. A killed rule is unfinished, not evaluated.
    Budget exhaustion and errors never mean a clean scan. Caller policy decides
    what findings or incomplete coverage should do to a tool call.

    Rules must be ordinary finite Rule data, not a blocking custom iterator.
    Limits bound serialization: 4096 rules, 1 Mi characters of predicate data,
    64 needles per substring rule, 4096 characters per regex/needle and at most
    4 MiB of input. Oversized bundles are explicitly incomplete, never sampled.
    The entire bounded input is searched as one string, including beyond the old
    256 KiB cap. This preserves unbounded regexes, anchors, lookarounds and ALL
    predicates without window overlap or duplicate findings. ``max_bytes`` is an
    optional stricter total limit; exceeding it makes ``result.findings`` raise.
    The legacy compiled mapping is accepted but ignored: re objects cannot cross
    the isolation boundary safely and an id-only cache can substitute stale rules.
    """
    started = time.perf_counter()
    if not isinstance(payload, str):
        raise TypeError("payload must be a string")
    if not isinstance(max_bytes, int) or not 0 <= max_bytes <= _MAX_INPUT_BYTES:
        raise ValueError(f"max_bytes must be between 0 and {_MAX_INPUT_BYTES}")
    if not math.isfinite(budget_s) or budget_s < 0:
        raise ValueError("budget_s must be finite and nonnegative")
    deadline = started + budget_s
    payload, truncated = _cap_payload(payload, max_bytes)
    findings = []
    errors = []
    evaluated = 0
    skipped = 0
    worker_error = None

    def result():
        return ScanResult(tuple(findings), evaluated, skipped, time.perf_counter() - started,
                          truncated, tuple(errors), worker_error)

    candidates = list(islice(rules, _MAX_RULES + 1))
    if len(candidates) > _MAX_RULES:
        worker_error = f"bundle exceeds {_MAX_RULES} rules"
        return result()
    wire = []
    chars = 0
    for rule in candidates:
        if rule.predicate_kind is PredicateKind.NONE:
            continue
        try:
            item = _wire_rule(rule)
        except ValueError as exc:
            errors.append(RuleError(rule.id, str(exc)))
            continue
        pred = item["predicate"]
        if item["kind"] == PredicateKind.STRUCTURED.value:
            pred = next(iter(pred.values()))
        chars += len(pred) if isinstance(pred, str) else sum(map(len, pred))
        if chars > _MAX_BUNDLE_CHARS:
            worker_error = f"bundle exceeds {_MAX_BUNDLE_CHARS} predicate characters"
            return result()
        wire.append(item)
    errors.sort(key=lambda error: (error.rule_id, error.reason))
    wire.sort(key=_schedule_key)
    if not wire:
        return result()
    if time.perf_counter() >= deadline:
        skipped = len(wire)
        return result()
    request = json.dumps(dict(payload=payload, rules=wire), ensure_ascii=False).encode("utf-8", "surrogatepass")
    if time.perf_counter() >= deadline:
        skipped = len(wire)
        return result()
    output, timed_out, returncode, worker_error = _run_worker(request, deadline)
    completed = set()
    for line in output.splitlines(keepends=True):
        if not line.endswith(b"\n"):
            break
        try:
            status, index, detail = json.loads(line)
            if not isinstance(index, int) or index != len(completed) or index >= len(wire):
                raise ValueError("invalid completion index")
            item = wire[index]
            if status == "error" and isinstance(detail, str):
                errors.append(RuleError(item["id"], detail))
            elif status == "ok":
                if detail is not None:
                    start, end = detail
                    if not (isinstance(start, int) and isinstance(end, int) and 0 <= start <= end <= len(payload)):
                        raise ValueError("invalid match span")
                    findings.append(Finding(item["id"], item["surface"], start, end))
                evaluated += 1
            else:
                raise ValueError("invalid completion status")
            completed.add(index)
        except (ValueError, TypeError, IndexError):
            worker_error = "invalid worker response"
            break
    skipped = len(wire) - len(completed)
    if timed_out:
        worker_error = worker_error or "worker deadline exceeded"
    elif returncode != 0 or len(completed) != len(wire):
        worker_error = worker_error or f"worker failed (exit {returncode}; {len(completed)}/{len(wire)} completed)"
    return result()


def scan_trusted(
    payload: str,
    rules: "Iterable[Rule]",
    *,
    max_bytes: int = _MAX_INPUT_BYTES,
) -> ScanResult:
    """Match in this process, with no isolation and no deadline.

    ``scan`` puts every match in a worker process because the payload is under an
    attacker's control and a pattern that backtracks cannot be interrupted once it
    starts. That costs one process launch per call, which is the right price for a
    hook that runs once per tool call and the wrong one for a benchmark that scans
    thousands of files.

    This entry point pays neither cost and gives up the protection that buys. Use it
    only for offline measurement over material the caller controls, where a hang is a
    slow build rather than a frozen session. **Never call it from a hook, and never
    give it a payload that arrived from outside.** Patterns are still screened, since
    ``compile_rule`` refuses anything the bundle should not contain, and a per-rule
    failure is recorded rather than raised so one bad rule cannot end a measurement.

    ``rules_skipped_budget`` is zero. Rejected rules and the explicit byte limit
    still make ``findings`` raise IncompleteScanError. Offline callers can supply
    a larger max_bytes than the isolated entry point allows.
    """
    if not isinstance(payload, str):
        raise TypeError("payload must be a string")
    if not isinstance(max_bytes, int) or max_bytes < 0:
        raise ValueError("max_bytes must be a nonnegative integer")
    payload, truncated = _cap_payload(payload, max_bytes)
    findings: list = []
    errors: list = []
    evaluated = 0
    started = time.perf_counter()
    for rule in rules:
        if rule.predicate_kind is PredicateKind.NONE:
            continue
        try:
            runtime = compile_rule(rule)
            if rule.predicate_kind in (PredicateKind.REGEX, PredicateKind.STRUCTURED):
                hit = runtime.search(payload)
                span = (hit.start(), hit.end()) if hit else None
            else:
                found = _search_substrings(rule, runtime, payload)
                span = (found.start, found.end) if found else None
        except Exception as exc:
            errors.append(RuleError(rule.id, f"{type(exc).__name__}: {exc}"[:512]))
            continue
        evaluated += 1
        if span is not None:
            start, end = span
            findings.append(Finding(rule.id, rule.surface.value, start, end))
    return ScanResult(partial_findings=tuple(findings), rules_evaluated=evaluated,
                      rules_skipped_budget=0, elapsed_s=time.perf_counter() - started,
                      truncated_input=truncated, errors=tuple(errors), worker_error=None)
