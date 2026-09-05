"""Bounded, dependency-free evaluation of normalized predicates.

Screening rejects known hazards, not every superlinear expression. All compilation
and matching for scan() runs in a disposable process killed at the scan deadline.
Results distinguish completed checks, rejected rules, unfinished work and worker
failure. OS scheduling and cleanup are not real-time operations.
"""

from __future__ import annotations

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
from typing import Iterable, Sequence

from .model import PredicateKind, Rule

DEFAULT_MAX_BYTES = 256 * 1024
DEFAULT_BUDGET_S = 0.25
_MAX_PATTERN_LEN = 4096
_MAX_RULES = 4096
_MAX_NEEDLES = 64
_MAX_BUNDLE_CHARS = 1024 * 1024
_MAX_INPUT_BYTES = 4 * 1024 * 1024
_MAX_MATCH_CHARS = 512
_CLEANUP_S = 0.1
_SUPERVISORS = threading.BoundedSemaphore(4)


@dataclass(frozen=True)
class Finding:
    rule_id: str
    surface: str
    start: int
    end: int
    matched: str
    truncated_input: bool = False
    truncated_match: bool = False


@dataclass(frozen=True)
class RuleError:
    rule_id: str
    reason: str


@dataclass(frozen=True)
class ScanResult:
    findings: Sequence[Finding]
    rules_evaluated: int
    rules_skipped_budget: int
    elapsed_s: float
    truncated_input: bool
    errors: Sequence[RuleError] = ()
    worker_error: str | None = None

    @property
    def complete(self) -> bool:
        return not (self.truncated_input or self.rules_skipped_budget or self.errors or self.worker_error)


class UnsafePattern(ValueError):
    """A pattern failed syntax validation or conservative hazard screening."""


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


def screen_pattern(pattern: str, flags: int = re.IGNORECASE) -> None:
    """Reject known hazards at bundle build time; this is not a linearity proof.

    scan() also validates inside its isolated worker so stale or unscreened data
    cannot bypass validation. Matching must still be isolated after this passes.
    """
    nested, branching, reference = _hazards(_parse_pattern(pattern, flags))
    if nested:
        raise UnsafePattern("quantified group under an outer quantifier")
    if branching:
        raise UnsafePattern("alternation under repetition")
    if reference:
        raise UnsafePattern("backreferences and conditional references are not supported")
    try:
        re.compile(pattern, flags)
    except (re.error, OverflowError, RecursionError, ValueError) as exc:
        raise UnsafePattern(f"does not compile: {exc}") from exc


def _regex_all_patterns(predicate) -> Sequence[str]:
    if not isinstance(predicate, dict) or set(predicate) != {"regex_all"}:
        raise ValueError("STRUCTURED requires exactly a regex_all list")
    patterns = predicate["regex_all"]
    if not isinstance(patterns, (list, tuple)) or not 1 <= len(patterns) <= _MAX_NEEDLES:
        raise ValueError(f"regex_all requires 1 to {_MAX_NEEDLES} patterns")
    if any(not isinstance(p, str) or len(p) > _MAX_PATTERN_LEN for p in patterns):
        raise ValueError("regex_all patterns must be strings of at most 4096 characters")
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
        screen_pattern(rule.predicate, flags)
        return re.compile(rule.predicate, flags)
    if rule.predicate_kind is PredicateKind.STRUCTURED:
        patterns = _regex_all_patterns(rule.predicate)
        for pattern in patterns:
            screen_pattern(pattern, flags)
        return _RegexAll(tuple(re.compile(pattern, flags) for pattern in patterns))
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
                first = Finding(rule.id, rule.surface.value, hit.start(), hit.end(), hit.group())
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
        pred = {"regex_all": list(_regex_all_patterns(pred))}
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
    return dict(id=rule.id, kind=kind.value, predicate=pred,
                case_sensitive=rule.case_sensitive, surface=rule.surface.value)


def _schedule_key(item: dict) -> tuple:
    pred = item["predicate"]
    if item["kind"] == PredicateKind.STRUCTURED.value:
        patterns = pred["regex_all"]
        return (2, sum(map(len, patterns)), item["id"], tuple(patterns),
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
            pred = pred["regex_all"]
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
                    findings.append(Finding(item["id"], item["surface"], start, end,
                                            payload[start:min(end, start + _MAX_MATCH_CHARS)],
                                            truncated, end - start > _MAX_MATCH_CHARS))
                evaluated += 1
            else:
                raise ValueError("invalid completion status")
            completed.add(index)
        except (ValueError, TypeError, IndexError):
            worker_error = "invalid worker response"
            break
    if timed_out:
        skipped = len(wire) - len(completed)
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

    The result carries no ``rules_skipped_budget``, because nothing here is skipped.
    """
    if not isinstance(payload, str):
        raise TypeError("payload must be a string")
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
            findings.append(Finding(rule.id, rule.surface.value, start, end,
                                    payload[start:min(end, start + _MAX_MATCH_CHARS)],
                                    truncated, end - start > _MAX_MATCH_CHARS))
    return ScanResult(findings=tuple(findings), rules_evaluated=evaluated,
                      rules_skipped_budget=0, elapsed_s=time.perf_counter() - started,
                      truncated_input=truncated, errors=tuple(errors), worker_error=None)
