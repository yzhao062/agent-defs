"""Scan configuration a person installs but did not write.

A skill document, an agent file, an MCP server manifest: somebody else wrote the
text and somebody else's machine will follow it. That is the channel worth
defending, and it is the only entry channel with a public labelled corpus that
has a negative class.

This module runs a rule the way its source runs it. Round three measured what
happens otherwise, on ATR's own skill benchmark of 32 malicious and 466 benign
documents: the 608 runnable patterns of the pinned rule set, matched flat, fire on
155 of the 466 benign documents, and on the historical 108-rule snapshot the same
harness fired on 445 of them. ATR's own ``scanSkill()`` fires on 1. The difference
is not tuning. ATR walks a rule's conditions one at a time, admits a rule to the
skill path only when its declared scan target or its condition logic says it
belongs there, and suppresses matches that land inside a fenced code block. Those
gates are read out of ATR's source by
:mod:`agent_defs.loaders.atr_skill_gates` and travel on each record as a
:class:`~agent_defs.model.ChannelBinding`; this module executes them.

One source behavior is deliberately not reproduced. ATR refuses to evaluate any
pattern against text longer than ``MAX_EVAL_LENGTH``, and a refused evaluation
returns no match, so a skill document over that length comes back clean. Here it
comes back incomplete instead. Nothing in the benchmark reaches the limit, so the
divergence costs no measured recall, and reading an empty result as a clean file
is the failure this package is built to make impossible.

Nothing here is bounded against a hostile payload. The document being scanned is
usually one a person is about to install, so it is exactly as hostile as the
thing it is being checked for. Use :func:`scan_cfg_isolated` when the caller did
not write the file; :func:`scan_cfg` is the offline entry point, like
``evaluate.scan_trusted``.
"""

from __future__ import annotations

import base64
import binascii
import json
import math
import re
import time
from dataclasses import dataclass
from typing import Iterable, Sequence

from .evaluate import (
    DEFAULT_BUDGET_S,
    DEFAULT_MAX_BYTES,
    Finding,
    IncompleteScanError,
    RuleError,
    ScanResult,
    _MAX_BUNDLE_CHARS,
    _MAX_INPUT_BYTES,
    _MAX_RULES,
    _cap_payload,
    _run_worker,
    screen_pattern,
)
from .model import ChannelBinding, Rule, Surface

#: Bounds ATR applies when it decodes base64 blocks out of a skill document, and
#: the length above which it evaluates no pattern at all. These mirror values
#: ``read_skill_gates`` reads out of the checkout; ``test_cfg`` compares the two
#: so a bound that moves upstream fails a test rather than drifting quietly.
BASE64_BLOCK = re.compile(r"[A-Za-z0-9+/]{32,}={0,2}")
BASE64_MIN_BLOCK_CHARS = 32
BASE64_MAX_BLOCKS = 5
BASE64_MIN_DECODED_CHARS = 10
BASE64_MIN_PRINTABLE_RATIO = 0.7
BASE64_MAX_DECODED_CHARS = 100_000
SOURCE_MAX_EVAL_CHARS = 100_000


@dataclass(frozen=True)
class CfgFinding:
    """A finding, plus where in the document the matching text was read.

    ``origin`` is ``document`` for the file as written and ``base64`` for text
    recovered from an encoded block, because a payload a reviewer cannot see in
    the file reads differently in a report from one they can.
    """

    rule_id: str
    surface: str
    start: int
    end: int
    condition_index: int
    origin: str = "document"

    def as_finding(self) -> Finding:
        return Finding(self.rule_id, self.surface, self.start, self.end)


def _code_block_ranges(text: str) -> list[tuple[int, int]]:
    """Ranges ATR treats as code, ported from ``buildCodeBlockRanges``.

    Fenced blocks are matched line by line rather than with a non-greedy regex,
    because ``````` markers must alternate open and close and a regex
    misaligns when the count is odd. An unterminated fence runs to end of text.
    Inline spans and quoted cells inside markdown table rows follow, in that
    order, which matters only in that the fenced ranges are already present when
    the inline pass tests whether a span sits inside one.
    """
    ranges: list[tuple[int, int]] = []
    block_start: int | None = None
    pos = 0
    for line in text.split("\n"):
        if line.lstrip().startswith("```"):
            if block_start is None:
                block_start = pos
            else:
                ranges.append((block_start, pos + len(line) + 1))
                block_start = None
        pos += len(line) + 1
    if block_start is not None:
        ranges.append((block_start, len(text)))

    fenced = list(ranges)
    for inline in re.finditer(r"`[^`\n]+`", text):
        at = inline.start()
        if not any(start <= at < end for start, end in fenced):
            ranges.append((at, at + len(inline.group())))

    for row in re.finditer(r"^\|.*$", text, re.MULTILINE):
        line_start = row.start()
        for quoted in re.finditer(r'"[^"\n]+"', row.group()):
            at = line_start + quoted.start()
            ranges.append((at, at + len(quoted.group())))
    return ranges


def _utf16_len(text: str) -> int:
    """Length as the source counts it. Node's String.length counts UTF-16 code
    units, so an astral character costs two. Counting code points here let a
    document past the source's own evaluation limit report as finished."""
    return len(text.encode("utf-16-le", "surrogatepass")) // 2


def _decoded_blocks(text: str, *, max_blocks: int = BASE64_MAX_BLOCKS) -> list[str]:
    """Base64 payloads ATR pulls out of a skill document, in its own bounds.

    One level of decoding, at most ``max_blocks`` blocks, and a block is kept
    only when it decodes to something mostly printable. The printable ratio is
    what separates a hidden instruction from a binary blob that happens to be
    base64-shaped.
    """
    out: list[str] = []
    for match in BASE64_BLOCK.finditer(text):
        if len(out) >= max_blocks:
            break
        # Node's Buffer.from(s, 'base64') decodes every complete group and drops
        # a trailing fragment; Python raises on the same input. Pad to the same
        # answer rather than skipping a block the source would have read. Its
        # toString('utf-8') substitutes on bad bytes where Python raises, so
        # substitute here too, which is what the printable-ratio test then sees.
        body = match.group().rstrip("=")
        if len(body) % 4 == 1:
            body = body[:-1]
        try:
            raw = base64.b64decode(body + "=" * (-len(body) % 4))
        except (binascii.Error, ValueError):
            continue
        decoded = raw.decode("utf-8", "replace")
        if not decoded:
            continue
        printable = sum(1 for ch in decoded if 32 <= ord(ch) < 127)
        # Upstream runs on Node, where String.length counts UTF-16 code units, so an
        # astral character costs two. Counting code points here keeps a block Node
        # would drop, and a kept block is a route to a finding upstream does not
        # produce. Match the source's arithmetic rather than Python's.
        units = sum(2 if ord(ch) > 0xFFFF else 1 for ch in decoded)
        if (printable / units > BASE64_MIN_PRINTABLE_RATIO
                and len(decoded) >= BASE64_MIN_DECODED_CHARS):
            # Node slices String.prototype.slice, which counts UTF-16 code units.
            # Slicing code points here kept text Node had already cut, so a needle
            # past the boundary matched for us and not for the source. A terminal
            # lone surrogate is preserved deliberately: that is what Node leaves.
            units = decoded.encode("utf-16-le", "surrogatepass")[:2 * BASE64_MAX_DECODED_CHARS]
            out.append(units.decode("utf-16-le", "surrogatepass"))
    return out


class _CompiledBinding:
    """One rule's conditions, compiled once, in the source's own order."""

    __slots__ = ("rule_id", "surface", "logic", "patterns", "suppress")

    def __init__(self, rule: Rule, binding: ChannelBinding) -> None:
        self.rule_id = rule.id
        self.surface = binding.channel
        self.logic = binding.condition_logic
        self.suppress = binding.suppress_in_code_blocks
        self.patterns: list[re.Pattern[str]] = []
        for pattern in binding.conditions:
            screen_pattern(pattern, re.IGNORECASE,
                           require_measurement=(rule.source == "atr"))
            self.patterns.append(re.compile(pattern, re.IGNORECASE))

    def search(self, text: str, code_ranges: Sequence[tuple[int, int]]):
        """Walk conditions the way the source's dispatcher walks them.

        ``any`` stops at the first condition that matches, which is also why the
        source can never report more than one matched condition for such a rule,
        and therefore why its compound gate rejects every ``any`` rule that is
        not declared for this channel. ``all`` requires every condition, and a
        condition whose first match lands inside a code block counts as not
        matching, exactly as ``isInsideCodeBlock`` decides it on the first match
        alone.
        """
        first = None
        for index, pattern in enumerate(self.patterns):
            hit = pattern.search(text)
            if hit is not None and self.suppress and code_ranges:
                if any(start <= hit.start() < end for start, end in code_ranges):
                    hit = None
            if hit is None:
                if self.logic == "all":
                    return None
                continue
            if first is None:
                first = (index, hit.start(), hit.end())
            if self.logic != "all":
                return first
        # ``any`` reaches here only when nothing matched, leaving ``first`` None.
        # ``all`` reaches here only when everything did.
        return first


def cfg_bindings(rules: Iterable[Rule]) -> list[tuple[Rule, ChannelBinding]]:
    """The rules whose source dispatches them to ``CFG``, with their binding.

    A rule with no ``CFG`` binding never reached this channel upstream. A rule
    with an ineligible one did reach it and was refused there; it stays in the
    package carrying the gate that refused it, which is the whole difference
    between a rule we dropped and a rule its author excluded.
    """
    out = []
    for rule in rules:
        binding = rule.binding(Surface.CFG)
        if binding is not None and binding.executable:
            out.append((rule, binding))
    return out


def scan_cfg(
    document: str,
    rules: Iterable[Rule],
    *,
    decode_base64: bool = True,
    suppress_code_blocks: bool = True,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> "CfgScanResult":
    """Scan one configuration document, in this process, with no deadline.

    Like ``evaluate.scan_trusted``, this pays neither the process-isolation cost
    nor the protection it buys, and it is for offline measurement and for
    material the caller controls. A hostile skill document is not that; route it
    through :func:`scan_cfg_isolated`.

    The two keyword arguments turn off parts of the source's own behavior and
    exist so a measurement can price each one; leaving either off is a departure
    from what ATR does, not a configuration choice a consumer should make.

    A per-rule failure is recorded rather than raised, so one unusable pattern
    cannot end a scan over a corpus.
    """
    if not isinstance(document, str):
        raise TypeError("document must be a string")
    if not isinstance(max_bytes, int) or max_bytes < 0:
        raise ValueError("max_bytes must be a nonnegative integer")
    document, truncated = _cap_payload(document, max_bytes)
    findings: list[CfgFinding] = []
    errors: list[RuleError] = []
    evaluated = 0
    code_ranges = _code_block_ranges(document) if suppress_code_blocks else []
    payloads = [("document", document, code_ranges)]
    if decode_base64:
        payloads += [("base64", block,
                      _code_block_ranges(block) if suppress_code_blocks else [])
                     for block in _decoded_blocks(document)]

    bindings = list(cfg_bindings(rules))
    for rule, binding in bindings:
        try:
            compiled = _CompiledBinding(rule, binding)
        except Exception as exc:  # pragma: no cover - screened at load time
            errors.append(RuleError(rule.id, f"{type(exc).__name__}: {exc}"[:512]))
            continue
        evaluated += 1
        for origin, text, ranges in payloads:
            hit = compiled.search(text, ranges)
            if hit is not None:
                index, start, end = hit
                findings.append(CfgFinding(rule.id, compiled.surface, start, end,
                                           index, origin))
                break
    errors.sort(key=lambda error: (error.rule_id, error.reason))
    return CfgScanResult(tuple(findings), evaluated, tuple(errors), truncated,
                         _utf16_len(document) > SOURCE_MAX_EVAL_CHARS,
                         empty_bundle=not bindings)


@dataclass(frozen=True)
class CfgScanResult:
    """What one document produced.

    ``findings`` raises unless every rule finished on the whole document, for the
    same reason ``evaluate.ScanResult`` does: a caller who reads an empty result
    as "this file is clean" must not be able to do so while a rule failed to
    compile or the document was cut short.
    """

    partial_findings: Sequence[CfgFinding]
    rules_evaluated: int
    errors: Sequence[RuleError] = ()
    truncated_input: bool = False
    #: True when the document is longer than the source's own evaluation limit.
    #: ATR returns no match there and therefore calls such a file clean; this
    #: result calls it unfinished instead.
    over_source_eval_limit: bool = False

    #: True when the bundle handed to the scan carried no executable binding at
    #: all. A zero-rule scan finds nothing, and reporting that as a clean document
    #: is the exact reading this module exists to make impossible. It is reachable
    #: whenever the loader could not read the source's own gates.
    empty_bundle: bool = False

    @property
    def complete(self) -> bool:
        return not (self.errors or self.truncated_input
                    or self.over_source_eval_limit or self.empty_bundle)

    def require_complete(self) -> "CfgScanResult":
        if not self.complete:
            errors = tuple(self.errors)
            if self.over_source_eval_limit:
                errors += (RuleError("", f"document exceeds the source's own "
                                         f"{SOURCE_MAX_EVAL_CHARS}-character evaluation "
                                         f"limit, where it evaluates no pattern at all"),)
            if self.empty_bundle:
                # Without this the raised ScanResult carries no error, and
                # ScanResult.complete then reads True: the empty bundle would be
                # incomplete here and clean one attribute away. The reason has to
                # travel with the exception, not only with the result that raised.
                errors += (RuleError("", "no executable binding in the bundle; a scan that "
                                         "evaluated no rule found nothing and is not a "
                                         "clean document"),)
            raise IncompleteScanError(
                ScanResult(tuple(f.as_finding() for f in self.partial_findings),
                           self.rules_evaluated, 0, 0.0, self.truncated_input,
                           errors, None))
        return self

    @property
    def findings(self) -> Sequence[CfgFinding]:
        self.require_complete()
        return self.partial_findings

    @property
    def rule_ids(self) -> tuple[str, ...]:
        return tuple(sorted({f.rule_id for f in self.findings}))

    def __bool__(self):
        raise TypeError("use result.complete and result.findings explicitly")


def scan_cfg_isolated(
    document: str,
    rules: Iterable[Rule],
    *,
    budget_s: float = DEFAULT_BUDGET_S,
    decode_base64: bool = True,
    suppress_code_blocks: bool = True,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> "CfgScanResult":
    """Scan one configuration document in a killable worker, under a deadline.

    ``evaluate.scan`` isolates because a regex that backtracks cannot be
    interrupted once it starts, and the skill document a person is about to
    install was written by whoever wrote the attack. The same isolation applies
    here, over the same worker and the same supervisor, with the channel's own
    execution model carried across: each rule's conditions in the source's order,
    its condition logic, and its code-block suppression flag.

    The document crosses raw. Splitting base64 blocks out and locating code
    fences both read attacker text, so they run inside the process that can be
    killed rather than in the caller's.

    The deadline covers preparation, startup, screening, compilation and
    matching. A rule the worker never reached is unfinished rather than clean,
    and ``findings`` raises for the whole result, so a timeout cannot be read as
    a document with nothing in it.
    """
    if not isinstance(document, str):
        raise TypeError("document must be a string")
    if not isinstance(max_bytes, int) or not 0 <= max_bytes <= _MAX_INPUT_BYTES:
        raise ValueError(f"max_bytes must be between 0 and {_MAX_INPUT_BYTES}")
    if not math.isfinite(budget_s) or budget_s < 0:
        raise ValueError("budget_s must be finite and nonnegative")
    deadline = time.perf_counter() + budget_s
    document, truncated = _cap_payload(document, max_bytes)
    over_limit = _utf16_len(document) > SOURCE_MAX_EVAL_CHARS
    findings: list[CfgFinding] = []
    errors: list[RuleError] = []

    bindings = list(cfg_bindings(rules))

    def result(worker_error=None, evaluated=0):
        errors.sort(key=lambda error: (error.rule_id, error.reason))
        if worker_error is not None:
            errors.append(RuleError("", worker_error))
        return CfgScanResult(tuple(findings), evaluated, tuple(errors), truncated,
                             over_limit, empty_bundle=not bindings)

    if not bindings:
        return result()
    if len(bindings) > _MAX_RULES:
        return result(f"bundle exceeds {_MAX_RULES} rules")
    wire = []
    chars = 0
    for rule, binding in bindings:
        chars += sum(len(condition) for condition in binding.conditions)
        if chars > _MAX_BUNDLE_CHARS:
            return result(f"bundle exceeds {_MAX_BUNDLE_CHARS} predicate characters")
        wire.append({"id": rule.id, "source": rule.source, "surface": binding.channel,
                     "conditions": list(binding.conditions),
                     "logic": binding.condition_logic,
                     "suppress": bool(binding.suppress_in_code_blocks)})
    request = json.dumps(dict(mode="cfg", payload=document, rules=wire,
                              decode_base64=bool(decode_base64),
                              suppress_code_blocks=bool(suppress_code_blocks)),
                         ensure_ascii=False).encode("utf-8", "surrogatepass")
    if time.perf_counter() >= deadline:
        return result("worker deadline exceeded before dispatch")
    output, timed_out, returncode, worker_error = _run_worker(request, deadline)

    completed = 0
    for line in output.splitlines(keepends=True):
        if not line.endswith(b"\n"):
            break
        try:
            status, index, detail = json.loads(line)
            if not isinstance(index, int) or index != completed or index >= len(wire):
                raise ValueError("invalid completion index")
            item = wire[index]
            if status == "error" and isinstance(detail, str):
                errors.append(RuleError(item["id"], detail))
            elif status == "ok":
                if detail is not None:
                    condition, start, end, origin = detail
                    if not (isinstance(condition, int) and isinstance(start, int)
                            and isinstance(end, int) and 0 <= start <= end
                            and 0 <= condition < len(item["conditions"])
                            and origin in ("document", "base64")):
                        raise ValueError("invalid match span")
                    findings.append(CfgFinding(item["id"], item["surface"], start, end,
                                               condition, origin))
            else:
                raise ValueError("invalid completion status")
            completed += 1
        except (ValueError, TypeError, IndexError):
            worker_error = "invalid worker response"
            break
    if timed_out:
        worker_error = worker_error or "worker deadline exceeded"
    elif returncode != 0 or completed != len(wire):
        worker_error = worker_error or (f"worker failed (exit {returncode}; "
                                        f"{completed}/{len(wire)} completed)")
    return result(worker_error, completed)


__all__ = [
    "BASE64_MAX_BLOCKS",
    "SOURCE_MAX_EVAL_CHARS",
    "CfgFinding",
    "CfgScanResult",
    "cfg_bindings",
    "scan_cfg",
    "scan_cfg_isolated",
]
