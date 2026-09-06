"""Read ATR's ``scanSkill()`` gates out of ATR's own source.

A rule lifted out of its dispatcher is a different artifact from the rule its
authors shipped. ATR's skill entry point admits far fewer rules than the raw
pattern set, and the difference is the whole gap between upstream's published
zero false positives on 466 benign skill documents and this package's 95.49%.
This module reads the admitting logic out of the checkout rather than
transcribing it, so a gate that moves upstream moves here or the read fails
loudly.

Every value carries a :class:`GateSource` naming the file and line it was read
from. Nothing here is a constant somebody typed in from memory.

The parse is deliberately narrow. It matches the exact shapes present at the
pinned revision and raises :class:`GateReadError` when one is absent, because a
silently defaulted gate is the failure this module exists to prevent. Upgrading
the pin is expected to require touching this file; that is the point.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

ENGINE_PATH = "src/engine.ts"
ENFORCEMENT_PATH = "src/enforcement.ts"
CONTRACT_PATH = "src/quality/rule-contract.ts"
INTERFACE_CONTRACT_PATH = "engines/typescript/INTERFACE-CONTRACT.md"


class GateReadError(ValueError):
    """An expected gate could not be read out of the upstream checkout."""


@dataclass(frozen=True)
class GateSource:
    """Where one gate value was read. ``line`` is 1-based."""

    path: str
    line: int
    excerpt: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line}"


@dataclass(frozen=True)
class SkillGates:
    """The admitting logic of ATR's ``scanSkill()`` at one revision.

    ``denylist`` is upstream's ``SKILL_CONTEXT_DENYLIST``, mapped to the comment
    upstream wrote beside each id. ``denylist_applied`` says whether the pinned
    engine actually consults it: at ``faf743f`` it does not, and upstream's own
    audit calls the set dead code, while the engine interface contract still
    says a conforming engine MUST honor it. Both facts travel, because a port
    that quietly picks one of them is asserting something upstream does not.
    """

    source_rev: str
    event_type: str
    scan_context: str
    exempt_scan_targets: frozenset[str]
    min_conditions_floor: int
    min_conditions_ratio: float
    any_logic_short_circuits: bool
    every_field_resolves_to_content: bool
    skipped_statuses: frozenset[str]
    denylist: Mapping[str, str]
    denylist_applied: bool
    denylist_required_by_interface_contract: bool
    base64_max_blocks: int
    base64_min_block_chars: int
    base64_min_decoded_chars: int
    base64_min_printable_ratio: float
    base64_max_decoded_chars: int
    max_eval_chars: int
    lane_default: str
    lane_blocked_maturities: frozenset[str]
    provenance: Mapping[str, GateSource]

    def min_required_conditions(self, condition_count: int) -> int:
        """Upstream's ``Math.max(2, Math.ceil(totalConds * 0.3))``.

        ``Number(rule.detection?.conditions?.length ?? 1)`` makes a missing or
        empty condition list count as one, so the floor decides those.
        """
        total = condition_count if condition_count > 0 else 1
        return max(self.min_conditions_floor, math.ceil(total * self.min_conditions_ratio))


def _find(text: str, pattern: "re.Pattern[str] | str", path: str,
          what: str) -> tuple[re.Match[str], GateSource]:
    match = (pattern.search(text) if isinstance(pattern, re.Pattern)
             else re.search(pattern, text))
    if match is None:
        raise GateReadError(f"{path}: could not read {what}")
    line = text.count("\n", 0, match.start()) + 1
    excerpt = text[match.start():match.end()].splitlines()[0].strip()
    return match, GateSource(path, line, excerpt[:200])


_DENYLIST_BLOCK = re.compile(
    r"const\s+SKILL_CONTEXT_DENYLIST\s*:\s*ReadonlySet<string>\s*=\s*new\s+Set\(\[(.*?)\]\)",
    re.DOTALL,
)
_DENYLIST_ENTRY = re.compile(r"^\s*'([^']+)'\s*,?\s*(?://\s*(.*))?$")

_COMPOUND_GATE = re.compile(
    r"if\s*\(isSkillContext\s*&&\s*rule\.tags\.scan_target\s*!==\s*'(?P<a>\w+)'"
    r"\s*&&\s*rule\.tags\.scan_target\s*!==\s*'(?P<b>\w+)'\)\s*\{\s*"
    r"const\s+totalConds[^\n]*?conditions\?\.length\s*\?\?\s*(?P<fallback>\d+)\)\s*;\s*"
    r"const\s+minRequired\s*=\s*Math\.max\((?P<floor>\d+),\s*Math\.ceil\(totalConds\s*\*\s*(?P<ratio>[\d.]+)\)\)\s*;",
    re.DOTALL,
)

_SCAN_SKILL_EVENT = re.compile(
    r"scanSkill\(content: string\): ATRMatch\[\]\s*\{\s*const\s+baseEvent\s*=\s*\{\s*"
    r"type:\s*'(?P<type>\w+)'.*?fields:\s*\{(?P<fields>\s*)\}.*?scanContext:\s*'(?P<ctx>\w+)'",
    re.DOTALL,
)

_STATUS_SKIP = re.compile(
    r"if\s*\(rule\.status\s*===\s*'(?P<a>\w+)'\s*\|\|\s*rule\.status\s*===\s*'(?P<b>\w+)'\)\s*continue;"
)

_FIELD_RESOLUTION = re.compile(
    r"if\s*\(event\.scanContext\s*===\s*'skill'\s*&&\s*event\.content\)\s*\{\s*return\s+event\.content;"
)

_ANY_SHORT_CIRCUIT = re.compile(r"const\s+isAny\s*=[^\n]*\n.*?if\s*\(isAny\)\s*break;", re.DOTALL)

_BASE64_BLOCK_RE = re.compile(r"const\s+BASE64_BLOCK_RE\s*=\s*/\(\?:\[A-Za-z0-9\+/\]\{(?P<min>\d+),\}")
_BASE64_MAX_BLOCKS = re.compile(r"const\s+MAX_DECODE_BLOCKS\s*=\s*(?P<n>\d+);")
_BASE64_KEEP = re.compile(
    r"if\s*\(printable\s*/\s*text\.length\s*>\s*(?P<ratio>[\d.]+)\s*&&\s*text\.length\s*>=\s*(?P<minlen>\d+)\)"
    r"\s*\{\s*decoded\.push\(text\.slice\(0,\s*(?P<cap>[\d_]+)\)\)"
)

_MAX_EVAL_LENGTH = re.compile(r"const\s+MAX_EVAL_LENGTH\s*=\s*(?P<n>[\d_]+);")

_LANE_DEFAULT = re.compile(r"export\s+const\s+DEFAULT_LANE\s*:\s*Lane\s*=\s*'(?P<lane>\w+)';")
_LANE_RETIRED = re.compile(r"if\s*\(m\s*===\s*'(?P<m>\w+)'\)\s*return\s+false;")


def _read_denylist(engine: str) -> tuple[dict[str, str], GateSource]:
    match, source = _find(engine, _DENYLIST_BLOCK, ENGINE_PATH, "SKILL_CONTEXT_DENYLIST")
    entries: dict[str, str] = {}
    for raw in match.group(1).splitlines():
        entry = _DENYLIST_ENTRY.match(raw)
        if entry is None:
            continue
        entries[entry.group(1)] = (entry.group(2) or "").strip()
    if not entries:
        raise GateReadError(f"{ENGINE_PATH}: SKILL_CONTEXT_DENYLIST parsed to nothing")
    return entries, source


def _denylist_is_applied(engine: str) -> bool:
    """True when the engine reads the set, rather than only declaring it.

    At ``faf743f`` the only occurrence is the declaration. Upstream's own
    ``docs/research/clawhub-benign-fp-2026-08-19.md`` reaches the same
    conclusion and names the one reachable member it therefore fails to exclude.
    """
    uses = [m for m in re.finditer(r"SKILL_CONTEXT_DENYLIST", engine)]
    declaration = re.search(r"const\s+SKILL_CONTEXT_DENYLIST", engine)
    if declaration is None:
        raise GateReadError(f"{ENGINE_PATH}: SKILL_CONTEXT_DENYLIST is not declared")
    return any(use.start() != declaration.end() - len("SKILL_CONTEXT_DENYLIST") for use in uses)


def read_skill_gates(root: Path, *, source_rev: str) -> SkillGates:
    """Read every gate ``scanSkill()`` applies, from ``root``.

    ``root`` is an ATR checkout. Raises :class:`GateReadError` when a gate this
    package depends on is missing or has changed shape, which is the intended
    behavior: an unread gate would silently restore the false-positive rate this
    module was written to remove.
    """
    root = Path(root)
    engine_file = root / ENGINE_PATH
    if not engine_file.is_file():
        raise GateReadError(f"{ENGINE_PATH} not found under {root}")
    engine = engine_file.read_text(encoding="utf-8")
    provenance: dict[str, GateSource] = {}

    denylist, provenance["denylist"] = _read_denylist(engine)
    applied = _denylist_is_applied(engine)

    compound, provenance["compound_gate"] = _find(
        engine, _COMPOUND_GATE, ENGINE_PATH, "the skill-context compound gate")
    event, provenance["scan_skill_event"] = _find(
        engine, _SCAN_SKILL_EVENT, ENGINE_PATH, "the scanSkill() base event")
    status, provenance["status_skip"] = _find(
        engine, _STATUS_SKIP, ENGINE_PATH, "the status skip")
    _, provenance["field_resolution"] = _find(
        engine, _FIELD_RESOLUTION, ENGINE_PATH,
        "the skill-context field resolution")
    _, provenance["any_short_circuit"] = _find(
        engine, _ANY_SHORT_CIRCUIT, ENGINE_PATH,
        "the any-logic short circuit that caps matchedConditions at 1")
    block_re, provenance["base64_block"] = _find(
        engine, _BASE64_BLOCK_RE, ENGINE_PATH, "the base64 block pattern")
    max_blocks, provenance["base64_max_blocks"] = _find(
        engine, _BASE64_MAX_BLOCKS, ENGINE_PATH, "MAX_DECODE_BLOCKS")
    keep, provenance["base64_keep"] = _find(
        engine, _BASE64_KEEP, ENGINE_PATH, "the base64 keep test")
    enforcement_file = root / ENFORCEMENT_PATH
    if not enforcement_file.is_file():
        raise GateReadError(f"{ENFORCEMENT_PATH} not found under {root}")
    max_eval, provenance["max_eval_length"] = _find(
        engine, _MAX_EVAL_LENGTH, ENGINE_PATH,
        "MAX_EVAL_LENGTH, above which the source evaluates no pattern at all")
    lane, provenance["lane_default"] = _find(
        enforcement_file.read_text(encoding="utf-8"), _LANE_DEFAULT, ENFORCEMENT_PATH,
        "the default detection lane")

    contract_file = root / CONTRACT_PATH
    if not contract_file.is_file():
        raise GateReadError(f"{CONTRACT_PATH} not found under {root}")
    contract = contract_file.read_text(encoding="utf-8")
    retired, provenance["lane_retired"] = _find(
        contract, _LANE_RETIRED, CONTRACT_PATH,
        "the maturity that never fires in any lane")

    interface_file = root / INTERFACE_CONTRACT_PATH
    required_by_contract = (
        interface_file.is_file()
        and "MUST honor SKILL_CONTEXT_DENYLIST" in interface_file.read_text(encoding="utf-8")
    )
    if required_by_contract:
        _, provenance["denylist_interface_contract"] = _find(
            interface_file.read_text(encoding="utf-8"),
            r"MUST honor SKILL_CONTEXT_DENYLIST[^\n]*", INTERFACE_CONTRACT_PATH,
            "the interface-contract requirement to honor the denylist")

    return SkillGates(
        source_rev=source_rev,
        event_type=event.group("type"),
        scan_context=event.group("ctx"),
        exempt_scan_targets=frozenset({compound.group("a"), compound.group("b")}),
        min_conditions_floor=int(compound.group("floor")),
        min_conditions_ratio=float(compound.group("ratio")),
        any_logic_short_circuits=True,
        every_field_resolves_to_content=True,
        skipped_statuses=frozenset({status.group("a"), status.group("b")}),
        denylist=dict(denylist),
        denylist_applied=applied,
        denylist_required_by_interface_contract=required_by_contract,
        base64_max_blocks=int(max_blocks.group("n")),
        base64_min_block_chars=int(block_re.group("min")),
        base64_min_decoded_chars=int(keep.group("minlen")),
        base64_min_printable_ratio=float(keep.group("ratio")),
        base64_max_decoded_chars=int(keep.group("cap").replace("_", "")),
        max_eval_chars=int(max_eval.group("n").replace("_", "")),
        lane_default=lane.group("lane"),
        lane_blocked_maturities=frozenset({retired.group("m")}),
        provenance=dict(provenance),
    )


def gate_summary(gates: SkillGates) -> dict:
    """A serializable record of what was read, for the audit trail."""
    return {
        "source_rev": gates.source_rev,
        "entry_point": "scanSkill",
        "event_type": gates.event_type,
        "scan_context": gates.scan_context,
        "exempt_scan_targets": sorted(gates.exempt_scan_targets),
        "min_conditions": {"floor": gates.min_conditions_floor,
                           "ratio": gates.min_conditions_ratio},
        "any_logic_short_circuits": gates.any_logic_short_circuits,
        "every_field_resolves_to_content": gates.every_field_resolves_to_content,
        "skipped_statuses": sorted(gates.skipped_statuses),
        "lane_default": gates.lane_default,
        "lane_blocked_maturities": sorted(gates.lane_blocked_maturities),
        "denylist": {"size": len(gates.denylist),
                     "applied_by_engine": gates.denylist_applied,
                     "required_by_interface_contract":
                         gates.denylist_required_by_interface_contract,
                     "ids": sorted(gates.denylist)},
        "base64": {"max_blocks": gates.base64_max_blocks,
                   "min_block_chars": gates.base64_min_block_chars,
                   "min_decoded_chars": gates.base64_min_decoded_chars,
                   "min_printable_ratio": gates.base64_min_printable_ratio,
                   "max_decoded_chars": gates.base64_max_decoded_chars},
        "max_eval_chars": gates.max_eval_chars,
        "read_from": {name: str(src) for name, src in sorted(gates.provenance.items())},
    }


__all__ = [
    "GateReadError",
    "GateSource",
    "SkillGates",
    "gate_summary",
    "read_skill_gates",
]
