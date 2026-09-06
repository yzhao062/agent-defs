"""Load ATR's declared pattern path without flattening field constraints.

``root`` is an ATR Git checkout, or a fixture directory with an
``atr-source.json`` manifest containing source_rev and a files mapping from
local names to {source_path, sha256}. Corpus data is never executable code.
PyYAML is imported only inside ``load`` (install ``agent-defs[atr]``).
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .. import evaluate
from ..model import (
    Breadth, ChannelBinding, Gate, Lane, Lineage, PredicateKind, Rule, Surface,
)
from ..rights import EXCLUDED_SOURCE_PATHS, agentharm_restriction, excluded_source_path
from . import atr_skill_gates

UPSTREAM = "https://github.com/Agent-Threat-Rule/agent-threat-rules"
POLICY = {"name": "agent-defs.atr", "version": 1, "date": "2026-09-04"}


@dataclass
class Delta:
    """Counts are occurrences, except extra_fields, which counts entries.

    Raw fields retained in extra are not losses. Unsupported constructs are
    retained as data but are absent from the executable predicate. Rejections
    include every rejected occurrence, even in already non-runnable rules.
    """

    entries_read: int = 0
    rules_emitted: int = 0
    source_rev: str = ""
    excluded_paths: dict[str, int] = field(default_factory=dict)
    dropped_fields: dict[str, int] = field(default_factory=dict)
    extra_fields: dict[str, int] = field(default_factory=dict)
    unsupported_constructs: dict[str, int] = field(default_factory=dict)
    pattern_rejections: list[dict[str, Any]] = field(default_factory=list)
    entry_errors: list[dict[str, str]] = field(default_factory=list)
    # Conversions this loader applied rather than constructs it could not carry.
    dialect_ports: dict[str, int] = field(default_factory=dict)
    composition_fallbacks: dict[str, int] = field(default_factory=dict)
    #: What was read out of ATR's own dispatcher, and where. ``read`` is False
    #: for a checkout that carries rules without engine sources, in which case no
    #: rule gets a CFG binding and the CFG bundle is empty rather than wrong.
    skill_gates: dict[str, Any] = field(default_factory=lambda: {"read": False})
    #: Per-rule verdicts of ATR's skill-path gates, counted by outcome.
    cfg_gate_counts: dict[str, int] = field(default_factory=dict)


@dataclass
class LoadResult:
    rules: list[Rule]
    delta: Delta


# These are diagnostic witnesses for common text constructs, not an admission
# corpus or independent benign trials. A hit keeps a rule out of NARROW.
BREADTH_PROBES = (
    "Please summarize this document in three sentences.",
    "Translate this paragraph into French and keep the formatting.",
    "Write a short story about a friendly robot in a library.",
    "Explain the difference between a list and a tuple in Python.",
    "The meeting is tomorrow at 10. Please send the agenda to the team.",
    "Thank you for your help. I appreciate the detailed explanation.",
    "The results show an improvement over the baseline on the test set.",
    "This experiment uses a language model and a public benchmark dataset.",
    "The customer asked us to update their delivery address.",
    "The documentation describes the configuration and installation process.",
    "Retrying connection: attempt 2 of 3. The request timed out.",
    "Please wait while the report is generated. Task completed successfully.",
    "Run the tests and check the build log for errors.",
    "Use the official documentation to install this package.",
    "import os\nfrom pathlib import Path\nprint(Path.cwd())",
    'const module = await import(packageName);',
    'const module = require(packageName);',
    'const answer = eval("2 + 2");',
    "curl https://example.com/manual.txt -o manual.txt",
    "python -m pip install numpy",
    "git status\ngit diff --stat",
    "SELECT name, email FROM customers WHERE id = 42;",
    'Contact support@example.com or visit https://example.com/help.',
    '![Build status](https://example.com/badge.svg)',
    "The configuration file stores the API key in an environment variable.",
    "The user's email address is alice@example.com.",
    "2026-09-04 10:30:00 INFO request completed status=200 latency=42ms",
    '{"name": "weather", "description": "Returns the current forecast."}',
    "The authentication token expires after one hour.",
    "Please review the attached report when you have time :)",
    "Hello world!",
    "\n\n",
    "   ",
    "",
)

_TEXT_FIELDS = {
    "input", "content", "user_input", "agent_output", "tool_response",
    "tool_description", "tool_args", "tool_name", "tool_input", "response",
}
_PROJECT_AUTHORS = {
    "ATR Community", "ATR Project", "ATR Threat Cloud Crystallization",
    "Threat Cloud LLM Analyzer", "ATR Community (MiroFish Predicted)",
    "ATR Community (Crystallization Pipeline)",
}
_CORPUS_MARKERS = ("garak", "corpus", "benchmark", "DoNotAnswer")


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *args], check=True, capture_output=True,
        text=True, encoding="utf-8",
    ).stdout.strip()


def _source_files(root: Path, source_rev: str | None = None):
    excluded = {prefix: {p.relative_to(root).as_posix()
                         for p in (root / prefix).rglob("*") if p.is_file()}
                for prefix in EXCLUDED_SOURCE_PATHS["atr"]}
    manifest_path = root / "atr-source.json"
    if manifest_path.is_file():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        revision = manifest["source_rev"]
        files = []
        for local, info in sorted(manifest["files"].items()):
            prefix = excluded_source_path("atr", info["source_path"])
            if prefix:
                excluded[prefix].add(info["source_path"])
                continue
            path = (root / local).resolve()
            if not path.is_relative_to(root):
                raise ValueError(f"ATR fixture path escapes root: {local}")
            if hashlib.sha256(path.read_bytes()).hexdigest() != info["sha256"]:
                raise ValueError(f"ATR fixture checksum mismatch: {local}")
            files.append((path, info["source_path"]))
    else:
        if not (root / ".git").exists() and source_rev is None:
            raise ValueError("ATR root needs Git metadata or atr-source.json; cannot invent source_rev")
        revision = source_rev
        if (root / ".git").exists():
            revision = _git(root, "rev-parse", "HEAD")
            _git(root, "diff", "--quiet", "HEAD", "--", "rules", "LICENSE")
            if _git(root, "ls-files", "--others", "--exclude-standard", "--", "rules"):
                raise ValueError("ATR rules include untracked files; source_rev would be misleading")
        if not (root / "rules").is_dir():
            raise ValueError("ATR root has no rules directory")
        files = [(p, p.relative_to(root).as_posix()) for p in sorted((root / "rules").rglob("*"))
                 if p.suffix in {".yaml", ".yml"} and p.is_file()]
    if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("ATR source_rev must be a full 40-character Git SHA")
    if source_rev is not None and source_rev != revision:
        raise ValueError("ATR source_rev disagrees with source metadata")
    license_text = (root / "LICENSE").read_text(encoding="utf-8")
    license_spdx = "MIT" if license_text.startswith("MIT License") else ""
    return revision, files, license_spdx, {p: len(paths) for p, paths in excluded.items()}


def _lineage(author: str, url: str) -> tuple[tuple[Lineage, ...], dict[str, Any]]:
    # Preserve the entire scalar, including attribution around a named corpus.
    spans = [{"start": m.start(), "end": m.end(), "value": m.group()}
             for m in re.finditer(r"\([^()]*\)", author)]
    markers = [marker for marker in _CORPUS_MARKERS if marker.lower() in author.lower()]
    classification = ("corpus_or_benchmark" if markers else
                      "project_attribution" if author in _PROJECT_AUTHORS else
                      "other_attribution")
    return ((Lineage("author_field", author, f"{url} (YAML author)"),) if author else ()), {
        "method": "whole author scalar verbatim; parenthetical spans are annotations only",
        "parenthetical_spans": spans,
        "classification": classification,
        "corpus_marker_matches": markers,
    }


def _surface(raw: dict[str, Any]) -> tuple[Surface, dict[str, Any]]:
    detection, tags = raw["detection"], raw.get("tags", {})
    target = tags.get("scan_target")
    conditions = detection.get("conditions", [])
    fields = sorted({c.get("field", "") for c in conditions if isinstance(c, dict)}, key=str) if isinstance(conditions, list) else []
    method = detection.get("method", "pattern")
    if method in {"trace", "behavioral"}:
        return Surface.NONE, {"reason": f"{method} requires state outside text hooks", "fields": fields}
    if target == "skill":
        surface, reason = Surface.CFG, "tags.scan_target=skill"
    elif target == "user_input":
        surface, reason = Surface.PROMPT, "tags.scan_target=user_input"
    elif target in {"tool_args", "tool_call"}:
        surface, reason = Surface.IN, f"tags.scan_target={target}"
    elif target in {"tool_output", "tool_response"}:
        surface, reason = Surface.OUT, f"tags.scan_target={target}"
    elif fields == ["tool_description"]:
        surface, reason = Surface.CFG, "condition field tool_description is a tool manifest"
    elif fields == ["user_input"]:
        surface, reason = Surface.PROMPT, "condition field user_input"
    elif fields and set(fields) <= {"tool_name", "tool_args", "tool_input"}:
        surface, reason = Surface.IN, "condition fields identify a tool invocation"
    elif "tool_response" in fields or fields == ["agent_output"]:
        surface, reason = Surface.OUT, "condition fields identify returned text"
    elif raw.get("agent_source", {}).get("type") == "tool_call":
        surface, reason = Surface.IN, "agent_source.type=tool_call"
    elif tags.get("category") in {"skill-compromise", "tool-poisoning"}:
        surface, reason = Surface.CFG, "generic content in skill/tool configuration category (inferred)"
    else:
        surface, reason = Surface.OUT, "generic content at the external-text interception point (inferred)"
    return surface, {"reason": reason, "fields": fields, "scan_target": target,
                     "single_surface_limitation": len(fields) > 1}


def _strings(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list):
        return tuple(item for item in value if isinstance(item, str))
    return ()


def _leaf_strings(value: Any, path: str = "") -> list[tuple[str, str]]:
    if isinstance(value, str):
        return [(path, value)]
    if isinstance(value, dict):
        return [(p, s) for k, v in value.items()
                for p, s in _leaf_strings(v, f"{path}.{k}" if path else k)]
    if isinstance(value, list):
        return [(p, s) for i, v in enumerate(value)
                for p, s in _leaf_strings(v, f"{path}[{i}]")]
    return []


def _examples(raw: dict[str, Any], polarity: str) -> tuple[tuple[str, ...], list[dict[str, Any]]]:
    values, origins = [], []
    conditions = raw["detection"].get("conditions", [])
    fields = {c.get("field") for c in conditions if isinstance(c, dict)} if isinstance(conditions, list) else set()
    for index, example in enumerate(raw.get("test_cases", {}).get(polarity, [])):
        # Do not stringify event objects: that would manufacture searchable text.
        payload = example if isinstance(example, str) else {
            k: v for k, v in example.items() if k in _TEXT_FIELDS or k == "tool_call"
        }
        leaves = _leaf_strings(payload)
        if len(fields) == 1:
            target = next(iter(fields))
            aliases = {target, f"input.{target}"}
            if target == "tool_response":
                aliases.update({"input.response", "response"})
            elif target == "tool_args":
                aliases.add("tool_call.args")
            elif target == "tool_name":
                aliases.add("tool_call.name")
            selected = [(p, s) for p, s in leaves if p in aliases]
            if not selected:
                # ATR uses plain input for any event type. Extra tool metadata
                # beside that input is context, not a second positive payload.
                for candidate in ("tool_response", "input", "content", "input.response",
                                  "input.tool_args", "tool_args", "user_input", "agent_output",
                                  "tool_description", "tool_name", "input.tool_name"):
                    selected = [(p, s) for p, s in leaves if p == candidate]
                    if selected:
                        break
            leaves = selected
        for path, text in leaves:
            values.append(text)
            origins.append({"test_case": index, "path": path})
    return tuple(values), origins


def _scoped(pattern: str) -> str:
    """Scope leading global flags before placing an expression in a union."""
    flags = ""
    while match := re.match(r"^\(\?([aiLmsux]+)\)", pattern):
        flags += match[1]
        pattern = pattern[match.end():]
    return f"(?{''.join(dict.fromkeys(flags))}:{pattern})" if flags else f"(?:{pattern})"


def _predicate(raw: dict[str, Any], rid: str, delta: Delta) -> tuple[PredicateKind, Any, list[str], dict[str, Any]]:
    detection = raw["detection"]
    conditions = detection.get("conditions", [])
    reasons: list[str] = []
    patterns: list[str] = []
    safe: list[bool] = []
    decisions: dict[str, Any] = {"method": detection.get("method", "pattern"),
                               "case_sensitive_reason": "ATR array regex conditions use implicit IGNORECASE"}

    def unsupported(name: str, reason: str) -> None:
        delta.unsupported_constructs[name] = delta.unsupported_constructs.get(name, 0) + 1
        reasons.append(reason)

    # One lookup for the whole rule, keyed on the condition texts that were timed.
    # A rule the measurement found crossing the hook budget is refused here, once,
    # with its numbers. A rule it found staying under carries that verdict down to
    # every condition, which is sound because a rule recorded as not crossing had
    # all of its patterns measured. An unmeasured rule is screened on shape.
    upstream_patterns = [c["value"] for c in conditions
                         if isinstance(c, dict) and c.get("operator") == "regex"
                         and isinstance(c.get("value"), str)] if isinstance(conditions, list) else []
    measurement = evaluate.measurement_for_rule("atr", raw["id"], upstream_patterns)
    if measurement is not None:
        decisions["measurement"] = {"verdict": measurement.verdict, "budget_s": measurement.budget_s,
                                    "crossing_bytes": measurement.crossing_bytes,
                                    "wall_s": measurement.wall_s, "over_60s": measurement.over_60s,
                                    "method": measurement.method, "measured_at": measurement.measured_at}
        if measurement.slow:
            unsupported("detection.conditions.regex.measured_backtracking",
                        f"refused on measurement: {measurement.refusal()}")
    else:
        decisions["measurement"] = {"verdict": "unmeasured",
                                    "reason": "no timing record for this rule at this content"}
    branch_measurement = measurement if measurement is not None and not measurement.slow else None

    method = detection.get("method", "pattern")
    if method == "semantic":
        if detection.get("semantic", {}).get("fallback_method") == "pattern":
            decisions["fallback"] = "detection.semantic.fallback_method=pattern"
            name = "detection.semantic.model_execution"
            delta.unsupported_constructs[name] = delta.unsupported_constructs.get(name, 0) + 1
        else:
            unsupported("detection.semantic.without_pattern_fallback", "semantic method has no declared pattern fallback")
    elif method != "pattern":
        unsupported(f"detection.{method}", f"{method} method needs a stateful engine")
    if raw.get("status") in {"draft", "deprecated"}:
        unsupported(f"status.{raw['status']}", f"upstream status={raw['status']} disables execution")
    if raw.get("tags", {}).get("suppress_in_code_blocks"):
        unsupported("tags.suppress_in_code_blocks", "code-block suppression has no faithful text predicate")
    for key in detection.keys() - {"method", "conditions", "condition", "false_positives", "semantic", "trace", "behavioral"}:
        unsupported(f"detection.{key}", f"unsupported detection field: {key}")
    if not isinstance(conditions, list) or not conditions:
        unsupported("detection.conditions.shape", "expected a nonempty list of ATR conditions")
        conditions = []
    fields = {c.get("field") for c in conditions if isinstance(c, dict)}
    if len(fields) > 1:
        unsupported("detection.conditions.multiple_fields", "multiple condition fields cannot be flattened into one text payload")
    allowed = {"content", "user_input", "tool_response", "agent_output", "tool_description", "tool_args", "tool_name", "tool_input"}
    for field_name in sorted(fields - allowed, key=str):
        unsupported(f"detection.conditions.field.{field_name}", f"unsupported input field: {field_name}")
    for index, condition in enumerate(conditions):
        if not isinstance(condition, dict):
            unsupported("detection.conditions.item", "condition is not a mapping")
            continue
        for key in condition.keys() - {"field", "operator", "value", "description"}:
            unsupported(f"detection.conditions.{key}", f"unsupported condition modifier: {key}")
        if condition.get("operator") != "regex" or not isinstance(condition.get("value"), str):
            unsupported("detection.conditions.operator_or_value", "expected operator=regex and a string value")
            continue
        # ATR's own engine is TypeScript, so its regexes are written against
        # JavaScript's UTF-16 code units. Read the surrogate pairs back as the
        # code points they encode before anything screens or runs them.
        pattern, port_notes = evaluate.port_utf16_surrogates(condition["value"])
        if port_notes:
            decisions.setdefault("utf16_port", []).append({"condition_index": index, "notes": port_notes})
            key = ("detection.conditions.regex.utf16_unpaired_surrogate"
                   if any(note.get("unpaired") for note in port_notes)
                   else "detection.conditions.regex.utf16_surrogate_pair")
            delta.dialect_ports[key] = delta.dialect_ports.get(key, 0) + 1
        patterns.append(pattern)
        try:
            evaluate.screen_pattern(pattern, measurement=branch_measurement,
                                    require_measurement=True)
        except evaluate.UnsafePattern as exc:
            safe.append(False)
            delta.pattern_rejections.append({"rule_id": rid, "condition_index": index,
                                             "stage": "upstream", "reason": str(exc)})
            unsupported("detection.conditions.regex.screen_rejected", f"condition {index}: {exc}")
        else:
            safe.append(True)
    logic = detection.get("condition")
    if logic not in {"any", "all"}:
        unsupported("detection.condition", f"unsupported condition logic: {logic!r}")

    # Probe only screened expressions. Even a rejected ANY rule can have an
    # accepted branch proving that its published condition matches common text.
    witnesses = []
    compiled = [(re.compile(p, re.IGNORECASE) if ok else None) for p, ok in zip(patterns, safe)]
    for index, probe in enumerate(BREADTH_PROBES):
        hits = [bool(p.search(probe)) if p else False for p in compiled]
        if hits and (all(hits) if logic == "all" else any(hits)):
            witnesses.append(index)
    decisions["breadth"] = {"policy": "common-text-witness-v1", "probe_indices": witnesses,
                            "reason": "BROAD when a screened path accepts a common text construct; otherwise MEDIUM, unmeasured"}
    if reasons:
        return PredicateKind.NONE, None, reasons, decisions

    if logic == "all" and len(patterns) > 1:
        decisions["composition"] = "independent screened regex searches; all must match the same payload"
        return PredicateKind.STRUCTURED, {"regex_all": patterns}, [], decisions

    predicate = patterns[0]
    if len(patterns) > 1:
        # Joining independently numbered backreferences can silently redirect a
        # reference into a previous branch. Do not rewrite their meaning.
        if any(re.search(r"(?<!\\)(?:\\\\)*\\[1-9]|\(\?P=|\(\?\(", p) for p in patterns):
            unsupported("detection.conditions.regex.backreference_composition", "backreferences cannot be safely composed across conditions")
            return PredicateKind.NONE, None, reasons, decisions
        scoped = [_scoped(p) for p in patterns]
        predicate = "|".join(scoped)
        decisions["composition"] = "scoped regex alternation"
        try:
            evaluate.screen_pattern(predicate, measurement=branch_measurement,
                                    require_measurement=True)
        except evaluate.UnsafePattern as exc:
            delta.pattern_rejections.append({"rule_id": rid, "condition_index": None,
                                             "stage": "composed", "reason": str(exc)})
            # Every branch passed on its own, so what failed is the join, and the
            # join is ours. Keep the disjunction the source published rather than
            # dropping the rule for the shape of a string it never wrote.
            if len(patterns) > evaluate.MAX_STRUCTURED_PATTERNS:
                unsupported("detection.conditions.regex.composition_screen_rejected",
                            f"composed predicate: {exc}; more than "
                            f"{evaluate.MAX_STRUCTURED_PATTERNS} branches to carry separately")
                return PredicateKind.NONE, None, reasons, decisions
            delta.composition_fallbacks[str(exc)] = delta.composition_fallbacks.get(str(exc), 0) + 1
            decisions["composition"] = ("independent screened regex searches; any may match "
                                        f"(alternation not carried: {exc})")
            return PredicateKind.STRUCTURED, {"regex_any": patterns}, [], decisions
    return PredicateKind.REGEX, predicate, [], decisions


#: The one method ATR's synchronous skill entry point evaluates as patterns.
#: ``scanSkill()`` builds an event with no trace, no fields and no session, so a
#: trace, signature or behavioral rule has nothing to read there, and a semantic
#: rule reaches ``evaluatePatternRule`` only through a declared pattern fallback.
#: Upstream's own ``skillUnreachableReason()`` names the same exclusions.
_CFG_PATTERN_METHOD = "pattern"
_CFG_SEMANTIC_METHOD = "semantic"


def _cfg_method_reachable(detection: dict[str, Any]) -> tuple[bool, str]:
    method = detection.get("method", _CFG_PATTERN_METHOD)
    if method == _CFG_PATTERN_METHOD:
        return True, "detection.method=pattern"
    if method == _CFG_SEMANTIC_METHOD:
        fallback = (detection.get("semantic") or {}).get("fallback_method")
        if fallback == _CFG_PATTERN_METHOD:
            return True, "detection.method=semantic with a declared pattern fallback"
        return False, ("detection.method=semantic with no pattern fallback; the "
                       "synchronous skill path has no judge and returns no match")
    return False, (f"detection.method={method!r}; scanSkill() supplies no trace, "
                   f"fields or session for it to read")


def _cfg_binding(raw: dict[str, Any],
                 gates: atr_skill_gates.SkillGates) -> ChannelBinding:
    """Build the record of how ATR's ``scanSkill()`` treats this rule.

    Every gate is consulted in the order the engine consults it, and every gate
    is recorded whether it passed or refused, so a reader can see which one
    excluded a rule rather than only that something did. The gate values come
    from :func:`atr_skill_gates.read_skill_gates`, which reads them out of the
    checkout; nothing below decides a threshold on its own.

    Two things differ from the flat predicate this loader also builds, and both
    are upstream's own semantics rather than a relaxation:

    * every condition field resolves to the whole document, so a rule the flat
      predicate refuses for naming two fields runs here unchanged;
    * conditions are evaluated one at a time and never composed, so a rule the
      flat predicate refuses because the *composed* alternation trips the screen
      runs here on the conditions that pass individually.

    A condition our screen refuses is dropped from an ``any`` rule and recorded.
    That can only lose matches, never add them, because ``any`` fires on one
    branch. An ``all`` rule loses its whole binding instead: dropping a branch
    there would make the rule fire on less evidence than its author required.
    """
    detection = raw.get("detection") or {}
    tags = raw.get("tags") or {}
    conditions = detection.get("conditions")
    logic = detection.get("condition")
    scan_target = tags.get("scan_target")
    checked: list[Gate] = []
    refusals: list[str] = []
    where = {name: str(src) for name, src in gates.provenance.items()}

    def gate(name: str, ok: bool, detail: str, key: str = "") -> bool:
        checked.append(Gate(name, "pass" if ok else "block", detail,
                            where.get(key or name, "")))
        if not ok:
            refusals.append(detail)
        return ok

    passes = gate(
        "status", raw.get("status") not in gates.skipped_statuses,
        f"status={raw.get('status')!r}; the engine skips "
        f"{sorted(gates.skipped_statuses)}", "status_skip")
    passes &= gate(
        "lane", str(raw.get("maturity", "")).strip() not in gates.lane_blocked_maturities,
        f"maturity={raw.get('maturity')!r}; the default {gates.lane_default!r} lane "
        f"admits every maturity except {sorted(gates.lane_blocked_maturities)}",
        "lane_default")
    method_ok, method_detail = _cfg_method_reachable(detection)
    passes &= gate("method", method_ok, method_detail, "scan_skill_event")
    shape_ok = isinstance(conditions, list) and bool(conditions) and logic in {"any", "all"}
    passes &= gate(
        "conditions",
        shape_ok,
        f"{len(conditions)} array-format conditions under condition={logic!r}"
        if shape_ok else
        f"detection.conditions is {type(conditions).__name__} with "
        f"condition={logic!r}; expected a nonempty list under any or all")

    count = len(conditions) if isinstance(conditions, list) else 0
    required = gates.min_required_conditions(count)
    exempt = scan_target in gates.exempt_scan_targets
    # An ``any`` rule short-circuits on its first matching condition, so the
    # engine can never report more than one matched condition for it, and the
    # gate's floor is two. That makes the gate an unconditional reject for every
    # ``any`` rule that is not declared for this channel.
    reachable = count if logic == "all" else 1
    compound_ok = exempt or reachable >= required
    passes &= gate(
        "skill_compound", compound_ok,
        f"scan_target={scan_target!r} is exempt from the compound gate"
        if exempt else
        f"scan_target={scan_target!r} is not in {sorted(gates.exempt_scan_targets)} "
        f"and condition={logic!r} over {count} conditions can report at most "
        f"{reachable} matched, against the {required} the gate requires",
        "compound_gate")

    checked.append(Gate(
        "field_resolution", "pass",
        "scanSkill() resolves every condition field to the whole document, so "
        "field constraints do not narrow this rule here",
        where.get("field_resolution", "")))

    denylisted = raw.get("id") in gates.denylist
    if denylisted:
        note = gates.denylist.get(raw.get("id"), "")
        if gates.denylist_applied:
            passes &= gate("skill_denylist", False,
                           f"listed in SKILL_CONTEXT_DENYLIST: {note}", "denylist")
        else:
            checked.append(Gate(
                "skill_denylist", "declared-not-applied",
                f"declared in SKILL_CONTEXT_DENYLIST ({note}) and the pinned engine "
                f"never reads the set, while the engine interface contract still says "
                f"a conforming engine must honor it",
                where.get("denylist", "")))

    usable: list[str] = []
    dropped: list[dict[str, Any]] = []
    if shape_ok:
        for index, condition in enumerate(conditions):
            reason = ""
            if not isinstance(condition, dict):
                reason = "condition is not a mapping"
            elif condition.get("operator") != "regex" or not isinstance(condition.get("value"), str):
                reason = "expected operator=regex and a string value"
            elif condition.keys() - {"field", "operator", "value", "description"}:
                extra = sorted(condition.keys() - {"field", "operator", "value", "description"})
                reason = f"unsupported condition modifier(s): {extra}"
            else:
                # Port the source dialect's surrogate pairs before screening, and
                # keep the ported text. Screening the raw string refused
                # ATR-2026-00129 here for an unpaired surrogate while the flat
                # path, which ports first, ran it. The channel that reads skill
                # documents was the one losing the rule.
                ported, _notes = evaluate.port_utf16_surrogates(condition["value"])
                try:
                    evaluate.screen_pattern(ported, require_measurement=True)
                except evaluate.UnsafePattern as exc:
                    reason = str(exc)
            if reason:
                dropped.append({"condition_index": index, "reason": reason})
            else:
                usable.append(ported)

    if dropped and logic == "all":
        passes &= gate(
            "screen", False,
            f"{len(dropped)} of {count} conditions refused under condition=all; "
            f"dropping one would fire the rule on less evidence than its author "
            f"required: {dropped}")
    elif dropped:
        checked.append(Gate(
            "screen", "pass" if usable else "block",
            f"{len(dropped)} of {count} conditions refused and dropped from an "
            f"any-logic rule, which can only lose matches: {dropped}"))
        if not usable:
            passes = False
            refusals.append("every condition was refused by the pattern screen")

    if passes and not usable:
        passes = False
        refusals.append("no executable condition survives")

    reason = ("admitted by ATR's skill dispatcher" if passes
              else "; ".join(refusals) or "refused by ATR's skill dispatcher")
    return ChannelBinding(
        channel=Surface.CFG.value, entry_point="scanSkill", eligible=passes,
        reason=reason, gates=tuple(checked), condition_logic=str(logic or ""),
        conditions=tuple(usable) if passes else (),
        suppress_in_code_blocks=bool(tags.get("suppress_in_code_blocks")),
    )


def _join_reasons(reasons: Sequence[str]) -> str:
    """One line per distinct reason, with the conditions that share it.

    Strict measurement refuses per condition, so a rule with six unmeasured
    conditions used to repeat the same sentence six times and push the reason
    past the length a person will read. Group by the text after the condition
    prefix and name the indices once.
    """
    prefix = re.compile(r"^condition (\d+): (.*)$", re.DOTALL)
    order: list[str] = []
    grouped: dict[str, list[str]] = {}
    for reason in reasons:
        match = prefix.match(reason)
        key, index = (match.group(2), match.group(1)) if match else (reason, None)
        if key not in grouped:
            grouped[key] = []
            order.append(key)
        if index is not None:
            grouped[key].append(index)
    parts = []
    for key in order:
        indices = grouped[key]
        if not indices:
            parts.append(key)
        elif len(indices) == 1:
            parts.append(f"condition {indices[0]}: {key}")
        else:
            parts.append(f"conditions {', '.join(indices)}: {key}")
    return "; ".join(parts)


def load(root: Path, *, source_rev: str | None = None) -> LoadResult:
    """Read deterministic Rule records and an enumerated normalization delta.

    A non-runnable entry still emits its identity, metadata, examples, full
    parsed upstream record and exact YAML text. Parse/identity errors appear in
    delta.entry_errors; nothing is silently skipped. All emitted patterns pass
    evaluate.screen_pattern, and a rejected branch disables the entire rule.

    For a verified archive tree without Git metadata, pass its pinned source_rev.
    The caller must verify the archive digest and tree bytes before using that pin.
    Excluded paths are counted by filename and never parsed.
    """
    try:
        import yaml
    except ImportError as exc:
        raise ImportError("ATR loading requires the optional extra: pip install 'agent-defs[atr]'") from exc

    class LiteralLoader(getattr(yaml, "CSafeLoader", yaml.SafeLoader)):
        pass

    LiteralLoader.yaml_implicit_resolvers = {
        key: [(tag, rx) for tag, rx in values if tag != "tag:yaml.org,2002:timestamp"]
        for key, values in LiteralLoader.yaml_implicit_resolvers.items()
    }
    root = Path(root).resolve()
    revision, files, license_spdx, excluded = _source_files(root, source_rev)
    delta = Delta(source_rev=revision, excluded_paths=excluded)
    # The dispatcher is part of the rule. A checkout that carries rule YAML
    # without engine sources produces records with no CFG binding at all, so a
    # caller measuring that channel sees nothing rather than seeing our flat
    # predicate wearing upstream's name.
    gates: atr_skill_gates.SkillGates | None = None
    try:
        gates = atr_skill_gates.read_skill_gates(root, source_rev=revision)
    except atr_skill_gates.GateReadError as exc:
        delta.skill_gates = {"read": False, "reason": str(exc)}
    else:
        delta.skill_gates = {"read": True, **atr_skill_gates.gate_summary(gates)}
    rules: list[Rule] = []
    seen: set[str] = set()
    for path, source_path in files:
        prefix = excluded_source_path("atr", source_path)
        if prefix:
            delta.excluded_paths[prefix] = delta.excluded_paths.get(prefix, 0) + 1
            continue
        delta.entries_read += 1
        raw_text = path.read_bytes().decode("utf-8")
        try:
            raw = yaml.load(raw_text, Loader=LiteralLoader)
            if not isinstance(raw, dict) or not isinstance(raw.get("id"), str) or not raw["id"]:
                raise ValueError("missing nonempty string id")
            if raw["id"] in seen:
                raise ValueError(f"duplicate id: {raw['id']}")
            for key in ("title", "description", "severity", "maturity", "author"):
                if key in raw and not isinstance(raw[key], str):
                    raise ValueError(f"{key} must be a string; refusing coercion")
            if not isinstance(raw.get("detection"), dict):
                raise ValueError("detection must be a mapping")
            for key in ("tags", "references", "test_cases", "agent_source"):
                if key in raw and not isinstance(raw[key], dict):
                    raise ValueError(f"{key} must be a mapping")
        except (yaml.YAMLError, ValueError) as exc:
            delta.entry_errors.append({"source_path": source_path, "reason": str(exc), "upstream_yaml": raw_text})
            key = "entry.parse_or_identity"
            delta.dropped_fields[key] = delta.dropped_fields.get(key, 0) + 1
            continue
        seen.add(raw["id"])
        rid = f"atr:{raw['id']}"
        url = f"{UPSTREAM}/blob/{revision}/{source_path}"
        lineage, lineage_decision = _lineage(raw.get("author", ""), url)
        provenance = raw.get("metadata_provenance")
        if isinstance(provenance, dict) and isinstance(provenance.get("payload_source"), str):
            lineage += (Lineage("payload_source", provenance["payload_source"],
                                f"{url} (YAML metadata_provenance.payload_source)"),)
        restricted_reason = agentharm_restriction(raw)
        surface, surface_decision = _surface(raw)
        kind, predicate, reasons, execution = _predicate(raw, rid, delta)
        positive, positive_origins = _examples(raw, "true_positives")
        negative, negative_origins = _examples(raw, "true_negatives")
        fp = _strings(raw["detection"].get("false_positives")) + _strings(raw.get("false_positives"))
        bindings: tuple[ChannelBinding, ...] = ()
        if gates is not None:
            binding = _cfg_binding(raw, gates)
            bindings = (binding,)
            outcome = "eligible" if binding.eligible else "refused"
            delta.cfg_gate_counts[outcome] = delta.cfg_gate_counts.get(outcome, 0) + 1
            for checked in binding.gates:
                if checked.verdict in {"block", "declared-not-applied"}:
                    key = f"{outcome}:{checked.name}:{checked.verdict}"
                    delta.cfg_gate_counts[key] = delta.cfg_gate_counts.get(key, 0) + 1
        for key in raw:
            delta.extra_fields[key] = delta.extra_fields.get(key, 0) + 1
        rules.append(Rule(
            id=rid, source="atr", source_id=raw["id"], source_rev=revision,
            source_path=source_path, upstream_url=url, lineage=lineage,
            license_spdx=license_spdx, redistribution="unresolved",
            restricted=bool(restricted_reason), restricted_reason=restricted_reason,
            title=raw.get("title", ""), description=raw.get("description", ""),
            severity_raw=raw.get("severity", ""), severity_field="severity" if "severity" in raw else "",
            maturity_raw=raw.get("maturity", ""),
            tags=tuple(s for value in raw.get("tags", {}).values() for s in _strings(value)),
            references=tuple(s for value in raw.get("references", {}).values() for s in _strings(value)),
            surface=surface, breadth=Breadth.BROAD if execution["breadth"]["probe_indices"] else Breadth.MEDIUM,
            predicate_kind=kind, predicate=predicate,
            not_runnable_reason=_join_reasons(reasons),
            case_sensitive=False, bindings=bindings,
            examples_positive=positive, examples_negative=negative,
            false_positive_notes=fp,
            lane=Lane.RECORD if (kind is not PredicateKind.NONE
                                 or any(b.executable for b in bindings)) else Lane.DO_NOT_SHIP,
            lane_reason=("No independent benign measurement" if kind is not PredicateKind.NONE
                         else "Runs only through ATR's own skill dispatcher; no independent benign measurement"
                         if any(b.executable for b in bindings)
                         else "No faithful screened predicate"),
            extra={"policy": dict(POLICY), "upstream": raw, "upstream_yaml": raw_text,
                   "lineage_parse": lineage_decision, "surface_decision": surface_decision,
                   "execution": execution, "positive_origins": positive_origins,
                   "negative_origins": negative_origins,
                   "license_decision": "Repository notice only; rights to named third-party corpus content remain unresolved",
                   "engine_scope": "Declared raw-text pattern path; no Unicode normalization, model, trace engine, or implicit engine context policies"},
        ))
    delta.rules_emitted = len(rules)
    return LoadResult(rules, delta)
