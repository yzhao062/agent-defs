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
from ..model import Breadth, Lane, Lineage, PredicateKind, Rule, Surface

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
    dropped_fields: dict[str, int] = field(default_factory=dict)
    extra_fields: dict[str, int] = field(default_factory=dict)
    unsupported_constructs: dict[str, int] = field(default_factory=dict)
    pattern_rejections: list[dict[str, Any]] = field(default_factory=list)
    entry_errors: list[dict[str, str]] = field(default_factory=list)


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


def _source_files(root: Path) -> tuple[str, list[tuple[Path, str]], str]:
    manifest_path = root / "atr-source.json"
    if manifest_path.is_file():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        revision = manifest["source_rev"]
        files = []
        for local, info in sorted(manifest["files"].items()):
            path = (root / local).resolve()
            if not path.is_relative_to(root):
                raise ValueError(f"ATR fixture path escapes root: {local}")
            if hashlib.sha256(path.read_bytes()).hexdigest() != info["sha256"]:
                raise ValueError(f"ATR fixture checksum mismatch: {local}")
            files.append((path, info["source_path"]))
    else:
        if not (root / ".git").exists():
            raise ValueError("ATR root needs Git metadata or atr-source.json; cannot invent source_rev")
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
    license_text = (root / "LICENSE").read_text(encoding="utf-8")
    license_spdx = "MIT" if license_text.startswith("MIT License") else ""
    return revision, files, license_spdx


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
        pattern = condition["value"]
        patterns.append(pattern)
        try:
            evaluate.screen_pattern(pattern)
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

    predicate = patterns[0]
    if len(patterns) > 1:
        # Joining independently numbered backreferences can silently redirect a
        # reference into a previous branch. Do not rewrite their meaning.
        if any(re.search(r"(?<!\\)(?:\\\\)*\\[1-9]|\(\?P=|\(\?\(", p) for p in patterns):
            unsupported("detection.conditions.regex.backreference_composition", "backreferences cannot be safely composed across conditions")
            return PredicateKind.NONE, None, reasons, decisions
        scoped = [_scoped(p) for p in patterns]
        predicate = ("|".join(scoped) if logic == "any" else
                     r"\A" + "".join(r"(?=[\s\S]*" + p + ")" for p in scoped))
        decisions["composition"] = "scoped regex alternation" if logic == "any" else "anchored conjunction of whole-payload searches"
        try:
            evaluate.screen_pattern(predicate)
        except evaluate.UnsafePattern as exc:
            delta.pattern_rejections.append({"rule_id": rid, "condition_index": None,
                                             "stage": "composed", "reason": str(exc)})
            unsupported("detection.conditions.regex.composition_screen_rejected", f"composed predicate: {exc}")
            return PredicateKind.NONE, None, reasons, decisions
    return PredicateKind.REGEX, predicate, [], decisions


def load(root: Path) -> LoadResult:
    """Read deterministic Rule records and an enumerated normalization delta.

    A non-runnable entry still emits its identity, metadata, examples, full
    parsed upstream record and exact YAML text. Parse/identity errors appear in
    delta.entry_errors; nothing is silently skipped. All emitted patterns pass
    evaluate.screen_pattern, and a rejected branch disables the entire rule.
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
    revision, files, license_spdx = _source_files(root)
    delta = Delta(source_rev=revision)
    rules: list[Rule] = []
    seen: set[str] = set()
    for path, source_path in files:
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
        surface, surface_decision = _surface(raw)
        kind, predicate, reasons, execution = _predicate(raw, rid, delta)
        positive, positive_origins = _examples(raw, "true_positives")
        negative, negative_origins = _examples(raw, "true_negatives")
        fp = _strings(raw["detection"].get("false_positives")) + _strings(raw.get("false_positives"))
        for key in raw:
            delta.extra_fields[key] = delta.extra_fields.get(key, 0) + 1
        rules.append(Rule(
            id=rid, source="atr", source_id=raw["id"], source_rev=revision,
            source_path=source_path, upstream_url=url, lineage=lineage,
            license_spdx=license_spdx, redistribution="unresolved",
            title=raw.get("title", ""), description=raw.get("description", ""),
            severity_raw=raw.get("severity", ""), severity_field="severity" if "severity" in raw else "",
            maturity_raw=raw.get("maturity", ""),
            tags=tuple(s for value in raw.get("tags", {}).values() for s in _strings(value)),
            references=tuple(s for value in raw.get("references", {}).values() for s in _strings(value)),
            surface=surface, breadth=Breadth.BROAD if execution["breadth"]["probe_indices"] else Breadth.MEDIUM,
            predicate_kind=kind, predicate=predicate, not_runnable_reason="; ".join(reasons),
            case_sensitive=False, examples_positive=positive, examples_negative=negative,
            false_positive_notes=fp, lane=Lane.RECORD if kind is not PredicateKind.NONE else Lane.DO_NOT_SHIP,
            lane_reason="No independent benign measurement" if kind is not PredicateKind.NONE else "No faithful screened predicate",
            extra={"policy": dict(POLICY), "upstream": raw, "upstream_yaml": raw_text,
                   "lineage_parse": lineage_decision, "surface_decision": surface_decision,
                   "execution": execution, "positive_origins": positive_origins,
                   "negative_origins": negative_origins,
                   "license_decision": "Repository notice only; rights to named third-party corpus content remain unresolved",
                   "engine_scope": "Declared raw-text pattern path; no Unicode normalization, model, trace engine, or implicit engine context policies"},
        ))
    delta.rules_emitted = len(rules)
    return LoadResult(rules, delta)
