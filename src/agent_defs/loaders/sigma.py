"""Conservative Sigma loading and evidence-based conversion deduplication.

``load()`` and ``dedup()`` return ``(rules, delta)``. YAML is imported only inside
``load()``. Source text is retained as data in ``extra['source_text_raw']``.
The scalar evaluator supports flat regex conjunctions but cannot enforce event
guards or general boolean trees; those records remain NONE, with all refusal
codes in their delta and extra.
"""

from __future__ import annotations

import copy
import fnmatch
import re
from collections import Counter
from dataclasses import replace
from pathlib import Path
from typing import Iterable, Mapping, NamedTuple
from urllib.parse import urlparse

from ..evaluate import UnsafePattern, scan, screen_pattern
from ..model import Lane, Lineage, PredicateKind, Rule, Surface

REPOSITORIES = {
    "netzilo": "https://github.com/netzilo/aidr-sigma",
    "agentshield": "https://github.com/agentshield-ai/agentshield",
}
NETZILO_ATR_IMPORT = "2428582eadfe0bdc297f11cb82933c7c7f9551d2"
SIGMA_SPEC = "https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html"
DECISION_VERSION = "agent_defs.sigma.v1/2026-09-05"

# These identify a single supplied payload, never a JSON serialization of an event.
TEXT_FIELDS = {"content": Surface.OUT, "response": Surface.OUT, "command": Surface.IN}
EVENT_SURFACES = {
    "tool_call": Surface.IN, "llm_tool_call": Surface.IN,
    "execute_process": Surface.IN, "http_request": Surface.IN,
    "file_write": Surface.IN, "file_read": Surface.IN,
    "user_input": Surface.PROMPT, "tool_response": Surface.OUT,
    "llm_tool_result": Surface.OUT, "content_retrieval": Surface.OUT,
    "document_retrieval": Surface.OUT, "skill_acquired": Surface.CFG,
    "tool_description": Surface.CFG, "tool_description_update": Surface.PIN,
}


class Result(NamedTuple):
    rules: tuple[Rule, ...]
    delta: dict


class UnsupportedSigma(ValueError):
    pass


def _join(op: str, nodes: list) -> tuple:
    flattened = []
    for node in nodes:
        flattened.extend(node[1:] if node[0] == op else [node])
    if not flattened:
        raise UnsupportedSigma("empty_expression")
    return flattened[0] if len(flattened) == 1 else (op, *flattened)


def parse_condition(condition: object, selections: Mapping) -> tuple:
    """Parse Sigma boolean syntax without eval or regex concatenation.

    The returned tree references selections by name. Quantifiers expand only
    matching identifiers, excluding underscore-prefixed identifiers for 'them'.
    Unsupported aggregation/count syntax fails closed.
    """
    if isinstance(condition, list):
        return _join("or", [parse_condition(c, selections) for c in condition])
    if not isinstance(condition, str) or not condition.strip():
        raise UnsupportedSigma("missing_condition")
    tokens = re.findall(r"\(|\)|[A-Za-z0-9_*]+|\S", condition)
    index = 0

    def peek():
        return tokens[index] if index < len(tokens) else None

    def take():
        nonlocal index
        value = peek()
        index += 1
        return value

    def atom():
        token = take()
        if token == "(":
            node = expression("or")
            if take() != ")":
                raise UnsupportedSigma("unbalanced_condition")
            return node
        if token == "not":
            return ("not", atom())
        if token in ("1", "all") and peek() == "of":
            take()
            pattern = take()
            if pattern is None:
                raise UnsupportedSigma("missing_quantifier_target")
            names = [name for name in selections if
                     (not name.startswith("_") if pattern == "them"
                      else fnmatch.fnmatchcase(name, pattern))]
            if not names:
                raise UnsupportedSigma("unmatched_quantifier:" + pattern)
            return _join("or" if token == "1" else "and", [("ref", n) for n in names])
        if token not in selections:
            raise UnsupportedSigma("unknown_condition_token:" + str(token))
        return ("ref", token)

    def expression(op):
        child = (lambda: expression("and")) if op == "or" else atom
        nodes = [child()]
        while peek() == op:
            take()
            nodes.append(child())
        return _join(op, nodes)

    tree = expression("or")
    if index != len(tokens):
        raise UnsupportedSigma("unsupported_condition_tail:" + str(peek()))
    return tree


def _literal(value: str) -> str:
    """Decode Sigma escapes, refusing wildcards instead of treating them literally."""
    result = []
    index = 0
    while index < len(value):
        char = value[index]
        if char == "\\" and index + 1 < len(value) and value[index + 1] in "\\*?":
            index += 1
            result.append(value[index])
        elif char in "*?":
            raise UnsupportedSigma("wildcard_value")
        else:
            result.append(char)
        index += 1
    return "".join(result)


def _selection(value: object, issues: set[str]) -> tuple:
    if isinstance(value, list):
        if value and all(isinstance(v, str) for v in value):
            if any(not v for v in value):
                raise UnsupportedSigma("empty_keyword_value")
            return _join("or", [("leaf", "content", "contains", _literal(v), False) for v in value])
        return _join("or", [_selection(v, issues) for v in value])
    if not isinstance(value, dict) or not value:
        raise UnsupportedSigma("invalid_selection")
    nodes = []
    for key, raw in value.items():
        if not isinstance(key, str):
            raise UnsupportedSigma("non_string_field")
        field, *mods = key.split("|")
        if field not in TEXT_FIELDS:
            issues.add("unsupported_field:" + field)
        all_values = "all" in mods
        if mods == ["re"] or mods == ["re", "i"]:
            op, sensitive = "regex", "i" not in mods
        elif mods in (["contains"], ["contains", "all"],
                      ["contains", "cased"], ["contains", "all", "cased"]):
            op, sensitive = "contains", "cased" in mods
        else:
            issues.add("unsupported_modifiers:" + ("|".join(mods) or "exact"))
            continue
        values = raw if isinstance(raw, list) else [raw]
        if not values or not all(isinstance(v, str) and v for v in values):
            issues.add("invalid_or_empty_value:" + key)
            continue
        leaves = []
        for item in values:
            try:
                literal = item if op == "regex" else _literal(item)
                leaves.append(("leaf", field, op, literal, sensitive))
            except UnsupportedSigma as exc:
                issues.add(str(exc))
        if leaves:
            nodes.append(_join("and" if all_values else "or", leaves))
    return _join("and", nodes) if nodes else ("unavailable",)


def _expand(tree: tuple, selections: Mapping, issues: set[str]) -> tuple:
    if tree[0] == "ref":
        return _selection(selections[tree[1]], issues)
    if tree[0] == "not":
        return ("not", _expand(tree[1], selections, issues))
    return _join(tree[0], [_expand(n, selections, issues) for n in tree[1:]])


def _leaves(tree: tuple):
    if tree[0] == "leaf":
        yield tree
    elif tree[0] in ("and", "or", "not"):
        for node in tree[1:]:
            yield from _leaves(node)


def _map_predicate(detection: object):
    issues: set[str] = set()
    if not isinstance(detection, dict):
        return PredicateKind.NONE, None, False, ["missing_detection"], ()
    selections = {k: v for k, v in detection.items() if k not in ("condition", "timeframe")}
    if "timeframe" in detection:
        issues.add("unsupported_timeframe")
    try:
        tree = _expand(parse_condition(detection.get("condition"), selections), selections, issues)
    except (UnsupportedSigma, RecursionError) as exc:
        issues.add(str(exc) or "condition_nesting_limit")
        tree = ("unavailable",)
    leaves = list(_leaves(tree))
    fields = sorted({leaf[1] for leaf in leaves})
    cases = {leaf[4] for leaf in leaves}
    sensitive = cases == {True}
    if len(fields) > 1:
        issues.add("multiple_payload_fields")
    if len(cases) > 1:
        issues.add("mixed_case_modes")
    kind, predicate = PredicateKind.NONE, None
    if tree[0] == "leaf":
        kind = PredicateKind.REGEX if tree[2] == "regex" else PredicateKind.SUBSTRING_ANY
        predicate = tree[3] if kind is PredicateKind.REGEX else (tree[3],)
    elif tree[0] in ("and", "or") and all(n[0] == "leaf" and n[2] == "contains" for n in tree[1:]):
        kind = PredicateKind.SUBSTRING_ALL if tree[0] == "and" else PredicateKind.SUBSTRING_ANY
        predicate = tuple(n[3] for n in tree[1:])
    elif tree[0] == "and" and all(n[0] == "leaf" and n[2] == "regex" for n in tree[1:]):
        kind = PredicateKind.STRUCTURED
        predicate = {"regex_all": [n[3] for n in tree[1:]]}
    else:
        issues.add("boolean_tree_requires_structured_runtime")
    if issues:
        kind, predicate = PredicateKind.NONE, None
    return kind, predicate, sensitive, sorted(issues), tuple(fields)


def _field_entries(value):
    if isinstance(value, dict):
        yield from value.items()
    elif isinstance(value, list):
        for item in value:
            yield from _field_entries(item)


def _strings(value) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (list, tuple)):
        return tuple(v for v in value if isinstance(v, str))
    return ()


def normalize(data: Mapping, *, source: str, source_rev: str,
              source_path: str, source_text: str = "", license_spdx: str = "") -> Rule:
    """Normalize one parsed document; no I/O or third-party imports."""
    if source not in REPOSITORIES:
        raise ValueError("source must be netzilo or agentshield")
    if not re.fullmatch(r"[0-9a-fA-F]{40}", source_rev):
        raise ValueError("source_rev must be a full 40-character commit SHA")
    if not isinstance(data.get("id"), str) or not data["id"]:
        raise ValueError("Sigma document requires a string id")
    kind, predicate, sensitive, issues, fields = _map_predicate(data.get("detection"))
    issues = set(issues)
    counts = Counter()
    rejections = []
    events = set()
    all_fields = set()
    detection = data.get("detection", {})
    for name, selection in detection.items() if isinstance(detection, dict) else ():
        if name in ("condition", "timeframe"):
            continue
        counts["selection:" + type(selection).__name__] += 1
        for key, value in _field_entries(selection):
            field, *mods = str(key).split("|")
            all_fields.add(field)
            counts["field:" + field] += 1
            counts["modifiers:" + ("|".join(mods) or "exact")] += 1
            counts["value:" + type(value).__name__] += 1
            if field == "event_type":
                events.update(_strings(value))
            if "re" in mods:
                for index, pattern in enumerate(value if isinstance(value, list) else [value]):
                    counts["regex_patterns"] += 1
                    try:
                        if not isinstance(pattern, str):
                            raise UnsafePattern("non-string pattern")
                        screen_pattern(pattern)
                    except UnsafePattern as exc:
                        rejections.append({"selection": name, "field": key,
                                           "index": index, "reason": str(exc)})
    condition = detection.get("condition") if isinstance(detection, dict) else None
    conditions = condition if isinstance(condition, list) else [condition]
    for value in conditions:
        tokens = re.findall(r"\b(?:and|or|not|all|of|them)\b|[()]", str(value))
        counts.update("condition:" + t for t in tokens)
    counts["condition:single_identifier"] += int(isinstance(condition, str) and bool(re.fullmatch(r"\w+", condition.strip())))
    if rejections:
        issues.add("screen_pattern_rejection")
    for field in all_fields - TEXT_FIELDS.keys():
        issues.add("unsupported_field:" + field)
    for key in ("script", "prompt", "correlation", "action"):
        if key in data and (key != "action" or data[key] not in ("report", "block")):
            issues.add("unsupported_execution_extension:" + key)
    logsource = data.get("logsource", {})
    if not isinstance(logsource, dict) or logsource.get("product") != "ai_agent":
        issues.add("unsupported_logsource")
    if isinstance(logsource, dict):
        if logsource.get("category") not in ("agent_events", "tool_output", "tool_input"):
            issues.add("unsupported_logsource_category:" + str(logsource.get("category")))
        if set(logsource) - {"product", "category", "definition"}:
            issues.add("unsupported_logsource_constraints")
    candidates = {EVENT_SURFACES.get(e, Surface.NONE) for e in events} if events else {
        TEXT_FIELDS.get(f, Surface.NONE) for f in all_fields}
    surface = next(iter(candidates)) if len(candidates) == 1 else Surface.NONE
    if surface is Surface.NONE:
        issues.add("no_single_surface")
    if issues:
        kind, predicate = PredicateKind.NONE, None
    reason = "; ".join(sorted(issues))
    extra = {
        "source_text_raw": source_text, "source_data_raw": copy.deepcopy(dict(data)),
        "sigma_detection_raw": copy.deepcopy(detection), "payload_fields": fields,
        "surface_candidates": sorted(s.value for s in candidates),
        "surface_method": "event_type stages if present; otherwise scalar field mapping",
        "constructs": dict(counts), "refused_constructs": sorted(issues),
        "pattern_rejections": rejections,
        "case_decision": {"case_sensitive": sensitive, "method": DECISION_VERSION,
                          "reason": "Sigma regex defaults to sensitive; contains defaults to insensitive; explicit re|i/cased and inline flags preserved.",
                          "evidence": SIGMA_SPEC},
    }
    test_cases = data.get("test_cases", {})
    if not isinstance(test_cases, dict):
        test_cases = {}
    def examples(key):
        return tuple(x["input"] for x in test_cases.get(key, [])
                     if isinstance(x, dict) and isinstance(x.get("input"), str))
    url = f"{REPOSITORIES[source]}/blob/{source_rev}/{source_path}"
    author = data.get("author")
    lineage = (Lineage("author_field", author, url),) if isinstance(author, str) else ()
    return Rule(
        id=f"{source}:{data['id']}", source=source, source_id=data["id"],
        source_rev=source_rev, source_path=source_path, upstream_url=url,
        lineage=lineage, license_spdx=data.get("license", license_spdx),
        title=data.get("title", ""), description=data.get("description", ""),
        severity_raw=data.get("level", ""), severity_field="level" if "level" in data else "",
        maturity_raw=data.get("status", ""), tags=_strings(data.get("tags")),
        references=_strings(data.get("references")), surface=surface,
        predicate_kind=kind, predicate=predicate, not_runnable_reason=reason,
        case_sensitive=sensitive, examples_positive=examples("true_positives"),
        examples_negative=examples("true_negatives"),
        false_positive_notes=_strings(data.get("falsepositives")),
        lane=Lane.RECORD if kind is not PredicateKind.NONE else Lane.DO_NOT_SHIP,
        lane_reason="No benign admission measurement." if kind is not PredicateKind.NONE else reason,
        extra=extra,
    )


def load(root: str | Path, *, source: str, source_rev: str,
         rules_dir: str | None = None, license_spdx: str = "") -> Result:
    """Read an explicitly pinned checkout. Never fetch upstream or run extensions."""
    import yaml

    class UniqueKeyLoader(yaml.SafeLoader):
        pass

    def mapping(loader, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            if key in result:
                raise ValueError("duplicate YAML key: " + str(key))
            result[key] = loader.construct_object(value_node, deep=deep)
        return result

    UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)
    if source not in REPOSITORIES:
        raise ValueError("source must be netzilo or agentshield")
    if not re.fullmatch(r"[0-9a-fA-F]{40}", source_rev):
        raise ValueError("source_rev must be a full 40-character commit SHA")
    root = Path(root)
    if root.is_file():
        paths, base = [root], root.parent
    else:
        base = root
        if rules_dir is None:
            rules_dir = "ai_agent" if source == "netzilo" else "rules/rules/ai_agent"
        directory = root / rules_dir
        if not directory.is_dir():
            raise FileNotFoundError(directory)
        paths = sorted(p for p in directory.rglob("*") if p.suffix in (".yml", ".yaml"))
    records, errors = [], []
    entries = 0
    seen = set()
    for path in paths:
        source_path = path.relative_to(base).as_posix()
        raw = path.read_bytes().decode("utf-8")
        try:
            documents = list(yaml.load_all(raw, Loader=UniqueKeyLoader))
        except (yaml.YAMLError, ValueError, TypeError) as exc:
            errors.append({"path": source_path, "reason": str(exc)})
            continue
        for document in documents:
            entries += 1
            try:
                if not isinstance(document, dict):
                    raise ValueError("document is not a mapping")
                if "action" in document and document["action"] in ("global", "reset", "repeat"):
                    raise ValueError("Sigma collection directives require preprocessing")
                rule = normalize(document, source=source, source_rev=source_rev,
                                 source_path=source_path, source_text=raw, license_spdx=license_spdx)
                if rule.id in seen:
                    raise ValueError("duplicate source id: " + rule.id)
                seen.add(rule.id)
                records.append(rule)
            except (ValueError, TypeError, AttributeError, RecursionError) as exc:
                errors.append({"path": source_path, "reason": str(exc)})
    scenario_delta = {"files_read": 0, "linked_scenarios": 0, "linked_rules": 0,
                      "unmatched": [], "ambiguous": [], "errors": []}
    example_dir = base / "bench" / "testcases"
    if source == "agentshield" and not root.is_file() and example_dir.is_dir():
        aliases = {}
        for rule in records:
            for alias in (rule.source_id, *_strings(rule.extra["source_data_raw"].get("aliases"))):
                aliases.setdefault(alias, set()).add(rule.id)
        scenarios = {}
        for path in sorted(example_dir.rglob("*.yaml")):
            scenario_delta["files_read"] += 1
            try:
                data = yaml.load(path.read_bytes().decode("utf-8"), Loader=UniqueKeyLoader)
                if not isinstance(data, dict) or not isinstance(data.get("expected"), dict):
                    raise ValueError("scenario requires an expected mapping")
                for alias in _strings(data["expected"].get("must_trigger_rules")):
                    found = aliases.get(alias, set())
                    detail = {"path": path.relative_to(base).as_posix(), "expected_rule_id": alias}
                    if len(found) != 1:
                        scenario_delta["ambiguous" if found else "unmatched"].append(detail)
                        continue
                    rule_id = next(iter(found))
                    scenarios.setdefault(rule_id, []).append({**detail, "scenario": data})
                    scenario_delta["linked_scenarios"] += 1
            except (yaml.YAMLError, ValueError, TypeError) as exc:
                scenario_delta["errors"].append({"path": path.relative_to(base).as_posix(), "reason": str(exc)})
        scenario_delta["linked_rules"] = len(scenarios)
        records = [replace(r, extra={**r.extra, "positive_scenarios_raw": scenarios[r.id]})
                   if r.id in scenarios else r for r in records]
    constructs, refused, raw_only = Counter(), Counter(), Counter()
    for rule in records:
        constructs.update(rule.extra["constructs"])
        refused.update(rule.extra["refused_constructs"])
        raw_only.update(set(rule.extra["source_data_raw"]) - {
            "id", "title", "description", "author", "level", "status", "tags",
            "references", "falsepositives", "detection", "logsource", "license", "test_cases"})
    return Result(tuple(records), {
        "files_read": len(paths), "entries_read": entries, "emitted": len(records),
        "errors": errors, "constructs": dict(constructs), "refused_constructs": dict(refused),
        "refused_by_id": {r.id: r.extra["refused_constructs"] for r in records if not r.runnable},
        "pattern_rejections": {r.id: r.extra["pattern_rejections"] for r in records if r.extra["pattern_rejections"]},
        "maturity": dict(Counter(r.maturity_raw for r in records)),
        "predicates": dict(Counter(r.predicate_kind.value for r in records)),
        "surfaces": dict(Counter(r.surface.value for r in records)),
        "raw_only_fields": dict(raw_only), "example_scenarios": scenario_delta,
    })


def _atr_references(rule: Rule) -> set[str]:
    ids = set()
    for ref in rule.references:
        url = urlparse(ref)
        if url.hostname in ("agentthreatrule.org", "www.agentthreatrule.org"):
            match = re.fullmatch(r"/(?:en/)?rules/(ATR-\d{4}-\d+)/?", url.path)
            if match:
                ids.add(match[1])
    return ids


def dedup(records: Iterable[Rule]) -> Result:
    """Mark conversions, retaining every record and input order.

    ATR: exact rule ID in the converter's agentthreatrule.org reference URL,
    plus the explicit 'ATR Community (adapted)' author declaration.
    AgentShield: exact preserved source ID AND an AgentShield author declaration.
    Titles and predicate similarity are never used. Missing or ambiguous origins
    remain visible. A conversion is lineage, not a claim of predicate equivalence.
    """
    records = tuple(records)
    origins = {}
    for rule in records:
        origins.setdefault((rule.source, rule.source_id), []).append(rule)
    output, matches, unmatched, ambiguous = [], [], [], []
    for rule in records:
        if rule.source != "netzilo":
            output.append(rule)
            continue
        author = rule.extra.get("source_data_raw", {}).get("author", "")
        atr_ids = _atr_references(rule)
        candidates = []
        method = ""
        if atr_ids and author == "ATR Community (adapted)":
            method = "exact_atr_reference_id"
            candidates = [("atr", i) for i in sorted(atr_ids)]
        elif isinstance(author, str) and author.startswith("AgentShield"):
            method = "preserved_agentshield_id_and_author"
            candidates = [("agentshield", rule.source_id)]
        extra = dict(rule.extra)
        for key in ("duplicate_of", "conversion_match"):
            extra.pop(key, None)
        extra["is_conversion_duplicate"] = False
        if not candidates:
            output.append(replace(rule, extra=extra))
            continue
        found = [origin for key in candidates for origin in origins.get(key, [])]
        if len(candidates) != 1 or len(found) > 1:
            detail = {"id": rule.id, "candidate_ids": [f"{s}:{i}" for s, i in candidates], "method": method}
            ambiguous.append(detail)
            extra["dedup_status"] = "ambiguous"
            output.append(replace(rule, extra=extra))
            continue
        origin_source, origin_id = candidates[0]
        evidence = method + "; " + rule.upstream_url
        conversion = Lineage("conversion", origin_id, evidence)
        lineage = tuple(l for l in rule.lineage if l.kind != "conversion") + (conversion,)
        if not found:
            unmatched.append({"id": rule.id, "origin_id": f"{origin_source}:{origin_id}", "method": method})
            extra["dedup_status"] = "origin_missing"
            output.append(replace(rule, extra=extra, lineage=lineage))
            continue
        origin = found[0]
        detail = {"id": rule.id, "origin_id": origin.id, "method": method,
                  "origin_rev": origin.source_rev, "evidence": evidence}
        matches.append(detail)
        extra.update(is_conversion_duplicate=True, duplicate_of=origin.id,
                     conversion_match=detail, dedup_status="matched")
        sensitive = rule.case_sensitive
        if origin.source == "atr":
            sensitive = origin.case_sensitive
            extra["case_decision"] = {
                "case_sensitive": sensitive, "method": DECISION_VERSION,
                "reason": "Restore the linked ATR origin's case mode lost during Sigma conversion; inline flags remain verbatim.",
                "evidence": origin.upstream_url, "origin_id": origin.id,
                "sigma_default_case_sensitive": rule.extra.get("case_decision", {}).get("sigma_default_case_sensitive", rule.case_sensitive),
            }
        positive = rule.examples_positive or origin.examples_positive
        negative = rule.examples_negative or origin.examples_negative
        if (not rule.examples_positive and positive) or (not rule.examples_negative and negative):
            extra["linked_examples_origin"] = {"id": origin.id, "rev": origin.source_rev,
                                               "url": origin.upstream_url}
        if origin.extra.get("positive_scenarios_raw") and not extra.get("positive_scenarios_raw"):
            extra["positive_scenarios_raw"] = origin.extra["positive_scenarios_raw"]
            extra["linked_scenarios_origin"] = {"id": origin.id, "rev": origin.source_rev,
                                                "url": origin.upstream_url}
        output.append(replace(rule, extra=extra, lineage=lineage, case_sensitive=sensitive,
                              examples_positive=positive, examples_negative=negative))
    return Result(tuple(output), {"input": len(records), "emitted": len(output),
                                 "matched": len(matches), "matches": matches,
                                 "methods": dict(Counter(m["method"] for m in matches)),
                                 "unmatched": unmatched, "ambiguous": ambiguous})


def deduplicated_view(records: Iterable[Rule]) -> tuple[Rule, ...]:
    """Suppress marked copies only when their origin is present in this view."""
    records = tuple(records)
    present = {r.id for r in records}
    return tuple(r for r in records if not (r.extra.get("is_conversion_duplicate")
                 and r.extra.get("duplicate_of") in present))


def reachability(records: Iterable[Rule]) -> dict:
    """Run supported, screened predicates against unchanged positive examples."""
    details, counts = {}, Counter()
    for rule in records:
        counts["rules"] += 1
        if rule.extra.get("positive_scenarios_raw"):
            counts["with_structured_examples"] += 1
            counts["structured_scenarios_not_evaluated"] += len(rule.extra["positive_scenarios_raw"])
            details[rule.id] = {"status": "structured_examples_require_event_runtime",
                                "scenarios": len(rule.extra["positive_scenarios_raw"])}
        if not rule.examples_positive:
            counts["without_examples"] += 1
            continue
        counts["with_examples"] += 1
        counts["examples"] += len(rule.examples_positive)
        if not rule.runnable:
            counts["not_runnable"] += 1
            details[rule.id] = {"status": "not_runnable", "examples": len(rule.examples_positive)}
            continue
        hits = sum(bool(scan(e, [rule]).require_complete().findings) for e in rule.examples_positive)
        counts["tested_rules"] += 1
        counts["tested_examples"] += len(rule.examples_positive)
        counts["example_hits"] += hits
        counts["reachable" if hits else "unreachable"] += 1
        details[rule.id] = {"status": "reachable" if hits else "unreachable",
                            "hits": hits, "examples": len(rule.examples_positive)}
    return {"counts": dict(counts), "by_id": details}
