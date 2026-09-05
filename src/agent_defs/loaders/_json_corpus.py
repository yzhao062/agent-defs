"""Loss accounting and build-time checks shared by the JSON catalog adapters."""

from __future__ import annotations

import hashlib
import json
import re
import warnings
from collections import Counter
from dataclasses import replace
from pathlib import Path

from agent_defs import evaluate
from agent_defs.model import Rule

REVIEW = {"by": "agent_defs.json_loaders.v1", "date": "2026-09-05"}


def validate_rev(source_rev: str) -> None:
    if not re.fullmatch(r"[0-9a-f]{40}", source_rev):
        raise ValueError("source_rev must be a full 40-character lowercase commit SHA")


def read_object(path: Path) -> dict:
    def unique_keys(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"{path}: duplicate JSON key {key!r}")
            result[key] = value
        return result

    data = json.loads(path.read_text(encoding="utf-8-sig"), object_pairs_hook=unique_keys)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return data


def text_field(row: dict, key: str) -> str:
    value = row[key]
    if not isinstance(value, str):
        raise ValueError(f"{key}: expected a string, got {type(value).__name__}")
    return value


def strings(value: object, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(v, str) for v in value):
        raise ValueError(f"{field}: expected an array of strings")
    return tuple(value)


def catalog(path: Path, id_field: str) -> tuple[dict, list[dict]]:
    data = read_object(path)
    rows = data.get("rules")
    if not isinstance(rows, list):
        raise ValueError(f"{path}: rules must be an array")
    check_ids(rows, id_field)
    return {k: v for k, v in data.items() if k != "rules"}, rows


def check_ids(rows: list[dict], id_field: str) -> None:
    seen = set()
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("every record must be a JSON object")
        source_id = text_field(row, id_field)
        if not source_id or source_id in seen:
            raise ValueError(f"empty or duplicate source ID: {source_id!r}")
        seen.add(source_id)


def screen_patterns(row: dict) -> list[dict]:
    """Screen declared pattern strings even when their enclosing condition is unsupported.

    An illustrative example is screened as a diagnostic only. Compilability
    never turns it into a predicate or supplies missing matching semantics.
    """
    reports = []

    def walk(value, pointer="", pattern_field=False):
        if isinstance(value, dict):
            for key, child in value.items():
                escaped = key.replace("~", "~0").replace("/", "~1")
                walk(child, f"{pointer}/{escaped}", pattern_field or key in {
                    "pattern", "patterns", "regex", "regexes", "example_patterns",
                })
        elif isinstance(value, list):
            for index, child in enumerate(value):
                walk(child, f"{pointer}/{index}", pattern_field)
        elif isinstance(value, str) and pattern_field:
            report = {"field": pointer, "status": "accepted", "reason": ""}
            try:
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter("always")
                    evaluate.screen_pattern(value)
                if caught:
                    report["warnings"] = [str(w.message) for w in caught]
            except evaluate.UnsafePattern as exc:
                report.update(status="rejected", reason=str(exc))
            reports.append(report)

    walk(row)
    return reports


def finish_rule(rule: Rule, row: dict, promoted: set[str], delta: dict) -> Rule:
    """Keep all source fields and distinguish a skipped positive from a miss."""
    delta["fields_preserved_in_extra"].update(set(row) - promoted)
    pattern_reports = screen_patterns(row)
    delta["pattern_screen"].update(r["status"] for r in pattern_reports)
    positives = rule.examples_positive
    reach = {"examples": len(positives), "checked": 0, "hits": 0, "misses": 0,
             "status": "no_positive_examples", "reason": "No positive examples in this JSON record."}
    if positives and not rule.runnable:
        reach.update(status="not_runnable", reason=rule.not_runnable_reason)
    elif positives:
        hits = sum(bool(evaluate.scan(example, [rule],
                        max_bytes=max(1, len(example.encode("utf-8"))),
                        budget_s=float("inf")).findings) for example in positives)
        reach.update(checked=len(positives), hits=hits, misses=len(positives) - hits,
                     status="reachable" if hits else "unreachable", reason="")
    delta["reachability"].update({reach["status"]: 1, "examples": len(positives),
                                 "checked": reach["checked"], "hits": reach["hits"],
                                 "misses": reach["misses"]})
    extra = dict(rule.extra)
    extra.update(upstream=row, pattern_screen=pattern_reports, reachability=reach,
                 classification={**REVIEW, "status": "INFERRED", **extra.get("classification", {})})
    return replace(rule, extra=extra)


def new_delta(source: str, source_rev: str) -> dict:
    return {"source": source, "source_rev": source_rev, "review": REVIEW.copy(),
            "entries_read": 0, "emitted": 0, "uncarried_fields": {},
            "fields_preserved_in_extra": Counter(), "unsupported_constructs": Counter(),
            "pattern_screen": Counter({"accepted": 0, "rejected": 0}),
            "reachability": Counter(), "documents": {}}


def document(delta: dict, path: Path, source_path: str, metadata: dict) -> None:
    delta["documents"][source_path] = {
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "metadata": metadata,
    }


def finish_delta(delta: dict, rules: list[Rule]) -> dict:
    delta.update(entries_read=len(rules), emitted=len(rules))
    delta["surfaces"] = dict(sorted(Counter(r.surface.value for r in rules).items()))
    delta["breadths"] = dict(sorted(Counter(r.breadth.value for r in rules).items()))
    delta["predicate_kinds"] = dict(sorted(Counter(r.predicate_kind.value for r in rules).items()))
    for key, value in list(delta.items()):
        if isinstance(value, Counter):
            delta[key] = dict(sorted(value.items()))
    return delta
