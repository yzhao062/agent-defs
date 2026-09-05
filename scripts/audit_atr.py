"""Reproduce ATR inventory, screen rejections, and positive reachability.

Run with PYTHONPATH=src python scripts/audit_atr.py /path/to/atr-checkout.
The JSON report is written to stdout; it never executes rejected patterns.
"""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import asdict
import json
from pathlib import Path
import re

from agent_defs.evaluate import UnsafePattern, compile_rule, scan, screen_pattern
from agent_defs.loaders.atr import BREADTH_PROBES, load


def audit(root: Path) -> dict:
    result = load(root)
    rules = result.rules
    reach = Counter()
    misses, blocked, parity_misses, broad, surface_rows = [], [], [], [], []
    parity_trials = 0
    for rule in rules:
        raw = rule.extra["upstream"]
        surface_rows.append({"id": rule.source_id, "surface": rule.surface.value,
                             **rule.extra["surface_decision"]})
        if rule.breadth.value == "BROAD":
            witnesses = []
            for index in rule.extra["execution"]["breadth"]["probe_indices"]:
                witness = BREADTH_PROBES[index]
                matching = []
                for i, condition in enumerate(raw["detection"]["conditions"]):
                    try:
                        screen_pattern(condition["value"])
                    except UnsafePattern:
                        continue
                    if re.search(condition["value"], witness, re.IGNORECASE):
                        matching.append(i)
                witnesses.append({"probe_index": index, "text": witness, "condition_indices": matching})
            broad.append({"id": rule.source_id, "title": rule.title, "runnable": rule.runnable,
                          "witnesses": witnesses})
        if not rule.runnable:
            reach["rules_not_runnable"] += 1
            reach["strings_not_evaluated"] += len(rule.examples_positive)
            blocked.append({"id": rule.source_id, "reason": rule.not_runnable_reason,
                            "positive_strings": len(rule.examples_positive)})
            continue
        runtime = compile_rule(rule)
        conditions = [re.compile(c["value"], re.IGNORECASE) for c in raw["detection"]["conditions"]]
        hit_count = 0
        for i, example in enumerate(rule.examples_positive):
            checked = scan(example, [rule], compiled={rule.id: runtime})
            assert not checked.truncated_input and checked.rules_evaluated == 1
            hit = bool(checked.findings)
            reach["strings_matched" if hit else "strings_missed"] += 1
            hit_count += hit
            if not hit:
                source_hits = [bool(c.search(example)) for c in conditions]
                source_hit = all(source_hits) if raw["detection"]["condition"] == "all" else any(source_hits)
                misses.append({"id": rule.source_id, "example_index": i,
                               "origin": rule.extra["positive_origins"][i],
                               "classification": "port_mismatch" if source_hit else "upstream_pattern_miss"})
        reach["rules_runnable"] += 1
        reach["rules_with_any_positive_match" if hit_count else "rules_without_positive_match"] += 1
        reach["rules_all_positive_strings_match" if hit_count == len(rule.examples_positive) else "rules_with_misses"] += 1
        for example in (*rule.examples_positive, *rule.examples_negative, *BREADTH_PROBES):
            upstream_hits = [bool(c.search(example)) for c in conditions]
            expected = all(upstream_hits) if raw["detection"]["condition"] == "all" else any(upstream_hits)
            parity_trials += 1
            if bool(runtime.search(example)) != expected:
                parity_misses.append(rule.source_id)
    for key in ("strings_missed", "rules_without_positive_match", "rules_with_misses"):
        reach.setdefault(key, 0)

    upstream = [r.extra["upstream"] for r in rules]
    authors = Counter(r["author"] for r in upstream)
    severity = Counter(r.severity_raw for r in rules)
    maturity = Counter(r.maturity_raw for r in rules)
    status = Counter(r["status"] for r in upstream)
    surfaces = Counter(r.surface.value for r in rules)
    for surface in ("CFG", "IN", "OUT", "PROMPT", "PIN", "NONE"):
        surfaces.setdefault(surface, 0)
    expected_surface = {"CFG": 159, "IN": 113, "OUT": 515, "PROMPT": 0, "PIN": 0, "NONE": 6}
    return {
        "source_rev": result.delta.source_rev,
        "delta": asdict(result.delta),
        "severity": dict(severity), "maturity": dict(maturity), "status": dict(status),
        "skill_maturity": dict(Counter(r["maturity"] for r in upstream if r["tags"].get("scan_target") == "skill")),
        "authors": dict(authors),
        "lineage_parse": dict(Counter(r.extra["lineage_parse"]["classification"] for r in rules)),
        "author_garak": sum(n for author, n in authors.items() if "garak" in author.lower()),
        "author_unqualified": sum(n for author, n in authors.items() if "(" not in author),
        "source_methods": dict(Counter(r["detection"].get("method", "pattern") for r in upstream)),
        "semantic_fallbacks": [{"id": r.source_id, "runnable": r.runnable}
                               for r in rules if "fallback" in r.extra["execution"]],
        "surfaces": dict(surfaces),
        "surface_difference_from_prompt": {s: surfaces[s] - expected_surface[s] for s in expected_surface},
        "surface_reasons": dict(Counter(r.extra["surface_decision"]["reason"] for r in rules)),
        "surface_rules": surface_rows,
        "runnable_surfaces": dict(Counter(r.surface.value for r in rules if r.runnable)),
        "breadth": dict(Counter(r.breadth.value for r in rules)), "broad_rules": broad,
        "upstream_pattern_occurrences": sum(len(r["detection"]["conditions"]) for r in upstream),
        "rejection_reasons": dict(Counter(r["reason"] for r in result.delta.pattern_rejections)),
        "rejected_rule_count": len({r["rule_id"] for r in result.delta.pattern_rejections}),
        "false_positive_notes": {
            "nested_strings": sum(len(r["detection"].get("false_positives", [])) for r in upstream),
            "nested_rules": sum(bool(r["detection"].get("false_positives")) for r in upstream),
            "top_level_strings": sum(len(r.get("false_positives", [])) for r in upstream),
            "emitted_strings": sum(len(r.false_positive_notes) for r in rules),
            "emitted_rules": sum(bool(r.false_positive_notes) for r in rules),
        },
        "source_positive_cases": sum(len(r["test_cases"]["true_positives"]) for r in upstream),
        "source_negative_cases": sum(len(r["test_cases"]["true_negatives"]) for r in upstream),
        "emitted_positive_strings": sum(len(r.examples_positive) for r in rules),
        "emitted_negative_strings": sum(len(r.examples_negative) for r in rules),
        "reachability": dict(reach), "misses": misses, "non_runnable_rules": blocked,
        "pattern_port_parity": {"comparisons": parity_trials, "mismatching_rule_ids": parity_misses},
        "limitations": [
            "Reachability compares raw published regex paths, not ATR's complete engine policies.",
            "Rejected and non-runnable rules are never evaluated; they are not positive misses.",
            "BROAD has a common-text witness; MEDIUM is unmeasured, not evidence of specificity.",
            "The single surface is an adapter decision; input field mappings remain in extra.",
        ],
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    args = parser.parse_args()
    print(json.dumps(audit(args.root), indent=2, ensure_ascii=True))
