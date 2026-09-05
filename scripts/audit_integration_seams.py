"""Count conjunction losses from pinned corpora without copying example text.

Run with PYTHONPATH=src python scripts/audit_integration_seams.py CORPORA_ROOT.
The caller supplies the verified checkouts named by sources.lock.
"""

import argparse
from collections import Counter
from dataclasses import asdict
import json
from pathlib import Path

import yaml

from agent_defs.loaders import atr, sigma


def documents(directory):
    for path in sorted(directory.rglob("*")):
        if path.suffix in (".yaml", ".yml"):
            for raw in yaml.load_all(path.read_text(encoding="utf-8"), Loader=yaml.CSafeLoader):
                if isinstance(raw, dict) and "id" in raw and "detection" in raw:
                    yield path, raw


def operators(tree):
    if tree[0] in ("and", "or", "not"):
        yield tree[0]
        for child in tree[1:]:
            yield from operators(child)


def audit(root, pins):
    report = {"status": "VERIFIED", "revisions": {name: p["commit"] for name, p in pins.items()}}
    delta = atr.Delta(source_rev=pins["atr"]["commit"])
    rows, kinds, backrefs = [], Counter(), []
    for path, raw in documents(root / "atr" / "rules"):
        delta.entries_read += 1
        rid = "atr:" + raw["id"]
        kind, predicate, reasons, decisions = atr._predicate(raw, rid, delta)
        delta.rules_emitted += 1
        kinds[kind.value] += 1
        detection = raw["detection"]
        conditions = detection.get("conditions", [])
        if detection.get("condition") == "all" and isinstance(conditions, list) and len(conditions) > 1:
            rows.append({"id": rid, "path": path.relative_to(root / "atr").as_posix(),
                         "title": raw.get("title"), "conditions": len(conditions),
                         "fields": sorted({c.get("field", "") for c in conditions if isinstance(c, dict)}),
                         "predicate_kind": kind.value, "reasons": reasons,
                         "composition": decisions.get("composition")})
        if any("reference" in r["reason"] for r in delta.pattern_rejections if r["rule_id"] == rid):
            backrefs.append(rid)
    report["atr"] = {"entries": delta.entries_read, "predicates": dict(kinds),
                     "multi_condition_all": len(rows), "conjunctions": rows,
                     "reference_rejected_ids": backrefs, "delta": asdict(delta)}
    for source, directory in (("netzilo", "ai_agent"), ("agentshield", "rules/rules/ai_agent")):
        rows, kinds, total, conjunctions = [], Counter(), 0, 0
        for path, raw in documents(root / source / directory):
            total += 1
            rule = sigma.normalize(raw, source=source, source_rev=pins[source]["commit"],
                                   source_path=path.relative_to(root / source).as_posix())
            kinds[rule.predicate_kind.value] += 1
            detection = raw["detection"]
            selections = {k: v for k, v in detection.items() if k not in ("condition", "timeframe")}
            try:
                tree = sigma._expand(sigma.parse_condition(detection.get("condition"), selections), selections, set())
            except (sigma.UnsupportedSigma, RecursionError):
                tree = ("unavailable",)
            ops = Counter(operators(tree))
            conjunctions += bool(ops["and"])
            if "boolean_tree_requires_structured_runtime" in rule.extra["refused_constructs"]:
                leaves = list(sigma._leaves(tree))
                rows.append({"id": rule.id, "path": rule.source_path, "title": rule.title,
                             "operators": dict(ops), "leaves": len(leaves),
                             "leaf_kinds": dict(Counter(n[2] for n in leaves)),
                             "fields": list(rule.extra["payload_fields"]),
                             "flat_regex_all": tree[0] == "and" and all(n[0] == "leaf" and n[2] == "regex" for n in tree[1:]),
                             "reasons": rule.extra["refused_constructs"]})
        report[source] = {"entries": total, "predicates": dict(kinds),
                          "with_conjunction": conjunctions, "boolean_runtime_refused": len(rows),
                          "refused_conjunctions": sum(bool(r["operators"].get("and")) for r in rows),
                          "boolean_only_refused": sum(r["reasons"] == ["boolean_tree_requires_structured_runtime"] for r in rows),
                          "flat_regex_all_only_refused": sum(r["flat_regex_all"] and r["reasons"] == ["boolean_tree_requires_structured_runtime"] for r in rows),
                          "refused_by_id": rows}
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpora", type=Path)
    args = parser.parse_args()
    pins = {p["name"]: p for p in json.loads(Path("sources.lock").read_text()) if p["name"] in ("atr", "netzilo", "agentshield")}
    print(json.dumps(audit(args.corpora, pins), indent=2, ensure_ascii=True))


if __name__ == "__main__":
    main()
