"""Combine disjoint benchmark reports without rescanning or changing predicates."""
import argparse
from collections import Counter
import copy
import csv
import json
from pathlib import Path

from agent_defs import bench


def combine(reports, rules):
    combined = copy.deepcopy(reports[0])
    for other in reports[1:]:
        if set(combined["rules"]) != set(other["rules"]):
            raise ValueError("different bundles")
        if {c["identity"] for c in combined["corpora"]} & {c["identity"] for c in other["corpora"]}:
            raise ValueError("corpora overlap")
        for rid, row in combined["rules"].items():
            rhs = other["rules"][rid]
            for key in ("rule_sha256", "excluded_reason", "reachability", "surface"):
                if row[key] != rhs[key]:
                    raise ValueError(f"incompatible evidence: {rid}:{key}")
            row["measurements"].extend(rhs["measurements"])
            for key in ("trials", "hits"):
                row["diagnostic"][key] += rhs["diagnostic"][key]
            if not row["excluded_reason"]:
                row["diagnostic"]["u95"] = bench.binomial_u95(row["diagnostic"]["trials"], row["diagnostic"]["hits"])
        combined["corpora"].extend(other["corpora"])
        combined["materials"].extend(other["materials"])
        for key in ("measurements", "diagnostic_measurements", "failures"):
            combined["bundle"][key].extend(other["bundle"][key])
    bundle = combined["bundle"]
    bundle["bundle_ok"] = not bundle["failures"]
    bundle["worst_u95"] = max(m["u95"] for m in bundle["measurements"])
    n = len(combined["materials"])
    hits = sum(bool(m["findings"]) for m in combined["materials"])
    bundle["diagnostic"].update(trials=n, hits=hits, u95=bench.binomial_u95(n, hits))
    counts = Counter(rid for m in combined["materials"] for rid in m["rule_ids"])
    summary = combined["summary"]
    quiet = [row for row in combined["rules"].values() if not row["excluded_reason"] and row["diagnostic"]["hits"] == 0]
    summary.update(trials=n, bytes=sum(m["bytes"] for m in combined["materials"]),
                   findings=sum(counts.values()), findings_per_unit=sum(counts.values())/n,
                   units_touched=hits, quiet_rules=len(quiet),
                   quiet_reachable=sum(r["reachability"]["status"] == "reachable" for r in quiet),
                   quiet_unreachable=sum(r["reachability"]["status"] == "unreachable" for r in quiet),
                   quiet_no_examples=sum(r["reachability"]["status"] == "no_examples" for r in quiet))
    for label, threshold in (("one", .01), ("five", .05)):
        loud = sorted(rid for rid, k in counts.items() if k/n > threshold)
        summary[f"rules_over_{label}_percent"] = loud
        summary[f"over_{label}_percent_share"] = sum(counts[r] for r in loud)/sum(counts.values()) if counts else 0
    removed = sum(counts[r] for r in summary["rules_over_five_percent"])
    summary.update(top_rule_share=max(counts.values(), default=0)/sum(counts.values()) if counts else 0,
                   findings_without_loud_rules=sum(counts.values())-removed,
                   findings_per_unit_without_loud_rules=(sum(counts.values())-removed)/n)
    for rule in rules:
        lane, reason = bench.admit_from_report(rule, combined)
        combined["rules"][rule.id].update(lane=lane.value, lane_reason=reason)
    combined["component_reports"] = [{"measured_at": r["measured_at"], "corpora": [c["identity"] for c in r["corpora"]],
                                      "elapsed_s": r.get("elapsed_s"), "execution": r["method"]["execution"]} for r in reports]
    combined["method"]["execution"] = {"isolated": True, "workers": "see component_reports", "budget_s": "see component_reports"}
    combined.pop("elapsed_s", None)
    return combined


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--evidence", type=Path, required=True)
    args = p.parse_args()
    root = args.evidence
    rules = bench.load_rules(root / "atr-out-rules.json")
    reports = [json.loads((root / f"{name}-out-report.json").read_text(encoding="utf-8"))
               for name in ("trace-commons", "local-claude")]
    report = combine(reports, rules)
    (root / "combined-out-report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    with (root / "per-rule-strata.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(["id", "corpus", "stratum", "trials", "hits", "u95", "lane", "positive_status", "condition", "excluded_reason"])
        for rule in rules:
            row = report["rules"][rule.id]
            measurement = row["diagnostic"]
            writer.writerow([rule.id, "pooled-diagnostic", "all", measurement["trials"], measurement["hits"],
                             measurement.get("u95"), row["lane"], row["reachability"]["status"], rule.predicate, row["excluded_reason"]])
            for m in row["measurements"]:
                writer.writerow([rule.id, m["corpus"], m["stratum"], m["trials"], m["hits"], m["u95"],
                                 row["lane"], row["reachability"]["status"], rule.predicate, ""])
    summary = {"summary": report["summary"], "lanes": dict(Counter(r["lane"] for r in report["rules"].values())),
               "per_corpus": [{"name": r["corpora"][0]["identity"], "summary": r["summary"],
                               "lanes": dict(Counter(x["lane"] for x in r["rules"].values()))} for r in reports],
               "bundle_strata": [m for m in report["bundle"]["measurements"] if m["stratum"] == "all" or m["stratum"].startswith("exposure=")],
               "top_rules": [{"id": rid, **row["diagnostic"]} for rid, row in sorted(report["rules"].items(), key=lambda item: -item[1]["diagnostic"]["hits"])[:30]]}
    (root / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
