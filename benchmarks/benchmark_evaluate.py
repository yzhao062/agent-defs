"""Cold-worker latency on pinned ATR single-condition rules and a real code file.

Requires PyYAML only for this offline benchmark. No corpus files are vendored.
Run with PYTHONPATH=src python benchmarks/benchmark_evaluate.py --atr PATH.
"""

import argparse
from collections import Counter
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import random
import statistics
import subprocess
import time

import yaml

from agent_defs import PredicateKind, Rule, Surface
from agent_defs.evaluate import UnsafePattern, scan, screen_pattern


def percentile(values, q):
    return sorted(values)[max(0, math.ceil(len(values) * q) - 1)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--atr", type=Path, required=True)
    parser.add_argument("--samples", type=int, default=200)
    parser.add_argument("--sizes", type=int, nargs="+", default=[1, 8, 16, 32])
    parser.add_argument("--budget", type=float, default=5)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    rev = subprocess.check_output(["git", "-C", str(args.atr), "rev-parse", "HEAD"], text=True).strip()
    root = args.atr.resolve()
    if os.name == "nt":
        root = Path("\\\\?\\" + str(root))
    counts = Counter()
    rules = []
    for path in sorted((root / "rules").rglob("*.yaml")):
        record = yaml.safe_load(path.read_text(encoding="utf-8"))
        counts["yaml_records"] += 1
        detection = record.get("detection", {})
        conditions = detection.get("conditions", [])
        if detection.get("condition") not in ("any", "all") or len(conditions) != 1:
            continue
        condition = conditions[0]
        if not (condition.get("field") == "content" and condition.get("operator") == "regex"
                and isinstance(condition.get("value"), str)):
            continue
        counts["single_content_regex"] += 1
        pattern = condition["value"]
        try:
            screen_pattern(pattern)
        except UnsafePattern as exc:
            counts["rejected:" + str(exc).split(":")[0]] += 1
            continue
        rules.append(Rule(
            id="atr:" + record["id"], source="atr", source_id=record["id"], source_rev=rev,
            source_path=path.relative_to(root).as_posix(),
            upstream_url=f"https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/{rev}/{path.relative_to(root).as_posix()}",
            surface=Surface.OUT, predicate_kind=PredicateKind.REGEX, predicate=pattern,
        ))
    counts["accepted"] = len(rules)
    # Select without timing or benign-hit cherry-picking; keep the seed and ids.
    random.Random(20260905).shuffle(rules)
    sizes = sorted(set(min(size, len(rules)) for size in args.sizes))
    payload_path = Path(subprocess.__file__)
    payload = payload_path.read_text(encoding="utf-8")
    metadata = dict(python=platform.python_version(), platform=platform.platform(),
                    source_rev=rev, counts=dict(counts), samples=args.samples,
                    payload_path=str(payload_path), payload_bytes=len(payload.encode("utf-8")),
                    payload_sha256=hashlib.sha256(payload.encode("utf-8")).hexdigest(),
                    budget_s=args.budget, measurements=[])
    print(json.dumps({k: v for k, v in metadata.items() if k != "measurements"}), flush=True)
    rows = {size: [] for size in sizes}
    # Interleave sizes so changing host load affects each bundle size.
    for sample in range(args.samples):
        for size in sizes:
            started = time.perf_counter()
            result = scan(payload, rules[:size], budget_s=args.budget)
            rows[size].append(dict(ms=(time.perf_counter() - started) * 1000,
                                   complete=result.complete, evaluated=result.rules_evaluated,
                                   skipped=result.rules_skipped_budget, hits=len(result.findings),
                                   errors=len(result.errors), worker_error=result.worker_error))
        if (sample + 1) % 25 == 0:
            print(f"{sample + 1}/{args.samples} samples per bundle", flush=True)
    for size in sizes:
        values = [row["ms"] for row in rows[size]]
        row = dict(size=size, p50_ms=statistics.median(values), p99_ms=percentile(values, .99),
                   max_ms=max(values), incomplete=sum(not row["complete"] for row in rows[size]),
                   hits=sorted(set(row["hits"] for row in rows[size])),
                   rule_ids=[rule.id for rule in rules[:size]], raw=rows[size])
        metadata["measurements"].append(row)
        print(json.dumps({k: v for k, v in row.items() if k not in ("raw", "rule_ids")}), flush=True)
    args.output.write_text(json.dumps(metadata, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
