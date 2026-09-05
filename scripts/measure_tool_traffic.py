"""Run agent_defs.bench on hash-verified, extracted tool-result JSONL."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import time

from agent_defs import bench
from agent_defs.model import Surface


def corpus(root, name, surface):
    metadata = json.loads((root / f"{name}-inventory.json").read_text())
    raw = (root / f"{name}-units.jsonl").read_bytes()
    if hashlib.sha256(raw).hexdigest() != metadata["units_sha256"]:
        raise ValueError("traffic snapshot digest mismatch")
    units = []
    for line in raw.splitlines():
        row = json.loads(line)
        text = row["text"] if surface is Surface.OUT else row["invocation"]
        encoded = text.encode("utf-8")
        digest = hashlib.sha256(encoded).hexdigest()
        if surface is Surface.OUT and (digest != row["sha256"] or len(encoded) != row["size_bytes"]):
            raise ValueError("tool result digest mismatch")
        strata = dict(row["strata"])
        strata["file_type"] = "tool-result" if surface is Surface.OUT else "tool-invocation"
        units.append(bench.Unit(row["id"], text, surface, strata, digest, len(encoded)))
    return bench.Corpus(name, metadata["revision"], tuple(units), metadata["units_sha256"],
                        ("exposure=attacker-reachable", "exposure=locally-generated"))


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--evidence", type=Path, required=True)
    p.add_argument("--names", nargs="+", required=True)
    p.add_argument("--surface", choices=["OUT", "IN"], default="OUT")
    p.add_argument("--rules", type=Path, required=True)
    p.add_argument("--workers", type=int, default=4)
    p.add_argument("--budget-s", type=float, default=30.0)
    args = p.parse_args()
    rules = bench.load_rules(args.rules)
    corpora = [corpus(args.evidence, name, Surface(args.surface)) for name in args.names]
    print("start", args.names, "rules", len(rules), "trials", sum(len(c.units) for c in corpora), flush=True)
    started = time.monotonic()
    report = bench.measure(rules, corpora, isolated=True, workers=args.workers, budget_s=args.budget_s)
    report["elapsed_s"] = time.monotonic() - started
    path = args.evidence / ("-".join(args.names) + "-" + args.surface.lower() + "-report.json")
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print("done", report["summary"], "lanes", Counter(r["lane"] for r in report["rules"].values()),
          "seconds", report["elapsed_s"], flush=True)


if __name__ == "__main__":
    main()
