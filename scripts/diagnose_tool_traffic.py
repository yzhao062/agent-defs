"""Isolate a failed rule/result pair, recording status but no private text."""
import argparse
from dataclasses import asdict
import json
from pathlib import Path

from agent_defs.bench import load_rules
from agent_defs.evaluate import scan


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--evidence", type=Path, required=True)
    p.add_argument("--rules", type=Path, required=True)
    p.add_argument("--unit", required=True)
    p.add_argument("--rule", required=True)
    p.add_argument("--budget-s", type=float, default=120)
    p.add_argument("--out-name", default="timeout-diagnosis.json")
    args = p.parse_args()
    rules = [r for r in load_rules(args.rules) if (r.runnable if args.rule == "ALL" else r.id == args.rule)]
    assert rules
    unit = next(json.loads(line) for line in (args.evidence / "local-claude-units.jsonl").read_text(encoding="utf-8").splitlines()
                if json.loads(line)["id"] == args.unit)
    result = scan(unit["text"], rules, max_bytes=unit["size_bytes"], budget_s=args.budget_s)
    output = {"unit": unit["id"], "sha256": unit["sha256"], "bytes": unit["size_bytes"],
              "rule": args.rule, "budget_s": args.budget_s, "elapsed_s": result.elapsed_s,
              "complete": result.complete, "rules_evaluated": result.rules_evaluated,
              "skipped": result.rules_skipped_budget, "truncated": result.truncated_input,
              "worker_error": result.worker_error, "errors": [asdict(e) for e in result.errors],
              "hits": len(result.findings)}
    (args.evidence / args.out_name).write_text(json.dumps(output, indent=2))
    print(json.dumps(output), flush=True)


if __name__ == "__main__":
    main()
