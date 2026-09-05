"""Measure fresh-process hook latency separately from precompiled scans.

Optional --atr-tree measures original ATR regex predicates as a workload, not
as normalized rules or a shippable bundle. Requires the atr extra only for that
offline benchmark. No corpus bytes are written into the package.
"""
from __future__ import annotations

import argparse
from dataclasses import replace
import json
import math
import os
from pathlib import Path
import shlex
import statistics
import subprocess
import sys
import tempfile
import time

from agent_defs.builtin import STARTER_RULES
from agent_defs.evaluate import compile_rule, scan, UnsafePattern
from agent_defs.hooks._claude_code_impl import atomic_json, default_config, hook_command, process
from agent_defs.model import PredicateKind


def summary(values):
    values = sorted(values)
    return {"n": len(values), "p50_ms": round(statistics.median(values) * 1000, 3),
            "p99_ms": round(values[math.ceil(.99 * len(values)) - 1] * 1000, 3)}


def timed(function, n):
    result = []
    for _ in range(n):
        start = time.perf_counter()
        function()
        result.append(time.perf_counter() - start)
    return summary(result)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--samples", type=int, default=200)
    parser.add_argument("--atr-tree", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--pair-only", action="store_true", help="measure one PreToolUse plus one PostToolUse per sample")
    args = parser.parse_args()
    results = {"python": sys.version, "executable": sys.executable, "samples": args.samples}
    def checkpoint():
        if args.output:
            args.output.write_text(json.dumps(results, indent=2), encoding="utf-8")
        print("completed", list(results)[-1], file=sys.stderr, flush=True)
    text = ("Issue: CSV export has one fewer row than the report. Steps: open report, export, compare rows.\n" * 3000)
    with tempfile.TemporaryDirectory(prefix="agent-defs-bench-") as directory:
        root = Path(directory)
        config = default_config()
        config["log_path"] = str(root / "findings.jsonl")
        path = root / "config.json"
        atomic_json(path, config)
        command = shlex.split(hook_command(path))
        env = dict(os.environ)
        env.pop("PYTHONPATH", None)
        def child(argv, data=b""):
            result = subprocess.run(argv, input=data, capture_output=True, cwd=root, env=env, timeout=5)
            assert result.returncode == 0 and not result.stderr, result.stderr
            return result.stdout
        if args.pair_only:
            pre = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Read",
                              "tool_input": {"file_path": "issue.txt"}}).encode()
            post = json.dumps({"hook_event_name": "PostToolUse", "tool_name": "Read",
                               "tool_response": {"type": "text", "file": {"content": text[:65536]}}}).encode()
            def pair():
                child(command, pre)
                child(command, post)
            results["starter_pre_plus_post_64k"] = timed(pair, args.samples)
            checkpoint()
            print(json.dumps(results, indent=2))
            return
        results["startup_isolated_python_no_site"] = timed(lambda: child([sys.executable, "-I", "-S", "-c", "pass"]), args.samples)
        checkpoint()
        results["startup_python_with_site"] = timed(lambda: child([sys.executable, "-c", "pass"]), args.samples)
        checkpoint()
        results["starter"] = []
        for size in (8*1024, 64*1024, 256*1024):
            body = text[:size]
            payload = {"hook_event_name": "PostToolUse", "tool_name": "Read",
                       "tool_input": {"file_path": "issue.txt"},
                       "tool_response": {"type": "text", "file": {"content": body, "numLines": 1}}}
            encoded = json.dumps(payload).encode()
            cache = {r.id: compile_rule(r) for r in STARTER_RULES}
            results["starter"].append({"rules": len(STARTER_RULES), "text_bytes": len(body.encode()),
                "precompiled_scan": timed(lambda: scan(body, STARTER_RULES, compiled=cache), args.samples),
                "warm_full_process": timed(lambda: process(payload, config), args.samples),
                "fresh_interpreter_hook": timed(lambda: child(command, encoded), args.samples)})
            checkpoint()
        payload["tool_response"]["file"]["content"] = text[:64*1024] + STARTER_RULES[0].examples_positive[0]
        encoded = json.dumps(payload).encode()
        results["starter_record_with_log_64k"] = timed(lambda: child(command, encoded), args.samples)
        checkpoint()
        scaled = tuple(replace(STARTER_RULES[i % 4], id=f"bench:{i}",
                              predicate=(f"INSTRUCTION MARKER {i:04d}:", *STARTER_RULES[i % 4].predicate))
                       for i in range(515))
        results["synthetic_linear_scaling"] = []
        for n in (64, 128, 515):
            rules = scaled[:n]
            cache = {r.id: compile_rule(r) for r in rules}
            for size in (64*1024, 256*1024):
                results["synthetic_linear_scaling"].append({"rules": n, "text_bytes": size,
                    "precompiled_scan": timed(lambda: scan(text[:size], rules, compiled=cache, budget_s=5), args.samples)})
        checkpoint()
        if args.atr_tree:
            import yaml
            import re
            tree = args.atr_tree.resolve()
            if os.name == "nt":
                tree = Path("\\\\?\\" + str(tree))
            paths = sorted((tree / "rules").rglob("*.yaml"))
            patterns = []
            rejected = 0
            for path in paths:
                document = yaml.safe_load(path.read_text(encoding="utf-8"))
                for condition in document.get("detection", {}).get("conditions", []):
                    if not isinstance(condition, dict) or condition.get("operator") != "regex" or not isinstance(condition.get("value"), str):
                        continue
                    rule = replace(STARTER_RULES[0], id=f"bench:{len(patterns)}", predicate_kind=PredicateKind.REGEX,
                                   predicate=condition["value"])
                    try:
                        runtime = compile_rule(rule)
                    except (UnsafePattern, re.error):
                        rejected += 1
                        continue
                    patterns.append((rule, runtime))
            results["atr_predicate_workload"] = {"source_records": len(paths), "screened_regex_predicates": len(patterns),
                                                  "rejected": rejected, "measurements": []}
            for n in (16, 32, 64, 128):
                rules = [p[0] for p in patterns[:n]]
                cache = {r.id: compiled for r, compiled in patterns[:n]}
                for size in (64*1024, 256*1024):
                    runs = []
                    def execute():
                        result = scan(text[:size], rules, compiled=cache, budget_s=.05)
                        runs.append(result.rules_evaluated)
                    timing = timed(execute, args.samples)
                    results["atr_predicate_workload"]["measurements"].append({"predicates": n, "text_bytes": size,
                        "scan": timing, "min_evaluated": min(runs), "max_evaluated": max(runs)})
                    checkpoint()
    output = json.dumps(results, indent=2)
    if args.output:
        args.output.write_text(output, encoding="utf-8")
    print(output)


if __name__ == "__main__":
    main()
