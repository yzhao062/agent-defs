"""Reproduce the Sigma corpus audit without vendoring the corpora.

Run with PYTHONPATH=src and the sigma extra installed. The optional case probe
runs upstream regexes in a separate process with a hard 30-second deadline. It
is diagnostic only: screen_pattern rejections never become runnable records.
"""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from agent_defs.loaders.sigma import (
    NETZILO_ATR_IMPORT, SIGMA_SPEC, dedup, deduplicated_view, load,
    parse_condition, reachability,
)
from agent_defs.model import Rule

ATR_REV = "66c7c1573e202b83ac526b70275244c50000068a"
NETZILO_REV = "5069b74d725a3cb7a7267833cbf0f8de1f31e4a7"
AGENTSHIELD_REV = "1bd56f9854426e29d59715e81c45fcfe38c7ee0e"


def git(root, *args):
    return subprocess.check_output(
        ["git", "-c", "core.protectNTFS=false", "-C", str(root), *args],
        text=True, encoding="utf-8",
    ).strip()


def atr_origins(root):
    import yaml

    result = []
    for path in sorted((root / "rules").rglob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or "id" not in data:
            continue
        tests = data.get("test_cases", {})
        path_raw = path.relative_to(root).as_posix()
        def extract(cases):
            strings, structured = [], []
            fields = {"input", "content", "tool_response", "tool_description", "agent_output",
                      "tool_args", "user_input", "tool_call", "tool_name"}
            for case in cases:
                if not isinstance(case, dict):
                    structured.append(case)
                    continue
                present = fields.intersection(case)
                if len(present) == 1 and isinstance(case[next(iter(present))], str):
                    strings.append(case[next(iter(present))])
                else:
                    structured.append(case)
            return tuple(strings), structured
        positives, structured = extract(tests.get("true_positives", []))
        negatives, _ = extract(tests.get("true_negatives", []))
        result.append(Rule(
            id="atr:" + data["id"], source="atr", source_id=data["id"],
            source_rev=ATR_REV, source_path=path_raw,
            upstream_url=f"https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/{ATR_REV}/{path_raw}",
            title=data.get("title", ""), case_sensitive=False,
            examples_positive=positives, examples_negative=negatives,
            not_runnable_reason="Audit identity/example carrier only; use the ATR loader for execution.",
            extra={"atr_detection_raw": data.get("detection", {}), "test_cases_raw": tests,
                   "positive_scenarios_raw": [{"path": path_raw, "expected_rule_id": data["id"],
                                               "scenario": case} for case in structured]},
        ))
    return result


def verify_atr_archive(root, repository):
    entries = git(repository, "ls-tree", "-r", ATR_REV, "rules").splitlines()
    expected = {}
    for entry in entries:
        meta, path = entry.split("\t", 1)
        if path.endswith(".yaml"):
            expected[path] = meta.split()[2]
    actual = {}
    for path in (root / "rules").rglob("*.yaml"):
        raw = path.read_bytes()
        actual[path.relative_to(root).as_posix()] = hashlib.sha1(
            b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    if actual != expected:
        raise ValueError("ATR archive files differ from the pinned Git tree")
    return len(actual)


def eval_tree(tree, selections):
    if tree[0] == "ref":
        return selections[tree[1]]
    if tree[0] == "not":
        return not eval_tree(tree[1], selections)
    values = [eval_tree(t, selections) for t in tree[1:]]
    return all(values) if tree[0] == "and" else any(values)


def probe(jobs):
    """Evaluate the original boolean expression, never a joined regex."""
    rows = []
    for job in jobs:
        detection = job["detection"]
        sels = {k: v for k, v in detection.items() if k != "condition"}
        tree = parse_condition(detection["condition"], sels)
        modes = {}
        try:
            for mode, flags in (("native", 0), ("restored", re.IGNORECASE)):
                modes[mode] = {name: [(key.split("|")[0], [re.compile(p, flags) for p in
                                      (patterns if isinstance(patterns, list) else [patterns])])
                                     for key, patterns in selection.items()]
                               for name, selection in sels.items()}
        except re.error as exc:
            rows.append({"id": job["id"], "error": str(exc)})
            continue
        def hit(mode, text):
            selections = {name: all(any(p.search(text) for p in patterns) for _, patterns in fields)
                          for name, fields in modes[mode].items()}
            return eval_tree(tree, selections)
        native = sum(hit("native", x) for x in job["examples"])
        lower = sum(hit("native", x.lower()) for x in job["examples"])
        restored = sum(hit("restored", x) for x in job["examples"])
        rows.append({"id": job["id"], "origin_id": job["origin_id"],
                     "title": job["title"], "examples": len(job["examples"]),
                     "native_hits": native, "lowercase_hits": lower,
                     "restored_hits": restored, "payload_fields": job["payload_fields"],
                     "input_examples": len(job["input_examples"]),
                     "input_native_hits": sum(hit("native", x) for x in job["input_examples"]),
                     "input_lowercase_hits": sum(hit("native", x.lower()) for x in job["input_examples"]),
                     "input_restored_hits": sum(hit("restored", x) for x in job["input_examples"])})
    return rows


def check_url(url):
    date = datetime.now(timezone.utc).date().isoformat()
    try:
        with urlopen(Request(url, headers={"User-Agent": "agent-defs-audit"}), timeout=20) as response:
            return {"url": url, "http_status": response.status, "observed_utc_date": date}
    except HTTPError as exc:
        return {"url": url, "http_status": exc.code, "observed_utc_date": date}
    except URLError as exc:
        return {"url": url, "http_status": None, "error": str(exc), "observed_utc_date": date}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--netzilo", type=Path)
    parser.add_argument("--agentshield", type=Path)
    parser.add_argument("--atr", type=Path)
    parser.add_argument("--atr-git", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--probe", action="store_true")
    parser.add_argument("--case-diagnostics", action="store_true")
    args = parser.parse_args()
    if args.probe:
        print(json.dumps(probe(json.load(sys.stdin))))
        return
    if not all((args.netzilo, args.agentshield, args.atr, args.atr_git, args.output)):
        parser.error("--netzilo, --agentshield, --atr, --atr-git and --output are required")
    verified_atr_files = verify_atr_archive(args.atr, args.atr_git)
    for root, expected in ((args.netzilo, NETZILO_REV), (args.agentshield, AGENTSHIELD_REV)):
        if git(root, "rev-parse", "HEAD") != expected:
            raise ValueError(f"{root}: unexpected revision")
        if git(root, "status", "--porcelain", "--untracked-files=no"):
            raise ValueError(f"{root}: modified tracked files")
    netzilo = load(args.netzilo, source="netzilo", source_rev=NETZILO_REV)
    agentshield = load(args.agentshield, source="agentshield", source_rev=AGENTSHIELD_REV)
    origins = atr_origins(args.atr)
    combined = dedup([*origins, *agentshield.rules, *netzilo.rules])
    by_id = {r.id: r for r in combined.rules}
    marked = [r for r in combined.rules if r.source == "netzilo"]
    own = [r for r in marked if not r.extra.get("is_conversion_duplicate")]
    imported = git(args.netzilo, "diff-tree", "--no-commit-id", "--name-only", "--diff-filter=A", "-r", NETZILO_ATR_IMPORT).splitlines()
    atr_conversions = [r for r in marked if str(r.extra.get("duplicate_of", "")).startswith("atr:")]
    import_paths = {r.source_path for r in atr_conversions}
    native_examples = {
        "netzilo": sum(bool(r.examples_positive) for r in netzilo.rules),
        "agentshield": sum(bool(r.examples_positive) for r in agentshield.rules),
    }
    single_field_jobs, multi_field_jobs = [], []
    for rule in atr_conversions:
        detection = rule.extra["sigma_detection_raw"]
        selections = [v for k, v in detection.items() if k != "condition"]
        if not rule.examples_positive or not all(isinstance(s, dict) for s in selections):
            continue
        keys = {key for s in selections for key in s}
        if not keys or not all(key.endswith("|re") for key in keys):
            continue
        fields = sorted({key.split("|")[0] for key in keys})
        origin = by_id[rule.extra["duplicate_of"]]
        input_examples = [case["input"] for case in origin.extra["test_cases_raw"].get("true_positives", [])
                          if isinstance(case, dict) and isinstance(case.get("input"), str)]
        job = {"id": rule.id, "origin_id": rule.extra["duplicate_of"],
               "title": rule.title, "detection": detection,
               "examples": rule.examples_positive, "payload_fields": fields,
               "input_examples": input_examples}
        (single_field_jobs if len(fields) == 1 else multi_field_jobs).append(job)
    diagnostic = {"status": "not requested"}
    if args.case_diagnostics:
        try:
            completed = subprocess.run(
                [sys.executable, str(Path(__file__).resolve()), "--probe"],
                input=json.dumps(single_field_jobs + multi_field_jobs),
                capture_output=True, text=True, encoding="utf-8", timeout=30, check=True,
            )
            rows = json.loads(completed.stdout)
            cases = [r for r in rows if not r.get("error") and r["native_hits"] == 0 and r["lowercase_hits"] > 0]
            for row in cases:
                rule = by_id[row["id"]]
                row["case_decision"] = rule.extra["case_decision"]
                row["predicate_kind"] = rule.predicate_kind.value
                row["screen_rejections"] = len(rule.extra["pattern_rejections"])
            diagnostic = {
                "status": "completed in subprocess with 30-second deadline",
                "single_field_rules": len(single_field_jobs), "multi_field_broadcast_probes": len(multi_field_jobs),
                "single_field_defects": [r for r in cases if len(r["payload_fields"]) == 1],
                "input_field_defects": [r for r in cases if len(r["payload_fields"]) == 1
                                        and r["input_examples"] and not r["input_native_hits"]
                                        and r["input_lowercase_hits"]],
                "multi_field_broadcast_defects": [r for r in cases if len(r["payload_fields"]) > 1],
                "single_field_reachability": {
                    mode: {"reachable": sum(r.get(mode, 0) > 0 for r in rows if len(r.get("payload_fields", [])) == 1),
                           "example_hits": sum(r.get(mode, 0) for r in rows if len(r.get("payload_fields", [])) == 1)}
                    for mode in ("native_hits", "lowercase_hits", "restored_hits")},
                "single_field_examples": sum(len(j["examples"]) for j in single_field_jobs),
                "single_field_by_id": {r["id"]: {k: v for k, v in r.items() if k not in ("id", "title")}
                                       for r in rows if len(r.get("payload_fields", [])) == 1},
                "errors": [r for r in rows if r.get("error")],
            }
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as exc:
            diagnostic = {"status": "UNRESOLVED", "error": str(exc)}
    own_counts = {
        "records": len(own), "maturity": dict(Counter(r.maturity_raw for r in own)),
        "surfaces": dict(Counter(r.surface.value for r in own)),
        "predicates": dict(Counter(r.predicate_kind.value for r in own)),
        "ids": [r.id for r in own],
    }
    urls = [
        f"https://github.com/netzilo/aidr-sigma/tree/{NETZILO_REV}",
        f"https://github.com/netzilo/aidr-sigma/commit/{NETZILO_ATR_IMPORT}",
        f"https://github.com/agentshield-ai/agentshield/tree/{AGENTSHIELD_REV}/rules/rules/ai_agent",
        f"https://github.com/Agent-Threat-Rule/agent-threat-rules/tree/{ATR_REV}/rules",
        f"https://raw.githubusercontent.com/Agent-Threat-Rule/agent-threat-rules/{ATR_REV}/src/engine.ts",
        SIGMA_SPEC,
        f"https://github.com/agentshield-ai/agentshield/tree/{AGENTSHIELD_REV}/bench/testcases",
    ]
    report = {
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "revisions": {"netzilo": NETZILO_REV, "agentshield": AGENTSHIELD_REV, "atr": ATR_REV},
        "netzilo": netzilo.delta, "agentshield": agentshield.delta,
        "atr_identity_records": len(origins), "dedup": combined.delta,
        "atr_files_verified_by_git_blob_hash": verified_atr_files,
        "deduplicated_records": len(deduplicated_view(combined.rules)),
        "import_commit": {"sha": NETZILO_ATR_IMPORT, "added_files": len(imported),
                          "matches_all_atr_paths": set(imported) == import_paths,
                          "unexpected_paths": sorted(set(imported) - import_paths),
                          "missing_paths": sorted(import_paths - set(imported))},
        "netzilo_own": own_counts,
        "netzilo_converted_surfaces": dict(Counter(r.surface.value for r in marked if r.extra.get("is_conversion_duplicate"))),
        "native_positive_example_rules": native_examples,
        "reachability": {"netzilo": reachability(marked), "agentshield": reachability(agentshield.rules)},
        "case_diagnostics": diagnostic, "url_checks": [check_url(u) for u in urls],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), "dedup_methods": combined.delta["methods"],
                      "unmatched": combined.delta["unmatched"], "ambiguous": combined.delta["ambiguous"],
                      "netzilo_own": {k: v for k, v in own_counts.items() if k != "ids"},
                      "reachability": {k: v["counts"] for k, v in report["reachability"].items()},
                      "case_defects": len(diagnostic.get("single_field_defects", []))}, indent=2))


if __name__ == "__main__":
    main()
