"""Verify the pinned AAK composition and Guardana generator/benchmark evidence.

Only JSON parsing, Python AST inspection and text comparison occur. No upstream
scanner, rule implementation, probe, or benchmark payload is executed.
"""

from __future__ import annotations

import argparse
import ast
import difflib
import hashlib
import json
import subprocess
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from agent_defs.loaders import agent_audit_kit, ave, guardana


def git_text(root: Path, rev: str, path: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), "show", f"{rev}:{path}"]).decode("utf-8")


def evidence(root: Path, repo: str, rev: str, path: str) -> tuple[str, dict]:
    raw = git_text(root, rev, path)
    url = f"https://raw.githubusercontent.com/{repo}/{rev}/{path}"
    with urllib.request.urlopen(url, timeout=30) as response:
        remote = response.read().decode("utf-8")
        if remote != raw:
            raise ValueError(f"Git and HTTP content disagree: {url}")
        return raw, {"url": url, "http_status": response.status,
                     "checked_at": datetime.now(timezone.utc).date().isoformat(),
                     "sha256": hashlib.sha256(remote.encode()).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("aak", "ave", "guardana", "garak", "harmbench"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    sources = []

    def read(root, repo, rev, path):
        content, item = evidence(root, repo, rev, path)
        sources.append(item)
        return content

    aak_rev = agent_audit_kit.REVIEWED_REV
    guard_rev = guardana.REVIEWED_REV
    changelog = read(args.aak, "sattyamjjain/agent-audit-kit", aak_rev, "CHANGELOG.md")
    assert "253 chains across 33.8%" in changelog and "2 chains in 2 configs" in changelog
    composition = read(args.aak, "sattyamjjain/agent-audit-kit", aak_rev,
                       "agent_audit_kit/scanners/composition.py")
    assert "_UNTRUSTED_SOURCE_RE.search(surface)" in composition
    assert "MAX_PATH_NODES" in composition and "_MAX_GRAPH_NODES = 200" in composition
    assert "suppression_keys" in composition
    schema = json.loads(read(args.ave, "aveproject/ave", ave.REVIEWED_REV,
                             "schema/ave-record-1.1.0.schema.json"))
    assert "not verbatim signatures" in schema["properties"]["example_patterns"]["description"]
    generator = read(args.guardana, "guardana/guardana", guard_rev, "scripts/generate_docs.py")
    generator_ast = ast.parse(generator)
    entry = next(n for n in generator_ast.body if isinstance(n, ast.FunctionDef) and n.name == "_rule_entry")
    exported = next(n.value for n in entry.body if isinstance(n, ast.Return))
    export_keys = [key.value for key in exported.keys]
    provider = read(args.guardana, "guardana/guardana", guard_rev,
                    "packages/guardana-rules/src/guardana/rules/__init__.py")
    provider_ast = ast.parse(provider)
    provide = next(n for n in provider_ast.body if isinstance(n, ast.FunctionDef) and n.name == "provide_rules")
    constructors = [n.func.id for n in ast.walk(provide) if isinstance(n, ast.Call)
                    and isinstance(n.func, ast.Name) and n.func.id.endswith("Rule")]
    prefix = "packages/guardana-rules/src/guardana/rules/catalog/"
    catalog_files = subprocess.check_output(["git", "-C", str(args.guardana), "ls-tree", "-r", "--name-only", guard_rev, "--", prefix], text=True).splitlines()
    yaml_files = [p for p in catalog_files if p.endswith(".yaml") and "/" not in p[len(prefix):]]
    jailbreak = read(args.guardana, "guardana/guardana", guard_rev, prefix + "jailbreak.yaml")
    first_prompt = " ".join(jailbreak.split("  - >\n", 2)[1].split())
    benchmark_specs = [
        (args.garak, "NVIDIA/garak", "2212c73e4886c9c9fe78768e82a543a47284addf",
         "garak/data/inthewild_jailbreak_llms.json", 642, 16,
         "garak"),
        (args.harmbench, "centerforaisafety/HarmBench", "8e1604d1171fe8a48d8febecd22f600e462bdcdd",
         "baselines/human_jailbreaks/jailbreaks.py", 77, 12,
         "HarmBench"),
    ]
    overlaps = []
    for root, repo, rev, path, position, size, name in benchmark_specs:
        corpus = read(root, repo, rev, path)
        if path.endswith(".json"):
            candidate = json.loads(corpus)[position]
            location = f"JSON index {position} (zero-based)"
        else:
            candidate = next(n.value for n in ast.walk(ast.parse(corpus)) if isinstance(n, ast.Constant)
                             and isinstance(n.value, str) and n.lineno == position)
            location = f"Python string constant at line {position}"
        words = first_prompt.split()
        match = difflib.SequenceMatcher(None, words, candidate.split(), autojunk=False).find_longest_match()
        assert match.size == size
        fragment = " ".join(words[match.a:match.a + match.size])
        overlaps.append({"corpus": repo, "name": name, "source_rev": rev, "location": location,
                         "shared_contiguous_tokens": size,
                         "shared_text_sha256": hashlib.sha256(fragment.encode()).hexdigest(),
                         "whole_prompt_equal": first_prompt == " ".join(candidate.split())})
    for root, repo, rev, path in [
        (args.aak, "sattyamjjain/agent-audit-kit", aak_rev, "LICENSE"),
        (args.ave, "aveproject/ave", ave.REVIEWED_REV, "LICENSE"),
        (args.guardana, "guardana/guardana", guard_rev, "LICENSE"),
        (args.guardana, "guardana/guardana", guard_rev, "uv.lock"),
    ]:
        read(root, repo, rev, path)
    report = {
        "status": "VERIFIED", "http_evidence": sources,
        "aak_composition_measurement": {"status": "VERIFIED upstream report, not independently rerun",
                                        "configs": 748, "wide_findings": 253,
                                        "narrow_findings": 2, "after_suppression": 0},
        "guardana_generator": {"python_rule_constructors": len(constructors),
                               "catalog_yaml_files": yaml_files, "exported_keys": export_keys,
                               "regeneration_executed": False},
        "guardana_first_prompt_sha256_after_whitespace_folding": hashlib.sha256(first_prompt.encode()).hexdigest(),
        "benchmark_overlaps": overlaps,
        "interpretation": "VERIFIED partial stock-DAN overlap; copying direction and full-payload identity are not established.",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"{len(sources)} HTTP 200 sources verified; {len(constructors)} Python constructors, {len(yaml_files)} catalog YAML files; 16/12-token benchmark overlaps; {args.output}")


if __name__ == "__main__":
    main()
