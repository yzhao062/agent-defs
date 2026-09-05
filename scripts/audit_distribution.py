"""Mandatory pre-release rights gate over complete, locally available corpora.

PYTHONPATH=src python scripts/audit_distribution.py /path/to/corpora \
    --archives /path/to/archives

No downloads, extraction, source execution, or payload output. Missing inputs,
digest mismatches, lost records, attribution loss and exclusion leaks fail.
"""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import tarfile

from agent_defs.loaders import agent_audit_kit, atr, ave, guardana, sigma
from agent_defs.model import default_bundle
from agent_defs.sources import load_lock


def require(condition, message):
    # A build gate must also work with python -O.
    if not condition:
        raise AssertionError(message)


def in_scope(source, path):
    if source == "atr":
        return (path in {"LICENSE", "package.json"}
                or path.startswith("data/test-corpora/")
                or path.startswith("rules/") and path.endswith((".yaml", ".yml")))
    if source in {"netzilo", "agentshield"}:
        prefixes = ("ai_agent/",) if source == "netzilo" else ("rules/rules/", "bench/testcases/")
        return path.startswith(prefixes) and path.endswith((".yaml", ".yml"))
    if source == "ave":
        return path.startswith(("records/", "crosswalks/")) and path.endswith(".json")
    return path == {"agent_audit_kit": "rules.json", "guardana": "docs/generated/rules.json"}[source]


def verify_tree(source, root, archive_path, pin):
    digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    require(digest == pin["archive_sha256"], f"{source}: archive digest disagrees with sources.lock")
    expected = set()
    with tarfile.open(archive_path, "r:gz") as archive:
        for member in archive:
            path = member.name.partition("/")[2]
            if not member.isfile() or not in_scope(source, path):
                continue
            expected.add(path)
            file = root / path
            require(file.is_file(), f"{source}: missing pinned input {path}")
            require(hashlib.sha256(file.read_bytes()).digest()
                    == hashlib.sha256(archive.extractfile(member).read()).digest(),
                    f"{source}: modified pinned input {path}")
    actual = {p.relative_to(root).as_posix() for p in root.rglob("*")
              if p.is_file() and in_scope(source, p.relative_to(root).as_posix())}
    require(actual == expected, f"{source}: input membership differs: {sorted(actual ^ expected)}")
    require(expected, f"{source}: no verified inputs")
    return {"archive_sha256": digest, "verified_files": len(expected)}


def yaml_records(root, prefix):
    import yaml

    records = {}
    for path in sorted((root / prefix).rglob("*")):
        if path.is_file() and path.suffix in {".yaml", ".yml"}:
            for raw in yaml.load_all(path.read_bytes(), Loader=getattr(yaml, "CSafeLoader", yaml.SafeLoader)):
                require(isinstance(raw, dict) and isinstance(raw.get("id"), str),
                        f"{path}: not a native record")
                require(raw["id"] not in records, f"{path}: duplicate native id {raw['id']}")
                records[raw["id"]] = (path.relative_to(root).as_posix(), raw)
    return records


def audit(corpora: Path, archives: Path, lock_path: Path | None = None):
    pins = load_lock(lock_path)
    expected_sources = {"atr", "netzilo", "agentshield", "agent_audit_kit", "ave", "guardana"}
    require(set(pins) == expected_sources, "Update the rights gate to cover every locked source")
    integrity = {name: verify_tree(name, corpora / name, archives / f"{name}.tar.gz", pin)
                 for name, pin in pins.items()}
    atr_native = yaml_records(corpora / "atr", "rules")
    # Independent evidence selection: do not ask the loaders which records need flags.
    agentharm_ids = {rid for rid, (_, raw) in atr_native.items()
                     if "agentharm" in json.dumps([raw.get("author"), raw.get("metadata_provenance")],
                                                  default=str).casefold()}
    require(agentharm_ids, "ATR: no AgentHarm evidence found; audit must not pass vacuously")
    payload_sources = {rid: raw["metadata_provenance"]["payload_source"]
                       for rid, (_, raw) in atr_native.items()
                       if isinstance(raw.get("metadata_provenance"), dict)
                       and "payload_source" in raw["metadata_provenance"]}
    loaded = atr.load(corpora / "atr", source_rev=pins["atr"]["commit"])
    groups = {"atr": loaded.rules}
    deltas = {"atr": asdict(loaded.delta)}
    require(not loaded.delta.entry_errors, "ATR: loader rejected native entries")
    for source in ("netzilo", "agentshield"):
        groups[source], deltas[source] = sigma.load(
            corpora / source, source=source, source_rev=pins[source]["commit"],
            rules_dir="ai_agent" if source == "netzilo" else "rules/rules",
            license_spdx=pins[source]["license_spdx"])
        require(not deltas[source]["errors"], f"{source}: loader rejected native entries: {deltas[source]['errors']}")
    for source, loader in (("agent_audit_kit", agent_audit_kit), ("ave", ave), ("guardana", guardana)):
        groups[source], deltas[source] = loader.load(corpora / source, source_rev=pins[source]["commit"])
    for source, rules in groups.items():
        require(len(rules) == pins[source]["record_count"],
                f"{source}: loaded {len(rules)} != locked population {pins[source]['record_count']}")
        require(all(r.source == source and r.source_rev == pins[source]["commit"] for r in rules),
                f"{source}: lost source identity or revision")
    by_id = {r.source_id: r for r in groups["atr"]}
    require(set(by_id) == set(atr_native), "ATR: normalized IDs differ from native input")
    require({r.source_id for r in groups["atr"] if r.restricted} == agentharm_ids,
            "ATR: restricted flags disagree with native AgentHarm evidence")
    for rid, (_, raw) in atr_native.items():
        author = raw.get("author")
        if author:
            require(any(item.kind == "author_field" and item.value == author for item in by_id[rid].lineage),
                    f"atr:{rid}: lost author attribution")
    for rid, payload_source in payload_sources.items():
        rule = by_id[rid]
        require(rule.extra["upstream"]["metadata_provenance"]["payload_source"] == payload_source,
                f"{rule.id}: lost raw payload_source")
        require(any(item.kind == "payload_source" and item.value == payload_source
                    and "metadata_provenance.payload_source" in item.evidence
                    and rule.upstream_url in item.evidence for item in rule.lineage),
                f"{rule.id}: lost payload_source lineage")
    netzilo_native = yaml_records(corpora / "netzilo", "ai_agent")
    converted_ids = {rid for rid, (_, raw) in netzilo_native.items()
                     if any(ref.rstrip("/").rsplit("/", 1)[-1] in agentharm_ids
                            for ref in raw.get("references", []))}
    require(converted_ids <= {r.source_id for r in groups["netzilo"] if r.restricted},
            "Netzilo: conversion of restricted ATR material lacks a restriction flag")
    rules = [r for group in groups.values() for r in group]
    bundle = default_bundle(rules)
    require(len({r.id for r in rules}) == len(rules), "Duplicate normalized IDs")
    require(all("AgentHarm" in r.restricted_reason and "field-of-use" in r.restricted_reason
                for r in rules if r.restricted), "Restricted record has no named restriction reason")
    require(not [r.id for r in bundle if r.restricted], "RELEASE BLOCKED: restricted record in default bundle")
    def excluded(rule):
        return rule.source == "atr" and rule.source_path.replace("\\", "/").startswith("data/test-corpora/")
    require(not [r.id for r in rules if excluded(r)], "ATR loader emitted an excluded path")
    require(not [r.id for r in bundle if excluded(r)], "RELEASE BLOCKED: excluded path in default bundle")
    require([r.id for r in bundle] == [r.id for r in rules if not r.restricted and not excluded(r)],
            "Default bundle silently omitted eligible records or changed their order")
    root = corpora / "atr" / "data/test-corpora"
    files = [p for p in root.rglob("*") if p.is_file()]
    require(loaded.delta.excluded_paths == {"data/test-corpora/": len(files)},
            "ATR: excluded-path delta disagrees with the verified corpus")
    drafts = yaml_records(corpora / "atr", "data/test-corpora")
    draft_count = sum(raw.get("status") == "draft" and raw.get("detection", {}).get("conditions") == []
                      and "TODO(human)" in (corpora / "atr" / path).read_text(encoding="utf-8")
                      for path, raw in drafts.values())
    return {
        "status": "VERIFIED", "integrity": integrity,
        "sources": {name: {"loaded": len(group), "ships": sum(r.shippable for r in group),
                           "restricted": sum(r.restricted for r in group),
                           "shipped_runnable": sum(r.shippable and r.runnable for r in group)}
                    for name, group in groups.items()},
        "loaded": len(rules), "ships": len(bundle), "restricted": sum(r.restricted for r in rules),
        "restricted_ids": {name: sorted(r.source_id for r in group if r.restricted)
                           for name, group in groups.items() if any(r.restricted for r in group)},
        "atr_agentharm_count": len(agentharm_ids), "atr_agentharm_is_25": len(agentharm_ids) == 25,
        "netzilo_restricted_atr_conversions": len(converted_ids),
        "atr_garak_author_count": sum("garak" in raw.get("author", "").casefold()
                                      for _, raw in atr_native.values()),
        "atr_garak_payload_source_count": sum("garak" in value.casefold() for value in payload_sources.values()),
        "atr_payload_source_ids": sorted(payload_sources),
        "excluded_paths": loaded.delta.excluded_paths,
        "test_corpora": {"files": len(files), "yaml_proposals": len(drafts),
                         "draft_empty_conditions_todo": draft_count,
                         "directories": dict(sorted(Counter(p.relative_to(root).parts[0] for p in files).items())),
                         "extensions": dict(sorted(Counter(p.suffix for p in files).items()))},
        "atr_npm_files_allowlist": json.loads((corpora / "atr" / "package.json").read_text())["files"],
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpora", type=Path)
    parser.add_argument("--archives", type=Path, required=True)
    parser.add_argument("--lock", type=Path)
    args = parser.parse_args()
    print(json.dumps(audit(args.corpora, args.archives, args.lock), indent=2))
