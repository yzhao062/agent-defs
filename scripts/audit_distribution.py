"""Mandatory pre-release rights gate over complete, locally available corpora.

PYTHONPATH=src python scripts/audit_distribution.py /path/to/corpora \
    --archives /path/to/archives

A corpus directory may be a full checkout or a tree ``sources.fetch()`` wrote.
Those two layouts differ in what reaches disk: the fetcher refuses to extract
ATR's sample directory, and its allow-list also leaves the npm manifest behind.
This gate reads whatever the fetcher withholds out of the pinned archive in
memory, so both layouts are audited against the same evidence and no sample
byte is written anywhere, including a temporary directory.

No downloads, extraction, source execution, or payload output. Missing inputs,
digest mismatches, lost records, attribution loss and exclusion leaks fail.
"""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import asdict
import hashlib
import json
from pathlib import Path, PurePosixPath
import tarfile

from agent_defs import sources
from agent_defs.loaders import agent_audit_kit, atr, ave, guardana, sigma
from agent_defs.model import default_bundle


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


def extractable(source, license_path, members):
    """The in-scope members a fetch writes to disk, decided by the fetcher itself.

    Restating that policy here would let the two drift apart, which is the fault
    that once made the extractor and the cache verifier read one archive two
    ways. This is a question about disk layout, not about records, so it stays
    separate from the independent evidence selection the rest of the gate does.
    """
    files = {sources._portable_path(path): member for path, member in members.items()}
    kept, _ = sources._kept(files, set(), name=source, license_path=license_path)
    return {path for path in members if sources._portable_path(path) in kept}


def verify_tree(source, root, archive_path, pin):
    """Byte-compare the tree against its pin and account for every in-scope member.

    A member the extraction policy admits must be on disk and identical. One the
    policy refuses may be absent, and is still byte-compared when a full checkout
    carries it anyway. An in-scope file on disk that the archive does not declare
    still fails, as does a modified one.
    """
    digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    require(digest == pin["archive_sha256"], f"{source}: archive digest disagrees with sources.lock")
    expected, present = {}, set()
    with tarfile.open(archive_path, "r:gz") as archive:
        for member in archive:
            path = member.name.partition("/")[2]
            if not member.isfile() or not in_scope(source, path):
                continue
            expected[path] = member
            file = root / path
            if not file.is_file():
                continue
            present.add(path)
            require(hashlib.sha256(file.read_bytes()).digest()
                    == hashlib.sha256(archive.extractfile(member).read()).digest(),
                    f"{source}: modified pinned input {path}")
    missing = sorted(extractable(source, pin["license_path"], expected) - present)
    require(not missing, f"{source}: missing pinned input {missing[:3]} ({len(missing)} in total)")
    actual = {p.relative_to(root).as_posix() for p in root.rglob("*")
              if p.is_file() and in_scope(source, p.relative_to(root).as_posix())}
    require(actual == present, f"{source}: input membership differs: {sorted(actual ^ present)}")
    require(expected, f"{source}: no verified inputs")
    return {"archive_sha256": digest, "verified_files": len(present),
            "withheld_from_disk": len(expected) - len(present)}


def collect_yaml(records, path, data):
    """Parse one file's documents into records; return the ids it added."""
    import yaml

    added = []
    for raw in yaml.load_all(data, Loader=getattr(yaml, "CSafeLoader", yaml.SafeLoader)):
        require(isinstance(raw, dict) and isinstance(raw.get("id"), str),
                f"{path}: not a native record")
        require(raw["id"] not in records, f"{path}: duplicate native id {raw['id']}")
        records[raw["id"]] = (path, raw)
        added.append(raw["id"])
    return added


def yaml_records(root, prefix):
    records = {}
    for path in sorted((root / prefix).rglob("*")):
        if path.is_file() and path.suffix in {".yaml", ".yml"}:
            collect_yaml(records, path.relative_to(root).as_posix(), path.read_bytes())
    return records


def withheld_members(archive_path, prefix, extras):
    """Read what a fetch keeps off disk out of the pinned archive, in memory.

    Members under ``prefix`` are the excluded sample corpus. They are counted,
    decoded and parsed in this process and are never written anywhere; the
    caller gets paths, record ids and counts. ``extras`` names the small
    metadata files the allow-list also leaves behind, read the same way.

    Digest verification happens before this runs, so these bytes are the pinned
    ones. Reading the census here rather than from disk also makes it identical
    in both layouts instead of shrinking silently when a checkout is partial.
    """
    paths, records, drafts, read = [], {}, 0, {}
    with tarfile.open(archive_path, "r:gz") as archive:
        for member in archive:
            path = member.name.partition("/")[2]
            if not member.isfile():
                continue
            if path in extras:
                read[path] = archive.extractfile(member).read()
            if not path.startswith(prefix):
                continue
            paths.append(path)
            if PurePosixPath(path).suffix in {".yaml", ".yml"}:
                data = archive.extractfile(member).read()
                for rid in collect_yaml(records, path, data):
                    # The decode stays behind the same short circuit the on-disk
                    # read had, so a file only has to be text when it is a draft.
                    raw = records[rid][1]
                    drafts += (raw.get("status") == "draft"
                               and raw.get("detection", {}).get("conditions") == []
                               and "TODO(human)" in data.decode("utf-8"))
    absent = sorted(set(extras) - set(read))
    require(not absent, f"pinned archive {archive_path.name} has no {absent}")
    return {"paths": paths, "records": records, "drafts": drafts, "read": read}


def verify_excluded_corpus(delta, prefix, on_disk, pinned):
    """Tie the loader's excluded-path delta to the corpus in front of it.

    The loader counts what it can see, so the delta is the pinned corpus in a
    checkout and zero in a fetched cache. Those two layouts are the only ones
    this gate accepts: a tree carrying part of an excluded directory is neither,
    and its delta would understate a corpus that is present.
    """
    require(delta == {prefix: len(on_disk)},
            f"ATR: excluded-path delta {delta} disagrees with the {len(on_disk)} "
            "files under that prefix the loader could read")
    require(len(on_disk) in (0, pinned),
            f"ATR: {len(on_disk)} of the pin's {pinned} excluded files are on disk; a fetched "
            "cache carries none of them and a full checkout carries all of them")


def census(paths, prefix):
    """Directory and extension counts over withheld members, from paths alone."""
    return {"directories": dict(sorted(Counter(
                path[len(prefix):].split("/")[0] for path in paths).items())),
            "extensions": dict(sorted(Counter(
                PurePosixPath(path).suffix for path in paths).items()))}


def audit(corpora: Path, archives: Path, lock_path: Path | None = None):
    pins = sources.load_lock(lock_path)
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
    prefix = "data/test-corpora/"
    withheld = withheld_members(archives / "atr.tar.gz", prefix, ("package.json",))
    files, proposals = withheld["paths"], withheld["records"]
    require(files, "ATR: the pin carries no excluded corpus; this audit must not pass vacuously")
    on_disk = [p for p in (corpora / "atr" / prefix).rglob("*") if p.is_file()]
    verify_excluded_corpus(loaded.delta.excluded_paths, prefix, on_disk, len(files))
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
        "test_corpora": {"files": len(files), "yaml_proposals": len(proposals),
                         "draft_empty_conditions_todo": withheld["drafts"],
                         "files_on_disk": len(on_disk), **census(files, prefix)},
        "atr_npm_files_allowlist": json.loads(withheld["read"]["package.json"])["files"],
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpora", type=Path)
    parser.add_argument("--archives", type=Path, required=True)
    parser.add_argument("--lock", type=Path)
    args = parser.parse_args()
    print(json.dumps(audit(args.corpora, args.archives, args.lock), indent=2))
