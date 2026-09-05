"""Load pinned rules on the Linux corpus host without extracting attack samples."""
import argparse
from collections import Counter
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import tarfile

from agent_defs.loaders import atr, sigma


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--archives", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    lock = json.loads(Path("sources.lock").read_text())
    pins = {entry["name"]: entry for entry in lock}
    for source in ("atr", "netzilo"):
        archive = args.archives / f"{source}.tar.gz"
        if hashlib.sha256(archive.read_bytes()).hexdigest() != pins[source]["archive_sha256"]:
            raise ValueError(f"{source} archive digest differs from sources.lock")
    # Full revision is fixed to the source measured in the earlier round.
    rev = pins["atr"]["commit"]
    root = args.out / "atr-source"
    root.mkdir(exist_ok=True)
    manifest = {"source_rev": rev, "files": {}}
    with tarfile.open(args.archives / "atr.tar.gz") as archive:
        for member in archive.getmembers():
            parts = Path(member.name).parts[1:]
            if not parts or not member.isfile():
                continue
            relative = Path(*parts)
            if relative.as_posix() != "LICENSE" and not (parts[0] == "rules" and relative.suffix in {".yaml", ".yml"}):
                continue
            raw = archive.extractfile(member).read()
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
            if parts[0] == "rules":
                manifest["files"][relative.as_posix()] = {"source_path": relative.as_posix(), "sha256": hashlib.sha256(raw).hexdigest()}
    (root / "atr-source.json").write_text(json.dumps(manifest))
    loaded = atr.load(root)
    (args.out / "atr-delta.json").write_text(json.dumps(asdict(loaded.delta), indent=2))
    out = [r for r in loaded.rules if r.surface.value == "OUT"]
    (args.out / "atr-out-rules.json").write_text(json.dumps([asdict(r) for r in out], ensure_ascii=False))
    print("ATR", len(loaded.rules), Counter((r.surface.value, r.predicate_kind.value) for r in loaded.rules), flush=True)
    net_root = args.archives.parent / "corpora" / "netzilo"
    verified_net = 0
    with tarfile.open(args.archives / "netzilo.tar.gz") as archive:
        for member in archive.getmembers():
            parts = Path(member.name).parts[1:]
            if not parts or not member.isfile() or parts[0] != "ai_agent" or Path(member.name).suffix not in {".yaml", ".yml"}:
                continue
            if (net_root / Path(*parts)).read_bytes() != archive.extractfile(member).read():
                raise ValueError(f"Netzilo checkout differs from pinned archive: {member.name}")
            verified_net += 1
    net = sigma.load(net_root, source="netzilo",
                     source_rev=pins["netzilo"]["commit"], license_spdx="Apache-2.0")
    in_rules = [r for r in net.rules if r.surface.value == "IN"]
    (args.out / "netzilo-in-rules.json").write_text(json.dumps([asdict(r) for r in in_rules], ensure_ascii=False))
    (args.out / "netzilo-delta.json").write_text(json.dumps(net.delta, indent=2))
    print("Netzilo", len(net.rules), Counter((r.surface.value, r.predicate_kind.value) for r in net.rules), flush=True)
    (args.out / "rule-source-audit.json").write_text(json.dumps({
        "archives": {source: {"sha256": pins[source]["archive_sha256"], "revision": pins[source]["commit"]}
                     for source in ("atr", "netzilo")},
        "atr_rule_files_verified": len(manifest["files"]), "netzilo_rule_files_verified": verified_net}, indent=2))


if __name__ == "__main__":
    main()
