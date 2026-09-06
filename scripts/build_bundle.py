"""Freeze a pinned corpus into the bundle the hook ships with and reads.

Run this on the corpus host. It reads the pinned archive named in
``sources.lock``, extracts only the rule files and the licence, and never
unpacks a sample directory: the extraction filter is an allow list, so a corpus
that grows a new data directory cannot start landing on disk by default.

Four filters decide what travels, and each one drops rules for a reason the
manifest records rather than for a count somebody picked:

``surface``       the hook evaluates tool input and tool result, so a rule
                  bound to any other channel has no interception point here.
``runnable``      a rule with no flat predicate cannot be evaluated by this
                  package's evaluator, whatever its own dispatcher can do.
``shippable``     a record carrying a narrower grant than this package's own
                  licence would hand every consumer a limit they cannot see.
                  This is the gate ``docs/distribution.md`` specifies, so it is
                  ``Rule.shippable`` and not the per-record ``redistribution``
                  field, which every loader deliberately leaves unresolved.
``screened``      the evaluator refuses an ATR pattern with no measured timing,
                  and refuses one measured slow. A refused pattern at runtime
                  is a scan reported incomplete on every tool call, so the
                  refusal belongs here, once, at build time.
"""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import tarfile
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from agent_defs import bundle  # noqa: E402
from agent_defs.evaluate import compile_rule  # noqa: E402
from agent_defs.model import default_bundle  # noqa: E402

#: Everything else in the archive stays in the archive.
KEEP_SUFFIXES = {".yaml", ".yml"}


def extract(archive: Path, root: Path) -> dict:
    """Unpack the rule files alone and return a per-file digest manifest."""
    manifest: dict[str, dict] = {}
    with tarfile.open(archive) as tar:
        for member in tar.getmembers():
            parts = Path(member.name).parts[1:]
            if not parts or not member.isfile():
                continue
            relative = Path(*parts)
            keep = relative.as_posix() == "LICENSE" or (
                parts[0] == "rules" and relative.suffix in KEEP_SUFFIXES)
            if not keep:
                continue
            raw = tar.extractfile(member).read()
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
            if parts[0] == "rules":
                manifest[relative.as_posix()] = {
                    "source_path": relative.as_posix(),
                    "sha256": hashlib.sha256(raw).hexdigest()}
    if not manifest:
        raise SystemExit(f"{archive}: no rule files found; is this the right archive?")
    return manifest


def screened(rule) -> str:
    """An empty string when the evaluator accepts this rule, else why not."""
    try:
        compile_rule(rule)
    except Exception as exc:  # the screen raises UnsafePattern and re.error alike
        return f"{type(exc).__name__}: {exc}"
    return ""


def select(rules, surfaces):
    """Return the rules that travel, and one counted reason per rule that does not."""
    keep, dropped = [], Counter()
    refusals: dict[str, str] = {}
    shippable = {rule.id for rule in default_bundle(rules)}
    for rule in rules:
        if rule.surface.value not in surfaces:
            dropped["surface:" + rule.surface.value] += 1
        elif not rule.runnable:
            dropped["not_runnable"] += 1
        elif rule.id not in shippable:
            dropped["not_shippable"] += 1
        elif (reason := screened(rule)):
            dropped["screen_refused"] += 1
            refusals[rule.id] = reason
        else:
            keep.append(rule)
    return keep, dict(dropped), refusals


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--archive", type=Path, required=True,
                        help="the pinned source archive, verified against the lock")
    parser.add_argument("--lock", type=Path, default=Path("sources.lock"))
    parser.add_argument("--source", default="atr")
    parser.add_argument("--surface", action="append", default=None,
                        help="repeatable; defaults to OUT and IN")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    surfaces = tuple(args.surface or ("OUT", "IN"))

    pins = {entry["name"]: entry for entry in json.loads(args.lock.read_text(encoding="utf-8"))}
    if args.source not in pins:
        raise SystemExit(f"{args.source}: not in {args.lock}")
    pin = pins[args.source]
    digest = hashlib.sha256(args.archive.read_bytes()).hexdigest()
    if digest != pin["archive_sha256"]:
        raise SystemExit(f"{args.source}: archive digest {digest} differs from {args.lock}")

    with tempfile.TemporaryDirectory(prefix="agent-defs-bundle-") as work:
        root = Path(work) / args.source
        root.mkdir(parents=True)
        manifest = extract(args.archive, root)
        (root / f"{args.source}-source.json").write_text(
            json.dumps({"source_rev": pin["commit"], "files": manifest}), encoding="utf-8")
        if args.source != "atr":
            raise SystemExit(f"{args.source}: no loader wired into this script yet")
        from agent_defs.loaders import atr

        loaded = atr.load(root)

    keep, dropped, refusals = select(loaded.rules, surfaces)
    if not keep:
        raise SystemExit("every rule was filtered out; refusing to write an empty bundle")
    size = bundle.write(
        args.out, keep,
        source=args.source, source_rev=pin["commit"],
        archive_sha256=pin["archive_sha256"], license_spdx=pin["license_spdx"],
        upstream_url=pin["repo_url"],
        built_at=datetime.now(timezone.utc).isoformat(),
        surfaces=list(surfaces), rule_files=len(manifest),
        loaded=len(loaded.rules), shipped=len(keep), dropped=dropped,
        screen_refusals=refusals)
    print(f"{args.out}: {len(keep)} of {len(loaded.rules)} rules, {size} bytes")
    for reason, count in sorted(dropped.items(), key=lambda row: -row[1]):
        print(f"  dropped {count:5d}  {reason}")
    print("  by surface " + json.dumps(dict(Counter(r.surface.value for r in keep))))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
