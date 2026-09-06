"""Freeze a pinned corpus into the bundle the hook ships with and reads.

Run this on the corpus host. It reads the pinned archive named in
``sources.lock``, extracts only the rule files and the licence, and never
unpacks a sample directory: the extraction filter is an allow list, so a corpus
that grows a new data directory cannot start landing on disk by default.

Five filters decide what travels, and each one drops rules for a reason the
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
``content-free``  the hook scans each string leaf of a tool result separately,
                  and leaves holding only whitespace are ordinary. A rule
                  matching one of the fixtures in ``CONTENT_FREE`` fires on
                  ordinary work, and no benign rate measured over joined text
                  can license it.

The last filter rejects rules matching specified whitespace-only fixtures. It
was introduced after inspecting the held-out traversal diagnostic, which is a
build policy change informed by that result, so the lower post-change
measurement is not an untouched validation of the revised detector. Writing the
criterion as a property of the pattern does not restore that independence: the
decision to look for this property came from seeing which rule inflated the
diagnostic, and a feature can be selected adaptively exactly as an identifier
can. What the fixtures establish is narrower than the name suggests, and
``CONTENT_FREE`` says so at its definition.

One thing does survive the adaptivity, and it is worth stating because it is
the reason removing the rule is not a statistical trick: deleting rules cannot
increase a union of predicate hits, so a bound already established for a fixed
superset stays conservative for any subset of it, adaptively chosen or not.
That licenses keeping the earlier number as an upper bound. It does not
license quoting the tighter post-removal count as a fresh validation.
"""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import tarfile
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from agent_defs import bench, bundle  # noqa: E402
from agent_defs.evaluate import compile_rule, scan_trusted  # noqa: E402
from agent_defs.model import default_bundle  # noqa: E402

#: Everything else in the archive stays in the archive.
KEEP_SUFFIXES = {".yaml", ".yml"}

#: Sample text, and the raw upstream documents that repeat it verbatim.
#: ``SAMPLES.md`` rule 2: an install must not drop AV-detected files on a disk,
#: and ``examples_positive`` is a build-time input rather than a shipped field.
STRIPPED_FIELDS = ("examples_positive", "examples_negative")
STRIPPED_EXTRA = ("upstream", "upstream_yaml")


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


#: Whitespace-only leaves an ordinary tool result carries. ``process`` already
#: skips the empty string, so these are the remaining shapes. The single space
#: comes first because a rule firing on it is the loudest case there is, and
#: the manifest records the first fixture that matched.
#:
#: **This is a fixture list, not a decision procedure.** A rule matching no
#: entry here can still match some whitespace-only string the list omits.
#: ``^ {7}$`` and ``^\u2028+$`` are both accepted by the screen and both fire
#: on a blank leaf, and neither is below; the first version of this list had no
#: single space in it at all. Deciding the real property, that a pattern's
#: language does not intersect the whitespace-only strings, takes an analysis
#: of the pattern rather than a longer list, and more lengths do not approach
#: it. This is a regression policy against the shape that was found.
#:
#: It is also the one place the fixtures are written.
#: ``tests/test_shipped_bundle.py`` imports this tuple rather than restating
#: it, because two lists drifting apart is how the single space went missing.
#:
#: Written as escapes throughout. A literal U+00A0 sitting in source is the one
#: thing a reader cannot check by looking.
CONTENT_FREE = (
    " ", "  ", "   ", " " * 4, " " * 100,
    "\t", "\v", "\f", "\n", "\r", "\r\n", "\n\n", " \n ", "\t\n\r ",
    "\u00a0", "\u00a0 ", "\u2007", "\u202f", "\u3000", "\ufeff",
)


class IndeterminateProbe(RuntimeError):
    """A content-free fixture neither matched nor completed."""


def fires_on_nothing(rule) -> str:
    """The content-free fixture this rule matches, or an empty string.

    ``ATR-2026-02010`` is the case this exists for. It looks for a string made
    entirely of emoji and invisible characters, which is a real attack shape,
    but ``\\s`` inside its class means every blank leaf matches it too. Measured
    over joined tool results it looked quiet, because a whole result is rarely
    blank; when scanned as a nonempty whitespace-only leaf, it matches. These
    fixtures do not establish how often such leaves occur in deployed tool
    responses, and nothing in this repository measures that.

    An incomplete scan raises rather than reading as a quiet one. To a caller
    that only checks ``findings`` the two are the same value, and a rule
    leaving here unflagged is supposed to mean it was tested.
    """
    for probe in CONTENT_FREE:
        found = scan_trusted(probe, [rule], max_bytes=len(probe.encode("utf-8")))
        if not found.complete or found.rules_evaluated != 1:
            raise IndeterminateProbe(
                f"{rule.id}: fixture {probe!r} evaluated {found.rules_evaluated} of "
                f"1 rules, complete={found.complete}")
        if found.findings:
            return repr(probe)
    return ""


def select(rules, surfaces, drop=None):
    """Return the rules that travel, and one counted reason per rule that does not."""
    keep, dropped = [], Counter()
    refusals: dict[str, str] = {}
    drop = drop or {}
    shippable = {rule.id for rule in default_bundle(rules)}
    for rule in rules:
        if rule.surface.value not in surfaces:
            dropped["surface:" + rule.surface.value] += 1
        elif not rule.runnable:
            dropped["not_runnable"] += 1
        elif rule.id not in shippable:
            dropped["not_shippable"] += 1
        elif rule.id in drop:
            dropped["measured_loud"] += 1
        elif (reason := screened(rule)):
            dropped["screen_refused"] += 1
            refusals[rule.id] = reason
        elif (probe := fires_on_nothing(rule)):
            dropped["fires_on_content_free_leaf"] += 1
            refusals[rule.id] = f"matches a leaf holding only {probe}"
        else:
            keep.append(rule)
    return keep, dict(dropped), refusals


def trim(rules):
    """Replace each rule's sample text with the result of checking it.

    ``SAMPLES.md`` rule 3: ship whether a rule matched its own positive
    examples, how many, and the digest of each, so a consumer can re-run the
    check against the pinned source without anyone redistributing the payload.
    The examples are read here, from the archive this build already has, and
    they do not travel.

    Matching is unaffected: the predicate is untouched, so a rule trims to the
    same behaviour. Only ``rule_fingerprint`` moves, which is why a bundle must
    be measured after trimming rather than before.
    """
    checked = bench.reachability(rules)
    out = []
    for rule in rules:
        found = checked.get(rule.id, {})
        extra = {key: value for key, value in dict(rule.extra).items() if key not in STRIPPED_EXTRA}
        extra["reachability"] = {
            "status": found.get("status", "unknown"),
            "examples": found.get("trials", 0),
            "matched": found.get("hits", 0),
            "example_sha256": [hashlib.sha256(text.encode("utf-8")).hexdigest()
                               for text in rule.examples_positive],
            "checked_by": "scripts/build_bundle.py via agent_defs.bench.reachability",
        }
        out.append(replace(rule, examples_positive=(), examples_negative=(), extra=extra))
    return out, Counter(row["status"] for row in checked.values())


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--archive", type=Path, required=True,
                        help="the pinned source archive, verified against the lock")
    parser.add_argument("--lock", type=Path, default=Path("sources.lock"))
    parser.add_argument("--source", default="atr")
    parser.add_argument("--surface", action="append", default=None,
                        help="repeatable; defaults to OUT and IN")
    parser.add_argument("--drop", type=Path, default=None,
                        help="JSON mapping rule id to the reason it is held back, "
                             "carried into the bundle so the omission is visible")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    surfaces = tuple(args.surface or ("OUT", "IN"))
    drop = json.loads(args.drop.read_text(encoding="utf-8")) if args.drop else {}

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

    keep, dropped, refusals = select(loaded.rules, surfaces, drop)
    if not keep:
        raise SystemExit("every rule was filtered out; refusing to write an empty bundle")
    keep, reach = trim(keep)
    size = bundle.write(
        args.out, keep,
        reachability=dict(reach), stripped_fields=list(STRIPPED_FIELDS),
        stripped_extra=list(STRIPPED_EXTRA),
        # A build host has no scanner, so rule 5 is answered separately and
        # keyed by digest. scripts/artifact-scan.json is that record; a rebuild
        # changes the digest and leaves the old record obviously stale rather
        # than quietly attached to bytes nobody scanned.
        scanner_self_check="see scripts/artifact-scan.json, matched by sha256 of this file",
        source=args.source, source_rev=pin["commit"],
        archive_sha256=pin["archive_sha256"], license_spdx=pin["license_spdx"],
        upstream_url=pin["repo_url"],
        built_at=datetime.now(timezone.utc).isoformat(),
        surfaces=list(surfaces), rule_files=len(manifest),
        loaded=len(loaded.rules), shipped=len(keep), dropped=dropped,
        held_back=drop, screen_refusals=refusals)
    print(f"{args.out}: {len(keep)} of {len(loaded.rules)} rules, {size} bytes")
    for reason, count in sorted(dropped.items(), key=lambda row: -row[1]):
        print(f"  dropped {count:5d}  {reason}")
    print("  by surface " + json.dumps(dict(Counter(r.surface.value for r in keep))))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
