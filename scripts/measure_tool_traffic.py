"""Run agent_defs.bench on hash-verified, extracted tool-traffic JSONL.

One snapshot carries both surfaces: each row holds the tool result the hook
sees at PostToolUse and the invocation it sees at PreToolUse. They are separate
corpora because they are separate bodies of material, with separate trial
counts and separate provenance, and a bundle enabling both surfaces has to be
measured on both or bench refuses the whole report.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys
import time

from agent_defs import bench
from agent_defs.model import Surface

sys.path.insert(0, str(Path(__file__).resolve().parent))
from prepare_tool_traffic import prose  # noqa: E402  the one definition of this stratum

REQUIRED_STRATA = ("exposure=attacker-reachable", "exposure=locally-generated")


def leaves(value):
    """Every string a PreToolUse hook would scan in this payload, in order.

    The hook walks the string values of ``tool_input`` and scans each one on its
    own. It never sees the serialization, the object keys, or the tool name, so
    matching the serialized ``{name, arguments}`` envelope is a different
    procedure: JSON quoting and the boundaries it introduces can suppress a
    match that the hook would find, and can supply context it would not have.
    """
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [leaf for item in value.values() for leaf in leaves(item)]
    if isinstance(value, list):
        return [leaf for item in value for leaf in leaves(item)]
    return []


def corpus(root, name, surface):
    """One corpus of material units, for one surface, out of one snapshot.

    An IN unit's material is the invocation, so its strata are the ones that
    describe an invocation. ``exposure`` and ``tool`` already are: both are
    classified from the call name and arguments. ``prose`` is not, because the
    snapshot classified it on the result, so it is reclassified here on the text
    actually being scanned; over the held-out corpus the two labels disagree on
    about a tenth of the units. ``result_status`` is kept as it stands: it is a
    property of the episode rather than of the invocation, and it partitions the
    corpus more finely, which can only make the worst stratum worse.

    Invocations repeat where results do not, because the same call can be made
    twice and return different bytes. The snapshot was deduplicated on the
    result, so the IN side is deduplicated again here on its own material. That
    satisfies bench's distinct-material contract, which is what its refusal is
    about; it is not a claim that repeated bytes would be invalid draws, nor
    that what remains is independent. It narrows the denominator, so it widens
    the interval rather than flattering it.
    """
    metadata = json.loads((root / f"{name}-inventory.json").read_text())
    raw = (root / f"{name}-units.jsonl").read_bytes()
    if hashlib.sha256(raw).hexdigest() != metadata["units_sha256"]:
        raise ValueError("traffic snapshot digest mismatch")
    units, seen, repeats = [], set(), 0
    for line in raw.splitlines():
        row = json.loads(line)
        text = row["text"] if surface is Surface.OUT else row["invocation"]
        encoded = text.encode("utf-8")
        digest = hashlib.sha256(encoded).hexdigest()
        if surface is Surface.OUT and (digest != row["sha256"] or len(encoded) != row["size_bytes"]):
            raise ValueError("tool result digest mismatch")
        if digest in seen:
            repeats += 1
            continue
        seen.add(digest)
        strata = dict(row["strata"])
        strata["file_type"] = "tool-result" if surface is Surface.OUT else "tool-invocation"
        parts = None
        if surface is Surface.IN:
            # The serialization stays as the unit's identity and its dedup key,
            # since one invocation is one trial however many strings it holds.
            # What gets matched is the leaves, because that is what the hook
            # walks. prose reads the leaves too, for the same reason.
            parts = tuple(leaves(json.loads(text).get("arguments")))
            strata["prose"] = prose(chr(10).join(parts))
            encoded = "".join(parts).encode("utf-8")
        units.append(bench.Unit(row["id"], text, surface, strata, digest, len(encoded),
                                parts))
    if surface is Surface.OUT and repeats:
        raise ValueError(f"{name}: {repeats} repeated tool results; the snapshot was already deduplicated")
    identity = name if surface is Surface.OUT else f"{name}-invocations"
    print(f"  {identity}: {len(units)} units, {repeats} repeated {surface.value} material dropped", flush=True)
    return bench.Corpus(identity, metadata["revision"], tuple(units),
                        metadata["units_sha256"], REQUIRED_STRATA)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--evidence", type=Path, required=True)
    p.add_argument("--names", nargs="+", required=True)
    p.add_argument("--surface", action="append", choices=["OUT", "IN"], default=None,
                   help="repeatable; defaults to OUT alone. A bundle enabling both "
                        "surfaces needs both here, in one report")
    p.add_argument("--rules", type=Path, required=True)
    p.add_argument("--workers", type=int, default=4)
    p.add_argument("--budget-s", type=float, default=30.0)
    args = p.parse_args()
    surfaces = tuple(args.surface or ("OUT",))
    rules = bench.load_rules(args.rules)
    corpora = [corpus(args.evidence, name, Surface(s)) for name in args.names for s in surfaces]
    print("start", args.names, "rules", len(rules), "trials", sum(len(c.units) for c in corpora), flush=True)
    started = time.monotonic()
    report = bench.measure(rules, corpora, isolated=True, workers=args.workers, budget_s=args.budget_s)
    report["elapsed_s"] = time.monotonic() - started
    path = args.evidence / ("-".join(args.names) + "-"
                            + "-".join(s.lower() for s in surfaces) + "-report.json")
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print("done", report["summary"], "lanes", Counter(r["lane"] for r in report["rules"].values()),
          "seconds", report["elapsed_s"], flush=True)


if __name__ == "__main__":
    main()
