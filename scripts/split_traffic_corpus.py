"""Split a traffic corpus into a selection half and a held-out half.

Choosing which rules to ship by watching which ones fire, and then quoting a
bound from the same material, states a number the selection already
guaranteed. The held-out half is never consulted while choosing, so its bound
is the first one that is not circular in that specific way.

It buys less than it looks like. The split is by payload digest, so one
session lands on both sides of the boundary and known groups are not kept
together. A payload split does not make the observations within either half
independent, and no code here can establish that the rule set and the
admission criterion were fixed before anyone looked at the held-out outcome.
Splitting by session or task would at least stop groups from crossing.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def half(digest: str, salt: str) -> int:
    return hashlib.sha256((salt + ":" + digest).encode()).digest()[0] % 2


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--salt", default="agent-defs-split-v1",
                        help="changing this reshuffles the split; record it if you do")
    args = parser.parse_args(argv)

    inventory = json.loads((args.evidence / f"{args.name}-inventory.json").read_text(encoding="utf-8"))
    raw = (args.evidence / f"{args.name}-units.jsonl").read_bytes()
    if hashlib.sha256(raw).hexdigest() != inventory["units_sha256"]:
        raise SystemExit(f"{args.name}: snapshot digest differs from its inventory")

    parts: dict[str, list] = {"select": [], "holdout": []}
    for line in raw.splitlines():
        row = json.loads(line)
        key = row.get("sha256") or hashlib.sha256(row["text"].encode("utf-8")).hexdigest()
        parts["select" if half(key, args.salt) == 0 else "holdout"].append(row)

    for part, rows in parts.items():
        if not rows:
            raise SystemExit(f"{args.name}: the {part} half is empty")
        out_name = f"{args.name}-{part}"
        body = "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows).encode("utf-8")
        (args.evidence / f"{out_name}-units.jsonl").write_bytes(body)
        out = dict(inventory)
        out.update(units_sha256=hashlib.sha256(body).hexdigest(), units=len(rows),
                   derived_from=args.name, derived_by="scripts/split_traffic_corpus.py",
                   split_half=part, split_salt=args.salt)
        (args.evidence / f"{out_name}-inventory.json").write_text(
            json.dumps(out, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
        print(f"{out_name}: {len(rows)} units")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
