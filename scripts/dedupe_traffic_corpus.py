"""Collapse exact duplicate tool-result text and record its multiplicity.

The output holds one row per distinct payload. That removes repeated text. It
does not establish independent observations, and it does not preserve the
frequency distribution of tool invocations: repeated text can come from
separate calls, and different results from one session can stay dependent.
Collapsing changes the population from invocations to distinct payloads, and
an unweighted rate over the result is not automatically a rate for a session's
traffic.

``bench`` refuses a corpus that repeats material, and it is right to. This
script exists so a corpus can satisfy that refusal, not so a bound can be
claimed over units it does not describe.
"""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--out-name", default=None,
                        help="written as <out-name>-units.jsonl (default: <name>-unique)")
    args = parser.parse_args(argv)
    out_name = args.out_name or f"{args.name}-unique"

    inventory = json.loads((args.evidence / f"{args.name}-inventory.json").read_text(encoding="utf-8"))
    raw = (args.evidence / f"{args.name}-units.jsonl").read_bytes()
    if hashlib.sha256(raw).hexdigest() != inventory["units_sha256"]:
        raise SystemExit(f"{args.name}: snapshot digest differs from its inventory")

    kept, folded, seen = [], Counter(), {}
    for line in raw.splitlines():
        row = json.loads(line)
        key = row.get("sha256") or hashlib.sha256(row["text"].encode("utf-8")).hexdigest()
        if key in seen:
            folded[key] += 1
            continue
        seen[key] = len(kept)
        kept.append(row)

    for row in kept:
        key = row.get("sha256") or hashlib.sha256(row["text"].encode("utf-8")).hexdigest()
        row["occurrences"] = 1 + folded.get(key, 0)

    body = "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in kept).encode("utf-8")
    (args.evidence / f"{out_name}-units.jsonl").write_bytes(body)
    out = dict(inventory)
    out.update(units_sha256=hashlib.sha256(body).hexdigest(), units=len(kept),
               collapsed_from=len(raw.splitlines()), duplicates_folded=sum(folded.values()),
               derived_from=args.name, derived_by="scripts/dedupe_traffic_corpus.py")
    (args.evidence / f"{out_name}-inventory.json").write_text(
        json.dumps(out, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")

    strata = Counter(row["strata"].get("exposure") for row in kept)
    print(f"{out_name}: {len(kept)} unique of {len(raw.splitlines())} "
          f"({sum(folded.values())} folded)")
    print("  exposure " + json.dumps(dict(strata), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
