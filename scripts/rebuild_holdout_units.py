"""Rebuild the exact units a measurement ran on, replaying its record.

The evidence directory a measurement writes is a working artifact and does not
survive. Its report does, and the report pins every unit by id and by the
sha256 of its text. This walks the same transcripts, keeps only rows whose id
is on that list, and refuses any row whose digest differs.

That distinction is the point of the file. Re-running the extractor would
re-select from transcripts that have grown since, which would quietly change
which payloads sit in a held-out half after its outcome was read. Replaying the
pinned list cannot: a unit either comes back with the digest the report
recorded, or it is reported absent. A run that recovers fewer than the report
declares has produced a different corpus and says so rather than normalizing.

Usage::

    python scripts/rebuild_holdout_units.py \\
        --report <corpus>-out-report.json \\
        --root ~/.claude/projects \\
        --corpus local-claude-unique-holdout \\
        --out units.jsonl

The output holds tool-result text from the operator's own sessions. It is
working material, not a package asset, and belongs outside the repository.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

from prepare_tool_traffic import parse_files  # noqa: E402

#: The projects the original selection excluded, kept here so a replay walks
#: the same population. A pinned id would not match one of these anyway; this
#: only saves parsing them.
EXCLUDED = ("agent-startup-thesis", "agent-defs", "agent-config")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True,
                        help="the transcript root the original run passed as --local-root")
    parser.add_argument("--corpus", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)

    report = json.loads(args.report.read_text(encoding="utf-8"))
    pinned = {row["id"]: row["sha256"] for row in report["materials"]
              if row["corpus"] == args.corpus}
    if not pinned:
        raise SystemExit(f"{args.report}: no materials for corpus {args.corpus!r}")
    print(f"report sha256: {hashlib.sha256(args.report.read_bytes()).hexdigest()}")
    print(f"pinned units: {len(pinned)}")

    # A unit id is "<digest of the transcript's relative path>/<digest of the
    # exchange>", so the file half selects which transcripts need parsing at
    # all. Everything else on disk is skipped rather than read.
    wanted = {uid.split("/")[0] for uid in pinned}
    paths = [p for p in args.root.rglob("*.jsonl")
             if not any(s in p.relative_to(args.root).parts[0] for s in EXCLUDED)]
    keep = [p for p in paths
            if hashlib.sha256(p.relative_to(args.root).as_posix().encode()).hexdigest()[:20]
            in wanted]
    print(f"transcripts on disk: {len(paths)}; matching a pinned id: {len(keep)} "
          f"of {len(wanted)}")

    rows, _ = parse_files(sorted(keep), args.root)
    by_id = {row["id"]: row for row in rows}
    recovered, mismatched, missing = [], [], []
    for uid, sha in pinned.items():
        row = by_id.get(uid)
        if row is None:
            missing.append(uid)
        elif row["sha256"] != sha:
            mismatched.append(uid)
        else:
            recovered.append(row)
    print(f"recovered: {len(recovered)}; digest mismatch: {len(mismatched)}; "
          f"absent: {len(missing)}")

    recovered.sort(key=lambda row: row["id"])
    raw = "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in recovered)
    args.out.write_bytes(raw.encode("utf-8"))
    print(f"wrote {args.out} ({args.out.stat().st_size} bytes), "
          f"sha256 {hashlib.sha256(raw.encode('utf-8')).hexdigest()}")
    if mismatched or missing:
        print("this is not the corpus the report describes; do not quote a rate from it")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
