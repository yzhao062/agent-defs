"""Fetch pinned public traces and record schemas, hashes and HTTP evidence."""
from __future__ import annotations

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

import pyarrow.parquet as pq
import requests

LAB_REV = "7256bbf77e76d5cb83f4ddbd5ad31d8faee9dc7a"
COMMONS_REV = "112ebd4d03ce852b00e935d523107c3d0c9a65bf"


def fetch(url, path):
    response = requests.get(url, timeout=120)
    entry = dict(url=url, status=response.status_code,
                 observed_at=datetime.now(timezone.utc).isoformat())
    response.raise_for_status()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(response.content)
    entry.update(bytes=len(response.content), sha256=hashlib.sha256(response.content).hexdigest())
    return entry


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    root = args.out
    ledger = []
    for kind in ("tool_calls", "rounds"):
        path = root / f"tracelab-{kind}.parquet"
        ledger.append(fetch(f"https://huggingface.co/datasets/UW-SyFI/TraceLab/resolve/{LAB_REV}/data/v0.0.2/{kind}/train.parquet", path))
        (root / "http-ledger.json").write_text(json.dumps(ledger, indent=2), encoding="utf-8")
        table = pq.read_table(path)
        info = {"rows": table.num_rows, "schema": str(table.schema)}
        if kind == "tool_calls":
            info["tool_counts"] = dict(Counter(table["tool_name"].to_pylist()))
            info["first_row"] = table.slice(0, 1).to_pylist()
        (root / f"tracelab-{kind}-inventory.json").write_text(json.dumps(info, indent=2, default=str), encoding="utf-8")
        print(kind, json.dumps(info, default=str), flush=True)
    url = f"https://huggingface.co/api/datasets/trace-commons/agent-traces/tree/{COMMONS_REV}?recursive=true&limit=1000"
    ledger.append(fetch(url, root / "commons-tree.json"))
    tree = json.loads((root / "commons-tree.json").read_text())
    paths = [r["path"] for r in tree if r["path"].startswith("sessions/claude_code/") and r["path"].endswith(".jsonl")]
    def get(path):
        return fetch(f"https://huggingface.co/datasets/trace-commons/agent-traces/resolve/{COMMONS_REV}/{path}", root / "commons" / Path(path).name)
    with ThreadPoolExecutor(max_workers=4) as executor:
        ledger.extend(executor.map(get, paths))
    (root / "http-ledger.json").write_text(json.dumps(ledger, indent=2), encoding="utf-8")
    print("commons files", len(paths), flush=True)


if __name__ == "__main__":
    main()
