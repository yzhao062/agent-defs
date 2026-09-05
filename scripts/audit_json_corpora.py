"""Reproduce the three JSON loader deltas without vendoring corpus records.

Example (PowerShell, with PYTHONPATH=src):
    python scripts/audit_json_corpora.py --aak AAK_ROOT --ave AVE_ROOT \
        --guardana GUARDANA_ROOT --output reports/json-loaders --verify-http

HTTP verification checks every input document against its pinned raw GitHub
object. The adapters themselves never use the network or run upstream code.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from agent_defs.loaders import agent_audit_kit, ave, guardana


def _verify(item):
    url, expected = item
    with urllib.request.urlopen(url, timeout=30) as response:
        digest = hashlib.sha256(response.read()).hexdigest()
        if digest != expected:
            raise ValueError(f"Pinned upstream bytes differ from the local Git object: {url}")
        return {"url": url, "http_status": response.status,
                "checked_at": datetime.now(timezone.utc).date().isoformat(),
                "sha256": digest, "matches_git_object": True}


def audit(module, root: Path, verify_http: bool) -> dict:
    rev = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    if rev != module.REVIEWED_REV:
        raise ValueError(f"{root}: expected reviewed revision {module.REVIEWED_REV}, got {rev}")
    rules, delta = module.load(root, source_rev=rev)
    for path, entry in delta["documents"].items():
        git_bytes = subprocess.check_output(["git", "-C", str(root), "show", f"{rev}:{path}"])
        local_bytes = (root / path).read_bytes()
        if local_bytes != git_bytes and local_bytes.replace(b"\r\n", b"\n") != git_bytes:
            raise ValueError(f"{root / path}: local content differs from the pinned Git object")
        entry["git_sha256"] = hashlib.sha256(git_bytes).hexdigest()
        entry["checkout_crlf_only"] = local_bytes != git_bytes
    delta["input_field_counts"] = dict(sorted(Counter(key for rule in rules for key in rule.extra["upstream"]).items()))
    delta["severity_raw_counts"] = dict(sorted(Counter(rule.severity_raw for rule in rules).items()))
    delta["maturity_raw_counts"] = dict(sorted(Counter(rule.maturity_raw for rule in rules).items()))
    delta["lane_counts"] = dict(sorted(Counter(rule.lane.value for rule in rules).items()))
    delta["lineage_counts"] = dict(sorted(Counter(item.kind for rule in rules for item in rule.lineage).items()))
    delta["pattern_rejections"] = [{"source_id": rule.source_id, **item} for rule in rules
                                   for item in rule.extra["pattern_screen"] if item["status"] == "rejected"]
    delta["pattern_warnings"] = [{"source_id": rule.source_id, **item} for rule in rules
                                 for item in rule.extra["pattern_screen"] if "warnings" in item]
    if module is ave:
        delta["status_raw_counts"] = dict(sorted(Counter(rule.extra["upstream"]["status"] for rule in rules).items()))
        delta["confidence_baseline_counts"] = [
            {"value": value, "count": count} for value, count in
            sorted(Counter(rule.extra["confidence_baseline"] for rule in rules).items())]
        delta["records_with_crosswalks"] = sum(bool(rule.extra["crosswalks"]) for rule in rules)
    if verify_http:
        raw_root = module.REPOSITORY.replace("https://github.com/", "https://raw.githubusercontent.com/")
        items = [(f"{raw_root}/{rev}/{path}", entry["git_sha256"]) for path, entry in delta["documents"].items()]
        with ThreadPoolExecutor(max_workers=8) as pool:
            delta["http_evidence"] = list(pool.map(_verify, items))
    # The returned loader delta retains full document metadata. Published audit
    # reports contain only field names and digests, avoiding corpus redistribution.
    delta["documents"] = {path: {"sha256": entry["sha256"],
                                "git_sha256": entry["git_sha256"],
                                "checkout_crlf_only": entry["checkout_crlf_only"],
                                "metadata_fields": sorted(entry["metadata"])}
                          for path, entry in delta["documents"].items()}
    return delta


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--aak", type=Path, required=True)
    parser.add_argument("--ave", type=Path, required=True)
    parser.add_argument("--guardana", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--verify-http", action="store_true")
    args = parser.parse_args()
    reports = [audit(module, root, args.verify_http) for module, root in
               [(agent_audit_kit, args.aak), (ave, args.ave), (guardana, args.guardana)]]
    args.output.mkdir(parents=True, exist_ok=True)
    for report in reports:
        path = args.output / f"{report['source']}-delta.json"
        path.write_text(json.dumps(report, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
        print(f"{report['source']}: {report['entries_read']} read, {report['emitted']} emitted; {path}")


if __name__ == "__main__":
    main()
