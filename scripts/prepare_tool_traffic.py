"""Extract complete top-level Claude tool exchanges; never execute trace content."""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re

COMMONS_REV = "112ebd4d03ce852b00e935d523107c3d0c9a65bf"


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def text_content(content):
    if isinstance(content, str):
        return content, "string"
    if isinstance(content, list) and all(isinstance(b, dict) and b.get("type") == "text"
                                         and isinstance(b.get("text"), str) for b in content):
        return "\n".join(b["text"] for b in content), "text-blocks"
    return None, "nontext-content"


def exposure(name, arguments):
    command = arguments.get("command", "") if isinstance(arguments, dict) else ""
    if name in {"WebFetch", "WebSearch"}:
        return "attacker-reachable"
    if name in {"Bash", "PowerShell"}:
        if re.search(r"\b(curl|wget|Invoke-WebRequest|Invoke-RestMethod)\b|\bgh\s+(api|issue|pr)\b|requests\.(get|post)|urllib\.request|https?://", command, re.I):
            return "network-command-mixed"
        if re.search(r"\b(cat|type|Get-Content|head|tail|sed|grep|rg)\b|read_text|read_bytes|open\(", command, re.I):
            return "file-origin-unknown"
        return "locally-generated"
    if name in {"Read", "Grep", "Edit", "MultiEdit", "Skill"}:
        return "file-origin-unknown"
    if name in {"Glob", "LS", "Write", "NotebookEdit", "TodoWrite", "TaskCreate", "TaskUpdate",
                "TaskList", "TaskGet", "TaskStop", "AskUserQuestion", "EnterPlanMode", "ExitPlanMode",
                "KillBash", "KillShell", "ToolSearch"}:
        return "locally-generated"
    if name.startswith("mcp__"):
        return "external-tool-unknown"
    return "mixed-or-unknown"


def parse_files(paths, root):
    stats = Counter()
    tools = Counter()
    results = []
    ledger = []
    for path in paths:
        raw = path.read_bytes()
        file_id = digest(path.relative_to(root).as_posix().encode())[:20]
        ledger.append({"file_id": file_id, "sha256": digest(raw), "bytes": len(raw)})
        calls, returned, ambiguous = {}, {}, set()
        for line in raw.splitlines():
            try:
                record = json.loads(line)
            except (ValueError, UnicodeError):
                stats["malformed_lines"] += 1
                continue
            blocks = record.get("message", {}).get("content", [])
            if not isinstance(blocks, list):
                continue
            for block in blocks:
                if not isinstance(block, dict):
                    continue
                if record.get("type") == "assistant" and block.get("type") == "tool_use":
                    key = (record.get("sessionId", file_id), block["id"])
                    if key in calls:
                        stats["duplicate_invocation_records"] += 1
                        if calls[key] != block:
                            ambiguous.add(key)
                    else:
                        calls[key] = block
                        tools[block["name"]] += 1
                if record.get("type") == "user" and block.get("type") == "tool_result":
                    key = (record.get("sessionId", file_id), block["tool_use_id"])
                    stats["result_records"] += 1
                    if key in returned:
                        stats["duplicate_result_records"] += 1
                        if returned[key] != block:
                            ambiguous.add(key)
                    else:
                        returned[key] = block
        stats["calls"] += len(calls)
        stats["files_with_calls"] += bool(calls)
        stats["calls_without_result"] += len(calls.keys() - returned.keys())
        stats["orphan_results"] += len(returned.keys() - calls.keys())
        for key in calls.keys() & returned.keys():
            if key in ambiguous:
                stats["ambiguous_exchanges"] += 1
                continue
            call, result = calls[key], returned[key]
            payload, encoding = text_content(result.get("content"))
            stats[encoding] += 1
            if payload is None:
                continue
            try:
                payload_bytes = payload.encode("utf-8")
            except UnicodeError:
                stats["invalid_unicode"] += 1
                continue
            if len(payload_bytes) > 4 * 1024 * 1024:
                stats["over_evaluator_4MiB"] += 1
                continue
            identifier = file_id + "/" + digest((key[0] + "/" + key[1]).encode())[:20]
            args = call.get("input", {})
            origin = exposure(call["name"], args)
            # This labels content topic, not whether a result is malicious.
            topic = "security-adjacent" if re.search(r"\b(security|vulnerabilit\w*|malware|prompt injection|penetration|exploit\w*)\b", payload, re.I) else "ordinary"
            strata = {"file_type": "tool-result", "prose": topic, "tool": call["name"],
                      "exposure": origin, "result_status": "error" if result.get("is_error") else "success"}
            results.append({"id": identifier, "text": payload, "sha256": digest(payload_bytes),
                            "size_bytes": len(payload_bytes), "surface": "OUT", "strata": strata,
                            "invocation": json.dumps({"name": call["name"], "arguments": args}, ensure_ascii=False, separators=(",", ":"))})
    stats["files_parsed"] = len(paths)
    stats["eligible_results"] = len(results)
    return results, {"counts": dict(stats), "tools": dict(tools), "files": ledger}


def quantiles(values):
    values = sorted(values)
    return {"count": len(values), "total": sum(values),
            **{label: values[round((len(values)-1)*q)] if values else None
               for label, q in [("min", 0), ("p25", .25), ("p50", .5), ("p75", .75), ("p90", .9), ("p95", .95), ("p99", .99), ("max", 1)]}}


def save(root, name, revision, results, inventory):
    results.sort(key=lambda row: row["id"])
    raw = "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in results).encode("utf-8")
    (root / f"{name}-units.jsonl").write_bytes(raw)
    inventory.update(identity=name, revision=revision or "sha256:" + digest(raw),
                     units_sha256=digest(raw), snapshot_at=datetime.now(timezone.utc).isoformat(),
                     selected_results=len(results), sizes=quantiles([r["size_bytes"] for r in results]),
                     selected_tools=dict(Counter(r["strata"]["tool"] for r in results)),
                     selected_files=len({r["id"].split("/")[0] for r in results}),
                     exposure={k: quantiles([r["size_bytes"] for r in results if r["strata"]["exposure"] == k])
                               for k in sorted({r["strata"]["exposure"] for r in results})})
    (root / f"{name}-inventory.json").write_text(json.dumps(inventory, indent=2), encoding="utf-8")
    print(name, json.dumps({k: v for k, v in inventory.items() if k not in {"files", "tools", "selected_tools"}}), flush=True)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--local-root", type=Path)
    p.add_argument("--local-files", type=int, default=120)
    p.add_argument("--local-results", type=int, default=4000)
    args = p.parse_args()
    commons = args.out / "commons"
    results, inventory = parse_files(sorted(commons.glob("*.jsonl")), commons)
    save(args.out, "trace-commons", COMMONS_REV, results, inventory)
    if args.local_root:
        paths = list(args.local_root.rglob("*.jsonl"))
        eligible = [p for p in paths if not any(s in p.relative_to(args.local_root).parts[0]
                                              for s in ("agent-startup-thesis", "agent-defs", "agent-config"))]
        eligible.sort(key=lambda path: digest(("r1-build2-v1/" + path.relative_to(args.local_root).as_posix()).encode()))
        results, inventory = parse_files(eligible[:args.local_files], args.local_root)
        results.sort(key=lambda row: digest(("r1-build2-units-v1/" + row["id"]).encode()))
        inventory.update(discovered_files=len(paths), eligible_files=len(eligible),
                         selection="lowest SHA256 of r1-build2-v1/relative-path, then lowest SHA256 of r1-build2-units-v1/unit-id",
                         excluded_projects=["agent-startup-thesis", "agent-defs", "agent-config"],
                         requested_files=args.local_files, requested_results=args.local_results)
        save(args.out, "local-claude", None, results[:args.local_results], inventory)


if __name__ == "__main__":
    main()
