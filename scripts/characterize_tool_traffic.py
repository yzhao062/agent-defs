"""Supplementary provenance/representation counts; contains no result excerpts."""
import argparse
from collections import Counter
import json
from pathlib import Path

import pyarrow.parquet as pq
from prepare_tool_traffic import digest, quantiles


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--evidence", type=Path, required=True)
    args = p.parse_args()
    root = args.evidence
    tools = pq.read_table(root / "tracelab-tool_calls.parquet").to_pylist()
    rounds = pq.read_table(root / "tracelab-rounds.parquet", columns=["round_pk", "provider", "session_id"]).to_pylist()
    identities = {r["round_pk"]: (r["provider"], r["session_id"]) for r in rounds}
    keys = [identities[r["round_pk"]] + (r["tool_call_id"],) for r in tools]
    native = {"Bash", "PowerShell", "Read", "Write", "Edit", "MultiEdit", "NotebookEdit", "Grep", "Glob", "LS",
              "shell", "bash", "shell_command", "exec_command", "apply_patch", "write_stdin", "view_image",
              "BashOutput", "KillBash", "KillShell"}
    lab = {"round_rows": len(rounds), "tool_rows": len(tools), "duplicate_call_ids": len(keys)-len(set(keys)),
           "provider_counts": dict(Counter(key[0] for key in keys)),
           "sessions": len({key[:2] for key in keys}),
           "native_shell_file_calls": sum(r["tool_name"] in native for r in tools),
           "explicit_web_calls": sum(r["tool_name"] in {"WebFetch", "WebSearch"} for r in tools),
           "null_result_chars": sum(r["result_chars"] is None for r in tools),
           "result_chars": quantiles([r["result_chars"] for r in tools if r["result_chars"] is not None]),
           "scannable_result_texts": 0,
           "result_bytes": "unavailable: source publishes character counts without result text"}
    result = {"tracelab": lab}
    for name in ("trace-commons", "local-claude"):
        rows = [json.loads(line) for line in (root / f"{name}-units.jsonl").read_text(encoding="utf-8").splitlines()]
        type_counts = Counter()
        if name == "trace-commons":
            for path in (root / "commons").glob("*.jsonl"):
                for line in path.read_bytes().splitlines():
                    record = json.loads(line)
                    if record.get("type") != "user":
                        continue
                    blocks = record.get("message", {}).get("content", [])
                    if isinstance(blocks, list):
                        for b in blocks:
                            if isinstance(b, dict) and b.get("type") == "tool_result" and isinstance(b.get("content"), list):
                                type_counts["+".join(sorted({str(x.get("type")) for x in b["content"] if isinstance(x, dict)}))] += 1
        result[name] = {
            "block_type_combinations": dict(type_counts),
            "persisted_output_previews": sum("<persisted-output>" in r["text"] for r in rows),
            "truncation_marker_results": sum(any(marker in r["text"] for marker in
                ("<persisted-output>", "output truncated", "Output truncated", "characters truncated", "content truncated")) for r in rows),
            "empty_outputs": sum(not r["text"] for r in rows),
            "duplicate_result_payloads": len(rows) - len({r["sha256"] for r in rows}),
            "web_tools": dict(Counter(r["strata"]["tool"] for r in rows if r["strata"]["exposure"] == "attacker-reachable")),
            "web_status": dict(Counter(r["strata"]["result_status"] for r in rows if r["strata"]["exposure"] == "attacker-reachable")),
            "web_sessions": len({r["id"].split("/")[0] for r in rows if r["strata"]["exposure"] == "attacker-reachable"}),
            "mcp_tools": dict(Counter(r["strata"]["tool"] for r in rows if r["strata"]["tool"].startswith("mcp__"))),
        }
    (root / "characterization.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
