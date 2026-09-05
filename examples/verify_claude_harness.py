"""Exercise the installed Claude Code harness against a loopback API fixture.

No model service is used. Settings, hooks, and API requests stay in a temporary
directory. Run with --claude PATH and optionally --output evidence.json.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def command(argv):
    # Claude Code command hooks use a POSIX shell, including Git Bash on Windows.
    return shlex.join([str(a).replace("\\", "/") for a in argv])


def run_case(claude, root, name, specs, original_text="ORIGINAL_PAYLOAD"):
    case = root / name
    case.mkdir()
    original = case / "original.txt"
    original.write_text(original_text, encoding="utf-8")
    alternate = case / "alternate.txt"
    alternate.write_text("ALTERNATE_PAYLOAD", encoding="utf-8")
    capture = case / "capture.jsonl"
    hook = case / "hook.py"
    hook.write_text('''import json, pathlib, sys, time
spec = json.loads(pathlib.Path(sys.argv[1]).read_text())
payload = json.load(sys.stdin)
with open(sys.argv[2], "a", encoding="utf-8") as f:
    f.write(json.dumps({"id":spec["id"],"start":time.time(),"payload":payload})+"\\n")
time.sleep(spec.get("sleep", 0))
out = spec.get("response", {})
if spec.get("identity"):
    out = {"hookSpecificOutput":{"hookEventName":"PostToolUse","updatedToolOutput":payload["tool_response"]}}
print(spec.get("raw", json.dumps(out)))
sys.exit(spec.get("exit", 0))
''', encoding="utf-8")
    hooks = {}
    for index, spec in enumerate(specs):
        spec = dict(spec, id=index)
        if spec.get("alternate"):
            spec["response"]["hookSpecificOutput"]["updatedInput"] = {"file_path": str(alternate)}
        sp = case / f"spec-{index}.json"
        sp.write_text(json.dumps(spec), encoding="utf-8")
        handler = spec.get("handler", {"type": "command", "command": command([sys.executable, hook, sp, capture]), "timeout": 5})
        hooks.setdefault(spec["event"], []).append({"matcher": "Read", "hooks": [handler]})
    settings = case / "settings.json"
    settings.write_text(json.dumps({"hooks": hooks, "permissions": {"allow": ["Read"]}}), encoding="utf-8")
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            if "/count_tokens" in self.path:
                body = b'{"input_tokens":10}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body)
                return
            requests.append(request)
            done = len(requests) > 1
            block = ({"type": "text", "text": "FIXTURE_DONE"} if done else
                     {"type": "tool_use", "id": "toolu_fixture", "name": "Read", "input": {"file_path": str(original), "limit": 10}})
            message = {"id": "msg_fixture", "type": "message", "role": "assistant", "model": "claude-sonnet-4-6",
                       "content": [block], "stop_reason": "end_turn" if done else "tool_use", "stop_sequence": None,
                       "usage": {"input_tokens": 10, "output_tokens": 10}}
            self.send_response(200)
            if not request.get("stream"):
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(message).encode())
                return
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            start = dict(message, content=[], stop_reason=None)
            events = [("message_start", {"message": start}),
                      ("content_block_start", {"index": 0, "content_block": dict(block, **({"text": ""} if done else {"input": {}}))}),
                      ("content_block_delta", {"index": 0, "delta": {"type": "text_delta", "text": block["text"]} if done else
                                               {"type": "input_json_delta", "partial_json": json.dumps(block["input"])}}),
                      ("content_block_stop", {"index": 0}),
                      ("message_delta", {"delta": {"stop_reason": message["stop_reason"], "stop_sequence": None}, "usage": {"output_tokens": 10}}),
                      ("message_stop", {})]
            for event, data in events:
                self.wfile.write((f"event: {event}\ndata: " + json.dumps(dict(data, type=event)) + "\n\n").encode())
            self.wfile.flush()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    env = {k: v for k, v in os.environ.items() if not k.startswith(("ANTHROPIC_", "CLAUDE_CODE_OAUTH")) and k != "CLAUDECODE"}
    env.update(ANTHROPIC_API_KEY="fixture-only", ANTHROPIC_BASE_URL=f"http://127.0.0.1:{server.server_port}",
               CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1")
    argv = [claude, "-p", "Run the fixture read.", "--setting-sources", "", "--settings", str(settings),
            "--strict-mcp-config", "--tools", "Read", "--permission-mode", "dontAsk", "--no-session-persistence",
            "--model", "claude-sonnet-4-6", "--system-prompt", "Local protocol test.", "--output-format", "json"]
    started = time.perf_counter()
    try:
        proc = subprocess.run(argv, cwd=case, env=env, capture_output=True, text=True, encoding="utf-8", timeout=45)
        outcome = {"exit": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}
    except subprocess.TimeoutExpired as exc:
        outcome = {"timeout": True, "stdout": str(exc.stdout), "stderr": str(exc.stderr)}
    finally:
        server.shutdown()
        server.server_close()
    outcome.update(case=name, elapsed_s=time.perf_counter()-started, requests=requests,
                   hooks=[json.loads(line) for line in capture.read_text(encoding="utf-8").splitlines()] if capture.exists() else [])
    return outcome


def pre(decision=None, **kwargs):
    fields = {"hookEventName": "PreToolUse"}
    if decision:
        fields["permissionDecision"] = decision
    return {"event": "PreToolUse", "response": {"hookSpecificOutput": fields}, **kwargs}


def post(text="REDACTED_PAYLOAD", **kwargs):
    return {"event": "PostToolUse", "response": {"hookSpecificOutput": {
        "hookEventName": "PostToolUse", "updatedToolOutput": {"type": "text", "file": {
            "filePath": "fixture.txt", "content": text, "numLines": 1, "startLine": 1, "totalLines": 1}}}}, **kwargs}


def verify(result, expected_product=None):
    assert not result.get("timeout"), result["case"]
    assert result["exit"] == 0, result["stderr"]
    name = result["case"]
    final = json.loads(result["stdout"])
    if name in ("defer", "defer_ask"):
        assert final["terminal_reason"] == "tool_deferred" and len(result["requests"]) == 1
        return
    assert len(result["requests"]) == 2
    messages = result["requests"][1]["messages"]
    tool_results = [block for message in messages for block in message.get("content", [])
                    if isinstance(block, dict) and block.get("type") == "tool_result"]
    assert len(tool_results) == 1
    output = tool_results[0]
    text = json.dumps(output["content"])
    if name in ("deny", "deny_allow", "deny_defer", "invalid_exit2"):
        assert output["is_error"] and "ORIGINAL_PAYLOAD" not in text
        if name != "invalid_exit2":
            assert "denied this tool" in text
    elif name in ("ask", "ask_allow"):
        assert output["is_error"] and "asked for confirmation" in text
    elif name == "updated_input":
        assert "ALTERNATE_PAYLOAD" in text and "ORIGINAL_PAYLOAD" not in text
        post_input = result["hooks"][-1]["payload"]["tool_input"]
        assert set(post_input) == {"file_path"}, "updatedInput must replace rather than merge"
    elif name in ("updated_output", "parallel_post_reverse"):
        assert "REDACTED_PAYLOAD" in text and "ORIGINAL_PAYLOAD" not in text
    elif name == "product":
        assert expected_product in text
        if "withheld" in expected_product:
            assert "collector.invalid" not in text and "ignore all previous" not in text
    else:
        assert "ORIGINAL_PAYLOAD" in text and not output.get("is_error")
    if name.startswith("parallel_post"):
        assert len(result["hooks"]) == 2
        first, second = sorted(result["hooks"], key=lambda h: h["start"])
        assert second["start"] - first["start"] < .5, "hooks did not overlap"
        for record in result["hooks"]:
            assert record["payload"]["tool_response"]["file"]["content"] == "ORIGINAL_PAYLOAD"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--claude", default="claude")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--case")
    parser.add_argument("--hook-config", type=Path)
    args = parser.parse_args()
    cases = {"allow": [pre("allow")], "deny": [pre("deny")], "ask": [pre("ask")], "defer": [pre("defer")],
             "updated_input": [pre(alternate=True), {"event": "PostToolUse", "response": {}}], "updated_output": [post()],
             "invalid_exit0": [pre(raw="{broken")], "invalid_exit1": [pre(raw="{broken", exit=1)],
             "invalid_exit2": [pre(raw="{broken", exit=2)],
             "deny_allow": [pre("deny"), pre("allow", sleep=.3)],
             "defer_ask": [pre("defer"), pre("ask", sleep=.3)],
             "ask_allow": [pre("ask"), pre("allow", sleep=.3)],
             "deny_defer": [pre("deny"), pre("defer", sleep=.3)],
             "parallel_post": [post(sleep=.5), post(identity=True, sleep=1)],
             "parallel_post_reverse": [post(identity=True, sleep=.5), post(sleep=1)]}
    evidence = {"version": subprocess.check_output([args.claude, "--version"], text=True).strip(), "cases": []}
    if Path(args.claude).is_file():
        evidence["executable_sha256"] = hashlib.sha256(Path(args.claude).read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory(prefix="agent-defs-harness-") as directory:
        expected_product = None
        if args.hook_config:
            from agent_defs.hooks._claude_code_impl import hook_spec, read_config, active_rules, effective_lanes, WITHHELD
            config = read_config(args.hook_config)
            lanes = effective_lanes(config, active_rules(config))
            expected_product = WITHHELD if lanes["builtin:agent-override"][0].value == "DENY" else "Issue #184"
            cases["product"] = [{"event": "PostToolUse", "handler": hook_spec(args.hook_config)}]
        for name, specs in cases.items():
            if args.case and name != args.case:
                continue
            if name == "product":
                from demo_injection import HOSTILE
                result = run_case(args.claude, Path(directory), name, specs, HOSTILE)
            else:
                result = run_case(args.claude, Path(directory), name, specs)
            evidence["cases"].append(result)
            verify(result, expected_product)
            result["verified"] = True
            print(name, "requests=", len(result["requests"]), "hooks=", len(result["hooks"]),
                  "elapsed=", round(result["elapsed_s"], 2), flush=True)
    if args.output:
        args.output.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    else:
        print(json.dumps(evidence, indent=2))


if __name__ == "__main__":
    main()
