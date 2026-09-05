"""Verify the installed adapter's shell transport in the local Claude harness."""
from dataclasses import asdict
import json
from pathlib import Path
import subprocess
import tempfile

from agent_defs.builtin import STARTER_RULES
from agent_defs.hooks import _claude_code_impl as hook
from agent_defs.lanes import u95_zero_hits
from agent_defs.model import BenignFiring
from verify_claude_harness import post, run_case


def verify(claude="claude"):
    evidence = {"version": subprocess.check_output([claude, "--version"], text=True).strip(), "cases": []}
    with tempfile.TemporaryDirectory(prefix="agent-defs-safety-") as directory:
        root = Path(directory)
        config_path = root / "config 'quoted'.json"
        config = hook.default_config()
        config["log_path"] = str(root / "findings.jsonl")
        hook.atomic_json(config_path, config)
        original_argv = hook.hook_argv
        try:
            hook.hook_argv = lambda config: [str(root / "missing-python.exe")]
            missing = hook.hook_spec(config_path)
        finally:
            hook.hook_argv = original_argv
        cases = [
            ("missing_interpreter", [{"event": "PreToolUse", "handler": missing}], "ORIGINAL_PAYLOAD", "ORIGINAL_PAYLOAD"),
            ("record_parallel", [post(), {"event": "PostToolUse", "handler": dict(
                hook.hook_spec(config_path), command="sleep 1\n" + hook.hook_spec(config_path)["command"])}],
             "ORIGINAL_PAYLOAD", "REDACTED_PAYLOAD"),
        ]
        for name, specs, original, expected in cases:
            result = run_case(claude, root, name, specs, original)
            check(result, expected)
            evidence["cases"].append({"case": name, "verified": True, "elapsed_s": result["elapsed_s"]})
        assert "launcher_error" in config_path.with_name(config_path.name + ".launcher-errors.jsonl").read_text()
        # Synthetic admission proves transport only, not benign performance.
        m = asdict(BenignFiring(2995, 0, u95_zero_hits(2995), "protocol fixture only", "2026-09-04"))
        config["sources"]["builtin"] = "DENY"
        config["evidence"] = {"fingerprint": hook.fingerprint(STARTER_RULES, config["surfaces"]),
                              "bundle": m, "rules": {r.id: m for r in STARTER_RULES}}
        hook.atomic_json(config_path, config)
        result = run_case(claude, root, "measured_output", [{"event": "PostToolUse", "handler": hook.hook_spec(config_path)}],
                          STARTER_RULES[0].examples_positive[0])
        check(result, hook.WITHHELD)
        evidence["cases"].append({"case": "measured_output", "verified": True, "elapsed_s": result["elapsed_s"]})
    return evidence


def check(result, expected):
    assert not result.get("timeout") and result["exit"] == 0, result
    assert len(result["requests"]) == 2, result
    blocks = [block for message in result["requests"][1]["messages"] for block in message.get("content", [])
              if isinstance(block, dict) and block.get("type") == "tool_result"]
    assert len(blocks) == 1 and not blocks[0].get("is_error"), blocks
    text = json.dumps(blocks[0]["content"])
    assert expected in text, text
    if expected != "ORIGINAL_PAYLOAD":
        assert "ORIGINAL_PAYLOAD" not in text and "ignore all previous instructions" not in text, text


if __name__ == "__main__":
    print(json.dumps(verify(), indent=2))
