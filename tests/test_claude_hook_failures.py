"""Exercise the actual adapter's admission and failure boundaries."""
from dataclasses import asdict, replace
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from agent_defs.builtin import STARTER_RULES
from agent_defs.evaluate import Finding, RuleError, ScanResult
from agent_defs.hooks import _claude_code_impl as hook
from agent_defs.lanes import u95_zero_hits
from agent_defs.model import BenignFiring, Lane, Surface


@pytest.fixture
def config(tmp_path):
    config = hook.default_config()
    config["log_path"] = str(tmp_path / "findings.jsonl")
    return config


def evidence(config, rules, trials=2995):
    m = asdict(BenignFiring(trials, 0, u95_zero_hits(trials), "unit fixture only", "2026-09-04"))
    config["evidence"] = {"fingerprint": hook.fingerprint(rules, config["surfaces"]),
                          "bundle": m, "rules": {r.id: m for r in rules}}


def payload(event, value="ordinary"):
    return {"hook_event_name": event, "tool_input" if event == "PreToolUse" else "tool_response": value}


@pytest.mark.parametrize("event", ["PreToolUse", "PostToolUse"])
@pytest.mark.parametrize("requested,measured", [("RECORD", False), ("DENY", False),
                                               ("ADVISE", True), ("DENY", True)])
@pytest.mark.parametrize("fault", ["deadline", "truncated", "rejected", "worker", "short_count", "exception"])
def test_incomplete_scan_is_never_a_clean_allow(config, monkeypatch, event, requested, measured, fault):
    rule = replace(STARTER_RULES[0], surface=Surface.IN if event == "PreToolUse" else Surface.OUT,
                   lane=Lane.DENY)
    config["sources"]["builtin"] = requested
    if measured:
        evidence(config, [rule])
    result = ScanResult((), 1, 0, 0, False)
    if fault == "deadline":
        result = replace(result, rules_evaluated=0, rules_skipped_budget=1)
    elif fault == "truncated":
        result = replace(result, truncated_input=True)
    elif fault == "rejected":
        result = replace(result, errors=(RuleError(rule.id, "attacker-controlled diagnostic"),))
    elif fault == "worker":
        result = replace(result, worker_error="attacker-controlled diagnostic")
    elif fault == "short_count":
        result = replace(result, rules_evaluated=0)

    def scanner(*args, **kwargs):
        if fault == "exception":
            raise RuntimeError("attacker-controlled diagnostic")
        return result

    monkeypatch.setattr(hook, "scan", scanner)
    response = hook.process(payload(event), config, [rule])
    specific = response.get("hookSpecificOutput", {})
    assert response["systemMessage"]
    assert "updatedToolOutput" not in specific
    assert specific["additionalContext"] == hook.INCOMPLETE
    if event == "PreToolUse" and requested == "DENY" and measured:
        assert specific["permissionDecision"] == "ask"
    else:
        assert "permissionDecision" not in specific
    log = Path(config["log_path"]).read_text()
    assert "scan_incomplete" in log
    assert "attacker-controlled diagnostic" not in json.dumps(response) + log


@pytest.mark.parametrize("event", ["PreToolUse", "PostToolUse"])
def test_completed_measured_deny_survives_a_later_worker_error(config, monkeypatch, event):
    rule = replace(STARTER_RULES[0], surface=Surface.IN if event == "PreToolUse" else Surface.OUT)
    evidence(config, [rule])
    config["sources"]["builtin"] = "DENY"
    finding = Finding(rule.id, rule.surface.value, 0, 6)
    monkeypatch.setattr(hook, "scan", lambda *a, **kw: ScanResult((finding,), 1, 0, 0, False, worker_error="crash"))
    response = hook.process(payload(event, "secret"), config, [rule])
    assert response["systemMessage"]
    specific = response["hookSpecificOutput"]
    if event == "PreToolUse":
        assert specific["permissionDecision"] == "deny"
    else:
        assert specific["updatedToolOutput"] == hook.WITHHELD


@pytest.mark.parametrize("event", ["PreToolUse", "PostToolUse"])
@pytest.mark.parametrize("declared", [Lane.RECORD, Lane.ADVISE, Lane.DENY])
def test_live_path_calls_admit_and_ignores_loader_lane(config, monkeypatch, event, declared):
    rule = replace(STARTER_RULES[0], lane=declared,
                   surface=Surface.IN if event == "PreToolUse" else Surface.OUT)
    config["sources"]["builtin"] = "DENY"
    calls = []
    real_admit = hook.admission.admit

    def admit(measured_rule, **kwargs):
        calls.append((measured_rule.benign, kwargs["bundle_ok"]))
        return real_admit(measured_rule, **kwargs)

    monkeypatch.setattr(hook.admission, "admit", admit)
    assert hook.process(payload(event, rule.examples_positive[0]), config, [rule]) == {}
    assert calls == [(None, False)]
    log = json.loads(Path(config["log_path"]).read_text())
    assert log["records"][0]["lane"] == "RECORD"
    evidence(config, [rule])
    response = hook.process(payload(event, rule.examples_positive[0]), config, [rule])
    assert calls[-1][0].trials == 2995 and calls[-1][1]
    assert "hookSpecificOutput" in response
    # Even with valid evidence, admit() retains control of the live decision.
    monkeypatch.setattr(hook.admission, "admit", lambda *a, **kw: (Lane.RECORD, "withdrawn admission"))
    assert hook.process(payload(event, rule.examples_positive[0]), config, [rule]) == {}


@pytest.mark.parametrize("state", ["clean", "record", "advice", "disabled", "error", "already_withheld"])
def test_parallel_last_writer_keeps_other_redaction_when_we_changed_nothing(config, monkeypatch, state):
    original = {"content": "ordinary", "other": "keep"}
    config["sources"]["builtin"] = "DENY"
    evidence(config, STARTER_RULES)
    if state in ("record", "advice"):
        original["content"] = STARTER_RULES[0].examples_positive[0]
        config["sources"]["builtin"] = "RECORD" if state == "record" else "ADVISE"
    elif state == "disabled":
        config["sources"]["builtin"] = "DO_NOT_SHIP"
    elif state == "error":
        monkeypatch.setattr(hook, "scan", lambda *a, **kw: ScanResult((), 0, 0, 0, False, worker_error="failed"))
    elif state == "already_withheld":
        original["content"] = hook.WITHHELD
        finding = Finding(STARTER_RULES[0].id, "OUT", 0, 1)
        monkeypatch.setattr(hook, "scan", lambda *a, **kw: ScanResult((finding,), len(STARTER_RULES), 0, 0, False))
        original.pop("other")
    response = hook.process(payload("PostToolUse", original), config)
    assert "updatedToolOutput" not in response.get("hookSpecificOutput", {})
    # Model the verified harness: every hook got original, ours finishes last.
    other_redaction = {"content": "REDACTED_BY_OTHER"}
    final = response.get("hookSpecificOutput", {}).get("updatedToolOutput", other_redaction)
    assert final == other_redaction


def shell():
    if os.name == "nt":
        path = Path("C:/Program Files/Git/bin/bash.exe")
        if path.is_file():
            return str(path)
    path = shutil.which("sh")
    if not path:
        pytest.skip("POSIX hook shell unavailable")
    return path


@pytest.mark.parametrize("failure", ["missing_interpreter", "exit1", "exit2", "exit127", "argparse", "bad_python_option"])
def test_installed_shell_catches_failures_before_python_boundary(tmp_path, monkeypatch, failure):
    if failure == "missing_interpreter":
        argv = [str(tmp_path / "missing interpreter '$()'.exe")]
    elif failure == "argparse":
        argv = [sys.executable, "-c", "import argparse;argparse.ArgumentParser().parse_args(['--bad'])"]
    elif failure == "bad_python_option":
        argv = [sys.executable, "--not-a-python-option"]
    else:
        argv = [sys.executable, "-c", "import os;os._exit(" + failure[4:] + ")"]
    monkeypatch.setattr(hook, "hook_argv", lambda config: argv)
    spec = hook.hook_spec(tmp_path / "config.json")
    result = subprocess.run([shell(), "-c", spec["command"]], input="{broken", cwd=tmp_path,
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0
    assert "systemMessage" in json.loads(result.stdout)
    assert "launcher_error" in (tmp_path / "config.json.launcher-errors.jsonl").read_text()


@pytest.mark.parametrize("raw", [b'\xff', b'{"hook_event_name":"PreToolUse","tool_input":"\\ud800"}',
                                  b'{"hook_event_name":"PostToolUse","tool_response":"\\ud800"}', b'"' * 10000])
def test_installed_command_returns_zero_for_nontext_and_surrogate_payloads(config, tmp_path, raw):
    path = tmp_path / "config with 'quote and $dollar.json"
    hook.atomic_json(path, config)
    result = subprocess.run([shell(), "-c", hook.hook_spec(path)["command"]], input=raw,
                            capture_output=True, cwd=tmp_path, timeout=10)
    assert result.returncode == 0
    response = json.loads(result.stdout)
    assert "permissionDecision" not in response.get("hookSpecificOutput", {})


def test_calibration_refuses_worker_errors_without_writing_evidence(config, tmp_path, monkeypatch):
    path = tmp_path / "config.json"
    hook.atomic_json(path, config)
    before = path.read_bytes()
    benign = tmp_path / "benign"
    benign.mkdir()
    (benign / "one.txt").write_text("ordinary")
    monkeypatch.setattr(hook, "scan", lambda *a, **kw: ScanResult((), 0, 0, 0, False, worker_error="failed"))
    with pytest.raises(ValueError, match="incomplete calibration"):
        hook.calibrate(path, benign, "fixture")
    assert path.read_bytes() == before


def test_broken_stdout_cannot_turn_shutdown_into_exit_120(config, tmp_path):
    path = tmp_path / "config.json"
    hook.atomic_json(path, config)
    proc = subprocess.Popen(hook.hook_argv(path), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, cwd=tmp_path)
    proc.stdout.close()
    proc.stdin.write(b'{}')
    proc.stdin.close()
    assert proc.wait(timeout=10) == 0
    proc.stderr.close()


def test_deep_tree_does_not_erase_an_earlier_redaction(config):
    rule = STARTER_RULES[0]
    config["sources"]["builtin"] = "DENY"
    evidence(config, [rule])
    nested = "ordinary"
    for _ in range(600):
        nested = [nested]
    original = {"matched": rule.examples_positive[0], "deep": nested}
    response = hook.process(payload("PostToolUse", original), config, [rule])
    assert response["hookSpecificOutput"]["updatedToolOutput"]["matched"] == hook.WITHHELD
    assert response["systemMessage"]


def test_partial_log_write_warns_without_discarding_redaction(config, monkeypatch):
    rule = STARTER_RULES[0]
    config["sources"]["builtin"] = "DENY"
    evidence(config, [rule])
    monkeypatch.setattr(hook.os, "write", lambda fd, data: 1)
    response = hook.process(payload("PostToolUse", rule.examples_positive[0]), config, [rule])
    assert response["hookSpecificOutput"]["updatedToolOutput"] == hook.WITHHELD
    assert "log could not be written" in response["systemMessage"]
