"""Guarantees that cross the independently repaired hook and evaluator."""
from dataclasses import replace
import hashlib
import io
import json
from pathlib import Path

import pytest

from agent_defs.evaluate import Finding, ScanResult
from agent_defs.hooks import _claude_code_impl as hook
from agent_defs.model import Surface
from test_claude_hook_failures import config, evidence, payload


def test_truncated_finding_never_encodes_or_hashes_the_full_value(config, monkeypatch):
    class Oversized(str):
        def encode(self, *args, **kwargs):
            raise AssertionError("unbounded encoding of truncated input")

    rule = hook.STARTER_RULES[0]
    monkeypatch.setattr(hook, "MAX_SCAN_BYTES", 8)
    finding = Finding(rule.id, "OUT", 0, 6)
    monkeypatch.setattr(hook, "scan", lambda *a, **kw: ScanResult((finding,), 1, 0, 0, True))
    response = hook.process(payload("PostToolUse", Oversized("secret" + "x" * 1000)), config, [rule])
    records = json.loads(Path(config["log_path"]).read_text())["records"]
    record = next(r for r in records if "rule_id" in r)
    assert record["text_sha256"] is None and record["truncated"]
    assert (record["start"], record["end"]) == (0, 6)
    assert response["hookSpecificOutput"]["additionalContext"] == hook.INCOMPLETE


def test_byte_budget_and_full_value_digest_preserve_surrogates(config, monkeypatch):
    rule = hook.STARTER_RULES[0]
    monkeypatch.setattr(hook, "MAX_SCAN_BYTES", 8)
    allowances = []

    def scanner(text, rules, **kwargs):
        allowances.append(kwargs["max_bytes"])
        return ScanResult((Finding(rule.id, "OUT", 0, len(text)),), 1, 0, 0, False)

    monkeypatch.setattr(hook, "scan", scanner)
    values = ["\ud800\u2603", "ok", "unscanned"]
    response = hook.process(payload("PostToolUse", values), config, [rule])
    assert allowances == [8, 2]
    records = json.loads(Path(config["log_path"]).read_text())["records"]
    findings = [r for r in records if "rule_id" in r]
    assert [r["text_sha256"] for r in findings] == [
        hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest() for text in values[:2]]
    assert response["hookSpecificOutput"]["additionalContext"] == hook.INCOMPLETE


def test_run_reads_only_the_bounded_envelope(config, monkeypatch, tmp_path):
    class Input(io.BytesIO):
        def read(self, size=-1):
            assert size == hook.MAX_PAYLOAD_BYTES + 1
            return super().read(size)

    stream = Input(b"x" * (hook.MAX_PAYLOAD_BYTES + 100))
    path = tmp_path / "config.json"
    hook.atomic_json(path, config)
    monkeypatch.setattr(hook.sys, "stdin", stream)
    assert hook.run(path) == hook.degraded_response()
    assert stream.tell() == hook.MAX_PAYLOAD_BYTES + 1


def test_event_budget_is_shared_and_exhaustion_warns_the_model(config, monkeypatch):
    now = [0.0]
    budgets = []
    monkeypatch.setattr(hook.time, "perf_counter", lambda: now[0])

    def scanner(text, rules, **kwargs):
        budgets.append(kwargs["budget_s"])
        now[0] += hook.SCAN_BUDGET_S
        return ScanResult((), len(rules), 0, 0, False)

    monkeypatch.setattr(hook, "scan", scanner)
    response = hook.process(payload("PostToolUse", ["first", "unscanned"]), config)
    assert budgets == [hook.SCAN_BUDGET_S]
    assert response == hook.degraded_response("PostToolUse")


@pytest.mark.parametrize("fault", ["missing_payload", "process_exception"])
def test_degraded_pre_response_retains_measured_ask_and_model_warning(config, monkeypatch, tmp_path, fault):
    rule = replace(hook.STARTER_RULES[0], surface=Surface.IN)
    config["sources"]["builtin"] = "DENY"
    evidence(config, [rule])
    if fault == "missing_payload":
        response = hook.process({"hook_event_name": "PreToolUse"}, config, [rule])
    else:
        path = tmp_path / "config.json"
        hook.atomic_json(path, config)
        monkeypatch.setattr(hook, "active_rules", lambda *a: [rule])
        monkeypatch.setattr(hook.sys, "stdin", io.StringIO(json.dumps(payload("PreToolUse"))))

        def broken(*args):
            raise RuntimeError("hostile exception text")

        monkeypatch.setattr(hook, "process", broken)
        response = hook.run(path)
    assert response == hook.degraded_response("PreToolUse", ask=True)
    assert response["hookSpecificOutput"]["additionalContext"] == hook.INCOMPLETE
    assert "hostile" not in json.dumps(response)
