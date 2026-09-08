"""Guarantees that cross the independently repaired hook and evaluator."""
from dataclasses import replace
import hashlib
import io
import json
from pathlib import Path

import pytest

from agent_defs.evaluate import BatchScanResult, Finding, LeafScanResult, ScanResult
from agent_defs.hooks import _claude_code_impl as hook
from agent_defs.model import PredicateKind, Surface
from test_claude_hook_failures import config, evidence, payload


def one_leaf(finding=None, *, evaluated=1, truncated=False, rules_scheduled=1, **kwargs):
    """A batch over exactly one scheduled leaf, with everything resolved."""
    leaf = LeafScanResult((finding,) if finding is not None else (), evaluated, truncated, True)
    return BatchScanResult(leaves=(leaf,), leaves_offered=1, leaves_scheduled=1,
                           rules_scheduled=rules_scheduled, pairs_scheduled=rules_scheduled,
                           pairs_resolved=rules_scheduled, pairs_rejected=0, elapsed_s=0.0,
                           **kwargs)


def test_truncated_finding_never_encodes_or_hashes_the_full_value(config, monkeypatch):
    class Oversized(str):
        def encode(self, *args, **kwargs):
            raise AssertionError("unbounded encoding of truncated input")

    rule = hook.STARTER_RULES[0]
    monkeypatch.setattr(hook, "MAX_SCAN_BYTES", 8)
    finding = Finding(rule.id, "OUT", 0, 6)
    called = []

    def scanner(leaves, rules, **kwargs):
        called.append(list(leaves))
        return one_leaf(finding, truncated=True)

    monkeypatch.setattr(hook, "scan_leaves", scanner)
    response = hook.process(payload("PostToolUse", Oversized("secret" + "x" * 1000)), config, [rule])
    assert len(called) == 1, "the injected batch scanner was not the one that ran"
    records = json.loads(Path(config["log_path"]).read_text())["records"]
    record = next(r for r in records if "rule_id" in r)
    assert record["text_sha256"] is None and record["truncated"]
    assert (record["start"], record["end"]) == (0, 6)
    assert response["hookSpecificOutput"]["additionalContext"] == hook.INCOMPLETE


def test_byte_budget_and_full_value_digest_preserve_surrogates(config, monkeypatch):
    """The byte allowance is one total for the event, spent leaf by leaf.

    Where the old shape asked the traversal for ``[8, 2]``, one allowance per
    scanner call, there is now one call carrying the whole event's leaves and
    the one total. The split is checked where it now lives, so the real scanner
    runs here rather than a fake: six bytes of the first value and two of the
    second exhaust eight, and the third value is declined and named.
    """
    rule = replace(hook.STARTER_RULES[0], predicate_kind=PredicateKind.REGEX, predicate=".+")
    monkeypatch.setattr(hook, "MAX_SCAN_BYTES", 8)
    monkeypatch.setattr(hook, "SCAN_BUDGET_S", 5)
    calls = []
    real = hook.scan_leaves

    def scanner(leaves, rules, **kwargs):
        calls.append((list(leaves), kwargs["max_bytes"]))
        return real(leaves, rules, **kwargs)

    monkeypatch.setattr(hook, "scan_leaves", scanner)
    values = ["\ud800\u2603", "ok", "unscanned"]
    response = hook.process(payload("PostToolUse", values), config, [rule])
    assert calls == [(values, 8)], "the event allowance was split per leaf or spent twice"
    records = json.loads(Path(config["log_path"]).read_text())["records"]
    findings = [r for r in records if "rule_id" in r]
    assert [r["text_sha256"] for r in findings] == [
        hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest() for text in values[:2]]
    coverage = next(r for r in records if r.get("status") == "scan_coverage")
    assert (coverage["leaves_offered"], coverage["leaves_scheduled"]) == (3, 2)
    assert coverage["declined_paths"] == ["/tool_response/2"]
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
    """One budget for the event, handed over once, and exhaustion still warns.

    The single-element list is the "exactly one call" pin: two leaves used to
    mean two scans splitting one budget, and the second one got what the first
    left. The fake reports what a worker killed at the deadline reports, no row
    terminated, so the warning this test is named for is still the thing being
    checked rather than a side effect of the second leaf being starved.
    """
    now = [0.0]
    budgets = []
    monkeypatch.setattr(hook.time, "perf_counter", lambda: now[0])

    def scanner(leaves, rules, **kwargs):
        budgets.append(kwargs["budget_s"])
        now[0] += hook.SCAN_BUDGET_S
        return BatchScanResult(
            leaves=tuple(LeafScanResult((), 0, False, True) for _ in leaves),
            leaves_offered=len(leaves), leaves_scheduled=len(leaves),
            rules_scheduled=len(rules), pairs_scheduled=len(rules) * len(leaves),
            pairs_resolved=0, pairs_rejected=0, elapsed_s=0.0,
            worker_error="worker deadline exceeded")

    monkeypatch.setattr(hook, "scan_leaves", scanner)
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
