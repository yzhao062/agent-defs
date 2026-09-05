import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

from agent_defs import PredicateKind
import agent_defs.evaluate as evaluator
from test_evaluate import rule


def test_completed_findings_survive_a_later_hang_and_worker_is_reaped(monkeypatch):
    children = []
    real_popen = subprocess.Popen

    def capture(*args, **kwargs):
        proc = real_popen(*args, **kwargs)
        children.append(proc)
        return proc

    monkeypatch.setattr(evaluator.subprocess, "Popen", capture)
    started = time.perf_counter()
    result = evaluator.scan("a" * 200000 + "!", [
        rule("slow", PredicateKind.REGEX, "a+b"),
        rule("early", PredicateKind.SUBSTRING_ANY, ["aaa"]),
    ], budget_s=1.5)
    assert [hit.rule_id for hit in result.partial_findings] == ["early"]
    assert result.rules_evaluated == 1
    assert result.rules_skipped_budget == 1
    assert not result.complete
    assert time.perf_counter() - started < 2.5
    assert all(proc.poll() is not None for proc in children)


def test_worker_death_is_incomplete_and_next_call_recovers(monkeypatch):
    real_popen = subprocess.Popen

    def crash(command, **kwargs):
        return real_popen([sys.executable, "-I", "-S", "-c", "import os; os._exit(7)"], **kwargs)

    r = rule("r", PredicateKind.REGEX, "x")
    with monkeypatch.context() as patch:
        patch.setattr(evaluator.subprocess, "Popen", crash)
        result = evaluator.scan("x", [r], budget_s=2)
    assert "exit 7" in result.worker_error
    assert not result.complete
    assert not result.partial_findings
    assert evaluator.scan("x", [r], budget_s=2).complete


def test_worker_start_failure_is_explicit(monkeypatch):
    def fail(*args, **kwargs):
        raise OSError("test launch failure")

    monkeypatch.setattr(evaluator.subprocess, "Popen", fail)
    result = evaluator.scan("x", [rule("r", PredicateKind.REGEX, "x")])
    assert "startup failed" in result.worker_error
    assert not result.complete


def test_deadline_also_interrupts_a_worker_that_never_reads_stdin():
    # Windows communicate() writes stdin synchronously before waiting on output.
    code = '''
import json, subprocess, sys, time
import agent_defs.evaluate as e
from agent_defs import Rule, PredicateKind
real_popen = subprocess.Popen
def unread(command, **kwargs):
    return real_popen([sys.executable, "-I", "-S", "-c", "import time; time.sleep(1.5)"], **kwargs)
e.subprocess.Popen = unread
r = Rule(id="r", source="t", source_id="r", source_rev="0"*40, source_path="p",
         upstream_url="", predicate_kind=PredicateKind.REGEX, predicate="x")
started = time.perf_counter()
result = e.scan("x"*200000, [r], budget_s=.15)
print(json.dumps({"elapsed": time.perf_counter()-started, "skipped": result.rules_skipped_budget}))
'''
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, timeout=5, check=True)
    import json
    result = json.loads(out.stdout)
    assert result["elapsed"] < 1
    assert result["skipped"] == 1


def test_slow_process_creation_does_not_hold_the_caller_or_leave_a_worker(monkeypatch):
    real_popen = subprocess.Popen
    children = []

    def slow_start(*args, **kwargs):
        time.sleep(1.5)
        child = real_popen(*args, **kwargs)
        children.append(child)
        return child

    monkeypatch.setattr(evaluator.subprocess, "Popen", slow_start)
    started = time.perf_counter()
    result = evaluator.scan("x", [rule("r", PredicateKind.REGEX, "x")], budget_s=.15)
    elapsed = time.perf_counter() - started
    # Wait for the deliberately late creation to finish, then verify cancellation.
    until = time.perf_counter() + 3
    while not children and time.perf_counter() < until:
        time.sleep(.02)
    if children:
        children[0].wait(timeout=1)
    assert elapsed < 1
    assert result.rules_skipped_budget == 1
    assert all(child.poll() is not None for child in children)


def test_pending_launches_have_a_fixed_resource_limit(monkeypatch):
    import threading
    release = threading.Event()
    real_popen = subprocess.Popen
    children = []

    def blocked_start(*args, **kwargs):
        release.wait(timeout=3)
        child = real_popen(*args, **kwargs)
        children.append(child)
        return child

    monkeypatch.setattr(evaluator.subprocess, "Popen", blocked_start)
    r = rule("r", PredicateKind.REGEX, "x")
    try:
        for _ in range(4):
            assert evaluator.scan("x", [r], budget_s=.03).rules_skipped_budget == 1
        result = evaluator.scan("x", [r], budget_s=.1)
        assert "capacity exhausted" in result.worker_error
        assert not result.complete
    finally:
        release.set()
        until = time.perf_counter() + 3
        while len(children) < 4 and time.perf_counter() < until:
            time.sleep(.02)
        for child in children:
            child.wait(timeout=1)
    assert len(children) == 4


def test_import_and_worker_need_no_site_packages():
    src = str(Path(__file__).resolve().parents[1] / "src")
    code = f'''
import sys
sys.path.insert(0, {src!r})
import agent_defs
assert "agent_defs.evaluate" not in sys.modules
assert not any("site-packages" in getattr(m, "__file__", "") for m in sys.modules.values() if getattr(m, "__file__", None))
from agent_defs.evaluate import scan
from agent_defs import Rule, PredicateKind
r = Rule(id="r", source="t", source_id="r", source_rev="0"*40, source_path="p",
         upstream_url="", predicate_kind=PredicateKind.REGEX, predicate="ok")
assert scan("ok", [r], budget_s=2).findings
'''
    subprocess.run([sys.executable, "-I", "-S", "-c", code], check=True, timeout=5)


@pytest.mark.parametrize("payload,limit,expected,truncated", [
    ("\u00e9x", 1, "", True), ("\u00e9x", 2, "\u00e9", True),
    ("\u00e9x", 3, "\u00e9x", False), ("\ud800x", 3, "\ud800", True),
    ("\U0001f600x", 4, "\U0001f600", True), ("x", 0, "", True),
])
def test_byte_cap_preserves_code_points(payload, limit, expected, truncated):
    assert evaluator._cap_payload(payload, limit) == (expected, truncated)


@pytest.mark.parametrize("kind,predicate", [
    (PredicateKind.SUBSTRING_ANY, "text"), (PredicateKind.SUBSTRING_ALL, []),
    (PredicateKind.SUBSTRING_ANY, [""]), (PredicateKind.REGEX, 42),
    (PredicateKind.STRUCTURED, {"condition": "unsupported"}),
])
def test_invalid_predicate_shapes_are_reported(kind, predicate):
    result = evaluator.scan("text", [rule("bad", kind, predicate)])
    assert [error.rule_id for error in result.errors] == ["bad"]
    assert not result.complete


def test_oversized_bundles_are_not_silently_sampled():
    r = rule("r", PredicateKind.REGEX, "x")
    result = evaluator.scan("x", [r] * 4097)
    assert "4096 rules" in result.worker_error
    assert not result.complete


def test_nonrunnable_rules_do_not_count_as_skipped_work():
    from dataclasses import replace
    r = replace(rule("r", PredicateKind.REGEX, "x"), predicate_kind=PredicateKind.NONE,
                predicate=None, not_runnable_reason="reference only")
    result = evaluator.scan("x", [r], budget_s=0)
    assert result.complete
    assert result.rules_evaluated == result.rules_skipped_budget == 0
