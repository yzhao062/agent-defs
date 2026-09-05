import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from agent_defs import evaluate
from agent_defs.loaders import agent_audit_kit, ave, guardana
from agent_defs.model import Breadth, Lane, PredicateKind, Rule, Surface
from agent_defs.loaders._json_corpus import finish_rule, new_delta


FIXTURES = Path(__file__).parent / "fixtures"
REV = "0123456789abcdef0123456789abcdef01234567"


def test_aak_registry_is_not_a_scanner():
    rules, delta = agent_audit_kit.load(FIXTURES / "agent_audit_kit", source_rev=agent_audit_kit.REVIEWED_REV)
    auth, compose, pin, diagnostic = rules
    assert delta["entries_read"] == delta["emitted"] == 4
    assert [r.surface for r in rules] == [Surface.CFG, Surface.CFG, Surface.PIN, Surface.NONE]
    assert auth.severity_raw == "high" and auth.severity_field == "severity"
    assert all(r.lane is Lane.RECORD and r.benign is None and r.maturity_raw == "" for r in rules)
    assert all(r.predicate_kind is PredicateKind.NONE and r.not_runnable_reason for r in rules)
    assert compose.breadth is Breadth.BROAD
    review = compose.extra["composition_review"]
    assert review["upstream_reported"] == {"trials": 748, "wide_findings": 253, "narrow_findings": 2, "after_suppression": 0}
    assert review["status"] == "VERIFIED"
    assert "suppression" in compose.not_runnable_reason
    assert pin.breadth is Breadth.NARROW
    assert diagnostic.surface is Surface.NONE
    assert auth.extra["upstream"]["new_field"] == {"must_survive": [1, False, None]}
    assert delta["fields_preserved_in_extra"]["new_field"] == 1
    assert delta["uncarried_fields"] == {}
    assert auth.lineage[0].value == "MCP01:2025"
    assert all(r.extra["reachability"]["status"] == "no_positive_examples" for r in rules)


def test_ave_examples_are_screened_but_never_promoted(monkeypatch):
    screened = []
    original = evaluate.screen_pattern

    def screen(pattern):
        screened.append(pattern)
        original(pattern)

    monkeypatch.setattr(evaluate, "screen_pattern", screen)
    rules, delta = ave.load(FIXTURES / "ave", source_rev=ave.REVIEWED_REV)
    example, runtime_class = rules
    assert screened == ["fixture-marker", "(a+)+", "["]
    assert delta["pattern_screen"] == {"accepted": 1, "rejected": 2}
    assert example.examples_positive == tuple(screened)
    assert all(r.predicate_kind is PredicateKind.NONE and r.surface is Surface.NONE for r in rules)
    assert all(r.breadth is Breadth.BROAD and r.lane is Lane.RECORD for r in rules)
    assert example.extra["reachability"]["status"] == "not_runnable"
    assert example.extra["reachability"]["checked"] == 0
    assert example.extra["reachability"]["misses"] == 0
    assert runtime_class.extra["reachability"]["status"] == "no_positive_examples"
    assert example.extra["confidence_baseline"] == 0.83
    assert runtime_class.extra["confidence_baseline"] == 0.55
    assert example.severity_raw == "HIGH" and example.severity_field == "severity"
    assert example.extra["upstream"]["aivss"]["aivss_severity"] == "CRITICAL"
    assert example.references == ("https://example.org/fixture",)
    assert example.extra["upstream"]["references"][0]["text"] == "Citation metadata survives."
    assert not evaluate.scan("fixture-marker", rules).findings


def test_ave_nested_crosswalks_keep_identity_caveats_and_gaps():
    rules, delta = ave.load(FIXTURES / "ave", source_rev=REV)
    one, two = rules
    assert {l.value for l in one.lineage if l.kind == "crosswalk"} == {"CFG-TEST-1", "CFG-TEST-2", "fixture/first"}
    assert [l.value for l in two.lineage if l.kind == "crosswalk"] == ["fixture/first"]
    nested = next(l for l in one.lineage if l.value == "fixture/first")
    assert "/mappings/0/rules/0" in nested.evidence
    assert REV in nested.evidence
    assert delta["crosswalk_links"] == 3
    assert one.extra["crosswalks"][0]["mapping"]["note"] == "Only the first subcase maps."
    doc = delta["documents"]["crosswalks/cfgaudit-to-ave.json"]["metadata"]
    assert doc["source"]["commit"] == "1" * 40
    assert doc["mappings"][1]["gap"] == "No matching class."
    assert delta["uncarried_fields"] == {}


def test_guardana_evaluator_name_does_not_supply_its_predicate():
    rules, delta = guardana.load(FIXTURES / "guardana/rules.json", source_rev=guardana.REVIEWED_REV)
    jailbreak, artifact, output = rules
    assert jailbreak.severity_raw == "HIGH" and jailbreak.severity_field == "severity"
    assert all(r.maturity_raw == "stable" and r.lane is Lane.RECORD and r.benign is None for r in rules)
    assert all(r.predicate_kind is PredicateKind.NONE and r.not_runnable_reason for r in rules)
    assert [r.surface for r in rules] == [Surface.NONE, Surface.CFG, Surface.OUT]
    assert jailbreak.description == ""
    assert jailbreak.extra["upstream"]["goal"] == "A secure fixture refuses an unsupported operation."
    assert artifact.extra["upstream"]["goal"] is None
    assert delta["unsupported_constructs"] == {"evaluator_without_expectation": 1, "implementation_not_in_generated_json": 3}
    assert delta["generator"]["script"] == "scripts/generate_docs.py"
    assert "provide_rules()" in delta["generator"]["input"]
    assert delta["fields_preserved_in_extra"]["goal"] == 2
    assert delta["uncarried_fields"] == {}
    benchmarks = [l for l in jailbreak.lineage if l.kind == "benchmark"]
    assert {l.value for l in benchmarks} == {"garak", "HarmBench"}
    assert all("partial stock-DAN overlap" in l.evidence for l in benchmarks)
    assert all("2026-09-05" in l.evidence and "HTTP 200" in l.evidence for l in benchmarks)


def test_reviews_do_not_silently_apply_to_a_new_revision():
    rules, _ = guardana.load(FIXTURES / "guardana/rules.json", source_rev=REV)
    assert all(l.kind != "benchmark" for l in rules[0].lineage)
    assert rules[0].extra["generator"]["status"] == "UNRESOLVED"
    rules, _ = agent_audit_kit.load(FIXTURES / "agent_audit_kit", source_rev=REV)
    assert rules[1].extra["composition_review"]["status"] == "UNRESOLVED"
    assert rules[1].breadth is Breadth.BROAD


def test_reachability_uses_each_rules_own_examples():
    delta = new_delta("fixture", REV)
    rule = Rule(id="fixture:one", source="fixture", source_id="one", source_rev=REV,
                source_path="one.json", upstream_url="https://example.org/one",
                predicate_kind=PredicateKind.REGEX, predicate="^fixture-marker$",
                examples_positive=("fixture-marker", "another-rules-example"))
    checked = finish_rule(rule, {}, set(), delta)
    reach = checked.extra["reachability"]
    assert reach["checked"] == 2 and reach["hits"] == 1 and reach["misses"] == 1
    assert reach["status"] == "reachable"


@pytest.mark.parametrize("module,path", [
    (agent_audit_kit, "agent_audit_kit/rules.json"),
    (ave, "ave/records/AVE-2026-00001.json"),
    (guardana, "guardana/rules.json"),
])
def test_unknown_conditions_are_preserved_screened_and_not_widened(module, path, tmp_path):
    data = json.loads((FIXTURES / path).read_text())
    row = data["rules"][0] if "rules" in data else data
    row["detection"] = {"patterns": ["(a+)+", "safe"], "condition": "both fields and external approval"}
    file = tmp_path / Path(path).name
    file.write_text(json.dumps(data))
    rules, delta = module.load(file, source_rev=REV)
    assert rules[0].predicate_kind is PredicateKind.NONE
    assert rules[0].extra["upstream"]["detection"] == row["detection"]
    assert delta["fields_preserved_in_extra"]["detection"] == 1
    screened = {r["field"]: r["status"] for r in rules[0].extra["pattern_screen"]}
    assert screened["/detection/patterns/0"] == "rejected"
    assert screened["/detection/patterns/1"] == "accepted"
    json.dumps(delta)


@pytest.mark.parametrize("module,path", [
    (agent_audit_kit, "agent_audit_kit"), (ave, "ave"), (guardana, "guardana/rules.json"),
])
def test_require_a_full_pin(module, path):
    with pytest.raises(ValueError, match="40-character"):
        module.load(FIXTURES / path, source_rev="main")


def test_duplicate_ids_and_non_string_severity_fail_visibly(tmp_path):
    data = json.loads((FIXTURES / "agent_audit_kit/rules.json").read_text())
    file = tmp_path / "rules.json"
    data["rules"].append(data["rules"][0])
    file.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="duplicate source ID"):
        agent_audit_kit.load(file, source_rev=REV)
    data["rules"].pop()
    data["rules"][0]["severity"] = 5
    file.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="expected a string"):
        agent_audit_kit.load(file, source_rev=REV)
    file.write_text('{"rules": [], "rules": []}')
    with pytest.raises(ValueError, match="duplicate JSON key"):
        agent_audit_kit.load(file, source_rev=REV)


def test_imports_work_without_site_packages_and_core_does_not_load_adapters():
    code = """
import sys
import agent_defs
assert not any(name.startswith('agent_defs.loaders') for name in sys.modules)
from agent_defs.loaders import agent_audit_kit, ave, guardana
assert not any(name in sys.modules for name in ('yaml', 'pydantic', 'requests'))
"""
    env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src"))
    subprocess.run([sys.executable, "-S", "-c", code], env=env, check=True)
