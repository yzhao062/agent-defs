import os
from dataclasses import replace
from pathlib import Path
import subprocess
import sys

import pytest

from agent_defs.evaluate import scan
from agent_defs.loaders.sigma import (
    dedup, deduplicated_view, load, normalize, parse_condition, reachability,
    UnsupportedSigma,
)
from agent_defs.model import Lane, PredicateKind, Rule

FIXTURES = Path(__file__).parent / "fixtures" / "sigma"
REV = "5069b74d725a3cb7a7267833cbf0f8de1f31e4a7"
ATR_REV = "66c7c1573e202b83ac526b70275244c50000068a"


def make_rule(detection, **fields):
    return normalize({"id": "fixture", "logsource": {"product": "ai_agent", "category": "agent_events"},
                      "detection": detection, **fields},
                     source="netzilo", source_rev=REV, source_path="fixture.yml")


def test_fixture_logic_and_refusal():
    pytest.importorskip("yaml")
    rules, delta = load(FIXTURES / "cases.yml", source="netzilo", source_rev=REV)
    by_id = {r.source_id: r for r in rules}
    assert delta["entries_read"] == delta["emitted"] == 8
    any_rule, all_rule = by_id["fixture-any"], by_id["fixture-all"]
    assert any_rule.predicate_kind is PredicateKind.SUBSTRING_ANY
    assert all_rule.predicate_kind is PredicateKind.SUBSTRING_ALL
    assert scan("MARKER ALPHA", [any_rule]).findings
    assert not scan("marker alpha", [all_rule]).findings
    assert scan("marker beta then marker alpha", [all_rule]).findings
    assert any_rule.maturity_raw == "stable" and any_rule.lane is Lane.RECORD
    assert any_rule.severity_raw == "high" and any_rule.severity_field == "level"
    assert any_rule.false_positive_notes == ("Synthetic fixture note",)
    for name in ("guard", "nested", "filter", "regex-tree", "unsafe", "field"):
        rule = by_id["fixture-" + name]
        assert rule.predicate_kind is PredicateKind.NONE
        assert rule.not_runnable_reason
    assert len(delta["pattern_rejections"]["netzilo:fixture-unsafe"]) == 2
    assert "unsupported_field:event_type" in by_id["fixture-guard"].not_runnable_reason


def test_selection_logic_is_independent_of_condition_quantifier():
    rule = make_rule({"s_a": {"content|contains": ["alpha", "beta"]}, "condition": "all of s_*"})
    assert rule.predicate_kind is PredicateKind.SUBSTRING_ANY
    rule = make_rule({"s_a": {"content|contains|all": ["alpha", "beta"]}, "condition": "1 of s_*"})
    assert rule.predicate_kind is PredicateKind.SUBSTRING_ALL
    rule = make_rule({"s_a": {"content|contains": "alpha"}, "s_b": {"content|contains": "beta"},
                      "condition": "(s_a and s_b)"})
    assert rule.predicate_kind is PredicateKind.SUBSTRING_ALL


def test_condition_parser_preserves_precedence_and_private_quantifiers():
    sels = {"a": {}, "b": {}, "c": {}, "_private": {}}
    assert parse_condition("a or b and not c", sels) == (
        "or", ("ref", "a"), ("and", ("ref", "b"), ("not", ("ref", "c"))))
    assert parse_condition("1 of them", sels) == ("or", ("ref", "a"), ("ref", "b"), ("ref", "c"))
    assert parse_condition(["a", "b"], sels) == ("or", ("ref", "a"), ("ref", "b"))
    for condition in ("2 of them", "a | count() > 3", "all of missing*", "(a", "a garbage"):
        with pytest.raises(UnsupportedSigma):
            parse_condition(condition, sels)


def test_lists_of_maps_do_not_lose_conjunctions():
    rule = make_rule({"s": [{"content|contains|all": ["alpha", "beta"]},
                            {"content|contains": "gamma"}], "condition": "s"})
    assert not rule.runnable
    assert "boolean_tree_requires_structured_runtime" in rule.not_runnable_reason


def test_case_modes_and_wildcard_escapes():
    sensitive = make_rule({"s": {"content|re": "marker"}, "condition": "s"})
    insensitive = make_rule({"s": {"content|re|i": "marker"}, "condition": "s"})
    assert sensitive.case_sensitive and not scan("MARKER", [sensitive]).findings
    assert not insensitive.case_sensitive and scan("MARKER", [insensitive]).findings
    literal = make_rule({"s": {"content|contains": r"a\*b\?c"}, "condition": "s"})
    assert literal.predicate == ("a*b?c",)
    assert scan("a*b?c", [literal]).findings
    for value in ("a*b", "a?b", ""):
        assert not make_rule({"s": {"content|contains": value}, "condition": "s"}).runnable


def test_raw_text_and_duplicate_yaml_key(tmp_path):
    pytest.importorskip("yaml")
    path = tmp_path / "bad.yml"
    path.write_text("id: x\ndetection: {}\ndetection: {}\n", encoding="utf-8")
    result = load(path, source="netzilo", source_rev=REV)
    assert not result.rules and "duplicate YAML key" in result.delta["errors"][0]["reason"]
    path.write_bytes(b"id: x\r\nlogsource: {product: ai_agent, category: agent_events}\r\ndetection: {s: {content|re: marker}, condition: s}\r\n")
    rule = load(path, source="netzilo", source_rev=REV).rules[0]
    assert rule.extra["source_text_raw"].encode() == path.read_bytes()
    with pytest.raises(ValueError, match="40-character"):
        load(path, source="netzilo", source_rev="main")


def converted_and_origin():
    yaml = pytest.importorskip("yaml")
    conversion = load(FIXTURES / "converted.yml", source="netzilo", source_rev=REV).rules[0]
    data = yaml.safe_load((FIXTURES / "origin.yaml").read_text(encoding="utf-8"))
    origin = Rule(id="atr:" + data["id"], source="atr", source_id=data["id"],
                  source_rev=ATR_REV, source_path="rules/prompt-injection/" + data["id"] + ".yaml",
                  upstream_url="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/" + ATR_REV,
                  title=data["title"], predicate_kind=PredicateKind.REGEX,
                  predicate=data["detection"]["conditions"][0]["value"], case_sensitive=False,
                  examples_positive=tuple(x["input"] for x in data["test_cases"]["true_positives"]))
    return conversion, origin


def test_real_conversion_lineage_examples_and_reachability():
    conversion, origin = converted_and_origin()
    assert conversion.case_sensitive
    assert not any(scan(x, [conversion]).findings for x in origin.examples_positive)
    result = dedup([conversion, origin])
    marked = result.rules[0]
    assert result.delta["methods"] == {"exact_atr_reference_id": 1}
    assert marked.extra["duplicate_of"] == origin.id
    assert any(l.kind == "conversion" and l.value == origin.source_id for l in marked.lineage)
    assert marked.examples_positive == origin.examples_positive
    assert not marked.case_sensitive and conversion.case_sensitive
    assert marked.extra["linked_examples_origin"]["id"] == origin.id
    assert all(scan(x, [marked]).findings for x in marked.examples_positive)
    assert reachability([marked])["counts"]["example_hits"] == 3
    assert deduplicated_view(result.rules) == (origin,)
    assert deduplicated_view([marked]) == (marked,)
    assert dedup(result.rules).rules == result.rules


def test_dedup_missing_ambiguous_and_unrelated_title():
    conversion, origin = converted_and_origin()
    missing = dedup([conversion])
    assert len(missing.delta["unmatched"]) == 1
    assert not missing.rules[0].extra["is_conversion_duplicate"]
    ambiguous = dedup([conversion, origin, replace(origin, source_rev="a" * 40)])
    assert len(ambiguous.delta["ambiguous"]) == 1
    unrelated = replace(conversion, references=(), title=origin.title)
    assert dedup([unrelated, origin]).delta["matched"] == 0
    citation_only = replace(conversion, extra={**conversion.extra, "source_data_raw": {"author": "Original research"}})
    assert dedup([citation_only, origin]).delta["matched"] == 0


def test_agentshield_port_uses_id_and_author_despite_changed_title():
    origin = make_rule({"s": {"content|contains": "marker"}, "condition": "s"})
    origin = replace(origin, source="agentshield", id="agentshield:fixture", title="Original title")
    port = make_rule({"s": {"content|contains|all": ["marker", "different"]}, "condition": "s"},
                     title="Changed title", author="AgentShield (ported to Netzilo)")
    result = dedup([port, origin])
    assert result.delta["methods"] == {"preserved_agentshield_id_and_author": 1}
    assert len(result.rules) == 2
    assert result.rules[0].predicate != origin.predicate


def test_imports_work_when_all_third_party_imports_are_blocked():
    script = '''
import sys, importlib.abc
class Block(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        name = fullname.split('.')[0]
        if name not in sys.stdlib_module_names and name != 'agent_defs':
            raise AssertionError('third-party import: ' + fullname)
sys.meta_path.insert(0, Block())
import agent_defs
assert not any(n.startswith('agent_defs.loaders') for n in sys.modules)
import agent_defs.loaders.sigma
assert 'yaml' not in sys.modules
'''
    env = dict(os.environ, PYTHONPATH=str(Path(__file__).parents[1] / "src"))
    subprocess.run([sys.executable, "-S", "-c", script], env=env, check=True, capture_output=True)


def test_external_scenarios_use_declared_aliases_and_keep_event_structure(tmp_path):
    pytest.importorskip("yaml")
    rules_dir = tmp_path / "rules" / "rules" / "ai_agent"
    rules_dir.mkdir(parents=True)
    (rules_dir / "rule.yml").write_text(
        "id: actual-id\naliases: [legacy-id]\nlogsource: {product: ai_agent, category: agent_events}\n"
        "detection: {s: {event_type: tool_call, command|contains: marker}, condition: s}\n", encoding="utf-8")
    examples = tmp_path / "bench" / "testcases"
    examples.mkdir(parents=True)
    (examples / "positive.yaml").write_text(
        "id: scenario\nevents: [{fields: {event_type: tool_call, command: marker}}]\n"
        "expected: {must_trigger_rules: [legacy-id, missing-id]}\n", encoding="utf-8")
    rules, delta = load(tmp_path, source="agentshield", source_rev=REV)
    assert delta["example_scenarios"]["linked_rules"] == 1
    assert delta["example_scenarios"]["unmatched"][0]["expected_rule_id"] == "missing-id"
    scenario = rules[0].extra["positive_scenarios_raw"][0]["scenario"]
    assert scenario["events"][0]["fields"]["command"] == "marker"
    assert not rules[0].examples_positive
    assert reachability(rules)["counts"]["structured_scenarios_not_evaluated"] == 1
