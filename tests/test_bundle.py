"""The distribution format, and what it refuses to carry."""
import json

import pytest

from agent_defs import bundle
from agent_defs.builtin import STARTER_RULES
from agent_defs.model import (Breadth, ChannelBinding, Gate, Lane, Lineage,
                              PredicateKind, Rule, Surface)


def _rule(rule_id="atr:0001", **overrides):
    fields = dict(
        id=rule_id, source="atr", source_id=rule_id.split(":")[1],
        source_rev="f" * 40, source_path="rules/a.yaml",
        upstream_url="https://example.invalid/a",
        lineage=(Lineage(kind="author_field", value="garak", evidence="rules/a.yaml:3"),),
        license_spdx="MIT", title="a", tags=("t1", "t2"),
        surface=Surface.OUT, breadth=Breadth.NARROW,
        predicate_kind=PredicateKind.SUBSTRING_ALL, predicate=("alpha", "beta"),
        bindings=(ChannelBinding(channel="OUT", entry_point="scanText", eligible=True,
                                 reason="", gates=(Gate(name="scanSkill", verdict="pass",
                                                        detail="", read_from="src/x.ts:9"),),
                                 condition_logic="all", conditions=("alpha", "beta")),),
        examples_positive=("alpha beta",),
    )
    fields.update(overrides)
    return Rule(**fields)


def test_a_round_trip_restores_the_nesting_not_just_the_values(tmp_path):
    path = tmp_path / "bundle.json"
    bundle.write(path, [_rule()], source="atr", source_rev="f" * 40)
    restored, metadata = bundle.read(path)

    assert metadata["source"] == "atr"
    assert metadata["format_version"] == bundle.FORMAT_VERSION
    only = restored[0]
    # asdict flattens these into mappings and JSON turns every tuple into a
    # list. A reader that skipped this step looks right until the first
    # attribute access on a binding.
    assert isinstance(only.bindings[0], ChannelBinding)
    assert isinstance(only.bindings[0].gates[0], Gate)
    assert isinstance(only.lineage[0], Lineage)
    assert only.bindings[0].executable
    assert only.predicate == ("alpha", "beta")
    assert only.tags == ("t1", "t2")
    assert only.surface is Surface.OUT


def test_a_stored_lane_or_measurement_never_survives_the_read(tmp_path):
    path = tmp_path / "bundle.json"
    bundle.write(path, [_rule(lane=Lane.DENY, lane_reason="trust me")])
    document = json.loads(path.read_text(encoding="utf-8"))

    assert set(bundle.NOT_CARRIED).isdisjoint(document["rules"][0])
    restored = bundle.load(path)
    assert restored[0].lane is Lane.RECORD
    assert restored[0].benign is None

    # A file that carries them anyway is still read as if it had not.
    document["rules"][0].update(lane="DENY", lane_reason="trust me", benign=None)
    path.write_text(json.dumps(document), encoding="utf-8")
    assert bundle.load(path)[0].lane is Lane.RECORD


def test_the_reader_refuses_what_it_cannot_read(tmp_path):
    path = tmp_path / "bundle.json"

    path.write_text(json.dumps({"format_version": 99, "rules": []}), encoding="utf-8")
    with pytest.raises(ValueError, match="format version"):
        bundle.read(path)

    path.write_text(json.dumps({"format_version": 1, "rules": {}}), encoding="utf-8")
    with pytest.raises(ValueError, match="array"):
        bundle.read(path)

    path.write_text(json.dumps([{"id": "a", "wat": 1}]), encoding="utf-8")
    with pytest.raises(ValueError, match="unknown record fields"):
        bundle.read(path)


def test_two_records_may_not_claim_one_identity(tmp_path):
    path = tmp_path / "bundle.json"
    bundle.write(path, [_rule("atr:0001"), _rule("atr:0001")])
    with pytest.raises(ValueError, match="duplicate rule IDs"):
        bundle.load(path)


def test_a_bare_array_is_read_the_same_way(tmp_path):
    path = tmp_path / "rules.json"
    path.write_text(json.dumps([bundle.to_record(_rule())]), encoding="utf-8")
    rules, metadata = bundle.read(path)
    assert metadata == {}
    assert rules[0].id == "atr:0001"


def test_the_benchmark_and_the_hook_read_through_the_same_reader(tmp_path):
    from agent_defs import bench

    path = tmp_path / "bundle.json"
    bundle.write(path, STARTER_RULES)
    assert [r.id for r in bench.load_rules(path)] == [r.id for r in STARTER_RULES]


def test_the_file_ends_the_same_way_on_every_platform(tmp_path):
    path = tmp_path / "bundle.json"
    size = bundle.write(path, [_rule()])
    raw = path.read_bytes()
    assert size == len(raw)
    assert b"\r\n" not in raw
    assert raw.endswith(b"\n")
