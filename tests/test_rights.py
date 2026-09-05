from dataclasses import replace
import hashlib
import json

import pytest

from agent_defs.loaders import atr, sigma
from agent_defs.model import default_bundle


REV = "a" * 40


def atr_tree(tmp_path, **fields):
    raw = {"id": "test-rule", "author": "ATR Community", "title": "Synthetic rights test",
           "detection": {"conditions": [{"field": "content", "operator": "regex", "value": "marker"}],
                         "condition": "any"}, **fields}
    path = tmp_path / "rules" / "test.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(raw), encoding="utf-8")
    (tmp_path / "LICENSE").write_text("MIT License\n", encoding="utf-8")
    return path


@pytest.mark.parametrize("fields", [
    {"author": "ATR Community (via AgentHarm benchmark)"},
    {"metadata_provenance": {"source": "https://example.invalid/AgentHarm"}},
    {"metadata_provenance": {"origins": [{"benchmark": "agentharm"}]}},
])
def test_atr_marks_declared_agentharm_without_deleting_it(tmp_path, fields):
    atr_tree(tmp_path, **fields)
    result = atr.load(tmp_path, source_rev=REV)
    assert result.delta.entries_read == result.delta.rules_emitted == 1
    rule, = result.rules
    assert rule.restricted and not rule.shippable
    assert "AgentHarm" in rule.restricted_reason and "field-of-use" in rule.restricted_reason
    assert all(rule.extra["upstream"][key] == value for key, value in fields.items())
    assert default_bundle(result.rules) == []


def test_garak_payload_source_survives_verbatim_with_evidence(tmp_path):
    value = "garak/probes/example.py Template + garak/data/example.json"
    atr_tree(tmp_path, author="ATR Community (via NVIDIA garak)",
             metadata_provenance={"payload_source": value})
    rule, = atr.load(tmp_path, source_rev=REV).rules
    assert not rule.restricted
    assert rule.extra["upstream"]["metadata_provenance"]["payload_source"] == value
    pointer, = [item for item in rule.lineage if item.kind == "payload_source"]
    assert pointer.value == value
    assert rule.upstream_url in pointer.evidence
    assert "metadata_provenance.payload_source" in pointer.evidence


@pytest.mark.parametrize("manifest", [False, True])
def test_atr_excludes_and_counts_test_corpora_before_reading_payload(tmp_path, manifest):
    path = atr_tree(tmp_path)
    excluded = tmp_path / "data/test-corpora/draft.yaml"
    excluded.parent.mkdir(parents=True)
    excluded.write_bytes(b"\xff invalid UTF-8; must not be read or parsed")
    if manifest:
        (tmp_path / "atr-source.json").write_text(json.dumps({"source_rev": REV, "files": {
            "rules/test.yaml": {"source_path": "rules/test.yaml", "sha256": hashlib.sha256(path.read_bytes()).hexdigest()},
            "data/test-corpora/draft.yaml": {"source_path": "data/test-corpora/draft.yaml", "sha256": "not-read"},
        }}), encoding="utf-8")
    result = atr.load(tmp_path, source_rev=REV)
    assert result.delta.entries_read == result.delta.rules_emitted == 1
    assert result.delta.excluded_paths == {"data/test-corpora/": 1}
    assert result.delta.entry_errors == []
    assert len(default_bundle(result.rules)) == 1


@pytest.mark.parametrize("path", ["data/test-corpora/draft.yaml", "data\\test-corpora\\draft.yaml",
                                   "./data/test-corpora/draft.yaml", "rules/../data/test-corpora/draft.yaml"])
def test_bundle_blocks_excluded_path_even_without_loader_flag(tmp_path, path):
    atr_tree(tmp_path)
    rule, = atr.load(tmp_path, source_rev=REV).rules
    leaked = replace(rule, source_path=path, restricted=False)
    neighbor = replace(rule, source_path="data/test-corpora-reviewed/rule.yaml")
    assert not leaked.shippable
    assert default_bundle([neighbor, leaked]) == [neighbor]


def test_sigma_conversion_is_restricted_but_incidental_prose_is_not():
    raw = {"id": "conversion", "author": "ATR Community (adapted)",
           "description": "Comparison with an AgentHarm detector",
           "logsource": {"product": "ai_agent", "category": "tool_output"},
           "detection": {"selection": {"content|contains": "marker"}, "condition": "selection"}}
    kwargs = {"source": "netzilo", "source_rev": REV, "source_path": "ai_agent/test.yml"}
    incidental = sigma.normalize(raw, **kwargs)
    converted = sigma.normalize({**raw, "references": ["https://github.com/ai-safety-institute/AgentHarm"]}, **kwargs)
    assert incidental.shippable
    assert converted.restricted
    assert "field-of-use" in converted.restricted_reason
    assert default_bundle([incidental, converted]) == [incidental]


def test_explicit_pin_cannot_override_manifest_revision(tmp_path):
    path = atr_tree(tmp_path)
    (tmp_path / "atr-source.json").write_text(json.dumps({"source_rev": REV, "files": {
        "rules/test.yaml": {"source_path": "rules/test.yaml", "sha256": hashlib.sha256(path.read_bytes()).hexdigest()},
    }}), encoding="utf-8")
    with pytest.raises(ValueError, match="disagrees"):
        atr.load(tmp_path, source_rev="b" * 40)
