"""Real-corpus release checks. The release CLI never skips missing inputs.

AGENT_DEFS_CORPORA=/path/to/corpora AGENT_DEFS_ARCHIVES=/path/to/archives \
    PYTHONPATH=src python -m pytest tests/test_distribution_corpora.py -q
"""

from dataclasses import replace
import importlib.util
import os
from pathlib import Path

import pytest


spec = importlib.util.spec_from_file_location(
    "audit_distribution", Path(__file__).resolve().parents[1] / "scripts/audit_distribution.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


@pytest.fixture(scope="module")
def inputs():
    if "AGENT_DEFS_CORPORA" not in os.environ:
        pytest.skip("Set AGENT_DEFS_CORPORA and AGENT_DEFS_ARCHIVES for the mandatory release gate")
    corpora = Path(os.environ["AGENT_DEFS_CORPORA"])
    archives = Path(os.environ["AGENT_DEFS_ARCHIVES"])
    assert corpora.is_dir() and archives.is_dir(), "Release inputs are missing"
    return corpora, archives


def test_default_bundle_against_all_six_verified_corpora(inputs):
    report = gate.audit(*inputs)
    assert report["atr_agentharm_count"] == 25
    assert report["atr_garak_author_count"] == 228
    assert report["atr_garak_payload_source_count"] == 121
    assert report["excluded_paths"] == {"data/test-corpora/": 1101}
    assert report["test_corpora"]["draft_empty_conditions_todo"] == 1013
    assert report["loaded"] == 2481
    assert report["restricted"] == 50
    assert report["ships"] == 2431


def test_release_gate_fails_if_bundle_forgets_restrictions(inputs, monkeypatch):
    monkeypatch.setattr(gate, "default_bundle", list)
    with pytest.raises(AssertionError, match="restricted record in default bundle"):
        gate.audit(*inputs)


@pytest.mark.parametrize("loss, message", [
    ("restriction", "restricted flags disagree"),
    ("lineage", "lost payload_source lineage"),
    ("excluded_path", "ATR loader emitted an excluded path"),
])
def test_release_gate_fails_if_loader_loses_evidence(inputs, monkeypatch, loss, message):
    original = gate.atr.load

    def faulty_load(*args, **kwargs):
        result = original(*args, **kwargs)
        if loss == "excluded_path":
            excluded = next((inputs[0] / "atr/data/test-corpora").rglob("*.yaml"))
            result.rules[0] = replace(result.rules[0], source_path=excluded.relative_to(inputs[0] / "atr").as_posix())
        else:
            result.rules = [replace(r, restricted=False) if loss == "restriction" else
                            replace(r, lineage=tuple(item for item in r.lineage if item.kind != "payload_source"))
                            for r in result.rules]
        return result

    monkeypatch.setattr(gate.atr, "load", faulty_load)
    with pytest.raises(AssertionError, match=message):
        gate.audit(*inputs)
