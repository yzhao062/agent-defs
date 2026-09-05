"""Transcript boundaries are part of the denominator, not just parsing detail."""
import json
from pathlib import Path
import sys

SCRIPTS = Path(__file__).parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
try:
    from prepare_tool_traffic import parse_files, text_content, exposure
    from summarize_tool_traffic import combine
finally:
    sys.path.pop(0)


def test_result_chunks_are_one_trial_and_progress_is_not_a_second_call(tmp_path):
    call = {"type": "tool_use", "id": "id1", "name": "WebFetch", "input": {"url": "https://example.test"}}
    result = {"type": "tool_result", "tool_use_id": "id1", "content": [
        {"type": "text", "text": "first"}, {"type": "text", "text": "second"}]}
    records = [{"type": "assistant", "sessionId": "s", "message": {"content": [call]}},
               {"type": "progress", "message": {"content": [call, result]}},
               {"type": "user", "sessionId": "s", "message": {"content": [result]}},
               {"type": "user", "sessionId": "s", "message": {"content": [result]}}]
    path = tmp_path / "session.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in records))
    rows, inventory = parse_files([path], tmp_path)
    assert len(rows) == 1
    assert rows[0]["text"] == "first\nsecond"
    assert rows[0]["strata"]["exposure"] == "attacker-reachable"
    assert inventory["counts"]["duplicate_result_records"] == 1
    assert inventory["counts"]["calls"] == 1


def test_multimodal_is_not_silently_measured_as_its_text_prefix():
    text, reason = text_content([{"type": "text", "text": "prefix"}, {"type": "image", "source": {}}])
    assert text is None and reason == "nontext-content"
    assert exposure("Read", {}) == "file-origin-unknown"
    assert exposure("Bash", {"command": "git status"}) == "locally-generated"
    assert exposure("Bash", {"command": "curl https://example.test"}) == "network-command-mixed"


def test_combined_reports_equal_joint_measurement_for_rates_and_lanes():
    from agent_defs import bench
    from agent_defs.model import PredicateKind, Rule, Surface

    rule = Rule(id="witness", source="atr", source_id="witness", source_rev="0" * 40,
                source_path="witness", upstream_url="https://example.test", surface=Surface.OUT,
                predicate_kind=PredicateKind.SUBSTRING_ANY, predicate=["witness"], examples_positive=["witness"])
    def corpus(name, text):
        import hashlib
        digest = hashlib.sha256(text.encode()).hexdigest()
        unit = bench.Unit(name, text, Surface.OUT, {"file_type": "text", "prose": "ordinary"}, digest, len(text))
        return bench.Corpus(name, "0" * 40, (unit,), digest, ())

    corpora = [corpus("a", "witness"), corpus("b", "ordinary")]
    merged = combine([bench.measure([rule], [c]) for c in corpora], [rule])
    joint = bench.measure([rule], corpora)
    assert merged["summary"] == joint["summary"]
    assert merged["rules"]["witness"]["diagnostic"] == joint["rules"]["witness"]["diagnostic"]
    assert merged["rules"]["witness"]["lane"] == joint["rules"]["witness"]["lane"]
    assert merged["bundle"]["diagnostic"] == joint["bundle"]["diagnostic"]
