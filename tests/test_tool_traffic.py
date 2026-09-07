"""Transcript boundaries are part of the denominator, not just parsing detail."""
import json
from pathlib import Path
import sys

SCRIPTS = Path(__file__).parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
try:
    from prepare_tool_traffic import parse_files, text_content, exposure, prose
    from summarize_tool_traffic import combine
    from measure_tool_traffic import corpus
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


def snapshot(tmp_path, rows, name="c"):
    import hashlib
    body = "\n".join(json.dumps(r) for r in rows).encode("utf-8")
    (tmp_path / f"{name}-units.jsonl").write_bytes(body)
    digest = hashlib.sha256(body).hexdigest()
    (tmp_path / f"{name}-inventory.json").write_text(
        json.dumps({"units_sha256": digest, "revision": "sha256:" + digest}), encoding="utf-8")
    return tmp_path


def unit_row(identifier, text, invocation, prose_label="ordinary", exposure_label="locally-generated"):
    import hashlib
    encoded = text.encode("utf-8")
    return {"id": identifier, "text": text, "invocation": invocation, "surface": "OUT",
            "sha256": hashlib.sha256(encoded).hexdigest(), "size_bytes": len(encoded),
            "strata": {"file_type": "tool-result", "prose": prose_label, "tool": "Bash",
                       "exposure": exposure_label, "result_status": "success"}}


def test_a_repeated_invocation_is_one_trial_even_though_its_results_differ(tmp_path):
    """The same call twice is one piece of PreToolUse material, not two trials.

    The snapshot was deduplicated on the tool result, so two runs of the same
    command survive it whenever the bytes they returned differ. On the IN side
    that is the same material twice, and counting it twice would inflate the
    denominator of a bound.
    """
    from agent_defs.model import Surface

    call = json.dumps({"name": "Bash", "arguments": {"command": "git status"}})
    rows = [unit_row("a", "clean tree", call, exposure_label="attacker-reachable"),
            unit_row("b", "one file changed", call),
            unit_row("c", "other", json.dumps({"name": "Bash", "arguments": {"command": "ls"}}))]
    root = snapshot(tmp_path, rows)

    assert len(corpus(root, "c", Surface.OUT).units) == 3
    inbound = corpus(root, "c", Surface.IN)
    assert len(inbound.units) == 2, "a repeated invocation was counted as a second trial"
    assert [u.text for u in inbound.units] == [call, rows[2]["invocation"]]
    assert inbound.identity == "c-invocations", "the two surfaces are separate bodies of material"


def test_an_in_unit_is_labelled_by_its_own_text_not_by_the_result(tmp_path):
    """`prose` is the one stratum the snapshot classified on the wrong text."""
    from agent_defs.model import Surface

    call = json.dumps({"name": "Bash", "arguments": {"command": "ls docs"}})
    rows = [unit_row("a", "a note about a vulnerability", call, prose_label="security-adjacent",
                     exposure_label="attacker-reachable"),
            unit_row("b", "ordinary output",
                     json.dumps({"name": "Bash", "arguments": {"command": "grep exploit ."}}))]
    root = snapshot(tmp_path, rows)

    assert prose(rows[0]["text"]) == "security-adjacent"
    strata = {u.id: u.strata for u in corpus(root, "c", Surface.IN).units}
    assert strata["a"]["prose"] == "ordinary", "an IN unit inherited the result's topic"
    assert strata["b"]["prose"] == "security-adjacent", "the invocation's own topic was ignored"
    assert strata["a"]["file_type"] == "tool-invocation"
    # Classified from the call name and arguments, so these already describe an
    # invocation and are carried across rather than recomputed.
    assert strata["a"]["exposure"] == "attacker-reachable"
    assert strata["a"]["result_status"] == "success"
    assert {u.strata["prose"] for u in corpus(root, "c", Surface.OUT).units} == {
        "security-adjacent", "ordinary"}


def test_the_leaf_walker_finds_what_the_hook_would_scan_and_nothing_else(tmp_path):
    from measure_tool_traffic import leaves

    payload = {"command": "ls", "opts": {"flag": "-a", "count": 3},
               "items": ["one", "", {"deep": "two"}], "ok": True, "none": None}
    # Nested through dicts and lists, in order. Keys are not scanned by the hook
    # and are not returned here; neither are non-string leaves.
    assert leaves(payload) == ["ls", "-a", "one", "", "two"]
    assert leaves("bare") == ["bare"]
    assert leaves(None) == [] and leaves(7) == []


def test_a_unit_is_matched_leaf_by_leaf_rather_than_through_its_serialization(tmp_path):
    """The defect this closes: JSON quoting can suppress a match the hook finds.

    A rule anchored at the start of a command matches that command as the hook
    sees it, and does not match the same command inside `{"command": "..."}`,
    because the quote in front of it is not a line start. Matching the
    serialization was therefore measuring a different question.
    """
    import hashlib

    from agent_defs import bench
    from agent_defs.model import PredicateKind, Rule, Surface

    # Not source="atr": the evaluator requires a recorded backtracking
    # measurement for those, and this rule exists only to be anchored.
    rule = Rule(id="anchored", source="builtin", source_id="anchored", source_rev="0" * 40,
                source_path="anchored", upstream_url="https://example.test", surface=Surface.IN,
                predicate_kind=PredicateKind.REGEX, predicate=r"(?:^|[\n;&|(])\$\{!\w+\}",
                examples_positive=["${!VAR} x"])
    command = "${!REVIEW_CMD} /tmp/review-marker"
    envelope = json.dumps({"name": "Bash", "arguments": {"command": command}})
    strata = {"file_type": "tool-invocation", "prose": "ordinary",
              "exposure": "attacker-reachable"}

    def measure(parts):
        unit = bench.Unit("u", envelope, Surface.IN, strata,
                          hashlib.sha256(envelope.encode()).hexdigest(), len(envelope), parts)
        return bench.measure([rule], [bench.Corpus("c", "0" * 40, (unit,),
                                                   hashlib.sha256(b"x").hexdigest(), ())])

    serialized = measure(None)
    assert serialized["summary"]["findings"] == 0, "the envelope was expected to hide this match"
    assert serialized["corpora"][0]["material"] == "whole"

    leafwise = measure((command,))
    assert leafwise["summary"]["findings"] == 1
    assert leafwise["corpora"][0]["material"] == "leaves"
    assert leafwise["corpora"][0]["leaves"] == 1
    # One invocation is one trial however many strings it holds.
    assert leafwise["corpora"][0]["trials"] == 1

    # Several leaves, one of which matches, is still one hit on one trial, and
    # an empty leaf is skipped the way the hook's traversal skips it.
    many = measure(("harmless", "", command, "also harmless"))
    assert many["summary"]["findings"] == 1 and many["corpora"][0]["trials"] == 1
    assert many["corpora"][0]["leaves"] == 4


def test_in_units_carry_their_argument_leaves(tmp_path):
    from agent_defs.model import Surface

    call = json.dumps({"name": "Bash", "arguments": {"command": "grep exploit .", "timeout": 5}})
    rows = [unit_row("a", "out", call, exposure_label="attacker-reachable"),
            unit_row("b", "out2", json.dumps({"name": "Read", "arguments": {"file_path": "/x"}}))]
    root = snapshot(tmp_path, rows)

    units = {u.id: u for u in corpus(root, "c", Surface.IN).units}
    assert units["a"].parts == ("grep exploit .",), "the tool name and non-strings are not scanned"
    assert units["b"].parts == ("/x",)
    # The serialization stays the identity, so one invocation is still one trial
    # and the dedup key is unchanged; the size describes what was scanned.
    assert units["a"].text == call
    assert units["a"].size_bytes == len("grep exploit .")
    # prose reads the leaves, not the envelope.
    assert units["a"].strata["prose"] == "security-adjacent"
    assert corpus(root, "c", Surface.OUT).units[0].parts is None


def test_a_repeated_tool_result_is_refused_rather_than_quietly_dropped(tmp_path):
    """Deduplicating OUT here would hide a snapshot that skipped its own step."""
    import pytest

    from agent_defs.model import Surface

    text = "identical output"
    rows = [unit_row("a", text, json.dumps({"name": "Bash", "arguments": {"command": "one"}})),
            unit_row("b", text, json.dumps({"name": "Bash", "arguments": {"command": "two"}}))]
    root = snapshot(tmp_path, rows)

    with pytest.raises(ValueError, match="already deduplicated"):
        corpus(root, "c", Surface.OUT)
