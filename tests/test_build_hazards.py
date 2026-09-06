"""What the table builder must refuse, and what it must not lose.

Two of these are failure modes a reviewer found in this script. The report says
how many patterns it timed and never which ones, so a rule whose condition
changed while its count held took the old verdict onto new text: a lookup hit
that is wrong, which never falls back to the shape screen the way a miss does.
And a rebuild had no way to carry a correction the shipped table already held,
so regenerating restored the weaker verdict the correction was written to
replace, without saying so.
"""

import importlib.util
import json
from pathlib import Path

import pytest

BUILDER = Path(__file__).resolve().parents[1] / "scripts" / "build_hazards.py"
REV = "test-revision"


@pytest.fixture(scope="module")
def builder():
    spec = importlib.util.spec_from_file_location("build_hazards_under_test", BUILDER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_corpus(root, rules):
    """``rules`` is ``(source_id, [condition, ...], logic)``. YAML reads JSON."""
    (root / "rules").mkdir(parents=True, exist_ok=True)
    for source_id, conditions, logic in rules:
        body = {"id": source_id,
                "detection": {"condition": logic,
                              "conditions": [{"operator": "regex", "value": v} for v in conditions]}}
        (root / "rules" / f"{source_id}.yaml").write_text(json.dumps(body), encoding="utf-8")
    return root


def write_report(path, rules):
    path.write_text(json.dumps({"rule_rows": {
        source_id: {"patterns_total": len(set(conditions)), "patterns_measured": len(set(conditions)),
                    "fully_measured": True, "cross_1s": False, "cross_60s": False,
                    "rep1": None, "rep60": None}
        for source_id, conditions, _ in rules}}), encoding="utf-8")
    return path


def run(builder, monkeypatch, *args):
    monkeypatch.setattr("sys.argv", ["build_hazards.py", *[str(a) for a in args]])
    return builder.main()


def build(builder, monkeypatch, tmp_path, rules, *, merge=None, corpus_rules=None):
    """Emit a manifest from ``rules``, then build against ``corpus_rules``."""
    atr = write_corpus(tmp_path / "atr", rules)
    report = write_report(tmp_path / "report.json", rules)
    manifest, out = tmp_path / "manifest.json", tmp_path / "hazards.json"
    merge_path = tmp_path / "merge.json"
    merge_path.write_text(json.dumps(merge or {"sources": []}), encoding="utf-8")
    run(builder, monkeypatch, "--report-data", report, "--atr", atr, "--source-rev", REV,
        "--manifest", manifest, "--emit-manifest")
    if corpus_rules is not None:
        atr = write_corpus(tmp_path / "atr2", corpus_rules)
    run(builder, monkeypatch, "--report-data", report, "--atr", atr, "--source-rev", REV,
        "--manifest", manifest, "--merge", merge_path, "--out", out)
    return json.loads(out.read_text(encoding="utf-8"))


RULES = [("ATR-TEST-0001", [r"alpha\d{1,4}", r"bravo\d{1,4}"], "any")]


def test_a_changed_condition_is_refused_even_when_the_count_holds(builder, monkeypatch, tmp_path):
    """The exact substitution the count check cannot see."""
    edited = [("ATR-TEST-0001", [r"alpha\d{1,4}", r"charlie\d{1,4}"], "any")]
    with pytest.raises(SystemExit) as raised:
        build(builder, monkeypatch, tmp_path, RULES, corpus_rules=edited)
    assert "differ from the manifest" in str(raised.value)


def test_a_manifest_from_another_revision_is_refused(builder, monkeypatch, tmp_path):
    atr = write_corpus(tmp_path / "atr", RULES)
    report = write_report(tmp_path / "report.json", RULES)
    manifest = tmp_path / "manifest.json"
    run(builder, monkeypatch, "--report-data", report, "--atr", atr, "--source-rev", REV,
        "--manifest", manifest, "--emit-manifest")
    with pytest.raises(SystemExit) as raised:
        run(builder, monkeypatch, "--report-data", report, "--atr", atr,
            "--source-rev", "a-different-revision", "--manifest", manifest,
            "--out", tmp_path / "hazards.json")
    assert "was emitted for" in str(raised.value)


def test_a_measured_condition_is_fast_and_what_the_loader_derives_is_not(builder, monkeypatch, tmp_path):
    """The sweep timed the rule's own conditions. It never timed their composition.

    Unit e3 found composition is exactly where a rule that looks fast crosses, so
    an alternation built from two fast conditions gets no verdict and falls
    through to the shape screen.
    """
    table = build(builder, monkeypatch, tmp_path, RULES)
    verdicts = {row[0] for row in table["patterns"].values()}
    assert verdicts == {"fast", "inferred-fast"}
    own = sum(1 for row in table["patterns"].values() if row[0] == "fast")
    derived = sum(1 for row in table["patterns"].values() if row[0] == "inferred-fast")
    assert own == 2 and derived == 1, table["patterns"]


def test_a_merged_correction_survives_the_rebuild(builder, monkeypatch, tmp_path):
    """Without this the next regeneration quietly restores the weaker verdict."""
    plain = build(builder, monkeypatch, tmp_path / "plain", RULES)
    assert plain["rules"]["atr:ATR-TEST-0001"][1] == "fast"
    digest = plain["rules"]["atr:ATR-TEST-0001"][0]
    merge = {"sources": [{"key": "replay", "note": "a crossing found by replaying another witness",
                          "rules": {"atr:ATR-TEST-0001": [digest, "slow", 16384, 1.04, True]},
                          "patterns": {}}]}
    merged = build(builder, monkeypatch, tmp_path / "merged", RULES, merge=merge)
    assert merged["rules"]["atr:ATR-TEST-0001"] == [digest, "slow", 16384, 1.04, True]
    assert merged["provenance"]["replay"].startswith("a crossing found")


def test_a_merge_that_would_downgrade_a_measured_crossing_is_refused(builder, monkeypatch, tmp_path):
    """Slow wins in one direction only; a merge file cannot argue a crossing away."""
    slow = [("ATR-TEST-0002", [r"alpha\d{1,4}"], "any")]
    atr = write_corpus(tmp_path / "atr", slow)
    report = tmp_path / "report.json"
    report.write_text(json.dumps({"rule_rows": {"ATR-TEST-0002": {
        "patterns_total": 1, "patterns_measured": 1, "fully_measured": True,
        "cross_1s": True, "cross_60s": True, "rep1": [16384, 2.5, "0" * 64], "rep60": None}}}),
        encoding="utf-8")
    manifest, out = tmp_path / "manifest.json", tmp_path / "hazards.json"
    merge_path = tmp_path / "merge.json"
    run(builder, monkeypatch, "--report-data", report, "--atr", atr, "--source-rev", REV,
        "--manifest", manifest, "--emit-manifest")
    run(builder, monkeypatch, "--report-data", report, "--atr", atr, "--source-rev", REV,
        "--manifest", manifest, "--merge", tmp_path / "absent.json", "--out", out)
    built = json.loads(out.read_text(encoding="utf-8"))
    digest = built["rules"]["atr:ATR-TEST-0002"][0]
    merge_path.write_text(json.dumps({"sources": [{"key": "bad", "note": "n",
                                                   "rules": {"atr:ATR-TEST-0002": [digest, "fast"]},
                                                   "patterns": {}}]}), encoding="utf-8")
    with pytest.raises(SystemExit) as raised:
        run(builder, monkeypatch, "--report-data", report, "--atr", atr, "--source-rev", REV,
            "--manifest", manifest, "--merge", merge_path, "--out", out)
    assert "downgrade a measured slow row" in str(raised.value)


def test_the_shipped_table_is_what_its_inputs_produce(builder, monkeypatch, tmp_path):
    """The builder, its manifest and its merge file must still describe what ships.

    A table nobody can regenerate is a table nobody can check. This runs only
    where the pinned corpus and the round-three report are both present, which is
    the machine that would regenerate it.
    """
    root = Path(__file__).resolve().parents[1]
    corpus = Path("C:/atrx/Agent-Threat-Rule-agent-threat-rules-faf743f")
    report = (root.parent / "agent-startup-thesis" / "research" / "efficacy-2026-09-05"
              / "evidence" / "report_data.json")
    if not (corpus.exists() and report.exists()):
        pytest.skip("the pinned corpus and the round-three report are not on this machine")
    out = tmp_path / "hazards.json"
    run(builder, monkeypatch, "--report-data", report, "--atr", corpus,
        "--manifest", root / "scripts" / "hazards-manifest.json",
        "--merge", root / "scripts" / "hazards-merge.json", "--out", out)
    shipped = json.loads((root / "src" / "agent_defs" / "hazards.json").read_text(encoding="utf-8"))
    rebuilt = json.loads(out.read_text(encoding="utf-8"))
    assert rebuilt["rules"] == shipped["rules"]
    assert rebuilt["patterns"] == shipped["patterns"]
    assert rebuilt["counts"] == shipped["counts"]
