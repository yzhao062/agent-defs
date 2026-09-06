"""The calibration gate's pins and its refusals, offline.

Every test here runs without the ATR corpora and without network. The one test
that scores the real figures is gated on AGENT_DEFS_CALIBRATION_WORKDIR and says
what to run when it is unset:

    PYTHONPATH=src python scripts/calibration_gate.py prepare --workdir W
    AGENT_DEFS_CALIBRATION_WORKDIR=W PYTHONPATH=src \
        python -m pytest tests/test_calibration_gate.py -q
"""

from dataclasses import replace
import importlib.util
import json
import os
from pathlib import Path
import sys

import pytest

from agent_defs.model import PredicateKind, Rule, Surface


spec = importlib.util.spec_from_file_location(
    "calibration_gate", Path(__file__).resolve().parents[1] / "scripts/calibration_gate.py")
gate = importlib.util.module_from_spec(spec)
# dataclasses resolves annotations through sys.modules, so register before exec.
sys.modules[spec.name] = gate
spec.loader.exec_module(gate)


def rule(rid, predicate, surface=Surface.CFG):
    return Rule(id=f"atr:{rid}", source="atr", source_id=rid, source_rev="0" * 40,
                source_path=f"rules/{rid}.yaml", upstream_url="https://example.invalid/fixture",
                surface=surface, predicate_kind=PredicateKind.SUBSTRING_ANY,
                predicate=[predicate], examples_positive=[predicate])


def snapshot(workdir, figure, bodies=None):
    """Write a snapshot that satisfies the pin, so a test can break one thing."""
    root = gate.snapshot_root(workdir, figure)
    (root / "rules").mkdir(parents=True)
    bodies = bodies if bodies is not None else [f"id: R{i}\n" for i in range(figure.rule_count)]
    for index, body in enumerate(bodies):
        (root / "rules" / f"{index:05d}.yaml").write_text(body, encoding="utf-8")
    (root / "SOURCE_REV").write_text(figure.executed_revision + "\n", encoding="utf-8")
    return root


def pinned_to(figure, root):
    digest, count = gate.rules_digest(root)
    return replace(figure, rules_digest=digest, rule_count=count)


# --------------------------------------------------------------------------
# The pins themselves
# --------------------------------------------------------------------------


def test_four_figures_each_carry_a_revision_a_rule_count_and_a_corpus():
    assert [f.key for f in gate.FIGURES] == ["self_test", "external_pint", "skill_md", "concentration"]
    for figure in gate.FIGURES:
        assert len(figure.executed_revision) == 40 and len(figure.measured_at_revision) == 40
        assert len(figure.rules_tree) == 40 and len(figure.rules_digest) == 64
        assert figure.rule_count > 0 and figure.claims
        assert figure.samples == figure.attacks + figure.benign
        assert figure.corpus in gate._CORPUS_LOADERS
        assert len(figure.corpus_digest) == 64


def test_the_four_rule_counts_and_revisions_are_the_ones_e4_recovered():
    pins = {f.key: (f.executed_revision[:7], f.rule_count, f.samples) for f in gate.FIGURES}
    assert pins == {
        "self_test": ("c815748", 652, 341),
        "external_pint": ("c815748", 652, 850),
        "skill_md": ("a8a4146", 108, 498),
        "concentration": ("1002d9d", 71, 850),
    }
    assert gate.SELF_TEST.measured_at_revision.startswith("74278ec4")


def test_the_criteria_are_the_preregistered_ones():
    assert (gate.TOLERANCE_POINTS, gate.SEVERE_GAP_POINTS, gate.MIN_AGREEING_FIGURES) == (5.0, 10.0, 3)


def test_no_figure_is_pinned_to_the_revision_this_package_ships():
    for figure in gate.FIGURES:
        assert figure.executed_revision != gate.PIN_REVISION
        assert figure.measured_at_revision != gate.PIN_REVISION


# --------------------------------------------------------------------------
# Refusals: a figure that cannot be reached never becomes an agreement
# --------------------------------------------------------------------------


def test_a_snapshot_holding_todays_tree_is_refused_by_name(tmp_path):
    figure = gate.CONCENTRATION
    root = snapshot(tmp_path, figure)
    (root / "SOURCE_REV").write_text(gate.PIN_REVISION + "\n", encoding="utf-8")
    with pytest.raises(gate.Unreachable, match="today's tree"):
        gate.verify_snapshot(root, figure)


def test_a_snapshot_at_the_wrong_revision_is_refused(tmp_path):
    figure = gate.CONCENTRATION
    root = snapshot(tmp_path, figure)
    (root / "SOURCE_REV").write_text("b" * 40 + "\n", encoding="utf-8")
    with pytest.raises(gate.Unreachable, match=figure.executed_revision):
        gate.verify_snapshot(root, figure)


def test_a_snapshot_with_the_wrong_rule_count_is_refused(tmp_path):
    figure = gate.CONCENTRATION
    root = snapshot(tmp_path, figure, bodies=["id: R\n"] * (figure.rule_count - 1))
    with pytest.raises(gate.Unreachable, match=f"pinned at {figure.rule_count} rules"):
        gate.verify_snapshot(root, figure)


def test_a_snapshot_with_edited_rule_text_is_refused(tmp_path):
    figure = gate.CONCENTRATION
    root = snapshot(tmp_path, figure)
    exact = pinned_to(figure, root)
    gate.verify_snapshot(root, exact)
    (root / "rules" / "00000.yaml").write_text("id: R0 edited\n", encoding="utf-8")
    with pytest.raises(gate.Unreachable, match="rule content digest"):
        gate.verify_snapshot(root, exact)


def test_a_snapshot_without_a_source_rev_is_refused(tmp_path):
    figure = gate.CONCENTRATION
    root = snapshot(tmp_path, figure)
    (root / "SOURCE_REV").unlink()
    with pytest.raises(gate.Unreachable, match="no SOURCE_REV"):
        gate.verify_snapshot(root, figure)


def test_a_missing_snapshot_is_refused(tmp_path):
    with pytest.raises(gate.Unreachable, match="run prepare"):
        gate.verify_snapshot(tmp_path / "absent", gate.SKILL_MD)


@pytest.mark.parametrize("damage, message", [
    ("count", "samples/attacks/benign"),
    ("text", "corpus digest"),
])
def test_a_corpus_that_is_not_the_pinned_one_is_refused(damage, message):
    samples = [{"id": "a", "text": "one", "expectedDetection": True},
               {"id": "b", "text": "two", "expectedDetection": False}]
    figure = replace(gate.CONCENTRATION, samples=2, attacks=1, benign=1,
                     corpus_digest=gate.corpus_digest(samples))
    gate.verify_corpus(samples, figure)
    damaged = samples[:1] if damage == "count" else [samples[0], {**samples[1], "text": "three"}]
    with pytest.raises(gate.Unreachable, match=message):
        gate.verify_corpus(damaged, figure)


def test_an_empty_workdir_fails_the_gate_with_four_unreachable_figures(tmp_path):
    report = gate.run(tmp_path)
    assert report["status"] == "FAIL"
    assert report["agreements"] == 0
    assert report["unreachable_figures"] == [f.key for f in gate.FIGURES]
    for figure in report["figure_reports"]:
        assert figure["status"] == "unreachable" and figure["agrees"] is False
        assert "run prepare" in figure["unreachable_reason"]
        # An unreachable figure reports no number of ours at all, in either direction.
        assert all(row["ours"] is None and row["gap_points"] is None for row in figure["claims"])
        assert all(not row["within_tolerance"] for row in figure["claims"])
        assert "measurement" not in figure


def test_the_cli_separates_an_unreachable_run_from_a_disagreeing_one(tmp_path, capsys):
    assert gate.main(["run", "--workdir", str(tmp_path), "--out", str(tmp_path / "r.json")]) == 3
    printed = capsys.readouterr().out
    assert "UNREACHABLE" in printed and "FAIL" in printed
    saved = json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))
    assert saved["unreachable_figures"]


def test_prepare_refuses_to_invent_history_without_network(tmp_path):
    with pytest.raises(gate.Unreachable, match="network is disabled"):
        gate.prepare(tmp_path, allow_network=False)


def test_the_report_says_what_our_number_is_and_where_the_semantics_seam_sits(tmp_path):
    report = gate.run(tmp_path)
    assert "raw-text product path" in report["method"]["our_number"]
    assert "recorded and not used" in report["method"]["our_number"]
    assert "our_findings" in report["method"]["seam"]
    assert "never our own top rule's" in report["method"]["counting"]
    assert report["prepared"] is None
    (tmp_path / "calibration-prepare.json").write_text(json.dumps({"snapshots": ["x"]}), encoding="utf-8")
    assert gate.run(tmp_path)["prepared"] == {"snapshots": ["x"]}


def test_the_figures_subcommand_prints_the_pins_without_any_corpus(capsys):
    assert gate.main(["figures"]) == 0
    printed = json.loads(capsys.readouterr().out)
    assert [row["figure"] for row in printed] == [f.key for f in gate.FIGURES]
    assert printed[0]["measured_at_revision"].startswith("74278ec4")
    assert {c["certification"] for row in printed for c in row["claims"]} == {"corroborated", "uncertifiable"}


# --------------------------------------------------------------------------
# Reporting: our number, upstream's, the gap, and the rule count beside it
# --------------------------------------------------------------------------


@pytest.mark.parametrize("ours, within, severe", [
    (63.6, True, False), (68.6, True, False), (58.6, True, False),
    (68.7, False, False), (74.0, False, True), (25.06, False, True),
])
def test_gap_arithmetic_and_the_two_thresholds(ours, within, severe):
    claim = gate.EXTERNAL_PINT.claims[0]
    row = gate._claim_row(claim, ours, gate.EXTERNAL_PINT.rule_count)
    assert row["upstream_published"] == 63.6
    assert row["gap_points"] == pytest.approx(ours - 63.6)
    assert row["rule_count"] == 652
    assert (row["within_tolerance"], row["severe"]) == (within, severe)


def test_a_metric_the_harness_cannot_produce_is_a_failure_not_a_blank():
    row = gate._claim_row(gate.SKILL_MD.claims[1], None, 108)
    assert row["ours"] is None and row["within_tolerance"] is False and row["severe"] is True


def test_the_uncertifiable_six_of_seventy_one_claim_is_recorded_not_taken_literally():
    active, dominant = gate.CONCENTRATION.claims
    assert active.certification == dominant.certification == "uncertifiable"
    assert active.published == pytest.approx(6 / 71 * 100)
    assert active.reproducible == pytest.approx(5 / 71 * 100)
    assert "five regex rules fire" in active.reproducible_statement
    assert "61-rule run" in active.uncertifiable_reason
    assert "tier2.5-embedding-match" in active.uncertifiable_reason
    assert dominant.published_is_floor is True
    assert dominant.reproducible == 97.89
    assert "278" in dominant.reproducible_statement and "97.89" in dominant.reproducible_statement
    row = gate._claim_row(active, 10 / 71 * 100, 71)
    assert row["gap_points"] == pytest.approx(4 / 71 * 100)
    assert row["gap_points_vs_reproducible"] == pytest.approx(5 / 71 * 100)
    assert row["within_tolerance"] is False


def test_every_published_claim_carries_its_quote_and_an_upstream_reference():
    for figure in gate.FIGURES:
        for claim in figure.claims:
            assert claim.quote.strip() and claim.upstream_reference.strip()
            assert claim.certification in {"corroborated", "uncertifiable"}
            if claim.certification == "uncertifiable":
                assert claim.reproducible is not None and claim.uncertifiable_reason


def test_the_recorded_baseline_is_e4s_and_names_its_three_causes():
    baseline = gate.RECORDED_BASELINE
    assert baseline["measured_at"] == "2026-09-05"
    assert baseline["figures"]["external_pint"]["recall"] == 25.06
    assert baseline["figures"]["skill_md"]["false_positive_rate"] == 95.49
    assert baseline["figures"]["concentration"]["dominant_rule_share"] == 0.0
    assert len(baseline["located_causes"]) == 3
    assert any("4,096" in cause for cause in baseline["located_causes"])
    assert any("scanSkill" in cause for cause in baseline["located_causes"])
    assert any("UTF-16" in cause for cause in baseline["located_causes"])


# --------------------------------------------------------------------------
# Measurement semantics
# --------------------------------------------------------------------------


def test_the_pint_port_trims_deduplicates_and_numbers_from_the_raw_index(tmp_path):
    root = tmp_path / "snap"
    (root / "data/pint-benchmark").mkdir(parents=True)
    (root / "data/pint-benchmark/pint-corpus.json").write_text(json.dumps([
        {"text": "  attack one  ", "label": True, "category": "jailbreak", "source": "s", "language": "en"},
        {"text": "   ", "label": True, "category": "jailbreak", "source": "s", "language": "en"},
        {"text": "ATTACK ONE", "label": True, "category": "jailbreak", "source": "s", "language": "en"},
        {"text": "benign two", "label": False, "category": "chat", "source": "s", "language": "en"},
        {"text": "not an attack", "label": "true", "category": "jailbreak", "source": "s", "language": "en"},
        {"text": " nbsp trimmed﻿", "label": True, "category": "jailbreak", "source": "s", "language": "de"},
    ]), encoding="utf-8")
    samples = gate.load_pint(root)
    assert [s["id"] for s in samples] == ["pint-0001", "pint-0004", "pint-0005", "pint-0006"]
    assert [s["text"] for s in samples] == ["attack one", "benign two", "not an attack", "nbsp trimmed"]
    # Only label true counts as an attack; the string "true" does not.
    assert [s["expectedDetection"] for s in samples] == [True, False, False, True]
    assert all(s["event_type"] == "llm_input" for s in samples)


def test_the_named_rule_is_scored_and_our_own_top_rule_never_stands_in_for_it():
    figure = replace(gate.CONCENTRATION, rule_count=71, named_rule="ATR-2026-001")
    rules = [rule("ATR-2026-051", "override"), rule("ATR-2026-072", "leak")]
    samples = [{"id": f"s{i}", "text": text, "expectedDetection": True,
                "event_type": "llm_input", "scan_target": None, "fields": {}}
               for i, text in enumerate(["override now", "override again", "leak it"])]
    measured = gate.measure(samples, rules, figure)
    assert measured["rules_fired"] == 2
    assert measured["active_rule_fraction"] == pytest.approx(2 / 71 * 100)
    assert measured["total_rule_matches"] == 3
    # The named rule is absent from the bundle, so its share is zero. Our own
    # top rule carries 2 of 3 and is reported separately, never as the comparison.
    assert measured["named_rule_matches"] == 0
    assert measured["dominant_rule_share"] == 0.0
    assert measured["observed_top_rule_share"] == pytest.approx(200 / 3)
    assert measured["top_rules"][0] == {"rule": "ATR-2026-051", "matches": 2}


def test_measure_counts_a_confusion_matrix_over_whole_samples():
    figure = replace(gate.SKILL_MD, named_rule=None)
    rules = [rule("ATR-2026-00001", "bad")]
    samples = [
        {"id": "tp", "text": "bad thing", "expectedDetection": True, "event_type": None,
         "scan_target": "skill", "fields": {}},
        {"id": "fn", "text": "quiet", "expectedDetection": True, "event_type": None,
         "scan_target": "skill", "fields": {}},
        {"id": "fp", "text": "bad joke", "expectedDetection": False, "event_type": None,
         "scan_target": "skill", "fields": {}},
        {"id": "tn", "text": "fine", "expectedDetection": False, "event_type": None,
         "scan_target": "skill", "fields": {}},
    ]
    measured = gate.measure(samples, rules, figure)
    assert (measured["tp"], measured["fn"], measured["fp"], measured["tn"]) == (1, 1, 1, 1)
    assert measured["recall"] == 50.0 and measured["precision"] == 50.0
    assert measured["false_positive_rate"] == 50.0
    assert measured["dominant_rule_share"] is None


def test_the_corpus_digest_ignores_key_order_and_unscored_fields():
    a = [{"id": "x", "text": "t", "expectedDetection": True, "fields": {"language": "en"}}]
    b = [{"expectedDetection": 1, "text": "t", "id": "x", "fields": {}}]
    assert gate.corpus_digest(a) == gate.corpus_digest(b)
    assert gate.corpus_digest(a) != gate.corpus_digest([{**a[0], "text": "u"}])


def test_render_shows_every_claim_with_its_rule_count(tmp_path):
    text = gate.render(gate.run(tmp_path))
    assert text.splitlines()[0].endswith("FAIL")
    for figure in gate.FIGURES:
        for claim in figure.claims:
            assert any(figure.key in line and claim.metric in line and str(figure.rule_count) in line
                       for line in text.splitlines())
    assert "reproducible form is" in text


# --------------------------------------------------------------------------
# The gate itself, against prepared corpora
# --------------------------------------------------------------------------


@pytest.fixture(scope="module")
def prepared_workdir():
    workdir = os.environ.get("AGENT_DEFS_CALIBRATION_WORKDIR")
    if not workdir:
        pytest.skip("Set AGENT_DEFS_CALIBRATION_WORKDIR to a directory built by "
                    "'calibration_gate.py prepare' to run the four-figure gate. It needs the ATR "
                    "corpora, including malicious skill samples, so it belongs on Linux.")
    return Path(workdir)


def test_the_gate_reaches_every_figure_and_reports_a_gap_for_each(prepared_workdir):
    report = gate.run(prepared_workdir)
    assert report["unreachable_figures"] == [], report["figure_reports"]
    assert len(report["figure_reports"]) == 4
    for figure in report["figure_reports"]:
        assert figure["status"] == "measured"
        assert figure["loader"]["loaded"] == next(
            f.rule_count for f in gate.FIGURES if f.key == figure["figure"])
        for row in figure["claims"]:
            assert row["ours"] is not None and row["gap_points"] is not None
            assert row["rule_count"] == figure["rule_count"]
        assert figure["agrees"] == all(row["within_tolerance"] for row in figure["claims"])
    assert report["status"] == ("PASS" if report["agreements"] >= 3 else "FAIL")
