"""Turning a bench measurement into the evidence this hook's arithmetic reads."""
from dataclasses import replace
import json

import pytest

from agent_defs import bundle as bundle_format
from agent_defs.bench import rule_fingerprint
from agent_defs.builtin import STARTER_RULES
from agent_defs.hooks import _claude_code_impl as hook
from agent_defs.lanes import binomial_u95, u95_zero_hits
from agent_defs.model import Lane

TRIALS = 3556


def _row(rule, *, hits=0, trials=TRIALS, surface=None):
    return {"surface": surface or rule.surface.value, "stratum": "all", "trials": trials,
            "hits": hits, "u95": u95_zero_hits(trials) if not hits else 0.5,
            "corpus": "local-claude-unique", "corpus_revision": "abc123",
            "measured_at": "2026-09-06T00:00:00+00:00"}


def _report(rules, *, loud=(), bundle_hits=0, omit=()):
    entries = {}
    for rule in rules:
        if rule.id in omit:
            continue
        hits = dict(loud).get(rule.id, 0)
        entries[rule.id] = {"rule_sha256": rule_fingerprint(rule),
                            "measurements": [_row(rule, hits=hits)]}
    return {"rules": entries,
            "bundle": {"measurements": [_row(rules[0], hits=bundle_hits)],
                       "rule_sha256": {r.id: rule_fingerprint(r) for r in rules},
                       "bundle_ok": False,
                       "failures": ["worst bundle stratum u95=0.950000 exceeds 0.005"],
                       "worst_u95": 0.95}}


@pytest.fixture
def installed(tmp_path):
    """A config whose bundle is a small stand-in for the shipped one."""
    carried = [replace(rule, id=rule.id.replace("builtin:", "atr:"), source="atr")
               for rule in STARTER_RULES]
    path = tmp_path / "bundle.json"
    bundle_format.write(path, carried)
    config = hook.default_config()
    config.update(log_path=str(tmp_path / "log.jsonl"), bundle=str(path), surfaces=["OUT"])
    config_path = tmp_path / "agent-defs.json"
    hook.atomic_json(config_path, config)
    enabled = hook.active_rules(config, hook.hook_rules(config)[0])
    return config_path, enabled


def test_a_clean_report_produces_evidence_the_hook_accepts(installed, tmp_path):
    config_path, enabled = installed
    report = tmp_path / "report.json"
    report.write_text(json.dumps(_report(enabled)), encoding="utf-8")

    result = hook.calibrate_from_report(config_path, report, accept_pooled_bound=True)
    assert result["bundle_hits"] == 0
    assert result["rules_measured"] == len(enabled)
    # bench refused this corpus on its own stricter gate, and the result says so
    # rather than leaving a reader to assume both gates agreed.
    assert result["bench_bundle_ok"] is False

    config = hook.read_config(config_path)
    # The validator compares u95 against the closed form exactly, so evidence
    # copied verbatim from a bisection result would be silently discarded.
    assert hook.measurement(config["evidence"]["bundle"]) is not None
    for stored in config["evidence"]["rules"].values():
        assert hook.measurement(stored) is not None


def test_the_evidence_actually_promotes_when_a_source_asks_for_it(installed, tmp_path):
    config_path, enabled = installed
    report = tmp_path / "report.json"
    report.write_text(json.dumps(_report(enabled)), encoding="utf-8")
    hook.calibrate_from_report(config_path, report, accept_pooled_bound=True)

    config = hook.read_config(config_path)
    rules = hook.hook_rules(config)[0]
    # The default config requests RECORD for every source, and the lane is the
    # lower of what the config asks for and what the measurement allows. So
    # evidence alone changes nothing until somebody opts in.
    assert {lane for lane, _ in hook.effective_lanes(config, hook.active_rules(config, rules)).values()} == {Lane.RECORD}

    config["sources"]["atr"] = "ADVISE"
    lanes = hook.effective_lanes(config, hook.active_rules(config, rules))
    assert {lane for rid, (lane, _) in lanes.items() if rid.startswith("atr:")} == {Lane.ADVISE}
    # builtin was not promoted, so it stays where the config left it.
    assert {lane for rid, (lane, _) in lanes.items() if rid.startswith("builtin:")} == {Lane.RECORD}


def test_a_rule_that_fired_is_transcribed_and_counted(installed, tmp_path):
    config_path, enabled = installed
    report = tmp_path / "report.json"
    report.write_text(json.dumps(_report(enabled, loud={enabled[0].id: 7})), encoding="utf-8")

    result = hook.calibrate_from_report(config_path, report, accept_pooled_bound=True)
    # The bound decides the lane in lanes.admit. Refusing a positive-hit
    # measurement here would be a second policy on top of that one, and would
    # discard a real number rather than making anything safer.
    assert result["rules_that_fired"] == 1
    stored = hook.read_config(config_path)["evidence"]["rules"][enabled[0].id]
    assert stored["hits"] == 7
    assert hook.measurement(stored) is not None


def test_a_stored_bound_is_recomputed_rather_than_trusted(installed, tmp_path):
    config_path, enabled = installed
    report = tmp_path / "report.json"
    report.write_text(json.dumps(_report(enabled, loud={enabled[0].id: 7})), encoding="utf-8")
    hook.calibrate_from_report(config_path, report, accept_pooled_bound=True)

    config = hook.read_config(config_path)
    # Widening a lane by editing one float in a config is the failure this
    # check exists for, and it is caught whether the edit is up or down.
    config["evidence"]["rules"][enabled[0].id]["u95"] = 0.0001
    assert hook.measurement(config["evidence"]["rules"][enabled[0].id]) is None


def test_a_report_that_misses_an_enabled_rule_is_refused(installed, tmp_path):
    config_path, enabled = installed
    report = tmp_path / "report.json"
    report.write_text(json.dumps(_report(enabled, omit=(enabled[-1].id,))), encoding="utf-8")

    # Writing evidence anyway would leave the bundle bound claiming quietness
    # for a rule nothing tested.
    with pytest.raises(ValueError, match="no measurement on their own surface"):
        hook.calibrate_from_report(config_path, report, accept_pooled_bound=True)


def test_a_report_measured_against_different_rules_is_refused(installed, tmp_path):
    config_path, enabled = installed
    document = _report(enabled)
    document["rules"][enabled[0].id]["rule_sha256"] = "0" * 64
    report = tmp_path / "report.json"
    report.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ValueError, match="changed since the report was measured"):
        hook.calibrate_from_report(config_path, report, accept_pooled_bound=True)


def test_the_bundle_bound_carries_its_hits_and_names_the_lane_it_reaches(installed, tmp_path):
    config_path, enabled = installed
    report = tmp_path / "report.json"
    report.write_text(json.dumps(_report(enabled, bundle_hits=1)), encoding="utf-8")

    result = hook.calibrate_from_report(config_path, report, accept_pooled_bound=True)
    assert result["bundle_hits"] == 1
    assert result["u95"] == pytest.approx(binomial_u95(TRIALS, 1))
    assert result["reaches"] == "ADVISE"

    # A bundle loud enough to exceed the advise ceiling reaches nothing, and
    # says so rather than leaving a caller to compare two floats.
    report.write_text(json.dumps(_report(enabled, bundle_hits=40)), encoding="utf-8")
    assert hook.calibrate_from_report(config_path, report, accept_pooled_bound=True)["reaches"] == "RECORD"


def test_calibrate_measures_the_rules_the_hook_will_run(installed, tmp_path):
    config_path, enabled = installed
    corpus = tmp_path / "benign"
    corpus.mkdir()
    (corpus / "a.md").write_text("An ordinary paragraph about the build.", encoding="utf-8")

    result = hook.calibrate(config_path, corpus, "unit fixture")
    config = hook.read_config(config_path)
    # Before this, calibrate measured builtin.STARTER_RULES whatever was
    # installed, so its fingerprint never matched the set the hook enabled.
    assert set(config["evidence"]["rules"]) == {rule.id for rule in enabled}
    assert result["trials"] == 1


def test_promote_refuses_a_lane_the_evidence_does_not_support(installed):
    config_path, _ = installed
    with pytest.raises(ValueError, match="cannot reach ADVISE"):
        hook.promote(config_path, "atr", "ADVISE")


def test_promote_turns_a_measured_source_on_and_says_what_changes(installed, tmp_path):
    config_path, enabled = installed
    report = tmp_path / "report.json"
    report.write_text(json.dumps(_report(enabled)), encoding="utf-8")
    hook.calibrate_from_report(config_path, report, accept_pooled_bound=True)

    result = hook.promote(config_path, "atr", "ADVISE")
    assert result["lane"] == "ADVISE"
    assert result["rules"] == sum(rule.source == "atr" for rule in enabled)
    assert "untrusted data" in result["effect"]
    assert hook.read_config(config_path)["sources"]["atr"] == "ADVISE"


def test_promote_rejects_a_source_with_nothing_enabled(installed):
    config_path, _ = installed
    with pytest.raises(ValueError, match="no enabled rules"):
        hook.promote(config_path, "guardana", "ADVISE")


def test_a_promoted_source_actually_changes_what_the_model_sees(installed, tmp_path):
    config_path, enabled = installed
    report = tmp_path / "report.json"
    report.write_text(json.dumps(_report(enabled)), encoding="utf-8")
    hook.calibrate_from_report(config_path, report, accept_pooled_bound=True)
    hook.promote(config_path, "atr", "ADVISE")

    config = hook.read_config(config_path)
    rules = hook.hook_rules(config)[0]
    attack = next(r for r in enabled if r.source == "atr").examples_positive[0]
    payload = {"hook_event_name": "PostToolUse", "tool_name": "Read",
               "tool_response": {"content": attack}}
    response = hook.process(payload, config, rules)
    assert "untrusted data" in response["hookSpecificOutput"]["additionalContext"]
    # ADVISE informs; it does not remove the text or refuse the call.
    assert "updatedToolOutput" not in response["hookSpecificOutput"]
    assert "permissionDecision" not in response["hookSpecificOutput"]


def _with_failure(rules, text):
    document = _report(rules)
    document["bundle"]["failures"].append(text)
    return document


@pytest.mark.parametrize("failure", [
    "c has 3998 duplicate material units; independence requires review",
    "c missing strata: OUT:exposure=attacker-reachable",
    "some check added after this code was written",
    # Worded so it does not carry the relaxable refusal's own prefix. The first
    # draft of this failure began "worst bundle stratum u95=", which the
    # importer keys its one relaxation on, so an unanswerable comparison would
    # have been waivable by the flag meant for a different disagreement.
    "bundle stratum bound 0.005000 is not resolvable against the 0.005 ceiling in double precision",
], ids=["duplicates", "missing-coverage", "unrecognised", "unresolvable-comparison"])
def test_a_benchmark_refusal_this_importer_cannot_relax_is_fatal(installed, tmp_path, failure):
    config_path, enabled = installed
    report = tmp_path / "report.json"
    report.write_text(json.dumps(_with_failure(enabled, failure)), encoding="utf-8")

    # Repeated material is one observation counted many times and absent
    # coverage is a population nobody sampled, so no choice of statistic
    # repairs either. An unrecognised refusal is fatal for the same reason a
    # new check should not be relaxed by default the day it lands.
    for opted_in in (False, True):
        with pytest.raises(ValueError, match="not one this importer may relax"):
            hook.calibrate_from_report(config_path, report, accept_pooled_bound=opted_in)
        assert hook.read_config(config_path).get("evidence") is None


def test_the_pooled_bound_is_a_choice_somebody_has_to_make(installed, tmp_path):
    config_path, enabled = installed
    report = tmp_path / "report.json"
    report.write_text(json.dumps(_report(enabled)), encoding="utf-8")

    with pytest.raises(ValueError, match="worst per-stratum interval"):
        hook.calibrate_from_report(config_path, report)
    assert hook.read_config(config_path).get("evidence") is None

    result = hook.calibrate_from_report(config_path, report, accept_pooled_bound=True)
    # Zero hits over 3,556 trials bounds at 0.084%, inside the deny ceiling.
    assert result["reaches"] == "DENY"
    # What was relaxed is recorded, so nobody has to recompute which gate the
    # lane is resting on.
    assert hook.read_config(config_path)["evidence"]["bench"]["relaxed"] == [
        "worst bundle stratum u95=0.950000 exceeds 0.005"]


def test_an_aggregate_measured_over_other_rules_is_refused(installed, tmp_path):
    config_path, enabled = installed
    document = _report(enabled)
    # Every per-rule row is current; only the union was measured over a
    # narrower set. The union is what gates the lane.
    document["bundle"]["rule_sha256"] = {enabled[0].id: rule_fingerprint(enabled[0])}
    report = tmp_path / "report.json"
    report.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ValueError, match="does not describe the exact enabled set"):
        hook.calibrate_from_report(config_path, report, accept_pooled_bound=True)

    document["bundle"].pop("rule_sha256")
    report.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ValueError, match="does not describe the exact enabled set"):
        hook.calibrate_from_report(config_path, report, accept_pooled_bound=True)


def test_a_trial_count_past_the_checkable_range_is_refused():
    from dataclasses import asdict

    from agent_defs.model import BenignFiring

    good = asdict(BenignFiring(hook.MAX_TRIALS, 0, binomial_u95(hook.MAX_TRIALS, 0),
                               "c", "2026-09-06T00:00:00+00:00"))
    assert hook.measurement(good) is not None

    # Past this the lgamma coefficient loses enough precision that a
    # recomputation can land on the other side of a lane threshold, so the
    # check would be certifying a number it cannot reproduce.
    over = hook.MAX_TRIALS + 1
    assert hook.measurement(dict(good, trials=over, u95=binomial_u95(over, 0))) is None


@pytest.fixture
def two_surfaces(tmp_path):
    """A bundle enabling IN and OUT, which is what the shipped one now does."""
    from agent_defs.model import Surface

    carried = [replace(rule, id=rule.id.replace("builtin:", "atr:"), source="atr")
               for rule in STARTER_RULES]
    carried[0] = replace(carried[0], surface=Surface.IN)
    path = tmp_path / "bundle.json"
    bundle_format.write(path, carried)
    config = hook.default_config()
    config.update(log_path=str(tmp_path / "log.jsonl"), bundle=str(path), surfaces=["IN", "OUT"])
    config_path = tmp_path / "agent-defs.json"
    hook.atomic_json(config_path, config)
    return config_path, hook.active_rules(config, hook.hook_rules(config)[0])


def _two_surface_report(rules, *, in_bundle_hits, drop_surface=None):
    """Per-rule rows on both surfaces; the union on IN is the loud one."""
    entries = {rule.id: {"rule_sha256": rule_fingerprint(rule),
                         "measurements": [_row(rule, hits=0)]} for rule in rules}
    aggregates = [_row(rules[0], hits=in_bundle_hits, surface="IN"),
                  _row(rules[0], hits=0, surface="OUT")]
    return {"rules": entries,
            "bundle": {"measurements": [a for a in aggregates if a["surface"] != drop_surface],
                       "rule_sha256": {r.id: rule_fingerprint(r) for r in rules},
                       "bundle_ok": False,
                       "failures": ["worst bundle stratum u95=0.950000 exceeds 0.005"],
                       "worst_u95": 0.95}}


def test_a_surface_with_no_union_is_refused_rather_than_skipped(two_surfaces, tmp_path):
    """The union is the measurement, and it cannot be inferred from its parts.

    Every rule can sit inside the ADVISE ceiling while their union sits outside
    it, so a report that carries the per-rule rows and loses one surface's union
    describes a quieter bundle than the one that was measured. Dropping the row
    instead of refusing it let that report promote every rule it covered.
    """
    config_path, enabled = two_surfaces
    assert {r.surface.value for r in enabled} == {"IN", "OUT"}
    report = tmp_path / "report.json"

    # With the IN union present the bundle is too loud for ADVISE.
    report.write_text(json.dumps(_two_surface_report(enabled, in_bundle_hits=60)),
                      encoding="utf-8")
    result = hook.calibrate_from_report(config_path, report, accept_pooled_bound=True)
    assert result["gating_surface"] == "IN"
    assert result["reaches"] == "RECORD"
    assert sorted(result["surfaces"]) == ["IN", "OUT"]

    # Remove only that row. Every fingerprint and per-rule row still matches.
    report.write_text(json.dumps(_two_surface_report(enabled, in_bundle_hits=60,
                                                     drop_surface="IN")), encoding="utf-8")
    with pytest.raises(ValueError, match="no whole-corpus bundle measurement for IN"):
        hook.calibrate_from_report(config_path, report, accept_pooled_bound=True)

    # The refusal has to come before publication, or the config carries evidence
    # for a bundle bound nothing measured.
    assert hook.read_config(config_path)["evidence"]["bundle"]["hits"] == 60


def test_the_bound_carried_forward_is_the_recomputed_one(installed, tmp_path):
    from dataclasses import asdict

    from agent_defs.model import BenignFiring

    exact = binomial_u95(TRIALS, 1)
    nudged = asdict(BenignFiring(TRIALS, 1, exact - 5e-13, "c", "2026-09-06T00:00:00+00:00"))
    accepted = hook.measurement(nudged)
    # Inside the tolerance, so admitted; but the value that reaches a lane
    # comparison is ours, not the one that was stored.
    assert accepted is not None
    assert accepted.u95 == exact
    assert accepted.u95 != nudged["u95"]
