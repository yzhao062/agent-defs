import hashlib
import json
import math
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from agent_defs.bench import (Corpus, Unit, admit_from_report, apply_report, binomial_u95,
                             load_corpus, load_rules, measure, reachability)
from agent_defs.lanes import u95_zero_hits
from agent_defs.model import Lane, PredicateKind, Rule, Surface

FIXTURE = Path(__file__).parent / "fixtures" / "bench"


def rule(rid="quiet", **kwargs):
    fields = dict(id=rid, source="fixture", source_id=rid, source_rev="0" * 40,
                  source_path="rules.json", upstream_url="https://example.invalid/fixture",
                  surface=Surface.CFG, predicate_kind=PredicateKind.SUBSTRING_ANY,
                  predicate=["SENTINEL_POSITIVE"], examples_positive=["SENTINEL_POSITIVE"])
    fields.update(kwargs)
    return Rule(**fields)


def corpus(ordinary=650, security=650, surface=Surface.CFG):
    units = []
    for prose, count in (("ordinary", ordinary), ("security-adjacent", security)):
        for i in range(count):
            text = f"project {prose} material {i}"
            units.append(Unit(f"{prose}/{i}.txt", text, surface,
                              {"file_type": ".txt", "prose": prose},
                              hashlib.sha256(text.encode()).hexdigest(), len(text)))
    return Corpus("synthetic", "0" * 40, tuple(units), "0" * 64, ())


def test_offline_fixture_quiet_reachable_dead_and_loud():
    rules = load_rules(FIXTURE / "rules.json")
    report = measure(rules, [load_corpus(FIXTURE / "corpus")])
    rows = report["rules"]
    assert report["summary"]["rules_run"] == 3
    assert report["summary"]["findings"] == 4  # repeated occurrences count once
    assert rows["quiet"]["reachability"]["status"] == "reachable"
    assert rows["quiet"]["lane"] == "RECORD"  # four fixtures cannot establish precision
    assert rows["dead"]["lane"] == "DO_NOT_SHIP"
    assert rows["loud"]["lane"] == "RECORD"
    assert report["bundle"]["bundle_ok"] is False
    assert report["bundle"]["diagnostic"]["hits"] == 4
    assert report["unmeasured_surfaces"] == ["IN", "OUT", "PIN", "PROMPT"]
    assert report["corpora"][0]["missing_strata"] == []
    assert all(row["corpus_revision"] and row["measured_at"] for row in rows["quiet"]["measurements"])


@pytest.mark.parametrize("n,k", [(1, 0), (10, 0), (598, 0), (2995, 0), (0, 0), (10, 10)])
def test_exact_bound_edges(n, k):
    assert binomial_u95(n, k) == (u95_zero_hits(n) if k == 0 else 1)


@pytest.mark.parametrize("n,k", [(10, 1), (20, 9), (100, 3), (842, 497), (842, 841)])
def test_nonzero_bound_inverts_binomial_cdf(n, k):
    p = binomial_u95(n, k)
    cdf = math.fsum(math.comb(n, j) * p ** j * (1 - p) ** (n - j) for j in range(k + 1))
    assert cdf == pytest.approx(0.05, rel=1e-10)


@pytest.mark.parametrize("n,k", [(-1, 0), (1, 2), (10, -1), (1.0, 0), (True, 0)])
def test_invalid_counts_rejected(n, k):
    with pytest.raises(ValueError):
        binomial_u95(n, k)


@pytest.mark.parametrize("count,lane", [(650, "ADVISE"), (3000, "DENY")])
def test_every_stratum_and_positive_witness_can_earn_lane(count, lane):
    r = rule()
    report = measure([r], [corpus(count, count)])
    assert report["rules"][r.id]["lane"] == lane
    assert admit_from_report(r, json.loads(json.dumps(report)))[0].value == lane
    assert report["bundle"]["bundle_ok"] is True


def test_quiet_rule_in_loud_bundle_stays_record():
    report = measure([rule(), rule("loud", predicate=["project"], examples_positive=["project"])], [corpus()])
    assert report["rules"]["quiet"]["lane"] == "RECORD"
    assert report["bundle"]["measurements"][0]["hits"] <= report["bundle"]["measurements"][0]["trials"]


def test_bundle_union_is_distinct_from_sum_of_rule_hits():
    rules = [rule("a", predicate=["project"]), rule("b", predicate=["project"])]
    report = measure(rules, [corpus(1, 1)])
    assert report["summary"]["findings"] == 4
    assert report["bundle"]["diagnostic"]["hits"] == 2
    overall = next(m for m in report["bundle"]["measurements"] if m["stratum"] == "all")
    assert overall["hits"] == overall["trials"] == 2


def test_bundle_bound_caps_deny_even_when_individual_rule_is_clean():
    c = corpus(4000, 4000)
    # Five scattered hits in each prose stratum: bundle fits ADVISE, not DENY.
    needles = [f"material {i}" for i in (991, 992, 993, 994, 995)]
    noisy = rule("some_hits", predicate=needles, examples_positive=[needles[0]])
    report = measure([rule(), noisy], [c])
    assert report["bundle"]["bundle_ok"] is True
    assert 0.001 < report["bundle"]["worst_u95"] < 0.005
    assert report["rules"]["quiet"]["lane"] == "ADVISE"


def test_pooling_cannot_hide_tiny_security_stratum():
    report = measure([rule()], [corpus(3000, 2)])
    assert report["rules"]["quiet"]["diagnostic"]["u95"] < 0.001
    assert report["rules"]["quiet"]["lane"] == "RECORD"


def test_missing_security_stratum_is_explicit_and_blocks_admission():
    report = measure([rule()], [corpus(3000, 0)])
    assert "CFG:prose=security-adjacent" in report["corpora"][0]["missing_strata"]
    assert report["rules"]["quiet"]["lane"] == "RECORD"


def test_cfg_proxy_does_not_buy_out_evidence_and_second_corpus_is_supported():
    r = rule(surface=Surface.OUT)
    cfg = corpus()
    out = replace(corpus(surface=Surface.OUT), identity="tool-results")
    first = measure([r], [cfg])
    assert first["rules"][r.id]["lane"] == "RECORD"
    assert first["surface_coverage"]["OUT"]["measured"] is False
    second = measure([r], [cfg, out])
    assert second["rules"][r.id]["lane"] == "ADVISE"
    assert second["surface_coverage"]["OUT"]["measured"] is True


def test_unmeasured_enabled_surface_blocks_entire_bundle():
    report = measure([rule(), rule("out", surface=Surface.OUT)], [corpus()])
    assert report["rules"]["quiet"]["lane"] == "RECORD"
    assert "unmeasured enabled surfaces: OUT" in report["bundle"]["failures"]


def test_missing_examples_is_unknown_and_examples_are_unchanged():
    absent = rule(examples_positive=[])
    strict = rule("strict", predicate=["sentinel_positive"], case_sensitive=True)
    result = reachability([absent, strict])
    assert result["quiet"]["status"] == "no_examples"
    assert result["strict"]["status"] == "unreachable"
    report = measure([absent], [corpus()])
    assert report["rules"]["quiet"]["lane"] == "RECORD"


def test_invalid_or_unsupported_rules_are_not_quiet_successes():
    rules = [rule("unsafe", predicate_kind=PredicateKind.REGEX, predicate="(a+)+$"),
             rule("structured", predicate_kind=PredicateKind.STRUCTURED, predicate={"all": []}),
             rule("none", predicate_kind=PredicateKind.NONE, predicate=None, not_runnable_reason="reference"),
             rule("malformed", predicate="a string is not a list")]
    report = measure(rules, [corpus(1, 1)])
    assert report["summary"]["rules_run"] == 0
    assert all(row["lane"] == "DO_NOT_SHIP" and row["diagnostic"]["trials"] == 0 for row in report["rules"].values())


def test_complete_payload_scanned_beyond_hook_byte_cap():
    c = corpus(1, 1)
    text = "x" * 300_000 + "SENTINEL_POSITIVE"
    first = replace(c.units[0], text=text, size_bytes=len(text), sha256=hashlib.sha256(text.encode()).hexdigest())
    report = measure([rule()], [replace(c, units=(first, c.units[1]))])
    assert report["rules"]["quiet"]["diagnostic"]["hits"] == 1


def test_duplicate_material_does_not_inflate_admission():
    c = corpus()
    duplicate = replace(c.units[0], id="duplicate.txt")
    report = measure([rule()], [replace(c, units=c.units + (duplicate,))])
    assert report["corpora"][0]["duplicate_units"] == 1
    assert report["bundle"]["bundle_ok"] is False


def test_changed_rule_cannot_reuse_report():
    r = rule()
    report = measure([r], [corpus(1, 1)])
    with pytest.raises(ValueError, match="stale report"):
        admit_from_report(replace(r, predicate=["different"]), report)


def test_apply_report_requires_exact_bundle_and_attaches_native_measurement():
    rules = [rule(), rule("second")]
    report = measure(rules, [corpus()])
    assigned = apply_report(rules, report)
    assert all(r.lane is Lane.ADVISE and r.benign.trials == 650 for r in assigned)
    with pytest.raises(ValueError, match="exact bundle"):
        apply_report(rules[:1], report)


def test_incomplete_evaluation_aborts_instead_of_reporting_zero(monkeypatch):
    from agent_defs import bench
    from agent_defs.evaluate import ScanResult

    monkeypatch.setattr(bench, "scan_trusted", lambda *a, **kw: ScanResult((), 0, 1, 0, False))
    with pytest.raises(RuntimeError, match="incomplete benchmark"):
        measure([rule()], [corpus(1, 1)])


def test_duplicate_ids_rejected():
    with pytest.raises(ValueError, match="duplicate rule"):
        measure([rule(), rule()], [corpus(1, 1)])


def test_cli_runs_offline_and_writes_json(tmp_path):
    output = tmp_path / "report.json"
    result = subprocess.run([sys.executable, "-m", "agent_defs.bench", "measure", "--corpus", str(FIXTURE / "corpus"),
                             "--rules", str(FIXTURE / "rules.json"), "--out", str(output)],
                            env={**os.environ, "PYTHONPATH": str(Path(__file__).parents[1] / "src")}, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert json.loads(output.read_text())["rules"]["dead"]["lane"] == "DO_NOT_SHIP"


def test_manifest_rejects_escape_and_changed_bytes(tmp_path):
    (tmp_path / "payload.txt").write_text("changed")
    manifest = {"identity": "fixture", "revision": "0" * 40,
                "units": [{"path": "../outside.txt", "sha256": "0" * 64}]}
    path = tmp_path / "corpus.json"
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="escapes"):
        load_corpus(tmp_path)
    manifest["units"][0]["path"] = "payload.txt"
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="digest mismatch"):
        load_corpus(tmp_path)
