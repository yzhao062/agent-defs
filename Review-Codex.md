<!-- Round 1 -->

Verification notes:

All shell commands below ran in C:/Users/yuezh/PycharmProjects/agent-defs with the prescribed Python interpreter. Root AGENTS.md and AGENTS.local.md were absent; the supplied instructions applied. No implementation file, installed configuration, Git index entry, commit, or remote was changed by this review.

1. Read the staged scope with `git diff --cached -- . ':!src/agent_defs/bundle.json'`, exit 0. The generated artifact was reviewed through its metadata and builder, not by reading its 206 rule rows. Final scope checks completed with exit 0: no whitespace errors and all 14 reviewed working files matched the index.

<details>
<summary>Exact final scope commands</summary>

~~~powershell
git diff --cached --check
git diff --exit-code -- . ':!Review-Codex.md'
@'
import json
import subprocess
raw = subprocess.check_output(["git", "diff", "--cached", "--name-only"])
paths = raw.decode().splitlines()
assert len(paths) == 14, paths
assert subprocess.run(["git", "diff", "--quiet", "--", *paths]).returncode == 0
print("All 14 reviewed working files match the index.")
'@ | & 'C:\Users\yuezh\miniforge3\envs\py312\python.exe' -
~~~

</details>

2. The initial command `& 'C:\Users\yuezh\miniforge3\envs\py312\python.exe' -m pytest -q` completed with exit 1: 24 collection errors because agent_defs was not on the import path. Correcting the checkout import path, without installing or changing configuration, produced **599 passed, 6 skipped, 1 warning in 37.78 s**, exit 0. The warning was the existing possible nested regex set in test_evaluate_adversarial.py.

~~~powershell
$env:PYTHONPATH = 'C:\Users\yuezh\PycharmProjects\agent-defs\src'
& 'C:\Users\yuezh\miniforge3\envs\py312\python.exe' -m pytest -q
~~~

3. The metadata check completed with exit 0. The staged artifact declares 206 shipped OUT rules, 206 reachable rules, revision faf743fee8a5018467959ec8ea7ccdb1a1aab333, and 793 loaded records. Shipped plus drop counts equals 793. Its 14 held-back entries match scripts/bundle-held-back.json; 11 were counted under measured_loud. Earlier filters precede that counter, so 14 entries versus 11 drops is not itself an arithmetic defect. The metadata records that the scanner self-check has not run.

<details>
<summary>Exact metadata command</summary>

~~~powershell
@'
import json
import subprocess
from pathlib import Path
def metadata(raw):
    prefix = raw.split(b' "rules": [', 1)[0]
    assert prefix != raw
    return json.loads(prefix.rstrip().rstrip(b",") + b"\n}")
old = metadata(subprocess.check_output(["git", "show", "HEAD:src/agent_defs/bundle.json"]))
new = metadata(subprocess.check_output(["git", "show", ":src/agent_defs/bundle.json"]))
for name, data in [("HEAD", old), ("staged", new)]:
    print(name, json.dumps({key: data.get(key) for key in
        ["source_rev", "shipped", "loaded", "surfaces", "reachability", "dropped", "scanner_self_check"]}))
held = json.loads(Path("scripts/bundle-held-back.json").read_text(encoding="utf-8"))
assert held == new["held_back"]
assert new["shipped"] + sum(new["dropped"].values()) == new["loaded"]
assert new["reachability"] == {"reachable": 206}
print("metadata verified; held-back entries:", len(held), "; measured_loud drops:", new["dropped"]["measured_loud"])
'@ | & 'C:\Users\yuezh\miniforge3\envs\py312\python.exe' -
~~~

</details>

4. Controlled admission, report, split, build-trimming, and independent numerical probes completed with exit 0. They used synthetic fixtures and temporary configurations, not installed settings. Results:

- An unmodified bench report over 4,000 units containing 3,998 duplicates was refused by bench only for duplicates. Import nevertheless reached DENY; promote succeeded; process withheld the matching string.
- A report missing its required attacker-reachable stratum likewise imported and promoted to DENY.
- Replacing an eight-rule report's aggregate with a genuine one-rule aggregate from the same corpus changed the imported ceiling from ADVISE to DENY. The actual union was 8 hits; the substituted union was 2. The aggregate fingerprint named only one enabled rule.
- Synthetic 1-hit/1,743-unit evidence refused DENY promotion without changing configuration. A direct DENY request still yielded ADVISE and additionalContext only.
- Missing-rule and stale-rule reports raised ValueError and preserved configuration bytes.
- With valid rule evidence and bundle=None, all lanes were RECORD and no exception occurred. An ADVISE bundle capped individually DENY-eligible rules at ADVISE.
- Twenty distinct results from one synthetic session split 9/11 across the digest halves.
- The build trim fixture preserved the predicate, removed sample fields and raw upstream extras, and retained correct reachability counts and example hashes.
- SciPy agreed with binomial_u95(1743, 1) to 6.27e-16 absolute error. Larger-count counterexamples appear in N5.

<details>
<summary>Exact controlled verification command</summary>

~~~powershell
$env:PYTHONPATH = 'C:\Users\yuezh\PycharmProjects\agent-defs\src'
@'
import contextlib
import copy
from dataclasses import replace
import hashlib
import importlib.util
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from scipy.stats import beta
from agent_defs import bench, bundle as bundle_format
from agent_defs.builtin import STARTER_RULES
from agent_defs.hooks import _claude_code_impl as hook
from agent_defs.lanes import binomial_u95
from agent_defs.model import Lane

results = {}
def unit(i, text, prose=None):
    raw = text.encode("utf-8")
    return bench.Unit(str(i), text, STARTER_RULES[0].surface,
                      {"file_type": "tool-result", "prose": prose or ("ordinary" if i % 2 else "security-adjacent")},
                      hashlib.sha256(raw).hexdigest(), len(raw))

def corpus(name, units, required=()):
    return bench.Corpus(name, "a" * 40, tuple(units), "b" * 64, required)

with TemporaryDirectory(prefix="agent-defs-review-") as tmp:
    root = Path(tmp)
    bundle_path = root / "bundle.json"
    bundle_format.write(bundle_path, [
        replace(rule, id=rule.id.replace("builtin:", "atr:"), source="atr")
        for rule in STARTER_RULES])
    config_path = root / "config.json"
    baseline = hook.default_config()
    baseline.update(bundle=str(bundle_path), surfaces=["OUT"], log_path=str(root / "log.jsonl"))
    hook.atomic_json(config_path, baseline)
    enabled = hook.active_rules(baseline, hook.hook_rules(baseline)[0])

    def import_report(report):
        hook.atomic_json(config_path, baseline)
        report_path = root / "report.json"
        report_path.write_text(json.dumps(report), encoding="utf-8")
        return hook.calibrate_from_report(config_path, report_path)

    duplicate_report = bench.measure(enabled, [corpus(
        "duplicate-probe", [unit(i, "Ordinary text " + str(i % 2)) for i in range(4000)])])
    imported = import_report(duplicate_report)
    promoted = hook.promote(config_path, "atr", "DENY")
    response = hook.process(
        {"hook_event_name": "PostToolUse", "tool_response": STARTER_RULES[0].examples_positive[0]},
        hook.read_config(config_path), hook.hook_rules(baseline)[0])
    assert promoted["lane"] == "DENY"
    assert "updatedToolOutput" in response["hookSpecificOutput"]
    results["duplicate_corpus"] = {
        "failures": duplicate_report["bundle"]["failures"],
        "duplicate_units": duplicate_report["corpora"][0]["duplicate_units"],
        "import_reaches": imported["reaches"], "promoted": promoted["lane"],
        "process_withheld": response["hookSpecificOutput"]["updatedToolOutput"] == hook.WITHHELD}

    missing_report = bench.measure(enabled, [corpus(
        "missing-stratum-probe", [unit(i, f"Ordinary unique result {i}") for i in range(4000)],
        ("exposure=attacker-reachable",))])
    imported = import_report(missing_report)
    results["missing_required_stratum"] = {
        "failures": missing_report["bundle"]["failures"],
        "import_reaches": imported["reaches"],
        "promoted": hook.promote(config_path, "atr", "DENY")["lane"]}

    materials = [unit(i, (STARTER_RULES[i // 2].examples_positive[0] + f" Case {i}")
                      if i < 8 else f"Ordinary unique result {i}") for i in range(10000)]
    measured_corpus = corpus("union-probe", materials)
    full = bench.measure(enabled, [measured_corpus])
    subset = bench.measure([enabled[0]], [measured_corpus])
    original_import = import_report(full)
    stale = copy.deepcopy(full)
    stale["bundle"] = subset["bundle"]
    imported = import_report(stale)
    results["stale_aggregate"] = {
        "true_union_hits": next(row["hits"] for row in full["bundle"]["measurements"] if row["stratum"] == "all"),
        "true_reaches": original_import["reaches"],
        "substituted_union_hits": next(row["hits"] for row in subset["bundle"]["measurements"] if row["stratum"] == "all"),
        "aggregate_rule_count": len(stale["bundle"]["rule_sha256"]),
        "enabled_rule_count": len(enabled),
        "import_reaches": imported["reaches"],
        "promoted": hook.promote(config_path, "atr", "DENY")["lane"]}

    heldout = bench.measure(enabled, [corpus("heldout-probe", [
        unit(i, STARTER_RULES[0].examples_positive[0] if i == 0 else f"Ordinary unique result {i}")
        for i in range(1743)])])
    imported = import_report(heldout)
    hook.promote(config_path, "atr", "ADVISE")
    before = config_path.read_bytes()
    try:
        hook.promote(config_path, "atr", "DENY")
        raise AssertionError("DENY unexpectedly accepted")
    except ValueError as exc:
        denial = str(exc)
    assert config_path.read_bytes() == before
    config = hook.read_config(config_path)
    config["sources"]["atr"] = "DENY"
    lanes = hook.effective_lanes(config, enabled)
    response = hook.process(
        {"hook_event_name": "PostToolUse", "tool_response": STARTER_RULES[0].examples_positive[0]},
        config, hook.hook_rules(config)[0])
    results["heldout_ceiling"] = {
        "u95": imported["u95"], "DENY_refusal": denial, "config_unchanged": True,
        "atr_lanes_when_DENY_requested": sorted({lane.value for rid, (lane, _) in lanes.items() if rid.startswith("atr:")}),
        "advice_only": "additionalContext" in response["hookSpecificOutput"] and
                       "updatedToolOutput" not in response["hookSpecificOutput"]}
    assert results["heldout_ceiling"]["advice_only"]

    for name, transform in [
        ("missing_rule", lambda report: report["rules"].pop(enabled[-1].id)),
        ("stale_rule", lambda report: report["rules"][enabled[-1].id].update(rule_sha256="0" * 64))]:
        report = copy.deepcopy(heldout)
        transform(report)
        hook.atomic_json(config_path, baseline)
        before = config_path.read_bytes()
        try:
            import_report(report)
            raise AssertionError("bad report accepted")
        except ValueError as exc:
            results[name] = {"refused": str(exc), "config_unchanged": config_path.read_bytes() == before}

    config = hook.read_config(config_path)
    quiet = dict(trials=4000, hits=0, u95=binomial_u95(4000, 0),
                 corpus="probe", measured_at="2026-09-06T00:00:00Z")
    config["sources"]["atr"] = "DENY"
    config["evidence"] = {"fingerprint": hook.fingerprint(enabled, config["surfaces"]),
                          "rules": {rule.id: dict(quiet) for rule in enabled}, "bundle": None}
    assert {lane for lane, _ in hook.effective_lanes(config, enabled).values()} == {Lane.RECORD}
    config["evidence"]["bundle"] = dict(trials=1743, hits=1, u95=binomial_u95(1743, 1),
                                        corpus="probe", measured_at="2026-09-06T00:00:00Z")
    results["indirect_DENY_guard"] = {
        "absent_bundle_all_RECORD": True,
        "quiet_rules_with_ADVISE_bundle": sorted({lane.value for rid, (lane, _) in hook.effective_lanes(config, enabled).items() if rid.startswith("atr:")})}

    script_path = Path("scripts/split_traffic_corpus.py")
    spec = importlib.util.spec_from_file_location("review_split", script_path)
    splitter = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(splitter)
    groups = {0: [], 1: []}
    for i in range(20):
        groups[splitter.half(hashlib.sha256(f"same session result {i}".encode()).hexdigest(),
                             "agent-defs-split-v1")].append(i)
    results["same_session_digest_split"] = {str(part): len(rows) for part, rows in groups.items()}
    assert all(groups.values())

    spec = importlib.util.spec_from_file_location("review_build", Path("scripts/build_bundle.py"))
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    sample = replace(STARTER_RULES[0], extra={"upstream": "sample", "upstream_yaml": "sample", "preserved": True})
    trimmed, reach = builder.trim([sample])
    assert not trimmed[0].examples_positive and not trimmed[0].examples_negative
    assert "upstream" not in trimmed[0].extra and "upstream_yaml" not in trimmed[0].extra
    assert trimmed[0].predicate == sample.predicate
    assert trimmed[0].extra["reachability"]["example_sha256"] == [
        hashlib.sha256(text.encode()).hexdigest() for text in sample.examples_positive]
    results["build_trim_fixture"] = {"predicate_unchanged": True, "samples_removed": True,
                                     "reachability": dict(reach), "sample_digests_correct": True}

numerical = []
for n, k in [(1743, 1), (3556, 1), (100000000, 500000), (10000000000, 10000000),
             (1000000000000000, 1)]:
    local = binomial_u95(n, k)
    reference = float(beta.ppf(.95, k + 1, n - k))
    stored = dict(trials=n, hits=k, u95=reference, corpus="numeric-probe",
                  measured_at="2026-09-06T00:00:00Z")
    numerical.append({"trials": n, "hits": k, "implementation": local,
                      "scipy": reference, "error": local-reference,
                      "independent_bound_accepted": hook.measurement(stored) is not None,
                      "own_bound_accepted": hook.measurement(dict(stored, u95=local)) is not None})
results["numerical"] = numerical
print(json.dumps(results, indent=2))

'@ | & 'C:\Users\yuezh\miniforge3\envs\py312\python.exe' -
~~~

</details>

5. Boundary probes completed with exit 0. At trials=1,001,645,599 and hits=1,000,000, both local and independent bounds exceed 0.001, but measurement accepts stored u95=0.001. At trials=10,005,200,450 and hits=10,000,000, the implementation itself falls below 0.001 while SciPy's bound is above it.

<details>
<summary>Exact numerical boundary command</summary>

~~~powershell
$env:PYTHONPATH = 'C:\Users\yuezh\PycharmProjects\agent-defs\src'
@'
import math
from scipy.stats import beta
from agent_defs.hooks._claude_code_impl import measurement
from agent_defs.lanes import binomial_u95
for hits in [10000, 100000, 1000000, 10000000]:
    target = .001
    low, high = int(hits / target), int((hits + 10 * math.sqrt(hits) + 100) / target)
    while high - low > 1:
        middle = (low + high) // 2
        if beta.ppf(.95, hits + 1, middle - hits) > target:
            low = middle
        else:
            high = middle
    n = low
    exact = float(beta.ppf(.95, hits + 1, n - hits))
    calculated = binomial_u95(n, hits)
    row = dict(trials=n, hits=hits, u95=target, corpus="boundary-probe",
               measured_at="2026-09-06T00:00:00Z")
    print({"n": n, "hits": hits, "scipy": exact, "local": calculated,
           "true_bound_above_DENY": exact > target,
           "implementation_allows_DENY": calculated <= target,
           "stored_DENY_threshold_accepted": measurement(row) is not None})
'@ | & 'C:\Users\yuezh\miniforge3\envs\py312\python.exe' -
~~~

</details>

6. Event-shape and incomplete-scan probes completed with exit 0. An anchored regex had zero benchmark hits in 4,000 joined text results, but process withheld a leaf of the corresponding structured result using that evidence. An intentionally substituted incomplete scan in RECORD produced both additionalContext and a user systemMessage. That substitution tested response policy; it was not a measured timeout.

<details>
<summary>Exact event-shape and RECORD command</summary>

~~~powershell
$env:PYTHONPATH = 'C:\Users\yuezh\PycharmProjects\agent-defs\src'
@'
import copy
from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from agent_defs import bench, evaluate
from agent_defs.builtin import STARTER_RULES
from agent_defs.hooks import _claude_code_impl as hook
from agent_defs.lanes import binomial_u95
from agent_defs.model import PredicateKind

rule = replace(STARTER_RULES[0], predicate_kind=PredicateKind.REGEX,
               predicate=r"^REVIEW_MARKER$", examples_positive=("REVIEW_MARKER",))
units = []
for i in range(4000):
    text = f"REVIEW_MARKER\nOrdinary result {i}"
    raw = text.encode()
    units.append(bench.Unit(str(i), text, rule.surface,
        {"file_type": "tool-result", "prose": "ordinary" if i % 2 else "security-adjacent"},
        hashlib.sha256(raw).hexdigest(), len(raw)))
corpus = bench.Corpus("flattened-probe", "a" * 40, tuple(units), "b" * 64, ())
report = bench.measure([rule], [corpus])
pooled = next(row for row in report["bundle"]["measurements"] if row["stratum"] == "all")
with TemporaryDirectory(prefix="agent-defs-review-event-") as tmp:
    config = hook.default_config()
    config.update(bundle="", surfaces=["OUT"], log_path=str(Path(tmp) / "log.jsonl"))
    config["sources"]["builtin"] = "DENY"
    m = dict(trials=pooled["trials"], hits=pooled["hits"], u95=pooled["u95"],
             corpus="flattened-probe", measured_at="2026-09-06T00:00:00Z")
    config["evidence"] = dict(fingerprint=hook.fingerprint([rule], config["surfaces"]),
                              bundle=dict(m), rules={rule.id: dict(m)})
    response = hook.process({"hook_event_name": "PostToolUse",
        "tool_response": [{"type": "text", "text": "REVIEW_MARKER"},
                          {"type": "text", "text": "Ordinary result 0"}]}, config, [rule])
    print(json.dumps({"flattened_benchmark_trials": pooled["trials"],
                      "flattened_benchmark_hits": pooled["hits"],
                      "hook_lane": hook.effective_lanes(config, [rule])[rule.id][0],
                      "structured_result_withheld": "updatedToolOutput" in response["hookSpecificOutput"]}))
    config["sources"]["builtin"] = "RECORD"
    config["evidence"] = None
    with patch.object(hook, "scan", return_value=evaluate.ScanResult((), 0, 1, 0, False)):
        response = hook.process({"hook_event_name": "PostToolUse", "tool_response": "ordinary"}, config, [rule])
    print(json.dumps({"incomplete_RECORD_adds_context": "additionalContext" in response["hookSpecificOutput"],
                      "incomplete_RECORD_warns_user": "systemMessage" in response}))
'@ | & 'C:\Users\yuezh\miniforge3\envs\py312\python.exe' -
~~~

</details>

7. A 60-digit mpmath CDF check completed with exit 0. At p=0.001, the two boundary cases had CDFs 0.050000036129900565753901806089441941 and 0.050000013519296606959118874161231148, both above 0.05. Thus both true upper bounds exceed the DENY ceiling, independently confirming N5.

<details>
<summary>Exact high-precision verification command</summary>

~~~powershell
$env:PYTHONPATH = 'C:\Users\yuezh\PycharmProjects\agent-defs\src'
@'
import mpmath as mp
from agent_defs.hooks._claude_code_impl import measurement
from agent_defs.lanes import binomial_u95
mp.mp.dps = 60
for n, k in [(1001645599, 1000000), (10005200450, 10000000)]:
    p = mp.mpf("0.001")
    term = total = mp.mpf(1)
    for j in range(k, 0, -1):
        term *= mp.mpf(j) / (n-j+1) * (1-p) / p
        total += term
        if term < total * mp.mpf("1e-55"):
            break
    log_cdf = (mp.loggamma(n+1)-mp.loggamma(k+1)-mp.loggamma(n-k+1)
               + k*mp.log(p)+(n-k)*mp.log1p(-p)+mp.log(total))
    cdf = mp.exp(log_cdf)
    assert cdf > mp.mpf("0.05")
    print(n, k, "60-digit CDF at p=.001:", mp.nstr(cdf, 35), "true upper bound exceeds .001")
    stored = dict(trials=n, hits=k, u95=.001 if n==1001645599 else binomial_u95(n,k),
                  corpus="precision-probe", measured_at="2026-09-06T00:00:00Z")
    assert measurement(stored) is not None
    print("accepted stored bound:", stored["u95"])
'@ | & 'C:\Users\yuezh\miniforge3\envs\py312\python.exe' -
~~~

</details>

8. Review format validation and same-directory atomic replacement completed with exit 0. The required round marker, verification status, verdict, and finding sections were present; exact readback succeeded and all 14 staged implementation files remained unchanged.

<details>
<summary>Exact review validation and replacement command</summary>

~~~powershell
@'
import os
from pathlib import Path
import subprocess
root = Path("C:/Users/yuezh/PycharmProjects/agent-defs").resolve()
temporary = root / ".Review-Codex-round1.tmp"
target = root / "Review-Codex.md"
data = temporary.read_bytes()
review = data.decode("utf-8")
assert review.startswith("<!-- Round 1 -->\n\nVerification notes:\n")
assert review.splitlines().count("Verification status: VERIFIED") == 1
assert review.splitlines().count("Commit verdict: BLOCK") == 1
for heading in ["## New", "## Previously raised", "### Fixed", "### Still open", "### Reopened", "### Deferred"]:
    assert heading in review
assert not any(char in review for char in ("\u202f", "\u2013", "\u2014"))
assert temporary.parent.resolve() == target.parent.resolve() == root
paths = subprocess.check_output(["git", "diff", "--cached", "--name-only"], cwd=root).decode().splitlines()
assert len(paths) == 14
assert subprocess.run(["git", "diff", "--quiet", "--", *paths], cwd=root).returncode == 0
os.replace(temporary, target)
assert target.read_bytes() == data
assert not temporary.exists()
print("Atomic replacement and review format checks passed; 14 staged files remain unchanged.")
'@ | & 'C:\Users\yuezh\miniforge3\envs\py312\python.exe' -
~~~

</details>

The official NIST exact-binomial reference and scikit-learn grouped-validation documentation were fetched during this review; links accompany the statistical discussion. No held-out report, inventory, or units JSONL was found in this checkout. I verified the formula given n=1,743 and k=1, not those empirical counts, corpus completeness, the claimed five cross-corpus overlaps, or selection chronology. I did not rebuild from the upstream archive, scan a release with antivirus, or run a live Claude Code session. Passing the full suite does not validate those claims.

Verification status: VERIFIED

Commit verdict: BLOCK

The blockers are N1, N2, and N3.

Scope and lens:

The staged diff covers .gitignore, README.md, docs/calibration.md, docs/distribution.md, scripts/build_bundle.py, scripts/bundle-held-back.json, scripts/dedupe_traffic_corpus.py, scripts/split_traffic_corpus.py, src/agent_defs/bench.py, src/agent_defs/bundle.json, src/agent_defs/cli.py, src/agent_defs/hooks/_claude_code_impl.py, src/agent_defs/lanes.py, and tests/test_calibrate_from_report.py. Supporting reads covered the evaluator, bundle model/loader, traffic extractor, existing benchmark contract, SAMPLES.md, and relevant tests. The lens is code correctness, admission arithmetic and evidence integrity, ADVISE/DENY behavior, and whether the statistical claims follow from the procedure.

## New

### N1. High: Report import discards hard coverage failures, allowing invalid evidence to authorize DENY

Location: src/agent_defs/hooks/_claude_code_impl.py:648, with the import decision beginning at line 592.

The exemption is broader than selecting a pooled rather than a per-stratum interval. bench.bundle_ok also encodes duplicate material and missing required coverage. calibrate_from_report records these failures under evidence.bench, marks skipped=0, and gives them no admission effect. No explicit pooled-policy choice or ADVISE-only restriction limits the bypass.

The duplicate probe used an unmodified report from bench.measure: two distinct quiet payloads repeated to 4,000 units produce 3,998 duplicate warnings but a pooled zero-hit bound below the DENY threshold. Both promote and process then act on it. Missing attacker-reachable coverage has the same result. This contradicts docs/bench.md's duplicate and required-stratum admission rules. It is not just the documented thin-stratum disagreement.

Recommendation: preserve benchmark refusal by default. A separate pooled policy needs an explicit, versioned contract identifying which statistical criterion changes and which coverage failures remain fatal. Logging a failed gate is insufficient. The tradeoff is that this personal corpus remains unable to promote under the existing contract.

Exact conservative rewrite at **src/agent_defs/hooks/_claude_code_impl.py:592**, immediately after loading report and before reading rows:

~~~python
    benchmark_bundle = report.get("bundle") or {}
    if benchmark_bundle.get("bundle_ok") is not True:
        failures = benchmark_bundle.get("failures") or ["bundle admission was not verified"]
        raise ValueError("benchmark refused admission: " + "; ".join(failures))
~~~

This deliberately refuses the current thin-stratum report too. It is the narrow safe default while the policy is settled, not a claim that pooled intervals are inherently invalid. Add regression cases asserting that duplicate and missing-required-coverage reports cannot change configuration or authorize either interrupting lane.

### N2. High: The aggregate measurement is never checked against its enabled-rule fingerprint

Location: src/agent_defs/hooks/_claude_code_impl.py:624 and line 642.

Per-rule rule_sha256 checks do not establish that the bundle union was measured over those rules. The report supplies bundle.rule_sha256, but the importer ignores it and stamps the current installed fingerprint onto the imported aggregate.

In the probe, all eight per-rule measurements were current. A genuine aggregate measured over one rule reported 2 hits/10,000 instead of the enabled set's 8 hits/10,000. Import accepted it, and promote allowed DENY where the complete aggregate only reached ADVISE. This is a report consistency failure; it does not depend on authenticating malicious report producers.

Exact rewrite at **src/agent_defs/hooks/_claude_code_impl.py:593**, before iterating over rules:

~~~python
    expected = {rule.id: rule_fingerprint(rule) for rule in rules}
    if (report.get("bundle") or {}).get("rule_sha256") != expected:
        raise ValueError("the bundle measurement does not describe the exact enabled set; remeasure it")
~~~

Keep the existing missing-rule and stale-rule refusals. Real report fixtures should retain the aggregate hash map instead of omitting it. Related hardening should require aggregate evidence for every enabled surface: the current comprehension drops absent surfaces and only checks whether any aggregate remains. Counts, corpus revision, manifest, and trial population should also agree between native rule rows and their aggregate before importing an assembled report.

### N3. High: Deduplication and a payload split do not establish the claimed traffic-rate confidence bound

Locations: scripts/dedupe_traffic_corpus.py:1; scripts/split_traffic_corpus.py:41; docs/calibration.md:35, line 70, and line 91; README.md:72.

The arithmetic is correct for the stated binomial model. The procedure has not established that model for these observations:

- Removing identical text does not make distinct outputs from the same session, task, repository, or user independent. The splitter hashes payloads rather than sessions or tasks; the probe demonstrates one session appearing in both halves.
- Identical strings are not necessarily duplicate observations of one invocation. Independent calls can legitimately return the same output. Conversely, distinct strings can be dependent. Deduplicating text and ignoring occurrences changes the target from invocation traffic to distinct payloads. The unweighted rate is not automatically a rate for a session's traffic.
- The documented five units shared with the first selection corpus are not excluded by the splitter. Their allocation and broader session overlap must be checked before calling final evaluation untouched.
- One implementer scanning both corpora does not by itself invalidate a holdout. What matters is whether the final rule set, split, exclusions, and admission criterion were fixed before inspecting holdout outcomes. Code cannot enforce the claim that nothing consulted that half, and no dated selection/measurement ledger was available.

A session/task split prevents known groups from crossing the boundary; it still does not make every observation within a held-out group independent. Use an uncertainty calculation justified for the sampling unit and define the deployment population. The grouped-data concerns follow from the assumptions described in the [scikit-learn validation guide](https://scikit-learn.org/stable/modules/cross_validation.html#cross-validation-iterators-for-grouped-data).

One fixed bundle's union of hits is a valid single Bernoulli endpoint under suitable independent representative sampling. Promoting 206 rules does **not** by itself require dividing alpha by 206 when the claim concerns that union. The defect is the sampling and selection contract, not the number of rules.

A pooled criterion can be defensible if chosen in advance for a specified traffic mixture; it offers no uniform guarantee for rare or attacker-reachable tools. Here the justification is that the consumer accepts the number despite the benchmark refusal. That does not justify switching admission policy after seeing which gate passes. Treat this as an explicit relaxation, not equivalent evidence. Bench's per-stratum bounds are also pointwise, not a simultaneous 95% guarantee over every stratum.

Disjoint sets of noisy rules justify concern about transfer and collecting a third independent corpus. They do not mathematically falsify a valid bound for a fixed population and preselected bundle: it already allows future hits. The claim that the tail thins is not established by comparing numbers of firing rules across changing candidate sets and different corpora.

Exact replacement for the full module docstring at **scripts/dedupe_traffic_corpus.py:1**:

~~~python
"""Collapse exact duplicate tool-result text and record its multiplicity.

The output contains one row per distinct payload. This removes repeated text;
it does not establish independent observations or preserve the frequency
distribution of tool invocations.
"""
~~~

Exact replacement for the paragraph at **docs/calibration.md:35**:

~~~markdown
Content deduplication reduced `trace-commons` from 4,198 to 2,937 distinct
payloads and `local-claude` from 4,000 to 3,556. These counts are not a count of
independent invocations. Repeated text can come from separate calls, while
different results from one session can remain dependent. The measurement
does not weight payloads by their recorded occurrence counts. The two corpora
reportedly share five payloads; their overlap with the final holdout must be
audited.
~~~

Exact replacement for the result paragraph at **docs/calibration.md:69**:

~~~markdown
The artifact declares 206 ATR rules on `OUT`, plus the four starter rules, at
`faf743fe`. The reported evaluation recorded one bundle hit among 1,743
distinct payloads. Treating these as independent representative Bernoulli
trials gives a nominal one-sided 95% Clopper-Pearson upper bound of 0.271875%.
The current pooled importer maps that number to an ADVISE ceiling and refuses
DENY. This is the code's threshold result; the payload split and deduplication
do not establish a 95% bound on future invocation traffic or other users.
~~~

Exact replacement for the paragraph at **docs/calibration.md:87**:

~~~markdown
`calibrate --report` currently selects the worst whole-corpus row for each
surface and then the worst of those rows. It does not sum across corpora.
It recomputes the selected bound and records the benchmark refusal separately.
This relaxes the benchmark's admission policy. A pooled criterion concerns a
specified traffic mixture and cannot certify each tool or exposure stratum.
The present sampling procedure has not established the independent,
representative trials needed to interpret this number as a deployment bound.
~~~

Replace the opening of **docs/calibration.md:97** with: "These observations concern selected distinct payloads from one user's traffic. They do not establish a confidence bound for ordinary work generally, and they do not measure attack recall." Qualify README.md:72 consistently. Keep the deployment claim provisional until the protocol and evidence support it.

### N4. Medium: The report measures joined text, while the hook acts on individual string leaves

Locations: src/agent_defs/hooks/_claude_code_impl.py:568; docs/calibration.md:9. Supporting paths: scripts/prepare_tool_traffic.py:24 and src/agent_defs/hooks/_claude_code_impl.py:213.

The extractor joins text blocks with newlines and bench scans one string. process recursively scans individual string leaves and uses a shared one-second event budget. The offline traffic script uses a 30-second scan budget. Rule fingerprints do not identify these different evaluation procedures.

The controlled rule `^REVIEW_MARKER$` had zero hits on 4,000 strings shaped like `REVIEW_MARKER\nOrdinary result i`. Using that evidence, process matched and withheld the marker leaf in a two-block result. No production ATR row was inspected to claim this exact defect affected the reported one hit; the counterexample shows the importer cannot generally certify the deployed decision function.

Preserve event structure during extraction, measure the same leaf traversal, and count the union of leaf hits once per invocation. Bind reports to a versioned evaluation protocol as well as rule fingerprints. Separately report incomplete-scan frequency, since these also inject context. Until then, describe the number as a flattened-text firing measurement, not the frequency of hook advice or withholding.

### N5. Medium: The tolerance works for 1,743 trials but does not validate the full accepted numeric domain

Locations: src/agent_defs/hooks/_claude_code_impl.py:125 and src/agent_defs/lanes.py:58.

For the reported evidence, the implementation returns 0.0027187451457536763 and SciPy returns 0.0027187451457543026. Their difference is far below 1e-12. Bisection rounding does not threaten this ADVISE-versus-DENY decision. The independent calculation uses the Beta(k+1,n-k) 95th percentile, equivalent to the one-sided CDF inversion described by [NIST](https://www.itl.nist.gov/div898/software/dataplot/refman2/auxillar/exacbino.htm).

The unrestricted-domain claim is false:

| Trials | Hits | Local bound | Independent bound | Consequence |
|---:|---:|---:|---:|---|
| 100,000,000 | 500,000 | 0.005011617345907879 | 0.005011617344864613 | A correct independently computed bound is rejected. |
| 1,001,645,599 | 1,000,000 | 0.0010000000005396712 | 0.001000000000349947 | Stored 0.001 is accepted although both bounds exceed the DENY ceiling. |
| 10,005,200,450 | 10,000,000 | 0.0009999999973497407 | 0.0010000000000414241 | Self-recomputation falls on the wrong side of the threshold. |
| 1,000,000,000,000,000 | 1 | 1.2820551951721037e-15 | 4.743864518390568e-15 | Large relative underestimation still passes self-recomputation. |

The 60-digit CDF check independently confirmed that both threshold cases belong above 0.001. Subtracting large lgamma values loses precision. Sixty-four bisection iterations cannot repair an inaccurate CDF. Returning the original stored m also permits a tolerated downward adjustment to survive into the lane comparison. These are large-count or extremely narrow boundary effects; they do not undermine the displayed 0.272% arithmetic.

Specify and test a supported count range or use a stable CDF/coefficient computation over the accepted range. Validate u95's probability range, normalize accepted evidence to a conservatively computed bound, and prevent tolerance from moving evidence across an admission threshold. Do not simply widen the tolerance. Only Windows was execution-tested here; no cross-platform certification is claimed.

## Previously raised

### Fixed

The earlier design review rejected the premise that RECORD was a permanent arithmetic ceiling. This change represents positive-hit evidence and demonstrates mechanical ADVISE promotion. It also addresses the distinction between repository files and tool traffic explicitly. These correct the earlier framing; N3 and N4 explain why the new measurement still does not establish a deployment guarantee.

The reviewed tree has a packaged bundle reader, export path, and exercised hook path. The prior proposal to connect a frozen artifact to an adapter is concrete. Some integration predates this diff; it is not all attributed to this change.

### Still open

**Medium: The README and promote effect text repeat the previously identified unconditional claim that RECORD reaches neither model nor user.** Locations: README.md:59 and src/agent_defs/hooks/_claude_code_impl.py:556. The fresh incomplete-scan probe confirms additionalContext plus systemMessage in RECORD. Clean events also do not always write a log line. Suggested wording: "Completed RECORD findings are logged without changing model context. Incomplete scans and diagnostic failures can still produce warnings, including model context for incomplete scans."

The requirement to separate selection from final admission remains unresolved at the session/task level. N3 records the current concrete issue rather than treating it as a concern with no history.

### Reopened

None established. The above items were not shown to have been fixed and then regressed.

### Deferred

The earlier review's guarded removal of unused Pre registration, asynchronous RECORD design, capture/completion ledger, and interleaved latency experiment are outside this staged change. They are not additional commit blockers here.

The release-artifact scanner self-check remains open. The staged documentation and metadata state this accurately. SAMPLES.md rule 5 requires it before publication; this review did not perform it and does not approve publication.

## Direct answers to the requested safety checks

There is no reachable bundle=None dereference at effective_lanes line 142 under the current admit implementation: bundle_ok is false, so admit returns RECORD before it can return DENY. Verified synthetic 1-hit/1,743-unit evidence cannot make process withhold output, even if configuration directly requests DENY. ADVISE adds context. Other invalid evidence accepted by the importer can authorize DENY, as N1 and N2 demonstrate.

Missing enabled rules, changed rule fingerprints, and unsupported per-source lane requests raise before writing configuration in the exercised cases. promote enforces effective_lanes; it does not independently validate evidence provenance or coherence. Its refusal mechanism works, while the report admission boundary does not fail closed overall.

docs/calibration.md:62 should say "Every selection-stage rule that fired" rather than "Every rule that fired": retaining the holdout firing is intentional. Earlier-stage counts concern different candidate sets, so explain their transition before interpreting firing-rule counts as a thinning tail. The code chooses the worst per-corpus pooled row, not an aggregate formed by pooling multiple corpora. These corrections supplement the blocking overclaims in N3.
