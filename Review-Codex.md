<!-- Round 5 -->

Verification notes:

All commands ran in `C:/Users/yuezh/PycharmProjects/agent-defs`. Root `AGENTS.md` and `AGENTS.local.md` were absent; the supplied instructions applied. Bootstrap, configuration refresh, and the session banner were skipped. Python commands used the prescribed interpreter, and subsequent PowerShell commands used `/c/Program Files/PowerShell/7/pwsh`. The verification helper is reproduced below; it never executes transcript commands or extracts archive members to disk.

1. Scope and whitespace commands completed with exit 0. HEAD was `36bd8fbbb2b2686726cacd2a4731355ae02808c4`, the fourteen requested files were modified, and there were no staged changes. The whitespace check reported no errors; Git emitted its existing LF-to-CRLF notices for the two diagnostic JSON files.

~~~powershell
git rev-parse HEAD
git status --short
git diff HEAD --stat
git diff --check HEAD
git diff --cached --stat
git show HEAD:Review-Codex.md
~~~

The non-bundle diff was read with these commands. Bundle review used parsed metadata and semantic comparisons instead of reviewing thousands of reordered rule-body lines.

~~~powershell
git diff HEAD -- scripts/measure_tool_traffic.py scripts/prepare_tool_traffic.py src/agent_defs/hooks/_claude_code_impl.py scripts/bound_leaf_discrepancy.py
git diff HEAD -- README.md docs/calibration.md docs/claude-code.md scripts/artifact-scan.json scripts/leaf-traversal-diagnostic.json tests/test_claude_code_hook.py tests/test_leaf_discrepancy_probes.py tests/test_shipped_bundle.py tests/test_tool_traffic.py
~~~

2. Full suite, exit 0: **736 passed, 6 skipped, 1 warning in 41.87 seconds**. The warning was the existing possible nested regex set in `test_evaluate_adversarial.py`. Source tests use synthetic archives and mocked downloads; no real corpus was fetched.

~~~powershell
$env:PYTHONPATH = 'src'
& 'C:\Users\yuezh\miniforge3\envs\py312\python.exe' -m pytest -q
~~~

3. Metadata inspection and evidence reconciliation, both exit 0. The first command captured hashes of the fourteen original working-tree files. The second reproduced current corpus construction, checked all 3,481 report material identities, digests, sizes and strata, reconstructed every per-rule and bundle stratum count, and independently checked bundle bounds with the binomial CDF. All 220 measured fingerprints matched the current enabled set. All 205 existing OUT records were semantically unchanged.

~~~powershell
& 'C:\Users\yuezh\miniforge3\envs\py312\python.exe' .Review-Codex-round5-probes.py inspect
& 'C:\Users\yuezh\miniforge3\envs\py312\python.exe' .Review-Codex-round5-probes.py evidence
~~~

4. IN representation probe, exit 0: **0/1,738** on serialized invocations and independently **0/1,738** on their reconstructed argument leaves, comprising **3,401 nonempty strings**. The leaf census used the real `_core.scan_payload` traversal with screened, cached predicates and generous offline limits. It does not measure production scan completion or latency. A separate controlled witness used isolated `evaluate.scan` and actual `process`: the shipped rule `ATR-2026-02525` missed the serialized invocation, matched its raw argument, and produced IN advice. No shell command in that witness was executed.

~~~powershell
& 'C:\Users\yuezh\miniforge3\envs\py312\python.exe' .Review-Codex-round5-probes.py leaf
~~~

5. Contract probes, exit 0 on all three executions as probes were added. Isolated scans reproduced all five cross-surface hits across the four reported rule/surface pairs. Actual `process` selected only native rules for each event. Synthetic bench runs verified native-hit counting, the `(surface, sha256)` duplicate distinction, and identity/revision rejection. Replaying HEAD's OUT corpus reader showed the exact behavior change for duplicate results: it previously returned a refused diagnostic report; current code raises before measuring. Normal report import reproduced the supplied configuration's counts and fingerprints. Missing-aggregate probes demonstrated N15, including a real RECORD-to-ADVISE lane change; the exact proposed guard rejected that case and preserved normal import. Config/report writes were intercepted in memory.

~~~powershell
& 'C:\Users\yuezh\miniforge3\envs\py312\python.exe' .Review-Codex-round5-probes.py contracts
~~~

6. In-memory rebuild, exit 0. The local ATR tarball matched the lock's sha256 `5d00c6b4b01cc2543277dc9b6ca9b3ec4bb205639621d66bdd8701639e54daf5`. Reading its 793 regular rule YAML members into memory reproduced 793 loaded rules, 57 IN rules, 14 runnable/shippable/screened IN rules, the three held-back IN identities, every drop count, the screen refusal, and all 216 trimmed shipped rule fingerprints and reachability records. No tar member was extracted to the filesystem, and `sources.fetch` was not called.

~~~powershell
& 'C:\Users\yuezh\miniforge3\envs\py312\python.exe' .Review-Codex-round5-probes.py archive
~~~

7. Diagnostic reconciliation, exit 0. Recomputed every relaxed candidate and newline probe from the retained OUT text: joined/newline/substring totals **1/1/489**, with substring gains **485/2/1** for `02007`/`00266`/`02106`. The joined hits came from the verified report, not a rerun of the base detector. The 205-rule subset, 102 probed rules, construct census, empty unprunable list, whole-bundle digest and subset-ID digest matched the committed diagnostic.

~~~powershell
& 'C:\Users\yuezh\miniforge3\envs\py312\python.exe' .Review-Codex-round5-probes.py diagnostic
~~~

8. Provenance checks, exit 0. All 1,743 rows declare `file_type=tool-result`; the extracted topic regex is identical to HEAD's expression; canonicalizing invocation object-key order still leaves 1,738 distinct invocations. Modification times were inspected, with their limitations discussed below. Verified evidence hashes:

| File within the supplied scratchpad | SHA-256 |
|---|---|
| `in-evidence/local-claude-unique-holdout-units.jsonl` | `bd429d68174135bab674426bea82e0e58f504241002c3e589202f8c1a828893e` |
| `in-evidence/local-claude-unique-holdout-out-in-report.json` | `7ff4ce5b564a6de4928e4e9f8b71abfa64395f89d4954e6c2107a2d422b3adb3` |
| `enabled-in-out.json` | `9b208767fb8e47f7e87b3956abea1b6c75c2d15e1286ebbd4b147764439b2f77` |
| `in-config.json` | `42796932e1e27fc134c04ba7864789ca77e51f46e0adc757d4dced462b694dc0` |

~~~powershell
& 'C:\Users\yuezh\miniforge3\envs\py312\python.exe' .Review-Codex-round5-probes.py provenance
~~~

9. Finalization command, exit 0: checked the original working-tree hashes, HEAD and index, embedded the helpers, flushed the complete sibling temporary review, replaced `Review-Codex.md` with `os.replace`, and verified the saved bytes. It removed only the named review helpers. The final additional tracked change is `Review-Codex.md`.

~~~powershell
& 'C:\Users\yuezh\miniforge3\envs\py312\python.exe' .Review-Codex-round5-finalize.py
~~~

Verification status: VERIFIED

Commit verdict: BLOCK

N15 permits an incomplete surface aggregate to grant a lane that the complete report refuses. The supplied report has both aggregates and does not exhibit that defect: its zero survives independent reconstruction and the argument-leaf census. No cross-surface execution bug was found.

File/diff scope: **the uncommitted `git diff HEAD` at `36bd8fb`**, not a committed range or the index. Fourteen files: `README.md`, `docs/calibration.md`, `docs/claude-code.md`, `scripts/artifact-scan.json`, `scripts/bound_leaf_discrepancy.py`, `scripts/leaf-traversal-diagnostic.json`, `scripts/measure_tool_traffic.py`, `scripts/prepare_tool_traffic.py`, `src/agent_defs/bundle.json`, `src/agent_defs/hooks/_claude_code_impl.py`, `tests/test_claude_code_hook.py`, `tests/test_leaf_discrepancy_probes.py`, `tests/test_shipped_bundle.py`, and `tests/test_tool_traffic.py`. Ancillary reads covered their benchmark, evaluator, traversal, builder, extraction and calibration dependencies, and the earlier review. N15 identifies retained importer logic newly exposed by shipping both surfaces; N17 includes a stale reference in unchanged `SAMPLES.md`.

Review lens: code correctness, evidence completeness, and whether the measured quantity supports the artifact's stated behavior. This is not an attack-recall evaluation, fresh holdout certification, or independent antivirus clearance.

## New

### N15. High: a missing native bundle aggregate silently weakens admission

Locations: `src/agent_defs/hooks/_claude_code_impl.py:660` and `src/agent_defs/hooks/_claude_code_impl.py:690`.

`bundle_rows` filters out missing surface rows, then requires only that at least one row survive. Per-rule coverage and the aggregate rule fingerprint can both pass while one surface's union is absent. The new `bundle_by_surface` dictionary records the omission, but admission still proceeds and the result says `measured`.

The minimal probe against the supplied report removes only its OUT `stratum=all` bundle row. Import then reports `bundle_hits=0`, `trials=1738`, and `gating_surface=IN` while retaining all 220 per-rule measurements. Both lanes happen to be ADVISE in this particular corpus.

A separate authentic `bench.measure` fixture demonstrates the admission consequence:

| Evidence | Trials | Hits | Nominal u95 |
|---|---:|---:|---:|
| Six IN rules' union | 1,000 | 6 | 1.180782% |
| Each IN rule separately | 1,000 | 1 | 0.473499% |
| OUT union | 1,000 | 0 | 0.299125% |

The complete report correctly resolves every rule to RECORD because of the IN union. Removing only the IN whole-corpus aggregate, leaving every fingerprint, per-rule row and other stratum unchanged, makes actual `effective_lanes` resolve every rule to ADVISE. A set of individually admissible rules does not replace its missing union measurement.

This requires an incomplete or transformed report; it is not evidence that honest `bench.measure` omits aggregates or that the supplied report is corrupt. It is a completeness check at the same import boundary that already refuses missing rule evidence. A normal bench report explicitly refused for an unmeasured surface remains correctly rejected.

Exact rewrite at **`src/agent_defs/hooks/_claude_code_impl.py:660`**, replacing the `bundle_rows` comprehension and its following empty-list check, while retaining `surfaces` above and `bundle = max(...)` below:

~~~python
    bundle_rows = []
    for surface in sorted(surfaces):
        row = _pooled(report.get("bundle", {}).get("measurements") or [], surface)
        if row is None:
            raise ValueError(f"the report carries no whole-corpus bundle measurement for {surface}")
        bundle_rows.append(row)
    if not bundle_rows:
        raise ValueError("the report carries no whole-corpus bundle measurement")
~~~

The probe executed this replacement in memory: normal import was unchanged and the missing-IN case raised before evidence publication. Add the regression to `tests/test_calibrate_from_report.py`, including the disjoint-hit union case rather than checking only the printed surface map. No implementation patch was applied in this review.

### N16. Medium: serialized invocation matching is not argument-leaf matching

Locations: `scripts/measure_tool_traffic.py:50`, `docs/calibration.md:133`, and `src/agent_defs/hooks/_claude_code_impl.py:255`.

The benchmark scans the JSON serialization of `{name, arguments}`. PreToolUse instead walks string values within `tool_input`; it does not scan the serialized envelope, object keys, or tool name. JSON escaping and added boundaries can change matches even without any surface mix-up.

For the shipped `atr:ATR-2026-02525`, the controlled argument `${!REVIEW_CMD} /tmp/review-marker` matches at the beginning of the raw command. Wrapping it in the extractor's invocation JSON suppresses that match. Isolated scans and actual `process` reproduced the difference, including the resulting IN advisory. The marker was only scanned, never executed.

**This did not change the supplied zero:** scanning all reconstructed argument leaves also found zero hits in the same 1,738 distinct invocations. Therefore this is a measurement-contract defect, not a claim that this corpus secretly contains native hits.

Preserve the invocation JSON for provenance and one-trial-per-invocation accounting, but evaluate and union hits over its argument strings using the hook's traversal semantics. Do not turn 3,401 leaves into 3,401 trials. Record which matching procedure a report used, and require complete evaluation of every relevant leaf. Until that path exists, describe the stored result as a serialized-invocation diagnostic; the assertion that it is the text the hook sees is inaccurate. The existing OUT decomposition caveat does not explain this distinct, reconstructable IN mismatch.

### N17. Low: rebuild and scan prose still describes the previous artifact

Locations: `docs/calibration.md:363` and `SAMPLES.md:155`.

Calibration still says the shipped bundle used seven fixtures and "has not been rebuilt." This bundle was rebuilt against the current twenty-fixture policy; the refusal metadata now identifies the single-space witness. The in-memory rebuild reproduced it.

`SAMPLES.md` names the previous 205-rule, 1,372,797-byte artifact and says the current `scripts/artifact-scan.json` is keyed by that old digest. The current record instead names the 216-rule, 1,456,844-byte artifact at `e6efd658a7f93eeef6ad1687a0e4782c3f3c2addc9cd2fd182eda0b3c96e3310`, with scan timestamp `2026-09-07T01:32:45.2398598Z`.

Update these paragraphs for the rebuild, or preserve the old scan explicitly as history with a reference to its historical record. The new scan record and current artifact do match; the stale prose is the defect.

## Previously raised

### Fixed

**N10 and N11:** Closed in `36bd8fb`, outside this diff. The shared source policy checks both destination and resolved source and applies ATR's declared-input allow-list. Source regression tests passed with mocked archives. The rebuilt artifact did not reopen either finding; this review did not fetch or extract a real source tree.

**N4:** The distant quantified-lookaround cases were repaired in HEAD, and their candidate-selection regressions passed. Current diagnostic counts and construct classification reconcile with the named OUT subset.

**N5:** The numerical comments now distinguish the observed maxima, state approximately twelve-fold empirical headroom, and call the slack an empirical refusal band. Shared numerical tests passed; no new platform-wide numerical claim was established.

**N12:** The automatic re-download explanation was withdrawn. The shared verifier repair remains separate from the cause of repeated materialization.

**N13:** The traversal budget test now asserts that the scanner was never called. It passed.

**N14:** `WriteAllText` is inside the publication guard. This was confirmed by code inspection; the external scanner was not rerun.

**N1, N2, N3, N6, N7, N8 and N9:** Remain closed within this review. Existing aggregate-set validation and refusal handling passed relevant tests. N15 is missing aggregate *surface coverage*, not a reopening of N2's mismatched rule-set identity. The post-selection and deployment limitations remain disclosed rather than resolved by the new measurement.

### Still open

None of the previously numbered findings remains open on the evidence reviewed here. N15 to N17 are listed separately as new findings.

### Reopened

None.

### Deferred

Fresh evaluation grouped by session/task; recovery of the lost selection material; complete deployed OUT payload capture; production completion/latency measurement; attack recall; an independent antivirus run; and platform-wide numerical certification remain outside this change. The other sources' extraction-input declarations are also outside scope. The new leaf census is an offline check over retained IN arguments, not a substitute for those studies.

## Measurement and selection assessment

### The counts and deduplication

The report and current material construction agree:

| Surface | Enabled rules | Distinct units | Native bundle hits | Recomputed nominal u95 |
|---|---:|---:|---:|---:|
| IN | 11 | 1,738 | 0 | 0.172218% |
| OUT | 209 | 1,743 | 1 | 0.271875% |

The five removed occurrences belong to **three invocation groups**, of sizes two, two and four. Two removals are Bash and three are Read. All five are `exposure=file-origin-unknown` and `result_status=success`. No additional duplicates appeared after canonicalizing JSON key order. An exact repeated serialization has the same complete predicate outcome, so removing these rows cannot conceal a distinct hit in this run.

Deduplication is appropriate for bench's declared **distinct-material** statistic. It is not a proof that the retained observations are independent, and repeated bytes are not inherently invalid independent draws when the intended population is invocation occurrences. The code's "second independent trial" rationale should be phrased as satisfying the distinct-payload contract. Here deduplication reduces the zero-hit denominator and slightly widens the nominal interval.

There is also an earlier selection to remember: this IN sample already passed OUT-result deduplication. Different invocations that returned identical output could have been removed before this additional IN deduplication. The 1,738 observations therefore represent distinct invocation serializations retained through an output-selected sample, not an occurrence-weighted sample of all calls. The existing conditional sampling disclaimer is necessary; none of these digest checks establishes representativeness.

For the requested OUT regression witness, two distinct calls returning `ordinary repeated output`, plus one distinct security-topic result, suffice. HEAD's reader lets bench complete and report a duplicate-material refusal. Current `corpus()` raises `ValueError` instead. Thus a diagnostic measurement becomes an early failure, but **no previously admissible measurement becomes inadmissible**: the duplicate refusal was already fatal to calibration. This is a deliberate loss of diagnostic output, not a demonstrated lane regression.

### Strata

`tool` and `exposure` match recomputation from every retained call. The old OUT topic expression and exported `TOPIC` are identical, and all original OUT topic labels match current `prose(result)`.

Across all 1,743 rows, 160 security-topic results become ordinary invocation text and 16 ordinary results become security-topic invocation text: 176 disagreements, or 10.10%. Among retained IN rows there are 175 disagreements, or 10.07%. Both support the rounded 10.1% disclosure.

| Count | OUT result labels | IN after dedup, before topic correction | IN after topic correction |
|---|---:|---:|---:|
| Security-adjacent | 186 | 185 | 42 |
| Ordinary | 1,557 | 1,553 | 1,696 |
| Error episodes | 91 | 91 | 91 |

The worst stratum does not move. On both surfaces, AskUserQuestion, Glob, Monitor and StructuredOutput each occur once and have zero native hits, giving u95=95%. IN Bash changes from 1,045 occurrences to 1,043 and Read from 130 to 127; neither becomes the worst stratum.

Keeping `result_status` is defensible as a descriptive attribute of the retained episode. It is not an attribute derivable from the invocation itself. No duplicate group here mixes error and success, so the first-occurrence choice does not distort those counts. For future groups with differing statuses, record which episode was retained rather than implying the label belongs to the unique command. Bench adds marginal status rows to its maximum; it does not construct a full cross-product partition. Adding those rows cannot lower that maximum. I would retain the contextual diagnostic, with this qualification, rather than claim it repairs sampling.

### One report and native surfaces

The two corpus identities differ, their shared revision/hash truthfully names the source snapshot, and their material digests name different surface-specific text. The duplicate identity/revision guard still runs before scanning. `(surface, sha256)` is the right key for the material contract: identical bytes presented at different interception points are different measurements. Within a surface, exact duplicates still trigger refusal. Cross-corpus diagnostic totals are not used to turn these into 3,481 independent admission trials.

All four cross-surface pairs were reproduced:

| Rule | Native surface | Diagnostic surface | Hits |
|---|---|---|---:|
| `ATR-2026-00118` | IN | OUT | 1 |
| `ATR-2026-02106` | OUT | IN | 1 |
| `ATR-2026-00296` | OUT | IN | 2 |
| `ATR-2026-00554` | OUT | IN | 1 |

Excluding them from native union counts is correct. `process` filters at `_claude_code_impl.py:244` before traversal, and `bench.measure` forms `native_hits` at `bench.py:321` before incrementing bundle counts. Both halves were exercised. N16 concerns representation within IN, not cross-surface evaluation.

### The three exclusions and the second reading

The unchanged held-back list identifies these IN rules, all excluded using trace-commons tool-result counts:

| IN rule | Recorded selection hits on OUT | Meaning of the record |
|---|---:|---|
| `ATR-2026-00064`, Over-Permissioned MCP Skill | 81/2,937 | Cross-surface diagnostic firing |
| `ATR-2026-00110`, Remote Code Execution via eval() and Dynamic Code Injection | 27/2,937 | Cross-surface diagnostic firing |
| `ATR-2026-00111`, Shell Metacharacter Injection in Tool Arguments | 4/2,937 | Cross-surface diagnostic firing |

"Prior selection, rather than dropping rules after reading this IN outcome" is defensible given the unchanged list and reported chronology. It does not turn those counts into native-IN false-positive evidence, prove independence from correlated selection material, or reconstruct the lost selection corpora. In particular, 00111's title gives no reason to treat its OUT firing rate as its invocation firing rate. README's short description would be more accurate as "three held back after firing on selection-stage tool results."

For primary characterization I would have measured **all fourteen runnable IN rules before reading IN results**, because the only available grounds for excluding three were on another surface. The tradeoff is a potentially wider union bound in exchange for showing the full runnable surface. The fixed eleven-rule deployment still needs its own exact-enabled-set report under this importer; the fourteen-rule report must not be silently imported as if its fingerprints described eleven. A prespecified fourteen-rule comparison can provide a conservative envelope because adding predicates cannot reduce the union at fixed units. I did not run the three held-back rules against the holdout or infer what that missing comparison would show.

The second reading disclosure is sufficient for describing an exploratory, **nominal** result. It does not restore an untouched validation claim. A numerical adaptive-reuse penalty cannot be inferred from "second reading" alone: the target-selection process and earlier queries matter. Preserve the actual protocol and use fresh grouped data for a confirmatory claim; a generic correction is not a replacement for that history.

There is a useful distinction from ordinary multiplicity. For **two fixed surface populations and valid marginal intervals**, taking `max(U_IN, U_OUT)` is a valid upper bound for the larger true rate without automatically halving alpha: for a fixed surface attaining the true maximum, failure of the maximum upper bound implies failure of that surface's own bound. No independence between the two surface samples is needed for that argument. This does not certify an adaptively chosen detector or the sampling assumptions here.

If the desired claim instead covers both separate intervals simultaneously, a nominal Bonferroni calculation using alpha=0.025 gives IN 0.212023% and OUT 0.319239%, still within ADVISE. That prices two fixed comparisons only, not unknown adaptive selection. The current worst-surface gate is sensible for a per-interception false-advice rate; it is not automatically a bound on the probability of any intervention across an entire episode's multiple interceptions.

## Remaining implementation and provenance checks

The IN advice is actionable and actual `process` emitted the new sentence. OUT retains the original sentence. Existing assertions mentioning "untrusted data" concern OUT promotion/advice; the shared incomplete-scan message is a separate path. No assertion was found requiring the old OUT advisory for a completed IN ADVISE result.

The supplied config's `bundle_by_surface` contains both populations, counts and corpus provenance, while `evidence.bundle` correctly stores OUT as the worse pooled row. Normal re-import reproduced these data and all per-rule evidence, apart from refreshed timestamps. The recorded dictionary is useful to a reader, but does not replace N15's missing completeness check.

Bundle metadata reconciles exactly: **793 loaded = 216 shipped + 222 not runnable + 14 held back + 1 content-free refusal + 116 CFG + 218 PROMPT + 6 NONE**. For IN specifically, **57 = 11 shipped + 3 held back + 43 not runnable**. The non-runnable IN count includes 25 measured refusals, 16 multiple-field refusals and two other refusals. Every shipped rule's normalized fingerprint and reachability record reproduced from the pinned archive. All 205 OUT records are unchanged from HEAD; the refusal text's move from three spaces to one follows the already-fixed fixture order.

The OUT diagnostic names the correct whole-bundle digest and the correct 205-rule subset digest. Its `--surface` default now selects the relevant OUT rules and leaves IN out of a tool-result diagnostic. Recomputed candidate counts agree with the stored 489; this remains a diagnostic, not deployed-hook admission evidence. The artifact scan record matches current bytes and size, but its scanner result was not independently rerun.

The restored OUT `file_type` assignment is semantically inert for this snapshot: all 1,743 rows already carry `tool-result`, and **every current material row matches the stored report**, not just that label.

It is not accurate to infer that this was the only subsequent edit. The report starts at `2026-09-07T01:18:08.058602Z` and its elapsed duration places completion at approximately `01:26:35.386602Z`. Current file modification times are later for twelve scoped files: the three Markdown documents; `artifact-scan.json`; `bound_leaf_discrepancy.py`; `leaf-traversal-diagnostic.json`; `measure_tool_traffic.py`; `bundle.json`; `_claude_code_impl.py`; and the hook, leaf-probe and shipped-bundle tests. Only `prepare_tool_traffic.py` and `test_tool_traffic.py` have earlier modification times.

Modification times do not establish which individual lines changed or preserve execution history. The stronger checks are semantic: report materials and current transforms match; all enabled fingerprints match; OUT records and evaluator/bench implementations are unchanged in this diff; normal import reproduces the stored evidence; and the regenerated diagnostic reconciles. Those checks support consistency with current code. The report does not carry a source-code revision/diff digest sufficient to certify the exact historical script bytes.

## Reproducible verification helpers

The helpers below were used only for this review. Their temporary filesystem copies were removed after the complete review was published. The `inspect` phase creates the baseline hash file used by `provenance` and finalization; the evidence phases read the scratchpad path supplied in the request.

<details>
<summary>.Review-Codex-round5-probes.py</summary>

~~~python
import argparse
import ast
from collections import Counter, defaultdict
import copy
from dataclasses import asdict, replace
from datetime import datetime, timezone
import hashlib
import importlib.util
import inspect as inspect_module
import json
import math
from pathlib import Path
import subprocess
import sys
import tarfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
S = Path('C:/Users/yuezh/AppData/Local/Temp/claude/C--Users-yuezh-PycharmProjects-agent-startup-thesis/0c2c85fb-d0d8-49d1-a9cd-a3b2dc006ecd/scratchpad')
E = S / 'in-evidence'
NAME = 'local-claude-unique-holdout'
sys.path[:0] = [str(ROOT / 'src'), str(ROOT / 'scripts')]
from agent_defs import bench, bundle, evaluate, lanes
from agent_defs.hooks import _claude_code_impl as hook
from agent_defs.model import Surface, Lane
import measure_tool_traffic as traffic
import prepare_tool_traffic as prepare


def read(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


def emit(tag, value):
    print(tag + ': ' + json.dumps(value, ensure_ascii=True, sort_keys=True), flush=True)


def inputs():
    rows = [json.loads(line) for line in (E / f'{NAME}-units.jsonl').read_bytes().splitlines()]
    report = read(E / f'{NAME}-out-in-report.json')
    return rows, report


def inspect():
    tracked = subprocess.check_output(['git', 'diff', '--name-only', 'HEAD'], cwd=ROOT).decode().splitlines()
    baseline = {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in tracked}
    (ROOT / '.Review-Codex-round5-baseline.json').write_text(json.dumps(baseline), encoding='utf-8')
    rows, report = inputs()
    meta = read(ROOT / 'src/agent_defs/bundle.json')
    previous = json.loads(subprocess.check_output(['git', 'show', 'HEAD:src/agent_defs/bundle.json'], cwd=ROOT))
    for label, value in [('bundle', meta), ('previous_bundle', previous)]:
        emit(label + '_metadata', {k: v for k, v in value.items() if k != 'rules'})
        emit(label + '_counts', dict(Counter(r['surface'] for r in value['rules'])))
    emit('IN_rules', [{k: r.get(k) for k in ('id', 'title', 'predicate', 'predicate_kind')} for r in meta['rules'] if r['surface'] == 'IN'])
    emit('report_keys', list(report))
    emit('report_summary', report['summary'])
    emit('report_execution', report['method'])
    emit('report_corpora', report['corpora'])
    emit('report_bundle', {k: v for k, v in report['bundle'].items() if k not in ('measurements', 'diagnostic_measurements', 'rule_sha256')})
    emit('input_inventory', {k: v for k, v in read(E / f'{NAME}-inventory.json').items() if k != 'files'})
    emit('row_schema', {k: type(v).__name__ for k, v in rows[0].items()})
    emit('config_evidence', {k: v for k, v in read(S / 'in-config.json')['evidence'].items() if k != 'rules'})


def exact_upper(n, k, alpha=.05):
    if not k:
        return -math.expm1(math.log(alpha) / n)
    low, high = 0., 1.
    for _ in range(80):
        p = (low + high) / 2
        cdf = sum(math.comb(n, j) * p ** j * (1-p) ** (n-j) for j in range(k+1))
        if cdf > alpha:
            low = p
        else:
            high = p
    return (low + high) / 2


def evidence():
    rows, report = inputs()
    raw = (E / f'{NAME}-units.jsonl').read_bytes()
    assert hashlib.sha256(raw).hexdigest() == 'bd429d68174135bab674426bea82e0e58f504241002c3e589202f8c1a828893e'
    corpora = [traffic.corpus(E, NAME, s) for s in (Surface.OUT, Surface.IN)]
    rules = bench.load_rules(S / 'enabled-in-out.json')
    config = read(S / 'in-config.json')
    current = hook.active_rules(config, hook.hook_rules(config)[0])
    fingerprints = {r.id: bench.rule_fingerprint(r) for r in rules}
    assert fingerprints == {r.id: bench.rule_fingerprint(r) for r in current}
    assert fingerprints == report['bundle']['rule_sha256']
    assert fingerprints == {rid: v['rule_sha256'] for rid, v in report['rules'].items()}
    assert len(rules) == 220 and Counter(r.surface.value for r in rules) == {'OUT': 209, 'IN': 11}
    surface_by_id = {r.id: r.surface.value for r in rules}
    report_mats = {(m['corpus'], m['id']): m for m in report['materials']}
    cross = Counter()
    for corpus in corpora:
        totals, hits, all_hits = Counter(), Counter(), Counter()
        per_rule = defaultdict(Counter)
        for unit in corpus.units:
            m = report_mats.pop((corpus.identity, unit.id))
            assert (m['surface'], m['sha256'], m['bytes'], m['strata']) == (
                unit.surface.value, unit.sha256, unit.size_bytes, unit.strata)
            native = [rid for rid in m['rule_ids'] if surface_by_id[rid] == m['surface']]
            cross.update((rid, m['surface']) for rid in m['rule_ids'] if rid not in native)
            for stratum in bench._strata(unit):
                totals[stratum] += 1
                hits[stratum] += bool(native)
                all_hits[stratum] += bool(m['rule_ids'])
                for rid in m['rule_ids']:
                    per_rule[rid][stratum] += 1
        corpus_report = next(c for c in report['corpora'] if c['identity'] == corpus.identity)
        assert corpus_report['revision'] == corpus.revision
        assert corpus_report['manifest_sha256'] == corpus.manifest_sha256
        assert corpus_report['duplicate_units'] == 0
        assert corpus_report['trials'] == len(corpus.units)
        assert {s['stratum']: s['trials'] for s in corpus_report['strata']} == totals
        for group, expected_hits in [('measurements', hits), ('diagnostic_measurements', all_hits)]:
            measurements = [m for m in report['bundle'][group] if m['corpus'] == corpus.identity]
            assert len(measurements) == len(totals)
            for m in measurements:
                n, k = totals[m['stratum']], expected_hits[m['stratum']]
                assert (m['trials'], m['hits']) == (n, k)
                assert abs(m['u95'] - exact_upper(n, k)) < 1e-12
        for rid, rule in report['rules'].items():
            for m in rule['measurements']:
                if m['corpus'] == corpus.identity:
                    assert (m['trials'], m['hits']) == (totals[m['stratum']], per_rule[rid][m['stratum']])
                    assert m['admission_eligible_surface'] == (m['surface'] == surface_by_id[rid])
        worst = max(exact_upper(totals[s], hits[s]) for s in totals)
        emit('surface', dict(surface=corpus.units[0].surface.value, trials=totals['all'],
             hits=hits['all'], u95=exact_upper(totals['all'], hits['all']),
             strata={s: [n, hits[s]] for s, n in sorted(totals.items())},
             worst=[s for s in totals if exact_upper(totals[s], hits[s]) == worst], worst_u95=worst))
    assert not report_mats
    emit('cross_surface_hits', {f'{rid}@{s}': k for (rid, s), k in cross.items()})
    groups = defaultdict(list)
    mismatches = Counter()
    for r in rows:
        inv = json.loads(r['invocation'])
        assert r['strata']['file_type'] == 'tool-result'
        assert r['strata']['tool'] == inv['name']
        assert r['strata']['exposure'] == prepare.exposure(inv['name'], inv['arguments'])
        assert r['strata']['prose'] == prepare.prose(r['text'])
        groups[r['invocation']].append(r)
        mismatches[(r['strata']['prose'], prepare.prose(r['invocation']))] += 1
    repeat_groups = []
    for inv, rr in groups.items():
        if len(rr) > 1:
            repeat_groups.append({'invocation_sha256': hashlib.sha256(inv.encode()).hexdigest(),
                                  'rows': [{'id': r['id'], 'strata': r['strata']} for r in rr]})
    emit('deduplication', dict(rows=len(rows), unique=len(groups), repeat_groups=repeat_groups))
    emit('topic_transition_all_rows', {f'{a}->{b}': n for (a, b), n in mismatches.items()})
    emit('topic_transition_dedup', dict(Counter(f"{rr[0]['strata']['prose']}->{prepare.prose(inv)}" for inv, rr in groups.items())))
    old = json.loads(subprocess.check_output(['git', 'show', 'HEAD:src/agent_defs/bundle.json'], cwd=ROOT))
    artifact_path = ROOT / 'src/agent_defs/bundle.json'
    artifact = read(artifact_path)
    assert {r['id']: r for r in old['rules']} == {r['id']: r for r in artifact['rules'] if r['surface'] == 'OUT'}
    assert artifact['shipped'] + sum(artifact['dropped'].values()) == artifact['loaded'] == 793
    assert artifact['held_back'] == read(ROOT / 'scripts/bundle-held-back.json')
    artifact_sha = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
    scan = read(ROOT / 'scripts/artifact-scan.json')
    leaf = read(ROOT / 'scripts/leaf-traversal-diagnostic.json')
    assert scan['sha256'] == leaf['inputs']['rules_sha256'] == artifact_sha
    assert scan['bytes'] == artifact_path.stat().st_size
    assert leaf['inputs']['surface'] == 'OUT'
    assert leaf['inputs']['units_sha256'] == hashlib.sha256(raw).hexdigest()
    import bound_leaf_discrepancy as probes
    outbound = [r for r in bundle.load(artifact_path) if r.surface is Surface.OUT]
    relaxed, splits, census, unprunable = probes.build_probes(outbound)
    emit('diagnostic_census', dict(rules=len(outbound), probed=len(splits), census=census, unprunable=unprunable))
    emit('diagnostic_record', leaf)
    emit('bundle_verified', dict(sha256=artifact_sha, rules=len(artifact['rules']), unchanged_OUT=205,
                                measured_at=report['measured_at'], elapsed_s=report.get('elapsed_s'),
                                config_evidence={k: v for k, v in config['evidence'].items() if k != 'rules'}))
    emit('modified_after_measurement', {p: (ROOT / p).stat().st_mtime for p in json.loads((ROOT / '.Review-Codex-round5-baseline.json').read_text())})


def leaf():
    from agent_defs.hooks import _core
    rows, report = inputs()
    inbound = [r for r in bundle.load(ROOT / 'src/agent_defs/bundle.json') if r.surface is Surface.IN]
    compiled = {r.id: evaluate.compile_rule(r) for r in inbound}
    assert all(r.predicate_kind.value == 'REGEX' for r in inbound)
    unique = {r['invocation']: r for r in reversed(rows)}
    wrapped_hits, leaf_hits = {}, {}
    count_leaves = 0
    def scanner(text, rules, *, max_bytes, budget_s):
        nonlocal count_leaves
        count_leaves += 1
        return evaluate.scan_trusted(text, rules, max_bytes=max_bytes)
    lane_map = {r.id: (Lane.RECORD, 'review complete leaf census') for r in inbound}
    with patch.object(evaluate, 'compile_rule', side_effect=lambda r: compiled[r.id]):
        for text, row in unique.items():
            wrapped = evaluate.scan_trusted(text, inbound, max_bytes=len(text.encode()))
            assert wrapped.complete and wrapped.rules_evaluated == 11
            if wrapped.findings:
                wrapped_hits[row['id']] = sorted({f.rule_id for f in wrapped.findings})
            args = json.loads(text)['arguments']
            outcome = _core.scan_payload(args, rules=inbound, lanes=lane_map, surface='IN',
                event='PreToolUse', location='/tool_input', scanner=scanner,
                limits=_core.Limits(max_bytes=10_000_000, max_nodes=100_000, max_depth=1000, budget_s=60))
            assert not outcome.incomplete
            rr = [r for r in outcome.records if 'rule_id' in r]
            if rr:
                leaf_hits[row['id']] = [{k: r[k] for k in ('rule_id', 'path', 'text_sha256')} for r in rr]
    emit('IN_leaf_census', dict(units=len(unique), leaves=count_leaves, wrapped_hits=wrapped_hits,
                                leaf_hits=leaf_hits, IN_rule_ids=[r.id for r in inbound]))
    fixture = '${!REVIEW_CMD} /tmp/review-marker'
    rule = next(r for r in inbound if r.id == 'atr:ATR-2026-02525')
    text = json.dumps({'name': 'Bash', 'arguments': {'command': fixture}}, ensure_ascii=False, separators=(',', ':'))
    wrapped = evaluate.scan(text, [rule], max_bytes=10000, budget_s=10)
    raw = evaluate.scan(fixture, [rule], max_bytes=10000, budget_s=10)
    assert wrapped.complete and raw.complete
    assert not wrapped.findings and [f.rule_id for f in raw.findings] == [rule.id]
    config = read(S / 'in-config.json')
    actual_rules = hook.hook_rules(config)[0]
    records = []
    with patch.object(hook, 'log_status', side_effect=lambda c, r: records.extend(r) or True):
        response = hook.process({'hook_event_name': 'PreToolUse', 'tool_name': 'Bash',
                                 'tool_input': {'command': fixture}}, config, actual_rules)
    assert response['hookSpecificOutput']['additionalContext'] == hook.ADVICE['IN']
    assert any(r.get('rule_id') == rule.id for r in records)
    emit('representation_witness', dict(rule=rule.id, literal=fixture, serialized_hits=0,
         isolated_raw_hits=1, actual_process_response=response, actual_process_records=records))


def contracts():
    rows, report = inputs()
    config = read(S / 'in-config.json')
    rules = hook.hook_rules(config)[0]
    by_id = {r.id: r for r in rules}
    material = {(m['surface'], m['id']): m for m in report['materials']}
    by_unit = {r['id']: r for r in rows}
    isolated_cross = Counter()
    for m in material.values():
        for rid in m['rule_ids']:
            rule = by_id[rid]
            if rule.surface.value == m['surface']:
                continue
            text = by_unit[m['id']]['text' if m['surface'] == 'OUT' else 'invocation']
            scan = evaluate.scan(text, [rule], max_bytes=len(text.encode()), budget_s=10)
            assert scan.complete and [f.rule_id for f in scan.findings] == [rid]
            isolated_cross[f'{rid}@{m["surface"]}'] += 1
    captured = []
    def inspect_scanner(text, chosen, **kwargs):
        captured.append({r.surface.value for r in chosen})
        return evaluate.ScanResult(partial_findings=(), rules_evaluated=len(chosen),
            rules_skipped_budget=0, elapsed_s=0, truncated_input=False, errors=(), worker_error=None)
    for event, surface, field in [('PreToolUse', 'IN', 'tool_input'), ('PostToolUse', 'OUT', 'tool_response')]:
        captured.clear()
        with patch.object(hook, 'scan', side_effect=inspect_scanner), patch.object(hook, 'log_status', return_value=True):
            assert hook.process({'hook_event_name': event, field: {'x': 'ordinary review fixture'}}, config, rules) == {}
        assert captured == [{surface}]
    emit('cross_surface_verification', dict(isolated_hits=isolated_cross, process_selected_only_native=True))

    proto = rules[0]
    def rule(rid, surface, token):
        return replace(proto, id=rid, source='review', surface=surface,
                       predicate_kind=type(proto.predicate_kind).REGEX, predicate=token,
                       examples_positive=(token,), examples_negative=(), extra={})
    rr = [rule('review:IN', Surface.IN, 'REVIEW_IN_TOKEN'), rule('review:OUT', Surface.OUT, 'REVIEW_OUT_TOKEN')]
    def unit(uid, surface, text, topic='ordinary'):
        return bench.Unit(uid, text, surface, {'file_type': 'review', 'prose': topic},
                          hashlib.sha256(text.encode()).hexdigest(), len(text.encode()))
    text = 'REVIEW_IN_TOKEN'
    units = tuple(unit(f'{s.value}-{i}', s, text + str(i), topic)
                  for s in (Surface.OUT, Surface.IN)
                  for i, topic in enumerate(('ordinary', 'security-adjacent')))
    c = bench.Corpus('review/mixed', 'sha256:'+'a'*64, units, 'a'*64, ())
    measured = bench.measure(rr, [c])
    pooled = {m['surface']: (m['trials'], m['hits']) for m in measured['bundle']['measurements'] if m['stratum'] == 'all'}
    assert pooled == {'IN': (2, 2), 'OUT': (2, 0)}
    assert measured['corpora'][0]['duplicate_units'] == 0
    duplicate = bench.measure(rr, [replace(c, units=units + (units[0],))])
    assert duplicate['corpora'][0]['duplicate_units'] == 1
    assert any('duplicate material units' in f for f in duplicate['bundle']['failures'])
    try:
        bench.measure(rr, [c, c])
    except ValueError as exc:
        assert str(exc) == 'duplicate corpus identity/revision'
    else:
        raise AssertionError('duplicate identity/revision was accepted')
    emit('bench_duplicate_contract', dict(cross_surface_identical_bytes_allowed=True,
                                         same_surface_repeat_refused=True, repeat_identity_refused=True,
                                         native_pooled_counts=pooled))
    duplicate_rows = []
    for i, payload in enumerate(('ordinary repeated output', 'ordinary repeated output', 'security review note')):
        duplicate_rows.append(dict(id=str(i), text=payload,
            invocation=json.dumps({'name': 'Bash', 'arguments': {'command': f'review command {i}'}}),
            sha256=hashlib.sha256(payload.encode()).hexdigest(), size_bytes=len(payload.encode()),
            strata=dict(file_type='tool-result', prose=prepare.prose(payload), tool='Bash',
                        exposure='attacker-reachable' if i == 2 else 'locally-generated', result_status='success')))
    body = b'\n'.join(json.dumps(r).encode() for r in duplicate_rows)
    digest = hashlib.sha256(body).hexdigest()
    metadata = {'units_sha256': digest, 'revision': 'sha256:' + digest}
    class MemorySnapshot:
        def __truediv__(self, name): return self
        def read_text(self): return json.dumps(metadata)
        def read_bytes(self): return body
    old_source = subprocess.check_output(['git', 'show', 'HEAD:scripts/measure_tool_traffic.py'], cwd=ROOT).decode()
    old_namespace = {'__name__': 'review_previous_traffic', '__file__': str(ROOT / 'scripts/measure_tool_traffic.py')}
    exec(compile(old_source, 'HEAD:scripts/measure_tool_traffic.py', 'exec'), old_namespace)
    old_corpus = old_namespace['corpus'](MemorySnapshot(), 'review', Surface.OUT)
    old_report = bench.measure([rr[1]], [old_corpus])
    assert any('duplicate material units' in f for f in old_report['bundle']['failures'])
    try:
        traffic.corpus(MemorySnapshot(), 'review', Surface.OUT)
    except ValueError as exc:
        current_error = str(exc)
    else:
        raise AssertionError('repeated OUT result was accepted')
    emit('repeated_OUT_behavior_change', dict(old_measurement_completed=True,
        old_admission=old_report['bundle']['bundle_ok'], old_failures=old_report['bundle']['failures'],
        current_error=current_error))

    def import_in_memory(document, local_config=None, chosen_rules=None, guarded=False):
        candidate = ROOT / '.Review-Codex-round5-memory-report.json'
        actual_read = Path.read_text
        actual_hook_rules = hook.hook_rules
        saved = []
        def read_candidate(path, *args, **kwargs):
            return json.dumps(document) if path == candidate else actual_read(path, *args, **kwargs)
        with patch.object(hook, 'read_config', return_value=copy.deepcopy(local_config or config)), \
             patch.object(Path, 'read_text', read_candidate), \
             patch.object(hook, 'hook_rules', side_effect=lambda c: (chosen_rules, []) if chosen_rules is not None else actual_hook_rules(c)), \
             patch.object(hook, 'atomic_json', side_effect=lambda p, c: saved.append(c)):
            run_import = hook.calibrate_from_report
            if guarded:
                source = inspect_module.getsource(run_import)
                start = source.index('    bundle_rows = [row for row in')
                end = source.index('    bundle = max(bundle_rows', start)
                replacement = '''    bundle_rows = []
    for surface in sorted(surfaces):
        row = _pooled(report.get("bundle", {}).get("measurements") or [], surface)
        if row is None:
            raise ValueError(f"the report carries no whole-corpus bundle measurement for {surface}")
        bundle_rows.append(row)
    if not bundle_rows:
        raise ValueError("the report carries no whole-corpus bundle measurement")
'''
                namespace = dict(vars(hook))
                exec(compile(source[:start] + replacement + source[end:], 'proposed_surface_guard', 'exec'), namespace)
                run_import = namespace['calibrate_from_report']
            outcome = run_import(ROOT / '.Review-Codex-round5-memory-config.json', candidate, accept_pooled_bound=True)
        return outcome, saved[0]
    result, saved = import_in_memory(report)
    assert result['gating_surface'] == 'OUT' and result['surfaces'] == {'IN': '0/1738', 'OUT': '1/1743'}
    assert saved['evidence']['fingerprint'] == config['evidence']['fingerprint']
    for rid, row in config['evidence']['rules'].items():
        assert {k: v for k, v in row.items() if k != 'measured_at'} == {
            k: v for k, v in saved['evidence']['rules'][rid].items() if k != 'measured_at'}
    emit('import_normal', result)
    missing = copy.deepcopy(report)
    missing['bundle']['measurements'] = [m for m in missing['bundle']['measurements']
                                         if not (m['surface'] == 'OUT' and m['stratum'] == 'all')]
    result, saved = import_in_memory(missing)
    assert result['gating_surface'] == 'IN' and result['surfaces'] == {'IN': '0/1738'}
    assert saved['evidence']['bundle']['hits'] == 0
    emit('import_missing_OUT_aggregate_accepted', result)
    partial = copy.deepcopy(report)
    partial['bundle']['failures'].append('unmeasured enabled surfaces: IN')
    try:
        import_in_memory(partial)
    except ValueError as exc:
        emit('actual_unmeasured_surface_refused', str(exc))
    else:
        raise AssertionError('a bench missing-surface failure was relaxed')

    synthetic = [replace(rule(f'builtin:review-IN-{i}', Surface.IN, f'REVIEW_INPUT_{i}'), source='builtin') for i in range(6)]
    synthetic.append(replace(rule('builtin:review-OUT', Surface.OUT, 'REVIEW_UNSEEN_OUTPUT'), source='builtin'))
    corpora = []
    for s in (Surface.IN, Surface.OUT):
        uu = tuple(unit(str(i), s, f'ordinary {s.value} unit {i}' +
                        (f' REVIEW_INPUT_{i}' if s is Surface.IN and i < 6 else ''),
                        'ordinary' if i % 2 else 'security-adjacent') for i in range(1000))
        corpora.append(bench.Corpus('review/' + s.value, 'sha256:'+'a'*64, uu, 'a'*64, ()))
    authentic = bench.measure(synthetic, corpora)
    local = hook.default_config()
    local['sources']['builtin'] = 'ADVISE'
    whole, good = import_in_memory(authentic, local, synthetic)
    good_lanes = {lane.value for lane, _ in hook.effective_lanes(good, synthetic).values()}
    assert whole['reaches'] == 'RECORD' and good_lanes == {'RECORD'}
    damaged = copy.deepcopy(authentic)
    damaged['bundle']['measurements'] = [m for m in damaged['bundle']['measurements']
                                          if not (m['surface'] == 'IN' and m['stratum'] == 'all')]
    accepted, bad = import_in_memory(damaged, local, synthetic)
    bad_lanes = {lane.value for lane, _ in hook.effective_lanes(bad, synthetic).values()}
    assert accepted['reaches'] == 'ADVISE' and bad_lanes == {'ADVISE'}
    guarded_good, _ = import_in_memory(authentic, local, synthetic, guarded=True)
    assert guarded_good == whole
    try:
        import_in_memory(damaged, local, synthetic, guarded=True)
    except ValueError as exc:
        assert str(exc) == 'the report carries no whole-corpus bundle measurement for IN'
        guard_message = str(exc)
    else:
        raise AssertionError('proposed guard accepted the missing native aggregate')
    emit('missing_aggregate_changes_actual_lanes', dict(
        authentic_IN={'trials': 1000, 'hits': 6, 'u95': lanes.binomial_u95(1000, 6)},
        authentic_OUT={'trials': 1000, 'hits': 0, 'u95': lanes.binomial_u95(1000, 0)},
        each_IN_rule={'trials': 1000, 'hits': 1, 'u95': lanes.binomial_u95(1000, 1)},
        whole_report_reaches=whole['reaches'], whole_report_effective_lanes=sorted(good_lanes),
        removed_only_IN_all_row_reaches=accepted['reaches'], removed_only_IN_all_row_effective_lanes=sorted(bad_lanes),
        proposed_guard_refuses=guard_message))


def archive():
    from agent_defs.loaders import atr
    import build_bundle
    pin = next(p for p in read(ROOT / 'sources.lock') if p['name'] == 'atr')
    archive_path = S / 'atr-pinned.tar.gz'
    archive_sha = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    assert archive_sha == pin['archive_sha256']
    class MemoryFile:
        def __init__(self, content): self.content = content
        def read_bytes(self): return self.content
    files = []
    with tarfile.open(archive_path) as tar:
        for member in tar.getmembers():
            relative = '/'.join(member.name.split('/')[1:])
            if member.isfile() and relative.startswith('rules/') and Path(relative).suffix in ('.yml', '.yaml'):
                files.append((MemoryFile(tar.extractfile(member).read()), relative))
        files.sort(key=lambda pair: pair[1])
        with patch.object(atr, '_source_files', return_value=(pin['commit'], files, 'MIT', {})), \
             patch.object(atr.atr_skill_gates, 'read_skill_gates', side_effect=atr.atr_skill_gates.GateReadError('in-memory rules-only build view')):
            loaded = atr.load(ROOT, source_rev=pin['commit'])
    assert not loaded.delta.entry_errors and len(loaded.rules) == 793
    inbound = [r for r in loaded.rules if r.surface is Surface.IN]
    runnable = [r for r in inbound if r.runnable and r.shippable and not build_bundle.screened(r)]
    held = read(ROOT / 'scripts/bundle-held-back.json')
    keep, dropped, refused = build_bundle.select(loaded.rules, ('OUT', 'IN'), held)
    trimmed, reachable = build_bundle.trim(keep)
    artifact = read(ROOT / 'src/agent_defs/bundle.json')
    assert dropped == artifact['dropped'] and refused == artifact['screen_refusals']
    assert {r.id: bench.rule_fingerprint(r) for r in trimmed} == {
        r.id: bench.rule_fingerprint(r) for r in bundle.load(ROOT / 'src/agent_defs/bundle.json')}
    emit('in_memory_build', dict(archive_sha256=archive_sha, rule_files=len(files), loaded=len(loaded.rules),
        IN=len(inbound), runnable_IN=len(runnable), held_IN=[{'id': r.id, 'title': r.title, 'reason': held[r.id]} for r in runnable if r.id in held],
        dropped=dropped, shipped=len(trimmed), reachable=reachable, files_extracted=0,
        measured_refusals=sum('refused on measurement' in r.not_runnable_reason for r in inbound),
        multiple_fields=sum(r.not_runnable_reason == 'multiple condition fields cannot be flattened into one text payload' for r in inbound)))


def diagnostic():
    import bound_leaf_discrepancy as probes
    rows, report = inputs()
    rules = [r for r in bundle.load(ROOT / 'src/agent_defs/bundle.json') if r.surface is Surface.OUT]
    native_ids = {r.id for r in rules}
    prior_hits = {m['id']: set(m['rule_ids']) & native_ids for m in report['materials'] if m['surface'] == 'OUT'}
    relaxed, splits, census, unprunable = probes.build_probes(rules)
    joined = newline = substring = 0
    gained_newline, gained_substring = Counter(), Counter()
    for row in rows:
        found = prior_hits[row['id']]
        candidates = {rid for rid, test in relaxed if rid not in found and test(row['text'])}
        lines = row['text'].split('\n')
        confirmed = {rid for rid in candidates if splits[rid](lines)}
        joined += bool(found)
        newline += bool(found | confirmed)
        substring += bool(found | candidates)
        gained_newline.update(confirmed)
        gained_substring.update(candidates)
    record = read(ROOT / 'scripts/leaf-traversal-diagnostic.json')
    assert (joined, newline, substring) == (record['joined']['hits'], record['newline_leaf_diagnostic']['hits'], record['substring_leaf_diagnostic']['hits'])
    assert gained_newline == record['newline_leaf_diagnostic']['rules_gaining']
    assert gained_substring == record['substring_leaf_diagnostic']['rules_gaining']
    assert {k: len(v) for k, v in census.items()} == record['construct_census']
    assert len(splits) == record['probed_rules'] and unprunable == record['probed_without_pruning']
    emit('diagnostic_recomputed', dict(trials=len(rows), joined=joined, newline=newline,
        substring=substring, gained_newline=gained_newline, gained_substring=gained_substring,
        original_joined_hits='reused verified report; base detector not rerun',
        all_newline_and_relaxed_candidates='recomputed from unit text'))


def provenance():
    rows, report = inputs()
    old_source = subprocess.check_output(['git', 'show', 'HEAD:scripts/prepare_tool_traffic.py'], cwd=ROOT).decode()
    topic_calls = [n for n in ast.walk(ast.parse(old_source)) if isinstance(n, ast.Call)
                   and isinstance(n.func, ast.Attribute) and n.func.attr == 'search'
                   and n.args and isinstance(n.args[0], ast.Constant)
                   and isinstance(n.args[0].value, str) and 'vulnerabilit' in n.args[0].value]
    assert len(topic_calls) == 1 and topic_calls[0].args[0].value == prepare.TOPIC.pattern
    assert prepare.TOPIC.flags & 2
    completed = datetime.fromisoformat(report['measured_at']).timestamp() + report['elapsed_s']
    paths = json.loads((ROOT / '.Review-Codex-round5-baseline.json').read_text())
    newer = {p: datetime.fromtimestamp((ROOT / p).stat().st_mtime, timezone.utc).isoformat()
             for p in paths if (ROOT / p).stat().st_mtime > completed}
    relevant = [E / f'{NAME}-out-in-report.json', S / 'enabled-in-out.json', S / 'in-config.json']
    emit('provenance', dict(report_started=report['measured_at'],
        report_completed_estimate=datetime.fromtimestamp(completed, timezone.utc).isoformat(),
        newer_worktree_mtimes=newer, file_hashes={str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in relevant},
        OUT_file_type_all_tool_result=all(r['strata']['file_type'] == 'tool-result' for r in rows),
        original_topic_regex_identical=True,
        unique_canonical_invocations=len({json.dumps(json.loads(r['invocation']), sort_keys=True, ensure_ascii=False) for r in rows}),
        per_surface_97_5_percent_bounds={s: exact_upper(n, k, .025) for s, n, k in [('IN',1738,0),('OUT',1743,1)]}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('phase')
    globals()[parser.parse_args().phase]()
~~~

</details>

<details>
<summary>.Review-Codex-round5-finalize.py</summary>

~~~python
import hashlib
import json
import os
from pathlib import Path
import subprocess

root = Path('C:/Users/yuezh/PycharmProjects/agent-defs').resolve()
temporary = root / '.Review-Codex-round5.tmp'
target = root / 'Review-Codex.md'
baseline_path = root / '.Review-Codex-round5-baseline.json'
expected_head = '36bd8fbbb2b2686726cacd2a4731355ae02808c4'
expected_paths = {
    'README.md', 'docs/calibration.md', 'docs/claude-code.md',
    'scripts/artifact-scan.json', 'scripts/bound_leaf_discrepancy.py',
    'scripts/leaf-traversal-diagnostic.json', 'scripts/measure_tool_traffic.py',
    'scripts/prepare_tool_traffic.py', 'src/agent_defs/bundle.json',
    'src/agent_defs/hooks/_claude_code_impl.py', 'tests/test_claude_code_hook.py',
    'tests/test_leaf_discrepancy_probes.py', 'tests/test_shipped_bundle.py',
    'tests/test_tool_traffic.py',
}


def git(*args):
    return subprocess.check_output(['git', *args], cwd=root)


baseline = json.loads(baseline_path.read_text(encoding='utf-8'))
assert set(baseline) == expected_paths
assert git('rev-parse', 'HEAD').decode().strip() == expected_head
assert git('diff', '--cached', '--binary') == b''
assert set(git('diff', '--name-only', 'HEAD').decode().splitlines()) == expected_paths
for path, digest in baseline.items():
    assert hashlib.sha256((root / path).read_bytes()).hexdigest() == digest, path
assert target.read_bytes() == git('show', 'HEAD:Review-Codex.md') or (
    target.read_bytes().replace(b'\r\n', b'\n') == git('show', 'HEAD:Review-Codex.md'))
git('diff', '--check', 'HEAD')
review = temporary.read_text(encoding='utf-8')
assert review.startswith('<!-- Round 5 -->\n\nVerification notes:\n')
assert review.splitlines().count('Verification status: VERIFIED') == 1
assert review.splitlines().count('Commit verdict: BLOCK') == 1
for heading in ('## New', '## Previously raised', '### Fixed', '### Still open', '### Reopened', '### Deferred'):
    assert heading in review
assert not any(c in review for c in ('\u202f', '\u2013', '\u2014'))
helpers = ['.Review-Codex-round5-probes.py', '.Review-Codex-round5-finalize.py']
for name in helpers:
    source = (root / name).read_text(encoding='utf-8')
    review += f'\n<details>\n<summary>{name}</summary>\n\n~~~python\n{source.rstrip()}\n~~~\n\n</details>\n'
assert temporary.parent.resolve() == target.parent.resolve() == root
data = review.encode('utf-8')
with temporary.open('wb') as stream:
    stream.write(data)
    stream.flush()
    os.fsync(stream.fileno())
os.replace(temporary, target)
assert target.read_bytes() == data
assert not temporary.exists()
for name in helpers + [baseline_path.name]:
    helper = root / name
    assert helper.resolve().parent == root and helper.name.startswith('.Review-Codex-round5-')
    helper.unlink()
assert git('rev-parse', 'HEAD').decode().strip() == expected_head
assert git('diff', '--cached', '--binary') == b''
for path, digest in baseline.items():
    assert hashlib.sha256((root / path).read_bytes()).hexdigest() == digest, path
assert set(git('diff', '--name-only', 'HEAD').decode().splitlines()) == expected_paths | {'Review-Codex.md'}
git('diff', '--check', 'HEAD')
assert not list(root.glob('.Review-Codex-round5-*'))
print('VERIFIED: complete Round 5 review atomically replaced and read back; helpers removed; all fourteen reviewed files unchanged; HEAD and index unchanged.')
print('Review bytes:', len(data), 'sha256:', hashlib.sha256(data).hexdigest())
~~~

</details>
