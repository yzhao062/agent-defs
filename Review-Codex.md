<!-- Round 4 -->

Verification notes:

All shell commands below ran in `C:/Users/yuezh/PycharmProjects/agent-defs`. The prescribed Python is CPython 3.12.12. PowerShell probes used `/c/Program Files/PowerShell/7/pwsh`. Root `AGENTS.md` and `AGENTS.local.md` were absent; the supplied instructions applied. Bootstrap and shared configuration refresh were skipped as instructed. The initial working tree was clean. Helpers are reproduced at the end of this review so the commands remain reproducible after cleanup.

1. These scope and environment commands completed successfully. HEAD was `199f5bbfc5b6d86fa8d2fae76a31d5f4860fa3c2`; the log contained exactly `199f5bb`, `eb745f7`, and `86534c7`. The whitespace check had no output. The historical review was Round 3.

~~~powershell
git status --short
git log --oneline 869ccd2..HEAD
git diff --stat 869ccd2..HEAD
git diff --name-only 869ccd2..HEAD
git diff --check 869ccd2..HEAD
git rev-parse HEAD
git show HEAD~3:Review-Codex.md
& 'C:\Users\yuezh\miniforge3\envs\py312\python.exe' --version
~~~

The complete diff was read in these two batches:

~~~powershell
git diff 869ccd2..HEAD -- src/agent_defs/sources.py src/agent_defs/hooks/_claude_code_impl.py src/agent_defs/hooks/_core.py tests/test_sources.py tests/test_hook_core.py
git diff 869ccd2..HEAD -- src/agent_defs/lanes.py scripts/bound_leaf_discrepancy.py tests/test_bound_within.py tests/test_leaf_discrepancy_probes.py docs/calibration.md SAMPLES.md
~~~

2. Full-suite command, exit 0: **717 passed, 6 skipped, 1 warning in 42.48 seconds**. The warning was the existing possible nested regex set in `test_evaluate_adversarial.py`. The source tests mock downloads and block unexpected network access; no real corpus was fetched by this suite. The reported nine-runner CI result was supplied by the requester, not independently rerun here.

~~~powershell
$env:PYTHONPATH = 'src'
& 'C:\Users\yuezh\miniforge3\envs\py312\python.exe' -m pytest -q
~~~

3. Archive-control probe, exit 0. Both a tar symlink and a tar hardlink materialized harmless marker bytes from excluded members under `rules/`; `verify()` returned `verified`. A second fetch was a cache hit. Six mutations were rejected by both `verify()` and `fetch()`: changed content, missing content, an extra file, an added excluded file, an added excluded directory, and removal of a required empty parent. Replaying the pre-range reader against this excluded-path cache raised `SourceError` without another download. The only `fetch()` calls outside the suite used this synthetic archive and a mocked response.

~~~powershell
& 'C:\Users\yuezh\miniforge3\envs\py312\python.exe' .Review-Codex-round4-probes.py sources
~~~

4. Numerical commands, both exit 0. The helper was recovered unchanged from the embedded Round 3 numerical probe and executed against current code.

~~~powershell
& 'C:\Users\yuezh\miniforge3\envs\py312\python.exe' .Review-Codex-round4-numeric.py capped
& 'C:\Users\yuezh\miniforge3\envs\py312\python.exe' .Review-Codex-round4-numeric.py coefficient
~~~

The search checked both adjacent integer trial counts at every positive-hit boundary below the cap for both lane ceilings. SciPy located the boundaries; 60-digit mpmath independently checked the largest observed errors and the three original witnesses.

| Ceiling | Boundary pairs checked | Unresolved | Wrong resolved decisions | Largest observed absolute log-CDF error, checked with mpmath |
|---|---:|---:|---:|---:|
| 0.001 | 19,670 | 628 | 0 | 7.32850e-8 |
| 0.005 | 99,264 | 1,415 | 0 | 8.35963e-8 |

All three original witnesses returned `None`; actual adapter lane resolution returned ADVISE, RECORD, RECORD. The full suite exercised both out-of-domain witnesses through `bound_within` and `admit`, and the cap boundary. The coefficient probe reproduced **-8.3614283313323e-8** at `(n, k) = (9,892,023, 49,095)`. These are empirical checks on this interpreter, not a proof across platforms or arbitrary thresholds.

5. Hook differential probe, exit 0: **1,200 generated cases, zero mismatches** between the actual pre-range `process` body and current `process`. Compared responses, ordered records, scanner calls, byte allowances, and supplied time budgets across nested payloads, IN/OUT, exhausted limits, empty and whitespace leaves, Unicode/surrogates, denied leaves, incomplete results, and scanner exceptions. The probe also rebound the adapter's `WITHHELD` and `INCOMPLETE`. Scalar NaN generated a spurious update in both versions; a nested NaN did not. A self-referential list returned in both versions under the tested depth limit.

~~~powershell
& 'C:\Users\yuezh\miniforge3\envs\py312\python.exe' .Review-Codex-round4-probes.py hooks
~~~

6. Diagnostic probe, final command exit 0. Two evaluator-accepted patterns each produced an actual leaf hit but zero joined, newline-diagnostic, and substring-diagnostic hits through the diagnostic's main entry point. The 205 shipped rules reproduced the committed classification: 102 probed, zero unprunable, identical construct census. This did not rerun the 1,743-unit corpus replay.

~~~powershell
& 'C:\Users\yuezh\miniforge3\envs\py312\python.exe' .Review-Codex-round4-probes.py regex
~~~

The initial direct rewrite probe succeeded. Its first extension to evaluator execution exited 1 because the capture-renumbering witness was rejected by the evaluator as an unsupported backreference. The corrected probe records that rejection and exercises the two accepted witnesses. The rejected witness is not reported as a reachable evaluator failure.

7. Mutation probe, exit 0 because the assertions confirm the test gap: removing only the node/depth/time guard's `return node` left **all 12 tests in `test_hook_core.py` passing**, although the scanner ran with all three budgets exhausted. As a control, the existing adapter integration test failed on the same in-memory mutation, observing budgets `[1.0, 0]` instead of `[1.0]`. No implementation file was mutated.

~~~powershell
& 'C:\Users\yuezh\miniforge3\envs\py312\python.exe' .Review-Codex-round4-probes.py vacuity
~~~

8. These PowerShell commands ran the real scanner script with a harmless review artifact and mocked directory creation. No scanner ran, no artifact scan copy was created, and cleanup validated its temporary targets.

~~~powershell
& ./.Review-Codex-round4-scan.ps1 -Mode setup
exit $LASTEXITCODE
~~~

Exit 2 as expected: a synthetic setup failure replaced the prior clean record with an inconclusive result.

~~~powershell
& ./.Review-Codex-round4-scan.ps1 -Mode locked
exit $LASTEXITCODE
~~~

Exit 3 as expected: `File.Replace` failed against a destination opened without delete sharing, preserved the prior bytes, and reported publication failure.

~~~powershell
& ./.Review-Codex-round4-scan.ps1 -Mode missing-parent
exit $LASTEXITCODE
~~~

Exit 1, the defect witness: `WriteAllText` raised outside the publication guard when the destination's parent did not exist. No result was published at that destination. The harness's separate control record remained unchanged; it is not evidence of a stale record at the missing destination.

9. Pinned ATR inspection command, exit 0 on its final execution. The archive was downloaded into a `BytesIO`-backed tar reader and never written. Its 42,260,904 bytes matched `sources.lock` sha256 `5d00c6b4b01cc2543277dc9b6ca9b3ec4bb205639621d66bdd8701639e54daf5`. Rule loading used in-memory file objects. Sample inspection computed digests and JSON schemas in memory; neither sample bytes nor sample text were written or printed. The final run also evaluated the proposed policy in memory and read CFG gates from its four explicitly selected source files.

~~~powershell
& 'C:\Users\yuezh\miniforge3\envs\py312\python.exe' .Review-Codex-round4-atr.py
~~~

Results: 20,015 tar members, 19,405 regular files, 793 YAML rules, zero loader errors, zero archive links. Current policy excludes 1,602 files and would materialize 17,803. The proposed ATR policy retains 798 files: 793 rules, the licence, and four gate inputs. CFG gate reading succeeded with that selection. Using a different source name retained the current non-ATR selection on the same archive. The earlier inspection executions completed successfully; the final helper corrects its initial coarse refusal categorization and adds the policy check.

The independent `IN` count is **57 total, 14 runnable/shippable/evaluator-screened, 16 refused only for multiple fields, 25 refused on measurement, and two additional refusals**. Details appear below. The requester’s 26 measured refusals was not reproduced.

10. Finalization command, exit 0 on the completed run: checked HEAD and the unchanged 11-file range, confirmed implementation and index remained unchanged, embedded the verification helpers, flushed the complete sibling temporary review, atomically replaced `Review-Codex.md` with `os.replace`, read it back, and removed only the named review helpers. Final tracked change: `Review-Codex.md` only.

~~~powershell
& 'C:\Users\yuezh\miniforge3\envs\py312\python.exe' .Review-Codex-round4-finalize.py
~~~

Verification status: VERIFIED

Commit verdict: BLOCK

The archive control still materializes known attack collections, and excluded bytes can bypass it through links. The leaf diagnostic also still prunes real matches. The numerical cap and hook refactor passed the relevant checks; neither passing tests nor an empirical numerical margin establishes the broader security and rewrite claims.

File/diff scope: **`git diff 869ccd2..199f5bbfc5b6d86fa8d2fae76a31d5f4860fa3c2`**, not the index. Eleven changed files: `SAMPLES.md`, `docs/calibration.md`, `scripts/bound_leaf_discrepancy.py`, `src/agent_defs/hooks/_claude_code_impl.py`, `src/agent_defs/hooks/_core.py`, `src/agent_defs/lanes.py`, `src/agent_defs/sources.py`, `tests/test_bound_within.py`, `tests/test_hook_core.py`, `tests/test_leaf_discrepancy_probes.py`, and `tests/test_sources.py`. Ancillary review of unchanged base files was limited to verifying Round 3 repairs, caller dependencies, and the committed diagnostic census, including `scripts/scan_artifact.ps1` and `scripts/build_bundle.py`. New findings identify retained defects when they predate the range.

Review lens: code correctness and whether the security control and diagnostic guarantees follow from their implementation. This is not an antivirus clearance, attack-recall evaluation, or publication approval.

## New

### N10. High: links bypass the excluded-source guard, and the shared verifier accepts the result

Location: `src/agent_defs/sources.py:88`.

`_layout` resolves each link to a regular `TarInfo`, but retains the link's destination as the dictionary key. `_kept` examines only that key. A symlink `rules/symlink.txt -> ../data/test-corpora/payload.txt` or a hardlink `rules/hardlink.txt -> repo/conformance/v1.0/fixtures/tp/marker.txt` therefore copies excluded bytes into `rules/`. Both were reproduced using harmless marker bytes; no actual attack sample was needed. The excluded directories did not exist, while the copies did, and both cache-hit `fetch()` and `verify()` accepted them.

The extraction bypass predates this range. The new shared filter preserves it and additionally makes the resulting excluded-member cache pass verification. The pinned ATR archive has no links, so this is a generic archive-control failure, not the cause of the particular ATR incident.

Exact minimal rewrite at `src/agent_defs/sources.py:88`, replacing the `kept_files` comprehension:

~~~python
    kept_files = {
        relative: member for relative, member in files.items()
        if not _is_excluded(PurePosixPath(relative).parts)
        and not _is_excluded(_safe_parts(member.name)[1:])
    }
~~~

This checks both the destination and the already-resolved source after removing the repository root. Preserve the shared writer/verifier policy and test symlinks and hardlinks in both directions. The larger rewrite under N11 includes this protection too.

### N11. High: the pinned ATR tree already contains further unexcluded attack collections

Locations: `src/agent_defs/sources.py:59`, `src/agent_defs/sources.py:88`, `SAMPLES.md:85`.

This is not merely a possibility on a future pin. At the locked revision, `_kept(*_layout(archive))` retains these regular files:

| Retained archive-relative file | In-memory structural check |
|---|---|
| `data/autoresearch/adversarial-samples.json` | 1,054 records; fields include `payload`, `technique`, and `original_rule_id` |
| `data/autoresearch/missed-payloads.json` | 895 records; fields include `payload`, `technique`, and `original_rule_id` |
| `data/evasion-payloads.json` | 64 records; fields include `payload`, `expected`, and `detection_field` |
| `data/semantic-validation/attacks.json` | 20 records; fields include `payload`, `label`, and `technique` |
| `data/pint-benchmark/pint-corpus.json` | 850 corpus records; fields include `text`, `category`, and `label`; not all are asserted malicious |

These are payload-bearing collections, not just filenames that sound suspicious. The present extraction loop would write them normally. This review makes no claim that a particular collection triggers Bitdefender, and did not test that by writing it. The bytes and selection were checked against the [pinned ATR archive](https://codeload.github.com/Agent-Threat-Rule/agent-threat-rules/tar.gz/faf743fee8a5018467959ec8ea7ccdb1a1aab333).

Recommend an ATR-specific input allow-list now. The main tradeoff is declaring the small additional inputs needed by its CFG loader. A global `rules/`-and-licence rule is incompatible with other loaders: Netzilo reads `ai_agent/`, AAK reads `rules.json`, AVE reads `records/` and `crosswalks/`, and Guardana reads `docs/generated/rules.json`. ATR itself reads three TypeScript files and the interface contract to establish CFG gates; dropping those silently removes CFG bindings.

Exact replacement for `_kept` at `src/agent_defs/sources.py:73`, including N10's source check:

~~~python
def _kept(files, directories, *, name, license_path):
    required = {
        _portable_path(license_path),
        "src/engine.ts",
        "src/enforcement.ts",
        "src/quality/rule-contract.ts",
        "engines/typescript/INTERFACE-CONTRACT.md",
    }

    def allowed(relative):
        parts = PurePosixPath(relative).parts
        if _is_excluded(parts):
            return False
        return name != "atr" or parts[0] == "rules" or relative in required

    kept_files = {
        relative: member for relative, member in files.items()
        if allowed(relative)
        and allowed(_portable_path("/".join(_safe_parts(member.name)[1:])))
    }
    if name == "atr":
        kept_dirs = {
            str(parent) for relative in kept_files
            for parent in PurePosixPath(relative).parents if str(parent) != "."
        }
    else:
        kept_dirs = {relative for relative in directories if allowed(relative)}
    return kept_files, kept_dirs
~~~

Exact replacement call at `src/agent_defs/sources.py:278`:

~~~python
            files, directories = _kept(
                *_layout(archive), name=name, license_path=entry["license_path"])
~~~

Exact replacement call at `src/agent_defs/sources.py:335`:

~~~python
                files, directories = _kept(
                    declared, all_directories, name=name,
                    license_path=entry["license_path"])
~~~

The standalone proposed filter was executed against the pinned layout in memory: 798 selected inputs, no `data/` members, and successful CFG gate parsing from the selected source files. This is a checked recommendation, not an applied implementation or a full regression test of the proposed patch. Update directory-policy fixtures accordingly and add the sample/link regressions.

Also replace the universal sentence at `SAMPLES.md:85` with this narrower statement:

~~~text
The selection materialized 793 rule files and the licence, and refused 18,611
other regular files. An input allow-list prevents unrelated upstream directories
from being extracted. It does not certify the contents of an allowed rule file.
~~~

An upstream sample can be added under `rules/`, and existing rule YAML can contain positive examples. Consequently neither this cheap policy nor the uncommitted rules-only script warrants “a sample cannot reach disk ... whatever upstream grows.” The policy should promise a bounded selection of declared inputs.

### N12. Low: the claimed automatic re-download mechanism is not in `fetch`

Locations: `SAMPLES.md:77`, `src/agent_defs/sources.py:80`, `src/agent_defs/sources.py:277`.

The old writer/verifier disagreement is real and the new shared layout fixes it. The stated consequence is wrong: `fetch()` immediately returns `_check()` for an existing cache, and a failed check raises `SourceError`. It does not fall through to download, remove the cache, or retry extraction. I executed the old reader against an excluded-path cache and confirmed zero additional requests. Repeated materialization requires a different/missing cache, external removal or retry logic, or failure before publication. The described cleanup failure could be relevant to the last case, but the verifier mismatch alone does not establish the incident's recurrence mechanism.

Replace the causal claim with: “A cache containing excluded archive paths failed verification on reuse. Subsequent fetches raised `SourceError` until the cache state changed. Sharing the filter fixes that disagreement; repeated downloads require a separate explanation.” Apply the correction in all three locations. The new source tests establish a valid cache hit, not an old automatic retry loop.

### N13. Low: the new budget tests can pass while scanning past every traversal limit

Location: `tests/test_hook_core.py:122`.

The parametrized budget test checks `incomplete` and unchanged output, but its clean scanner also returns unchanged output if it runs. Deleting only the budget guard's early return makes it continue scanning after setting `incomplete`; all 12 tests in this new module still pass. The existing adapter integration test detects that mutation, so the complete suite is not vacuous in this way.

Add `assert scanner.seen == []` after the call at line 124. Retain the positive scanner-injection test, which prevents “never call the scanner” from satisfying the module. The finding concerns this test's claimed stopping contract; no corresponding runtime regression was found in HEAD.

### N14. Low: temporary-record write failures escape the new publication exit contract

Location: `scripts/scan_artifact.ps1:62` (Round 3 fix follow-up, unchanged within this range).

`WriteAllText` is before the publication `try`. With `-Out` beneath a nonexistent directory, it throws without setting `PublishFailed`; the script invocation fails with exit 1, which the documented protocol assigns to a detection, instead of exit 3 for an unpublished result. The probe mocked setup failure so no scanner ran. This does not refute `File.Replace` atomicity or reproduce a false clean result.

Move the temporary-file write inside the same `try` as `File.Replace`/`File.Move`, so ordinary write failures use the existing stderr message and exit-3 path. Keep the original record intact if publication cannot complete.

## Previously raised

### Fixed

**N6:** The residual hook-frequency assertion was removed. `scripts/build_bundle.py:149` now states that the nonempty whitespace leaf matches and that the fixtures do not establish deployed frequency. The full suite passed the artifact/fixture checks.

**N8:** The demonstrated setup-failure hole is fixed. The run record exists before artifact lookup/hash/directory creation inside the guarded operation; an injected directory-creation failure replaced an existing clean record and returned exit 2. The wording now limits the record promise to handled failures and distinguishes publication failure. This is not a promise against interruption or an unwritable destination.

**N9:** The original destructive replacement failure is fixed. Actual `File.Replace` against a locked destination preserved the prior bytes and the script returned exit 3. The ordinary successful replacement was exercised by the setup-failure test. N14 is a separate residual failure to include the temporary write in that publication guard.

**N1, N2, N3, N7:** No reopening evidence in the reviewed range or passing suite. The previously closed native-refusal, aggregate-set, post-selection-disclosure, and required-artifact-test findings remain closed for this review. Their entire earlier evidence base was not reconstructed again.

### Still open

#### N4. Medium: the unsupported-pattern detector still misses quantified lookarounds

Locations: `scripts/bound_leaf_discrepancy.py:213`, `scripts/bound_leaf_discrepancy.py:260`, `docs/calibration.md:223`.

The original directly adjacent quantified lookaround, atomic/possessive cases, and conditional classification are now refused from pruning. The 3.9-compatible classification tests correctly inspect syntax before attempting to compile constructs unavailable on that interpreter. The disclosure that all-lines splitting is not the hook decomposition is also fixed.

However, checking only `pattern[end]` after the lookaround misses syntax the regex parser ignores before applying a quantifier. Both examples below compile through the actual evaluator, match the leaf `abc`, and fail on joined text `x\nabc\ny`. Both receive an empty unsupported set, then the rewrite moves `{0}` onto the preceding `b`:

| Pattern | Incorrect relaxed pattern | Full diagnostic result |
|---|---|---|
| `(?x)^ab(?=x) {0} c$` | `(?x)ab {0} c` | leaf 1; joined/newline/substring 0/0/0 |
| `^ab(?=x)(?#comment){0}c$` | `ab(?#comment){0}c` | leaf 1; joined/newline/substring 0/0/0 |

The split probe itself finds `abc`; the false negative occurs when the relaxed candidate filter prevents that probe from running. Thus the `UNSUPPORTED` names are not sufficient to make the implemented classification complete. No additional assertion-free, evaluator-supported construct outside the named classes was established; the concrete failure is missing valid spellings of an existing class.

A separate generic rewrite counterexample, `^(a)(?=(b))(bc)\2$`, loses its match on `abcb` when removing the lookahead renumbers captures. The evaluator rejects backreferences, so this is a limitation of the helper's general claim, not an accepted-rule counterexample in the deployed evaluator.

A cheap conservative fix is to make every pattern containing a lookaround unprunable; otherwise classify parsed quantification with correct handling of verbose whitespace and comment groups. Add the two accepted examples through candidate selection and the full diagnostic entry point. Until then, withdraw the remaining “only widens” assertion in the script, JSON method string, and calibration paragraph. The regenerated 205-rule census matches the committed record; these examples do not establish that its stored 489 candidates change.

#### N5. Low residual wording: the domain leak is fixed, but the stated empirical headroom is inconsistent

Locations: `src/agent_defs/lanes.py:75`, `src/agent_defs/lanes.py:143`.

The substantive cap repair passes: `bound_within` owns `MAX_SUPPORTED_TRIALS`, the adapter aliases it, both large-count witnesses are refused by the shared routine, and `admit` stays RECORD. The repeated capped search found zero wrong resolved decisions across 118,934 pairs. The old incorrect derivation is explicitly withdrawn.

The replacement comment still says the worst observed coefficient error is about 2.7e-8 and the margin has roughly thirty-fold headroom, immediately after recording a larger in-domain error. The independently reproduced magnitude is 8.3614283313323e-8, leaving about **12-fold**, not thirty-fold, headroom over this known witness. A limited sweep can have a 2.7e-8 maximum; it is not the maximum over the observations now available. The docstring's “where `LOG_CDF_SLACK` bounds it” also states a guarantee the empirical disclaimer does not establish.

State the two observed maxima with their scopes and call the slack an empirical refusal band throughout. For example: “A limited sweep observed about 2.7e-8; the adversarial witness above reaches 8.36e-8. The 1e-6 band is about twelve times that known error. This is empirical headroom, not a proved bound.” This residual wording is not a numerical counterexample inside the cap and is not itself a blocker.

The revised inverted-bound test appropriately checks proximity to the ceiling and independent exact truth without requiring a particular floating-point side. Its tolerance admits both reported platform values, and it passed here. A direct comparison of the two supplied Windows/glibc and macOS values would indeed choose different sides; the claim about a lane determined that way is correct. This review did not execute macOS. The fixed witness's refusal is well inside the empirical band; do not generalize the observed cross-runner agreement into a guarantee for all comparisons near the band's edges.

### Reopened

None. N4 and N5 retain specifically identified unfinished parts. N9's original atomicity defect is closed; N14 identifies a different write-failure boundary.

### Deferred

The original attack/benign corpus replay, actual antivirus execution, full deployed `tool_response` capture and calibration, and platform-wide numerical certification were not performed. The global migration of other corpus loaders to declared extraction inputs remains broader than the ATR-specific recommendation. The asynchronous RECORD design, unused Pre registration, capture/completion ledger, and interleaved latency work from prior reviews remain outside this change.

## Hook and cache conclusions

The hot-path extraction preserves the old traversal for the supported payload shapes checked. Nodes are still charged before the limits check; empty strings skip scanning only after that check; scanner exceptions do not debit bytes; successful calls use the same UTF-8/surrogatepass byte arithmetic. Incomplete-detail records precede findings, and the aggregate incomplete record remains last. Withholding still requires DENY and OUT. JSON Pointer escaping still replaces `~` before `/`. No string leaf was scanned twice or omitted differently in the differential tests. Existing integration tests additionally exercise the advancing shared clock and truncated-result hashing.

Rebinding the adapter's `WITHHELD` still works because `process` explicitly passes `withheld=WITHHELD`. `INCOMPLETE` is read by the adapter when forming the response; traversal does not use it. Existing clock tests patch the attribute of the shared `time` module, so they still control the core clock. The feared marker-rebinding vacuity is not present in HEAD.

`Outcome.changed` means inequality, not necessarily a withholding event. A scalar NaN is unequal to itself and triggers an update in both old and new code. Python's `json.loads` accepts the nonstandard `NaN` token, so this is reachable at the hook's raw input boundary even though valid JSON has no NaN. Nested NaNs are the same object in the reconstructed containers and do not necessarily produce inequality. JSON decoding cannot create a self-referential container; direct Python callers can. The tested cycle was bounded and returned in both versions, although a resulting cyclic object cannot be serialized as JSON. These are pre-existing boundary semantics, not a refactor regression. Rename the property's docstring to describe inequality if its implementation remains unchanged.

For ordinary non-link members, `_kept` now correctly aligns extraction, cache hits, and `verify()`. A retained parent such as `data/` can remain empty after `data/test-corpora/` is excluded; that writes no sample and does not remove a loader input. Removing that expected parent is correctly rejected by the current exact-tree contract. I did not find a new acceptance of changed bytes, extra/missing regular paths, or inserted excluded directories. The policy-invalid link result in N10 is the demonstrated acceptance failure; it is not an attacker modifying the archive behind an unchanged digest. Files outside `tree/`, such as the informational `EXCLUDED` marker, are not newly brought into the verified-content contract by this change.

## ATR count reconciliation

The in-memory load used the actual ATR loader with only its file-discovery/read boundary replaced by memory objects. Its normalization, shippability property, and evaluator screen were unchanged. CFG reading was deliberately absent for the IN count; the separate proposed-profile check verified that the four selected source inputs suffice for gate reading.

| Mutually exclusive outcome | Count |
|---|---:|
| Runnable, shippable, evaluator-screened | 14 |
| Reason is exactly “multiple condition fields cannot be flattened into one text payload” | 16 |
| Reason contains “refused on measurement” | 25 |
| Other refusal | 2 |
| Total IN | 57 |

The two residual rules are `ATR-2026-01602`, refused for code-block suppression plus multiple condition fields, and `ATR-2026-02557`, refused for code-block suppression. Reasons overlap: 27 IN rules mention multiple condition fields in total, including 10 measurement refusals and `ATR-2026-01602`. Counting 16 exact field-only refusals is valid; counting 26 measurement refusals was not reproduced. No raw rule examples are included here.

## Reproducible verification helpers

These are temporary review instrumentation, not proposed repository additions. A successful witness probe means it reproduced and asserted the reported defect. The policy helper is the unapplied recommendation checked in memory. The finalizer embeds these sources before removing the named helper files.

<details>
<summary>.Review-Codex-round4-probes.py</summary>

~~~python
import ast
from contextlib import contextmanager
from dataclasses import replace
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import random
import re
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'src'))
from agent_defs import sources, bundle, evaluate
from agent_defs.hooks import _core, _claude_code_impl as hook
from agent_defs.model import Lane, PredicateKind, Rule, Surface


def load_diagnostic():
    spec = importlib.util.spec_from_file_location('diagnostic', ROOT / 'scripts/bound_leaf_discrepancy.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def archive_probe():
    marker = b'harmless review marker, not an attack sample\n'
    entries = [('repo/rules/ok.yaml', b'id: harmless\n', None),
               ('repo/data/test-corpora/payload.txt', marker, None),
               ('repo/conformance/v1.0/fixtures/tp/marker.txt', marker, None),
               ('repo/rules/symlink.txt', b'', ('sym', '../data/test-corpora/payload.txt')),
               ('repo/rules/hardlink.txt', b'', ('hard', 'repo/conformance/v1.0/fixtures/tp/marker.txt'))]
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w:gz') as archive:
        for name, data, link in entries:
            member = tarfile.TarInfo(name)
            if link:
                member.type = tarfile.SYMTYPE if link[0] == 'sym' else tarfile.LNKTYPE
                member.linkname = link[1]
                archive.addfile(member)
            else:
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
    blob = buf.getvalue()
    entry = dict(name='synthetic', repo_url='https://github.com/fixture/review', commit='1'*40,
                 archive_sha256=hashlib.sha256(blob).hexdigest(), fetched_at='2026-09-06T00:00:00Z',
                 license_spdx='MIT', license_path='LICENSE', record_count=1)
    calls = []

    @contextmanager
    def download(*args):
        calls.append(args)
        yield io.BytesIO(blob)

    with tempfile.TemporaryDirectory(prefix='agent-defs-round4-synthetic-') as temporary:
        root = Path(temporary)
        lock = root / 'lock.json'
        lock.write_text(json.dumps([entry]), encoding='utf-8')
        with patch.object(sources, '_response', download):
            tree = sources.fetch('synthetic', root / 'cache', lock_path=lock)
            assert not (tree / 'data/test-corpora').exists()
            assert not (tree / 'conformance').exists()
            assert (tree / 'data').is_dir()
            assert (tree / 'rules/symlink.txt').read_bytes() == marker
            assert (tree / 'rules/hardlink.txt').read_bytes() == marker
            assert sources.verify(root / 'cache', lock_path=lock)['synthetic']['status'] == 'verified'
            assert sources.fetch('synthetic', root / 'cache', lock_path=lock) == tree
            assert len(calls) == 1
            rejected = []
            for mode in ('edit', 'missing', 'extra', 'excluded_file', 'excluded_directory', 'missing_parent'):
                target = tree / 'rules/ok.yaml'
                original = target.read_bytes()
                if mode == 'edit': target.write_bytes(b'tampered harmless marker')
                if mode == 'missing': target.unlink()
                if mode == 'extra': (tree / 'extra.txt').write_bytes(marker)
                if mode == 'excluded_file':
                    (tree / 'conformance').mkdir()
                    (tree / 'conformance/extra.txt').write_bytes(marker)
                if mode == 'excluded_directory': (tree / 'conformance').mkdir()
                if mode == 'missing_parent': (tree / 'data').rmdir()
                assert sources.verify(root / 'cache', lock_path=lock)['synthetic']['status'] == 'invalid', mode
                try:
                    sources.fetch('synthetic', root / 'cache', lock_path=lock)
                except sources.SourceError:
                    rejected.append(mode)
                else:
                    raise AssertionError(mode)
                assert len(calls) == 1
                if mode in ('edit', 'missing'): target.write_bytes(original)
                if mode == 'extra': (tree / 'extra.txt').unlink()
                if mode == 'excluded_file': (tree / 'conformance/extra.txt').unlink()
                if mode in ('excluded_file', 'excluded_directory'): (tree / 'conformance').rmdir()
                if mode == 'missing_parent': (tree / 'data').mkdir()
            # Replay the pre-range reader against the same excluded-path cache.
            old = subprocess.check_output(['git', 'show', '869ccd2:src/agent_defs/sources.py'], cwd=ROOT).decode()
            namespace = {'__file__': str(ROOT / 'src/agent_defs/sources.py'), '__name__': 'old_sources'}
            exec(compile(old, 'old_sources.py', 'exec'), namespace)
            with patch.dict(namespace, {'_response': download}):
                try:
                    namespace['fetch']('synthetic', root / 'cache', lock_path=lock)
                except namespace['SourceError']:
                    pass
                else:
                    raise AssertionError('old cache check should reject this tree')
            assert len(calls) == 1
            print(json.dumps(dict(link_bytes_written=['symlink', 'hardlink'], unsafe_tree_status='verified',
                                  tampering_rejected=rejected, requests=1, old_reader='raises without redownload')))


def regex_probe():
    diagnostic = load_diagnostic()
    cases = [(r'^(a)(?=(b))(bc)\2$', 'abcb', 'x\nabcb\ny'),
             (r'(?x)^ab(?=x) {0} c$', 'abc', 'x\nabc\ny'),
             (r'^ab(?=x)(?#comment){0}c$', 'abc', 'x\nabc\ny')]
    for pattern, leaf, joined in cases:
        strict = re.compile(pattern)
        relaxed, kinds = diagnostic.strip_assertions(pattern)
        assert strict.search(leaf)
        assert not strict.search(joined)
        assert not diagnostic.unsupported_constructs(pattern)
        assert relaxed is not None and not re.search(relaxed, joined)
        fake = SimpleNamespace(id='t:probe', predicate_kind=PredicateKind.REGEX, predicate=pattern,
                               case_sensitive=True)
        loose, splits, census, unprunable = diagnostic.build_probes([fake])
        assert not loose[0][1](joined)
        assert splits[fake.id](joined.split('\n'))
        real = Rule(id='t:probe', source='t', source_id='probe', source_rev='1'*40,
                    source_path='rules/probe.yaml', upstream_url='https://example.test', title='probe',
                    surface=Surface.OUT, predicate_kind=PredicateKind.REGEX, predicate=pattern,
                    case_sensitive=True)
        accepted = True
        try:
            evaluate.compile_rule(real)
        except ValueError as exc:
            accepted = False
            print(json.dumps(dict(evaluator_rejection=str(exc))))
        print(json.dumps(dict(pattern=pattern, leaf=leaf, relaxed=relaxed, assertion_kinds=sorted(kinds),
                              unsupported=[], true_split=True, candidate=False,
                              joined_match=bool(strict.search(joined)), evaluator_accepts=accepted)))
        if not accepted:
            continue
        with tempfile.TemporaryDirectory(prefix='agent-defs-round4-regex-') as temporary:
            temp = Path(temporary)
            units, report = temp / 'units.jsonl', temp / 'report.json'
            units.write_text(json.dumps({'text': joined}) + '\n', encoding='utf-8')
            with patch.object(diagnostic.bundle, 'load', lambda _: [real]):
                with patch.object(sys, 'stdout', io.StringIO()):
                    assert diagnostic.main(['--units', str(units), '--rules', str(ROOT/'src/agent_defs/bundle.json'),
                                            '--out', str(report)]) == 0
            data = json.loads(report.read_text())
            assert data['joined']['hits'] == data['newline_leaf_diagnostic']['hits'] == data['substring_leaf_diagnostic']['hits'] == 0
            assert diagnostic.hits(leaf, [real]) == {'t:probe'}
    shipped = bundle.load(ROOT / 'src/agent_defs/bundle.json')
    relaxed, splits, census, unprunable = diagnostic.build_probes(shipped)
    record = json.loads((ROOT / 'scripts/leaf-traversal-diagnostic.json').read_text())
    assert len(shipped) == 205 and len(splits) == record['probed_rules'] == 102
    assert unprunable == record['probed_without_pruning'] == []
    assert {k: len(v) for k,v in sorted(census.items())} == record['construct_census']
    print('VERIFIED: evaluator-accepted witnesses have leaf=1, joined/newline/substring=0; shipped 205-rule classification matches the committed record.')


def hook_probe():
    old = subprocess.check_output(['git', 'show', '869ccd2:src/agent_defs/hooks/_claude_code_impl.py'], cwd=ROOT).decode()
    parsed = ast.parse(old)
    process = next(n for n in parsed.body if isinstance(n, ast.FunctionDef) and n.name == 'process')
    old_process = ast.Module(body=[process], type_ignores=[])
    scope = hook.__dict__.copy()
    exec(compile(old_process, 'old_process.py', 'exec'), scope)
    prior = scope['process']
    rule = SimpleNamespace(id='r', surface=SimpleNamespace(value='OUT'))
    config = dict(surfaces=['OUT', 'IN'])
    rng = random.Random(4606)

    def payload(depth=0):
        if depth > 3 or rng.random() < .5:
            return rng.choice(['', ' ', 'abc', 'deny', 'partial', 'error', '\ud800', 'é🙂', None, 2, True])
        if rng.random() < .5:
            return [payload(depth+1) for _ in range(rng.randrange(5))]
        return {f'a~/{i}': payload(depth+1) for i in range(rng.randrange(5))}

    def one(fn, value, surface, limit):
        records, calls = [], []
        def scanner(text, rules, **kwargs):
            calls.append((text, kwargs))
            if text == 'error': raise MemoryError('synthetic')
            finding = SimpleNamespace(rule_id='r', start=0, end=1)
            return SimpleNamespace(complete=text != 'partial', rules_evaluated=0 if text == 'partial' else 1,
                                   rules_skipped_budget=0, errors=(), worker_error=None, truncated_input=False,
                                   partial_findings=[finding] if text == 'deny' else [])
        changes = dict(active_rules=lambda c, r: r,
                       effective_lanes=lambda c, r: {'r': (Lane.DENY, 'measured')},
                       log_status=lambda c, r: records.extend(r) or True,
                       scan=scanner, MAX_SCAN_BYTES=limit[0], MAX_NODES=limit[1],
                       MAX_DEPTH=limit[2], SCAN_BUDGET_S=limit[3], WITHHELD='custom withheld',
                       INCOMPLETE='custom incomplete')
        field = 'tool_response' if surface == 'OUT' else 'tool_input'
        event = 'PostToolUse' if surface == 'OUT' else 'PreToolUse'
        rule.surface.value = surface
        with patch.dict(fn.__globals__, changes), patch.object(hook.time, 'perf_counter', lambda: 0):
            result = fn(dict(hook_event_name=event, **{field: value}), config, [rule])
        return result, records, calls

    for i in range(1200):
        value = payload()
        surface = rng.choice(['IN', 'OUT'])
        limit = rng.choice([(20, 20, 3, 1), (0, 20, 3, 1), (20, 1, 3, 1), (20, 20, 0, 1), (20, 20, 3, 0)])
        assert one(prior, value, surface, limit) == one(hook.process, value, surface, limit), i
    nan = float('nan')
    old_nan = one(prior, nan, 'OUT', (20, 20, 3, 1))[0]
    new_nan = one(hook.process, nan, 'OUT', (20, 20, 3, 1))[0]
    assert 'updatedToolOutput' in old_nan['hookSpecificOutput']
    assert 'updatedToolOutput' in new_nan['hookSpecificOutput']
    assert one(prior, {'n': nan}, 'OUT', (20, 20, 3, 1))[0] == {}
    assert one(hook.process, {'n': nan}, 'OUT', (20, 20, 3, 1))[0] == {}
    cycle = []
    cycle.append(cycle)
    outcomes = []
    for fn in (prior, hook.process):
        try: one(fn, cycle, 'OUT', (20, 20, 3, 1))
        except RecursionError: outcomes.append('RecursionError')
        else: outcomes.append('returned')
    print(json.dumps(dict(differential_cases=1200, mismatches=0, root_nan='spurious update in both',
                          nested_nan='unchanged in both', cycles=outcomes,
                          adapter_markers='custom WITHHELD and INCOMPLETE injected and equivalent')))


def vacuity_probe():
    import inspect
    import pytest
    code = ast.parse(inspect.getsource(_core.scan_payload))
    walk = next(n for n in ast.walk(code) if isinstance(n, ast.FunctionDef) and n.name == 'walk')
    budget_guard = walk.body[2]
    assert isinstance(budget_guard, ast.If) and isinstance(budget_guard.body[-1], ast.Return)
    budget_guard.body.pop()
    exec(compile(code, 'mutated_core.py', 'exec'), _core.__dict__)
    status = pytest.main(['-q', 'tests/test_hook_core.py'])
    assert status == 0, status
    calls = []
    def scanner(*args, **kwargs):
        calls.append(args[0])
        return SimpleNamespace(complete=True, rules_evaluated=0, partial_findings=[])
    outcome = _core.scan_payload({'a': 'content'}, rules=[], lanes={}, surface='OUT', event='e',
                                 limits=_core.Limits(100, 0, 0, 0), scanner=scanner)
    assert calls == ['content'] and outcome.incomplete
    print('VERIFIED WITNESS: all core tests pass after removing the node/depth/time early return; the scanner still ran with all three budgets exhausted.')
    status = pytest.main(['-q', 'tests/test_hook_integration.py::test_event_budget_is_shared_and_exhaustion_warns_the_model'])
    assert status == 1, status
    print('VERIFIED CONTROL: the existing adapter integration test detects this mutation.')


if __name__ == '__main__':
    {'sources': archive_probe, 'regex': regex_probe, 'hooks': hook_probe, 'vacuity': vacuity_probe}[sys.argv[1]]()
~~~

</details>

<details>
<summary>.Review-Codex-round4-numeric.py</summary>

~~~python
import argparse
from dataclasses import replace
import json
import math
import sys
from pathlib import Path

import numpy as np
from scipy.special import betaincc
import mpmath as mp

sys.path.insert(0, str(Path(__file__).resolve().parent / 'src'))
from agent_defs import lanes
from agent_defs.builtin import STARTER_RULES
from agent_defs.hooks import _claude_code_impl as hook
from agent_defs.model import BenignFiring


def boundary_pairs(hits, p):
    low = (hits / p).astype(np.int64)
    high = np.ceil((hits + 10 * np.sqrt(hits) + 100) / p).astype(np.int64)
    while np.any(high - low > 1):
        mid = (low + high) // 2
        above = betaincc(hits + 1, mid - hits, p) > .05
        low = np.where(above, mid, low)
        high = np.where(above, high, mid)
    return low, high


def reference(n, k, p):
    mp.mp.dps = 60
    prob = mp.mpf(p)
    term = total = mp.mpf(1)
    for i in range(k, 0, -1):
        term *= mp.mpf(i) / (n - i + 1) * (1 - prob) / prob
        total += term
        if term < total * mp.mpf('1e-55'):
            break
    log_cdf = (mp.loggamma(n + 1) - mp.loggamma(k + 1) - mp.loggamma(n - k + 1)
               + k * mp.log(prob) + (n - k) * mp.log1p(-prob) + mp.log(total))
    return log_cdf - mp.log(mp.mpf('.05'))


def capped():
    for p in (.001, .005):
        hits = np.arange(1, int(hook.MAX_TRIALS * p), dtype=np.int64)
        low, high = boundary_pairs(hits, p)
        valid = high <= hook.MAX_TRIALS
        results = []
        unresolved = wrong = checked = 0
        max_error = (0, None)
        for ns in (low, high):
            ref = np.log(betaincc(hits + 1, ns - hits, p)) - math.log(.05)
            for i in np.where(valid)[0]:
                n, k = int(ns[i]), int(hits[i])
                delta = lanes.log_binomial_cdf(n, k, p) - math.log(.05)
                decision = lanes.bound_within(n, k, p)
                error = abs(delta - float(ref[i]))
                if error > max_error[0]:
                    max_error = error, (n, k, delta, float(ref[i]))
                checked += 1
                unresolved += decision is None
                if decision is not None and decision != (ref[i] <= 0):
                    wrong += 1
                    results.append((n, k, delta, float(ref[i]), decision))
        print(json.dumps(dict(ceiling=p, checked=checked, unresolved=unresolved,
                              wrong_resolved=wrong, max_log_error_vs_scipy=max_error,
                              wrong=results)), flush=True)
        n, k, local, _ = max_error[1]
        precise = reference(n, k, p)
        print(json.dumps(dict(ceiling=p, max_error_high_precision=dict(n=n, k=k,
                             reference_delta=str(precise), local_delta=local,
                             error=str(mp.mpf(local)-precise)))), flush=True)
        assert wrong == 0
    for n, k, p in [(5023741, 4907, .001), (1268982, 6214, .005), (9733435, 48305, .005)]:
        m = dict(trials=n, hits=k, u95=lanes.binomial_u95(n, k), corpus='numeric', measured_at='2026-09-06')
        rule = STARTER_RULES[0]
        config = hook.default_config()
        config.update(surfaces=['OUT'], bundle='')
        config['sources']['builtin'] = 'DENY'
        config['evidence'] = dict(fingerprint=hook.fingerprint([rule], config['surfaces']),
                                  bundle=m.copy(), rules={rule.id: m.copy()})
        lane = hook.effective_lanes(config, [rule])[rule.id][0].value
        print(json.dumps(dict(n=n, k=k, ceiling=p, comparison=lanes.bound_within(n,k,p),
                              reference_delta=str(reference(n,k,p)), effective_lane=lane)), flush=True)
        assert lane == ('ADVISE' if p == .001 else 'RECORD')


def uncapped():
    rng = np.random.default_rng(20260906)
    hits = rng.integers(100000, 10000000, size=200, dtype=np.int64)
    for p in (.001, .005):
        low, high = boundary_pairs(hits, p)
        witnesses = []
        for ns in (low, high):
            for nv, kv in zip(ns, hits):
                n, k = int(nv), int(kv)
                local = lanes.bound_within(n, k, p)
                ref = float(betaincc(k+1,n-k,p))
                if local is True and ref > .05:
                    precise = reference(n,k,p)
                    if precise <= 0:
                        continue
                    u95 = lanes.binomial_u95(n,k)
                    rule = replace(STARTER_RULES[0], benign=BenignFiring(n,k,u95,'numeric','2026-09-06'))
                    witnesses.append(dict(n=n,k=k,ceiling=p,decision=local,
                        local_delta=lanes.log_binomial_cdf(n,k,p)-math.log(.05),
                        reference_delta=str(precise),u95=u95,
                        admit=lanes.admit(rule,bundle_ok=True)[0].value,
                        hook_measurement_accepted=hook.measurement(dict(trials=n,hits=k,u95=u95,
                                                             corpus='numeric',measured_at='2026-09-06')) is not None))
                    break
            if witnesses:
                break
        print(json.dumps(dict(uncapped_ceiling=p,witnesses=witnesses)),flush=True)


def coefficient():
    mp.mp.dps = 70
    for n,k in [(9388513,9229),(9892023,49095)]:
        terms=[n+1,k+1,n-k+1]
        errors=[str(mp.mpf(math.lgamma(x))-mp.loggamma(x)) for x in terms]
        local=math.lgamma(n+1)-math.lgamma(k+1)-math.lgamma(n-k+1)
        exact=mp.loggamma(n+1)-mp.loggamma(k+1)-mp.loggamma(n-k+1)
        assert abs(mp.mpf(local)-exact) > mp.mpf('5e-8')
        print(json.dumps(dict(n=n,k=k,lgamma_errors=errors,
                              coefficient_error=str(mp.mpf(local)-exact))))


if __name__ == '__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('phase',choices=['capped','uncapped','coefficient'])
    globals()[parser.parse_args().phase]()
~~~

</details>

<details>
<summary>.Review-Codex-round4-scan.ps1</summary>

~~~powershell
param([ValidateSet('setup', 'locked', 'missing-parent')][string]$Mode)
$ErrorActionPreference = 'Stop'
$reviewRoot = [IO.Path]::GetFullPath((Get-Location).Path)
$reviewRecord = Join-Path $reviewRoot '.Review-Codex-round4-scan-record.json'
$reviewArtifact = Join-Path $reviewRoot '.Review-Codex-round4-harmless.txt'
$reviewMissing = Join-Path $reviewRoot '.Review-Codex-round4-absent-parent'
if ([IO.Directory]::Exists($reviewMissing)) { throw 'expected missing parent already exists' }
$reviewOld = '{"verdict":"clean","review_marker":true}'
[IO.File]::WriteAllText($reviewRecord, $reviewOld)
[IO.File]::WriteAllText($reviewArtifact, 'harmless review artifact')
$reviewLock = $null
function New-Item {
    [CmdletBinding()]
    param($ItemType, $Path)
    throw 'synthetic scan directory setup failure'
}
function Remove-Item {
    [CmdletBinding()]
    param($LiteralPath, [switch]$Recurse, [switch]$Force)
    $resolved = [IO.Path]::GetFullPath($LiteralPath)
    if ($Recurse) {
        $tempRoot = [IO.Path]::GetFullPath($env:TEMP).TrimEnd('\') + '\'
        if (-not $resolved.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -or
            [IO.Path]::GetFileName($resolved) -notmatch '^agent-defs-scan-[0-9a-f]{8}$') {
            throw 'cleanup escaped the expected temporary scan directory'
        }
        if ([IO.Directory]::Exists($resolved)) { throw 'mock unexpectedly created scan directory' }
        return
    }
    if ([IO.Path]::GetDirectoryName($resolved) -ne $reviewRoot -or
        [IO.Path]::GetFileName($resolved) -notlike '.Review-Codex-round4-scan-record.json.*.tmp') {
        throw 'cleanup escaped review temporary files'
    }
    [IO.File]::Delete($resolved)
}
try {
    if ($Mode -eq 'locked') {
        $reviewLock = [IO.File]::Open($reviewRecord, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    }
    $destination = if ($Mode -eq 'missing-parent') { Join-Path $reviewMissing 'result.json' } else { $reviewRecord }
    try {
        & ./scripts/scan_artifact.ps1 -Path $reviewArtifact -Out $destination
        $reviewExit = $LASTEXITCODE
    } catch {
        $reviewExit = 1
        Write-Output ('Unhandled exception: ' + $_.Exception.Message)
    }
    $after = [IO.File]::ReadAllText($reviewRecord)
    $parsed = $after | ConvertFrom-Json
    if ($Mode -eq 'setup' -and ($parsed.verdict -notlike 'inconclusive:*' -or $reviewExit -ne 2)) {
        throw 'setup failure did not replace the old record with exit 2'
    }
    if ($Mode -eq 'locked' -and ($after -ne $reviewOld -or $reviewExit -ne 3)) {
        throw 'locked destination was not preserved with exit 3'
    }
    if ($Mode -eq 'missing-parent' -and $reviewExit -ne 1) { throw 'temporary-write witness changed' }
    [ordered]@{ mode=$Mode; script_exit=$reviewExit; previous_record_unchanged=($after -eq $reviewOld);
                verdict=$parsed.verdict; actual_scanner_executed=$false } | ConvertTo-Json -Compress
    exit $reviewExit
} finally {
    if ($reviewLock) { $reviewLock.Dispose() }
    [IO.File]::Delete($reviewRecord)
    [IO.File]::Delete($reviewArtifact)
}
~~~

</details>

<details>
<summary>.Review-Codex-round4-atr.py</summary>

~~~python
from collections import Counter
import hashlib
import io
import importlib.util
import json
from pathlib import Path, PurePosixPath
import sys
import tarfile
from unittest.mock import patch
import urllib.request

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'src'))
from agent_defs import evaluate, sources
from agent_defs.loaders import atr
from agent_defs.model import Surface


class MemoryFile:
    def __init__(self, data): self.data = data
    def read_bytes(self): return self.data


entry = sources.load_lock()['atr']
url = entry['archive_http']['url']
with urllib.request.urlopen(url, timeout=90) as response:
    assert response.status == 200
    blob = response.read()
assert hashlib.sha256(blob).hexdigest() == entry['archive_sha256']
print(json.dumps(dict(url=url, sha256=entry['archive_sha256'], archive_bytes=len(blob))), flush=True)
with tarfile.open(fileobj=io.BytesIO(blob), mode='r:gz') as archive:
    members = archive.getmembers()
    root = members[0].name.split('/')[0]
    files, directories = sources._layout(archive)
    kept, kept_dirs = sources._kept(files, directories)
    counts = Counter('/'.join(PurePosixPath(p).parts[:3]) for p in kept)
    possible = [p for p in kept if not p.startswith('rules/') and
                any(token in p.lower() for token in ('malicious', 'payload', 'fixture', 'sample', 'attack', 'test-corp', 'benchmark'))]
    print(json.dumps(dict(members=len(members), declared_files=len(files), kept_files=len(kept),
                          excluded_files=len(files)-len(kept),
                          possible_sample_paths=[p for p in possible if p.startswith('data/') and '/benign/' not in p],
                          actual_links=sum(m.issym() or m.islnk() for m in members))), flush=True)
    # Read only approved regular rule YAML and LICENSE. No archive bytes or members are written.
    rule_files = []
    license_text = None
    for member in members:
        rel = member.name.removeprefix(root + '/')
        if not member.isfile(): continue
        if rel == entry['license_path']:
            license_text = archive.extractfile(member).read().decode('utf-8')
        elif rel.startswith('rules/') and PurePosixPath(rel).suffix in ('.yaml', '.yml'):
            rule_files.append((MemoryFile(archive.extractfile(member).read()), rel))
    rule_files.sort(key=lambda row: row[1])
    assert license_text.startswith('MIT License')
    def memory_source(*args): return entry['commit'], rule_files, 'MIT', {}
    with patch.object(atr, '_source_files', memory_source), patch.object(
            atr.atr_skill_gates, 'read_skill_gates', side_effect=atr.atr_skill_gates.GateReadError('rules-only in-memory view')):
        result = atr.load(ROOT, source_rev=entry['commit'])
    inbound = [r for r in result.rules if r.surface == Surface.IN]
    categories = Counter()
    details = []
    for rule in inbound:
        if not rule.runnable:
            reason = rule.not_runnable_reason
            category = ('multiple fields' if 'multiple condition fields cannot be flattened' in reason else
                        'measured backtracking' if 'refused on measurement' in reason else 'other refusal')
        elif not rule.shippable:
            category, reason = 'not shippable', rule.restricted_reason
        else:
            try:
                compiled = evaluate.compile_rule(rule)
                assert compiled is not None
            except (ValueError, NotImplementedError) as exc:
                category, reason = 'evaluator rejection', str(exc)
            else:
                category, reason = 'runnable shippable screened', ''
        categories[category] += 1
        details.append(dict(id=rule.id, category=category, reason=reason))
    measured = [r for r in inbound if 'refused on measurement' in r.not_runnable_reason]
    exact_fields = [r for r in inbound if r.not_runnable_reason == 'multiple condition fields cannot be flattened into one text payload']
    residual = [r for r in inbound if not r.runnable and r not in measured and r not in exact_fields]
    print(json.dumps(dict(yaml_files=len(rule_files), loaded=len(result.rules), errors=len(result.delta.entry_errors),
                          inbound=len(inbound), runnable_shippable_screened=categories['runnable shippable screened'],
                          measured_refusal=len(measured), exact_fields_only=len(exact_fields),
                          residual=[dict(id=r.id, reason=r.not_runnable_reason) for r in residual])), flush=True)
    # Only digests are compared for non-allow-listed members, without printing their contents.
    excluded_hashes = {}
    for path, member in files.items():
        if path not in kept:
            excluded_hashes.setdefault(hashlib.sha256(archive.extractfile(member).read()).hexdigest(), []).append(path)
    aliases = []
    for path in possible:
        member = kept[path]
        digest = hashlib.sha256(archive.extractfile(member).read()).hexdigest()
        same = excluded_hashes.get(digest, [])
        if any('/tp/' in p or '/malicious/' in p for p in same):
            aliases.append(dict(kept=path, sha256=digest, excluded=same[:3], bytes=member.size))
    print(json.dumps(dict(kept_identical_to_excluded_positive=aliases)), flush=True)
    for path in ['data/autoresearch/adversarial-samples.json', 'data/autoresearch/missed-payloads.json',
                 'data/evasion-payloads.json', 'data/pint-benchmark/pint-corpus.json',
                 'data/semantic-validation/attacks.json', 'data/fn-mining/skill-benchmark-malicious.json']:
        member = kept[path]
        value = json.loads(archive.extractfile(member).read())
        schema = ({key: dict(type=type(val).__name__, length=len(val) if isinstance(val, (list, dict, str)) else None)
                   for key, val in value.items()} if isinstance(value, dict) else
                  dict(type=type(value).__name__, length=len(value), first_keys=list(value[0]) if value and isinstance(value[0], dict) else None))
        print(json.dumps(dict(kept_json=path, bytes=member.size, schema=schema)), flush=True)
    spec = importlib.util.spec_from_file_location('proposed_policy', ROOT / '.Review-Codex-round4-policy.py')
    policy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(policy)
    selected, selected_dirs = policy._kept(files, directories, name='atr', license_path=entry['license_path'])
    assert len(selected) == 798
    assert not any(path.startswith('data/') for path in selected)
    other, other_dirs = policy._kept(files, directories, name='synthetic_other', license_path='LICENSE')
    assert other == kept and other_dirs == kept_dirs
    class MemoryPath:
        def __init__(self, name=''): self.name = name
        def __truediv__(self, segment): return MemoryPath(self.name + '/' + segment if self.name else segment)
        def is_file(self): return self.name in selected
        def read_text(self, **kwargs): return archive.extractfile(selected[self.name]).read().decode('utf-8')
        def __str__(self): return self.name
    with patch.object(atr.atr_skill_gates, 'Path', lambda _: MemoryPath()):
        gates = atr.atr_skill_gates.read_skill_gates('memory', source_rev=entry['commit'])
    assert gates.source_rev == entry['commit']
    print(json.dumps(dict(proposed_policy_keeps=len(selected), unchanged_other_source_policy=True,
                          cfg_gates_read=True, cfg_scan_context=gates.scan_context)), flush=True)
~~~

</details>

<details>
<summary>.Review-Codex-round4-policy.py</summary>

~~~python
from pathlib import PurePosixPath
from agent_defs.sources import _is_excluded, _portable_path, _safe_parts


def _kept(files, directories, *, name, license_path):
    required = {
        _portable_path(license_path),
        "src/engine.ts",
        "src/enforcement.ts",
        "src/quality/rule-contract.ts",
        "engines/typescript/INTERFACE-CONTRACT.md",
    }

    def allowed(relative):
        parts = PurePosixPath(relative).parts
        if _is_excluded(parts):
            return False
        return name != "atr" or parts[0] == "rules" or relative in required

    kept_files = {
        relative: member for relative, member in files.items()
        if allowed(relative)
        and allowed(_portable_path("/".join(_safe_parts(member.name)[1:])))
    }
    if name == "atr":
        kept_dirs = {
            str(parent) for relative in kept_files
            for parent in PurePosixPath(relative).parents if str(parent) != "."
        }
    else:
        kept_dirs = {relative for relative in directories if allowed(relative)}
    return kept_files, kept_dirs
~~~

</details>

<details>
<summary>.Review-Codex-round4-finalize.py</summary>

~~~python
import hashlib
import os
from pathlib import Path
import subprocess

root = Path('C:/Users/yuezh/PycharmProjects/agent-defs').resolve()
temporary = root / '.Review-Codex-round4.tmp'
target = root / 'Review-Codex.md'
expected_head = '199f5bbfc5b6d86fa8d2fae76a31d5f4860fa3c2'
expected_paths = {
    'SAMPLES.md', 'docs/calibration.md', 'scripts/bound_leaf_discrepancy.py',
    'src/agent_defs/hooks/_claude_code_impl.py', 'src/agent_defs/hooks/_core.py',
    'src/agent_defs/lanes.py', 'src/agent_defs/sources.py',
    'tests/test_bound_within.py', 'tests/test_hook_core.py',
    'tests/test_leaf_discrepancy_probes.py', 'tests/test_sources.py',
}


def git(*args):
    return subprocess.check_output(['git', *args], cwd=root)


assert git('rev-parse', 'HEAD').decode().strip() == expected_head
assert set(git('diff', '--name-only', '869ccd2..HEAD').decode().splitlines()) == expected_paths
git('diff', '--check', '869ccd2..HEAD')
git('diff', '--exit-code', '--', '.', ':!Review-Codex.md')
assert git('diff', '--cached', '--binary') == b''
review = temporary.read_text(encoding='utf-8')
assert review.startswith('<!-- Round 4 -->\n\nVerification notes:\n')
assert review.splitlines().count('Verification status: VERIFIED') == 1
assert review.splitlines().count('Commit verdict: BLOCK') == 1
for heading in ['## New', '## Previously raised', '### Fixed', '### Still open', '### Reopened', '### Deferred']:
    assert heading in review
assert not any(c in review for c in ('\u202f', '\u2013', '\u2014'))
helpers = [
    '.Review-Codex-round4-probes.py', '.Review-Codex-round4-numeric.py',
    '.Review-Codex-round4-scan.ps1', '.Review-Codex-round4-atr.py',
    '.Review-Codex-round4-policy.py', '.Review-Codex-round4-finalize.py',
]
for name in helpers:
    source = (root / name).read_text(encoding='utf-8')
    language = 'powershell' if name.endswith('.ps1') else 'python'
    review += f'\n<details>\n<summary>{name}</summary>\n\n~~~{language}\n{source.rstrip()}\n~~~\n\n</details>\n'
assert temporary.parent.resolve() == target.parent.resolve() == root
data = review.encode('utf-8')
with temporary.open('wb') as stream:
    stream.write(data)
    stream.flush()
    os.fsync(stream.fileno())
os.replace(temporary, target)
assert target.read_bytes() == data
assert not temporary.exists()
for name in helpers:
    helper = root / name
    assert helper.resolve().parent == root and helper.name.startswith('.Review-Codex-round4-')
    helper.unlink()
assert git('rev-parse', 'HEAD').decode().strip() == expected_head
git('diff', '--exit-code', '--', '.', ':!Review-Codex.md')
assert git('diff', '--cached', '--binary') == b''
status = git('status', '--porcelain').decode().splitlines()
assert status == [' M Review-Codex.md'], status
print('VERIFIED: complete Round 4 review atomically replaced and read back; verification helpers removed; HEAD and index unchanged; only Review-Codex.md modified.')
print('Review bytes:', len(data), 'sha256:', hashlib.sha256(data).hexdigest())
~~~

</details>
