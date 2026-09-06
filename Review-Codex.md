<!-- Round 2 -->

Verification notes:

- From the repository root, PowerShell: `$env:PYTHONPATH='src'; & 'C:\Users\yuezh\miniforge3\envs\py312\python.exe' -m pytest tests -q`. Exit 0: **564 passed, 6 skipped, 1 warning in 37.59 s**. The warning concerns a possible nested regex set in an existing adversarial test. This verifies the working tree, including three unstaged fixes, not an isolated export of the index.
- `$env:PYTHONPATH='src'; & 'C:\Users\yuezh\miniforge3\envs\py312\python.exe' Review-Codex-probes.py --corpus`. Exit 0, approximately five seconds. I inspected and reran this existing probe script. It reproduced the staged/working-tree CFG differences, the missing-measurement admission, the inferred-fast loader bypass, a builder crash, corpus coverage counts, UTF-16 boundary differences, and the mocked Windows override behavior. Its staged-module checks execute `git show :src/agent_defs/cfg.py` and `git show :src/agent_defs/loaders/atr.py`; other imports use the working tree.
- That probe invokes `C:\Program Files\nodejs\node.exe -e <decoder-and-harness>` with a ten-second timeout. The exact generated source is in `Review-Codex-probes.py`: it removes type annotations from the fixture's actual `decodeBase64Blocks` function and feeds it the same inputs as Python. All 121 short cases agreed; the additional long case exposed a slice-boundary difference. No tested block retained by Node was dropped by Python.
- `git diff --cached --check`: exit 0, no diagnostics. `git rev-parse HEAD`: exit 0, `49f11a550f6cd317821226d37450779fa5b727fd`. `git diff --cached --stat` and `git status --short`: 49 staged files, with additional unstaged changes in `cfg.py`, `loaders/atr.py`, and `build_hazards.py`.
- `git diff -- src/agent_defs/cfg.py src/agent_defs/loaders/atr.py scripts/build_hazards.py`: exit 0; confirms the three recovered fixes are outside the index. The staged implementation was reviewed through `git diff --cached`, supplemented by surrounding source and fixtures.
- No timing sweep, malicious-corpus extraction, full four-figure calibration, or isolated staged-suite run was performed. The baseline of 458 passed and 5 skipped is user supplied and was not rerun. The Windows probe mocks extraction; it does not extract samples or enable a real extraction override.

Verification status: VERIFIED

Commit verdict: BLOCK

Scope and review lens: the 49-file staged change against `49f11a5`, emphasizing security-library correctness, admission safety, and whether measured evidence covers the executable pattern. Close review covered the hazard table reader/builder, ATR flat and CFG admission, CFG matching and decoding, calibration preparation/scoring, model/lane changes, packaging, and the changed tests. Fixture source excerpts were read where they define the behavior being ported; every YAML payload was not individually audited. The unchanged scan worker was inspected to trace runtime validation. Neither root `AGENTS.md` nor `AGENTS.local.md` exists; the supplied instructions apply. Product source and the index were not modified.

**New findings**

1. **High: a rule-level fast verdict certifies untimed derived patterns and can override an exact slow verdict.** `src/agent_defs/loaders/atr.py:361` and `:401` pass the raw rule's measurement to ported conditions and a newly composed alternation. At `src/agent_defs/evaluate.py:479`, supplying that measurement skips the exact-pattern lookup. The synthetic builder probe produced an `inferred-fast` row that direct screening refused as unmeasured, but `_predicate` returned `REGEX` with no refusal. A separate probe supplied a fast override for a real pattern recorded slow and screening admitted it.

   Timing independent raw searches does not time their composition. Timing an unported surrogate expression in Python is especially poor evidence for its port: the raw expression can be fast simply because it cannot match well-formed text. The checked-in table still contains only `fast` and `slow`; the builder edit has not corrected existing inferred entries.

   Exact replacements at `src/agent_defs/loaders/atr.py:361` and `:401`, using the signature and resolution rewrite under Previously raised 4:

   ```python
   evaluate.screen_pattern(pattern, require_measurement=True)
   ```

   ```python
   evaluate.screen_pattern(predicate, require_measurement=True)
   ```

   Retain the existing independent-branch fallback when a composed expression lacks its own measurement. Emit raw fast rows from content-verified measurements; keep untimed ports/compositions distinguishable and unmeasured. Regenerate the table with replay evidence preserved. A fast rule override must never defeat an exact slow row; the resolution rewrite below enforces this.

2. **High: the builder can attach old timings to changed text while manufacturing a matching digest.** `scripts/build_hazards.py:90` checks only the number of distinct patterns, then hashes the current corpus strings. Replacing a condition while preserving the count creates a matching rule-level fast row for text the report need not have measured. The probe successfully built such a row from a report containing no pattern identity, and the loader admitted it. This differs from a lookup miss: it creates a misleading lookup hit.

   Exact insertion before the existing count check at `scripts/build_hazards.py:90`, after extending the measurement producer to record the identities it actually timed:

   ```python
   expected = sorted({_fingerprint(pattern) for pattern in patterns})
   if row.get("pattern_digests") != expected:
       raise SystemExit(f"{source_id}: measurement pattern digests do not match corpus")
   ```

   A legacy report lacking that field must fail validation. Preserve flags and runtime/method information with the evidence as well. The declared corpus pin must come from a verified input tree rather than the default `--source-rev` string.

   Neither `measured_at` nor `provenance.corpora.atr` is compared with the loaded revision. Exact pattern lookup and the rule-content digest detect many edits, but their misses currently fall open, and the builder can stamp stale evidence with a new matching digest. An age cutoff is not a substitute for content identity. Reusing an unchanged measured pattern across revisions is reasonable; changed executable text must require its own evidence, and a provenance mismatch should be reported explicitly.

3. **High for consumer release: there is no usable bounded CFG entry point.** `src/agent_defs/cfg.py:224` executes regexes in-process without a deadline; `scan_cfg_isolated` raises `NotImplementedError` at staged `:355` (working-tree `:363`). The offline-only documentation is candid, but this is not safe for the hostile documents the configuration channel is intended to inspect. Flat `scan()` does not protect this function.

   The corpus probe found 133 eligible CFG rules and 474 distinct surviving conditions, including **207 unmeasured conditions**. Of the eligible rules, 59 have slow whole-rule verdicts and **39**, not 59, are marked over 60 seconds. No surviving condition has an exact slow row. Therefore these counts do not prove that the known offending condition survives; the missing deadline and unmeasured survivors are the actual exposure.

   Implement a killable CFG worker before releasing that consumer capability. A concrete safe interim rewrite at `src/agent_defs/cfg.py:224` is to rename the existing implementation to `scan_cfg_trusted`, update offline callers/exports accordingly, and expose:

   ```python
   def scan_cfg(document: str, rules: Iterable[Rule], *,
                budget_s: float = 1.0,
                max_bytes: int = DEFAULT_MAX_BYTES) -> "CfgScanResult":
       return scan_cfg_isolated(document, rules, budget_s=budget_s,
                                max_bytes=max_bytes)
   ```

   Until isolation exists, this fails immediately on consumer use. The eventual worker must preserve condition order, suppression, decoded origin, partial findings, and incomplete status. It should return `CfgScanResult`; the placeholder's `ScanResult` annotation cannot express all that information. Keeping an explicitly trusted research API is acceptable; presenting it as the available consumer scan path is not.

4. **Medium: regeneration discards the manually added replay refusal.** `src/agent_defs/hazards.json:18` discloses the separate evidence for `atr:ATR-2026-02351`, but `scripts/build_hazards.py` has no input or merge step for it. Rebuilding from the described original sweep restores that rule's non-crossing row and loses the correction.

   A hand-transcribed slow result is acceptable as a temporary conservative refusal if its origin is stated honestly. It is not yet reproducible measured evidence. Preserve the replay as machine-readable input with pattern identity, flags, witness bytes or generator/digest, command, runtime, and whether timing completed or timed out. Merge it with slow taking precedence. Retaining the known refusal does not require waiting for a full cross-pattern sweep.

5. **Medium: shared patterns can crash table generation.** At `scripts/build_hazards.py:105`, `prior` can be a one-element fast/inferred-fast row inserted for an earlier rule. The two-rule probe reproduced `IndexError: list index out of range` at `length < prior[1]`. The contradiction checks below the loop cannot repair this. Replace the condition with:

   ```python
   if prior is None or prior[0] != "slow" or length < prior[1]:
   ```

6. **Medium: UTF-16 limits still use Python code points outside the ratio.** At `src/agent_defs/cfg.py:278`, a document with 91,000 code points but 102,000 UTF-16 units reports `over_source_eval_limit=False` and `complete=True`. This contradicts the policy of marking input beyond Node's 100,000-unit evaluation limit incomplete. Use `len(document.encode("utf-16-le", "surrogatepass")) // 2` for that comparison.

   At `src/agent_defs/cfg.py:159`, decoded text is also sliced by code points. The differential case containing 79,999 ASCII characters, 10,000 emoji, and `needle` retains the entire word in Python, while Node's slice retains only its first character. Slice encoded UTF-16 to `2 * BASE64_MAX_DECODED_CHARS` bytes and decode with `surrogatepass` to preserve Node's boundary behavior, including a possible terminal lone surrogate. Add focused boundary assertions.

7. **Medium: the Windows opt-in accepts the value `0`.** The mocked probe confirmed that `AGENT_DEFS_ALLOW_MALICIOUS_EXTRACT=0` reaches the archive call. At `scripts/calibration_gate.py:723`, replace the condition with:

   ```python
   if (platform.system() == "Windows"
           and os.environ.get("AGENT_DEFS_ALLOW_MALICIOUS_EXTRACT") != "1"):
   ```

   The current guard is early enough to prevent extraction: it precedes `git archive` and `extractall`. It follows workdir creation, a possible blobless `--no-checkout` clone, and history/tree checks. Moving it to function entry would avoid unnecessary work and make rejection deterministic. An explicit environment opt-in is proportionate here; this is an operator-controlled preparation tool, not a security boundary against that operator.

**Previously raised**

1. **Fixed in working tree; Still open in index: empty-bundle exception completeness.** The fresh probe reports working-tree `IncompleteScanError.result.complete=False`, one error; staged `complete=True`, zero errors. The unstaged fix works. Exact insertion immediately before constructing the exception at staged `src/agent_defs/cfg.py:319`:

   ```python
   if self.empty_bundle:
       errors += (RuleError("", "no executable binding in the bundle; "
                                "a zero-rule scan is not a clean document"),)
   ```

   Include the existing reviewed working-tree fix in the index before committing and assert the exception result itself is incomplete. The current suite does not catch the staged defect.

2. **Fixed in working tree; Still open in index: CFG surrogate port.** The tag-payload probe reports two usable conditions and an `ATR-2026-00129` finding in the working tree; one condition and no finding with the staged loader. Exact rewrite of the screening block inside `else`, beginning at staged `src/agent_defs/loaders/atr.py:554`:

   ```python
   ported, _notes = evaluate.port_utf16_surrogates(condition["value"])
   try:
       evaluate.screen_pattern(ported)
   except evaluate.UnsafePattern as exc:
       reason = str(exc)
   ```

   Replace staged `src/agent_defs/loaders/atr.py:561`, `usable.append(condition["value"])`, with `usable.append(ported)`. The existing working-tree fix implements this. Combine it with the stricter call below and retain a CFG-specific tag regression assertion.

3. **Still open end to end: inferred-fast rows.** The two working-tree replacements at `scripts/build_hazards.py:115` and `:117` correctly write `inferred-fast`; staged code still writes `fast`. `_measurement_from_row` ignores an inferred row and direct lookup returns `None`, as intended. However, that merely invokes the shape screen. A simple shape is still admitted, and the probe's nested shape is admitted by ATR through the raw-rule fast override described in New 1. Thus "refused as unmeasured" is true for the direct nested-pattern probe, not the entire loading path. Correct the override, strict admission policy, and existing JSON as well as the builder labels.

4. **Still open, High: require measurement on the ATR corpus path before shipping.** Scoped fail-closed is required for the claimed measurement-based admission policy. Appending `(?:)` to the measured-slow pattern from `ATR-2026-00040` preserves its matching behavior but produces no lookup row and is admitted. Worker revalidation repeats the same decision. The deadline bounds flat-scan resource exposure, but still lets a slow rule consume the event's scan budget and prevent later detections. It provides containment, not measurement coverage.

   Exact signature at `src/agent_defs/evaluate.py:454`:

   ```python
   def screen_pattern(pattern: str, flags: int = re.IGNORECASE, *,
                      measurement: "Measurement | None" = None,
                      require_measurement: bool = False) -> None:
   ```

   Replace the measurement-resolution/slow-refusal block at `src/agent_defs/evaluate.py:479` through the existing slow refusal, leaving the subsequent shape fallback intact:

   ```python
   recorded = measurement_for_pattern(pattern)
   if recorded is not None and recorded.slow:
       raise UnsafePattern(recorded.refusal())
   if measurement is not None and measurement.slow:
       raise UnsafePattern(measurement.refusal())
   if require_measurement and recorded is None:
       raise UnsafePattern("pattern has no exact measurement; unmeasured")
   measurement = recorded if recorded is not None else measurement
   ```

   The strict check deliberately requires the exact lookup, even if a caller supplies a fast override. Other callers retain the default behavior. Apply these exact call-site replacements together:

   | File:line | Replacement |
   |---|---|
   | `src/agent_defs/loaders/atr.py:361` | `evaluate.screen_pattern(pattern, require_measurement=True)` |
   | `src/agent_defs/loaders/atr.py:401` | `evaluate.screen_pattern(predicate, require_measurement=True)` |
   | `src/agent_defs/loaders/atr.py:555` staged, `:561` after recovered port fix | `evaluate.screen_pattern(ported, require_measurement=True)` |
   | `src/agent_defs/evaluate.py:572` | `screen_pattern(rule.predicate, flags, require_measurement=(rule.source == "atr"))` |
   | `src/agent_defs/evaluate.py:577` | `screen_pattern(pattern, flags, require_measurement=(rule.source == "atr"))` |
   | `src/agent_defs/cfg.py:175` | `screen_pattern(pattern, re.IGNORECASE, require_measurement=(rule.source == "atr"))` |

   Runtime enforcement also requires preserving source identity, which the current worker discards. Exact replacement of the return at `src/agent_defs/evaluate.py:637`:

   ```python
   return dict(id=rule.id, source=rule.source, kind=kind.value, predicate=pred,
               case_sensitive=rule.case_sensitive, surface=rule.surface.value)
   ```

   At `src/agent_defs/_scan_worker.py:19`, replace the first line of the `Rule` construction, retaining its remaining arguments:

   ```python
   rule = Rule(id=item["id"], source=item["source"], source_id="", source_rev="",
   ```

   Netzilo, AgentShield, and direct synthetic screening calls retain the default. Tests constructing ATR rules must explicitly provide measurement evidence where they test strict admission. The fresh corpus probe confirms zero missing rows among **444 distinct executable regex strings, counting structured branches individually, in 427 runnable rules**. This supports no flat-bundle cost from missing-row refusal today. It does not establish that every existing fast row came from timing that exact string. Correcting inferred data may cost additional rules, and CFG's 207 unmeasured surviving strings make its tradeoff real and reportable.

**Other requested assessments**

The printable-ratio edit itself is correct. Both implementations count ASCII 32 through 126 in the numerator, UTF-16 units in the denominator, and require a strict ratio greater than 0.7. It cannot by itself drop a block Node keeps. The short differential cases covered astral characters, threshold boundaries, malformed UTF-8, padding fragments, and multiple blocks, with no discrepancies. The remaining `len(decoded) >= 10` difference cannot lose a qualifying block under the current 32-character base64 minimum: the only shorter-than-ten-code-point string with at least ten UTF-16 units and enough ASCII is eight ASCII characters plus one astral character, whose UTF-8 encoding produces only 16 base64 characters. The actual remaining boundary defects are New 6. This is targeted verification, not exhaustive decoder equivalence.

The five edited tests retain some useful properties, but two now ask less:

- `tests/test_cfg.py:66`: the Apify/00111 replacement still explicitly requires the flat false positive and zero CFG findings. It preserves the intended comparison.
- `tests/test_cfg.py:242`: the dropped-condition carrier still requires one refusal, a recorded screen gate, and three survivors. It preserves that property. Correct the docstring's `00440` to the actual `00162` carrier.
- `tests/test_cfg.py:224`: the six-survivor update still pins CFG eligibility, flat refusal, and the survivor count. This does not hide loss of the assertion, although the composition-based explanation should be updated for the measurement refusal.
- `tests/test_hazard_screen.py:123`: deriving slow/fast counts now tests internal consistency rather than preserving an independent measurement total. The explicit `02351` check protects that correction, but other accidental fast relabels can pass if counts change with them. Validate against reproducible evidence; another hard-coded total is not sufficient evidence either.
- `tests/test_cfg.py:380`: deriving the condition index proves the reported condition matches somewhere, but does not require the first matching condition or its reported span. The present payload matches only condition 1, and the probe reports 1, so it still pins this fixture's index. Strengthen it by deriving the first match with `re.IGNORECASE` and comparing both index and span. A future fixture with several matches could otherwise conceal an ordering regression.

These test files are newly added relative to HEAD, so their pre-edit forms are not available as a separate staged comparison. The assessment uses their current assertions and documented former purpose. The `test_atr.py` fixture replacements also retain separate runnable/refused semantic-fallback checks and a runnable breadth witness.

The calibration source-pin premise needs correction: `_SRC_TREE` has one entry, but two figures share it. `self_test` and `external_pint` both have checked source trees; `skill_md` and `concentration` do not. Only `self_test` substitutes an executed revision for the measured revision, and `prepare` checks both rules and source trees for both revisions there. The other figures execute their specified measured revisions, while scoring verifies rule and corpus content digests. Missing redundant source-tree pins for those two figures are not independently a release blocker. Report absent checks explicitly, as the `_SRC_TREE` comment promises, and require source equivalence whenever a substitution is introduced.

The calibration gate still routes every sample through `scan_trusted`, including skill samples; it does not yet validate the new CFG path. Its reported FAIL 0 of 4 can be an honest flat-path calibration result, as intended, but cannot be cited as an end-to-end CFG reproduction. The full figure result was not rerun in this review; the suite's optional prepared-corpus test was skipped.
