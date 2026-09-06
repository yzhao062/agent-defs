# ATR loader

Install `agent-defs[atr]` and call `agent_defs.loaders.atr.load(root)`, with `root`
pointing to a clean ATR Git checkout. The returned `LoadResult` has `rules` and
`delta`. Fixture subsets can instead supply `atr-source.json`; see the checked-in
fixtures for its format. A directory name is never used as proof of a revision.

A verified archive tree can pass `source_rev=<full pinned SHA>` explicitly. The
caller must first verify the archive digest and tree bytes; the release gate in
`scripts/audit_distribution.py` does both against `sources.lock`. An explicit pin
cannot override a conflicting fixture manifest or Git revision.

The loader only discovers rule YAML under `rules/`. It counts all files under
`data/test-corpora/` in `delta.excluded_paths`, without reading their content.
Fixture manifests cannot reintroduce that excluded path. AgentHarm declarations
in `author` or `metadata_provenance` set `restricted` and `restricted_reason`,
while retaining the complete normalized record. `model.default_bundle()` removes
restricted records and rejects excluded source paths even if a loader emits one.
See `distribution.md` for the real-corpus release gate.

Every valid entry emits a `Rule`, including entries that cannot execute. The
complete parsed record is retained in `extra["upstream"]` and the decoded YAML
in `extra["upstream_yaml"]`. `delta.extra_fields` counts entries retaining each
upstream field. `delta.dropped_fields` counts rejected entries, whose YAML and
reason are retained in `delta.entry_errors`. `delta.unsupported_constructs`
counts constructs absent from executable predicates. `delta.pattern_rejections`
identifies every rejected occurrence by rule, zero-based condition index,
screening stage, and reason. These count dictionaries serialize with
`dataclasses.asdict` and `json.dumps`.

The author scalar becomes one verbatim `Lineage`, including project-only
attribution. Parenthetical spans and a separate corpus-marker classification
are annotations. Neither severity nor maturity is mapped. ATR's separate
`status` remains in `extra["upstream"]`.

`metadata_provenance.payload_source` also becomes a verbatim `Lineage` with
`kind="payload_source"` and evidence identifying the upstream YAML field. The
original value remains in `extra["upstream"]` as well.

Surface routing uses explicit scan targets and condition fields before category
inference. Each rule records the reason in `extra["surface_decision"]`. Rules
with multiple condition fields stay non-runnable because one text payload does
not preserve their field boundaries. There is no PIN classification without an
actual before/after comparison.

Each rule also carries ATR's own dispatch for the `CFG` channel in
`rule.bindings`, read from `src/engine.ts` and its neighbours by
`agent_defs.loaders.atr_skill_gates` and summarized in `delta.skill_gates` with
the file and line each gate value came from. A checkout that carries rule YAML
without engine sources emits no bindings at all and records why in
`delta.skill_gates["reason"]`; the CFG bundle is then empty rather than wrong.
The binding names every gate consulted and its verdict, so a rule ATR's own
dispatcher refuses is distinguishable from a rule this loader dropped. It is a
different execution model from the flat predicate above and refuses different
things: 42 pinned rules have no flat predicate and an executable binding. See
`cfg.md`, which measures the difference on ATR's own skill benchmark.

ATR's own engine is TypeScript, so its regexes are written against JavaScript's
UTF-16 code units. Each condition therefore passes `evaluate.port_utf16_surrogates`
before it is screened, which reads a surrogate pair back as the code point it
encodes: `\uDB40[\uDC00-\uDC7F]` becomes `[\U000E0000-\U000E007F]`, the Unicode
tag block. One rule in the pinned corpus needs this, `ATR-2026-00129`, and
without it the rule compiles, ships and matches nothing, because Python sees two
unpaired surrogates that no well-formed text contains. Each rewrite is recorded
in `extra["execution"]["utf16_port"]` and counted in `delta.dialect_ports`; the
upstream text stays verbatim in `extra["upstream"]`. A surrogate left unpaired is
reported rather than guessed at, and `screen_pattern` then refuses it.

Every ported regex is screened, including patterns in non-runnable entries. The
screen consults the shipped timing measurement first, so a rule measured above
the one-second hook budget is refused with its numbers in the reason, and a rule
measured under it is admitted even where the shape screen objects. A rule the
measurement does not cover is screened on shape and its reason says so.
`extra["execution"]["measurement"]` records which of the three applied.

Same-field ANY conditions use alternation with scoped inline flags. Same-field
ALL conditions use `STRUCTURED` with `regex_all`: independent screened searches
that must each match the same input. ANY compositions are screened again, and
when the composition alone fails, which at this pin means only that the joined
string exceeds the length limit bounding a single upstream pattern, the branches
are carried as `STRUCTURED` with `regex_any` rather than the rule being dropped.
The join is this loader's rewrite; the disjunction is what the source published.
`delta.composition_fallbacks` counts these by the reason the join failed.

A rejected branch disables the complete rule. Backreferences, unknown modifiers,
stateful methods, explicit code-block suppression, and disabled upstream statuses
fail closed. The 19 declared semantic pattern fallbacks are selected explicitly;
the model configuration survives as data. This implements raw published pattern
paths, not ATR's complete engine with its own Unicode processing and implicit
context policies.

Code-block suppression fails closed only here: the `CFG` binding implements it,
because ATR's skill path applies it and a port that skipped it would not be the
rule its authors shipped.

Positive and negative examples are verbatim text values projected from the
corresponding condition field. Adjacent event metadata stays in `extra`; it is
not another positive input. Multi-field examples retain separate text leaves
and their source paths without concatenation or object stringification.
False-positive prose is preserved from both supported upstream locations.

`BROAD` requires a screened condition path that matches a common text witness
from `BREADTH_PROBES`. The witness indices are recorded. Other rules are MEDIUM
and unmeasured; the loader does not infer NARROW from lack of a witness. This
diagnostic identifies common construct matches and does not estimate firing
rates. Runnable rules start in RECORD with no benign measurement.

Run `PYTHONPATH=src python scripts/audit_atr.py /path/to/atr` to reproduce the
inventory, all rejection IDs and reasons, breadth witnesses, surface decisions,
and reachability. The audit also compares composed predicates against the
original condition logic on positive/negative examples and diagnostic probes.
Rejected patterns are never executed by this audit.
