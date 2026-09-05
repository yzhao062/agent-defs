# ATR loader

Install `agent-defs[atr]` and call `agent_defs.loaders.atr.load(root)`, with `root`
pointing to a clean ATR Git checkout. The returned `LoadResult` has `rules` and
`delta`. Fixture subsets can instead supply `atr-source.json`; see the checked-in
fixtures for its format. A directory name is never used as proof of a revision.

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

Surface routing uses explicit scan targets and condition fields before category
inference. Each rule records the reason in `extra["surface_decision"]`. Rules
with multiple condition fields stay non-runnable because one text payload does
not preserve their field boundaries. There is no PIN classification without an
actual before/after comparison.

Every original regex is screened, including patterns in non-runnable entries.
Same-field ANY conditions use alternation with scoped inline flags. Same-field
ALL conditions use `STRUCTURED` with `regex_all`: independent screened searches
that must each match the same input. ANY compositions are screened again. A
rejected branch disables the complete rule. Backreferences, unknown modifiers, stateful methods,
explicit code-block suppression, and disabled upstream statuses fail closed.
The 19 declared semantic pattern fallbacks are selected explicitly; the model
configuration survives as data. This implements raw published pattern paths,
not ATR's complete engine with Unicode processing and implicit context policies.

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
