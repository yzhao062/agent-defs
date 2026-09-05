# Sigma loading and conversion deduplication

Install `agent-defs[sigma]` to read YAML. PyYAML is imported inside `load()` only;
the package and this loader module can both be imported without it. The existing
`sigma` extra already declares `PyYAML>=6.0`; the core dependencies remain empty.

```python
from agent_defs.loaders.sigma import load, dedup, deduplicated_view, reachability

netzilo, load_delta = load(
    "/checkouts/aidr-sigma",
    source="netzilo",
    source_rev="5069b74d725a3cb7a7267833cbf0f8de1f31e4a7",
)
agentshield, shield_delta = load(
    "/checkouts/agentshield",
    source="agentshield",
    source_rev="1bd56f9854426e29d59715e81c45fcfe38c7ee0e",
)
# atr_records must come from the ATR loader with its case mode and examples.
full, dedup_delta = dedup([*atr_records, *agentshield, *netzilo])
unique = deduplicated_view(full)
positives = reachability(full)
```

`load()` accepts a repository root or a single YAML file. Defaults are `ai_agent`
for Netzilo and `rules/rules/ai_agent` for the AgentShield application repository.
Pass `rules_dir` explicitly when the same upstream repository uses another layout.
The caller supplies a full pinned commit SHA. The loader never fetches upstream.
Both functions return a named tuple with `rules` and `delta` fields, also unpackable.

Deduplication preserves input order and every record. An ATR match requires the
published `ATR Community (adapted)` author and exact ATR ID in an
`agentthreatrule.org/.../rules/ATR-...` reference. An AgentShield match requires
an AgentShield author declaration and an exactly preserved source ID. Neither
title similarity nor regex similarity is used. The matched copy gains
`Lineage(kind="conversion", value=<origin source ID>, evidence=<method and URL>)`,
`extra.is_conversion_duplicate=True`, and `extra.duplicate_of=<normalized ID>`.
The delta enumerates every match, missing origin and ambiguous origin by ID.
Ambiguous or absent origins do not suppress records. A source citation alone
does not establish a conversion.

`deduplicated_view()` filters only marked copies whose origin is present in the
requested view. This is provenance deduplication: a conversion may have changed
its predicate. It does not establish behavioral equivalence or certify that the
origin is runnable. Use the full result to review those differences.

Boolean parsing preserves selection references, parentheses, AND, OR, NOT,
condition lists, and `1/all of` quantifiers. A contains list remains OR unless
its own `all` modifier requires AND. Pure, same-field containment expressions
that flatten exactly become `SUBSTRING_ANY` or `SUBSTRING_ALL`. A single regex
becomes `REGEX`. A flat conjunction of regexes on one field with one modifier
case mode becomes `STRUCTURED` with `regex_all`, searched independently. Regex
alternatives, mixed containment groups and negated filters remain `NONE`: the
runtime does not support general Boolean trees. The loader never
joins clauses into a regex and never drops an event guard or unavailable field.
`content`, `response` and `command` each identify a scalar payload; they are not
interchangeable fields. Consumers must supply that field's value when scanning.
Multi-field predicates, event-type guards, wildcards, unsupported modifiers,
execution scripts and unsupported logsource constraints are retained with reasons.
Surface assignments are metadata; they cannot replace those guards.

Every published regex is screened, including patterns in refused selections.
Any rejection makes the whole rule non-runnable; an unsafe OR branch is never
silently removed. The delta records selection, field, list index and reason by
rule ID. Ordinary Sigma regex defaults remain case-sensitive and contains defaults
remain insensitive. Deduplication restores a matched ATR origin's case mode and
records its source revision and reason. Inline flags remain unchanged.

Raw file text, parsed source metadata and the original detection are retained in
`extra`. Linked ATR examples are copied unchanged and labeled with their origin.
The audit accepts both `input` and a single named scalar payload such as
`tool_response`. It keeps multi-field and object-valued examples as structured
data, and separately reports the original `input`-only case-defect cohort.
AgentShield's `bench/testcases/*.yaml` scenarios link through exact IDs or declared
aliases in `expected.must_trigger_rules`; their complete event structures remain
in `extra.positive_scenarios_raw`. They cannot fit `Sequence[str]` examples without
losing event/session semantics. `reachability()` reports them as unevaluated and
does not serialize them into text scans. It separately tests the supported scalar
predicates against unchanged string examples. Source maturity never promotes a lane.

`tools/audit_sigma.py` reproduces all published counts and writes a JSON report.
It verifies the two Sigma checkouts and verifies every ATR archive file against
the pinned Git blob hash. Its optional case diagnostic runs the original regex
boolean condition in a subprocess with a hard deadline. That diagnostic can test
screen-rejected upstream patterns, but never changes their admission or runtime
status. Multi-field scalar-broadcast probes are reported separately and are not
native reachability results. [sigma-audit.json](sigma-audit.json) contains all
conversion matches, unmatchable IDs, refused constructs, screening rejections,
case decisions and observed source URL statuses.
