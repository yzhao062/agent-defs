# The Normalized Record

Every source loader in this package emits `agent_defs.model.Rule` and nothing else. This file is the
contract. A loader that cannot fill a field says so in `not_runnable_reason` or leaves the field
empty; it never invents a value, and it never converts one.

## The rule that decides every other question

**What the source published travels verbatim. What we decided travels beside it, under our own name,
dated and withdrawable.**

Fields ending in `_raw` hold upstream bytes. `severity_raw` is the clearest case. Six corpora use six
severity vocabularies, and a mapping that silently rewrote `critical` into a number would quietly
downgrade the rules that matter most. So the string is carried as published, `severity_field` records
which upstream key it came from, and any mapping lives in one named function per source that a reader
can go look at.

`lane` is the opposite case. It is ours, it is assigned at build time from a measurement, and an
upstream marking of `stable`, `critical` or `confidence: 95` grants nothing.

## Identity and lineage

| Field | Meaning |
|---|---|
| `id` | `{source}:{source_id}`, the identifier this package uses |
| `source` | one of `atr`, `netzilo`, `agentshield`, `agent_audit_kit`, `ave`, `guardana` |
| `source_id` | the upstream identifier, verbatim |
| `source_rev` | the pinned commit the record was read from, full 40-character sha |
| `source_path` | path inside the source repository |
| `upstream_url` | a link a person can open |
| `lineage` | `Lineage(kind, value, evidence)` per declared origin |
| `license_spdx` | the source's own licence identifier |
| `redistribution` | `granted`, `denied` or `unresolved` |

`lineage` is where a corpus's statement about its own content is kept. Three shapes seen so far, all
facts the projects publish about themselves:

- ATR's `author` field names an attack corpus or benchmark on 288 of its 793 rules, and names garak
  on 228 of those. `kind="author_field"`.
- Netzilo's 1,153 rules include 814 conversions of ATR and AgentShield, recorded in a single import
  commit. `kind="conversion"`, with the commit in `evidence`.
- Guardana ships a jailbreak text that also sits in two benchmark corpora. `kind="benchmark"`.

Carrying that is adapter work and it is the differentiator. Ranking projects on it is a separate
artifact and does not belong in this package.

## Execution

| Field | Meaning |
|---|---|
| `surface` | `CFG`, `IN`, `OUT`, `PROMPT`, `PIN` or `NONE` |
| `breadth` | `NARROW`, `MEDIUM`, `BROAD` |
| `predicate_kind` | `REGEX`, `SUBSTRING_ANY`, `SUBSTRING_ALL`, `STRUCTURED`, `NONE` |
| `predicate` | the condition, in the shape `predicate_kind` names |
| `not_runnable_reason` | required whenever `predicate_kind` is `NONE` |
| `case_sensitive` | defaults to `False` |
| `bindings` | `ChannelBinding` per channel the source's own dispatcher routes this rule to |

The surfaces are the four places a person's agent offers, plus `PROMPT` for rules about the user's own
text and `NONE` for reference material with no interception point. Measured distribution across the
six corpora: 787 of ATR's 793 rules execute somewhere and 515 of those sit on `OUT`; agent-audit-kit
is almost entirely `CFG` at 235 of 330; AVE ships zero executable predicates and is reference
material.

**`case_sensitive` defaults to False on purpose.** Eleven Netzilo rules miss all 61 of their own
linked positive examples until the example is lowercased, because their selectors dropped a
case-insensitivity that ATR supplies implicitly. A loader that ports a Sigma selector must decide
this deliberately and record why in `extra`.

**Do not approximate a structured condition into a loose regex.** A Sigma `selection` with three
`contains` clauses is `SUBSTRING_ALL` or `STRUCTURED`, never a regex built by joining them. Widening
a condition to make it runnable manufactures exactly the noise this project exists to avoid. A
condition that cannot be carried faithfully gets `predicate_kind=NONE` and a reason, and is counted.

The supported `STRUCTURED` forms are `{"regex_all": [pattern, ...]}` and
`{"regex_any": [pattern, ...]}`: 1 to 64 regexes that must all match the same text payload, or of
which any one may. Each leaf passes `screen_pattern` and is searched independently; the loader adds
no regex syntax and the runtime does not retry one leaf in response to another. The rule's case mode
applies to each leaf, including its original inline flags. `regex_all` findings show the first
leaf's match span only after every leaf matches, as with `SUBSTRING_ALL`; `regex_any` reports the
leftmost hit, breaking a tie toward the earlier leaf, which is where an alternation of the same
branches would have matched. Other structured forms, mixed payload fields, mixed case modes and
backreferences remain unsupported. `scan()` screens and searches every leaf in its worker under the
same scan deadline.

`regex_any` exists so that a limit on pattern length cannot decide whether a rule ships. A source's
disjunction is normally carried as one scoped alternation, which is this package's own rewrite of
what the source published. Two ATR rules join to more than the 4,096-character limit that bounds a
single pattern, and the limit has real headroom against upstream text: the longest pattern any of
the six corpora publishes is 2,213 characters and the largest condition count is 46. When the join
does not fit, the branches are carried instead, and `extra["execution"]["composition"]` records why.

**`bindings` carries the source's own dispatcher, and it is part of the rule.** A pattern lifted out
of the engine that decides when it runs is a different artifact from what its authors shipped. On
ATR's skill benchmark the same patterns matched flat flag 155 of 466 benign documents and, run
through ATR's own admission gates, flag the 1 that ATR itself flags. A `ChannelBinding` names the
channel, the source's entry point, whether that entry point admits the rule, and every gate consulted
with its verdict and the upstream file and line the gate value was read from. A refused rule keeps
its binding, so a rule this package dropped stays distinguishable from a rule its own author excluded.

A binding is a second execution model, not a view of `predicate_kind`, and the two refuse different
things. ATR's skill path resolves every condition field to the whole document, so a rule the flat
predicate refuses for naming two fields runs there unchanged; it never composes an `any` rule's
conditions, so a rule refused because the composed alternation trips the pattern screen runs there on
the conditions that pass individually. 42 of the 793 pinned ATR rules have no flat predicate and an
executable binding, and such a rule is admissible: `admit()` reads `bindings` as well as
`predicate_kind`.

Direction matters when a condition is refused on safety. Dropping one branch of an `any` rule can
only lose matches, so the branch is dropped and recorded on the binding. Dropping one branch of an
`all` rule would fire it on less evidence than its author required, so the rule loses its binding
instead. A loader that cannot read its source's dispatcher emits no binding at all rather than a flat
predicate wearing the dispatcher's name.

## What the source says about itself

| Field | Meaning |
|---|---|
| `examples_positive` | the source's own positive examples, verbatim |
| `examples_negative` | its negative examples |
| `false_positive_notes` | its prose notes about false positives |

`examples_positive` carries a job. A rule that matches nothing on benign material is the goal, and a
rule whose condition can never be true is dead weight, and the two look identical in a match count.
Running a rule against its own positive examples separates them: 1,308 of the 1,333 rules that matched
no benign file still match their own examples, so the quiet majority is precise rather than dead.

The false-positive notes are prose, not predicates: 2,346 strings across 761 ATR rules, 3,918 across
Netzilo, 164 across AgentShield. None is a suppression rule. They are input to a build-time review.

## Admission

| Field | Meaning |
|---|---|
| `lane` | `DO_NOT_SHIP`, `RECORD`, `ADVISE`, `DENY` |
| `lane_reason` | why, in one line |
| `benign` | `BenignFiring(trials, hits, u95, corpus, measured_at)` or `None` |

Every executable rule starts in `RECORD`. Leaving it needs a measurement on benign material, and the
bound is exact rather than a rule of thumb: with zero hits in `n` independent trials the 95% upper
bound on the true rate is `1 - 0.05 ** (1/n)`. A 0.5% claim needs 598 trials, a 0.1% claim needs
2,995, and zero hits in ten authored fixtures bounds the rate only at 25.9%. `agent_defs.lanes` holds
this and the tests pin the three numbers.

The bundle matters as much as the rule. One quiet rule inside a loud bundle still produces a loud
tool, so `admit()` takes `bundle_ok` and refuses an interrupting lane without it.

## Two safety rules a loader must not break

**Rules are data, loaded by code.** Nothing renders corpus content into a file an agent reads as
instructions. These corpora carry jailbreak payloads, so writing them into `AGENTS.md`, `CLAUDE.md`
or an equivalent would be an injection channel rather than a defence.

**Patterns are screened before they ship and executed behind a process deadline.**
`evaluate.screen_pattern` refuses a pattern on measurement where one exists and on shape where none
does. The measurement is build-time data in `src/agent_defs/hazards.json`: for every rule in the
pinned ATR corpus, whether an adversarial witness held one `re.search` past the one-second hook
budget, the smallest crossing input, and the time there. A recorded crossing refuses and carries its
numbers into the reason. A recorded non-crossing admits, and overrides the shape screen, because a
measurement of the property beats a proxy for it: across that corpus the shape screen refused 86
rules for a nested quantifier of which 44 never crossed, while 220 rules that did cross shipped. A
pattern with no record keeps the shape screen, which rejects nested repetition and alternation under
repetition, and its refusal says the pattern was unmeasured. Backreferences, conditional references,
unpaired UTF-16 surrogates and invalid patterns are refused whatever their timing.

Neither route is a proof of linear runtime, and the two verdicts are not symmetric: a witness that
crossed is proof, while a search that found none is evidence. Python's `re` offers no timeout, so the
runtime deadline stays the backstop for both. `scan()` therefore validates, compiles, and matches
inside a disposable standard-library subprocess that the parent kills at the scan deadline. Worker
validation also protects against stale or unscreened bundles. Process creation and pipe I/O run in a
bounded supervisor thread so a slow OS launch cannot hold the caller. Late launches are cancelled
before receiving input. At most four pending supervisors are allowed. Cleanup may add up to 100 ms
to the caller's wait; there is no claim of hard real-time OS scheduling.

Rules run in deterministic cost-hint order, with substring predicates first. Findings do not stop the
scan. Completed findings survive a later timeout. `ScanResult.complete` is false on input truncation,
unfinished rules, rejected rules, or worker failure; an empty incomplete result is not a clean scan.
Reading `ScanResult.findings` raises `IncompleteScanError` unless the scan is complete.
`partial_findings` is the explicit escape hatch for callers that implement a policy for incomplete
coverage. Offline measurements abort; the hook retains completed findings and issues fixed user and
model warnings. A coverage failure alone never grants an interrupting lane.

The isolated evaluator now searches the entire input up to 4 MiB by default, under the same 250 ms
deadline and up to 100 ms cleanup allowance. This replaces the old 256 KiB prefix. It uses one
contiguous string because accepted regexes can have unbounded match lengths and lookarounds; finite
window overlap cannot preserve all of those predicates. Offsets remain original Python string
indices and each rule returns at most one finding. Inputs beyond 4 MiB, or an explicitly smaller
`max_bytes`, are incomplete. Preparation is bounded by this input size and the existing bundle limits.
The evaluator does not promote a timeout or a RECORD finding into an interrupting decision.

Case-insensitive substring matching uses the same Unicode semantics as Python `re.IGNORECASE`, with
offsets into the original input. Matching performs no normalization and no full multi-character case
folding. UTF-8 byte limits preserve lone surrogates with `surrogatepass` rather than deleting them.
Findings carry only `rule_id`, `surface`, `start`, and `end`. There is no matched-text field or excerpt.
A person can locate evidence in the original payload using the span; the hook log adds the JSON
value path and a content hash. Model warnings contain only package-authored constants, never excerpts,
rule prose, identifiers, paths, or exception details. Rejected conditions remain explicit errors,
never looser predicates.

## Reporting what did not survive

Each loader returns its records and a delta: how many upstream entries it read, how many it emitted,
and every field or construct it could not carry, by name and count. The delta is published with the
package. A compatibility claim ages badly and an enumerated delta does not, which is the mechanism
worth borrowing from PyOD rather than its interface.
