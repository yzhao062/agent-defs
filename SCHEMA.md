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

**Patterns are screened before they ship, never in the hot path.** `evaluate.screen_pattern` refuses a
quantified group under an outer quantifier and anything that does not compile. Python's `re` offers no
timeout, so a pattern that can backtrack catastrophically has to be kept out of the bundle; once it is
running, nothing can interrupt it.

## Reporting what did not survive

Each loader returns its records and a delta: how many upstream entries it read, how many it emitted,
and every field or construct it could not carry, by name and count. The delta is published with the
package. A compatibility claim ages badly and an enumerated delta does not, which is the mechanism
worth borrowing from PyOD rather than its interface.
