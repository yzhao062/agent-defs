# The Refusal Screen, and Why It Refuses on Measurement

`evaluate.screen_pattern` decides which patterns this package will run. Until
round three it decided on shape: it parsed each regex and refused two syntactic
forms, a quantified group under an outer quantifier and an alternation inside a
repetition. That screen was the project's strongest safety claim. It was also
wrong in both directions, and the numbers are not close.

## What the Measurement Found

Round three timed all 3,320 patterns in the pinned ATR corpus against
adversarial witnesses built from each pattern's own parse tree, at nine input
lengths up to 1 MiB, one killable subprocess per attempt.

| | Rules of 793 |
|---|---:|
| At least one pattern held a single `re.search` past one second | 296 |
| Past sixty seconds | 211 |
| Of those sixty-second rules, shipped by the shape screen | 161 |
| Refused by the shape screen for a nested quantifier | 86 |
| Of those 86, never crossing one second at any tested length | 44 |

The shape screen's precision on its own claim was 42 of 86. Its recall against
the rules that actually crossed was 42 of 296. A test with those numbers is not
evidence about the property it names, and the property has a direct measurement.

The shape it structurally cannot see is a sequence of independent wildcards.
`ATR-2026-00233` carries `\w+:\s*.*\w+:`, which is neither of the two forms, and
which took 22.80 seconds on an idle machine against one real, unmodified 28 KB
mail thread. It shipped.

## The Rule This Package Now Follows

`screen_pattern` consults `src/agent_defs/hazards.json`, keyed by the exact
pattern text, and resolves in this order.

1. **A capability limit refuses first.** Backreferences, conditional references
   and unpaired UTF-16 surrogates are refused whatever their timing, because the
   timing would not change the answer and naming it would tell the reader less.
2. **A recorded crossing refuses, with its numbers in the message.** For example,
   `measured 22.80 s on 16384 bytes against a 1 s budget and still running at 60 s`.
3. **A recorded non-crossing admits, and the shape screen does not run.** This is
   the half that returns the 44.
4. **No record keeps the shape screen, and the refusal says `unmeasured`.**

`compile_rule` and the isolated worker consult the same table, so a rule the
loader admitted is not refused later by the same screen reading the same string.
The ATR loader passes its rule-level verdict down to every condition, which is
sound because a rule recorded as not crossing had every one of its patterns
measured.

## Why the Two Verdicts Are Not Symmetric

A witness that crossed is proof of slowness: the search ran, the clock ran, the
budget went. A search that found no witness is evidence, not proof, because a
witness generator can miss the input a particular pattern needs.

So the two are treated differently. A slow verdict refuses, because a refused
rule costs detections that nothing else recovers. A fast verdict admits, because
the runtime deadline still bounds the cost of being wrong: `scan` matches in a
disposable subprocess and kills it at the deadline. Being wrong about a negative
turns into one bounded, recorded incomplete scan. Being wrong about a positive
turns into a rule nobody can use.

## The Screen and the Deadline Are Both Load-Bearing

Neither replaces the other, and this is the reason to keep both.

Python's `re` cannot be interrupted mid-match. The only lever `scan` has is to
kill the whole worker at the deadline, which ends that event's scan for every
rule scheduled after the one that ran long. Dropping the deadline would turn each
slow shipped pattern into a real hang on ordinary input, since the mail thread
above was not crafted. Dropping the screen would not add wall-clock exposure,
because the deadline still bounds it, but it would raise how often an ordinary
event exhausts its budget and returns an incomplete scan. The screen lowers the
frequency at no runtime cost; the deadline bounds the damage of what the screen
does not catch.

## What the Table Is, and When It Goes Stale

`hazards.json` carries one row per rule and one per pattern. A rule row holds a
digest of the rule's own condition texts. An upstream source can edit a rule
without changing its id, and a verdict keyed on the id alone would then decide a
pattern nobody timed, so a digest mismatch falls back to shape screening. A
pattern row is keyed by the first 64 bits of the pattern's SHA-256.

The pattern rows carry only what follows from the sweep. A rule that never
crossed had every pattern measured, so each of its patterns is fast, and so is
every string this loader derives from them: the surrogate port and the scoped
alternation. A rule that crossed identifies only the pattern that crossed; its
siblings are left out, because the sweep does not say what they do alone.

A missing or malformed table degrades to shape screening rather than to
admission. That is the fail-closed direction, and it is what a consumer sees if
the table is stripped from an install.

Regenerate it with `scripts/build_hazards.py`, which reads the sweep's output and
the pinned corpus. It refuses to write a table whose pattern counts disagree with
the corpus, and refuses one where any pattern is recorded both fast and slow.

## The Benefit, Measured

The witness round three found for `ATR-2026-00233` is 16,383 bytes of plain
ASCII, `"a:"` repeated, which anybody who can put text in a tool result can send.
Timed against the pinned corpus's `OUT` bundle on one idle machine:

| | Rules | Seconds |
|---|---:|---:|
| Before, the 306 rules the shape screen shipped | 306 | 282.996 |
| After | 218 | 0.262 |

Two rules carry 282.5 of those seconds: `ATR-2026-00233` at 142.65 and
`ATR-2026-00228` at 139.84. Both are refused on measurement now. The bundle goes
from 283 times the one-second hook budget to 26% of it.

The same comparison on benign material is much less dramatic, which is the honest
half of the result: on 28 KB of this repository's own documentation the before
bundle takes 0.837 seconds and the after bundle 0.430. The screen's value is
against text somebody chose, and `CFG` and `OUT` are exactly the channels where
somebody else chose it.

## The Cost, Measured

Against the pinned ATR corpus, executable rules go from 608 to 428.

| Surface | Corpus | Executable before | Executable after |
|---|---:|---:|---:|
| `CFG` | 116 | 94 | 59 |
| `OUT` | 396 | 306 | 218 |
| `PROMPT` | 218 | 183 | 137 |
| `IN` | 57 | 25 | 14 |

220 rules leave because a measurement says they cross the hook's budget. 39
return because a measurement says the shape screen was wrong about them, and one
more because a length limit stopped deciding whether a rule ships. Of the 365
rules that remain unexecutable, 296 are refused on safety with a measurement
attached and 69 on a named capability limit: 41 for multiple condition fields, 13
for code-block suppression, 6 for a stateful method, 5 for a construct Python's
`re` will not compile, 2 for a backreference, and 2 disabled upstream.

Every rule this package refuses stays in the package with its reason, and none of
those reasons is now a limit on how long a string this package composed happened
to be.

The table is keyed by pattern text rather than by corpus, so a rule republished
somewhere else inherits the timing of the pattern it republished. Netzilo carries
several hundred ATR conversions, and its executable count moves from 80 to 72:
fifteen rules refused on a measured crossing, seven admitted because the same
measurement says the shape screen was wrong about them.
