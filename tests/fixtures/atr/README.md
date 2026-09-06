# ATR fixtures

Seventeen complete YAML rules copied from Git blobs at revision
`faf743fee8a5018467959ec8ea7ccdb1a1aab333` of
[Agent-Threat-Rule/agent-threat-rules](https://github.com/Agent-Threat-Rule/agent-threat-rules/tree/faf743fee8a5018467959ec8ea7ccdb1a1aab333),
the revision `sources.lock` pins and the revision the shipped timing measurement
covers. The twelve rules present before that re-pin are byte-identical at the
earlier revision `66c7c1573e202b83ac526b70275244c50000068a` they used to declare.
The adjacent LICENSE is the upstream MIT notice. `atr-source.json` records the
original repository paths and SHA-256 checksums. Filenames are shortened for
Windows path limits; YAML contents are unchanged.

These files are untrusted test data. They cover populated author attribution,
skill maturity, all five surfaces this loader assigns, a rejected pattern,
declared semantic fallback, conjunction, backreferences, mixed input fields,
code-block suppression, structured example inputs, and top-level false-positive
notes. The loader keeps third-party content redistribution unresolved.

Five of them carry a specific disposition rather than a specific shape, so the
screen's three routes are exercised against rules somebody actually published:

| Rule | What it covers |
|---|---|
| `00005` | twelve `any` conditions whose scoped alternation exceeds the pattern-length limit, so the branches are carried as `regex_any` instead of the rule being dropped |
| `00110` | measured fast, `IN`, and BROAD against a common-text witness |
| `00129` | a condition written as UTF-16 surrogate pairs, ported to code points before it is screened |
| `00570` | measured fast on `OUT` |
| `01025` | measured fast with a declared semantic fallback |

Six of the seventeen are measured above the one-second hook budget and are
refused with the measurement attached: `00040`, `00070`, `00120`, `01756`,
`02260` and `02261`. That is a property of the rules upstream published, not of
this fixture; a rule with no timing record is screened on shape and says so.
