# Default bundle redistribution gate

Before releasing a corpus bundle, run the following against all six pinned
corpora and their original archives. This command fails if inputs are absent,
modified, incomplete, unaccounted for, or inconsistent with the rights policy.
It performs no download or extraction and prints counts and identifiers only.

```sh
PYTHONPATH=src python scripts/audit_distribution.py /path/to/corpora \
  --archives /path/to/archives
AGENT_DEFS_CORPORA=/path/to/corpora AGENT_DEFS_ARCHIVES=/path/to/archives \
  PYTHONPATH=src python -m pytest tests/test_distribution_corpora.py -q
```

The pytest checks use real loaded corpora and deliberately remove restriction
flags, omit attribution, leak an excluded path, and bypass bundle filtering to
verify that the gate fails. They skip in ordinary fixture-only development when
`AGENT_DEFS_CORPORA` is unset; the release command above never skips. There is no
corpus release pipeline in this repository yet, so a future publisher must run
this gate before serialization and independently check its final artifact.

On 2026-09-04 Pacific, the gate verified all six archive digests against
`sources.lock` and byte-compared every file used by the loaders, plus ATR's
excluded directory and npm manifest. The result is `distribution-audit.json`.

| Source | Loaded records | In default bundle | Held: AgentHarm field-of-use |
|---|---:|---:|---:|
| ATR | 793 | 768 | 25 |
| Netzilo | 1,156 | 1,131 | 25 |
| AgentShield | 69 | 69 | 0 |
| agent-audit-kit | 332 | 332 | 0 |
| AVE | 80 | 80 | 0 |
| Guardana | 51 | 51 | 0 |
| Total | 2,481 | 2,431 | 50 |

`default_bundle()` returns 2,431 normalized records from these inputs, holding
back 50 under **AgentHarm field-of-use**: 25 ATR originals and 25 declared
Netzilo conversions. The latter exclusion is a conservative decision about
declared derivation, pending separate rights review. Under **ATR test corpora**,
1,101 files are excluded before loading and are not part of the 2,481-record
denominator. Of those files, 1,013 are draft proposals with empty conditions
and `TODO(human)`; 88 are ancillary files. The loader already used only `rules/`
before this change. The new delta makes that boundary visible, and both the
manifest input path and bundle filter enforce it explicitly.

**garak attribution** excludes zero records. All 228 ATR garak author strings
survive, as do 121 `payload_source` pointers in raw data and explicit lineage.
The previously reported count of 110 was not reproduced. No deduplication is
included in these numbers. Only 660 eligible records currently have executable
predicates; the other 1,771 remain reference records. Redistribution eligibility
does not grant an interrupting lane or resolve every underlying rights question.

These are normalized bundle counts, not a claim that the current wheel contains
the six corpora. The package currently contains code and four authored starter
rules. This gate does not serialize raw rules or certify sample removal, scanner
results, or the final artifact. `THIRD-PARTY-NOTICES` is explicitly included in
package license files so attribution accompanies the wheel and source archive.
