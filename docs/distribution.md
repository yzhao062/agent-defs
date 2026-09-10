# Default bundle redistribution gate

Before releasing a corpus bundle, run the following against all six pinned
corpora and their original archives. This command fails if inputs are absent,
modified, incomplete, unaccounted for, or inconsistent with the rights policy.
It performs no download or extraction and prints counts and identifiers only.

The corpus directory may be a full checkout or a tree `sources.fetch()` wrote.
Those two layouts differ in what reaches disk: the fetcher refuses to extract
ATR's `data/test-corpora/` members, and its allow-list also leaves the npm
manifest behind. Whatever the fetcher withholds is read out of the pinned
archive in memory, so the sample census and the manifest are the same in either
layout and no sample byte is written anywhere. That is the one absence the gate
accepts. A member the extraction policy admits is still required on disk and
byte-compared, a member it refuses is still byte-compared when a checkout
carries it, and an in-scope file the archive does not declare still fails.

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

All three ways this gate can be exercised have now been run. On 2026-09-10 the
five pytest checks above passed against the six real corpora and their pinned
archives on a Linux host. That run used a full checkout, the layout a maintainer
has. `tests/test_distribution_fetched_cache.py` covers the archive-memory path
against a fixture archive and needs no corpus. The end-to-end check passed that
same day over a real tree `sources.fetch()` wrote. There the fetcher itself
downloaded and extracted the six pinned sources. `data/test-corpora/` and
`data/skill-benchmark/malicious/` were absent because the extractor refused them
rather than because anything deleted them afterwards. Zero files sit on disk
under the excluded prefix while its 1,101 archived members are still counted.
The run reproduces the same 2,481 loaded and 2,431 shipping records the checkout
layout reports. That check skips unless `AGENT_DEFS_FETCHED_CORPORA` and
`AGENT_DEFS_ARCHIVES` are both set.

The sample census now comes from the archive while the loader's excluded-path delta
still counts files on disk, and the gate requires those two to agree in a checkout.
That equality holds only where every archived sample member is a regular file or a
directory. Measured on the pinned ATR archive on 2026-09-10: 610 directories and
19,405 regular files across the whole tarball, with no symbolic and no hard links,
and `data/test-corpora/` holding 13 directories and 1,101 files. A later pin that
stores a member as a link would need that check repeated.

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

These are normalized bundle counts across all six corpora, and the wheel carries
a subset of one of them. Today the package ships `src/agent_defs/bundle.json`:
216 ATR records at `faf743fe`, 205 on `OUT` and 11 on `IN`, beside the four
authored starter rules. Sample text does not travel with them.
`scripts/build_bundle.py` strips `examples_positive`, `examples_negative` and the
raw upstream documents that repeat them. It records the build-time reachability
result in their place, which is `SAMPLES.md` rules 2 and 3. The committed
`scripts/artifact-scan.json` records a clean scan of this artifact's exact bytes,
which is rule 5. See
[SAMPLES.md](../SAMPLES.md#the-one-that-was-open-and-what-it-found) for what that
scan establishes and its limits.

This gate does not certify the final artifact. `THIRD-PARTY-NOTICES` is
explicitly included in package license files so attribution accompanies the
wheel and source archive.
