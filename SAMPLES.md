# Known-Malicious Sample Content

Several corpora ship attack samples beside their rules. ATR carries 32 under
`data/skill-benchmark/malicious/`, and 1,613 malicious skills sit in the archived `openclaw/skills`
snapshot this project also wants to preserve. This file states what happens to that content, because
getting it wrong breaks an install rather than a measurement.

## What happened on 2026-09-05

A build worker extracted ATR at `faf743f` onto a Windows machine running Bitdefender Total Security.
Real-time protection quarantined files out of the checkout as `tar` wrote them, and kept going for
ten minutes afterwards. Measured against ATR's own `manifest.json`:

| | Manifest | On disk | Quarantined |
|---|---:|---:|---:|
| `malicious/` | 32 | 20 | **12** |
| `benign/` | 466 | 466 | 0 |

Two detections were seen live, `ninja-039-malware-dropper-whatsapp-mgv.md` as
`Trojan.Generic.39669511` at 18:37:26 and `snyk-005-malware-dropper-rentry.md` as
`Trojan.Generic.40095305` at 18:40:57. A second checkout of an earlier revision on the same machine
had already lost 12 of the same class before anyone looked.

**The selection was exact.** All 12 taken are `malware_delivery` (11) or `reverse_shell` (1). The 20
left are `context_poisoning`, `credential_exfiltration` (6), `prompt_injection` (2), `evasion` (4),
`supply_chain` (2), `unicode_injection`, `rug_pull`, `subcommand_overflow`, `privilege_escalation`
and `data_exfiltration`. Nothing in the benign class was touched.

## What that settles

**Antivirus already covers the code-shaped half and sees nothing in the instruction-shaped half.**
Twelve of twelve against droppers and reverse shells; zero of twenty against samples whose whole
payload is text addressed to an agent. The second class is the one this package is for, and this is
the cleanest evidence available that the two do not overlap.

**Sample text cannot be shipped.** `pip install agent-defs` must not drop AV-detected files onto
anyone's disk. An install that trips the user's antivirus is a worse failure than a noisy hook: it
costs trust immediately, it is reported rather than tuned, and the index may pull the package.

**A corpus that only exists on disk is a corpus that silently degrades.** Any count taken from an
extracted checkout on a protected machine is a count of the survivors. Measurements taken this way
must record how many manifest entries were present when they ran.

## The rules that follow

1. **Extract the inputs a loader declares, and nothing else.** "Known-malicious paths" is the wrong
   unit, because a corpus does not tell you where it will put its samples next; the deny-list that
   tried was outrun twice. `sources.DECLARED_INPUTS` names what each loader reads and `fetch`
   writes only that. Anything else is read from the archive in memory, never written. A source with
   no declaration is still on the deny-list and still carries that risk.
2. **Never vendor sample text into the wheel or the npm package.** `examples_positive` is a
   build-time input, not a shipped field.
3. **Ship the result of the reachability check, not its input.** For each rule: whether it matched
   its own positive examples, how many, and the sha256 of each example. A consumer who wants to
   re-run the check fetches the pinned source themselves and verifies against the digest. This keeps
   the check reproducible without redistributing the payload.
4. **Every measurement records corpus completeness.** A run states how many manifest entries it
   found against how many the manifest declares. A run over an incomplete corpus is reported as
   incomplete rather than silently normalized.
5. **Ship a self-check.** Before publishing a bundle, scan the built artifact with whatever scanner
   is available and record the result. A detection on our own release is a release blocker.

## It happened a third time, and the guard was the thing that failed

2026-09-06. A `sources.fetch("atr")` on the Windows host to count something unrelated set the
antivirus off again. The two `NEVER_EXTRACT` prefixes held: `data/skill-benchmark/malicious` and
`data/test-corpora` were skipped, 1,133 members in total. What landed was
`conformance/v1.0/fixtures/tp/`, the corpus's own conformance suite, which carries one
true-positive attack document per rule in 74 directories. The deny-list did not name it, and the
fetch then failed during cleanup because the scanner was holding a file open.

**A deny-list cannot know where a corpus will put its samples next.** That is the finding, and
adding the missing prefixes was not the fix. `fetch` now extracts by **allow-list**: a source listed
in `sources.DECLARED_INPUTS` gets the inputs its loader reads and nothing else. For ATR that is
`rules/`, the licence, and the four engine sources `atr_skill_gates` parses to establish which rules
the skill entry point admits. Measured against the pinned archive in memory: **798 members selected,
18,607 refused**, no `data/` member among them. The deny-list alone would have selected 17,803.

Naming the missed prefixes would not have been enough, and this is what settles it. At that same
revision the deny-list also did not name `data/autoresearch/adversarial-samples.json` (1,054 payload
records), `data/autoresearch/missed-payloads.json` (895), `data/evasion-payloads.json` (64),
`data/semantic-validation/attacks.json` (20), or the 850-record `data/pint-benchmark/pint-corpus.json`.
Adding those five would have left a sixth to be found the same way, by a scanner.

This bounds what is extracted to a declared set. It does not certify the contents of an allowed file:
upstream can add a sample under `rules/`, and rule YAML carries positive examples by design. The
promise is a bounded selection of declared inputs, not a clean corpus.

A cache built before this change holds paths the allow-list no longer selects, so it fails
verification with "cached tree has missing or extra paths" and `fetch` raises rather than hitting.
Delete the entry and refetch. That is the fail-closed direction, and on this host the cache is empty.

Three further changes:

1. Each file is admitted on both the path it is written to and the path its bytes come from. A link
   is stored under its own name while carrying its target's content, so `rules/x -> ../data/test-corpora/payload`
   copied an excluded file into an admitted directory under both policies. Symlinks and hardlinks
   are regression-tested in both directions.
2. Under an allow-list a directory exists only because an admitted file needs it, so a refused tree
   no longer leaves behind empty folders named after the samples it refused.
3. A real defect found while fixing the first: the extractor skipped excluded members while the cache
   verifier compared the tree against **every** member the archive declares. A cache built for a
   corpus with excluded paths therefore failed its own verification, so it could never hit again and
   later calls raised `SourceError` until the cache state changed. Sharing one filter fixes that
   disagreement. It was never tested because the fixture archive has no excluded members; it is now.

That defect is **not** the reason samples kept reaching a scanner, and an earlier draft of this
section said it was. `fetch` returns `_check()` for an existing cache and raises on failure; it does
not fall through to a download. Repeated extraction needs a missing cache, an external removal, or a
failure before publication, which is what the third incident was: extraction into the staging
directory failed while the scanner held a file open, so no entry was published and the 17,756 staged
files had to be swept by hand. A run that cannot publish leaves nothing for the next one to hit.

The count that prompted the fetch was taken the way rule 1 asks for, and the allow-list above was
verified the same way: the tarball streamed into memory, never written.

## It happened again, which is why it is now a guard rather than a rule

2026-09-04, later the same day. Real-time protection fired repeatedly during the second build round.
Two paths were named in the alerts, and a sweep found the actual state: **six separate ATR checkouts
on the Windows host**, holding roughly 4,520 files between them under
`data/skill-benchmark/malicious/` and `data/test-corpora/`. One was a build worker's evidence cache
left behind by the first round, still being rescanned hours after that round had been committed.

Two things were wrong, and only one of them was the scanner's business.

**The operator was interrupted repeatedly by their own antivirus doing its job.** Nothing here was a
false positive.

**Every count taken on that host was a count of survivors, and stayed that way silently.** A checkout
that shrinks under a running measurement produces a number with no error bar and no warning.

The instruction to keep this material off the host existed and was ignored, because it was a sentence
in a briefing rather than something the code enforced. `sources.NEVER_EXTRACT` now holds the two
prefixes and `fetch()` skips them, so a member under either one is never written by this package. When
anything is skipped the cache entry carries an `EXCLUDED` file recording the count, because a silent
omission is the failure this whole file is about. `tests/test_sources.py` pins both the blocked and the
allowed paths.

Nothing needs them on disk. Reachability is checked at build time against examples read from the
archive in memory, and the full corpus lives on a Linux box with no scanner when a whole-corpus count
is genuinely required.

## The one that was open, and what it found

Rule content itself carries attack strings, because a detection pattern for a dropper contains the
dropper's indicators. Whether a bundle of such patterns trips a scanner on its own was unmeasured,
and rule 5 existed to find out before a user did.

It has now run. `scripts/scan_artifact.ps1` copies the artifact to a temporary directory and scans
the copy, so a detection quarantines the copy and leaves the repository alone. The copy also passes
under whatever resident protection is active, so one run addresses both questions: whether an
on-demand scan reports a threat, and whether the file survives contact with resident protection.

It has run twice, once per artifact. The current record, on 2026-09-07 against
`src/agent_defs/bundle.json` at sha256
`e6efd658a7f93eeef6ad1687a0e4782c3f3c2addc9cd2fd182eda0b3c96e3310`, 1,456,844 bytes, 216 ATR rules:
**one Windows Defender on-demand scan reported no threats, and the copy was still on disk three
seconds after it was written, on a machine registering Windows Defender and Bitdefender Antivirus
with the Security Center.** Verdict `clean`. The first run, on 2026-09-06, was the same verdict
against the 205-rule artifact at `2611b056`, 1,372,797 bytes. The record is
`scripts/artifact-scan.json`, keyed by digest rather than by a path, so it names the exact bytes
scanned and does not silently carry over to a rebuild; that is why a rebuild replaces it. `tests/test_shipped_bundle.py` fails when the committed record describes
different bytes or is missing, so a rebuild without a rescan is caught rather than assumed.

Say it that way rather than "two scanners cleared it", because the run does not establish the
stronger claim. The product list comes from Security Center registration, which reports that a
product is installed and not that it was scanning that path; the survival window is three seconds,
so a delayed detection is not observed; and only one of the two products was asked for a verdict.

Two further limits on the result. It is one machine, so it is evidence rather than a guarantee for
every consumer. And it was taken after rules 2 and 3 removed 985 sample strings and 4.3 MB of raw
upstream documents from the artifact; the untrimmed bundle was never scanned, so it says nothing
about what would have shipped before that change.

The script that produced it took two rounds of review to get its failure handling right, and both
defects were the same shape: a run that went wrong left an older `clean` record for the same bytes
standing as the answer. First it threw the moment resident protection removed the copy, so the
single outcome most worth recording produced no record at all. Then it built the record only after
hashing the artifact and creating the scan directory, so a failure in either did the same thing
again, and it published with `Move-Item -Force`, whose provider answers a sharing violation on the
destination by deleting it and retrying. Setup now runs inside the guarded block, the record is
created before any of it, and publication uses `File.Replace`.

What the script promises is narrower than "every exit writes a record", which is what this file
said after the first of those rounds. A destination that cannot be written cannot be written. Every
*handled* failure replaces the record, and the exit code carries the rest: 0 clean and recorded, 1 a
detection, 2 an inconclusive run, 3 a result that could not be published.
