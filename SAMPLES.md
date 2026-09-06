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

1. **Never extract known-malicious sample paths to disk.** Read them from the archive in memory. The
   loader reads members by name out of the pinned tarball; nothing writes them out.
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

On 2026-09-06, against `src/agent_defs/bundle.json` at sha256
`2611b05684f17848406fbb20c3fe0fe2701be24f3d567b1b61db00889a091fa1`, 1,372,797 bytes, 205 ATR rules:
**one Windows Defender on-demand scan reported no threats, and the copy was still on disk three
seconds after it was written, on a machine registering Windows Defender and Bitdefender Antivirus
with the Security Center.** Verdict `clean`. The record is `scripts/artifact-scan.json`, keyed by
that digest rather than by a path, so it names the exact bytes scanned and does not silently carry
over to a rebuild. `tests/test_shipped_bundle.py` fails when the committed record describes
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
