"""Regenerate ``src/agent_defs/hazards.json`` from a timing measurement.

The screen refuses on measurement where a measurement exists, so the measurement
has to be build-time data: a per-pattern regex timing sweep takes hours and
cannot run at import. This script turns the round-three sweep into that data.

Inputs
------
``--report-data``  the sweep's per-rule output (``report_data.json``): for every
                   rule, whether any of its patterns held a single ``re.search``
                   past one second, the smallest crossing input, and the wall
                   time there. Every rule in it is fully covered, so a rule
                   recorded as not crossing had all of its patterns measured.
``--atr``          the pinned corpus, read for the condition texts the sweep
                   timed. Nothing else in the tree is opened.
``--manifest``     the pattern texts each rule carried when the sweep ran, as
                   digests. The report names a count and not an identity, so
                   without this a rule whose condition changed while its count
                   held would take the old verdict onto new text: not a lookup
                   miss, which falls back to shape, but a lookup hit that is
                   wrong. Every rule the builder accepts must match it exactly.
``--merge``        measurements this table carries that the report cannot
                   produce. They are applied last, slow winning over fast, so a
                   rebuild keeps a correction instead of restoring the weaker
                   verdict it was written to replace.

What lands in the table
-----------------------
Rule rows carry a digest of the rule's own condition texts. A source can edit a
rule without changing its id, and a verdict keyed on the id alone would then
decide a pattern nobody timed; a digest mismatch falls back to shape screening.

Pattern rows carry the verdicts that follow from the sweep and no others. A rule
that never crossed had every one of its patterns measured, so each of them is
fast, and so is every string this loader derives from them: the surrogate port
and the scoped alternation. A rule that crossed identifies only the pattern that
crossed; its siblings are left out, because the sweep does not say what they do
on their own.

Run
---
    PYTHONPATH=src python scripts/build_hazards.py \
        --report-data <round3>/evidence/report_data.json \
        --atr C:/atrx/Agent-Threat-Rule-agent-threat-rules-faf743f
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from agent_defs.evaluate import _fingerprint, port_utf16_surrogates
from agent_defs.loaders.atr import _scoped

BUDGET_S = 1.0
MEASUREMENT_ID = "agent-defs.hazards e3-2026-09-05"
METHOD = ("per-pattern adversarial witness search built from each pattern's own parse tree, nine "
          "input lengths to 1 MiB, 1.10 s discovery cap and 62 s confirmation cap, one killable "
          "subprocess per attempt, CPython 3.12 on Windows")
MEASURED_AT = "2026-09-05"


def condition_patterns(raw):
    conditions = raw["detection"].get("conditions", [])
    if not isinstance(conditions, list):
        return []
    return [c["value"] for c in conditions
            if isinstance(c, dict) and c.get("operator") == "regex" and isinstance(c.get("value"), str)]


def main() -> int:
    cli = argparse.ArgumentParser(description=__doc__)
    here = Path(__file__).resolve().parent
    cli.add_argument("--report-data", type=Path, required=True)
    cli.add_argument("--atr", type=Path, required=True)
    cli.add_argument("--source-rev", default="faf743fee8a5018467959ec8ea7ccdb1a1aab333")
    cli.add_argument("--manifest", type=Path, default=here / "hazards-manifest.json")
    cli.add_argument("--merge", type=Path, default=here / "hazards-merge.json")
    cli.add_argument("--emit-manifest", action="store_true",
                     help="write --manifest from --atr and stop; run once per pinned revision")
    cli.add_argument("--out", type=Path,
                     default=Path(__file__).resolve().parents[1] / "src" / "agent_defs" / "hazards.json")
    args = cli.parse_args()

    import yaml

    measured = json.loads(args.report_data.read_text(encoding="utf-8"))["rule_rows"]
    rules = {}
    for path in sorted((args.atr / "rules").rglob("*")):
        if path.suffix not in (".yml", ".yaml") or not path.is_file():
            continue
        raw = yaml.load(path.read_text(encoding="utf-8"), Loader=getattr(yaml, "CSafeLoader", yaml.SafeLoader))
        rules[raw["id"]] = (condition_patterns(raw), raw["detection"].get("condition"))

    if args.emit_manifest:
        manifest = {
            "policy": "agent-defs.hazards.manifest",
            "version": 1,
            "source_rev": args.source_rev,
            "comment": ("The digest of every regex condition each rule carries at this revision. "
                        "build_hazards.py refuses a rule whose corpus text no longer matches, "
                        "because the report records how many patterns were timed and not which "
                        "ones. Emitted from the checkout rather than recorded by the sweep, so it "
                        "freezes drift from here on rather than proving what the sweep read."),
            "rules": {source_id: [_fingerprint(text) for text in patterns]
                      for source_id, (patterns, _) in sorted(rules.items())},
        }
        args.manifest.write_text(json.dumps(manifest, indent=1, sort_keys=False) + "\n",
                                 encoding="utf-8", newline="\n")
        print(f"wrote {args.manifest} ({len(manifest['rules'])} rules)")
        return 0

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    if manifest.get("source_rev") != args.source_rev:
        raise SystemExit(f"manifest was emitted for {manifest.get('source_rev')}, "
                         f"this build asserts {args.source_rev}")
    expected = manifest["rules"]

    rule_rows, pattern_rows = {}, {}
    slow_sources = {}
    unmeasured = []
    for source_id, (patterns, logic) in sorted(rules.items()):
        row = measured.get(source_id)
        if row is None or not row.get("fully_measured"):
            unmeasured.append(source_id)
            continue
        if row["patterns_total"] != len(set(patterns)):
            raise SystemExit(f"{source_id}: corpus has {len(set(patterns))} distinct patterns, "
                             f"the measurement covered {row['patterns_total']}")
        # The count above says how much was timed, never what. Editing a condition
        # while holding the count produces a rule-level row keyed to a digest of
        # text nobody measured, which reads as a hit rather than a miss and so
        # never falls back to the shape screen. The manifest is what makes the
        # identity checkable at all.
        current = [_fingerprint(text) for text in patterns]
        if expected.get(source_id) != current:
            raise SystemExit(
                f"{source_id}: condition texts differ from the manifest for "
                f"{args.source_rev}. The measurement describes text this corpus no "
                f"longer carries; re-run the sweep, or re-emit the manifest only "
                f"when the corpus and the report were measured together.")
        digest = _fingerprint("\n".join(patterns))
        if row["cross_1s"]:
            crossing, wall = (row["rep1"] or row["rep60"])[:2]
            rule_rows[f"atr:{source_id}"] = [digest, "slow", crossing, round(float(wall), 3),
                                             bool(row["cross_60s"])]
            for key in ("rep1", "rep60"):
                rep = row.get(key)
                if not rep:
                    continue
                length, seconds, pattern_id = rep[0], float(rep[1]), rep[2]
                short = pattern_id[:16]
                prior = pattern_rows.get(short)
                if prior is None or prior[0] != "slow" or length < prior[1]:
                    pattern_rows[short] = ["slow", length, round(seconds, 3), bool(row["cross_60s"])]
                slow_sources.setdefault(short, source_id)
            continue
        rule_rows[f"atr:{source_id}"] = [digest, "fast"]
        ported = []
        for pattern in patterns:
            port, _ = port_utf16_surrogates(pattern)
            ported.append(port)
            # This rule's own conditions were timed and none crossed, and the
            # manifest check above is what makes "these are the texts it timed" a
            # statement rather than an assumption. So they are measured fast.
            #
            # What this loader derives from them was never timed. The surrogate
            # port changes the expression, and the scoped alternation composes
            # several of them, and neither behaves like its input by
            # construction: unit e3 found composition is exactly where a rule
            # that looks fast crosses. An inferred row yields no measurement, so
            # a derived string falls through to the shape screen rather than
            # certifying itself on its origin's timing.
            key = _fingerprint(pattern)
            prior = pattern_rows.get(key)
            if prior is None or prior[0] == "inferred-fast":
                pattern_rows[key] = ["fast"]
            if port != pattern:
                pattern_rows.setdefault(_fingerprint(port), ["inferred-fast"])
        if logic == "any" and len(ported) > 1:
            pattern_rows.setdefault(_fingerprint("|".join(_scoped(p) for p in ported)), ["inferred-fast"])

    contradictions = [key for key, row in pattern_rows.items() if row[0] == "slow" and key in slow_sources
                      and pattern_rows[key][0] != "slow"]
    fast_and_slow = [key for key in slow_sources if pattern_rows.get(key, [""])[0] != "slow"]
    if contradictions or fast_and_slow:
        raise SystemExit(f"a pattern is both fast and slow: {sorted(set(contradictions + fast_and_slow))[:5]}")

    # Measurements the report cannot produce. Slow wins on every collision: each
    # of these rows exists because it corrects a weaker verdict, and letting the
    # rebuild win would restore exactly the verdict the row was written to
    # replace, quietly, on the next regeneration.
    merged = json.loads(args.merge.read_text(encoding="utf-8")) if args.merge.exists() else {"sources": []}
    merge_notes, merge_counts = {}, {}
    for source in merged.get("sources", []):
        added = 0
        for rows, target in ((source.get("rules", {}), rule_rows),
                             (source.get("patterns", {}), pattern_rows)):
            verdict_at = 1 if target is rule_rows else 0
            for key, row in rows.items():
                prior = target.get(key)
                if prior is not None and prior[verdict_at] == "slow" and row[verdict_at] != "slow":
                    raise SystemExit(f"{source['key']}: {key} would downgrade a measured slow row")
                target[key] = row
                added += 1
        merge_notes[source["key"]] = source["note"]
        merge_counts[source["key"]] = added

    table = {
        "policy": "agent-defs.hazards",
        "version": 1,
        "budget_s": BUDGET_S,
        "measurement_id": MEASUREMENT_ID,
        "method": METHOD,
        "measured_at": MEASURED_AT,
        "provenance": {
            "measurement": "research/efficacy-2026-09-05, unit e3",
            "report_data_sha256": hashlib.sha256(args.report_data.read_bytes()).hexdigest(),
            "manifest_sha256": hashlib.sha256(args.manifest.read_bytes()).hexdigest(),
            "corpora": {"atr": args.source_rev},
            **merge_notes,
            "verdicts": {
                "slow": "a witness held one re.search past the budget; the crossing is proof",
                "fast": "no witness crossed at any tested length; evidence, not a proof, and the "
                        "runtime deadline remains the backstop",
            },
        },
        "counts": {
            "rules": len(rule_rows),
            "rules_slow": sum(1 for row in rule_rows.values() if row[1] == "slow"),
            "rules_fast": sum(1 for row in rule_rows.values() if row[1] == "fast"),
            "patterns": len(pattern_rows),
            "patterns_slow": sum(1 for row in pattern_rows.values() if row[0] == "slow"),
            "rules_without_measurement": len(unmeasured),
        },
        "rules": dict(sorted(rule_rows.items())),
        "patterns": dict(sorted(pattern_rows.items())),
    }
    args.out.write_text(json.dumps(table, indent=1, sort_keys=False) + "\n", encoding="utf-8")
    print(json.dumps(table["counts"], indent=2))
    print(f"wrote {args.out} ({args.out.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
