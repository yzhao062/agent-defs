"""Acceptance gate: reproduce the four figures ATR publishes in LIMITATIONS.md.

Owner decision 8 makes this comparison the acceptance test for the package
rather than a one-time audit, so it has to be runnable on demand. Round three's
E4 unit did it once by hand, recovered the historical revision behind each
figure, and scored at most one agreement of four. Everything that unit had to
rediscover is pinned here.

Each figure is bound to the exact revision and rule count it was measured at.
A figure the gate cannot reach is reported as unreachable and fails the run; it
is never scored against today's rules, because a comparison between upstream's
2026-03 number and this quarter's bundle measures nothing.

    PYTHONPATH=src python scripts/calibration_gate.py figures
    PYTHONPATH=src python scripts/calibration_gate.py prepare --workdir W
    PYTHONPATH=src python scripts/calibration_gate.py run --workdir W --out report.json

``prepare`` needs network once (it fetches upstream history) and Node with tsx
for the self-test corpus, which lives in TypeScript source. ``run`` is offline
Python. The skill benchmark carries malicious samples, so prepare and run belong
on a Linux host, never on the Windows workstation.

Exit codes: 0 the gate passed, 1 measured disagreement, 2 usage, 3 at least one
figure could not be reached.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import io
import json
from pathlib import Path
import shutil
import os
import platform
import subprocess
import sys
import tarfile

from agent_defs.evaluate import scan_trusted
from agent_defs.loaders import atr

UPSTREAM_URL = "https://github.com/Agent-Threat-Rule/agent-threat-rules"

# The revision this package currently pins. No historical figure may be scored
# against it; that substitution is the failure mode this gate exists to refuse.
PIN_REVISION = "faf743fee8a5018467959ec8ea7ccdb1a1aab333"

# Preregistered in prereg-2026-09-05.md, section E4, before any number existed.
TOLERANCE_POINTS = 5.0
SEVERE_GAP_POINTS = 10.0
MIN_AGREEING_FIGURES = 3

_ARCHIVE_PATHS = ("rules", "src", "package.json", "LICENSE", "data/pint-benchmark", "data/skill-benchmark")

# JavaScript String.prototype.trim removes WhiteSpace plus LineTerminator. The
# set is spelled out by code point because Python's str.strip() covers a
# different one -- it takes U+0085 and skips U+00A0 and U+FEFF -- and the PINT
# loader below has to agree with upstream's TypeScript character for character
# or its sample count silently drifts.
_JS_WHITESPACE = "".join(chr(c) for c in (
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20, 0xA0, 0x1680,
    *range(0x2000, 0x200B), 0x2028, 0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF,
))


class Unreachable(Exception):
    """A figure's revision, rule set or corpus is missing or does not match its pin."""


@dataclass(frozen=True)
class Claim:
    """One published number, in percentage points, and what is known about it.

    ``published`` is always the comparison target: the gate reproduces what
    upstream printed. ``reproducible`` carries a restatement when E4 could not
    certify the literal from upstream's own stored artifact; its gap is reported
    beside the published one and never replaces it.
    """

    metric: str
    published: float
    quote: str
    upstream_reference: str
    published_is_floor: bool = False
    certification: str = "corroborated"
    reproducible: float | None = None
    reproducible_statement: str = ""
    uncertifiable_reason: str = ""


#: src tree id per rules tree, filled in as figures are added. A missing entry
#: means the substitution has not been checked on the src half and prepare says so.
_SRC_TREE: dict[str, str] = {
    "31ee4e1a95934dff87dc5cbb7e3ec9c55feb3f14": "5f61fb884c248d53e61de53dbd4e4183968471e5",
}


@dataclass(frozen=True)
class Figure:
    key: str
    title: str
    executed_revision: str
    measured_at_revision: str
    substitution_note: str
    rules_tree: str
    #: The src tree id. The self-test corpus is produced by src/eval/corpus.ts,
    #: so a revision substitution has to hold on this half too, not only on rules.
    src_tree: str
    rules_digest: str
    rule_count: int
    corpus: str
    samples: int
    attacks: int
    benign: int
    corpus_digest: str
    corpus_source: str
    named_rule: str | None
    claims: tuple[Claim, ...]
    prepare_notes: tuple[str, ...] = ()

    @property
    def short(self) -> str:
        return self.executed_revision[:7]


SELF_TEST = Figure(
    key="self_test",
    title="ATR self-test corpus, 341 samples",
    executed_revision="c815748ad12ec406dbf6739e85ee52e1a5bcaa5a",
    measured_at_revision="74278ec44e6117bee17979a4f0cd75ffc8a2a25e",
    substitution_note=(
        "LIMITATIONS.md dates the measurement to 74278ec4. That revision and c815748a share "
        "both the rules tree 31ee4e1a and the src tree 5f61fb88, so executing c815748a executes "
        "the same rules and the same eval harness. prepare verifies both tree ids rather than "
        "asserting the substitution."),
    rules_tree="31ee4e1a95934dff87dc5cbb7e3ec9c55feb3f14",
    src_tree=_SRC_TREE.get("31ee4e1a95934dff87dc5cbb7e3ec9c55feb3f14", ""),
    rules_digest="0b9833775d9458ebe892261ec7a6b9e26c261677d62cf1ac3c9ea41ef3d0146d",
    rule_count=652,
    corpus="self",
    samples=341,
    attacks=321,
    benign=20,
    corpus_digest="ded70c2a1ab043574c49e62d3f35cb24d1c740b81b32f3c181f8941783486205",
    corpus_source="src/eval/corpus.ts, exported by scripts/calibration_export.mts",
    named_rule=None,
    claims=(
        Claim(
            metric="recall",
            published=89.7,
            quote="ATR's self-test corpus produces an 89.7% recall rate.",
            upstream_reference=(
                "E4 ran the unmodified c815748a TypeScript engine over the same 341 samples and "
                "got 287/321 = 89.41%. The 0.31-point residual is the published report's "
                "tier2.5-embedding detector, which catches tp-009 and which the regex-only path "
                "does not run."),
        ),
    ),
    prepare_notes=(
        "The self-test corpus is TypeScript source, so this figure needs Node with tsx once, "
        "at prepare time. Without it the figure is unreachable and the gate says so.",
    ),
)

EXTERNAL_PINT = Figure(
    key="external_pint",
    title="PINT-format public reconstruction, 850 samples",
    executed_revision="c815748ad12ec406dbf6739e85ee52e1a5bcaa5a",
    measured_at_revision="c815748ad12ec406dbf6739e85ee52e1a5bcaa5a",
    substitution_note="Same v3.5.0 revision as the self-test figure; no substitution.",
    rules_tree="31ee4e1a95934dff87dc5cbb7e3ec9c55feb3f14",
    src_tree=_SRC_TREE.get("31ee4e1a95934dff87dc5cbb7e3ec9c55feb3f14", ""),
    rules_digest="0b9833775d9458ebe892261ec7a6b9e26c261677d62cf1ac3c9ea41ef3d0146d",
    rule_count=652,
    corpus="pint",
    samples=850,
    attacks=451,
    benign=399,
    corpus_digest="cd12c5ed05c08166dad8fd3caba1ed55c7c513dd623af4ea83a53ebc0d2b6e68",
    corpus_source="data/pint-benchmark/pint-corpus.json, sha256 7883cf72, through loadPintCorpus",
    named_rule=None,
    claims=(
        Claim(
            metric="recall",
            published=63.6,
            quote="| Recall | 63.6% |",
            upstream_reference=(
                "E4 ran the unmodified c815748a engine and got 287/451 = 63.64%, reproducing the "
                "published figure exactly."),
        ),
        Claim(
            metric="precision",
            published=99.7,
            quote="| Precision | 99.7% |",
            upstream_reference="Same run; upstream fires on 1 of 399 benign samples.",
        ),
    ),
    prepare_notes=(
        "Recall counts the 451 attacks, not all 850 entries. Lakera's official private PINT "
        "corpus, roughly 4,314 samples, is not public and is not what this figure measures.",
    ),
)

SKILL_MD = Figure(
    key="skill_md",
    title="SKILL.md benchmark, 498 files, 108 rules",
    executed_revision="a8a4146bc3983db4678cd0df0b9a3dcf86888f95",
    measured_at_revision="a8a4146bc3983db4678cd0df0b9a3dcf86888f95",
    substitution_note="LIMITATIONS.md calls this v1.0; a8a4146 is package version 1.1.1 with 108 rules.",
    rules_tree="9591a68e4ed7a9bd9c37c8e3070d84be6bd9fa06",
    src_tree=_SRC_TREE.get("9591a68e4ed7a9bd9c37c8e3070d84be6bd9fa06", ""),
    rules_digest="15e9d108178cc07469bec87b737d050f4e2dd2f99e05b6cb3ac10f019965c39d",
    rule_count=108,
    corpus="skill",
    samples=498,
    attacks=32,
    benign=466,
    corpus_digest="8fdbe74095b65f8a66301147748e406d6b4c5c77f8ec2559711ae15aa8448c05",
    corpus_source="data/skill-benchmark/manifest.json, sha256 f369f066, and its 498 files",
    named_rule=None,
    claims=(
        Claim(
            metric="recall",
            published=96.9,
            quote=("The SKILL.md benchmark (v1.0, 108 rules) shows much broader rule activation: "
                   "96.9% recall across 498 real-world samples with 0% false positives."),
            upstream_reference=(
                "E4 ran the historical scanSkill() over all 108 rules and got 31/32 = 96.875%."),
        ),
        Claim(
            metric="false_positive_rate",
            published=0.0,
            quote=("... 96.9% recall across 498 real-world samples with 0% false positives."),
            upstream_reference=(
                "Same run: 0 of 466 benign files fire. scanSkill() carries a 22-rule denylist and "
                "skips 85 MCP-only rules; the union excludes 88 rules before anything matches."),
        ),
    ),
    prepare_notes=(
        "The 498 denominator is 32 attacks plus 466 benign files, and 14 of the attacks are "
        "labelled adversarial-handcrafted. It is not 498 independent real-world attacks.",
        "LIMITATIONS.md carries a second SKILL.md line, '100% recall, 97% precision, 0.20% FP', in "
        "its 3.5.0 header stats. That is a different version and a different run. This figure is "
        "the v1.0, 108-rule statement, which is the one with a recoverable revision behind it.",
        "The malicious half of this corpus must stay off the Windows workstation.",
    ),
)

CONCENTRATION = Figure(
    key="concentration",
    title="MCP/PINT rule concentration, v0.4, 71 rules",
    executed_revision="1002d9d0f0e3dc88a33b0be09510e9b9fee3604c",
    measured_at_revision="1002d9d0f0e3dc88a33b0be09510e9b9fee3604c",
    substitution_note=(
        "1002d9d is package version 0.4.0 with exactly 71 rules, matching the published "
        "'v0.4, 71 rules at the time'. The stored report that the claim appears to summarize "
        "lives at 36fe782 and describes a 61-rule run; see the claim notes."),
    rules_tree="77223b15d5f40fa93c5530af21fb1c576f6ff519",
    src_tree=_SRC_TREE.get("77223b15d5f40fa93c5530af21fb1c576f6ff519", ""),
    rules_digest="3999a03073831475c8a6c35a35b44d95a12d18ceda5eb2fcc7428517b83e64a6",
    rule_count=71,
    corpus="pint",
    samples=850,
    attacks=451,
    benign=399,
    corpus_digest="cd12c5ed05c08166dad8fd3caba1ed55c7c513dd623af4ea83a53ebc0d2b6e68",
    corpus_source="data/pint-benchmark/pint-corpus.json, sha256 7883cf72, through loadPintCorpus",
    named_rule="ATR-2026-001",
    claims=(
        Claim(
            metric="active_rule_fraction",
            published=6 / 71 * 100,
            quote=("On the MCP/PINT benchmark (v0.4, 71 rules at the time), only 6 rules fired "
                   "on external data."),
            upstream_reference=(
                "E4 ran the reconstructed 71-rule v0.4 engine on the same 850 samples: "
                "ATR-2026-001 277 attack and 1 benign match, ATR-2026-051 2, ATR-2026-003 2, "
                "ATR-2026-072 1, ATR-2026-004 1, and zero for the other 66."),
            certification="uncertifiable",
            reproducible=5 / 71 * 100,
            reproducible_statement="five regex rules fire, 5 of 71",
            uncertifiable_reason=(
                "The literal 'six of 71' cannot be certified from upstream's stored artifact. At "
                "v0.4, data/pint-benchmark/pint-eval-report.json still records a 61-rule run dated "
                "2026-03-26. Its six firing entries are the five ATR regex rules above plus "
                "tier2.5-embedding-match, a synthetic detector with 29 matches. Six firing entries "
                "plus 56 never-fired rules totals 62 against a 61-rule base, because the synthetic "
                "detector enters the firing count. A firing-entry count is therefore not a count "
                "of ATR rules."),
        ),
        Claim(
            metric="dominant_rule_share",
            published=95.0,
            quote=("ATR-2026-001 (prompt override detection) accounted for over 95% of all "
                   "detections."),
            upstream_reference=(
                "Same run: ATR-2026-001 carries 278 of 284 regex rule-sample matches. It covers "
                "all 277 detected attacks and the single false positive; the other four firing "
                "rules add no uniquely detected sample."),
            published_is_floor=True,
            certification="uncertifiable",
            reproducible=97.89,
            reproducible_statement="one rule carries 278/284 = 97.89% of regex rule-sample matches",
            uncertifiable_reason=(
                "'Over 95% of all detections' is valid for sample coverage and for regex rule "
                "matches, and invalid for all matches in the stored hybrid report, where the same "
                "numerator over 313 matches is 88.82%. The documentation mixes a stale rule-count "
                "denominator, a synthetic detector, and an unspecified detection denominator."),
        ),
    ),
    prepare_notes=(
        "Our number for dominant_rule_share is the named rule's own share. E4 refused to "
        "substitute our different top rule for it, and so does this gate: a bundle that drops "
        "ATR-2026-001 scores zero on this claim, and the report says why.",
    ),
)

FIGURES: tuple[Figure, ...] = (SELF_TEST, EXTERNAL_PINT, SKILL_MD, CONCENTRATION)

# What E4 measured on 2026-09-05, kept so a later run has something to move
# against. These are our numbers, not upstream's, and they are expected to
# change: the two fix tracks exist to change them.
RECORDED_BASELINE = {
    "measured_at": "2026-09-05",
    "unit": "research/efficacy-2026-09-05/e4-result.md",
    "verdict": "at most one agreement of four, granting the SKILL.md recall alone",
    "figures": {
        "self_test": {"recall": 70.40, "loaded": 652, "runnable": 481, "excluded": 171},
        "external_pint": {"recall": 25.06, "precision": 100.0, "loaded": 652, "runnable": 481, "excluded": 171},
        "skill_md": {"recall": 96.875, "false_positive_rate": 95.49, "loaded": 108, "runnable": 69, "excluded": 39},
        "concentration": {"rules_fired": 10, "dominant_rule_share": 0.0, "loaded": 71, "runnable": 39,
                          "excluded": 32,
                          "note": "ATR-2026-001 is refused on the 4,096-character composition limit; "
                                  "our largest retained rule carried 59/219 = 26.94%, reported as a "
                                  "diagnostic and never as the compared value"},
    },
    "located_causes": [
        "The loader refuses ATR-2026-001 on a 4,096-character composition limit, and that rule "
        "carries 97.89% of matches on the PINT corpus.",
        "We do not implement scanSkill()'s 22-rule denylist or its 85-rule MCP-only skip, which "
        "together account for 397 of our 445 false positives on the skill benchmark.",
        "ATR-2026-00129 expresses Unicode tags as UTF-16 surrogate pairs. JavaScript matches them; "
        "Python sees supplementary code points and returns nothing.",
    ],
}


# --------------------------------------------------------------------------
# Corpora
# --------------------------------------------------------------------------


def _js_trim(text: str) -> str:
    return text.strip(_JS_WHITESPACE)


def load_pint(root: Path) -> list[dict]:
    """Port of upstream's loadPintCorpus, character for character.

    Trim, drop empties, deduplicate on the lowercased first 200 characters, and
    number ids from the raw index rather than the retained count. Verified equal
    to the TypeScript export by corpus digest on the pinned corpus.
    """
    path = root / "data/pint-benchmark/pint-corpus.json"
    if not path.is_file():
        raise Unreachable(f"missing PINT corpus at {path}")
    raw = json.loads(path.read_text(encoding="utf-8"))
    seen: set[str] = set()
    samples = []
    for index, entry in enumerate(raw):
        text = _js_trim(entry["text"])
        key = text.lower()[:200]
        if not text or key in seen:
            continue
        seen.add(key)
        samples.append({"id": "pint-%04d" % (index + 1), "text": text,
                        "expectedDetection": entry["label"] is True,
                        "event_type": "llm_input", "scan_target": None,
                        "fields": {"source": entry.get("source"), "language": entry.get("language")}})
    return samples


def load_skill(root: Path) -> list[dict]:
    manifest_path = root / "data/skill-benchmark/manifest.json"
    if not manifest_path.is_file():
        raise Unreachable(f"missing skill manifest at {manifest_path}")
    entries = json.loads(manifest_path.read_text(encoding="utf-8"))
    samples = []
    for entry in entries:
        path = root / "data/skill-benchmark" / entry["file"]
        if not path.is_file():
            raise Unreachable(f"skill manifest names a missing file: {entry['file']}")
        samples.append({"id": entry["file"], "text": path.read_text(encoding="utf-8"),
                        "expectedDetection": entry["label"] == "malicious",
                        "event_type": None, "scan_target": "skill",
                        "fields": {"layer": entry.get("layer"), "attack_type": entry.get("attack_type")}})
    return samples


def load_self(root: Path) -> list[dict]:
    path = root / "calibration-corpus-self.json"
    if not path.is_file():
        raise Unreachable(
            "self-test corpus export is missing. It lives in TypeScript source; rerun prepare on a "
            f"host with Node and tsx so it writes {path.name}")
    return [{"id": s["id"], "text": s["text"], "expectedDetection": bool(s["expectedDetection"]),
             "event_type": s.get("eventType"), "scan_target": None, "fields": s.get("fields") or {}}
            for s in json.loads(path.read_text(encoding="utf-8"))]


_CORPUS_LOADERS = {"pint": load_pint, "skill": load_skill, "self": load_self}


def corpus_digest(samples) -> str:
    """Order-independent digest over id, text and label only.

    Deliberately blind to key order and to fields the gate does not score, so a
    re-export through a different JSON writer still matches its pin.
    """
    lines = sorted(
        hashlib.sha256(("%s\x00%s\x00%d" % (s["id"], s["text"], int(bool(s["expectedDetection"]))))
                       .encode("utf-8", "surrogatepass")).hexdigest()
        for s in samples)
    digest = hashlib.sha256()
    for line in lines:
        digest.update(line.encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def rules_digest(root: Path) -> tuple[str, int]:
    files = sorted((p.relative_to(root).as_posix(), p) for p in (root / "rules").rglob("*")
                   if p.is_file() and p.suffix in {".yaml", ".yml"})
    digest = hashlib.sha256()
    for relative, path in files:
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).hexdigest().encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest(), len(files)


# --------------------------------------------------------------------------
# Verification
# --------------------------------------------------------------------------


def snapshot_root(workdir: Path, figure: Figure) -> Path:
    return Path(workdir) / ("atr-" + figure.short)


def verify_snapshot(root: Path, figure: Figure) -> None:
    """Refuse anything that is not the pinned tree, loudly and by name."""
    if not root.is_dir():
        raise Unreachable(f"no snapshot at {root}; run prepare")
    marker = root / "SOURCE_REV"
    if not marker.is_file():
        raise Unreachable(f"{root} has no SOURCE_REV; it was not written by prepare")
    revision = marker.read_text(encoding="utf-8").strip()
    if revision == PIN_REVISION:
        raise Unreachable(
            f"{figure.key} is pinned to {figure.executed_revision[:8]} and the snapshot holds today's "
            f"tree {PIN_REVISION[:8]}. Scoring a 2026 figure against the current bundle would compare "
            "two different rule sets and report the difference as agreement")
    if revision != figure.executed_revision:
        raise Unreachable(f"{figure.key} expects {figure.executed_revision}, snapshot holds {revision}")
    if not (root / "rules").is_dir():
        raise Unreachable(f"{root} has no rules directory")
    digest, count = rules_digest(root)
    if count != figure.rule_count:
        raise Unreachable(f"{figure.key} is pinned at {figure.rule_count} rules; snapshot holds {count}")
    if digest != figure.rules_digest:
        raise Unreachable(f"{figure.key} rule content digest is {digest}, pinned {figure.rules_digest}")


def verify_corpus(samples, figure: Figure) -> None:
    attacks = sum(bool(s["expectedDetection"]) for s in samples)
    actual = (len(samples), attacks, len(samples) - attacks)
    expected = (figure.samples, figure.attacks, figure.benign)
    if actual != expected:
        raise Unreachable(
            f"{figure.key} corpus is pinned at {expected} samples/attacks/benign and holds {actual}")
    digest = corpus_digest(samples)
    if digest != figure.corpus_digest:
        raise Unreachable(f"{figure.key} corpus digest is {digest}, pinned {figure.corpus_digest}")


# --------------------------------------------------------------------------
# Measurement
# --------------------------------------------------------------------------


def our_findings(text: str, rules, context: dict) -> set[str]:
    """One sample through the product, returning normalized rule ids.

    This is the seam the semantics work lands on. Today the product accepts a
    payload and nothing else, so ``context`` -- the sample's event type, its scan
    target and its named fields -- is recorded in the report and not passed on.
    When a rule carries its execution binding and the scan honours it, wire the
    context in here; the pins above do not move.
    """
    result = scan_trusted(text, rules, max_bytes=max(1, len(text.encode("utf-8", "surrogatepass"))))
    result.require_complete()
    return {finding.rule_id for finding in result.findings}


def measure(samples, rules, figure: Figure) -> dict:
    source_id = {rule.id: rule.source_id for rule in rules}
    counts = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    matches: dict[str, int] = {}
    for sample in samples:
        hits = our_findings(sample["text"], rules,
                            {"event_type": sample["event_type"], "scan_target": sample["scan_target"],
                             "fields": sample["fields"]})
        attack = bool(sample["expectedDetection"])
        counts[("tp" if hits else "fn") if attack else ("fp" if hits else "tn")] += 1
        for rule_id in hits:
            key = source_id.get(rule_id, rule_id)
            matches[key] = matches.get(key, 0) + 1
    total = sum(matches.values())
    detected = counts["tp"] + counts["fp"]
    ranked = sorted(matches.items(), key=lambda item: (-item[1], item[0]))
    named = matches.get(figure.named_rule, 0) if figure.named_rule else None
    return {
        **counts,
        "recall": 100.0 * counts["tp"] / (counts["tp"] + counts["fn"]) if counts["tp"] + counts["fn"] else None,
        "precision": 100.0 * counts["tp"] / detected if detected else None,
        "false_positive_rate": 100.0 * counts["fp"] / (counts["fp"] + counts["tn"]) if counts["fp"] + counts["tn"] else None,
        "rules_fired": len(matches),
        "active_rule_fraction": 100.0 * len(matches) / figure.rule_count,
        "total_rule_matches": total,
        "dominant_rule_share": (100.0 * named / total if total else 0.0) if figure.named_rule else None,
        "named_rule": figure.named_rule,
        "named_rule_matches": named,
        "top_rules": [{"rule": name, "matches": n} for name, n in ranked[:10]],
        "observed_top_rule_share": 100.0 * ranked[0][1] / total if total else 0.0,
    }


def _claim_row(claim: Claim, ours: float | None, rule_count: int) -> dict:
    row = {
        "metric": claim.metric,
        "ours": ours,
        "upstream_published": claim.published,
        "gap_points": None if ours is None else ours - claim.published,
        "rule_count": rule_count,
        "published_quote": claim.quote,
        "published_is_floor": claim.published_is_floor,
        "certification": claim.certification,
        "upstream_reference": claim.upstream_reference,
    }
    if claim.reproducible is not None:
        row["upstream_reproducible"] = claim.reproducible
        row["gap_points_vs_reproducible"] = None if ours is None else ours - claim.reproducible
        row["reproducible_statement"] = claim.reproducible_statement
        row["uncertifiable_reason"] = claim.uncertifiable_reason
    if ours is None:
        row.update(within_tolerance=False, severe=True,
                   note="the harness produced no value for this metric")
        return row
    gap = abs(row["gap_points"])
    row.update(within_tolerance=gap <= TOLERANCE_POINTS, severe=gap > SEVERE_GAP_POINTS)
    return row


def evaluate_figure(workdir: Path, figure: Figure) -> dict:
    report = {
        "figure": figure.key,
        "title": figure.title,
        "executed_revision": figure.executed_revision,
        "measured_at_revision": figure.measured_at_revision,
        "substitution_note": figure.substitution_note,
        "rule_count": figure.rule_count,
        "corpus": figure.corpus,
        "corpus_source": figure.corpus_source,
        "corpus_samples": figure.samples,
        "notes": list(figure.prepare_notes),
    }
    root = snapshot_root(workdir, figure)
    try:
        verify_snapshot(root, figure)
        samples = _CORPUS_LOADERS[figure.corpus](root)
        verify_corpus(samples, figure)
        loaded = atr.load(root, source_rev=figure.executed_revision)
        rules = [rule for rule in loaded.rules if rule.runnable]
        measured = measure(samples, rules, figure)
    except (Unreachable, OSError, ValueError, KeyError, ImportError, RuntimeError) as exc:
        report.update(status="unreachable", agrees=False, claims_within_tolerance=0,
                      unreachable_reason=f"{type(exc).__name__}: {exc}",
                      claims=[_claim_row(claim, None, figure.rule_count) for claim in figure.claims])
        return report
    excluded = [rule for rule in loaded.rules if not rule.runnable]
    reasons: dict[str, int] = {}
    for rule in excluded:
        reasons[rule.not_runnable_reason] = reasons.get(rule.not_runnable_reason, 0) + 1
    report["loader"] = {
        "loaded": len(loaded.rules), "runnable": len(rules), "excluded": len(excluded),
        "entry_errors": len(loaded.delta.entry_errors),
        "top_exclusion_reasons": sorted(reasons.items(), key=lambda item: (-item[1], item[0]))[:5],
    }
    if figure.named_rule:
        by_source = {rule.source_id: rule for rule in loaded.rules}
        rule = by_source.get(figure.named_rule)
        report["named_rule"] = {
            "id": figure.named_rule,
            "present": rule is not None,
            "runnable": bool(rule and rule.runnable),
            "reason": "" if rule is None or rule.runnable else rule.not_runnable_reason,
        }
    report["measurement"] = measured
    claims = [_claim_row(claim, measured.get(claim.metric), figure.rule_count) for claim in figure.claims]
    report.update(status="measured", claims=claims,
                  agrees=all(row["within_tolerance"] for row in claims),
                  claims_within_tolerance=sum(row["within_tolerance"] for row in claims))
    return report


METHOD = {
    "our_number": (
        "Each sample's text through agent_defs.loaders.atr.load at the figure's pinned revision "
        "and agent_defs.evaluate.scan_trusted, one scan per sample over every runnable rule. This "
        "is the raw-text product path: the sample's event type, scan target and named fields are "
        "recorded and not used, because the product does not yet accept them."),
    "seam": (
        "calibration_gate.our_findings is the one call site. When a rule carries its execution "
        "binding and the scan honours it, wire the context in there; none of the pins move."),
    "counting": (
        "A sample counts once, detected or not. A rule counts once per sample it matches, so "
        "rule-sample matches exceed detected samples. active_rule_fraction divides distinct firing "
        "rules by the figure's pinned rule count, and dominant_rule_share is the named upstream "
        "rule's own share of rule-sample matches, never our own top rule's."),
    "excluded_rules": (
        "Rules the loader refuses are absent from the scan, not scored as negatives. Their count "
        "and reasons are in each figure's loader block."),
}


def run(workdir: Path) -> dict:
    workdir = Path(workdir)
    figures = [evaluate_figure(workdir, figure) for figure in FIGURES]
    unreachable = [f["figure"] for f in figures if f["status"] == "unreachable"]
    agreeing = [f["figure"] for f in figures if f["agrees"]]
    lenient = [f["figure"] for f in figures
               if f["status"] == "measured" and f.get("claims_within_tolerance", 0)]
    severe = [(f["figure"], row["metric"], row["gap_points"])
              for f in figures for row in f["claims"] if row.get("severe") and row.get("gap_points") is not None]
    passed = not unreachable and len(agreeing) >= MIN_AGREEING_FIGURES
    prepared = workdir / "calibration-prepare.json"
    return {
        "schema_version": 1,
        "gate": "ATR published-figure calibration",
        "authority": "prereg-2026-09-05.md section E4; agent-risk-flow-plan.md owner decision 8",
        "criteria": {"tolerance_points": TOLERANCE_POINTS, "severe_gap_points": SEVERE_GAP_POINTS,
                     "min_agreeing_figures": MIN_AGREEING_FIGURES, "figures": len(FIGURES),
                     "agreement": "a figure agrees only when every published claim attached to it "
                                  "is within tolerance"},
        "method": METHOD,
        "workdir": str(workdir),
        "prepared": json.loads(prepared.read_text(encoding="utf-8")) if prepared.is_file() else None,
        "status": "PASS" if passed else "FAIL",
        "agreeing_figures": agreeing,
        "agreements": len(agreeing),
        "figures_with_any_claim_in_tolerance": lenient,
        "unreachable_figures": unreachable,
        "severe_gaps": [{"figure": key, "metric": metric, "gap_points": gap} for key, metric, gap in severe],
        "pin_revision_refused_for_historical_figures": PIN_REVISION,
        "recorded_baseline": RECORDED_BASELINE,
        "figure_reports": figures,
    }


# --------------------------------------------------------------------------
# prepare
# --------------------------------------------------------------------------


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True,
                          text=True, encoding="utf-8").stdout.strip()


def prepare(workdir: Path, history: Path | None = None, *, url: str = UPSTREAM_URL,
            allow_network: bool = True, export: bool = True, tsx: str | None = None) -> dict:
    """Reconstruct the pinned snapshots and export the corpus that needs Node.

    The history clone is unshallow and blobless. Every pinned revision is checked
    to be an ancestor of the revision this package pins, and every figure's rules
    tree is checked against its pinned tree id, which is how the self-test
    figure's substitution of c815748a for 74278ec4 is verified rather than
    asserted.
    """
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    repo = Path(history) if history else workdir / "atr-history"
    if not (repo / "HEAD").is_file() and not (repo / ".git").exists():
        if not allow_network:
            raise Unreachable(f"no upstream history at {repo} and network is disabled")
        subprocess.run(["git", "clone", "--filter=blob:none", "--no-checkout", url, str(repo)], check=True)
    revisions = sorted({figure.executed_revision for figure in FIGURES})
    for revision in revisions:
        _git(repo, "merge-base", "--is-ancestor", revision, PIN_REVISION)
    for figure in FIGURES:
        for revision in sorted({figure.executed_revision, figure.measured_at_revision}):
            seen = _git(repo, "rev-parse", f"{revision}:rules")
            if seen != figure.rules_tree:
                raise Unreachable(
                    f"{figure.key}: rules tree at {revision[:8]} is {seen}, pinned {figure.rules_tree}. "
                    "The revision behind this figure is not the one it was measured at")
            if figure.src_tree:
                seen_src = _git(repo, "rev-parse", f"{revision}:src")
                if seen_src != figure.src_tree:
                    raise Unreachable(
                        f"{figure.key}: src tree at {revision[:8]} is {seen_src}, pinned "
                        f"{figure.src_tree}. The eval harness behind this figure is not the one it "
                        "was measured with")
    # Every revision this extracts carries data/skill-benchmark/malicious. On the
    # Windows development host an antivirus has twice quarantined those files mid-write
    # and silently degraded a corpus that had already been measured. A docstring is not
    # an enforcement point, so refuse here and make the override explicit.
    if (platform.system() == "Windows"
            and os.environ.get("AGENT_DEFS_ALLOW_MALICIOUS_EXTRACT") != "1"):
        raise RuntimeError(
            "prepare extracts data/skill-benchmark/malicious and refuses to run on Windows. "
            "Run it on a Linux host, or set AGENT_DEFS_ALLOW_MALICIOUS_EXTRACT=1 if this host "
            "has no real-time scanner."
        )
    steps = []
    for revision in revisions:
        root = workdir / ("atr-" + revision[:7])
        root.mkdir(exist_ok=True)
        listed = set(_git(repo, "ls-tree", "-r", "--name-only", revision).splitlines())
        wanted = [p for p in _ARCHIVE_PATHS if p in listed or any(f.startswith(p + "/") for f in listed)]
        blob = subprocess.run(["git", "-C", str(repo), "archive", revision, *wanted],
                              check=True, capture_output=True).stdout
        with tarfile.open(fileobj=io.BytesIO(blob)) as archive:
            archive.extractall(root, filter="data")
        (root / "SOURCE_REV").write_text(revision + "\n", encoding="utf-8")
        digest, count = rules_digest(root)
        steps.append({"revision": revision, "root": str(root), "paths": wanted,
                      "archive_sha256": hashlib.sha256(blob).hexdigest(),
                      "rules": count, "rules_digest": digest})
    exported = {}
    script = Path(__file__).resolve().parent / "calibration_export.mts"
    runner = tsx or shutil.which("tsx")
    for figure in FIGURES:
        if figure.corpus != "self":
            continue
        if not export:
            exported[figure.key] = "skipped by request"
        elif runner is None:
            exported[figure.key] = ("no tsx found; pass --tsx or put it on PATH. The self-test corpus "
                                    "is TypeScript source, so its figure will report unreachable")
        else:
            completed = subprocess.run([runner, str(script), str(snapshot_root(workdir, figure))],
                                       capture_output=True, text=True, encoding="utf-8")
            exported[figure.key] = completed.stdout.strip() or completed.stderr.strip()[-500:]
    report = {"workdir": str(workdir), "history": str(repo), "snapshots": steps, "exports": exported}
    (workdir / "calibration-prepare.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------


def render(report: dict) -> str:
    lines = [f"ATR published-figure calibration: {report['status']}",
             f"  agreements {report['agreements']} of {report['criteria']['figures']}, "
             f"need {report['criteria']['min_agreeing_figures']} within "
             f"{report['criteria']['tolerance_points']} points"]
    if report["unreachable_figures"]:
        lines.append(f"  unreachable: {', '.join(report['unreachable_figures'])}")
    header = f"  {'figure':<14} {'rules':>6} {'metric':<22} {'ours':>9} {'upstream':>9} {'gap':>9}  verdict"
    lines += ["", header, "  " + "-" * (len(header) - 2)]
    for figure in report["figure_reports"]:
        for row in figure["claims"]:
            ours = "n/a" if row["ours"] is None else f"{row['ours']:.2f}"
            gap = "n/a" if row["gap_points"] is None else f"{row['gap_points']:+.2f}"
            if figure["status"] == "unreachable":
                verdict = "UNREACHABLE"
            elif row["severe"]:
                verdict = "fails, over 10 points"
            elif not row["within_tolerance"]:
                verdict = "fails"
            else:
                verdict = "agrees"
            lines.append(f"  {figure['figure']:<14} {row['rule_count']:>6} {row['metric']:<22} "
                         f"{ours:>9} {row['upstream_published']:>9.2f} {gap:>9}  {verdict}")
        if figure["status"] == "unreachable":
            lines.append(f"      reason: {figure['unreachable_reason']}")
        elif figure.get("named_rule") and not figure["named_rule"]["runnable"]:
            lines.append(f"      {figure['named_rule']['id']} is not runnable in our bundle: "
                         f"{figure['named_rule']['reason'] or 'absent'}")
    uncertifiable = [(f["figure"], row) for f in report["figure_reports"] for row in f["claims"]
                     if row.get("certification") == "uncertifiable"]
    if uncertifiable:
        lines += ["", "  Upstream claims this gate restates rather than takes literally:"]
        for key, row in uncertifiable:
            lines.append(f"    {key}.{row['metric']}: reproducible form is "
                         f"{row.get('reproducible_statement', '')}")
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("figures", help="print the pinned figure table and exit")
    build = sub.add_parser("prepare", help="reconstruct pinned snapshots and export corpora")
    build.add_argument("--workdir", required=True, type=Path)
    build.add_argument("--history", type=Path, help="existing upstream clone; otherwise cloned into workdir")
    build.add_argument("--url", default=UPSTREAM_URL)
    build.add_argument("--no-network", action="store_true")
    build.add_argument("--no-export", action="store_true", help="skip the Node corpus export")
    build.add_argument("--tsx", help="path to the tsx binary, when it is not on PATH")
    score = sub.add_parser("run", help="measure the four figures and compare")
    score.add_argument("--workdir", required=True, type=Path)
    score.add_argument("--out", type=Path)
    score.add_argument("--json", action="store_true", help="print the report instead of the table")
    args = parser.parse_args(argv)
    if args.command == "figures":
        print(json.dumps([{
            "figure": f.key, "title": f.title, "executed_revision": f.executed_revision,
            "measured_at_revision": f.measured_at_revision, "rule_count": f.rule_count,
            "corpus": f.corpus, "samples": f.samples, "attacks": f.attacks, "benign": f.benign,
            "claims": [{"metric": c.metric, "published": c.published, "certification": c.certification,
                        "reproducible": c.reproducible, "quote": c.quote} for c in f.claims],
        } for f in FIGURES], indent=2))
        return 0
    if args.command == "prepare":
        try:
            report = prepare(args.workdir, args.history, url=args.url,
                             allow_network=not args.no_network, export=not args.no_export,
                             tsx=args.tsx)
        except (Unreachable, subprocess.CalledProcessError, OSError) as exc:
            print(f"calibration-gate prepare: {exc}", file=sys.stderr)
            return 3
        print(json.dumps(report, indent=2))
        return 0
    report = run(args.workdir)
    if args.out:
        args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2) if args.json else render(report))
    if report["unreachable_figures"]:
        return 3
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
