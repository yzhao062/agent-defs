"""Offline benign-noise measurements and conservative lane admission.

Corpora are directories with a ``corpus.json`` manifest. Each listed UTF-8
file is one complete material unit; its surface is declared, never inferred
from a rule. See docs/bench.md for the manifest and statistical limitations.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Sequence

from .evaluate import compile_rule, scan, scan_trusted
from .lanes import ADVISE_MAX_U95, DENY_MAX_U95, admit, trials_needed, u95_zero_hits
from .model import BenignFiring, Breadth, Lane, Lineage, PredicateKind, Rule, Surface

TRIAL_DEFINITIONS = {
    "CFG": "One complete configuration or repository file at rest.",
    "IN": "One complete tool invocation payload, including its name and arguments.",
    "OUT": "One complete tool result payload from one invocation, with chunks reassembled.",
    "PROMPT": "One complete user message.",
    "PIN": "One complete before/after comparison of a pinned artifact.",
    "NONE": "No interception surface; diagnostic text matching only.",
}
_SECURITY_PATH = re.compile(r"security|threat|attack|inject|secret|vulnerab|pentest|audit|red.team", re.I)


@lru_cache(maxsize=8192, typed=True)
def binomial_u95(trials: int, hits: int) -> float:
    """One-sided exact Clopper-Pearson upper limit, solved numerically.

    For nonzero hits, invert P[Binomial(n, p) <= hits] = .05. Summing
    downwards from hits is stable because the root is above hits / trials.
    """
    if type(trials) is not int or type(hits) is not int or not 0 <= hits <= trials:
        raise ValueError("require integer 0 <= hits <= trials")
    if hits == 0:
        return u95_zero_hits(trials)
    if hits == trials:
        return 1.0
    low, high = hits / trials, 1.0
    coefficient = math.lgamma(trials + 1) - math.lgamma(hits + 1) - math.lgamma(trials - hits + 1)
    for _ in range(64):
        p = (low + high) / 2
        if p == high or p == low:
            break
        term = total = 1.0
        for k in range(hits, 0, -1):
            term *= k / (trials - k + 1) * (1 - p) / p
            total += term
            if term < total * 1e-16:
                break
        log_cdf = coefficient + hits * math.log(p) + (trials - hits) * math.log1p(-p) + math.log(total)
        if log_cdf > math.log(0.05):
            low = p
        else:
            high = p
    return high


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                     separators=(",", ":")).encode("utf-8")).hexdigest()


def rule_fingerprint(rule: Rule) -> str:
    record = asdict(rule)
    for key in ("benign", "lane", "lane_reason"):
        record.pop(key)
    return _digest(record)


def load_rules(path: Path | str) -> list[Rule]:
    """Read a JSON array of normalized records, or an object with ``rules``.

    Stored lanes and measurements are intentionally discarded for remeasurement.
    No Python module or source text is executed to load a bundle.
    """
    data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    records = data["rules"] if isinstance(data, dict) else data
    if not isinstance(records, list):
        raise ValueError("bundle rules must be an array")
    rules = []
    for original in records:
        row = dict(original)
        for key, enum_type in (("surface", Surface), ("breadth", Breadth), ("predicate_kind", PredicateKind)):
            if key in row:
                row[key] = enum_type(row[key])
        row["lineage"] = tuple(Lineage(**entry) for entry in row.get("lineage", ()))
        row.update(benign=None, lane=Lane.RECORD, lane_reason="")
        rules.append(Rule(**row))
    if len({r.id for r in rules}) != len(rules):
        raise ValueError("duplicate rule IDs in bundle")
    return rules


@dataclass(frozen=True)
class Unit:
    id: str
    text: str
    surface: Surface
    strata: dict[str, str]
    sha256: str
    size_bytes: int


@dataclass(frozen=True)
class Corpus:
    identity: str
    revision: str
    units: tuple[Unit, ...]
    manifest_sha256: str
    required_strata: tuple[str, ...]


def _file_type(name: str) -> str:
    path = Path(name)
    if path.name == "SKILL.md":
        return "SKILL.md"
    if path.name.endswith(".agent.md"):
        return ".agent.md"
    if path.name.lower().startswith("readme"):
        return "README"
    return path.suffix.lower() or "no_extension"


def _strata(unit: Unit) -> list[str]:
    return ["all"] + [f"{k}={v}" for k, v in sorted(unit.strata.items())] + [
        f"file_type={unit.strata['file_type']}&prose={unit.strata['prose']}"
    ]


def load_corpus(directory: Path | str) -> Corpus:
    root = Path(directory).resolve()
    manifest = json.loads((root / "corpus.json").read_text(encoding="utf-8-sig"))
    identity, revision = manifest["identity"], manifest["revision"]
    if not identity or not re.fullmatch(r"(?:[0-9a-f]{40}|sha256:[0-9a-f]{64})", revision):
        raise ValueError("corpus needs an identity and pinned full commit SHA or sha256 revision")
    units = []
    seen = set()
    for entry in manifest["units"]:
        name = entry.get("id", entry["path"])
        if name in seen:
            raise ValueError(f"duplicate corpus unit: {name}")
        seen.add(name)
        path = (root / entry["path"]).resolve()
        if not path.is_relative_to(root) or path == root / "corpus.json":
            raise ValueError(f"material path escapes corpus or is its manifest: {name}")
        raw = path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        if entry.get("sha256") != digest:
            raise ValueError(f"material digest mismatch: {name}")
        surface = Surface(entry.get("surface", manifest.get("surface", "CFG")))
        if surface is Surface.NONE:
            raise ValueError("a benign corpus must declare a material surface")
        strata = {"file_type": _file_type(name), "prose": "security-adjacent" if _SECURITY_PATH.search(name) else "ordinary"}
        strata.update(entry.get("strata", {}))
        if any(not isinstance(k, str) or not isinstance(v, str) or not v or any(c in k + v for c in "=&")
               for k, v in strata.items()):
            raise ValueError(f"strata must be nonempty labels without = or &: {name}")
        units.append(Unit(name, raw.decode("utf-8"), surface, strata, digest, len(raw)))
    if not units:
        raise ValueError("empty benign corpus")
    required = tuple(manifest.get("required_strata", ()))
    return Corpus(identity, revision, tuple(units), _digest(manifest), required)


def _prepare(rules: Sequence[Rule]) -> tuple[list[Rule], dict, dict[str, str]]:
    if len({r.id for r in rules}) != len(rules):
        raise ValueError("duplicate rule IDs in bundle")
    runnable, compiled, excluded = [], {}, {}
    for rule in rules:
        if not rule.runnable:
            excluded[rule.id] = rule.not_runnable_reason
            continue
        try:
            if rule.predicate_kind is PredicateKind.REGEX and not isinstance(rule.predicate, str):
                raise ValueError("REGEX predicate must be a string")
            if rule.predicate_kind in (PredicateKind.SUBSTRING_ANY, PredicateKind.SUBSTRING_ALL):
                if not isinstance(rule.predicate, (list, tuple)) or not rule.predicate or any(
                    not isinstance(s, str) or not s for s in rule.predicate
                ):
                    raise ValueError("substring predicate must be a nonempty sequence of nonempty strings")
            if not isinstance(rule.examples_positive, (list, tuple)) or any(not isinstance(s, str) for s in rule.examples_positive):
                raise ValueError("positive examples must be unchanged strings")
            compiled[rule.id] = compile_rule(rule)
        except (ValueError, TypeError, NotImplementedError) as exc:
            excluded[rule.id] = f"{type(exc).__name__}: {exc}"
        else:
            runnable.append(rule)
    return runnable, compiled, excluded


def _hits(text: str, rules: Sequence[Rule], compiled: dict, *, isolated: bool = False,
          budget_s: float = 10.0) -> set[str]:
    # A benchmark must finish every rule and every byte, unlike a hook scan.
    options = {"max_bytes": max(1, len(text.encode("utf-8", "surrogatepass")))}
    if isolated:
        options["budget_s"] = budget_s
    result = (scan if isolated else scan_trusted)(text, rules, **options)
    if not result.complete or result.rules_evaluated != len(rules):
        raise RuntimeError("incomplete benchmark scan; refusing a quiet measurement: "
                           f"evaluated={result.rules_evaluated}/{len(rules)}, "
                           f"skipped={result.rules_skipped_budget}, truncated={result.truncated_input}, "
                           f"errors={result.errors!r}, worker_error={result.worker_error!r}")
    return {f.rule_id for f in result.findings}


def reachability(rules: Sequence[Rule], *, isolated: bool = False, budget_s: float = 10.0) -> dict[str, dict]:
    """Evaluate every rule against each of its own unchanged positive examples.

    Missing examples are unknown, not dead. One positive witness establishes
    reachability; it does not establish attack recall.
    """
    runnable, compiled, excluded = _prepare(rules)
    result = {rid: {"status": "not_runnable", "trials": 0, "hits": 0, "reason": reason}
              for rid, reason in excluded.items()}
    for rule in runnable:
        matches = [i for i, example in enumerate(rule.examples_positive)
                   if _hits(example, [rule], compiled, isolated=isolated, budget_s=budget_s)]
        result[rule.id] = {"status": "reachable" if matches else "unreachable" if rule.examples_positive else "no_examples",
                           "trials": len(rule.examples_positive), "hits": len(matches), "matched_indices": matches}
    return result


def _measurement(corpus: Corpus, surface: str, stratum: str, n: int, k: int, date: str) -> dict:
    return {"corpus": corpus.identity, "corpus_revision": corpus.revision,
            "manifest_sha256": corpus.manifest_sha256, "surface": surface,
            "stratum": stratum, "trials": n, "hits": k,
            "u95": binomial_u95(n, k), "measured_at": date}


def _worst(rows: list[dict]) -> dict:
    return max(rows, key=lambda row: row["u95"])


def admit_from_report(rule: Rule, report: dict) -> tuple[Lane, str]:
    """Apply ``admit`` to native-surface evidence, with reachability/bundle gates.

    Reports describe exactly the fingerprinted bundle. Remeasure after changing
    any enabled rule or corpus selection; this is a local build artifact, not a
    signed attestation for untrusted report producers.
    """
    row = report["rules"][rule.id]
    if row["rule_sha256"] != rule_fingerprint(rule):
        raise ValueError(f"stale report for {rule.id}")
    if row["excluded_reason"]:
        return Lane.DO_NOT_SHIP, f"not runnable in this benchmark: {row['excluded_reason']}"
    positive = row["reachability"]
    if row["diagnostic"]["hits"] == 0 and positive["status"] == "unreachable":
        return Lane.DO_NOT_SHIP, "candidate: no benign hits and no unchanged positive example matched"
    if positive["status"] != "reachable":
        return Lane.RECORD, "no positive reachability witness"
    measurements = [m for m in row["measurements"] if m["surface"] == rule.surface.value]
    if not measurements:
        return admit(replace(rule, benign=None), bundle_ok=False)
    worst = _worst(measurements)
    benign = BenignFiring(worst["trials"], worst["hits"], worst["u95"],
                         f"{worst['corpus']}@{worst['corpus_revision']}:{worst['surface']}:{worst['stratum']}",
                         worst["measured_at"])
    bundle = report["bundle"]
    lane, reason = admit(replace(rule, benign=benign), bundle_ok=bundle["bundle_ok"])
    if not bundle["bundle_ok"]:
        return Lane.RECORD, "bundle gate: " + "; ".join(bundle["failures"])
    if lane is Lane.DENY and bundle["worst_u95"] > DENY_MAX_U95:
        return Lane.ADVISE, "bundle bound only qualifies for ADVISE"
    return lane, f"worst native stratum {worst['stratum']}: {reason}"


def apply_report(rules: Sequence[Rule], report: dict) -> list[Rule]:
    """Return measured rules with assigned lanes, rejecting a changed bundle."""
    expected = {rid: row["rule_sha256"] for rid, row in report["rules"].items()}
    if len({r.id for r in rules}) != len(rules) or {r.id: rule_fingerprint(r) for r in rules} != expected:
        raise ValueError("report does not describe this exact bundle; remeasure it")
    assigned = []
    for rule in rules:
        row = report["rules"][rule.id]
        rows = [m for m in row["measurements"] if m["surface"] == rule.surface.value]
        benign = None
        if rows:
            worst = _worst(rows)
            benign = BenignFiring(worst["trials"], worst["hits"], worst["u95"],
                                 f"{worst['corpus']}@{worst['corpus_revision']}:{worst['surface']}:{worst['stratum']}",
                                 worst["measured_at"])
        lane, reason = admit_from_report(rule, report)
        assigned.append(replace(rule, benign=benign, lane=lane, lane_reason=reason))
    return assigned


def measure(rules: Sequence[Rule], corpora: Sequence[Corpus], *, measured_at: str | None = None,
            isolated: bool = False, workers: int = 1, budget_s: float = 10.0) -> dict:
    if type(workers) is not int or not 1 <= workers <= 4:
        raise ValueError("workers must be between 1 and 4")
    if not corpora:
        raise ValueError("at least one corpus is required")
    if len({(c.identity, c.revision) for c in corpora}) != len(corpora):
        raise ValueError("duplicate corpus identity/revision")
    date = measured_at or datetime.now(timezone.utc).isoformat()
    runnable, compiled, excluded = _prepare(rules)
    positive = reachability(rules, isolated=isolated, budget_s=budget_s)
    report = {"schema_version": 1, "measured_at": date,
              "method": {"bound": "one-sided exact 95% Clopper-Pearson; pointwise per stratum",
                         "trial_definitions": TRIAL_DEFINITIONS,
                         "finding": "at most one hit per rule per material unit; bundle hits are the union",
                         "clean_trials_needed": {"ADVISE": trials_needed(ADVISE_MAX_U95), "DENY": trials_needed(DENY_MAX_U95)},
                         "strata_classifier": "path-keywords-v1; manifest overrides; file type, prose, and their intersection",
                         "execution": {"isolated": isolated, "workers": workers,
                                       "budget_s": budget_s if isolated else None},
                         "limitations": ["Surface and provenance are supplied by the corpus manifest.",
                                         "Binomial limits assume independent representative trials; one repository does not establish this.",
                                         "Pointwise 95% bounds are not a simultaneous 95% guarantee across all strata or rules.",
                                         "Positive examples establish reachability, not recall or production safety."]},
              "rules": {}, "corpora": [], "bundle": {"measurements": [], "diagnostic_measurements": []}}
    for rule in rules:
        report["rules"][rule.id] = {"rule_sha256": rule_fingerprint(rule), "source_rev": rule.source_rev,
                                     "surface": rule.surface.value, "excluded_reason": excluded.get(rule.id),
                                     "reachability": positive[rule.id], "measurements": [],
                                     "diagnostic": {"trials": 0, "hits": 0}}
    all_findings = Counter()
    material_rows = []
    observed_surfaces = set()
    coverage_failures = []
    enabled_surfaces = {r.surface.value for r in runnable}
    total_bytes = 0
    for corpus in corpora:
        counts = Counter()
        rule_hits = {r.id: Counter() for r in runnable}
        bundle_hits = Counter()
        diagnostic_bundle_hits = Counter()
        seen_content = set()
        duplicates = 0
        def evaluate_unit(unit):
            try:
                return _hits(unit.text, runnable, compiled, isolated=isolated, budget_s=budget_s)
            except RuntimeError as exc:
                raise RuntimeError(f"{corpus.identity}:{unit.id}: {exc}") from exc

        # Keep only a bounded batch of scans/results in memory. External traffic
        # uses scan's killable subprocess even when several units run concurrently.
        def evaluated_units():
            with ThreadPoolExecutor(max_workers=workers) as pool:
                for start in range(0, len(corpus.units), workers):
                    batch = corpus.units[start:start + workers]
                    yield from zip(batch, pool.map(evaluate_unit, batch))

        for unit, hits in evaluated_units():
            surface = unit.surface.value
            observed_surfaces.add(surface)
            content_key = (surface, unit.sha256)
            duplicates += content_key in seen_content
            seen_content.add(content_key)
            total_bytes += unit.size_bytes
            native_hits = {r.id for r in runnable if r.surface is unit.surface and r.id in hits}
            all_findings.update(hits)
            material_rows.append({"corpus": corpus.identity, "id": unit.id, "surface": surface,
                                  "sha256": unit.sha256, "bytes": unit.size_bytes, "strata": unit.strata,
                                  "findings": len(hits), "rule_ids": sorted(hits)})
            for stratum in _strata(unit):
                key = (surface, stratum)
                counts[key] += 1
                bundle_hits[key] += bool(native_hits)
                diagnostic_bundle_hits[key] += bool(hits)
                for rid in hits:
                    rule_hits[rid][key] += 1
        missing_strata = []
        for surface in {u.surface.value for u in corpus.units}:
            required = set(corpus.required_strata) | {"prose=ordinary", "prose=security-adjacent"}
            missing_strata.extend(f"{surface}:{s}" for s in sorted(required) if not counts[(surface, s)])
        if missing_strata:
            coverage_failures.append(f"{corpus.identity} missing strata: {', '.join(missing_strata)}")
        if duplicates:
            coverage_failures.append(f"{corpus.identity} has {duplicates} duplicate material units; independence requires review")
        report["corpora"].append({"identity": corpus.identity, "revision": corpus.revision,
                                  "manifest_sha256": corpus.manifest_sha256, "trials": len(corpus.units),
                                  "bytes": sum(u.size_bytes for u in corpus.units), "duplicate_units": duplicates,
                                  "missing_strata": missing_strata,
                                  "strata": [{"surface": s, "stratum": t, "trials": n}
                                             for (s, t), n in sorted(counts.items()) if n]})
        for (surface, stratum), n in sorted(counts.items()):
            if not n:
                continue
            if surface in enabled_surfaces:
                report["bundle"]["measurements"].append(_measurement(corpus, surface, stratum, n, bundle_hits[(surface, stratum)], date))
            report["bundle"]["diagnostic_measurements"].append(
                _measurement(corpus, surface, stratum, n, diagnostic_bundle_hits[(surface, stratum)], date))
            for rule in runnable:
                row = _measurement(corpus, surface, stratum, n, rule_hits[rule.id][(surface, stratum)], date)
                row["admission_eligible_surface"] = surface == rule.surface.value
                report["rules"][rule.id]["measurements"].append(row)
    missing = sorted(enabled_surfaces - observed_surfaces)
    bundle_rows = report["bundle"]["measurements"]
    worst = _worst(bundle_rows)["u95"] if bundle_rows else 1.0
    failures = coverage_failures + ([f"unmeasured enabled surfaces: {', '.join(missing)}"] if missing else [])
    if not runnable:
        failures.append("no runnable rules")
    if worst > ADVISE_MAX_U95:
        failures.append(f"worst bundle stratum u95={worst:.6f} exceeds {ADVISE_MAX_U95}")
    report["bundle"].update(bundle_ok=not failures, worst_u95=worst, failures=failures,
                            rule_sha256={r.id: rule_fingerprint(r) for r in runnable})
    n = len(material_rows)
    touched = sum(bool(m["findings"]) for m in material_rows)
    report["bundle"]["diagnostic"] = {"trials": n, "hits": touched, "u95": binomial_u95(n, touched),
                                        "note": "pooled union of all rule hits; cross-surface diagnostic only"}
    loud = sorted(rid for rid, k in all_findings.items() if k / n > 0.05)
    over_one = sorted(rid for rid, k in all_findings.items() if k / n > 0.01)
    findings = sum(all_findings.values())
    removed = sum(all_findings[rid] for rid in loud)
    quiet = [r.id for r in runnable if all_findings[r.id] == 0]
    report["summary"] = {"rules_loaded": len(rules), "rules_run": len(runnable), "rules_excluded": len(excluded),
                         "trials": n, "bytes": total_bytes, "findings": findings, "findings_per_unit": findings / n,
                         "units_touched": touched,
                         "quiet_rules": len(quiet), "quiet_reachable": sum(positive[r]["status"] == "reachable" for r in quiet),
                         "quiet_unreachable": sum(positive[r]["status"] == "unreachable" for r in quiet),
                         "quiet_no_examples": sum(positive[r]["status"] == "no_examples" for r in quiet),
                         "rules_over_one_percent": over_one,
                         "over_one_percent_share": sum(all_findings[r] for r in over_one) / findings if findings else 0,
                         "rules_over_five_percent": loud, "over_five_percent_share": removed / findings if findings else 0,
                         "top_rule_share": max(all_findings.values(), default=0) / findings if findings else 0,
                         "findings_without_loud_rules": findings - removed,
                         "findings_per_unit_without_loud_rules": (findings - removed) / n}
    report["surface_coverage"] = {s.value: {"measured": s.value in observed_surfaces,
                                           "trial_definition": TRIAL_DEFINITIONS[s.value]}
                                  for s in Surface if s is not Surface.NONE}
    report["unmeasured_surfaces"] = sorted(s for s, c in report["surface_coverage"].items() if not c["measured"])
    report["materials"] = material_rows
    for rule in rules:
        row = report["rules"][rule.id]
        if rule.id not in excluded:
            row["diagnostic"] = {"trials": n, "hits": all_findings[rule.id], "u95": binomial_u95(n, all_findings[rule.id]),
                                 "note": "pooled cross-surface prevalence; not admission evidence"}
        lane, reason = admit_from_report(rule, report)
        row.update(lane=lane.value, lane_reason=reason)
    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    noise = sub.add_parser("measure", help="measure a bundle on pinned benign corpora")
    noise.add_argument("--corpus", action="append", required=True, type=Path)
    noise.add_argument("--rules", required=True, type=Path)
    noise.add_argument("--out", required=True, type=Path)
    noise.add_argument("--isolated", action="store_true", help="required for external/untrusted traffic")
    noise.add_argument("--workers", type=int, default=1)
    noise.add_argument("--budget-s", type=float, default=10.0)
    positive = sub.add_parser("reachability", help="run unchanged upstream positive examples")
    positive.add_argument("--rules", required=True, type=Path)
    positive.add_argument("--out", required=True, type=Path)
    positive.add_argument("--isolated", action="store_true")
    args = parser.parse_args(argv)
    try:
        rules = load_rules(args.rules)
        if args.command == "measure":
            report = measure(rules, [load_corpus(p) for p in args.corpus], isolated=args.isolated,
                             workers=args.workers, budget_s=args.budget_s)
        else:
            report = {"schema_version": 1, "measured_at": datetime.now(timezone.utc).isoformat(),
                      "rules": reachability(rules, isolated=args.isolated)}
        args.out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(2, f"bench: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
