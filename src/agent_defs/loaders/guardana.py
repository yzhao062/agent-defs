"""Guardana's generated registry, with generator and benchmark provenance."""

from __future__ import annotations

from pathlib import Path

from agent_defs.model import Breadth, Lane, Lineage, Rule, Surface
from ._json_corpus import (catalog, document, finish_delta, finish_rule, new_delta,
                           text_field, validate_rev)

SOURCE = "guardana"
REPOSITORY = "https://github.com/guardana/guardana"
REVIEWED_REV = "5d6e4174f69a1a7f945bad189c721e3c601ae4ad"
SOURCE_PATH = "docs/generated/rules.json"
_CATALOG = "packages/guardana-rules/src/guardana/rules/catalog/jailbreak.yaml"
_BENCHMARKS = (
    ("garak", "https://github.com/NVIDIA/garak/blob/2212c73e4886c9c9fe78768e82a543a47284addf/garak/data/inthewild_jailbreak_llms.json",
     "JSON index 642", 16),
    ("HarmBench", "https://github.com/centerforaisafety/HarmBench/blob/8e1604d1171fe8a48d8febecd22f600e462bdcdd/baselines/human_jailbreaks/jailbreaks.py#L77",
     "string constant at line 77", 12),
)


def classify_surface(row: dict) -> tuple[Surface, str]:
    if row.get("target_kind") == "artifact" and row.get("surface") == "build":
        return Surface.CFG, "Build-time inspection of an artifact at rest."
    if row.get("family") == "output":
        return Surface.OUT, "Response-content check; an agent hook cannot necessarily see the endpoint response."
    return Surface.NONE, "Requires a live endpoint probe or a stateful recorded trace, not one hook payload."


def load(path: str | Path, *, source_rev: str) -> tuple[list[Rule], dict]:
    """Load a root or generated rules.json without importing the upstream registry."""
    validate_rev(source_rev)
    path = Path(path)
    path = path / SOURCE_PATH if path.is_dir() else path
    metadata, rows = catalog(path, "id")
    delta = new_delta(SOURCE, source_rev)
    document(delta, path, SOURCE_PATH, metadata)
    generator = {
        "status": "VERIFIED" if source_rev == REVIEWED_REV else "UNRESOLVED",
        "reviewed_rev": REVIEWED_REV,
        "evidence_http_status": 200,
        "evidence_checked_at": "2026-09-05",
        "script": "scripts/generate_docs.py",
        "command": "uv run python scripts/generate_docs.py",
        "check_command": "uv run python scripts/generate_docs.py --check",
        "input": "guardana.rules.provide_rules(): 39 Python rule constructors and 12 catalog YAML files at reviewed_rev; sorted by meta.id; _rule_entry serializes metadata only.",
        "input_paths": ["packages/guardana-rules/src/guardana/rules/__init__.py",
                        "packages/guardana-rules/src/guardana/rules/catalog/*.yaml",
                        "packages/guardana-core/src/guardana/core", "uv.lock"],
        "evidence": f"{REPOSITORY}/blob/{REVIEWED_REV}/scripts/generate_docs.py#L204",
    }
    delta["generator"] = generator
    promoted = {"id", "title", "severity", "maturity", "family"}
    rules = []
    for row in rows:
        source_id = row["id"]
        url = f"{REPOSITORY}/blob/{source_rev}/{SOURCE_PATH}"
        taxonomy = row.get("taxonomy", [])
        if not isinstance(taxonomy, list) or any(not isinstance(t, dict) for t in taxonomy):
            raise ValueError(f"{source_id}: taxonomy must contain objects")
        lineage = [Lineage("taxonomy_mapping", text_field(t, "reference"),
                           f"{url}#id={source_id}; /taxonomy/{i}") for i, t in enumerate(taxonomy)]
        if source_rev == REVIEWED_REV:
            lineage.append(Lineage("generator", "scripts/generate_docs.py", generator["evidence"]))
        elif isinstance(metadata.get("generated_by"), str):
            lineage.append(Lineage("generator_field", metadata["generated_by"], f"{url}#/generated_by"))
        if source_id == "guardana.prompt.jailbreak.dan_style" and source_rev == REVIEWED_REV:
            for name, evidence_url, location, tokens in _BENCHMARKS:
                lineage.append(Lineage(
                    "benchmark", name,
                    f"VERIFIED 2026-09-05: first prompt in {REPOSITORY}/blob/{REVIEWED_REV}/{_CATALOG} "
                    f"shares {tokens} contiguous whitespace-tokenized words with {evidence_url} ({location}); "
                    "partial stock-DAN overlap, not full-payload identity or proof of copying direction. HTTP 200.",
                ))
        surface, surface_reason = classify_surface(row)
        reason = "Generated rules.json serializes metadata only; evaluator IDs do not include expectations, probe inputs, thresholds, state or Python implementations."
        rule = Rule(
            id=f"{SOURCE}:{source_id}", source=SOURCE, source_id=source_id,
            source_rev=source_rev, source_path=SOURCE_PATH, upstream_url=url,
            license_spdx="Apache-2.0" if source_rev == REVIEWED_REV else "",
            redistribution="unresolved", lineage=tuple(lineage),
            title=text_field(row, "title"), severity_raw=text_field(row, "severity"),
            severity_field="severity", maturity_raw=text_field(row, "maturity"),
            tags=(text_field(row, "family"),), references=tuple(text_field(t, "reference") for t in taxonomy),
            surface=surface, breadth=Breadth.MEDIUM, not_runnable_reason=reason,
            lane=Lane.RECORD, lane_reason="Upstream maturity is a claim; no local benign measurement.",
            extra={"generator": generator,
                   "classification": {"surface_reason": surface_reason,
                                      "breadth_reason": "Domain-specific catalog check; executable selectivity is absent from this export."}},
        )
        delta["unsupported_constructs"]["implementation_not_in_generated_json"] += 1
        if row.get("evaluator") is not None:
            delta["unsupported_constructs"]["evaluator_without_expectation"] += 1
        rules.append(finish_rule(rule, row, promoted, delta))
    return rules, finish_delta(delta, rules)
