"""Read AAK's JSON registry without inventing predicates from scanner descriptions."""

from __future__ import annotations

from pathlib import Path

from agent_defs.model import Breadth, Lane, Lineage, Rule, Surface
from ._json_corpus import (catalog, document, finish_delta, finish_rule, new_delta,
                           strings, text_field, validate_rev)

SOURCE = "agent_audit_kit"
REPOSITORY = "https://github.com/sattyamjjain/agent-audit-kit"
REVIEWED_REV = "496d4fc84aa8a8a09cc3c314ab5e40cab024fda1"
_REFERENCE_FIELDS = (
    "adversa_references", "aicm_references", "cve_references", "incident_references",
    "owasp_agentic_references", "owasp_ast_references", "owasp_mcp_references",
)
_REFERENCE_ONLY = {
    "AAK-INTERNAL-SCANNER-FAIL", "AAK-OX-COVERAGE-MANIFEST-001",
    "AAK-PRISMA-AIRS-COVERAGE-001", "AAK-MCP-LINEAGE-STAINLESS-001",
}


def classify_surface(row: dict) -> tuple[Surface, str]:
    source_id = row["rule_id"]
    if source_id.startswith("AAK-RUGPULL-"):
        return Surface.PIN, "The rule compares tool definitions against a prior pin."
    if source_id in _REFERENCE_ONLY:
        return Surface.NONE, "Scanner diagnostic or coverage/provenance metadata."
    return Surface.CFG, "AAK inspects repository artifacts at rest, including code and manifests."


def classify_breadth(row: dict) -> tuple[Breadth, str]:
    if row["rule_id"].startswith("AAK-COMPOSE-"):
        return Breadth.BROAD, "Composition family requires graph and suppression context; historical wide predicate was noisy."
    if row.get("cve_references") or row["rule_id"].startswith("AAK-RUGPULL-"):
        return Breadth.NARROW, "A named vulnerability or a change against a specific pin limits the described scope."
    return Breadth.MEDIUM, "Category-level static check; executable selectivity is not present in the JSON registry."


def load(path: str | Path, *, source_rev: str) -> tuple[list[Rule], dict]:
    """Load a repository root or rules.json; return records and a serializable delta."""
    validate_rev(source_rev)
    path = Path(path)
    path = path / "rules.json" if path.is_dir() else path
    metadata, rows = catalog(path, "rule_id")
    delta = new_delta(SOURCE, source_rev)
    document(delta, path, "rules.json", metadata)
    rules = []
    promoted = {"rule_id", "title", "description", "severity", "category", "limitations"}
    for row in rows:
        source_id = row["rule_id"]
        url = f"{REPOSITORY}/blob/{source_rev}/rules.json"
        lineage = [Lineage("taxonomy_mapping", ref, f"{url}#rule_id={source_id}; field={key}")
                   for key in _REFERENCE_FIELDS for ref in strings(row.get(key, []), key)]
        surface, surface_reason = classify_surface(row)
        breadth, breadth_reason = classify_breadth(row)
        extra = {"classification": {"surface_reason": surface_reason, "breadth_reason": breadth_reason}}
        if source_id.startswith("AAK-COMPOSE-"):
            extra["composition_review"] = {
                "status": "VERIFIED" if source_rev == REVIEWED_REV else "UNRESOLVED",
                "reviewed_rev": REVIEWED_REV,
                "evidence_http_status": 200,
                "evidence_checked_at": "2026-09-05",
                "evidence": f"{REPOSITORY}/blob/{REVIEWED_REV}/CHANGELOG.md#L462",
                "implementation": f"{REPOSITORY}/blob/{REVIEWED_REV}/agent_audit_kit/scanners/composition.py",
                "upstream_reported": {"trials": 748, "wide_findings": 253,
                                      "narrow_findings": 2, "after_suppression": 0},
                "condition": "Named untrusted-content source; directed path of 2 or 3 components; sensitive access before egress; no component holds all roles; graph cap 200; suppress if a component already has an equal-or-higher severity finding.",
                "scope": "Historical review of AAK-COMPOSE-001 at reviewed_rev; not our benign measurement or a review of any other revision.",
            }
        reason = "rules.json contains registry metadata only; Python scanner conditions, file scope and suppression are not serialized."
        rule = Rule(
            id=f"{SOURCE}:{source_id}", source=SOURCE, source_id=source_id,
            source_rev=source_rev, source_path="rules.json", upstream_url=url,
            license_spdx="MIT" if source_rev == REVIEWED_REV else "",
            redistribution="unresolved", lineage=tuple(lineage),
            title=text_field(row, "title"), description=text_field(row, "description"),
            severity_raw=text_field(row, "severity"), severity_field="severity",
            tags=(text_field(row, "category"),),
            references=tuple(ref.value for ref in lineage),
            false_positive_notes=(row["limitations"],) if row.get("limitations") else (),
            surface=surface, breadth=breadth, not_runnable_reason=reason,
            lane=Lane.RECORD, lane_reason="No upstream maturity or confidence; no local benign measurement.",
            extra=extra,
        )
        delta["unsupported_constructs"]["scanner_condition_not_in_rules_json"] += 1
        rules.append(finish_rule(rule, row, promoted, delta))
    return rules, finish_delta(delta, rules)
