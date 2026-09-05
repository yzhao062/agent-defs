"""AVE behavioral classes and declared crosswalks, without synthetic signatures."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from agent_defs.model import Breadth, Lane, Lineage, Rule, Surface
from ._json_corpus import (check_ids, document, finish_delta, finish_rule, new_delta,
                           read_object, strings, text_field, validate_rev)

SOURCE = "ave"
REPOSITORY = "https://github.com/aveproject/ave"
REVIEWED_REV = "76f4bac4a89519763486e6cc9c63dca3d5ffdfb5"
_TAXONOMIES = ("owasp_asi", "owasp_mcp", "nist_ai_rmf", "mitre_atlas")
_MAPPING_FIELDS = (
    "ast_id", "maestro_threat", "cfgaudit_rules", "rule_id", "nova_rule",
    "ramparts_finding", "semia_label", "sss_rules", "skillsentry_rules",
    "skillspector_category",
)


def _crosswalks(path: Path, source_rev: str, delta: dict) -> dict:
    by_id = defaultdict(list)
    for file in sorted(path.glob("*.json")):
        data = read_object(file)
        source_path = f"crosswalks/{file.name}"
        # Whole crosswalks retain unmapped classes, caveats, pins and coverage gaps.
        document(delta, file, source_path, data)
        url = f"{REPOSITORY}/blob/{source_rev}/{source_path}"
        mappings = data.get("mappings")
        if not isinstance(mappings, list):
            raise ValueError(f"{file}: mappings must be an array")

        def walk(value, pointer):
            if isinstance(value, dict):
                ids = strings(value.get("ave_ids", []), f"{pointer}/ave_ids")
                for key in ("ave_id", "primary_ave_id"):
                    if value.get(key) is not None:
                        ids += (text_field(value, key),)
                for ave_id in dict.fromkeys(ids):
                    values = []
                    for field in _MAPPING_FIELDS:
                        if field in value:
                            raw = value[field]
                            values.extend(strings(raw, field) if isinstance(raw, list)
                                          else (text_field(value, field),))
                    entry = {"source_path": source_path, "pointer": pointer,
                             "source": data.get("source"), "target": data.get("target"),
                             "note": data.get("note"), "mapping": value,
                             "lineage": tuple(Lineage("crosswalk", v,
                                              f"{url}#{pointer}; class mapping, not content identity")
                                              for v in values)}
                    by_id[ave_id].append(entry)
                    if not values:
                        delta["unsupported_constructs"]["crosswalk_identity_only_in_extra"] += 1
                for key, child in value.items():
                    walk(child, f"{pointer}/{key}")
            elif isinstance(value, list):
                for index, child in enumerate(value):
                    walk(child, f"{pointer}/{index}")

        walk(mappings, "/mappings")
    return by_id


def load(path: str | Path, *, source_rev: str,
         crosswalks_path: str | Path | None = None) -> tuple[list[Rule], dict]:
    """Read a root, records directory, or one record, with optional crosswalks.

    Root/records layouts discover adjacent crosswalks automatically. No network
    fetch or source implementation import occurs while loading.
    """
    validate_rev(source_rev)
    path = Path(path)
    if path.is_dir() and (path / "records").is_dir():
        root, records_dir = path, path / "records"
        files = sorted(records_dir.glob("AVE-*.json"))
    elif path.is_dir():
        root = path.parent if path.name == "records" else path
        files = sorted(path.glob("AVE-*.json"))
    else:
        root = path.parent.parent if path.parent.name == "records" else path.parent
        files = [path]
    if not files:
        raise ValueError(f"{path}: no AVE record files")
    rows = [read_object(file) for file in files]
    check_ids(rows, "ave_id")
    delta = new_delta(SOURCE, source_rev)
    crosswalks = _crosswalks(Path(crosswalks_path) if crosswalks_path is not None
                            else root / "crosswalks", source_rev, delta)
    rules = []
    promoted = {"ave_id", "title", "description", "severity", "behavioral_vector", "example_patterns"}
    for file, row in zip(files, rows):
        source_id = row["ave_id"]
        source_path = f"records/{file.name}"
        url = f"{REPOSITORY}/blob/{source_rev}/{source_path}"
        document(delta, file, source_path, {})
        lineage = [Lineage("taxonomy_mapping", value, f"{url}#/{key}")
                   for key in _TAXONOMIES for value in strings(row.get(key, []), key)]
        entries = crosswalks.get(source_id, [])
        lineage.extend(item for entry in entries for item in entry["lineage"])
        refs = row.get("references", [])
        if not isinstance(refs, list):
            raise ValueError(f"{source_id}: references must be an array")
        references = tuple(text_field(ref, "url") if isinstance(ref, dict) else ref for ref in refs)
        if any(not isinstance(ref, str) for ref in references):
            raise ValueError(f"{source_id}: references must contain strings or URL objects")
        reason = "Behavioral classification and scanner hints only; no matching operator or executable condition. example_patterns are illustrative payloads, not signatures."
        extra = {
            "classification": {"surface_reason": "Reference taxonomy has no executable interception point.",
                               "breadth_reason": "A behavioral class spans multiple concrete implementations and payloads."},
            "crosswalks": [{k: v for k, v in entry.items() if k != "lineage"} for entry in entries],
            "predicate_assessment": {
                "status": "VERIFIED" if source_rev == REVIEWED_REV else "UNRESOLVED",
                "reviewed_rev": REVIEWED_REV,
                "evidence_http_status": 200,
                "evidence_checked_at": "2026-09-05",
                "evidence": f"{REPOSITORY}/blob/{REVIEWED_REV}/schema/ave-record-1.1.0.schema.json#L109",
                "example_role": "Illustrative attack payloads; a skipped reachability check is not a miss.",
            },
        }
        if "confidence_baseline" in row:
            extra["confidence_baseline"] = row["confidence_baseline"]
        rule = Rule(
            id=f"{SOURCE}:{source_id}", source=SOURCE, source_id=source_id,
            source_rev=source_rev, source_path=source_path, upstream_url=url,
            license_spdx="Apache-2.0" if source_rev == REVIEWED_REV else "",
            redistribution="unresolved", lineage=tuple(lineage),
            title=text_field(row, "title"), description=text_field(row, "description"),
            severity_raw=text_field(row, "severity"), severity_field="severity",
            tags=strings(row.get("behavioral_vector", []), "behavioral_vector"),
            references=references, examples_positive=strings(row.get("example_patterns", []), "example_patterns"),
            surface=Surface.NONE, breadth=Breadth.BROAD, not_runnable_reason=reason,
            lane=Lane.RECORD, lane_reason="Reference record; confidence_baseline is an upstream claim, not lane evidence.",
            extra=extra,
        )
        delta["unsupported_constructs"]["behavioral_class_without_predicate"] += 1
        rules.append(finish_rule(rule, row, promoted, delta))
    delta["crosswalk_links"] = sum(len(rule.extra["crosswalks"]) for rule in rules)
    delta["crosswalk_lineage_entries"] = sum(item.kind == "crosswalk" for rule in rules for item in rule.lineage)
    return rules, finish_delta(delta, rules)
