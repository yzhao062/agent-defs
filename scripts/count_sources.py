"""Count native records directly in a pinned archive, without executing it.

Usage: python scripts/count_sources.py atr /path/to/atr.tar.gz
YAML sources require the existing atr/sigma extra (PyYAML); JSON uses stdlib.
Malformed records fail the count. No expected population is used as a filter.
"""

import argparse
from collections import Counter
import json
from pathlib import Path
import tarfile


def count_source(name, archive_path):
    yaml_roots = {"atr": "rules/", "netzilo": "ai_agent/", "agentshield": "rules/rules/"}
    ids, paths = [], []
    with tarfile.open(archive_path, "r:gz") as archive:
        members = {m.name.partition("/")[2]: m for m in archive if m.isfile()}
        if name in yaml_roots:
            import yaml

            for path, member in sorted(members.items()):
                if path.startswith(yaml_roots[name]) and path.endswith((".yml", ".yaml")):
                    paths.append(path)
                    for record in yaml.safe_load_all(archive.extractfile(member)):
                        if not isinstance(record, dict) or "detection" not in record:
                            raise ValueError(f"{path}: expected a rule mapping with detection")
                        ids.append(record["id"])
        elif name == "ave":
            for path, member in sorted(members.items()):
                if path.startswith("records/") and path.endswith(".json"):
                    paths.append(path)
                    ids.append(json.load(archive.extractfile(member))["ave_id"])
        else:
            path = {"agent_audit_kit": "rules.json", "guardana": "docs/generated/rules.json"}[name]
            paths.append(path)
            records = json.load(archive.extractfile(members[path]))["rules"]
            if not isinstance(records, list):
                raise ValueError(f"{path}: rules must be an array")
            key = "rule_id" if name == "agent_audit_kit" else "id"
            ids.extend(record[key] for record in records)
    if not ids or any(not isinstance(value, str) or not value for value in ids):
        raise ValueError(f"{name}: no records or invalid record identifiers")
    counts = Counter(ids)
    return {"name": name, "record_count": len(ids), "unique_ids": len(counts),
            "record_files": len(paths),
            "duplicate_ids": {key: count for key, count in counts.items() if count > 1}}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("name", choices=["atr", "netzilo", "agentshield", "agent_audit_kit", "ave", "guardana"])
    parser.add_argument("archive", type=Path)
    args = parser.parse_args()
    print(json.dumps(count_source(args.name, args.archive), indent=2))
