"""Fetch pinned data outside the checkout for the b7 reproduction check.

Requires the existing ``atr`` extra (PyYAML). This is deliberately a small
single-condition extraction, not a production ATR loader. No payload is
installed as an agent instruction file, or executed.
"""

import argparse
import hashlib
import io
import json
import urllib.request
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

import yaml

BENIGN_REV = "7b1ebe6333397841ca918dec904d24d4695fe953"
ATR_REV = "faf743fee8a5018467959ec8ea7ccdb1a1aab333"


def fetch(repo, revision, output, ledger):
    url = f"https://codeload.github.com/{repo}/zip/{revision}"
    with urllib.request.urlopen(url, timeout=60) as response:
        raw = response.read()
        ledger.append({"url": url, "http_status": response.status,
                       "observed_at": datetime.now(timezone.utc).isoformat(),
                       "sha256": hashlib.sha256(raw).hexdigest()})
    (output / (repo.split("/")[-1] + ".zip")).write_bytes(raw)
    return zipfile.ZipFile(io.BytesIO(raw))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    output = args.out.resolve()
    checkout = Path(__file__).resolve().parents[1]
    if output.is_relative_to(checkout):
        parser.error("external corpus data must stay outside the checkout")
    output.mkdir(parents=True, exist_ok=True)
    ledger = []
    benign = fetch("github/awesome-copilot", BENIGN_REV, output, ledger)
    corpus = output / "corpus"
    (corpus / "material").mkdir(parents=True, exist_ok=True)
    manifest = {"identity": "github/awesome-copilot", "revision": BENIGN_REV, "surface": "CFG", "units": []}
    for name in sorted(benign.namelist()):
        path = PurePosixPath(name)
        relative = PurePosixPath(*path.parts[1:])
        if name.endswith("/"):
            continue
        selected = (path.name == "SKILL.md" or path.name.endswith(".agent.md") or path.name.lower().startswith("readme")
                    or str(relative) == "mcp.json"
                    or (str(relative).startswith("eng/") and path.suffix in {".ts", ".js", ".mjs", ".cjs", ".py", ".sh", ".ps1"}
                        and ".test." not in str(relative) and str(relative) != "eng/pr-risk-scan.mjs"))
        if selected:
            raw = benign.read(name)
            dest = f"material/{len(manifest['units']):04d}.txt"
            (corpus / dest).write_bytes(raw)
            manifest["units"].append({"id": str(relative), "path": dest, "sha256": hashlib.sha256(raw).hexdigest()})
    (corpus / "corpus.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    atr = fetch("Agent-Threat-Rule/agent-threat-rules", ATR_REV, output, ledger)
    rules, skips = [], Counter()
    parsed = 0
    fields = {"content": "OUT", "user_input": "PROMPT", "tool_description": "CFG"}
    for name in sorted(atr.namelist()):
        path = PurePosixPath(name)
        if path.parts[1:2] != ("rules",) or not path.name.startswith("ATR-") or path.suffix != ".yaml":
            continue
        row = yaml.safe_load(atr.read(name))
        parsed += 1
        detection = row["detection"]
        conditions = detection["conditions"]
        if row.get("tags", {}).get("suppress_in_code_blocks"):
            skips["code-span suppression not supported by evaluator"] += 1
            continue
        if len(conditions) != 1:
            skips["multiple conditions: outside this extraction"] += 1
            continue
        if row.get("confirm") or row.get("detection_tier", "pattern") not in ("pattern", "regex"):
            skips["confirmation or non-pattern detection tier"] += 1
            continue
        if set(detection) - {"conditions", "condition", "false_positives", "method"} or detection.get("method", "pattern") != "pattern":
            skips["additional detection method or gate"] += 1
            continue
        condition = conditions[0]
        if detection.get("condition") not in ("any", "all") or condition["operator"] != "regex" or condition["field"] not in fields:
            skips["unsupported operator, field, or condition"] += 1
            continue
        if set(condition) - {"field", "operator", "value", "description"}:
            skips["extra condition gate"] += 1
            continue
        tests = row.get("test_cases", {})
        examples = [case["input"] for case in tests.get("true_positives", [])]
        negatives = [case["input"] for case in tests.get("true_negatives", [])]
        if any(not isinstance(s, str) for s in examples + negatives):
            skips["non-text examples"] += 1
            continue
        relative = str(PurePosixPath(*path.parts[1:]))
        rules.append({"id": "atr:" + row["id"], "source": "atr", "source_id": row["id"], "source_rev": ATR_REV,
                      "source_path": relative, "upstream_url": f"https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/{ATR_REV}/{relative}",
                      "title": row["title"], "severity_raw": row["severity"], "severity_field": "severity",
                      "surface": fields[condition["field"]], "predicate_kind": "REGEX", "predicate": condition["value"],
                      "case_sensitive": False, "examples_positive": examples, "examples_negative": negatives,
                      "extra": {"extraction": "b7 single-condition text projection; no production loader parity claimed",
                                "surface_mapping": "content=OUT, user_input=PROMPT, tool_description=CFG",
                                "detection_raw": detection}})
    (output / "rules.json").write_text(json.dumps({"rules": rules}, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    evidence = {"sources": ledger, "atr_records_parsed": parsed, "rules_extracted": len(rules), "skips": dict(skips),
                "corpus_files": len(manifest["units"]), "corpus_bytes": sum((corpus / u["path"]).stat().st_size for u in manifest["units"])}
    (output / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(evidence, indent=2))


if __name__ == "__main__":
    main()
