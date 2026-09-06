"""Short Round 2 review probes; no malicious corpus extraction or long regex runs."""
import base64
import contextlib
import dataclasses
import io
import json
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import types
from unittest.mock import patch

from agent_defs import cfg, evaluate
from agent_defs.loaders import atr
from agent_defs.loaders.atr_skill_gates import read_skill_gates

ROOT = Path(__file__).resolve().parent
SKILL = ROOT / "tests/fixtures/atr_skill"
PIN = "faf743fee8a5018467959ec8ea7ccdb1a1aab333"
out = {}


def staged_module(name, path, package):
    module = types.ModuleType(name)
    module.__package__ = package
    sys.modules[name] = module
    source = subprocess.check_output(["git", "show", ":" + path], cwd=ROOT, timeout=5)
    exec(compile(source, path, "exec"), module.__dict__)
    return module


staged_cfg = staged_module("agent_defs.review_staged_cfg", "src/agent_defs/cfg.py", "agent_defs")
staged_atr = staged_module("agent_defs.loaders.review_staged_atr", "src/agent_defs/loaders/atr.py", "agent_defs.loaders")
for name, module in (("working", cfg), ("staged", staged_cfg)):
    result = module.scan_cfg("plain", [])
    try:
        result.require_complete()
    except evaluate.IncompleteScanError as exc:
        out[name + "_empty_exception"] = {"complete": exc.result.complete, "errors": len(exc.result.errors)}

loaded = atr.load(ROOT / "tests/fixtures/atr")
gates = read_skill_gates(SKILL, source_rev=PIN)
carrier = next(r for r in loaded.rules if r.source_id == "ATR-2026-00129")
tags = "".join(chr(0xE0000 + c) for c in (1, 0x48, 0x49))
for name, module in (("working", atr), ("staged", staged_atr)):
    binding = module._cfg_binding(carrier.extra["upstream"], gates)
    result = cfg.scan_cfg("skill body " + tags + " tail", [dataclasses.replace(carrier, bindings=(binding,))])
    out[name + "_tag_payload"] = {"conditions": len(binding.conditions), "findings": list(result.rule_ids)}

for rule in loaded.rules:
    for cond in rule.extra["upstream"]["detection"].get("conditions", []):
        if not isinstance(cond, dict) or not isinstance(cond.get("value"), str):
            continue
        pattern = cond["value"]
        m = evaluate.measurement_for_pattern(pattern)
        if m is None or not m.slow:
            continue
        try:
            evaluate.screen_pattern(pattern + "(?:)")
        except evaluate.UnsafePattern:
            continue
        out["semantics_preserving_edit"] = {"rule": rule.id, "before": m.verdict,
            "after_measurement": evaluate.measurement_for_pattern(pattern + "(?:)"), "after_screen": "admitted"}
        break
    if "semantics_preserving_edit" in out:
        break

builder = runpy.run_path(str(ROOT / "scripts/build_hazards.py"))
import yaml
with tempfile.TemporaryDirectory(prefix="agent-defs-review-") as tmp:
    root = Path(tmp)
    (root / "rules").mkdir()
    pattern = r"^(ab+)+z$"
    raw = {"id": "ATR-2026-99998", "detection": {"method": "pattern", "condition": "any",
        "conditions": [{"operator": "regex", "field": "user_input", "value": pattern}]}}
    (root / "rules/a.yaml").write_text(yaml.safe_dump(raw), encoding="utf-8")
    rows = {raw["id"]: {"fully_measured": True, "patterns_total": 1, "cross_1s": False}}
    (root / "report.json").write_text(json.dumps({"rule_rows": rows}), encoding="utf-8")
    original_argv = sys.argv
    sys.argv = ["build_hazards.py", "--report-data", str(root / "report.json"),
                "--atr", str(root), "--out", str(root / "hazards.json")]
    with contextlib.redirect_stdout(io.StringIO()):
        builder["main"]()
    generated = json.loads((root / "hazards.json").read_text())
    cache = evaluate._HAZARD_CACHE
    evaluate._HAZARD_CACHE = generated
    try:
        try:
            evaluate.screen_pattern(pattern)
            direct = "admitted"
        except evaluate.UnsafePattern as exc:
            direct = str(exc)
        kind, pred, reasons, decisions = atr._predicate(raw, "atr:" + raw["id"], atr.Delta())
        out["inferred_row"] = {"row": generated["patterns"][evaluate._fingerprint(pattern)],
            "direct_lookup": evaluate.measurement_for_pattern(pattern), "direct_screen": direct,
            "loader_kind": kind.value, "loader_reasons": reasons,
            "input_report_has_pattern_identity": False}
    finally:
        evaluate._HAZARD_CACHE = cache
    raw2 = {**raw, "id": "ATR-2026-99999"}
    (root / "rules/b.yaml").write_text(yaml.safe_dump(raw2), encoding="utf-8")
    rows[raw2["id"]] = {"fully_measured": True, "patterns_total": 1, "cross_1s": True,
        "cross_60s": False, "rep1": [1024, 1.2, evaluate._fingerprint(pattern)]}
    (root / "report.json").write_text(json.dumps({"rule_rows": rows}), encoding="utf-8")
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            builder["main"]()
    except Exception as exc:
        out["builder_shared_fast_slow"] = type(exc).__name__ + ": " + str(exc)
    sys.argv = original_argv

engine = (SKILL / "src/engine.ts").read_text(encoding="utf-8")
start = engine.index("export function decodeBase64Blocks")
end = engine.index("\n}", start) + 2
decoder = engine[start:end].replace("export function", "function")
for annotation in (": RegExpExecArray | null", ": string[]", ": string"):
    decoder = decoder.replace(annotation, "")
node = "const BASE64_BLOCK_RE = /(?:[A-Za-z0-9+/]{32,}={0,2})/g; const MAX_DECODE_BLOCKS = 5;\n" + decoder
node += "\nconst inputs=JSON.parse(require('fs').readFileSync(0,'utf8')); process.stdout.write(JSON.stringify(inputs.map(s=>{BASE64_BLOCK_RE.lastIndex=0;return decodeBase64Blocks(s)})));"
payloads = []
for ascii_count in (0, 7, 8, 10, 20, 21, 22, 28, 31, 32, 70, 71):
    for nonascii in (b"", "\U0001f600".encode(), "\U0001f600".encode() * 5,
                     "\u00e9".encode() * 8, b"\xff\xc0\xaf", b"\xf0\x9f\x98"):
        payloads.append(b"a" * ascii_count + nonascii)
inputs = [base64.b64encode(p).decode() for p in payloads]
inputs += [s.rstrip("=") + "A" * k for s in inputs[-12:] for k in range(4)]
inputs += ["\n".join(inputs[-8:])]
small_count = len(inputs)
inputs += [base64.b64encode(b"A" * 79999 + "\U0001f600".encode() * 10000 + b"needle").decode()]
completed = subprocess.run([r"C:\Program Files\nodejs\node.exe", "-e", node],
    input=json.dumps(inputs), capture_output=True, text=True, check=True, timeout=10)
node_outputs = json.loads(completed.stdout)
python_outputs = [cfg._decoded_blocks(s) for s in inputs]
out["node_differential"] = {"cases": len(inputs), "small_cases": small_count,
    "small_mismatches": [i for i in range(small_count) if python_outputs[i] != node_outputs[i]],
    "python_dropped_node_kept": [i for i in range(len(inputs)) if node_outputs[i] and not python_outputs[i]],
    "long_case_lengths": {"python_codepoints": len(python_outputs[-1][0]),
                          "node_codepoints": len(node_outputs[-1][0])}}

skill_loaded = atr.load(SKILL)
index_rule = next(r for r in skill_loaded.rules if r.source_id == "ATR-2026-00120")
payload = index_rule.examples_positive[2]
binding = index_rule.binding("CFG")
out["edited_index_test"] = {"matching_conditions": [i for i, p in enumerate(binding.conditions)
    if cfg.re.search(p, payload, cfg.re.IGNORECASE)],
    "reported": cfg.scan_cfg(payload, [index_rule]).findings[0].condition_index}
astral_document = "a " * 40000 + "\U0001f600" * 11000
limit_rule = dataclasses.replace(index_rule, bindings=(dataclasses.replace(binding, conditions=("needle",)),))
astral_result = cfg.scan_cfg(astral_document, [limit_rule], decode_base64=False, suppress_code_blocks=False)
out["source_utf16_limit"] = {"codepoints": len(astral_document),
    "utf16_units": len(astral_document.encode("utf-16-le")) // 2,
    "over_source_eval_limit": astral_result.over_source_eval_limit, "complete": astral_result.complete}

table = evaluate.hazard_table()
known = next(c["value"] for r in loaded.rules for c in r.extra["upstream"]["detection"].get("conditions", [])
             if isinstance(c, dict) and isinstance(c.get("value"), str)
             and evaluate.measurement_for_pattern(c["value"]) is not None
             and evaluate.measurement_for_pattern(c["value"]).slow)
try:
    evaluate.screen_pattern(known, measurement=evaluate.Measurement("fast", 1.0))
    out["fast_override_exact_slow"] = "admitted"
except evaluate.UnsafePattern as exc:
    out["fast_override_exact_slow"] = str(exc)

if "--corpus" in sys.argv:
    corpus = atr.load(Path("C:/atrx/Agent-Threat-Rule-agent-threat-rules-faf743f"), source_rev=PIN)
    raw_patterns = {c["value"] for r in corpus.rules
        for c in (r.extra["upstream"]["detection"].get("conditions") or [])
        if isinstance(c, dict) and isinstance(c.get("value"), str) and c.get("operator") == "regex"}
    predicates = {p for r in corpus.rules if r.runnable for p in
        ([r.predicate] if isinstance(r.predicate, str) else list(r.predicate.values())[0])}
    cfg_patterns = {p for r, b in cfg.cfg_bindings(corpus.rules) for p in b.conditions}
    over60 = []
    slow_cfg = []
    for r, b in cfg.cfg_bindings(corpus.rules):
        patterns = [c["value"] for c in r.extra["upstream"]["detection"]["conditions"]
                    if isinstance(c, dict) and c.get("operator") == "regex" and isinstance(c.get("value"), str)]
        measurement = evaluate.measurement_for_rule("atr", r.source_id, patterns)
        if measurement and measurement.slow:
            slow_cfg.append(r.id)
        if measurement and measurement.over_60s:
            over60.append(r.id)
    out["corpus_coverage"] = {"rules": len(corpus.rules), "runnable": sum(r.runnable for r in corpus.rules),
        "raw_patterns": len(raw_patterns), "raw_without_measurement": sum(evaluate.measurement_for_pattern(p) is None for p in raw_patterns),
        "runnable_predicate_objects": len({json.dumps(r.predicate, sort_keys=True) for r in corpus.rules if r.runnable}),
        "runnable_patterns": len(predicates), "runnable_without_measurement": sum(evaluate.measurement_for_pattern(p) is None for p in predicates),
        "cfg_rules": len(cfg.cfg_bindings(corpus.rules)), "cfg_patterns": len(cfg_patterns),
        "cfg_without_measurement": sum(evaluate.measurement_for_pattern(p) is None for p in cfg_patterns),
        "cfg_exact_slow_patterns": sum(bool(evaluate.measurement_for_pattern(p) and evaluate.measurement_for_pattern(p).slow) for p in cfg_patterns),
        "cfg_rule_slow": len(slow_cfg), "cfg_rule_over60": len(over60)}

sys.path.insert(0, str(ROOT / "scripts"))
import calibration_gate as gate
out["calibration_src_pins"] = {f.key: {"checked": bool(f.src_tree),
    "substitution": f.executed_revision != f.measured_at_revision} for f in gate.FIGURES}
with tempfile.TemporaryDirectory(prefix="agent-defs-guard-") as tmp:
    root = Path(tmp)
    (root / "history/.git").mkdir(parents=True)
    calls = []
    figure = gate.FIGURES[0]

    def fake_git(repo, *args):
        calls.append(args[0])
        if args[0] == "rev-parse":
            return figure.src_tree if args[-1].endswith(":src") else figure.rules_tree
        return "rules/example.yaml" if args[0] == "ls-tree" else ""

    for value in (None, "0"):
        calls.clear()
        env = {} if value is None else {"AGENT_DEFS_ALLOW_MALICIOUS_EXTRACT": value}
        with patch.object(gate, "FIGURES", [figure]), patch.object(gate, "_git", fake_git), \
             patch.object(gate.platform, "system", return_value="Windows"), \
             patch.dict(gate.os.environ, env, clear=True), \
             patch.object(gate.subprocess, "run", side_effect=RuntimeError("archive reached; mocked, no extraction")):
            try:
                gate.prepare(root / "work", root / "history", allow_network=False, export=False)
            except RuntimeError as exc:
                out["windows_guard_" + str(value)] = {"calls": list(calls), "outcome": str(exc)}

print(json.dumps(out, indent=2, ensure_ascii=True))
