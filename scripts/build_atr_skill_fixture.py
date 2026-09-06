"""Rebuild tests/fixtures/atr_skill from a pinned ATR checkout.

    python scripts/build_atr_skill_fixture.py /path/to/atr-checkout

The fixture carries upstream rule YAML verbatim plus the spans of ATR's own
engine that ``agent_defs.loaders.atr_skill_gates`` reads. Slicing named line
ranges and stamping each with the range it came from is what keeps the fixture an
excerpt rather than a rewrite: a gate that moves upstream then shows up as a
fixture that no longer parses, instead of as a fixture that quietly disagrees.

Every rule in the manifest is there for a reason, and the reason is recorded
beside it in ``atr-source.json``.
"""
import hashlib
import json
import pathlib
import re
import sys
import textwrap

ATR = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
DST = pathlib.Path(__file__).resolve().parent.parent / "tests/fixtures/atr_skill"
PIN = "faf743fee8a5018467959ec8ea7ccdb1a1aab333"

SPANS = {
    "src/engine.ts": [
        ("the skill-context denylist", r"^/\*\*\n \* Rules excluded from skill-context scanning due to high false-positive rate\.\n \* Threshold", r"^\]\);"),
        ("base64 block bounds and decoder", r"^const BASE64_BLOCK_RE", r"^\}\n"),
        ("the status skip and the skill compound gate", r"^    // Tier 2: Pattern matching \(existing regex rules\)", r"^        matches\.push\(matchResult\);"),
        ("the any-logic short circuit", r"^  private evaluateArrayConditions\(", r"^    if \(!matched\) return null;"),
        ("skill-context field resolution", r"^  private resolveField\(fieldName: string, event: AgentEvent\): string \| undefined \{", r"^    // Check explicit fields first"),
        ("the scanSkill entry point", r"^  scanSkill\(content: string\): ATRMatch\[\] \{", r"^  \}\n"),
        ("the maximum evaluated length", r"^/\*\* Maximum input length for regex evaluation", r"^\}\n"),
    ],
    "src/enforcement.ts": [
        ("the default detection lane", r"^export const DEFAULT_LANE", r"^export const DEFAULT_LANE.*$"),
    ],
    "src/quality/rule-contract.ts": [
        ("the lane gate", r"^export function laneAllows", r"^\}"),
    ],
    "engines/typescript/INTERFACE-CONTRACT.md": [
        ("the evaluate() contract", r"^   \* Contract:", r"^   \* - Synchronous"),
    ],
}


def slice_span(text, start_re, end_re):
    s = re.search(start_re, text, re.M)
    assert s, start_re
    e = re.search(end_re, text[s.start():], re.M)
    assert e, end_re
    span = text[s.start():s.start() + e.end()]
    first = text.count("\n", 0, s.start()) + 1
    return span, first, first + span.count("\n")


def build_source_excerpts():
    for rel, spans in SPANS.items():
        text = (ATR / rel).read_text(encoding="utf-8")
        comment = "//" if rel.endswith(".ts") else "<!--"
        close = "" if rel.endswith(".ts") else " -->"
        out = [f"{comment} Excerpt of {rel} at ATR {PIN}, MIT licensed.{close}",
               f"{comment} Only the spans agent_defs.loaders.atr_skill_gates reads are kept,"
               f" so this fixture cannot drift into a rewrite of upstream's logic.{close}", ""]
        for label, a, b in spans:
            span, lo, hi = slice_span(text, a, b)
            out.append(f"{comment} --- {label}: {rel} lines {lo}-{hi} ---{close}")
            out.append(span.rstrip("\n"))
            out.append("")
        dst = DST / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text("\n".join(out), encoding="utf-8")
        print("wrote", rel, dst.stat().st_size, "bytes")


def build_rules():
    """Copy the upstream rules the gate tests need, verbatim."""
    wanted = {
        "ATR-2026-00120": "a scan_target: skill rule the dispatcher admits",
        "ATR-2026-00121": "a skill rule whose composed alternation the flat screen refuses",
        "ATR-2026-00123": "the one denylisted rule the pinned engine still runs",
        "ATR-2026-00162": "a skill rule whose every condition crosses the budget",
        "ATR-2026-00421": "a CFG-eligible rule still carrying tags.suppress_in_code_blocks",
        "ATR-2026-00111": "a denylisted mcp rule the compound gate already excludes",
        "ATR-2026-02377": "a condition: all rule with two conditions, admitted without a skill target",
        "ATR-2026-00040": "an mcp any-logic rule the compound gate refuses",
        "ATR-2026-00276": "a skill rule with two conditions refused on safety",
    }
    files = {}
    for rid, why in wanted.items():
        hits = [p for p in (ATR / "rules").rglob(f"{rid}-*.y*ml")]
        assert len(hits) == 1, (rid, hits)
        src = hits[0]
        local = rid.rsplit("-", 1)[1] + ".yaml"
        data = src.read_bytes()
        (DST / local).write_bytes(data)
        files[local] = {"source_path": src.relative_to(ATR).as_posix(),
                        "sha256": hashlib.sha256(data).hexdigest(), "why": why}
    (DST / "atr-source.json").write_text(
        json.dumps({"source_rev": PIN, "files": files}, indent=2) + "\n", encoding="utf-8")
    print("wrote", len(files), "rules")


DST.mkdir(parents=True, exist_ok=True)
(DST / "LICENSE").write_bytes((DST.parent / "atr" / "LICENSE").read_bytes())
(DST / "README.md").write_text(textwrap.dedent(f"""\
    # ATR skill-dispatcher fixture

    Upstream rule YAML plus the spans of ATR's own engine that
    `agent_defs.loaders.atr_skill_gates` reads, both verbatim from
    `{PIN}`, MIT licensed. `atr-source.json` records each rule's upstream path,
    its digest, and why this fixture carries it.

    The source files here are excerpts, not rewrites:
    `scripts/build_atr_skill_fixture.py` slices
    named line ranges and stamps them with the range it took, so a gate that
    moves upstream shows up as a fixture that no longer parses rather than as a
    fixture that quietly disagrees with the source.
    """), encoding="utf-8")
build_source_excerpts()
build_rules()
