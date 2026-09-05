"""Render the unit return artifact in memory, then write its destination once."""
import argparse
from collections import Counter
import json
from pathlib import Path
import re

from agent_defs import bench
from agent_defs.lanes import admit
from agent_defs.model import BenignFiring
from dataclasses import replace


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--evidence", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    root = args.evidence.resolve()
    def read(name):
        return json.loads((root / name).read_text(encoding="utf-8"))
    report = read("combined-out-report.json")
    rules = bench.load_rules(root / "atr-out-rules.json")
    rule_map = {r.id: r for r in rules}
    net = bench.load_rules(root / "netzilo-in-rules.json")
    sources = {name: read(name + "-inventory.json") for name in ("trace-commons", "local-claude")}
    characterization = read("characterization.json")
    summary = report["summary"]
    lanes = Counter(row["lane"] for row in report["rules"].values())
    n, k = summary["trials"], summary["units_touched"]
    union = report["bundle"]["diagnostic"]
    test_log = (root.parent / "r1-final-tests.txt").read_text(encoding="utf-8")
    test_summary = re.findall(r"\d+ failed, \d+ passed[^\n]*", test_log)[-1]
    pct = lambda value: f"{100*value:.6f}%"
    esc = lambda value: str(value).replace("|", "\\|").replace("\n", " ")
    lines = ["# r1 result",
             f"Conclusion: The full OUT bundle is not ready for hooks: zero rules qualify for promotion, real Gmail output defeats a 30-second scan budget, and {k}/{n} results fired on the completed offline measurement.",
             "Files: src/agent_defs/bench.py; docs/bench.md; tests/test_bench.py; tests/test_tool_traffic.py; scripts/inspect_tool_traffic.py; scripts/prepare_tool_traffic.py; scripts/measure_tool_traffic.py; scripts/characterize_tool_traffic.py; scripts/summarize_tool_traffic.py; scripts/write_tool_traffic_result.py; scripts/diagnose_tool_traffic.py; scripts/export_traffic_rules.py. Evidence is outside the clone in r1-evidence/.",
             "Open items: Slow accepted predicates on real output; more independent attacker-reachable traffic; raw PostToolUse payload coverage; historical 515 versus current-loader 396 OUT discrepancy; Windows incomplete-scan cause; the 7 existing non-benchmark test failures.",
             f"Verification: PYTHONPATH=src python -m pytest tests -q: {test_summary}. Focused bench/traffic tests: 41 passed. No commit, push, destructive Git command, or rule-condition change was made.",
             "", "## Decision and sample-size arithmetic", "",
             f"**VERIFIED:** {n:,} recorded textual OUT results were scanned completely by all 306 runnable current-loader ATR OUT rules. The bundle fired on {k:,} results ({pct(k/n)}); its pooled diagnostic u95 is {pct(union['u95'])}. This is not constant firing. The unmodified full bundle still fails the existing admission gate, and this experiment does not justify shipping it as an interrupting hook.",
             "",
             "**VERIFIED:** A clean 0.5% claim requires 598 trials; 0.1% requires 2,995. Public web results provide only 19 trials. Local web results provide 604, including 6 tool-marked errors and 598 successes. Even 623 pooled clean web results would only bound the rate at 0.479702%, and pooling the sources is not permitted for admission. The public web stratum alone bounds a zero-hit rate only at 14.586850%.",
             "",
             f"**VERIFIED:** Actual ATR lanes are {lanes.get('RECORD',0)} RECORD, {lanes.get('DO_NOT_SHIP',0)} DO_NOT_SHIP, 0 ADVISE, 0 DENY. All 306 runnable OUT rules are sample-size-limited by native strata with fewer than 598 trials, independently of whether they fire. All 306 are also too small for the 2,995-trial threshold on those strata. The other 90 are unsupported, not 90 clean or sample-size-limited rules. Zero rules can be promoted with the current strata and bundle gate. The blockers overlap: small strata, repeated outputs, and bundle noise must not be counted as disjoint categories.",
             "",
             "**INFERRED:** This does not kill the general detector design on constant-noise grounds. It does reject promotion of this full bundle from these measurements. A separate verified runtime failure prevents treating it as a complete-scan hook: on one real Gmail output the 250 ms evaluator completed only 132/306 rules. Its apparent quietness reflects narrower runnable coverage than the historical claim and establishes neither production precision nor attack recall.",
             "", "## Sources and extraction", "",
             "All external HTTP observations below were made on 2026-09-05 UTC, which was 2026-09-04 Pacific. Counts are parser outputs, not dataset-card totals.", "",
             "**VERIFIED: TraceLab v0.0.2.** Both pinned Parquet GETs returned HTTP 200. Parsing found 743,819 tool rows and 665,453 round rows; joining round_pk gave 305,005 Claude calls, 438,814 Codex calls, and 7,244 sessions, with zero repeated (provider, session_id, tool_call_id) keys. The tool file has NO result text or full invocation arguments. It contains result_chars, input_chars, timings, tool names, executable metadata, and a command skeleton. Consequently it contributes **zero scannable OUT trials and zero complete IN trials**. Its 743,819 rows cannot be used as the denominator of this regex experiment.", "",
             "Sources: [tool_calls/train.parquet](https://huggingface.co/datasets/UW-SyFI/TraceLab/resolve/7256bbf77e76d5cb83f4ddbd5ad31d8faee9dc7a/data/v0.0.2/tool_calls/train.parquet), [rounds/train.parquet](https://huggingface.co/datasets/UW-SyFI/TraceLab/resolve/7256bbf77e76d5cb83f4ddbd5ad31d8faee9dc7a/data/v0.0.2/rounds/train.parquet). HTTP 200, dates, file lengths and SHA-256 are retained in http-ledger.json. The tool-file digest is 7186e0d86d3d870e5b374cc29678a4754fcb789ebee4f5ad86461dd02db6f68b.", "",
             "**VERIFIED:** TraceLab has 743,050 non-null result character counts and 769 nulls. Character-count min/p25/p50/p75/p90/p95/p99/max are 0/123/407/2,472/8,219/13,302/40,151/11,005,195. **Byte sizes are unavailable**, because the original strings and Unicode composition are absent. Do not relabel characters as bytes. Tool names identify 5,346 WebFetch/WebSearch calls and 646,197 native shell/file calls, but do not prove output provenance; the remainder and custom tools remain unresolved. A shell command can fetch remote text and a Read can expose outside-authored code.", "",
             "**VERIFIED: Trace Commons.** The pinned recursive API tree returned 44 entries, no next-page Link, and exactly 28 Claude Code JSONL files. All 28 transcript GETs returned HTTP 200. They contain 4,264 top-level tool invocations, 4,262 returned result blocks, 2 invocations without a result, no malformed lines, no orphan results, and no repeated invocation or result records. There are 27 files with calls and one without. Of the result blocks, 4,185 contain strings and 13 contain only text blocks, yielding **4,198 OUT trials**. The other 64 are 28 tool-reference results, 31 image-only results, and 5 mixed image/text results. They are excluded in full, not counted as clean text prefixes.", "",
             "Sources: [pinned tree](https://huggingface.co/api/datasets/trace-commons/agent-traces/tree/112ebd4d03ce852b00e935d523107c3d0c9a65bf?recursive=true&limit=1000), [example pinned transcript](https://huggingface.co/datasets/trace-commons/agent-traces/resolve/112ebd4d03ce852b00e935d523107c3d0c9a65bf/sessions/claude_code/da5d32d6-547f-45ae-a5b5-4747ed06542f.jsonl). HTTP 200 on the date above. Every transcript URL/status/hash is in http-ledger.json; pagination evidence is in commons-pagination.json.", "",
             "**VERIFIED: Added local Claude traffic.** At enumeration, ~/.claude/projects contained 2,392 JSONL files. Excluding the agent-startup-thesis, agent-defs, and agent-config project paths to avoid measuring this security experiment's own outputs left 1,842. A fixed SHA-256 ordering selected 120 files before rule evaluation. They contained 4,461 invocations, 4,460 results, 4,315 text-eligible results, 145 nontext results, and 1 missing result. A second fixed hash ordering selected 4,000 eligible results. These came from 102 files; 18 of the 120 had no calls. There were no malformed lines, ambiguous exchanges, or global repeated invocation IDs in the selected files. This is a deterministic convenience sample, not a representative user population. Private payloads are not included in this result or the repository.", "",
             "The exact selection prefixes are r1-build2-v1/relative-path for files and r1-build2-units-v1/unit-id for results. The file-hash inventory and resulting snapshot hash freeze what was actually used; replay from a changing live transcript tree requires retaining that snapshot.", "",
             "**VERIFIED trial definition:** One trial is one complete recorded textual content field from one returned tool invocation, joined by session and tool-use ID. A string is scanned unchanged. A text-block list is joined in order with one newline between blocks, still one trial. The name and arguments are preserved separately for IN and provenance. Assistant prose, nested progress events, hidden toolUseResult metadata, and other conversation records do not become OUT units. Repeated payloads from distinct actual invocations remain observed traffic and are reported as duplicates; no copies were manufactured to grow n.", "",
             "**UNRESOLVED representation limit:** Complete recorded content is not necessarily complete raw PostToolUse output. The public sample contains 3 persisted-output previews and 12 results with an explicit truncation marker; the local sample contains 14 persisted-output previews (also 14 truncation-marker results). Public persisted files are not supplied. The full underlying output was not invented or reassembled from a preview. WebFetch often returns a model-produced summary; WebSearch returns query text, link JSON and snippets. These are real returned outputs, but do not measure the original page before summarization. The 26 visibly shortened outputs remain in the observed-traffic diagnostic; a stricter sensitivity count is supplied below. This limitation independently prevents a complete raw-hook claim.",
             "", "## Sizes and provenance strata", "",
             "Sizes are UTF-8 bytes of the scanned text, after the stated text-block join. Percentiles use the nearest indexed observation with round((n-1)*q).",
             "", "| Corpus | n | Total bytes | Min | p25 | p50 | p75 | p90 | p95 | p99 | Max |", "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for name, source in sources.items():
        s = source["sizes"]
        lines.append("| " + name + " | " + " | ".join(str(s[x]) for x in ("count","total","min","p25","p50","p75","p90","p95","p99","max")) + " |")
    lines += ["", "The exposure classifier is explicitly **INFERRED** from tool names and invocation arguments. Direct WebFetch/WebSearch is attacker-reachable. File reads, grep and edits have unknown file authorship. Shell calls with network indicators are mixed network commands; other commands that read files remain unknown-origin. Remaining shell/status/list/write acknowledgements are classified as locally generated, with provenance uncertainty because arbitrary code can emit fetched bytes. Unknown MCP tools and agent/orchestration outputs are kept separate. No file-blame evidence was available, so local path location was never equated with trusted authorship.", "",
              "The 18 local MCP results are specifically Gmail thread/message/search reads and are also an attacker-reachable channel through outside-authored mail. They remain separately visible under external-tool-unknown, rather than being pooled into quiet shell outputs. Public MCP text results comprise 3 browser navigate responses, one browser tab-context response and two haven management responses; their content origin is not established by the MCP prefix alone.", "",
              "| Corpus | Exposure | n | Bytes | Median bytes | p95 bytes | Bundle hits | Rate | u95 |", "|---|---|---:|---:|---:|---:|---:|---:|---:|"]
    for m in report["bundle"]["measurements"]:
        if m["stratum"].startswith("exposure="):
            exposure = m["stratum"].split("=", 1)[1]
            size = sources[m["corpus"]]["exposure"][exposure]
            lines.append(f"| {m['corpus']} | {exposure} | {m['trials']} | {size['total']} | {size['p50']} | {size['p95']} | {m['hits']} | {pct(m['hits']/m['trials'])} | {pct(m['u95'])} |")
    lines += ["", "**VERIFIED:** The sole local direct-web hit is atr:ATR-2026-00237 (Dual-Response Jailbreak with Persona Commands), 1/604, u95=0.782978%. Its local generated-output count is 0/670. The Gmail stratum has one atr:ATR-2026-00002 hit in 18 results. These strata must not be diluted with shell acknowledgements. Firing results were not adjudicated as malicious or benign, so these are observed firing rates, not proven false-positive rates.", "",
              "**VERIFIED:** Direct web results occur in only 6 public and 24 local transcript files. Local WebFetch/WebSearch counts are 280/324; public counts are 13/6. Public direct web statuses are 19 successes; local statuses are 598 successes and 6 errors. The web strata are 0.453% and 15.1% of scannable public/local results respectively. Pooling these sources would hide a substantial traffic-mix difference.", "",
              "**VERIFIED:** Exact repeated output counts are 1,261 public and 444 local. They are mostly recurring traffic shapes such as acknowledgements, but are not independently adjudicated. The existing duplicate-material gate remains in force. Binomial bounds below are pointwise conditional calculations assuming independent representative trials; session clustering, selection and duplication do not justify that assumption. They are not simultaneous 95% guarantees across hundreds of rules.",
              "", "## Aggregate firing and lane results", "", "| Corpus | Trials | Rule findings | Results hit (union) | Union u95 | Silent | Silent reachable | Silent unreachable | Silent without examples |", "|---|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for name in sources:
        r = read(name + "-out-report.json")
        s, b = r["summary"], r["bundle"]["diagnostic"]
        lines.append(f"| {name} | {s['trials']} | {s['findings']} | {s['units_touched']} | {pct(b['u95'])} | {s['quiet_rules']} | {s['quiet_reachable']} | {s['quiet_unreachable']} | {s['quiet_no_examples']} |")
    lines.append(f"| Pooled diagnostic | {n} | {summary['findings']} | {k} | {pct(union['u95'])} | {summary['quiet_rules']} | {summary['quiet_reachable']} | {summary['quiet_unreachable']} | {summary['quiet_no_examples']} |")
    hypothetical = Counter()
    for rule in rules:
        row = report["rules"][rule.id]
        if row["excluded_reason"]:
            continue
        m = row["diagnostic"]
        measurement = BenignFiring(m["trials"], m["hits"], m["u95"], "pooled diagnostic", report["measured_at"])
        hypothetical[admit(replace(rule, benign=measurement), bundle_ok=True)[0].value] += 1
    lines += ["", f"If one incorrectly treated the pooled rate as the only gate and asserted bundle_ok=True, bare admit() would return {dict(hypothetical)}. Those are counterfactual threshold counts, **not promotions**. Actual lanes come from bench.admit_from_report(), which invokes lanes.admit() with the measured bundle flag and worst native stratum. It returns {dict(lanes)}. The small-stratum blocker applies to all 306 runnable rules even in a counterfactual zero-hit run.", "",
              "**VERIFIED reachability:** Each runnable rule was tested only against its own unchanged upstream positives. Across the 306 rules, all 1,519 positive examples matched. The counts in the table separate silence from dead conditions: no silent runnable rule failed its own examples and none lacked examples. The 90 excluded OUT rules were not called silent or dead. Positive-example success is a witness that the predicate can fire, not a recall measurement on independent embedded attacks.", "",
              "**VERIFIED coverage disagreement:** loaders.atr read and emitted 793 records from 793 archive-verified rule files. Its actual distribution is OUT 396 (306 REGEX, 90 NONE), PROMPT 218, CFG 116, IN 57, NONE 6. The context's 515 OUT count is not reproduced by this loader. This experiment did not alter its mapping or count the other 119 historical claims as measured OUT rules. Reconciliation to the historical IDs remains unresolved. The current OUT exclusions include mixed-field conditions, conservative regex-screen refusals, and suppression/structured semantics that cannot be faithfully reduced to text.",
              "", "## Rules above 1% and finding concentration", ""]
    loud = summary["rules_over_one_percent"]
    lines.append("**VERIFIED, strict >1% over all real results:** " + (", ".join(loud) if loud else "none.") + f" Threshold is more than {n/100:g} hits, not greater than or equal to 1%.")
    for name in sources:
        r = read(name + "-out-report.json")
        lines.append(f"{name}: " + (", ".join(r["summary"]["rules_over_one_percent"]) or "no rule exceeds 1% of that corpus.") )
    ranked = sorted(((rid, row["diagnostic"]["hits"]) for rid, row in report["rules"].items() if row["diagnostic"]["hits"]), key=lambda pair: (-pair[1], pair[0]))
    cumulative, concentration = 0, []
    for rid, hits in ranked:
        if concentration and cumulative / summary["findings"] >= .807:
            break
        cumulative += hits
        concentration.append(rid)
    lines += ["", f"The equivalent of the earlier concentration list is the following {len(concentration)} rules: together they carry {cumulative}/{summary['findings']} findings ({pct(cumulative/summary['findings']) if summary['findings'] else '0%'}). This is a descriptive list, not a proposal to remove or tune them.", "",
              "| Rule | Title | Hits | Rate | u95 |", "|---|---|---:|---:|---:|"]
    for rid in concentration:
        m = report["rules"][rid]["diagnostic"]
        lines.append(f"| {rid} | {esc(rule_map[rid].title)} | {m['hits']} | {pct(m['hits']/n)} | {pct(m['u95'])} |")
    stratum_loud = {}
    for rid, row in report["rules"].items():
        matches = [m for m in row["measurements"] if m["stratum"].startswith("exposure=") and m["hits"]/m["trials"] > .01]
        if matches:
            stratum_loud[rid] = matches
    lines += ["", "Every rule exceeding 1% in any reported exposure stratum (including small strata) is listed here. Small denominators are displayed so one hit is not disguised as stable prevalence.", "", "| Rule | Corpus | Exposure | Hits / trials | u95 |", "|---|---|---|---:|---:|"]
    for rid, matches in sorted(stratum_loud.items()):
        for m in matches:
            lines.append(f"| {rid} | {m['corpus']} | {m['stratum']} | {m['hits']}/{m['trials']} | {pct(m['u95'])} |")
    condition_ids = set(concentration) | set(loud) | set(stratum_loud) | {"atr:ATR-2026-00233", "atr:ATR-2026-00237"}
    for name in sources:
        condition_ids.update(read(name + "-out-report.json")["summary"]["rules_over_one_percent"])
    lines += ["", "Exact normalized conditions for every rule named above, plus the slow rule ATR-2026-00233 discussed below, follow. All are REGEX with case_sensitive=False. They are detection data, not executable instructions; the conditions were not tuned."]
    for rid in sorted(condition_ids):
        lines += ["", f"### {rid}: {rule_map[rid].title}", "", "```text", rule_map[rid].predicate, "```"]
    lines += ["", "## Complete per-rule OUT measurements", "",
              "Each runnable row has n=8,198 pooled, n=4,198 public, n=4,000 local, n=19 public web, n=604 local web, n=1,622 public locally-generated, and n=670 local locally-generated. Cells are hits / u95-percent; zeros are measured zeros. Pooled u95 is diagnostic. All exact floating-point bounds and every additional tool/prose/status/exposure stratum are in per-rule-strata.csv and combined-out-report.json. Excluded rows have zero evaluated trials and NA bounds, regardless of corpus size.", "",
              "| Rule | Pooled hits / u95 | Public hits / u95 | Local hits / u95 | Public web hits / u95 | Local web hits / u95 | Public generated hits / u95 | Local generated hits / u95 | Lane | Positive |", "|---|---:|---:|---:|---:|---:|---:|---:|---|---|"]
    for rule in sorted(rules, key=lambda r:r.id):
        row = report["rules"][rule.id]
        if row["excluded_reason"]:
            cells = ["0 trials / NA"] * 7
        else:
            d = row["diagnostic"]
            cells = [f"{d['hits']} / {pct(d['u95'])}"]
            for corpus, stratum in [("trace-commons","all"),("local-claude","all"),("trace-commons","exposure=attacker-reachable"),("local-claude","exposure=attacker-reachable"),("trace-commons","exposure=locally-generated"),("local-claude","exposure=locally-generated")]:
                m = next(m for m in row["measurements"] if m["corpus"] == corpus and m["stratum"] == stratum)
                cells.append(f"{m['hits']} / {pct(m['u95'])}")
        lines.append(f"| {rule.id} | " + " | ".join(cells) + f" | {row['lane']} | {row['reachability']['status']} |")
    lines += ["", "### OUT exclusion reasons", "", "| Rule | Reason |", "|---|---|"]
    for rid, row in sorted(report["rules"].items()):
        if row["excluded_reason"]:
            lines.append(f"| {rid} | {esc(row['excluded_reason'])} |")
    lines += ["", "## Representation sensitivity", "",
              "These are additional descriptive slices of the already-scanned results, with the same per-result union of hits. They do not change admission or replace the declared corpus.", "",
              "| Corpus | Slice | Trials | Union hits | u95 |", "|---|---|---:|---:|---:|"]
    for name in sources:
        traffic = [json.loads(line) for line in (root / f"{name}-units.jsonl").read_text(encoding="utf-8").splitlines()]
        touched = {m["id"] for m in report["materials"] if m["corpus"] == name and m["findings"]}
        markers = ("<persisted-output>", "output truncated", "Output truncated", "characters truncated", "content truncated")
        slices = {"without explicit truncation markers": [r for r in traffic if not any(marker in r["text"] for marker in markers)],
                  "successful direct web": [r for r in traffic if r["strata"]["exposure"] == "attacker-reachable" and r["strata"]["result_status"] == "success"]}
        if name == "local-claude":
            slices["direct web plus Gmail"] = [r for r in traffic if r["strata"]["exposure"] == "attacker-reachable" or r["strata"]["tool"].startswith("mcp__claude_ai_Gmail__")]
        for label, members in slices.items():
            trials = len(members)
            hits = sum(r["id"] in touched for r in members)
            lines.append(f"| {name} | {label} | {trials} | {hits} | {pct(bench.binomial_u95(trials,hits))} |")
    lines += ["", "## Netzilo IN", "",
              "**VERIFIED:** The corpus supports name-and-arguments invocation text for the 8,198 paired exchanges. The pinned Sigma loader emits 1,156 total Netzilo records, of which 296 are IN. All 296 are predicate_kind=NONE; zero IN rules are runnable. Common refusals are event_type guards, exact selectors, boolean trees, mixed case modes, and action/script extensions. I ran bench on the paired IN corpus: it evaluated **zero rule-trials**, and all 296 rules are DO_NOT_SHIP. A zero in that report is not evidence of precision. This is an execution-coverage failure, not sample-size failure, and no condition was flattened to make it run. The report is trace-commons-local-claude-in-report.json.", "",
              "| IN rule | Evaluated trials | Hits | Bound | Lane | Refusal |", "|---|---:|---:|---|---|---|"]
    for rule in sorted(net, key=lambda r:r.id):
        lines.append(f"| {rule.id} | 0 | 0 | NA | DO_NOT_SHIP | {esc(rule.not_runnable_reason)} |")
    lines += ["", "## Tool inventories", "", "### Trace Commons and local Claude", "",
              "Calls are all parsed invocations in the source file selection; OUT n is the final measured text sample.", "", "| Tool | Public calls | Public OUT n | Local parsed calls | Local OUT n |", "|---|---:|---:|---:|---:|"]
    tool_names = set().union(*(set(s["tools"]) for s in sources.values()))
    for tool in sorted(tool_names):
        a, b = sources["trace-commons"], sources["local-claude"]
        lines.append(f"| {esc(tool)} | {a['tools'].get(tool,0)} | {a['selected_tools'].get(tool,0)} | {b['tools'].get(tool,0)} | {b['selected_tools'].get(tool,0)} |")
    lines += ["", "### TraceLab metadata-only calls", "", "| Tool name | Calls |", "|---|---:|"]
    for tool, count in sorted(read("tracelab-tool_calls-inventory.json")["tool_counts"].items(), key=lambda item:(-item[1], item[0])):
        lines.append(f"| {esc(tool)} | {count} |")
    lines += ["", "## Verified runtime failure on actual attacker-reachable traffic", "",
              "The full local run was attempted at a 30-second per-result offline deadline on both Windows and Linux. Both aborted and wrote no valid report. The instrumented Linux failure names unit 8134cec95c09d4bb7c1e/1d925e0095cff00467d5: a 28,049-byte mcp__claude_ai_Gmail__get_thread result, SHA-256 61688a4e4dd195700bd7ca93301ec5ae318002a5d6f4c2d539a882e643d8ad83. It completed 257/306 rules, with 49 unfinished, no input truncation, and no evaluator errors. A standalone repeat reproduced the same 257/49 split in 30.003424 seconds with zero hits (timeout-diagnosis-30s.json). This is a deadline failure, not a clean scan.", "",
              "The next scheduled rule was atr:ATR-2026-00233, Structured Dual-Response Jailbreak with Command System. A separate isolated scan of that rule on the same payload finished in 14.893606 seconds with zero hits. The accepted condition contains a branch beginning `\\w+:\\s*.*\\w+:`, among others; no branch was changed. Attribution of all elapsed time in the full scan to that one rule would be unwarranted, but its own measured runtime is already excessive for a hook.", "",
              "A direct cold evaluator reproduction with all 306 rules and the hook's 0.25-second budget took 0.252337 seconds, completed 132 rules, left 174 unfinished, and returned zero findings with complete=False and truncated=False. This is **VERIFIED** evaluator behavior at the hook deadline, not an end-to-end hook installation test. A consumer interpreting that empty result as clean would silently miss unfinished checks; a consumer blocking every incomplete result would block this real mail read. The unchanged full local corpus was therefore measured at a 180-second offline deadline to obtain firing counts, while retaining this failure as a separate product blocker. No negative trial was discarded for being slow.", "",
              "Reproduction: `PYTHONPATH=src python3 scripts/diagnose_tool_traffic.py --evidence private-local --rules evidence/atr-out-rules.json --unit 8134cec95c09d4bb7c1e/1d925e0095cff00467d5 --rule atr:ATR-2026-00233 --budget-s 120`; repeat with `--rule ALL --budget-s 0.25 --out-name timeout-diagnosis-250ms.json`. Exact machine-readable outcomes are timeout-diagnosis.json and timeout-diagnosis-250ms.json. Inputs are private measurement artifacts, not copied into this report.", "",
              "## Verification, artifacts, and runtime limits", "",
              "`scripts/inspect_tool_traffic.py` produced the HTTP ledger and Parquet inventories; `scripts/prepare_tool_traffic.py` produced the transcript counts and snapshot hashes; `scripts/characterize_tool_traffic.py` produced the joined TraceLab counts, size percentiles, truncation markers and provenance counts. Exact commands (P is the Miniforge py312 interpreter; E is the external r1-evidence directory):", "",
              "```powershell", "$P = 'C:/Users/yuezh/miniforge3/envs/py312/python.exe'", "$E = '../../agent-io/build2/r1-evidence'", "$env:PYTHONPATH = 'src'", "& $P scripts/inspect_tool_traffic.py --out $E", "& $P scripts/prepare_tool_traffic.py --out $E --local-root C:/Users/yuezh/.claude/projects", "& $P scripts/characterize_tool_traffic.py --evidence $E", "& $P scripts/measure_tool_traffic.py --evidence $E --names trace-commons local-claude --surface IN --rules $E/netzilo-in-rules.json", "& $P scripts/summarize_tool_traffic.py --evidence $E", "& $P -m pytest tests -q", "```", "",
              "The complete ATR/Netzilo source export and successful OUT scans ran in the supplied Linux host's dedicated r1-build2 directory:", "", "```sh", "PYTHONPATH=src python3 scripts/export_traffic_rules.py --archives ../archives --out evidence", "PYTHONPATH=src python3 scripts/measure_tool_traffic.py --evidence evidence --names trace-commons --rules evidence/atr-out-rules.json --workers 4", "PYTHONPATH=src python3 scripts/measure_tool_traffic.py --evidence private-local --names local-claude --rules evidence/atr-out-rules.json --workers 3 --budget-s 180", "```", "",
              "Both source archives were verified against sources.lock; 793 ATR YAML rule files and every Netzilo rule file used were checked against the pinned archives. No known-malicious sample directory was extracted. Sources: [ATR pinned archive](https://codeload.github.com/Agent-Threat-Rule/agent-threat-rules/tar.gz/faf743fee8a5018467959ec8ea7ccdb1a1aab333), [Netzilo pinned archive](https://codeload.github.com/netzilo/aidr-sigma/tar.gz/0139a6648ed3daa1094fc4f49e2b157524a0bec7). Both HTTP 200 on 2026-09-05 UTC in the existing verified fetch ledger; this run reverified archive hashes and parsed counts. rule-source-audit.json records the verification.", "",
              "The first Windows local-traffic run aborted with an incomplete benchmark scan and wrote no success report. Its older error omitted the unit and evaluator failure details, so the reason is **UNRESOLVED**, not established as a regex timeout. The benchmark now includes unit identity, evaluated/skipped counts and evaluator errors in that exception. The successful rerun uses the same frozen 4,000 results and unchanged predicates. Private transfer inputs were placed in a mode-700 directory on the supplied Linux host, and removed after retrieving the result. No private result excerpts are included here.", "",
              "Successful scans used killable evaluate.scan subprocesses with offline budgets of 30 seconds per public result and 180 seconds per local result, preserving each recorded payload's full size. No external traffic or upstream positive example used scan_trusted. The benchmark's CP, unit counting, union counting, reachability, fingerprints and admit adapter were retained. The report combiner verifies bundle and positive-result identity; a regression test confirms its aggregate counts/bounds/lanes equal a joint bench.measure call. The separate 250 ms probe above is one evaluator-level runtime witness, not a population latency benchmark or an end-to-end hook/recall claim.", "",
              f"Initial Windows suite: 222 passed, 9 failed, 10 errors. Checksum errors were traced to Git checkout CRLF expansion: 32 fixture files were restored to their exact Git blob bytes without changing logical fixture contents or manifests. Final full suite: {test_summary}. Focused command `python -m pytest tests/test_tool_traffic.py tests/test_bench.py -q`: 41 passed. Full output is in r1-final-tests.txt beside the evidence directory. The remaining seven failures concern ATR screening/conjunction expectations, four hook readers, and a JSON-loader reachability name; no remaining failure belongs to this unit.", "",
              f"Evidence directory: `{root.as_posix()}`. Main artifacts: combined-out-report.json, the two component OUT reports, per-rule-strata.csv, the IN report, summary.json, characterization.json, both inventories and frozen unit snapshots, http-ledger.json, commons-pagination.json, rule-source-audit.json, and loader deltas. Snapshots contain private/source material and are measurement inputs, not redistributable package assets.", "",
              "## Confidence and what would change it", "",
              "**VERIFIED** counts, hash identities, exact-bound calculations, native-lane outputs and positive witnesses are reproducible from the frozen inputs and scripts. **INFERRED** provenance labels distinguish clear web channels, locally generated proxies and unresolved file/network/MCP origins; they do not prove attacker authorship or benignness. Untouched real traffic is not an adjudicated false-positive set.", "",
              "The decision would change with sufficient independent full raw tool-result traffic on each intended attacker-reachable stratum, adjudication of firing results, reconciliation of the missing historical OUT coverage, and a measured exact enabled bundle that completes at hook byte/time limits. Until then, the measured quiet majority is reachable, the constant-noise kill hypothesis is unsupported on this sample, the runtime failure is real, and promotion remains unjustified."]
    if args.out.exists():
        raise FileExistsError("the unit result must be written only once")
    args.out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(args.out, "bytes", args.out.stat().st_size)


if __name__ == "__main__":
    main()
