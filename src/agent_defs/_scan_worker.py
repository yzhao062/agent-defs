"""Private single-request worker. Only JSON data arrives on stdin."""

import json
from pathlib import Path
import sys

# -I -S excludes the caller's working directory, site hooks and PYTHONPATH.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agent_defs.evaluate import _search_substrings, compile_rule
from agent_defs.model import ChannelBinding, PredicateKind, Rule, Surface


def _cfg(request):
    """Run the configuration channel here, where a runaway match can be killed.

    The document arrives raw rather than pre-split, so the base64 decode and the
    code-block scan are inside the killable process too. Both read attacker text
    and neither is free.
    """
    from agent_defs.cfg import _CompiledBinding, _code_block_ranges, _decoded_blocks

    document = request["payload"]
    suppress = request["suppress_code_blocks"]
    ranges = _code_block_ranges(document) if suppress else []
    payloads = [("document", document, ranges)]
    if request["decode_base64"]:
        payloads += [("base64", block, _code_block_ranges(block) if suppress else [])
                     for block in _decoded_blocks(document)]
    for index, item in enumerate(request["rules"]):
        try:
            rule = Rule(id=item["id"], source=item.get("source", ""), source_id="", source_rev="",
                        source_path="", upstream_url="", surface=Surface(item["surface"]),
                        predicate_kind=PredicateKind.NONE, predicate=None,
                        case_sensitive=False,
                        # These rules have no flat predicate by construction: the
                        # channel runs the binding, not a composed alternation.
                        not_runnable_reason="runs through the source's own dispatcher")
            binding = ChannelBinding(channel=item["surface"], entry_point="", eligible=True,
                                     reason="", conditions=tuple(item["conditions"]),
                                     condition_logic=item["logic"],
                                     suppress_in_code_blocks=item["suppress"])
            compiled = _CompiledBinding(rule, binding)
            record = ["ok", index, None]
            for origin, text, code_ranges in payloads:
                hit = compiled.search(text, code_ranges)
                if hit is not None:
                    condition, start, end = hit
                    record = ["ok", index, [condition, start, end, origin]]
                    break
        except Exception as exc:
            record = ["error", index, f"{type(exc).__name__}: {exc}"[:512]]
        print(json.dumps(record, ensure_ascii=True), flush=True)


def main():
    request = json.loads(sys.stdin.buffer.read().decode("utf-8", "surrogatepass"))
    if request.get("mode") == "cfg":
        return _cfg(request)
    payload = request["payload"]
    for index, item in enumerate(request["rules"]):
        try:
            rule = Rule(id=item["id"], source=item.get("source", ""), source_id="", source_rev="",
                        source_path="", upstream_url="", surface=Surface(item["surface"]),
                        predicate_kind=PredicateKind(item["kind"]), predicate=item["predicate"],
                        case_sensitive=item["case_sensitive"])
            runtime = compile_rule(rule)
            if rule.predicate_kind in (PredicateKind.REGEX, PredicateKind.STRUCTURED):
                hit = runtime.search(payload)
                span = [hit.start(), hit.end()] if hit else None
            else:
                hit = _search_substrings(rule, runtime, payload)
                span = [hit.start, hit.end] if hit else None
            record = ["ok", index, span]
        except Exception as exc:
            record = ["error", index, f"{type(exc).__name__}: {exc}"[:512]]
        print(json.dumps(record, ensure_ascii=True), flush=True)


if __name__ == "__main__":
    main()
