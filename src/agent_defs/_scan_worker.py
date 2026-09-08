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


#: The protocol this worker speaks, as a literal rather than an import. A
#: half-installed tree whose evaluator moved on must fail closed here, and an
#: imported constant would agree with itself.
_PROTOCOL = 2


def _emit(record):
    print(json.dumps(record, ensure_ascii=True), flush=True)


def _leaves(request):
    """Sweep every rule over every leaf, rule-major, one row at a time.

    Compilation is hoisted out of the leaf loop, which carries the saving, and
    stays inside the rule loop, which carries the incrementality: a kill still
    leaves the rows that already finished, and their hits, on the wire.

    A row does not stop at its first hit. Withholding is decided per leaf, so
    every leaf must receive every rule's verdict.
    """
    leaves = request["leaves"]
    for index, item in enumerate(request["rules"]):
        try:
            rule = Rule(id=item["id"], source=item.get("source", ""), source_id="", source_rev="",
                        source_path="", upstream_url="", surface=Surface(item["surface"]),
                        predicate_kind=PredicateKind(item["kind"]), predicate=item["predicate"],
                        case_sensitive=item["case_sensitive"])
            runtime = compile_rule(rule)
        except Exception as exc:
            _emit(["err", index, f"{type(exc).__name__}: {exc}"[:512]])
            continue
        swept = True
        for leaf_index, leaf in enumerate(leaves):
            try:
                if rule.predicate_kind in (PredicateKind.REGEX, PredicateKind.STRUCTURED):
                    hit = runtime.search(leaf)
                    span = [hit.start(), hit.end()] if hit else None
                else:
                    hit = _search_substrings(rule, runtime, leaf)
                    span = [hit.start, hit.end] if hit else None
            except Exception as exc:
                _emit(["err", index, f"{type(exc).__name__}: {exc}"[:512]])
                swept = False
                break
            if span is not None:
                _emit(["hit", index, leaf_index, span[0], span[1]])
        if swept:
            _emit(["done", index, len(leaves)])


def main():
    # Read stdin to EOF before the first byte of output. This is what makes a
    # pipe deadlock structurally impossible now that a request carries every
    # leaf of an event: the worker cannot fill its stdout pipe while the parent
    # is still writing stdin, because it has not started writing.
    request = json.loads(sys.stdin.buffer.read().decode("utf-8", "surrogatepass"))
    mode = request.get("mode")
    if mode == "cfg":
        return _cfg(request)
    # Fail closed and loudly on anything else: no frame, nonzero exit, and the
    # parent reports worker failure rather than an empty scan.
    if request.get("protocol") != _PROTOCOL or mode != "leaves":
        raise SystemExit(2)
    if request.get("stride") != len(request["leaves"]):
        raise SystemExit(2)
    return _leaves(request)


if __name__ == "__main__":
    main()
