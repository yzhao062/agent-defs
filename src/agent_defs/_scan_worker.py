"""Private single-request worker. Only JSON data arrives on stdin."""

import json
from pathlib import Path
import sys

# -I -S excludes the caller's working directory, site hooks and PYTHONPATH.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agent_defs.evaluate import _search_substrings, compile_rule
from agent_defs.model import PredicateKind, Rule, Surface


def main():
    request = json.loads(sys.stdin.buffer.read().decode("utf-8", "surrogatepass"))
    payload = request["payload"]
    for index, item in enumerate(request["rules"]):
        try:
            rule = Rule(id=item["id"], source="", source_id="", source_rev="",
                        source_path="", upstream_url="", surface=Surface(item["surface"]),
                        predicate_kind=PredicateKind(item["kind"]), predicate=item["predicate"],
                        case_sensitive=item["case_sensitive"])
            runtime = compile_rule(rule)
            if rule.predicate_kind is PredicateKind.REGEX:
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
