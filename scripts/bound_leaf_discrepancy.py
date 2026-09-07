"""Compare what the benchmark scanned with what the hook scans.

``scripts/prepare_tool_traffic.py`` joins a tool result's text blocks with
newlines and the benchmark scans one string. ``process`` walks the payload and
scans each string leaf on its own. Those are different evaluation procedures,
and a rule fingerprint does not record which one produced a measurement.

Re-extracting with the structure preserved would re-select from transcripts that
have changed, after the outcomes on this corpus are already known, so the
held-out claim would no longer be held out. This measures part of the gap on
the same fixed material instead. **It produces diagnostics, not bounds**, and
the reasons are worth reading before the numbers are quoted.

What an earlier version got wrong
---------------------------------

It simulated the split by recompiling anchored patterns with ``re.MULTILINE``,
and the review that found it listed why that fails: ``\\A`` and ``\\Z`` ignore
the flag, ``(?<!\\n)X`` and ``X(?!\\n)`` flip at a boundary the flag does not
touch, ``^X$(?![\\s\\S])`` keeps a lookahead that still sees the joined suffix,
and ``(?-m:^X$)`` switches the flag back off inside the pattern. Nothing
simulates a split reliably, so this performs one.

Performing it removes the need to simulate, and it does not make either number
a bound. Two further limits are load bearing.

**Splitting at every newline is not the hook's decomposition.** The extractor
joined blocks with newlines, but a block may contain newlines of its own, so
the real cuts are a *subset* of the newline positions. Cutting at all of them
destroys a match lying across lines within one block: ``\\Afoo\\nbar\\Z``
matches the leaf ``foo\\nbar`` and neither pass finds it. The all-lines probe
is therefore not an over-approximation either, and the middle number is a union
of two procedures rather than a count of anything.

**An assertion is not the only thing that can make a match vanish** once a leaf
is embedded in more text. An atomic group or possessive quantifier commits, so
``a(?>bc\\nx|b)c`` matches ``abc`` and not ``z\\nabc\\nx\\ny``, with no
assertion present at all. Removing an assertion that carries a quantifier also
changes what the remainder matches, because the quantifier lands on the token
before it: ``^ab(?=x){0}c$`` relaxes to ``ab{0}c``, which matches ``ac`` rather
than ``abc``, so the prune would discard a real match. :data:`UNSUPPORTED`
names these, and a pattern carrying one is probed without being pruned.

One argument survives and explains the result. ``\\b`` is a position with
``\\w`` on exactly one side, counting off-the-end as not-``\\w``; a newline is
not a word character, so the position just after one and the position at a
string start present the same left-hand context. A word boundary alone
therefore gains nothing from a newline split. That is a fact about the
assertion rather than about any rule carrying it, since the same rule can carry
something else.

What the two numbers are
------------------------

**newline-leaf** is the joined hits unioned with the all-lines probe, evaluated
with each rule's own flags and its own ``regex_all`` conjunction. Read it as
"this procedure found nothing extra", not as a leaf count and not as a bound.

**substring-leaf** removes every zero-width assertion and matches the remainder
against the joined text. For a pattern free of the :data:`UNSUPPORTED`
constructs *and of backreferences* the rewrite only widens what matches, so a
match on any contiguous substring implies a match of the remainder on the
whole; a pattern carrying one is counted as a candidate on every unit instead
of being rewritten. Loose by construction.

The backreference clause is not hypothetical: removing the lookahead from
``^(a)(?=(b))(bc)\\2$`` renumbers the groups, and the rewrite stops matching
``abcb``. It is excluded here rather than detected because the evaluator
rejects backreferences outright, so no accepted rule can carry one. That makes
the exclusion a property of what this runs on rather than of the rewrite, and a
caller reusing this helper on unscreened patterns has to check for itself.

Neither number covers content the corpus does not hold. The corpus records
``tool_result.content``; the hook walks ``tool_response``, whose other string
values, including ones as short as a block's own ``"text"`` type tag, were
never extracted. No computation on this corpus reaches them. **So neither
number is an upper bound on the deployed hook's firing rate, and neither may
be used as admission evidence.**
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from agent_defs import bundle  # noqa: E402
from agent_defs.evaluate import scan_trusted  # noqa: E402
from agent_defs.lanes import binomial_u95  # noqa: E402
from agent_defs.model import PredicateKind  # noqa: E402


def patterns_of(rule):
    """The regex texts a rule evaluates, and how they combine.

    ``regex_all`` matches only when every branch matches the *same* payload, so
    a split probe has to require them on one leaf rather than across leaves.
    """
    if rule.predicate_kind is PredicateKind.REGEX and isinstance(rule.predicate, str):
        return "any", [rule.predicate]
    if isinstance(rule.predicate, dict) and len(rule.predicate) == 1:
        mode, patterns = next(iter(rule.predicate.items()))
        return ("all" if mode == "regex_all" else "any"), list(patterns)
    if isinstance(rule.predicate, (list, tuple)):
        return "any", [p for p in rule.predicate if isinstance(p, str)]
    return "any", []


def flags_for(rule) -> int:
    """The flags ``evaluate.compile_rule`` uses, so a probe sees what ships."""
    return 0 if rule.case_sensitive else re.IGNORECASE


def class_body_end(pattern: str, start: int):
    """Index of the ``]`` closing the class opening at ``start``, or None.

    A ``]`` immediately after ``[`` or ``[^`` is a literal, which is how
    ``[]]`` and ``[^]]`` are written. Reading it as the terminator loses the
    rest of the class and, with it, any anchor after it.
    """
    index = start + 1
    if index < len(pattern) and pattern[index] == "^":
        index += 1
    if index < len(pattern) and pattern[index] == "]":
        index += 1
    while index < len(pattern):
        if pattern[index] == "\\":
            index += 2
            continue
        if pattern[index] == "]":
            return index
        index += 1
    return None


def close_paren(pattern: str, start: int):
    """Index just past the group opening at ``start``, or None if unbalanced."""
    depth, index = 0, start
    while index < len(pattern):
        char = pattern[index]
        if char == "\\":
            index += 2
            continue
        if char == "[":
            end = class_body_end(pattern, index)
            if end is None:
                return None
            index = end + 1
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index + 1
        index += 1
    return None


#: Constructs whose presence makes both the classification and the rewrite
#: below unsound, so a pattern carrying one is never pruned and always probed.
#:
#: An atomic group or a possessive quantifier commits, so a match inside a leaf
#: can disappear when the leaf is embedded in more text even with no assertion
#: anywhere: ``a(?>bc\\nx|b)c`` matches ``abc`` and not ``z\\nabc\\nx\\ny``.
#: Removing an assertion that carries a quantifier moves the quantifier onto
#: the preceding token, which changes what the remainder matches rather than
#: widening it: ``^ab(?=x){0}c$`` relaxes to ``ab{0}c``, matching ``ac`` and no
#: longer ``abc``. A conditional depends on whether a group participated. Round
#: 3 of the review built all three.
#:
#: Detection is a scan of the pattern text, so it works on an interpreter that
#: cannot compile what it finds. An atomic group and a possessive quantifier
#: are syntax errors before Python 3.11, and a rule carrying one would fail to
#: compile here long before this classification mattered; the scan still names
#: it rather than letting it look ordinary.
UNSUPPORTED = ("atomic group or possessive quantifier", "conditional",
               "quantified lookaround")


def after_inert(pattern: str, index: int) -> int:
    """Skip forward over what the parser may drop before a quantifier.

    Verbose mode ignores unescaped whitespace and ``#`` to end of line, and
    ``(?#...)`` is a comment under any flags. Whether whitespace is dropped
    depends on a flag this scan does not have, so it is skipped either way.
    In a pattern that is not verbose that only mistakes a widening rewrite for
    a narrowing one, and the cost of that is a rule probed without being pruned.
    """
    while index < len(pattern):
        if pattern[index].isspace():
            index += 1
        elif pattern.startswith("(?#", index):
            end = pattern.find(")", index)
            if end < 0:
                return index
            index = end + 1
        elif pattern[index] == "#":
            end = pattern.find("\n", index)
            index = len(pattern) if end < 0 else end + 1
        else:
            break
    return index


def unsupported_constructs(pattern: str) -> set:
    """Which :data:`UNSUPPORTED` constructs this pattern carries, if any.

    Errs towards saying yes. An escaped brace before a quantifier, ``\\}+``,
    reads here as a possessive ``}+``, and the cost of that is a rule probed
    without being pruned rather than one wrongly skipped.

    A quantifier cannot follow ``^``, ``$``, ``\\b`` or ``\\A`` in a pattern
    that compiles at all, so the quantified case only has to be checked for
    lookaround groups.

    The quantifier need not be adjacent to the group. Round 4 of the review
    reached past an adjacency check with ``(?x)^ab(?=x) {0} c$`` and
    ``^ab(?=x)(?#comment){0}c$``, both of which compile, match the leaf ``abc``,
    and lose that match in the joined text. :func:`after_inert` skips what the
    parser may drop in between.
    """
    found, index = set(), 0
    while index < len(pattern):
        char = pattern[index]
        if char == "\\":
            index += 2
            continue
        if char == "[":
            end = class_body_end(pattern, index)
            if end is None:
                return {"unparseable character class"}
            index = end + 1
            continue
        if pattern.startswith("(?>", index):
            found.add(UNSUPPORTED[0])
        elif pattern.startswith("(?(", index):
            found.add(UNSUPPORTED[1])
        elif char == "+" and index and pattern[index - 1] in "*+?}":
            found.add(UNSUPPORTED[0])
        else:
            head = pattern[index:index + 4]
            if head[:3] in ("(?=", "(?!") or head in ("(?<=", "(?<!"):
                end = close_paren(pattern, index)
                if end is None:
                    return {"unbalanced group"}
                quantifier = after_inert(pattern, end)
                if quantifier < len(pattern) and pattern[quantifier] in "*+?{":
                    found.add(UNSUPPORTED[2])
                index = end
                continue
        index += 1
    return found


def strip_assertions(pattern: str):
    """Remove every zero-width assertion, returning ``(relaxed, kinds)``.

    ``relaxed`` is None when the pattern carries an :data:`UNSUPPORTED`
    construct, cannot be walked, or does not compile once rewritten. The caller
    treats that rule as always a candidate rather than quietly dropping it,
    because this rewrite is used only as a necessary condition and a rewrite
    that can lose a match is a prune that can hide one.
    """
    if unsupported_constructs(pattern):
        return None, {"unsupported"}
    out, kinds, index = [], set(), 0
    while index < len(pattern):
        char = pattern[index]
        if char == "\\" and index + 1 < len(pattern):
            nxt = pattern[index + 1]
            if nxt in "AbBZz":
                kinds.add("\\" + nxt)
                index += 2
                continue
            out.append(pattern[index:index + 2])
            index += 2
            continue
        if char == "[":
            end = class_body_end(pattern, index)
            if end is None:
                return None, kinds
            out.append(pattern[index:end + 1])
            index = end + 1
            continue
        if char in "^$":
            kinds.add(char)
            index += 1
            continue
        head = pattern[index:index + 4]
        if head[:3] in ("(?=", "(?!") or head in ("(?<=", "(?<!"):
            kinds.add(head[:4] if head[:3] == "(?<" else head[:3])
            end = close_paren(pattern, index)
            if end is None:
                return None, kinds
            index = end
            continue
        out.append(char)
        index += 1
    relaxed = "".join(out)
    try:
        re.compile(relaxed)
    except re.error:
        return None, kinds
    return relaxed, kinds


def probe(patterns, mode, flags, extra=0):
    """A callable testing a rule's own logic over one string."""
    compiled = [re.compile(p, flags | extra) for p in patterns]
    if mode == "all":
        return lambda text: all(m.search(text) for m in compiled)
    return lambda text: any(m.search(text) for m in compiled)


def split_probe(patterns, mode, flags):
    """The same logic, but required to be satisfied within a single line."""
    compiled = [re.compile(p, flags) for p in patterns]
    if mode == "all":
        return lambda lines: any(all(m.search(line) for m in compiled) for line in lines)
    return lambda lines: any(m.search(line) for m in compiled for line in lines)


def hits(text, rules):
    if not text or not rules:
        return set()
    found = scan_trusted(text, rules,
                         max_bytes=max(1, len(text.encode("utf-8", "surrogatepass"))))
    if not found.complete or found.rules_evaluated != len(rules):
        raise RuntimeError("incomplete scan; refusing a quiet measurement")
    return {f.rule_id for f in found.findings}


def build_probes(rules):
    """Relaxed and split probes for the rules that can gain, plus a census.

    A rule gains nothing from a split when its pattern has no zero-width
    assertion and no :data:`UNSUPPORTED` construct: everything left is
    consuming, so a match inside a leaf matches the same characters at the same
    offsets in text that contains the leaf. Those rules are skipped. Every
    other rule is probed, and one carrying an unsupported construct is probed
    without being pruned, because the prune's rewrite is not valid for it.
    """
    relaxed, splits = [], {}
    census: dict[str, list] = {}
    unprunable = []
    for rule in rules:
        mode, patterns = patterns_of(rule)
        if not patterns:
            continue
        flags = flags_for(rule)
        stripped, kinds = [], set()
        for pattern in patterns:
            one, found = strip_assertions(pattern)
            stripped.append(one)
            kinds |= found | unsupported_constructs(pattern)
        for kind in sorted(kinds):
            census.setdefault(kind, []).append(rule.id)
        if not kinds:
            continue
        splits[rule.id] = split_probe(patterns, mode, flags)
        if any(one is None for one in stripped):
            unprunable.append(rule.id)
            relaxed.append((rule.id, lambda _text: True))
        else:
            relaxed.append((rule.id, probe(stripped, mode, flags)))
    return relaxed, splits, census, unprunable


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--units", type=Path, required=True)
    parser.add_argument("--rules", type=Path, required=True)
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--units-from", default="",
                        help="how the units file was produced, recorded verbatim in the report")
    args = parser.parse_args(argv)

    raw_units = args.units.read_bytes()
    raw_rules = args.rules.read_bytes()
    rules = bundle.load(args.rules)
    relaxed, splits, census, unprunable = build_probes(rules)
    print(f"rules: {len(rules)}; probed: {len(splits)}; "
          f"probed without pruning: {len(unprunable)}", flush=True)
    for kind, ids in sorted(census.items()):
        print(f"  {kind:6s} {len(ids):4d} rules", flush=True)

    trials = joined_hits = newline_hits = substring_hits = 0
    gained_newline: dict[str, int] = {}
    gained_substring: dict[str, int] = {}
    for line in raw_units.splitlines():
        text = json.loads(line)["text"]
        trials += 1
        found = hits(text, rules)
        candidates = {rid for rid, test in relaxed if rid not in found and test(text)}
        lines = text.split("\n")
        confirmed = {rid for rid in candidates if splits[rid](lines)}
        joined_hits += bool(found)
        newline_hits += bool(found | confirmed)
        substring_hits += bool(found | candidates)
        for rule_id in confirmed:
            gained_newline[rule_id] = gained_newline.get(rule_id, 0) + 1
        for rule_id in candidates:
            gained_substring[rule_id] = gained_substring.get(rule_id, 0) + 1

    report = {
        # Identity, so a committed result names the material and the rule set
        # it describes rather than a path that can be repointed.
        "inputs": {
            "units": str(args.units), "units_sha256": hashlib.sha256(raw_units).hexdigest(),
            "units_from": args.units_from,
            "rules": str(args.rules), "rules_sha256": hashlib.sha256(raw_rules).hexdigest(),
            "rule_count": len(rules),
            "rule_ids_sha256": hashlib.sha256(
                "\n".join(sorted(r.id for r in rules)).encode()).hexdigest(),
            "python": sys.version.split()[0],
        },
        "trials": trials,
        "joined": {"hits": joined_hits, "nominal_u95": binomial_u95(trials, joined_hits)},
        "newline_leaf_diagnostic": {"hits": newline_hits,
                                    "nominal_u95": binomial_u95(trials, newline_hits),
                                    "rules_gaining": gained_newline},
        "substring_leaf_diagnostic": {"hits": substring_hits,
                                      "nominal_u95": binomial_u95(trials, substring_hits),
                                      "rules_gaining": gained_substring},
        "hook_upper_bound": None,
        "leaf_decomposition_bound": None,
        "construct_census": {k: len(v) for k, v in sorted(census.items())},
        "probed_rules": len(splits),
        "probed_without_pruning": unprunable,
        "method": {
            "newline_leaf": ("joined hits unioned with an all-lines probe, evaluated with each "
                             "rule's own flags and conjunction. NOT an exact leaf count and NOT "
                             "a bound: the extractor joined blocks with newlines but a block can "
                             "contain newlines of its own, so this cuts at a superset of the real "
                             "boundaries and destroys a match that spans lines inside one block"),
            "substring_leaf": ("the same rules matched with every zero-width assertion removed. "
                               "The rewrite is sound only for patterns free of atomic groups, "
                               "possessive quantifiers, conditionals and quantified lookarounds; "
                               "a pattern carrying one is counted as a candidate on every unit "
                               "rather than rewritten. Loose by construction"),
            "not_covered": ("string values of tool_response the extractor never rendered into "
                            "tool_result.content; no computation on this corpus reaches them, "
                            "so neither number is a bound on the deployed hook and neither is "
                            "admission evidence"),
        },
    }
    print(json.dumps(report, indent=1))
    if args.out:
        args.out.write_bytes((json.dumps(report, indent=1) + "\n").encode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
