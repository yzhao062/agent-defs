"""The leaf-discrepancy probes, against the constructs that broke the last one.

Round 1 of this diagnostic simulated a per-leaf scan by recompiling anchored
patterns with ``re.MULTILINE`` and called the result an upper bound. The round
2 review produced seven runnable patterns that match a leaf and get nothing
from that pass. They are reproduced here, with one more character-class form,
as the acceptance test for the replacement, which performs a real split
instead of simulating one.
"""

import importlib.util
from pathlib import Path
import random
import re

import pytest

# The "[[]" fixture is exactly the literal-bracket class the old parser lost;
# Python warns that it looks like a nested set, and that warning is the point.
pytestmark = pytest.mark.filterwarnings("ignore::FutureWarning")

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "bound_leaf_discrepancy.py"
LEAF = "REVIEW_MARKER"
PREFIX, SUFFIX = "ordinary prefix", "ordinary suffix"

#: (pattern, leaf). Each matches its leaf and not the newline-joined text.
#: Python spells the absolute end anchor ``\Z``; ``\z`` does not compile at
#: all here, so a rule carrying one never reaches a scan to begin with.
ESCAPES_A_FLAG = [
    (r"\AREVIEW_MARKER", LEAF),
    (r"REVIEW_MARKER\Z", LEAF),
    (r"(?<!\n)REVIEW_MARKER", LEAF),
    (r"REVIEW_MARKER(?!\n)", LEAF),
    (r"^REVIEW_MARKER$(?![\s\S])", LEAF),
    (r"(?-m:^REVIEW_MARKER$)", LEAF),
    (r"[[]REVIEW_MARKER$", "[" + LEAF),
    (r"[^]]REVIEW_MARKER$", "x" + LEAF),
]


@pytest.fixture(scope="module")
def probes():
    spec = importlib.util.spec_from_file_location("bound_leaf_under_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def joined(leaf):
    return f"{PREFIX}\n{leaf}\n{SUFFIX}"


@pytest.mark.parametrize("pattern,leaf", ESCAPES_A_FLAG)
def test_the_fixture_really_does_distinguish_a_leaf_from_the_joined_text(pattern, leaf):
    """Guard the guard: a fixture that matches both sides proves nothing."""
    compiled = re.compile(pattern)
    assert compiled.search(leaf)
    assert not compiled.search(joined(leaf))


@pytest.mark.parametrize("pattern,leaf", ESCAPES_A_FLAG)
def test_each_is_routed_to_the_split_rather_than_to_a_flag(probes, pattern, leaf):
    _, kinds = probes.strip_assertions(pattern)
    assert kinds, "no assertion detected, so this rule would get no split probe"


@pytest.mark.parametrize("pattern,leaf", ESCAPES_A_FLAG)
def test_the_split_probe_finds_what_the_joined_scan_misses(probes, pattern, leaf):
    text = joined(leaf)
    probe = probes.split_probe([pattern], "any", 0)
    assert probe(text.split("\n"))
    assert not probes.probe([pattern], "any", 0)(text)


@pytest.mark.parametrize("pattern,leaf", ESCAPES_A_FLAG)
def test_the_relaxed_pattern_is_a_necessary_condition_for_the_split(probes, pattern, leaf):
    """The prune must never drop a candidate the split would have confirmed."""
    relaxed, _ = probes.strip_assertions(pattern)
    assert relaxed is not None
    assert probes.probe([relaxed], "any", 0)(joined(leaf))


def test_a_word_boundary_gains_nothing_from_a_newline_split(probes):
    """Stated in the module docstring; checked rather than asserted."""
    pattern = r"\bREVIEW_MARKER\b"
    text = joined(LEAF)
    assert probes.probe([pattern], "any", 0)(text)
    assert probes.split_probe([pattern], "any", 0)(text.split("\n"))


def test_a_class_starting_with_a_bracket_does_not_swallow_the_rest(probes):
    assert probes.class_body_end("[]]x", 0) == 2
    assert probes.class_body_end("[^]]x", 0) == 3
    assert probes.class_body_end("[[]x", 0) == 2
    assert probes.class_body_end(r"[\]]x", 0) == 3
    assert probes.class_body_end("[abc", 0) is None


def test_a_conjunction_must_be_satisfied_within_one_leaf(probes):
    """regex_all means the same payload, so two lines are not a match."""
    patterns = [r"^alpha$", r"^beta$"]
    lines = ["alpha", "beta"]
    assert not probes.split_probe(patterns, "all", 0)(lines)
    assert probes.split_probe(patterns, "any", 0)(lines)
    assert probes.split_probe([r"^alpha$", r"^alpha$"], "all", 0)(lines)


def test_case_sensitivity_follows_the_rule_rather_than_the_probe(probes):
    class Fake:
        case_sensitive = True

    assert probes.flags_for(Fake()) == 0
    Fake.case_sensitive = False
    assert probes.flags_for(Fake()) == re.IGNORECASE


#: Round 3's counterexamples to the rewrite itself, and to the premise that
#: only a zero-width assertion can make a leaf match vanish in the joined text.
#: Each must be refused from pruning rather than rewritten.
UNSOUND_TO_STRIP = [
    (r"^ab(?=x){0}c$", "abc", "quantified lookaround"),
    (r"(?>(?!\A)a|ab)c", "abc", "atomic group or possessive quantifier"),
    (r"a(?>bc\nx|b)c", "abc", "atomic group or possessive quantifier"),
    (r"(?(1)a|b)c", "bc", "conditional"),
    (r"ab++c", "abc", "atomic group or possessive quantifier"),
]


@pytest.mark.parametrize("pattern,leaf,kind", UNSOUND_TO_STRIP)
def test_a_pattern_the_rewrite_cannot_handle_is_refused_not_rewritten(probes, pattern, leaf, kind):
    assert kind in probes.unsupported_constructs(pattern)
    relaxed, kinds = probes.strip_assertions(pattern)
    assert relaxed is None, (
        f"{pattern!r} was rewritten to {relaxed!r}; the prune would then decide "
        f"whether to probe it, and the rewrite is not valid here")
    assert kinds == {"unsupported"}


@pytest.mark.parametrize("pattern,leaf,kind", UNSOUND_TO_STRIP)
def test_the_counterexample_really_does_lose_its_match_when_rewritten(probes, pattern, leaf, kind):
    """Guard the guard, for the two whose rewrite is the actual failure."""
    if kind != "quantified lookaround":
        return
    naive = re.sub(r"\(\?=x\)", "", pattern)
    assert re.compile(pattern).search(leaf)
    assert not re.compile(naive).search(leaf)


def test_an_unprunable_rule_is_still_probed(probes):
    """Refusing the rewrite must widen the probe, not silence it.

    The fixture is a conditional rather than the atomic group used above,
    because ``build_probes`` compiles what it is given and ``(?>`` is a syntax
    error before Python 3.11. The two are the same case here: both are in
    ``UNSUPPORTED``, so both take the unprunable path.
    """

    class Fake:
        id = "t:conditional"
        case_sensitive = False
        predicate_kind = probes.PredicateKind.REGEX
        predicate = r"(a)?(?(1)b|c)"

    relaxed, splits, census, unprunable = probes.build_probes([Fake()])
    assert unprunable == ["t:conditional"]
    assert "t:conditional" in splits
    # The stand-in probe admits every unit, so nothing is pruned away.
    assert relaxed[0][1]("anything at all") is True


def test_the_string_level_detection_needs_no_interpreter_support(probes):
    """Detection is a scan, so it holds on a Python that cannot compile these.

    CI runs 3.9, where an atomic group and a possessive quantifier are syntax
    errors. Classification must still refuse them, because the script's job is
    to decide whether a rule can be pruned, not to run every pattern.
    """
    for pattern in (r"a(?>bc|b)c", r"ab++c", r"a{2,3}+b"):
        assert probes.unsupported_constructs(pattern) == {
            "atomic group or possessive quantifier"}
        assert probes.strip_assertions(pattern) == (None, {"unsupported"})


def test_stripping_never_loses_a_substring_match(probes):
    """If a pattern matches any contiguous substring, the stripped one matches.

    The atom list carries the constructs round 3 used against the rewrite, so a
    regression that starts rewriting them shows up here rather than only in the
    targeted cases above.
    """
    atoms = ["a", "b", "ab", "[ab]", ".", r"\w", r"\s", "(?:ab)", "a?", "a*", "b+",
             r"\b", r"\B", "^", "$", "(?=a)", "(?!a)", "(?<=a)", "(?<!a)",
             r"\A", r"\Z", "(?:a|b)", "[]]", "[^]]",
             "(?>a|ab)", "a++", "b*+", "(?=a){0}", "(?!a){2}", "{0}"]
    random.seed(20260906)
    checked = refused = 0
    for _ in range(6000):
        pattern = "".join(random.choice(atoms) for _ in range(random.randint(1, 4)))
        # Classification first, and independent of whether this interpreter can
        # compile the pattern. Before Python 3.11 an atomic group is a syntax
        # error, so ordering the compile first would have made the refusal
        # count collapse on 3.9 and this test pass for the wrong reason.
        relaxed, _ = probes.strip_assertions(pattern)
        if relaxed is None:
            refused += 1
            continue
        try:
            strict = re.compile(pattern)
        except re.error:
            continue
        loose = re.compile(relaxed, re.MULTILINE)
        text = "".join(random.choice("ab\n c]") for _ in range(random.randint(0, 6)))
        for i in range(len(text) + 1):
            for j in range(i, len(text) + 1):
                if strict.search(text[i:j]):
                    checked += 1
                    assert loose.search(text), (pattern, relaxed, text, text[i:j])
                    break
            else:
                continue
            break
    assert checked > 500, f"only {checked} substring matches exercised"
    assert refused > 100, f"only {refused} patterns refused; the risky atoms are not landing"
