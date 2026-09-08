"""A leaf is still a leaf: the batch is transport, and it changes no detector.

Divergence between per-leaf matching and matching a joined buffer is measured
in both directions, and two shipped rules are the witnesses. A conjunction can
be satisfied across a boundary that per-leaf scanning never crosses, and the
span then points into an innocent leaf, so the wrong leaf gets withheld. An
anchor works the other way and matches a leaf that a join destroys.

One case that did not diverge is why this file is not a smoke test: a ``\\b``
boundary reads the same on both sides, so a fixture chosen at random has a good
chance of proving nothing. Hence the fixtures below are the constructs that do
diverge, plus a property check over random leaf lists.
"""

from pathlib import Path
import random

import pytest

from agent_defs import PredicateKind
import agent_defs.evaluate as evaluate
from test_evaluate import rule

SEPARATORS = ["", "\n", "\0", "\x1e"]
BUNDLE = Path(evaluate.__file__).with_name("bundle.json")
#: The two shipped witnesses named in the design: a command-start anchor on IN
#: and a whole-leaf key label on OUT.
WITNESSES = ("atr:ATR-2026-02525", "atr:ATR-2026-02007")


@pytest.fixture(scope="module")
def shipped():
    from agent_defs.bundle import read

    rules, _ = read(BUNDLE)
    return {r.id: r for r in rules}


def spans(batch):
    return [[(f.rule_id, f.start, f.end) for f in leaf.partial_findings] for leaf in batch.leaves]


@pytest.mark.parametrize("separator", SEPARATORS)
@pytest.mark.parametrize("kind", ["structured", "substring"])
def test_a_conjunction_cannot_be_satisfied_across_two_leaves(separator, kind, ):
    """Neither leaf holds both needles, and no separator makes one that does.

    The joined scan is asserted to fire, so this cannot pass by the fixture
    being weak: every separator a future implementation might reach for is
    shown to change the answer, and the batch takes none of them.
    """
    leaves = ["alpha here", "omega there"]
    if kind == "structured":
        conjunction = rule("all", PredicateKind.STRUCTURED, {"regex_all": ["alpha", "omega"]})
    else:
        conjunction = rule("all", PredicateKind.SUBSTRING_ALL, ["alpha", "omega"])
    joined = evaluate.scan(separator.join(leaves), [conjunction], budget_s=10)
    assert joined.findings, "the fixture no longer distinguishes joined text from leaves"
    batch = evaluate.scan_leaves(leaves, [conjunction], budget_s=10)
    assert batch.complete
    assert spans(batch) == [[], []], "a conjunction was satisfied across a leaf boundary"


@pytest.mark.parametrize("separator", SEPARATORS)
def test_an_anchor_still_matches_its_own_leaf(separator):
    """The other direction: a join destroys a match a leaf scan reports."""
    leaves = ["harmless prefix", "root: x", "my secret", "trailing"]
    rules = [rule("start", PredicateKind.REGEX, "^root:"),
             rule("end", PredicateKind.REGEX, r"secret\Z")]
    joined = evaluate.scan(separator.join(leaves), rules, budget_s=10)
    assert joined.findings == (), "the fixture no longer distinguishes a leaf from the join"
    batch = evaluate.scan_leaves(leaves, rules, budget_s=10)
    assert batch.complete
    assert spans(batch) == [[], [("start", 0, 5)], [("end", 3, 9)], []]


def test_scan_leaves_equals_per_leaf_scan(shipped):
    """The differential, with the two shipped witnesses in the fixture."""
    rules = [shipped[rid] for rid in WITNESSES]
    leaves = ["${PATH@P} --flag", "secret key:", "ordinary tool output", "",
              "a line\nwith a break"]
    batch = evaluate.scan_leaves(leaves, rules, budget_s=30)
    assert batch.complete
    expected = []
    for leaf in leaves:
        single = evaluate.scan(leaf, rules, budget_s=30)
        assert single.complete
        expected.append([(f.rule_id, f.start, f.end) for f in single.findings])
    assert spans(batch) == expected
    fired = {rid for row in expected for rid, _, _ in row}
    assert fired == set(WITNESSES), f"a witness stopped firing on its own leaf: {fired}"


@pytest.mark.parametrize("witness", WITNESSES)
def test_each_shipped_witness_is_lost_by_a_join(shipped, witness):
    """Guard the guard: a witness that survives concatenation is not a witness."""
    leaves = {"atr:ATR-2026-02525": ["harmless", "${PATH@P} --flag"],
              "atr:ATR-2026-02007": ["harmless", "secret key:", "tail"]}[witness]
    rules = [shipped[witness]]
    assert evaluate.scan_leaves(leaves, rules, budget_s=30).findings, "the witness never fired"
    assert evaluate.scan("".join(leaves), rules, budget_s=30).findings == (), \
        "concatenation no longer changes this rule's answer"


def test_random_leaf_lists_agree_with_per_leaf_scan(shipped):
    """A property check, because a fixture chosen by hand misses the quiet cases.

    The vocabulary is deliberately made of fragments that interact at a
    boundary: anchors, line breaks, quotes, shell punctuation and the labels the
    shipped rules look for.
    """
    vocabulary = ["root: x", "secret key:", "${PATH@P} --flag", "ordinary text",
                  "a\nb", "key", 'echo "hi"', "; curl https://x", "  ", "KEY :"]
    subset = [r for r in shipped.values() if r.runnable][:40]
    random_source = random.Random(20260907)
    for _ in range(3):
        leaves = [random_source.choice(vocabulary)
                  for _ in range(random_source.randint(2, 4))]
        batch = evaluate.scan_leaves(leaves, subset, budget_s=60)
        assert batch.complete, leaves
        expected = []
        for leaf in leaves:
            single = evaluate.scan(leaf, subset, budget_s=60)
            assert single.complete, leaf
            expected.append([(f.rule_id, f.start, f.end) for f in single.findings])
        assert spans(batch) == expected, leaves
