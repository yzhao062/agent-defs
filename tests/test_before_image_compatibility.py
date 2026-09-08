"""What ``scan`` answered before the batch existed, pinned as literal values.

Every expectation here is the answer the single-payload implementation at
``add5dee`` gave, written out rather than computed. Comparing ``scan`` against
``scan_leaves`` cannot establish backward compatibility, because both are the
new code: a shared mistake agrees with itself. Callers that predate the batch
read these verdicts, ``bench`` and ``calibrate`` among them.

Two behaviours reached review as regressions and are pinned here so they cannot
return quietly.

The byte debit at a multi-byte boundary. The old traversal charged the leaf the
bytes of its first ``remaining`` *characters*, capped at ``remaining``; the
batch first charged only the bytes it retained. With ``["abé", "Z"]`` and three
bytes those differ: capping keeps ``"ab"`` and costs two, so the second spelling
leaves one byte, schedules ``"Z"``, and finds a match the old path never looked
for. That is a detector change, and this one is a transport change.

The scalar zero-allowance case. ``scan_leaves`` declines a leaf once its
allowance reaches zero, which is right for a batch. ``scan`` never did: it
capped, then scanned whatever it had, including the empty string.
"""

from agent_defs import PredicateKind
from agent_defs.evaluate import scan, scan_leaves
from test_evaluate import rule

BUDGET = 30


def test_an_empty_payload_with_no_allowance_is_complete_and_untruncated():
    """The before-image: complete, untruncated, one rule evaluated, span [0, 0].

    Routing this through the batch's decline policy reported nothing evaluated,
    truncated input and an incomplete scan, which is a different answer to the
    same question.
    """
    result = scan("", [rule("r", PredicateKind.REGEX, "^$")], max_bytes=0, budget_s=BUDGET)
    assert result.complete is True
    assert result.truncated_input is False
    assert result.rules_evaluated == 1
    assert result.rules_skipped_budget == 0
    assert [(f.start, f.end) for f in result.findings] == [(0, 0)]


def test_an_empty_payload_with_no_rules_and_no_allowance_is_still_complete():
    result = scan("", [], max_bytes=0, budget_s=BUDGET)
    assert result.complete is True
    assert result.truncated_input is False
    assert result.rules_evaluated == 0


def test_a_nonempty_payload_with_no_allowance_still_evaluates_the_capped_empty_string():
    """Incomplete because the input was cut, and the rule still ran on what was left."""
    result = scan("abc", [rule("r", PredicateKind.REGEX, "^$")], max_bytes=0, budget_s=BUDGET)
    assert result.complete is False
    assert result.truncated_input is True
    assert result.rules_evaluated == 1
    assert [(f.start, f.end) for f in result.partial_findings] == [(0, 0)]


def test_truncation_comes_from_the_cap_and_not_from_scheduling():
    result = scan("abc", [rule("r", PredicateKind.SUBSTRING_ANY, ["c"])],
                  max_bytes=2, budget_s=BUDGET)
    assert result.truncated_input is True
    assert result.complete is False
    assert result.rules_evaluated == 1
    assert result.partial_findings == ()


def test_an_ordinary_scalar_scan_is_unchanged():
    result = scan("abc", [rule("r", PredicateKind.SUBSTRING_ANY, ["b"])],
                  max_bytes=100, budget_s=BUDGET)
    assert result.complete is True
    assert result.truncated_input is False
    assert result.rules_evaluated == 1
    assert [(f.start, f.end) for f in result.findings] == [(1, 2)]


def test_a_zero_budget_scalar_scan_is_incomplete_rather_than_clean():
    result = scan("abc", [rule("r", PredicateKind.SUBSTRING_ANY, ["b"])],
                  max_bytes=100, budget_s=0)
    assert result.complete is False


def test_the_multibyte_debit_leaves_the_next_leaf_unafforded():
    """Three bytes, a two-byte character at the boundary, and nothing left over.

    The old traversal charged three and declined ``"Z"``. Charging the two bytes
    actually retained would leave one, schedule ``"Z"``, and report a finding
    the before-image never produced.
    """
    batch = scan_leaves(["abé", "Z"],
                        [rule("z", PredicateKind.SUBSTRING_ANY, ["Z"], case_sensitive=True)],
                        max_bytes=3, budget_s=BUDGET)
    assert [leaf.scheduled for leaf in batch.leaves] == [True, False]
    assert [f for leaf in batch.leaves for f in leaf.partial_findings] == []


def test_the_debit_still_admits_a_second_leaf_when_the_bytes_are_there():
    """The control: the rule above must not be a blanket refusal of later leaves."""
    batch = scan_leaves(["ab", "Z"],
                        [rule("z", PredicateKind.SUBSTRING_ANY, ["Z"], case_sensitive=True)],
                        max_bytes=3, budget_s=BUDGET)
    assert [leaf.scheduled for leaf in batch.leaves] == [True, True]
    assert [(f.start, f.end) for leaf in batch.leaves for f in leaf.partial_findings] == [(0, 1)]
