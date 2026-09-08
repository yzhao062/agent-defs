"""Parent-side frame validation, against a worker the test writes.

The accounting is the invariant that fails open, so it gets the adversarial
worker rather than the friendly one. ``_run_worker`` is faked here so a stream
no real worker would produce can be handed to the reader on purpose: a
completion claim it never earned, a pair repeated, a row terminated twice, a
span belonging to another leaf. Everything these check is decided by the parent
from the leaves and the schedule it already holds, and nothing is learned from
the worker.

The one thing no protocol over a channel the worker controls can catch is a
worker that says ``done`` after sweeping one leaf. That check is behavioural and
lives in ``test_scan_leaves.py``.
"""

import json

import pytest

from agent_defs import PredicateKind
import agent_defs.evaluate as evaluate
from test_evaluate import rule

LEAVES = ["leaf zero", "leaf one", "leaf two", "leaf three", "leaf four"]


def needles(count):
    """Rules whose schedule order is their id order, so a test can name a row."""
    return [rule(f"r{index}", PredicateKind.SUBSTRING_ANY, ["leaf"]) for index in range(count)]


def stream(*rows):
    return b"".join(json.dumps(row, ensure_ascii=True).encode() + b"\n" for row in rows)


def worker(monkeypatch, output, *, timed_out=False, returncode=0, error=None):
    """Replace the child with a fixed answer, and keep the request it was sent."""
    sent = {}

    def run(request, deadline):
        sent["request"] = json.loads(request.decode("utf-8", "surrogatepass"))
        return output, timed_out, returncode, error

    monkeypatch.setattr(evaluate, "_run_worker", run)
    return sent


def scanned(monkeypatch, output, *, rules=6, leaves=LEAVES, **kwargs):
    sent = worker(monkeypatch, output, **kwargs)
    return evaluate.scan_leaves(leaves, needles(rules), budget_s=5), sent


@pytest.mark.parametrize("shape", ["per_pair_terminator", "rule_index_advances"])
def test_a_worker_that_finishes_one_leaf_is_not_complete(monkeypatch, shape):
    """Six rules, five leaves, and a worker that swept leaf 0 only.

    This is the fail-open case the whole protocol exists for. A rule-shaped
    completion count would read six completions here, compute nothing skipped,
    and report a clean scan of one leaf out of five. Both spellings a leaf-major
    port produces are refused, and neither leaves a resolved pair behind.
    """
    if shape == "per_pair_terminator":
        # It terminates what it actually swept: one leaf, not the row.
        output = stream(*[["done", index, 1] for index in range(6)])
    else:
        # It advances the rule index inside leaf 0, which no terminated row did.
        output = stream(["hit", 0, 0, 0, 4], ["hit", 1, 0, 0, 4], ["hit", 2, 0, 0, 4])
    batch, _ = scanned(monkeypatch, output)
    assert batch.worker_error == "invalid worker response"
    assert batch.pairs_resolved == 0
    assert not batch.complete
    with pytest.raises(evaluate.IncompleteScanError):
        batch.findings


def test_a_fabricated_row_terminator_still_leaves_the_batch_short(monkeypatch):
    """Two honest rows out of six, and the arithmetic says so in pair terms."""
    batch, _ = scanned(monkeypatch, stream(
        ["hit", 0, 2, 0, 4], ["done", 0, 5],
        ["hit", 1, 4, 0, 4], ["done", 1, 5]))
    assert batch.rules_scheduled == 6 and batch.leaves_scheduled == 5
    assert batch.pairs_scheduled == 30
    assert batch.pairs_resolved == 10
    assert batch.pairs_skipped_budget == 20
    assert not batch.complete
    with pytest.raises(evaluate.IncompleteScanError):
        batch.findings
    assert [f.rule_id for f in batch.leaves[2].partial_findings] == ["r0"]
    assert [f.rule_id for f in batch.leaves[4].partial_findings] == ["r1"]


def test_repeated_frames_for_one_pair_are_refused(monkeypatch):
    """Thirty copies of one pair are one pair, and the reader counts positions."""
    batch, _ = scanned(monkeypatch, stream(*([["hit", 0, 0, 0, 4]] * 30)))
    assert batch.worker_error == "invalid worker response"
    assert batch.pairs_resolved == 0
    assert not batch.complete


def test_rows_out_of_order_are_refused(monkeypatch):
    batch, _ = scanned(monkeypatch, stream(["done", 1, 5], ["done", 0, 5]))
    assert batch.worker_error == "invalid worker response"
    assert batch.pairs_resolved == 0


def test_a_terminator_past_the_last_row_is_refused(monkeypatch):
    rows = [["done", index, 5] for index in range(6)] + [["done", 6, 5]]
    batch, _ = scanned(monkeypatch, stream(*rows))
    assert batch.worker_error == "invalid worker response"
    assert not batch.complete


def test_a_done_frame_with_the_wrong_leaf_count_is_refused(monkeypatch):
    batch, _ = scanned(monkeypatch, stream(["done", 0, 4]))
    assert batch.worker_error == "invalid worker response"
    assert batch.pairs_resolved == 0


@pytest.mark.parametrize("frame", [
    ["hit", True, 0, 0, 4], ["hit", 0, True, 0, 4], ["hit", 0, 0, True, 4],
    ["done", True, 5], ["done", 0, True], ["err", True, "no"],
])
def test_a_bool_index_is_not_an_int(monkeypatch, frame):
    """``isinstance(True, int)`` is true, so the reader asks for the exact type."""
    batch, _ = scanned(monkeypatch, stream(frame))
    assert batch.worker_error == "invalid worker response"
    assert batch.pairs_resolved == 0


@pytest.mark.parametrize("frame", [
    ["nope", 0, 5], ["done", 0], ["hit", 0, 0, 0], "not a list", [],
    ["err", 0, 42], ["hit", 0, 0, 0, 4, 9],
])
def test_a_malformed_frame_is_refused(monkeypatch, frame):
    batch, _ = scanned(monkeypatch, stream(frame))
    assert batch.worker_error == "invalid worker response"


def test_a_partial_trailing_line_is_discarded_without_poisoning_the_rows(monkeypatch):
    output = stream(["done", 0, 5]) + b'["done", 1, 5]'
    batch, _ = scanned(monkeypatch, output)
    assert batch.pairs_resolved == 5, "an unterminated line was read as a row"
    assert batch.worker_error and "1/6" in batch.worker_error


def test_hits_from_an_unterminated_row_are_kept(monkeypatch):
    """A row that died mid-sweep keeps its hits and earns no credit."""
    batch, _ = scanned(monkeypatch, stream(["hit", 0, 0, 0, 4], ["hit", 0, 3, 0, 4]),
                       timed_out=True)
    assert batch.pairs_resolved == 0
    assert [f.rule_id for f in batch.leaves[0].partial_findings] == ["r0"]
    assert [f.rule_id for f in batch.leaves[3].partial_findings] == ["r0"]
    assert batch.worker_error == "worker deadline exceeded"
    assert not batch.complete


def test_a_span_past_its_own_leaf_is_refused(monkeypatch):
    """Leaf 0 is shorter than leaf 1, and the bound is the leaf the hit names."""
    leaves = ["ab", "abcdefgh"]
    sent = worker(monkeypatch, stream(["hit", 0, 0, 0, len(leaves[1])]))
    batch = evaluate.scan_leaves(leaves, needles(1), budget_s=5)
    assert sent["request"]["leaves"] == leaves
    assert batch.worker_error == "invalid worker response"
    assert batch.leaves[0].partial_findings == ()


def test_a_span_valid_for_another_leaf_is_still_refused(monkeypatch):
    """The span fits leaf 0 exactly and is out of range for the leaf it names."""
    leaves = ["abcdefgh", "ab"]
    worker(monkeypatch, stream(["hit", 0, 1, 0, 8]))
    batch = evaluate.scan_leaves(leaves, needles(1), budget_s=5)
    assert batch.worker_error == "invalid worker response"
    assert all(leaf.partial_findings == () for leaf in batch.leaves)


def test_the_request_shape_is_the_protocol_the_worker_checks(monkeypatch):
    """One string per leaf on the wire: no separator, no joined buffer, no base."""
    sent = worker(monkeypatch, stream(*[["done", index, 5] for index in range(6)]))
    evaluate.scan_leaves(LEAVES, needles(6), budget_s=5)
    request = sent["request"]
    assert request["protocol"] == evaluate.SCAN_PROTOCOL
    assert request["mode"] == "leaves"
    assert request["stride"] == len(LEAVES) == len(request["leaves"])
    assert request["leaves"] == LEAVES, "the leaves were joined, reordered or rewritten"
    assert "payload" not in request and len(request["rules"]) == 6


def test_cfg_document_spans_are_bounded_by_the_document(monkeypatch):
    """The span class ``cfg`` lost when several blocks joined one request.

    ``0 <= start <= end`` alone admits an end past the document, and a Finding
    carries coordinates only, so a shifted offset is undetectable downstream.
    The parent holds the document, so the document origin gets the upper bound.
    """
    from agent_defs import cfg
    from agent_defs.model import ChannelBinding, Rule, Surface

    document = "short document"
    bound = Rule(id="t:1", source="t", source_id="1", source_rev="0" * 40, source_path="p",
                 upstream_url="", surface=Surface.CFG, predicate_kind=PredicateKind.NONE,
                 predicate=None, not_runnable_reason="runs through the source's own dispatcher",
                 bindings=(ChannelBinding(channel="CFG", entry_point="", eligible=True, reason="",
                                          conditions=("document",), condition_logic="any"),))

    def over(request, deadline):
        return (json.dumps(["ok", 0, [0, 0, len(document) + 1, "document"]]).encode() + b"\n",
                False, 0, None)

    monkeypatch.setattr(cfg, "_run_worker", over)
    result = cfg.scan_cfg(document, [bound], budget_s=5)
    assert result.partial_findings == ()
    assert any("invalid worker response" in error.reason for error in result.errors)

    def inside(request, deadline):
        return (json.dumps(["ok", 0, [0, 0, len(document), "document"]]).encode() + b"\n",
                False, 0, None)

    monkeypatch.setattr(cfg, "_run_worker", inside)
    assert cfg.scan_cfg(document, [bound], budget_s=5).partial_findings


def batch(**overrides):
    """A BatchScanResult built by hand, the way an injected scanner would.

    Internally consistent by default: every leaf reports the scheduled rule
    count, so a test that wants a contradiction has to introduce it on purpose.
    A fixture whose leaves say they evaluated nothing while its aggregates claim
    every pair resolved is itself the defect under test, and one shipped here
    until review caught it.
    """
    count = overrides.pop("leaf_count", 5)
    rules_scheduled = overrides.get("rules_scheduled", 6)
    leaves = overrides.pop("leaves", None)
    if leaves is None:
        leaves = tuple(evaluate.LeafScanResult(partial_findings=(),
                                               rules_evaluated=rules_scheduled,
                                               truncated_input=False, scheduled=True)
                       for _ in range(count))
    fields = dict(leaves=tuple(leaves), leaves_offered=count, leaves_scheduled=count,
                  rules_scheduled=rules_scheduled, pairs_scheduled=rules_scheduled * count,
                  pairs_resolved=rules_scheduled * count, pairs_rejected=0, elapsed_s=0.0)
    fields.update(overrides)
    return evaluate.BatchScanResult(**fields)


def leaf(scheduled=True, rules_evaluated=6, truncated=False):
    return evaluate.LeafScanResult(partial_findings=(), rules_evaluated=rules_evaluated,
                                   truncated_input=truncated, scheduled=scheduled)


@pytest.mark.parametrize("scheduled,resolved", [(6, 6), (0, 0)])
def test_rule_shaped_counts_in_pair_shaped_fields_are_not_complete(scheduled, resolved):
    """The docstring's promise, enforced rather than advisory.

    ``scan_payload`` takes ``scanner`` as a documented parameter, so a result
    this shape can reach the traversal without any worker involved. Six rules
    over five leaves is thirty pairs; a six satisfies the other aggregate
    clauses while twenty-four pairs never happened, and an empty finding list
    then reads as a scanned-and-clean event.
    """
    result = batch(pairs_scheduled=scheduled, pairs_resolved=resolved)
    assert result.pairs_scheduled != result.rules_scheduled * result.leaves_scheduled
    assert not result.complete
    with pytest.raises(evaluate.IncompleteScanError):
        result.require_complete()


@pytest.mark.parametrize("name,kwargs", [
    # Every leaf says it was never sent, while the aggregates claim all thirty
    # pairs resolved. The leaf knows and the batch has to as well.
    ("never scheduled", dict(leaves=[leaf(scheduled=False, rules_evaluated=0)] * 5)),
    # Sent but nothing run on them.
    ("nothing evaluated", dict(leaves=[leaf(rules_evaluated=0)] * 5)),
    # Every pair rejected, so pairs_evaluated is zero.
    ("everything rejected", dict(pairs_rejected=30)),
    # A five-entry vector under metadata describing four.
    ("vector longer than metadata", dict(
        leaves=[leaf(), leaf(), leaf(), leaf(), leaf(scheduled=False, rules_evaluated=0)],
        leaves_offered=4, leaves_scheduled=4, pairs_scheduled=24, pairs_resolved=24)),
])
def test_aggregates_that_contradict_their_own_leaves_are_not_complete(name, kwargs):
    """Reconciling the aggregates against each other leaves the vector unchecked.

    Each of these satisfies the product identity and still describes leaves that
    were never examined, so ``complete`` has to read the vector too.
    """
    result = batch(**kwargs)
    assert not result.complete
    with pytest.raises(evaluate.IncompleteScanError):
        result.require_complete()


def test_a_real_producer_result_is_complete_and_agrees_with_its_leaves():
    """The positive control comes from the producer, not from a hand-built object.

    A fixture can be made to satisfy any predicate; only a real scan shows the
    added clauses do not refuse what the worker actually emits.

    Every count is checked against the input rather than against another count
    from the same result. Comparing the result's own numbers with each other
    admits a scan of nothing: discarding the three rules before the call leaves
    three leaves scheduled, no rule run, no finding, no worker needed, and all
    the internal identities satisfied. The denominators below are what the caller
    asked for, so that scan fails them.
    """
    leaves = ["leaf zero", "leaf one", "leaf two"]
    rules = [rule(f"r{index}", PredicateKind.SUBSTRING_ANY, ["leaf"]) for index in range(3)]
    result = evaluate.scan_leaves(leaves, rules, budget_s=30)
    assert result.complete
    assert result.require_complete() is result
    assert result.rules_scheduled == len(rules) == 3
    assert result.leaves_scheduled == result.leaves_offered == len(result.leaves) == len(leaves)
    assert result.pairs_scheduled == result.pairs_resolved == len(rules) * len(leaves) == 9
    for scanned in result.leaves:
        assert scanned.scheduled is True
        assert scanned.rules_evaluated == result.rules_scheduled
        # Every rule matches every leaf, so the work is visible as well as counted.
        assert {found.rule_id for found in scanned.partial_findings} == {r.id for r in rules}
