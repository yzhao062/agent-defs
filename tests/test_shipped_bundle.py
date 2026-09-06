"""Properties the artifact in this package must hold, checked on the real file.

These are not checks on the builder. They read what is committed, because the
builder runs on a corpus host and what ships is whatever came back from it.

Nothing here skips. An earlier version made the whole module conditional on the
bundle existing, and the scan-record check conditional on the record existing,
which meant a packaging omission or a rebuild that dropped its old scan record
turned a release guard into a green run. The absence of either file is the
failure these tests are for, so it is asserted rather than skipped.
"""
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

from agent_defs import bundle
from agent_defs.evaluate import scan_trusted
from agent_defs.hooks import _claude_code_impl as hook
from agent_defs.model import Surface

ROOT = Path(hook.__file__).resolve().parents[3]
SCAN_RECORD = ROOT / "scripts" / "artifact-scan.json"
BUILDER = ROOT / "scripts" / "build_bundle.py"


def _builder():
    """The builder module, for the one constant this file must not restate."""
    spec = importlib.util.spec_from_file_location("build_bundle_for_tests", BUILDER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


#: The fixtures the build filter applies, imported rather than copied. Two
#: hand-maintained lists is how the builder ended up probing three spaces and
#: never one, while this file probed one and never U+00A0.
CONTENT_FREE = list(_builder().CONTENT_FREE)


@pytest.fixture(scope="module")
def shipped():
    assert hook.BUNDLE_PATH.exists(), (
        f"no bundle at {hook.BUNDLE_PATH}; a checkout without one cannot be released, "
        f"and skipping here is what hid that")
    return bundle.read(hook.BUNDLE_PATH)


@pytest.mark.parametrize("probe", CONTENT_FREE, ids=[repr(p) for p in CONTENT_FREE])
def test_no_shipped_rule_fires_on_a_leaf_with_nothing_in_it(shipped, probe):
    rules, _ = shipped
    assert rules
    found = scan_trusted(probe, rules, max_bytes=len(probe.encode("utf-8")))
    # An incomplete scan and a quiet one carry the same empty findings list, so
    # the count of rules actually evaluated is the part that makes this a test.
    assert found.complete
    assert found.rules_evaluated == len(rules)
    # The hook scans each string leaf separately, so a rule matching a blank
    # leaf fires on ordinary work whatever a corpus of joined text showed.
    # ATR-2026-02010 reached a shipped bundle exactly this way.
    assert [f.rule_id for f in found.findings] == []


def test_the_fixture_list_covers_the_shape_that_got_through(shipped):
    """A regression policy is only as good as the case it was written for."""
    assert " " in CONTENT_FREE, "a single space is the loudest blank leaf there is"
    assert " " in CONTENT_FREE, "the non-breaking space this file used to miss"
    assert "\t" in CONTENT_FREE and "\n" in CONTENT_FREE
    assert len(set(CONTENT_FREE)) == len(CONTENT_FREE), "duplicate fixtures"


def test_no_sample_text_travels(shipped):
    rules, meta = shipped
    # SAMPLES.md rule 2. An earlier bundle shipped 985 positive examples,
    # five of them dropper-shaped, plus the raw upstream documents repeating
    # them, which is 4.3 MB of attack strings inside an installable package.
    assert not [r.id for r in rules if r.examples_positive or r.examples_negative]
    leaked = [r.id for r in rules if {"upstream", "upstream_yaml"} & set(r.extra or {})]
    assert leaked == []
    assert set(meta.get("stripped_fields", ())) == {"examples_positive", "examples_negative"}


def test_the_reachability_result_travels_instead(shipped):
    rules, _ = shipped
    # SAMPLES.md rule 3: ship the result of the check, not its input.
    assert rules
    for rule in rules:
        found = (rule.extra or {}).get("reachability")
        assert found, rule.id
        assert found["status"] == "reachable", rule.id
        assert found["matched"] >= 1, rule.id
        assert len(found["example_sha256"]) == found["examples"], rule.id


def test_every_shipped_rule_is_one_this_hook_can_run(shipped):
    rules, meta = shipped
    assert rules
    assert {r.surface for r in rules} == {Surface.OUT}
    assert all(r.runnable for r in rules)
    assert all(r.shippable for r in rules)
    assert len({r.id for r in rules}) == len(rules)
    assert meta["shipped"] == len(rules)
    assert meta["shipped"] + sum(meta["dropped"].values()) == meta["loaded"]


def test_what_was_held_back_is_recorded_with_its_reason(shipped):
    _, meta = shipped
    held = meta.get("held_back") or {}
    assert held, "a bundle that dropped measured rules must say which"
    assert all(isinstance(reason, str) and reason for reason in held.values())


def test_the_scanner_self_check_names_a_record_rather_than_a_promise(shipped):
    _, meta = shipped
    assert "artifact-scan.json" in str(meta.get("scanner_self_check", ""))
    assert SCAN_RECORD.exists(), (
        f"no scan record at {SCAN_RECORD}; SAMPLES.md rule 5 says an artifact is "
        f"scanned before it is published, and a missing record is an unscanned "
        f"artifact rather than a test that does not apply")
    record = json.loads(SCAN_RECORD.read_text(encoding="utf-8"))
    # Keyed by digest, so a rebuilt artifact leaves the old record visibly
    # stale rather than quietly attached to bytes nobody scanned.
    digest = hashlib.sha256(hook.BUNDLE_PATH.read_bytes()).hexdigest()
    assert record["sha256"] == digest, "the scan record describes different bytes; rescan"
    assert record["verdict"] == "clean"
    assert record.get("bytes") == hook.BUNDLE_PATH.stat().st_size
