"""The release gate over a tree `sources.fetch()` wrote, with no real corpus.

`tests/test_distribution_corpora.py` runs the whole gate over the six pinned
corpora and skips without them. These checks are the part that needs no corpus:
they build a small ATR-shaped archive, lay out both the fetched-cache tree and
the full checkout beside it, and hold the gate to the same assertions in each.
Every byte here is fixture scaffolding; nothing in this file comes from a corpus.
"""

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile

import pytest


spec = importlib.util.spec_from_file_location(
    "audit_distribution", Path(__file__).resolve().parents[1] / "scripts/audit_distribution.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

SAMPLES = "data/test-corpora/"
#: An ATR-shaped repository. `rules/`, the licence and the TypeScript sources are
#: what `sources.DECLARED_INPUTS` admits to disk; the npm manifest and everything
#: under `data/test-corpora/` are what it withholds, which is the case under test.
ATR = {
    "LICENSE": b"MIT License\n\nfixture text\n",
    "package.json": b'{"files": ["rules", "dist"]}\n',
    "rules/first.yaml": b"id: fixture-rule-1\n",
    "rules/nested/second.yml": b"id: fixture-rule-2\n",
    "src/engine.ts": b"export {};\n",
    SAMPLES + "index.json": b'{"entries": 0}\n',
    SAMPLES + "notes/readme.md": b"# fixture\n",
    SAMPLES + "notes/third.yaml": (
        b"id: fixture-proposal-3\nstatus: published\ndetection:\n  conditions: []\n# TODO(human)\n"),
    SAMPLES + "proposals/first.yaml": (
        b"id: fixture-proposal-1\nstatus: draft\ndetection:\n  conditions: []\n# TODO(human)\n"),
    SAMPLES + "proposals/second.yaml": (
        b"id: fixture-proposal-2\nstatus: draft\ndetection:\n  conditions: []\n"),
}
#: What a fetch writes for this archive: the allow-list, plus the licence.
FETCHED = ("LICENSE", "rules/first.yaml", "rules/nested/second.yml", "src/engine.ts")
IN_SCOPE_ON_DISK = 3  # LICENSE and the two rule files; the TypeScript source is not in scope.
WITHHELD = 6  # package.json and the five members under data/test-corpora/.


def tarball(members, root="atr-fixture"):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        directory = tarfile.TarInfo(root)
        directory.type = tarfile.DIRTYPE
        archive.addfile(directory)
        for name, content in members.items():
            member = tarfile.TarInfo(f"{root}/{name}")
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
    return output.getvalue()


def write_archive(tmp_path, members, name="atr.tar.gz"):
    blob = tarball(members)
    path = tmp_path / name
    path.write_bytes(blob)
    return path, {"archive_sha256": hashlib.sha256(blob).hexdigest(), "license_path": "LICENSE"}


def write_tree(tmp_path, members, names=None, name="tree"):
    """Lay out a corpus directory; `names` selects what a fetch would extract."""
    root = tmp_path / name
    for relative in members if names is None else names:
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(members[relative])
    return root


@pytest.fixture
def fetched(tmp_path):
    """The archive, the tree a fetch would write, and the pin that covers both."""
    archive, pin = write_archive(tmp_path, ATR)
    return write_tree(tmp_path, ATR, FETCHED), archive, pin


@pytest.fixture
def checkout(tmp_path):
    """The same archive with every member on disk, as a full clone carries it."""
    archive, pin = write_archive(tmp_path, ATR)
    return write_tree(tmp_path, ATR, name="checkout"), archive, pin


def test_fetched_cache_verifies_while_the_sample_directory_stays_absent(fetched):
    tree, archive, pin = fetched
    result = gate.verify_tree("atr", tree, archive, pin)
    assert result["archive_sha256"] == pin["archive_sha256"]
    assert result["verified_files"] == IN_SCOPE_ON_DISK
    assert result["withheld_from_disk"] == WITHHELD
    assert not (tree / "data").exists() and not (tree / "package.json").exists()


def test_full_checkout_verifies_every_member_of_the_same_archive(checkout):
    tree, archive, pin = checkout
    result = gate.verify_tree("atr", tree, archive, pin)
    assert result["verified_files"] == IN_SCOPE_ON_DISK + WITHHELD
    assert result["withheld_from_disk"] == 0


@pytest.mark.parametrize("removed", ["rules/first.yaml", "rules/nested/second.yml", "LICENSE"])
def test_an_input_the_fetch_extracts_is_still_required_on_disk(fetched, removed):
    tree, archive, pin = fetched
    (tree / removed).unlink()
    with pytest.raises(AssertionError, match="missing pinned input"):
        gate.verify_tree("atr", tree, archive, pin)


def test_a_source_without_an_allow_list_may_withhold_nothing(tmp_path):
    members = {"LICENSE": b"Apache License\n", "ai_agent/one.yaml": b"title: fixture\n"}
    archive, pin = write_archive(tmp_path, members, name="netzilo.tar.gz")
    tree = write_tree(tmp_path, members, ["LICENSE"])
    with pytest.raises(AssertionError, match="missing pinned input"):
        gate.verify_tree("netzilo", tree, archive, pin)
    assert gate.verify_tree("netzilo", write_tree(tmp_path, members, name="whole"),
                            archive, pin)["withheld_from_disk"] == 0


@pytest.mark.parametrize("tampered", ["rules/first.yaml", "LICENSE"])
def test_an_extracted_input_is_still_byte_compared(fetched, tampered):
    tree, archive, pin = fetched
    (tree / tampered).write_bytes(ATR[tampered] + b"appended\n")
    with pytest.raises(AssertionError, match="modified pinned input"):
        gate.verify_tree("atr", tree, archive, pin)


@pytest.mark.parametrize("tampered", [SAMPLES + "proposals/first.yaml", "package.json"])
def test_a_withheld_member_a_checkout_carries_is_still_byte_compared(checkout, tampered):
    tree, archive, pin = checkout
    (tree / tampered).write_bytes(ATR[tampered] + b"appended\n")
    with pytest.raises(AssertionError, match="modified pinned input"):
        gate.verify_tree("atr", tree, archive, pin)


def test_an_in_scope_file_the_archive_does_not_declare_still_fails(fetched):
    tree, archive, pin = fetched
    (tree / "rules/extra.yaml").write_bytes(b"id: not-in-the-archive\n")
    with pytest.raises(AssertionError, match="input membership differs"):
        gate.verify_tree("atr", tree, archive, pin)


def test_a_sample_that_reappears_on_disk_is_still_byte_compared(fetched):
    tree, archive, pin = fetched
    target = tree / SAMPLES / "proposals/first.yaml"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"id: fixture-proposal-1\n")
    with pytest.raises(AssertionError, match="modified pinned input"):
        gate.verify_tree("atr", tree, archive, pin)


def test_withheld_members_counts_the_corpus_without_writing_any_of_it(tmp_path, monkeypatch):
    archive, _ = write_archive(tmp_path, ATR)
    tree = write_tree(tmp_path, ATR, FETCHED)
    monkeypatch.chdir(tmp_path)  # a stray relative write would land inside the snapshot
    before = {p: p.stat().st_mtime_ns for p in tmp_path.rglob("*")}
    withheld = gate.withheld_members(archive, SAMPLES, ("package.json",))
    assert before == {p: p.stat().st_mtime_ns for p in tmp_path.rglob("*")}
    assert not (tree / "data").exists()
    assert len(withheld["paths"]) == 5
    assert sorted(withheld["records"]) == [
        "fixture-proposal-1", "fixture-proposal-2", "fixture-proposal-3"]
    assert withheld["drafts"] == 1
    assert json.loads(withheld["read"]["package.json"])["files"] == ["rules", "dist"]


def test_the_census_the_report_prints_comes_from_the_archive(tmp_path):
    archive, _ = write_archive(tmp_path, ATR)
    paths = gate.withheld_members(archive, SAMPLES, ())["paths"]
    assert gate.census(paths, SAMPLES) == {
        "directories": {"index.json": 1, "notes": 2, "proposals": 2},
        "extensions": {".json": 1, ".md": 1, ".yaml": 3}}
    assert all(path.startswith(SAMPLES) for path in paths)


def test_a_requested_member_the_archive_lacks_fails(tmp_path):
    archive, _ = write_archive(tmp_path, ATR)
    with pytest.raises(AssertionError, match="has no"):
        gate.withheld_members(archive, SAMPLES, ("package.json", "npm-shrinkwrap.json"))


def test_duplicate_ids_across_withheld_members_still_fail(tmp_path):
    members = dict(ATR)
    members[SAMPLES + "proposals/second.yaml"] = b"id: fixture-proposal-1\nstatus: draft\n"
    archive, _ = write_archive(tmp_path, members)
    with pytest.raises(AssertionError, match="duplicate native id"):
        gate.withheld_members(archive, SAMPLES, ())


def test_a_withheld_document_that_is_not_a_record_still_fails(tmp_path):
    members = dict(ATR)
    members[SAMPLES + "proposals/second.yaml"] = b"- one\n- two\n"
    archive, _ = write_archive(tmp_path, members)
    with pytest.raises(AssertionError, match="not a native record"):
        gate.withheld_members(archive, SAMPLES, ())


@pytest.mark.parametrize("on_disk, delta", [(0, {SAMPLES: 0}), (1101, {SAMPLES: 1101})])
def test_both_accepted_layouts_satisfy_the_excluded_path_delta(on_disk, delta):
    gate.verify_excluded_corpus(delta, SAMPLES, [None] * on_disk, 1101)


@pytest.mark.parametrize("on_disk, delta, message", [
    (0, {SAMPLES: 1101}, "disagrees with the 0 files"),
    (1101, {SAMPLES: 0}, "disagrees with the 1101 files"),
    (1101, {}, "disagrees with the 1101 files"),
    (700, {SAMPLES: 700}, "700 of the pin's 1101 excluded files are on disk"),
])
def test_a_delta_or_a_layout_that_understates_the_corpus_fails(on_disk, delta, message):
    with pytest.raises(AssertionError, match=message):
        gate.verify_excluded_corpus(delta, SAMPLES, [None] * on_disk, 1101)


def test_yaml_records_and_the_archive_reader_agree_on_one_corpus(tmp_path):
    """The on-disk reader and the archive reader must return the same records."""
    archive, _ = write_archive(tmp_path, ATR)
    tree = write_tree(tmp_path, ATR, name="checkout")
    from_disk = gate.yaml_records(tree, SAMPLES)
    from_archive = gate.withheld_members(archive, SAMPLES, ())["records"]
    assert set(from_disk) == set(from_archive)
    assert {rid: path for rid, (path, _) in from_disk.items()} == {
        rid: path for rid, (path, _) in from_archive.items()}
