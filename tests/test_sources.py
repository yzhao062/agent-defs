import hashlib
import io
import json
from pathlib import Path
import tarfile
from urllib.error import HTTPError, URLError

import pytest

from agent_defs import sources


FIXTURE_LOCK = Path(__file__).parent / "fixtures" / "sources.lock.json"


class Response(io.BytesIO):
    status = 200


def tarball(entries=None):
    output = io.BytesIO()
    if entries is None:
        entries = [("repo/rules/test.json", b'{"id":"fixture-1"}\n', None)]
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for name, content, link in entries:
            member = tarfile.TarInfo(name)
            if link is not None:
                kind, target = ("sym", link) if isinstance(link, str) else link
                member.type = tarfile.SYMTYPE if kind == "sym" else tarfile.LNKTYPE
                member.linkname = target
                archive.addfile(member)
            else:
                member.size = len(content)
                archive.addfile(member, io.BytesIO(content))
    return output.getvalue()


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("Unexpected network request in offline test")
    monkeypatch.setattr(sources.urllib.request, "urlopen", blocked)


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    archive = tarball()
    entries = json.loads(FIXTURE_LOCK.read_text(encoding="utf-8"))
    entries[0]["archive_sha256"] = hashlib.sha256(archive).hexdigest()
    path = tmp_path / "sources.lock"
    path.write_text(json.dumps(entries), encoding="utf-8")
    monkeypatch.setattr(sources, "DEFAULT_LOCK", path)
    return path, entries, archive, tmp_path / "cache"


def fake_download(monkeypatch, blob):
    calls = []
    def open_url(request, *, timeout):
        calls.append((request.full_url, timeout))
        return Response(blob)
    monkeypatch.setattr(sources.urllib.request, "urlopen", open_url)
    return calls


def test_load_fixture_lock():
    locked = sources.load_lock(FIXTURE_LOCK)
    assert list(locked) == ["atr", "netzilo", "agentshield"]
    assert locked["atr"]["commit"] == "1" * 40


@pytest.mark.parametrize("field,value", [
    ("commit", "main"), ("commit", "123abcd"), ("archive_sha256", "invalid"),
    ("repo_url", "http://github.com/fixture/atr"), ("record_count", True),
    ("license_path", "../LICENSE"), ("fetched_at", "yesterday"),
])
def test_invalid_pin_rejected_before_network(fixture, field, value):
    path, entries, _, cache = fixture
    entries[0][field] = value
    path.write_text(json.dumps(entries), encoding="utf-8")
    with pytest.raises(ValueError, match="atr"):
        sources.fetch("atr", cache)


def test_duplicate_source_rejected(fixture):
    path, entries, _, _ = fixture
    path.write_text(json.dumps(entries + [entries[0]]), encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate"):
        sources.load_lock(path)


def test_fetch_pinned_archive_and_noop_cache_hit(fixture, monkeypatch):
    path, entries, archive, cache = fixture
    calls = fake_download(monkeypatch, archive)
    tree = sources.fetch("atr", cache, lock_path=path)
    assert tree == sources._cache_root(cache) / entries[0]["archive_sha256"] / "tree"
    assert (tree / "rules/test.json").read_bytes() == b'{"id":"fixture-1"}\n'
    assert calls == [("https://codeload.github.com/fixture/atr/tar.gz/" + "1" * 40, 30)]
    before = {p: p.stat().st_mtime_ns for p in cache.rglob("*")}
    assert sources.fetch("atr", cache) == tree
    assert before == {p: p.stat().st_mtime_ns for p in cache.rglob("*")}
    assert len(calls) == 1
    statuses = {k: v["status"] for k, v in sources.verify(cache).items()}
    assert statuses == {"atr": "verified", "netzilo": "missing", "agentshield": "missing"}
    assert len(calls) == 1


def test_digest_mismatch_never_extracts_or_publishes(fixture, monkeypatch):
    _, _, _, cache = fixture
    calls = fake_download(monkeypatch, b"incorrect archive bytes")
    with pytest.raises(sources.SourceError, match="atr: archive digest mismatch"):
        sources.fetch("atr", cache)
    assert len(calls) == 1
    assert list(cache.iterdir()) == []


def http_error(url, code, msg):
    """An HTTPError shaped the way urllib actually raises one.

    The fifth argument is the response body, and urllib always has one. Passing
    None instead leaves the object half-built: on 3.9 HTTPError reaches
    tempfile._TemporaryFileWrapper through urllib.response.addbase, whose
    __init__ only runs when fp is not None, so its __getattr__ raises KeyError
    rather than AttributeError for any name it does not carry. That reached the
    suite twice. pytest reads __name__ off each parametrize value to build an
    id, which made collection of this module fail outright and ended the whole
    3.9 run; and sources.py's own attribute reads then returned None instead of
    a status. Handing it a real body fixes both, and models the real error.
    """
    return HTTPError(url, code, msg, {}, io.BytesIO(b""))


@pytest.mark.parametrize("failure,status", [
    (URLError("offline"), None),
    (http_error("https://example.invalid", 404, "not found"), 404),
    (TimeoutError("timed out"), None),
], ids=["urlerror", "http-404", "timeout"])
def test_network_failure_names_source_and_never_falls_back(fixture, monkeypatch, failure, status):
    _, _, _, cache = fixture
    calls = []
    def fail(request, *, timeout):
        calls.append(request.full_url)
        raise failure
    monkeypatch.setattr(sources.urllib.request, "urlopen", fail)
    with pytest.raises(sources.SourceError, match="atr:") as caught:
        sources.fetch("atr", cache)
    assert caught.value.http_status == status
    assert len(calls) == 1 and calls[0].endswith("1" * 40)
    assert list(cache.iterdir()) == []


@pytest.mark.parametrize("damage", ["archive", "changed", "deleted", "extra"])
def test_verify_detects_cached_corruption(fixture, monkeypatch, damage):
    _, _, archive, cache = fixture
    calls = fake_download(monkeypatch, archive)
    tree = sources.fetch("atr", cache)
    if damage == "archive":
        (tree.parent / "archive.tar.gz").write_bytes(b"corrupt")
    elif damage == "changed":
        (tree / "rules/test.json").write_bytes(b"modified")
    elif damage == "deleted":
        (tree / "rules/test.json").unlink()
    else:
        (tree / "extra.txt").write_text("extra", encoding="utf-8")
    assert sources.verify(cache)["atr"]["status"] == "invalid"
    with pytest.raises(sources.SourceError, match="atr: cache verification failed"):
        sources.fetch("atr", cache)
    assert len(calls) == 1


def test_unreadable_cached_file_is_invalid(fixture, monkeypatch):
    _, _, archive, cache = fixture
    calls = fake_download(monkeypatch, archive)
    tree = sources.fetch("atr", cache)
    original_open = Path.open
    def deny_file(path, *args, **kwargs):
        if path == tree / "rules/test.json":
            raise PermissionError("Permission denied")
        return original_open(path, *args, **kwargs)
    monkeypatch.setattr(Path, "open", deny_file)
    result = sources.verify(cache)["atr"]
    assert result["status"] == "invalid"
    assert "Permission denied" in result["error"]
    with pytest.raises(sources.SourceError, match="atr: cache verification failed"):
        sources.fetch("atr", cache)
    assert len(calls) == 1


@pytest.mark.parametrize("entries", [
    [("repo/../../escape", b"x", None)],
    [("/absolute", b"x", None)],
    [("repo/C:/escape", b"x", None)],
    [("repo/dir\\escape", b"x", None)],
    [("repo/link", b"", "../../escape")],
    [("repo/file", b"a", None), ("repo/file", b"b", None)],
    [("repo/file", b"a", None), ("other/file", b"b", None)],
    [("repo/Dir/file", b"a", None), ("repo/dir/other", b"b", None)],
])
def test_unsafe_archive_rejected(fixture, monkeypatch, entries):
    path, locked, _, cache = fixture
    archive = tarball(entries)
    locked[0]["archive_sha256"] = hashlib.sha256(archive).hexdigest()
    path.write_text(json.dumps(locked), encoding="utf-8")
    fake_download(monkeypatch, archive)
    with pytest.raises(sources.SourceError, match="atr:"):
        sources.fetch("atr", cache)
    assert list(cache.iterdir()) == []


def test_internal_file_link_materialized_and_verified(fixture, monkeypatch):
    path, entries, _, cache = fixture
    archive = tarball([("repo/rules/file", b"data", None),
                       ("repo/rules/copy", b"", "file")])
    entries[0]["archive_sha256"] = hashlib.sha256(archive).hexdigest()
    path.write_text(json.dumps(entries), encoding="utf-8")
    fake_download(monkeypatch, archive)
    tree = sources.fetch("atr", cache)
    assert (tree / "rules/copy").read_bytes() == b"data"
    assert not (tree / "rules/copy").is_symlink()
    assert sources.verify(cache)["atr"]["status"] == "verified"


def test_nonportable_names_preserve_bytes_without_collisions(fixture, monkeypatch):
    path, entries, _, cache = fixture
    archive = tarball([("repo/rules/elevenlabs:sdk-migration.md", b"colon", None),
                       ("repo/rules/elevenlabs%3Asdk-migration.md", b"percent", None)])
    entries[0]["archive_sha256"] = hashlib.sha256(archive).hexdigest()
    path.write_text(json.dumps(entries), encoding="utf-8")
    fake_download(monkeypatch, archive)
    tree = sources.fetch("atr", cache)
    assert (tree / "rules/elevenlabs%3Asdk-migration.md").read_bytes() == b"colon"
    assert (tree / "rules/elevenlabs%253Asdk-migration.md").read_bytes() == b"percent"
    assert sources.verify(cache)["atr"]["status"] == "verified"


def test_deep_cache_path(fixture, monkeypatch):
    _, _, archive, cache = fixture
    cache = cache / ("deep" * 25) / ("path" * 25)
    fake_download(monkeypatch, archive)
    tree = sources.fetch("atr", cache)
    assert (tree / "rules/test.json").is_file()
    assert sources.verify(cache)["atr"]["status"] == "verified"


def test_drift_three_states_and_current_default_branch(fixture, monkeypatch):
    path, _, _, _ = fixture
    before = path.read_bytes()
    calls = []
    def open_url(request, *, timeout):
        url = request.full_url
        calls.append(url)
        if "agentshield" in url:
            raise http_error(url, 503, "unavailable")
        if "/commits/" not in url:
            return Response(b'{"default_branch":"release/new"}')
        assert url.endswith("/commits/release%2Fnew")
        return Response(json.dumps({"sha": "1" * 40 if "/atr/" in url else "f" * 40}).encode())
    monkeypatch.setattr(sources.urllib.request, "urlopen", open_url)
    result = sources.check_upstream()
    assert result["atr"]["report"] == "unchanged"
    assert result["atr"]["status"] == "unchanged"
    assert result["atr"]["http_status"] == 200
    assert result["netzilo"]["report"] == "moved " + "2" * 40 + ".." + "f" * 40
    assert result["netzilo"]["status"] == "moved"
    assert result["netzilo"]["http_status"] == 200
    assert result["agentshield"]["status"] == "unreachable"
    assert result["agentshield"]["http_status"] == 503
    assert result["agentshield"]["upstream_commit"] is None
    assert len(calls) == 5
    assert path.read_bytes() == before


@pytest.mark.parametrize("head,status", [
    (b"invalid json", 200), (b'{"sha":"main"}', 200),
    (b"{}", 200), (b"null", 200),
    (URLError("offline"), None),
    (http_error("https://example.invalid", 403, "rate limited"), 403),
], ids=["invalid-json", "sha-is-a-branch-name", "empty-object", "null",
        "urlerror", "http-403"])
def test_bad_head_is_unreachable_even_after_metadata_success(fixture, monkeypatch, head, status):
    def open_url(request, *, timeout):
        if "/commits/" not in request.full_url:
            return Response(b'{"default_branch":"main"}')
        if isinstance(head, Exception):
            raise head
        return Response(head)
    monkeypatch.setattr(sources.urllib.request, "urlopen", open_url)
    results = sources.check_upstream()
    for result in results.values():
        assert result["status"] == result["report"] == "unreachable"
        assert result["http_status"] == status
        assert result["checks"][0]["http_status"] == 200
        assert result["checks"][1]["http_status"] == status
        assert result["upstream_commit"] is None


def test_malicious_sample_paths_are_never_written_to_disk():
    """The guard that stops a scanner quarantining files out of our own cache.

    Six ATR checkouts across two build rounds put roughly 4,500 malware samples
    and harmful-prompt files on a Windows host, and real-time protection deleted
    them out from under running measurements. Nothing here needs them on disk.
    """
    from pathlib import Path

    from agent_defs.sources import NEVER_EXTRACT, _is_excluded

    assert ("data", "skill-benchmark", "malicious") in NEVER_EXTRACT
    assert ("data", "test-corpora") in NEVER_EXTRACT

    blocked = [
        "data/skill-benchmark/malicious/snyk-005-malware-dropper-rentry.md",
        "data/skill-benchmark/malicious/ninja-039-malware-dropper-whatsapp-mgv.md",
        "data/test-corpora/harmbench/ATR-HARMB-anything.proposal.yaml",
        "data/test-corpora/advbench/x.yaml",
    ]
    for path in blocked:
        assert _is_excluded(Path(path).parts), path

    allowed = [
        "rules/prompt-injection/ATR-2026-00040.yaml",
        "data/skill-benchmark/benign/ordinary-skill.md",
        "data/skill-benchmark/manifest.json",
        "LICENSE",
    ]
    for path in allowed:
        assert not _is_excluded(Path(path).parts), path


#: An archive shaped like the real corpus: rules beside sample directories, one
#: of which the deny-list did not know about until it reached a scanner.
SAMPLE_BEARING = [
    ("repo/rules/test.json", b'{"id":"fixture-1"}\n', None),
    ("repo/LICENSE", b"MIT\n", None),
    ("repo/data/skill-benchmark/benign/ordinary.md", b"an ordinary skill\n", None),
    ("repo/data/skill-benchmark/malicious/dropper.md", b"PAYLOAD\n", None),
    ("repo/data/test-corpora/advbench/x.yaml", b"PAYLOAD\n", None),
    ("repo/conformance/v1.0/fixtures/tp/ATR-2026-00080/input.md", b"PAYLOAD\n", None),
    ("repo/conformance/v1.0/fixtures/tn/ATR-2026-00080/input.md", b"benign\n", None),
    ("repo/spec/conformance/baseline/fixtures/a.md", b"PAYLOAD\n", None),
    ("repo/tests/fixtures/b.md", b"PAYLOAD\n", None),
]


@pytest.fixture
def sample_bearing(tmp_path, monkeypatch):
    archive = tarball(SAMPLE_BEARING)
    entries = json.loads(FIXTURE_LOCK.read_text(encoding="utf-8"))
    entries[0]["archive_sha256"] = hashlib.sha256(archive).hexdigest()
    path = tmp_path / "sources.lock"
    path.write_text(json.dumps(entries), encoding="utf-8")
    monkeypatch.setattr(sources, "DEFAULT_LOCK", path)
    return path, archive, tmp_path / "cache"


def test_the_conformance_suite_never_reaches_disk(sample_bearing, monkeypatch):
    """The directory that set the antivirus off on 2026-09-06.

    The two original prefixes held that day. What landed was the corpus's
    conformance suite, whose tp directory is one true-positive attack document
    per rule, and which the deny-list did not name.
    """
    path, archive, cache = sample_bearing
    fake_download(monkeypatch, archive)
    tree = sources.fetch("atr", cache, lock_path=path)

    written = {p.relative_to(tree).as_posix() for p in tree.rglob("*") if p.is_file()}
    assert written == {"rules/test.json", "LICENSE"}
    for gone in ("conformance", "spec", "tests", "data"):
        assert not (tree / gone).exists(), f"{gone} was extracted"
    # Under an allow-list a directory exists only because an admitted file needs
    # it, so no empty folder survives to name what was refused. The benign
    # skill-benchmark file goes too: no loader reads it, and the deny-list kept
    # it only because nothing said not to.
    assert not list(tree.rglob("ATR-2026-00080"))
    assert not [p for p in tree.rglob("*") if p.is_file() and b"PAYLOAD" in p.read_bytes()]
    assert (tree.parent / "EXCLUDED").read_text(encoding="utf-8").startswith("7 members")


def test_a_cache_with_excluded_members_verifies_and_is_reused(sample_bearing, monkeypatch):
    """The bug that made every run re-extract, which is how samples recur.

    The extractor skipped excluded members while the verifier compared the tree
    against every member the archive declares, so the first cache entry failed
    its own check and the next call downloaded and extracted the corpus again.
    """
    path, archive, cache = sample_bearing
    calls = fake_download(monkeypatch, archive)
    tree = sources.fetch("atr", cache, lock_path=path)
    assert len(calls) == 1

    before = {p: p.stat().st_mtime_ns for p in cache.rglob("*")}
    assert sources.fetch("atr", cache, lock_path=path) == tree
    assert len(calls) == 1, "the cache did not hit, so the corpus was extracted twice"
    assert before == {p: p.stat().st_mtime_ns for p in cache.rglob("*")}
    assert sources.verify(cache, lock_path=path)["atr"]["status"] == "verified"


def pin(path, entries, index, archive):
    """Point one locked entry at this archive, leaving the others unresolvable."""
    entries[index]["archive_sha256"] = hashlib.sha256(archive).hexdigest()
    path.write_text(json.dumps(entries), encoding="utf-8")
    return entries[index]["name"]


#: A link names one path and carries another's bytes. `_layout` resolves it to
#: the target's member while keeping the link's own path as the key, so a filter
#: that reads only the key admits the target's content under an allowed name.
LINKS = [
    ("sym", "../data/test-corpora/payload.txt"),
    ("hard", "repo/data/test-corpora/payload.txt"),
]


@pytest.mark.parametrize("source,index", [("atr", 0), ("netzilo", 1)])
@pytest.mark.parametrize("kind,target", LINKS)
def test_a_link_cannot_carry_an_excluded_file_into_an_allowed_name(
        fixture, monkeypatch, source, index, kind, target):
    """Both extraction policies check the path the bytes come from.

    The allow-list is not enough on its own: `rules/` is declared, so a link
    written there is admitted on its own path no matter what it points at.
    """
    path, entries, _, cache = fixture
    archive = tarball([("repo/rules/ok.yaml", b"id: harmless\n", None),
                       ("repo/data/test-corpora/payload.txt", b"PAYLOAD\n", None),
                       ("repo/rules/copy.txt", b"", (kind, target))])
    name = pin(path, entries, index, archive)
    assert name == source
    fake_download(monkeypatch, archive)
    tree = sources.fetch(source, cache)

    assert not (tree / "rules/copy.txt").exists(), "an excluded file was copied under an allowed name"
    assert (tree / "rules/ok.yaml").is_file()
    assert not [p for p in tree.rglob("*") if p.is_file() and b"PAYLOAD" in p.read_bytes()]
    assert sources.verify(cache)[source]["status"] == "verified"


#: Payload-bearing collections the deny-list does not name, at the revision it
#: was extended for. Naming these five would have left a sixth to be found the
#: same way, which is why the shape changed rather than the list.
UNNAMED_COLLECTIONS = (
    "data/autoresearch/adversarial-samples.json",
    "data/autoresearch/missed-payloads.json",
    "data/evasion-payloads.json",
    "data/semantic-validation/attacks.json",
    "data/pint-benchmark/pint-corpus.json",
)


def test_the_collections_the_deny_list_never_named_are_refused_anyway(fixture, monkeypatch):
    path, entries, _, cache = fixture
    archive = tarball(
        [("repo/rules/ok.yaml", b"id: harmless\n", None), ("repo/LICENSE", b"MIT\n", None)]
        + [(f"repo/{p}", b'[{"payload": "PAYLOAD"}]\n', None) for p in UNNAMED_COLLECTIONS])
    pin(path, entries, 0, archive)
    fake_download(monkeypatch, archive)
    tree = sources.fetch("atr", cache)

    for collection in UNNAMED_COLLECTIONS:
        assert not sources._is_excluded(Path(collection).parts), (
            f"{collection} is deny-listed; this test no longer shows the shape change")
        assert not (tree / collection).exists(), collection
    assert {p.relative_to(tree).as_posix() for p in tree.rglob("*") if p.is_file()} == {
        "rules/ok.yaml", "LICENSE"}


def test_the_declared_cfg_inputs_survive_the_allow_list(fixture, monkeypatch):
    """An allow-list that dropped these would silently remove every CFG gate.

    Bound to the loader's own constants rather than to copies of the strings, so
    an upstream rename moves the gate and this test, not the gate alone.
    """
    from agent_defs.loaders import atr_skill_gates as gates

    needed = [p for p in sources.DECLARED_INPUTS["atr"] if not p.endswith("/")]
    assert set(needed) == {gates.ENGINE_PATH, gates.ENFORCEMENT_PATH,
                           gates.CONTRACT_PATH, gates.INTERFACE_CONTRACT_PATH}
    assert "rules/" in sources.DECLARED_INPUTS["atr"], "the corpus itself must be declared"
    path, entries, _, cache = fixture
    archive = tarball([("repo/rules/ok.yaml", b"id: harmless\n", None),
                       ("repo/LICENSE", b"MIT\n", None),
                       ("repo/package.json", b"{}\n", None)]
                      + [(f"repo/{p}", b"// source\n", None) for p in needed])
    pin(path, entries, 0, archive)
    fake_download(monkeypatch, archive)
    tree = sources.fetch("atr", cache)

    for relative in needed:
        assert (tree / relative).is_file(), relative
    assert not (tree / "package.json").exists(), "an undeclared root file was extracted"


def test_a_source_without_declared_inputs_still_extracts_what_is_not_denied(fixture, monkeypatch):
    """Five loaders are still on the deny-list; that path has to keep working."""
    assert "netzilo" not in sources.DECLARED_INPUTS
    path, entries, _, cache = fixture
    archive = tarball([("repo/ai_agent/rule.yaml", b"id: harmless\n", None),
                       ("repo/LICENSE", b"Apache\n", None),
                       ("repo/README.md", b"docs\n", None),
                       ("repo/tests/fixtures/sample.md", b"PAYLOAD\n", None)])
    pin(path, entries, 1, archive)
    fake_download(monkeypatch, archive)
    tree = sources.fetch("netzilo", cache)

    assert {p.relative_to(tree).as_posix() for p in tree.rglob("*") if p.is_file()} == {
        "ai_agent/rule.yaml", "LICENSE", "README.md"}
    assert sources.verify(cache)["netzilo"]["status"] == "verified"
