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
                member.type, member.linkname = tarfile.SYMTYPE, link
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


@pytest.mark.parametrize("failure,status", [
    (URLError("offline"), None),
    (HTTPError("https://example.invalid", 404, "not found", {}, None), 404),
    (TimeoutError("timed out"), None),
])
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
                       ("repo/copy", b"", "rules/file")])
    entries[0]["archive_sha256"] = hashlib.sha256(archive).hexdigest()
    path.write_text(json.dumps(entries), encoding="utf-8")
    fake_download(monkeypatch, archive)
    tree = sources.fetch("atr", cache)
    assert (tree / "copy").read_bytes() == b"data"
    assert not (tree / "copy").is_symlink()
    assert sources.verify(cache)["atr"]["status"] == "verified"


def test_nonportable_names_preserve_bytes_without_collisions(fixture, monkeypatch):
    path, entries, _, cache = fixture
    archive = tarball([("repo/elevenlabs:sdk-migration.md", b"colon", None),
                       ("repo/elevenlabs%3Asdk-migration.md", b"percent", None)])
    entries[0]["archive_sha256"] = hashlib.sha256(archive).hexdigest()
    path.write_text(json.dumps(entries), encoding="utf-8")
    fake_download(monkeypatch, archive)
    tree = sources.fetch("atr", cache)
    assert (tree / "elevenlabs%3Asdk-migration.md").read_bytes() == b"colon"
    assert (tree / "elevenlabs%253Asdk-migration.md").read_bytes() == b"percent"
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
            raise HTTPError(url, 503, "unavailable", {}, None)
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
    (HTTPError("https://example.invalid", 403, "rate limited", {}, None), 403),
])
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
