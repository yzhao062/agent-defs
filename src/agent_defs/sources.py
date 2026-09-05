"""Pinned GitHub archives and an offline, content-addressed source cache.

The default lock belongs to this checkout. Installed callers can pass lock_path.
Cache entries contain archive.tar.gz and tree/; links to archived regular files
are materialized as ordinary files, so extraction also works on Windows.
Windows-invalid filename characters (and literal percent signs) are percent
escaped on every platform. The tarball retains the original names and bytes.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
from http.client import HTTPException
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import posixpath
import re
import shutil
import tarfile
import tempfile
from urllib.error import HTTPError, URLError
from urllib.parse import quote
import urllib.request


DEFAULT_LOCK = Path(__file__).resolve().parents[2] / "sources.lock"
DEFAULT_CACHE = Path("data/cache")
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_REPO = re.compile(r"https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)\Z")


class SourceError(RuntimeError):
    """A source could not be fetched or verified; no unpinned retry is made."""

    def __init__(self, source, message, *, http_status=None, url=None):
        self.source = source
        self.http_status = http_status
        self.url = url
        status = f" (HTTP {http_status})" if http_status is not None else ""
        super().__init__(f"{source}: {message}{status}")


def load_lock(path=None):
    """Read a JSON array of source entries and return a mapping keyed by name.

    Invalid pins fail before any network request. Additional evidence fields in
    the lock are preserved. Duplicate names and abbreviated SHAs are rejected.
    """
    path = Path(path) if path is not None else DEFAULT_LOCK
    try:
        entries = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"Cannot read source lock {path}: {exc}") from exc
    if not isinstance(entries, list) or not entries:
        raise ValueError(f"Source lock {path} must be a nonempty JSON array")
    locked = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError(f"Invalid source entry in {path}")
        name = entry.get("name")
        if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9_]*", name):
            raise ValueError(f"Invalid source name in {path}: {name!r}")
        if name in locked:
            raise ValueError(f"{name}: duplicate source in {path}")
        for key, pattern in (("repo_url", _REPO), ("commit", _SHA),
                             ("archive_sha256", _DIGEST)):
            value = entry.get(key)
            if not isinstance(value, str) or not pattern.fullmatch(value):
                raise ValueError(f"{name}: invalid {key} in {path}")
        for key in ("fetched_at", "license_spdx", "license_path"):
            if not isinstance(entry.get(key), str) or not entry[key]:
                raise ValueError(f"{name}: missing {key} in {path}")
        try:
            stamp = datetime.fromisoformat(entry["fetched_at"].replace("Z", "+00:00"))
            if stamp.tzinfo is None:
                raise ValueError("timestamp has no timezone")
            _safe_parts(entry["license_path"])
        except ValueError as exc:
            raise ValueError(f"{name}: invalid timestamp or license_path: {exc}") from exc
        count = entry.get("record_count")
        if type(count) is not int or count < 0:
            raise ValueError(f"{name}: record_count must be a nonnegative integer")
        locked[name] = entry
    return locked


@contextmanager
def _response(source, url, timeout):
    status = None
    request = urllib.request.Request(url, headers={"User-Agent": "agent-defs/0.0.2"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status = response.status
            if status != 200:
                raise SourceError(source, f"request failed: {url}", http_status=status, url=url)
            yield response
    except HTTPError as exc:
        exc.close()
        raise SourceError(source, f"request failed: {url}: {exc.reason}",
                          http_status=exc.code, url=url) from exc
    except (OSError, URLError, HTTPException) as exc:
        raise SourceError(source, f"network request failed: {url}: {exc}",
                          http_status=status, url=url) from exc


def _digest(stream):
    digest = hashlib.sha256()
    for block in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(block)
    return digest.hexdigest()


def _safe_parts(name):
    parts = name.rstrip("/").split("/")
    if not parts or any(
        part in ("", ".", "..") or "\\" in part or PureWindowsPath(part).drive
        or any(ord(char) < 32 for char in part)
        for part in parts
    ):
        raise ValueError(f"unsafe archive path: {name!r}")
    return tuple(parts)


def _portable_path(name):
    parts = []
    for part in _safe_parts(name):
        escaped = "".join(f"%{ord(char):02X}" if char in '%:<>"|?*' else char for char in part)
        while escaped.endswith((".", " ")):
            escaped = escaped[:-1] + f"%{ord(escaped[-1]):02X}"
        if PureWindowsPath(escaped).is_reserved():
            escaped = f"%{ord(escaped[0]):02X}" + escaped[1:]
        parts.append(escaped)
    return "/".join(parts)


def _cache_root(path):
    path = Path(path)
    if os.name == "nt":
        absolute = str(path.resolve())
        if not absolute.startswith("\\\\?\\"):
            absolute = "\\\\?\\UNC\\" + absolute[2:] if absolute.startswith("\\\\") else "\\\\?\\" + absolute
        path = Path(absolute)
    return path


def _layout(archive):
    """Validate the whole archive before writing; return files and directories."""
    members = {}
    roots = set()
    portable_names = set()
    for member in archive.getmembers():
        parts = _safe_parts(member.name)
        roots.add(parts[0])
        if not (member.isdir() or member.isfile() or member.issym() or member.islnk()):
            raise ValueError(f"unsupported archive member: {member.name}")
        key = "/".join(parts)
        if key.casefold() in portable_names:
            raise ValueError(f"duplicate archive path: {key}")
        portable_names.add(key.casefold())
        members[key] = member
    if len(roots) != 1:
        raise ValueError("archive must have exactly one repository root")
    root = next(iter(roots))
    files, directories = {}, set()
    for key, member in members.items():
        if key == root:
            if not member.isdir():
                raise ValueError("archive root is not a directory")
            continue
        relative = _portable_path(key[len(root) + 1:])
        directories.update(str(p) for p in PurePosixPath(relative).parents if str(p) != ".")
        if member.isdir():
            directories.add(relative)
            continue
        if member.issym() or member.islnk():
            target = member.linkname
            if member.issym():
                target = posixpath.join(posixpath.dirname(key), target)
            target = posixpath.normpath(target)
            _safe_parts(target)
            if not target.startswith(root + "/"):
                raise ValueError(f"link escapes repository: {key}")
            member = members.get(target)
            if member is None or not member.isfile():
                raise ValueError(f"link must target an archived regular file: {key}")
        files[relative] = member
    if not files:
        raise ValueError("archive contains no files")
    if {p.casefold() for p in files} & {p.casefold() for p in directories}:
        raise ValueError("archive path is both a file and a directory")
    paths = set(files) | directories
    if len({p.casefold() for p in paths}) != len(paths):
        raise ValueError("archive paths collide on a case-insensitive filesystem")
    return files, directories


def _check(entry, cached):
    name = entry["name"]
    try:
        if cached.is_symlink() or not cached.is_dir():
            raise ValueError("cache entry is not a regular directory")
        archive_path, tree = cached / "archive.tar.gz", cached / "tree"
        if archive_path.is_symlink() or not archive_path.is_file():
            raise ValueError("cached archive is missing or is a link")
        with archive_path.open("rb") as stream:
            actual = _digest(stream)
        if actual != entry["archive_sha256"]:
            raise ValueError(f"archive digest mismatch: expected {entry['archive_sha256']}, got {actual}")
        if tree.is_symlink() or not tree.is_dir():
            raise ValueError("cached tree is missing or is a link")
        with tarfile.open(archive_path, "r:gz") as archive:
            files, directories = _layout(archive)
            observed_files, observed_dirs = set(), set()
            for parent, dirs, names in os.walk(tree, followlinks=False):
                for child in dirs + names:
                    path = Path(parent) / child
                    relative = path.relative_to(tree).as_posix()
                    if path.is_symlink():
                        raise ValueError(f"unexpected cache link: {relative}")
                    if path.is_dir():
                        observed_dirs.add(relative)
                    elif path.is_file():
                        observed_files.add(relative)
                    else:
                        raise ValueError(f"unexpected cache file type: {relative}")
            if observed_files != set(files) or observed_dirs != directories:
                raise ValueError("cached tree has missing or extra paths")
            for relative, member in files.items():
                with archive.extractfile(member) as expected, (tree / relative).open("rb") as actual:
                    if _digest(expected) != _digest(actual):
                        raise ValueError(f"cached file differs from pinned archive: {relative}")
    except (OSError, ValueError, tarfile.TarError, EOFError) as exc:
        raise SourceError(name, f"cache verification failed: {exc}") from exc
    return tree


def fetch(name, cache_dir=DEFAULT_CACHE, *, lock_path=None, timeout=30):
    """Download only the pinned tarball, verify it, and return its extracted tree.

    A valid cache hit performs no writes or network requests. Corruption raises
    SourceError rather than silently replacing evidence. New entries are staged
    on the same filesystem and published only after complete extraction.
    """
    locked = load_lock(lock_path)
    if name not in locked:
        raise ValueError(f"Unknown locked source: {name}")
    entry = locked[name]
    cache_dir = _cache_root(cache_dir)
    cached = cache_dir / entry["archive_sha256"]
    if cached.exists() or cached.is_symlink():
        return _check(entry, cached)
    repo = entry["repo_url"].removeprefix("https://github.com/")
    url = f"https://codeload.github.com/{repo}/tar.gz/{entry['commit']}"
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix=".fetch-", dir=cache_dir) as temporary:
            stage = Path(temporary) / "entry"
            stage.mkdir()
            archive_path = stage / "archive.tar.gz"
            with _response(name, url, timeout) as response, archive_path.open("wb") as output:
                shutil.copyfileobj(response, output)
            with archive_path.open("rb") as stream:
                actual = _digest(stream)
            if actual != entry["archive_sha256"]:
                raise SourceError(name, f"archive digest mismatch: expected {entry['archive_sha256']}, got {actual}")
            tree = stage / "tree"
            with tarfile.open(archive_path, "r:gz") as archive:
                files, directories = _layout(archive)
                tree.mkdir()
                for relative in sorted(directories):
                    (tree / relative).mkdir(parents=True, exist_ok=True)
                for relative, member in files.items():
                    with archive.extractfile(member) as source, (tree / relative).open("xb") as target:
                        shutil.copyfileobj(source, target)
            try:
                stage.rename(cached)
            except OSError:
                if cached.exists():
                    return _check(entry, cached)
                raise
    except (OSError, ValueError, tarfile.TarError, EOFError) as exc:
        raise SourceError(name, f"could not cache pinned archive: {exc}") from exc
    return cached / "tree"


def verify(cache_dir=DEFAULT_CACHE, *, lock_path=None):
    """Offline audit of every locked source: verified, missing, or invalid.

    Both tarball bytes and the complete extracted tree are checked against the
    lock. A missing cache is reported explicitly and is never fetched here.
    """
    results = {}
    for name, entry in load_lock(lock_path).items():
        cached = _cache_root(cache_dir) / entry["archive_sha256"]
        result = {"name": name, "status": "missing", "path": str(cached)}
        if cached.exists() or cached.is_symlink():
            try:
                _check(entry, cached)
                result["status"] = "verified"
            except SourceError as exc:
                result.update(status="invalid", error=str(exc))
        results[name] = result
    return results


def check_upstream(*, lock_path=None, timeout=30):
    """Report unchanged, moved, or unreachable, preserving observed HTTP status.

    Discover the current default branch on every call. The checks list preserves
    each request's URL and status; a transport failure has status None, while
    malformed HTTP 200 data is unreachable with status 200. Never updates pins.
    """
    results = {}
    for name, entry in load_lock(lock_path).items():
        checks = []
        result = {"name": name, "pinned_commit": entry["commit"],
                  "upstream_commit": None, "status": "unreachable",
                  "report": "unreachable", "http_status": None, "checks": checks}
        repo = entry["repo_url"].removeprefix("https://github.com/")
        api = f"https://api.github.com/repos/{repo}"

        def read_json(url):
            check = {"url": url, "http_status": None}
            checks.append(check)
            try:
                with _response(name, url, timeout) as response:
                    check["http_status"] = response.status
                    return json.load(response)
            except SourceError as exc:
                check["http_status"] = exc.http_status
                raise

        try:
            metadata = read_json(api)
            branch = metadata["default_branch"]
            if not isinstance(branch, str) or not branch:
                raise ValueError("default_branch is not a nonempty string")
            result["default_branch"] = branch
            head = read_json(f"{api}/commits/{quote(branch, safe='')}")["sha"]
            if not isinstance(head, str) or not _SHA.fullmatch(head):
                raise ValueError("upstream head is not a full commit SHA")
            result["upstream_commit"] = head
            result["status"] = "unchanged" if head == entry["commit"] else "moved"
            result["report"] = "unchanged" if head == entry["commit"] else f"moved {entry['commit']}..{head}"
        except (SourceError, ValueError, KeyError, TypeError) as exc:
            result["error"] = str(exc)
        result["http_status"] = checks[-1]["http_status"]
        result["checked_at"] = datetime.now(timezone.utc).isoformat()
        results[name] = result
    return results
