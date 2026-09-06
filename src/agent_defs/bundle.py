"""The distribution format: normalized records frozen into one JSON document.

A loader needs its corpus on disk and a YAML parser to produce ``Rule``
records. The machine that runs the hook has neither, and fetching a corpus
from inside a tool-call hook would put a network request on the critical path
of every tool call. The build therefore freezes a loader's output here, and the
hook reads this document and nothing else. No Python module and no source text
is executed to read a bundle.

A bundle carries what the source published and what the loader decided. It
never carries a lane, a lane reason, or a benign measurement. Those three are
ours, they are assigned from a measurement of the enabled set on the machine
that will run it, and a lane read out of a shipped file would be a lane nobody
measured. :func:`load` therefore drops all three on the way in, whatever the
file says.
"""

from __future__ import annotations

from dataclasses import asdict, fields
import json
from pathlib import Path
from typing import Iterable, Sequence

from .model import (
    Breadth,
    ChannelBinding,
    Gate,
    Lane,
    Lineage,
    PredicateKind,
    Rule,
    Surface,
)

#: Bumped when a stored record can no longer be read by the previous reader.
FORMAT_VERSION = 1

#: Assigned per machine from a measurement, so never carried in a bundle.
NOT_CARRIED = ("lane", "lane_reason", "benign")

_SEQUENCE_FIELDS = ("tags", "references", "examples_positive",
                    "examples_negative", "false_positive_notes")
_ENUM_FIELDS = (("surface", Surface), ("breadth", Breadth),
                ("predicate_kind", PredicateKind))
_FIELD_NAMES = frozenset(f.name for f in fields(Rule))


def to_record(rule: Rule) -> dict:
    """One rule as a plain JSON-ready mapping, without the assigned fields."""
    record = asdict(rule)
    for key in NOT_CARRIED:
        record.pop(key, None)
    return record


def from_record(record: dict) -> Rule:
    """One stored mapping back to a ``Rule``, with the nesting restored.

    ``asdict`` flattens ``ChannelBinding`` and ``Gate`` into plain mappings, and
    JSON turns every tuple into a list. A record read back without this step
    looks right and fails later at the first attribute access on a binding.
    """
    if not isinstance(record, dict):
        raise ValueError("each bundle record must be an object")
    unknown = set(record) - _FIELD_NAMES
    if unknown:
        raise ValueError(f"unknown record fields: {', '.join(sorted(unknown))}")
    row = {key: value for key, value in record.items() if key not in NOT_CARRIED}
    for key, enum_type in _ENUM_FIELDS:
        if key in row:
            row[key] = enum_type(row[key])
    for key in _SEQUENCE_FIELDS:
        if key in row:
            row[key] = tuple(row[key])
    if isinstance(row.get("predicate"), list):
        row["predicate"] = tuple(row["predicate"])
    row["lineage"] = tuple(Lineage(**entry) for entry in row.get("lineage", ()))
    row["bindings"] = tuple(_binding(entry) for entry in row.get("bindings", ()))
    row.update(benign=None, lane=Lane.RECORD, lane_reason="")
    return Rule(**row)


def _binding(entry: dict) -> ChannelBinding:
    row = dict(entry)
    row["gates"] = tuple(Gate(**gate) for gate in row.get("gates", ()))
    row["conditions"] = tuple(row.get("conditions", ()))
    return ChannelBinding(**row)


def document(rules: Iterable[Rule], **metadata: object) -> dict:
    """The full document: the format version, the metadata, and the records.

    Callers pass whatever pins the build, such as the source revision and the
    archive digest it was read from. Nothing here validates those, because a
    build that lies about its own inputs is a build problem rather than a
    reader problem, and :mod:`agent_defs.bundle` must stay readable by a person
    checking what shipped.
    """
    return {"format_version": FORMAT_VERSION, **metadata,
            "rules": [to_record(rule) for rule in rules]}


def read(path: Path | str) -> tuple[list[Rule], dict]:
    """Return the bundle's rules and everything else the document carries."""
    data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if isinstance(data, list):
        return _rules(data), {}
    if not isinstance(data, dict):
        raise ValueError("a bundle is an array of records or an object with rules")
    version = data.get("format_version", FORMAT_VERSION)
    if version != FORMAT_VERSION:
        raise ValueError(f"unsupported bundle format version: {version!r}")
    metadata = {key: value for key, value in data.items() if key != "rules"}
    return _rules(data.get("rules")), metadata


def load(path: Path | str) -> list[Rule]:
    """The bundle's rules alone. Stored lanes and measurements are dropped."""
    return read(path)[0]


def _rules(records: object) -> list[Rule]:
    if not isinstance(records, list):
        raise ValueError("bundle rules must be an array")
    rules = [from_record(record) for record in records]
    if len({rule.id for rule in rules}) != len(rules):
        raise ValueError("duplicate rule IDs in bundle")
    return rules


def write(path: Path | str, rules: Sequence[Rule], **metadata: object) -> int:
    """Write a bundle and return the byte count, with a stable line ending.

    ``Path.write_text`` grew its ``newline`` argument in 3.10, and this package
    supports 3.9, so the bytes are assembled here rather than encoded on the
    way out of a text handle.
    """
    text = json.dumps(document(rules, **metadata), ensure_ascii=False,
                      indent=1, sort_keys=False) + "\n"
    data = text.encode("utf-8")
    Path(path).write_bytes(data)
    return len(data)
