"""The normalized record every source loader emits.

One rule from one upstream corpus becomes one ``Rule``. Nothing here converts a
value the source published; fields that carry an upstream string carry it
verbatim, and any mapping we apply lives beside it under our own name. That
separation is the whole point of the record: a consumer must be able to tell
what the source said from what we decided.

The module imports nothing outside the standard library, and nothing else in
this package imports an adapter or an emitter at module scope. ``import
agent_defs`` must stay free of third-party packages.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Mapping, Sequence

SCHEMA_VERSION = 1


class Surface(str, enum.Enum):
    """Where in an agent's lifecycle a rule can be evaluated."""

    CFG = "CFG"        # configuration at rest: MCP servers, skills, agent files
    IN = "IN"          # a tool call, before it runs
    OUT = "OUT"        # a tool result, after it comes back
    PROMPT = "PROMPT"  # the user's own prompt text
    PIN = "PIN"        # a change since the person pinned something
    NONE = "NONE"      # no interception point in an agent; reference material


class Breadth(str, enum.Enum):
    """How much material a rule's condition can match."""

    NARROW = "NARROW"
    MEDIUM = "MEDIUM"
    BROAD = "BROAD"


class PredicateKind(str, enum.Enum):
    """How ``Rule.predicate`` is to be evaluated."""

    REGEX = "REGEX"
    SUBSTRING_ANY = "SUBSTRING_ANY"
    SUBSTRING_ALL = "SUBSTRING_ALL"
    STRUCTURED = "STRUCTURED"  # a field/operator tree the evaluator walks
    NONE = "NONE"              # not mechanically runnable; see not_runnable_reason


class Lane(str, enum.Enum):
    """Admission lane. Assigned by our build, never read from a source.

    Evaluated in order, first match sets the ceiling. A source marking of
    ``critical``, ``stable`` or ``confidence: 95`` grants nothing here.
    """

    DO_NOT_SHIP = "DO_NOT_SHIP"
    RECORD = "RECORD"    # every new executable rule starts here
    ADVISE = "ADVISE"
    DENY = "DENY"


@dataclass(frozen=True)
class Lineage:
    """One declared origin for a rule's content.

    ``kind`` says what the claim is about (``author_field``, ``conversion``,
    ``benchmark``, ``import_commit``). ``value`` is the upstream string.
    ``evidence`` records where we read it, so a reader can go check.
    """

    kind: str
    value: str
    evidence: str = ""


@dataclass(frozen=True)
class BenignFiring:
    """The measured firing rate on benign material.

    ``u95`` is the exact binomial upper bound on the true rate. With zero hits
    in ``trials`` independent trials that is ``1 - 0.05 ** (1 / trials)``, so a
    0.5% claim needs 598 trials and ten authored fixtures bound nothing below
    25.9%. A rule with no measurement here cannot leave ``Lane.RECORD``.
    """

    trials: int
    hits: int
    u95: float
    corpus: str
    measured_at: str


@dataclass(frozen=True)
class Rule:
    """One upstream rule, normalized.

    Every ``*_raw`` field holds the source's own bytes. Everything else is ours
    and is dated, named and withdrawable.
    """

    # Identity and lineage
    id: str                    # "{source}:{source_id}"
    source: str                # "atr", "netzilo", "agentshield", ...
    source_id: str             # the upstream identifier, verbatim
    source_rev: str            # the pinned commit the record was read from
    source_path: str           # path inside the source repository
    upstream_url: str
    lineage: Sequence[Lineage] = ()
    license_spdx: str = ""
    redistribution: str = "unresolved"  # granted | denied | unresolved

    # Content, as published
    title: str = ""
    description: str = ""
    severity_raw: str = ""     # never converted; any mapping is a separate field
    severity_field: str = ""   # which upstream key severity_raw came from
    maturity_raw: str = ""     # experimental | stable | test | ...
    tags: Sequence[str] = ()
    references: Sequence[str] = ()

    # Execution
    surface: Surface = Surface.NONE
    breadth: Breadth = Breadth.NARROW
    predicate_kind: PredicateKind = PredicateKind.NONE
    predicate: object = None
    not_runnable_reason: str = ""
    case_sensitive: bool = False

    # The source's own evidence about itself
    examples_positive: Sequence[str] = ()
    examples_negative: Sequence[str] = ()
    false_positive_notes: Sequence[str] = ()

    # Admission, ours
    lane: Lane = Lane.RECORD
    lane_reason: str = ""
    benign: BenignFiring | None = None

    extra: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.predicate_kind is PredicateKind.NONE and self.predicate is not None:
            raise ValueError(f"{self.id}: predicate set with predicate_kind NONE")
        if self.predicate_kind is not PredicateKind.NONE and not self.not_runnable_reason:
            return
        if self.predicate_kind is PredicateKind.NONE and not self.not_runnable_reason:
            raise ValueError(f"{self.id}: not runnable but no reason given")

    @property
    def runnable(self) -> bool:
        return self.predicate_kind is not PredicateKind.NONE

    @property
    def interrupting(self) -> bool:
        return self.lane in (Lane.ADVISE, Lane.DENY)
