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

from .rights import excluded_source_path

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
class Gate:
    """One admission test a source's own dispatcher applies before a rule runs.

    ``verdict`` is ``pass``, ``block``, or ``declared-not-applied`` when the
    source declares a gate that its shipped engine never consults. ``read_from``
    names the file and line the gate was read from, so a reader can check the
    claim against the source rather than against us.
    """

    name: str
    verdict: str
    detail: str = ""
    read_from: str = ""


@dataclass(frozen=True)
class ChannelBinding:
    """How a source's own dispatcher admits one rule on one channel.

    A pattern lifted out of its dispatcher is a different artifact from the rule
    its authors shipped: ATR's 608 runnable patterns fire on 155 of 466 benign
    skill documents when matched flat, and on the 1 of 466 that ATR itself fires
    on when run through its dispatcher. The binding is therefore part of the
    rule, not a runtime setting, and it travels on the record.

    ``conditions`` holds the source's condition patterns in the source's own
    order, because a dispatcher that walks conditions one at a time and
    suppresses some of them cannot be reproduced from a flattened predicate.
    ``eligible`` is False for a rule the dispatcher can never admit on this
    channel; ``reason`` says which gate refused it.
    """

    channel: str
    entry_point: str
    eligible: bool
    reason: str
    gates: Sequence[Gate] = ()
    condition_logic: str = ""
    conditions: Sequence[str] = ()
    suppress_in_code_blocks: bool = False

    @property
    def executable(self) -> bool:
        return self.eligible and bool(self.conditions)


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
    restricted: bool = False   # carries a narrower grant than this package's own licence
    restricted_reason: str = ""

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
    #: The source's own dispatch, one entry per channel it routes this rule to.
    bindings: Sequence[ChannelBinding] = ()

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

    def binding(self, channel: "str | Surface") -> ChannelBinding | None:
        """The source's dispatch for one channel, or None when it routes none.

        A rule can carry an executable binding while ``runnable`` is False: the
        flat predicate and the source's own dispatcher are different execution
        models, and a construct one refuses the other can express. ATR's skill
        path resolves every condition field to the whole document, so a rule our
        flat predicate refuses for naming two fields runs there unchanged.
        """
        wanted = channel.value if isinstance(channel, Surface) else str(channel)
        for bound in self.bindings:
            if bound.channel == wanted:
                return bound
        return None

    @property
    def interrupting(self) -> bool:
        return self.lane in (Lane.ADVISE, Lane.DENY)

    @property
    def shippable(self) -> bool:
        """True when this record may travel in the default bundle.

        A ``restricted`` record carries a grant narrower than this package's MIT
        licence, so shipping it would hand every downstream consumer a limit they
        could not see. The 25 ATR rules embedding AgentHarm text are the case this
        exists for: AgentHarm is "MIT License with an additional clause", and the
        clause restricts the purpose rather than requiring an attribution. An
        attribution is satisfied once by a notices file; a purpose restriction
        travels to every recipient.

        The record still exists, with its lineage intact. This project carries what
        its sources published rather than deleting it, and a consumer who wants a
        restricted record fetches the pinned upstream under that upstream's terms.
        """
        return not self.restricted and not excluded_source_path(self.source, self.source_path)


def default_bundle(rules):
    """The records that may ship, in order. See ``Rule.shippable``."""
    return [r for r in rules if r.shippable]
