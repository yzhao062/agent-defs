"""agent-defs: definitions for agent security.

Public rule sets and risk corpora, normalized, carrying where each rule came
from, watched for changes, and preserved after the source disappears.

Importing this package pulls in no third-party dependency and no adapter. Each
source loader and each emitter lives behind its own extra, and is imported by
name when it is asked for.
"""

from .model import (
    SCHEMA_VERSION,
    BenignFiring,
    Breadth,
    ChannelBinding,
    Gate,
    Lane,
    Lineage,
    PredicateKind,
    Rule,
    Surface,
)

__all__ = [
    "SCHEMA_VERSION",
    "BenignFiring",
    "Breadth",
    "ChannelBinding",
    "Gate",
    "Lane",
    "Lineage",
    "PredicateKind",
    "Rule",
    "Surface",
    "__version__",
]

__version__ = "0.0.2.dev0"
