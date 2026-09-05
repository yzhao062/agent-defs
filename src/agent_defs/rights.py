"""Named redistribution exclusions, separate from predicate admission."""

from collections.abc import Mapping
import posixpath


EXCLUDED_SOURCE_PATHS = {"atr": ("data/test-corpora/",)}
AGENTHARM_REASON = (
    "AgentHarm-derived content: its MIT License with an additional clause has a "
    "field-of-use restriction limiting use to improving AI safety and security."
)


def excluded_source_path(source: str, source_path: str) -> str:
    """Return the excluded directory, or an empty string."""
    path = posixpath.normpath(source_path.replace("\\", "/"))
    return next((prefix for prefix in EXCLUDED_SOURCE_PATHS.get(source, ())
                 if path == prefix.rstrip("/") or path.startswith(prefix)), "")


def _strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for child in value.values():
            yield from _strings(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            yield from _strings(child)


def agentharm_restriction(data: Mapping, *, include_references: bool = False) -> str:
    """Use declared origins, never an incidental mention in rule prose."""
    fields = ("author", "metadata_provenance")
    if include_references:
        fields += ("references",)
    if any("agentharm" in value.casefold()
           for key in fields for value in _strings(data.get(key))):
        return AGENTHARM_REASON
    return ""
