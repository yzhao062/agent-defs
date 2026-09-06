# ATR skill-dispatcher fixture

Upstream rule YAML plus the spans of ATR's own engine that
`agent_defs.loaders.atr_skill_gates` reads, both verbatim from
`faf743fee8a5018467959ec8ea7ccdb1a1aab333`, MIT licensed. `atr-source.json` records each rule's upstream path,
its digest, and why this fixture carries it.

The source files here are excerpts, not rewrites:
`scripts/build_atr_skill_fixture.py` slices
named line ranges and stamps them with the range it took, so a gate that
moves upstream shows up as a fixture that no longer parses rather than as a
fixture that quietly disagrees with the source.
