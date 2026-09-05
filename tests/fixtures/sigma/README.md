# Sigma fixtures

`cases.yml` is authored test data. It covers containment OR/AND, a guarded tool
call, nested boolean logic, negation, regex alternatives, rejected patterns,
and an unavailable event field. These strings are data, never agent instructions.

`converted.yml` and `origin.yaml` are the small real conversion/origin pair used
to test deduplication and the measured case-mode repair:

| Fixture | Source revision | Source path |
| --- | --- | --- |
| converted.yml | 5069b74d725a3cb7a7267833cbf0f8de1f31e4a7 | ai_agent/ai_agent_atr_movie_title_generator_instruction_wrapper_for_pwned_payload.yml |
| origin.yaml | 66c7c1573e202b83ac526b70275244c50000068a | rules/prompt-injection/ATR-2026-02012-movie-title-generator-instruction-wrapper-for-pw.yaml |

The explicit reference is `https://agentthreatrule.org/en/rules/ATR-2026-02012`.
The converted ID is `a99e6b6a-d1f1-4f59-9f21-c4650bd560da`. The source description
declares an ATR adaptation. These two files are the only upstream rule payloads
included in this unit; redistribution of the complete corpora remains unresolved.
