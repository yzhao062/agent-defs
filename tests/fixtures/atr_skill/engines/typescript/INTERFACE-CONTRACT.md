<!-- Excerpt of engines/typescript/INTERFACE-CONTRACT.md at ATR faf743fee8a5018467959ec8ea7ccdb1a1aab333, MIT licensed. -->
<!-- Only the spans agent_defs.loaders.atr_skill_gates reads are kept, so this fixture cannot drift into a rewrite of upstream's logic. -->

<!-- --- the evaluate() contract: engines/typescript/INTERFACE-CONTRACT.md lines 131-154 --- -->
   * Contract:
   * - Pre-compiles regex patterns at load time for hot-path latency
   * - Filters by severity / maturity per config (when supported)
   * - Skips rules whose RE2 grammar check fails (NOT loaded; logged)
   * - Throws on schema validation failure
   */
  async loadRules(): Promise<number>;

  /**
   * Evaluate a single AgentEvent against all loaded rules.
   * Returns matching ATRMatch results in rule-loaded order.
   *
   * Contract:
   * - Pre-check: Tier 0 invariants (hard boundaries, returns deny match)
   * - Tier 1: blacklist lookup (known-bad skill IDs)
   * - Tier 2: pattern matching (regex / behavioral conditions)
   * - Layer 2.5: optional embedding similarity (if module configured)
   * - Layer 3: optional semantic LLM-as-judge (if module configured)
   * - MUST emit matches in rule-loaded order
   * - MUST NOT mutate input AgentEvent
   * - MUST honor SKILL_CONTEXT_DENYLIST when event.scanContext === 'skill'
   * - MUST update session tracker if configured
   * - MUST POST to reporter if configured (fire-and-forget for performance)
   * - Synchronous
