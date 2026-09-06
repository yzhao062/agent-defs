// Excerpt of src/engine.ts at ATR faf743fee8a5018467959ec8ea7ccdb1a1aab333, MIT licensed.
// Only the spans agent_defs.loaders.atr_skill_gates reads are kept, so this fixture cannot drift into a rewrite of upstream's logic.

// --- the skill-context denylist: src/engine.ts lines 54-104 ---
/**
 * Rules excluded from skill-context scanning due to high false-positive rate.
 * Threshold: >0.5% FP on 466 real-world SKILL.md files (skills-sh corpus).
 * Re-evaluate when adding new rules or updating detection patterns.
 */
/**
 * Rules excluded from skill-context scanning due to high false-positive rate.
 *
 * Audit 2026-04-14: denylist reduced from 22 → 10 rules.
 * Rules with ≤2 FP on 466 benign SKILL.md samples were removed from denylist
 * to improve wild scan coverage (previously missing 2000+ potential threats).
 *
 * Threshold: >2 FP on 466 benchmark benign samples (>0.43%).
 * Re-evaluate when adding new rules or updating detection patterns.
 */
const SKILL_CONTEXT_DENYLIST: ReadonlySet<string> = new Set([
  // HIGH FP (>20%) — must stay denylisted until regex rewrite
  'ATR-2026-00111', // Shell Escape — 70% FP (matches any shell/exec mention in code examples)
  'ATR-2026-00118', // Approval Fatigue — 27% FP (matches any approval/confirm pattern)
  'ATR-2026-00051', // Resource Exhaustion — 23% FP (SQL/loop patterns in normal skills)
  // MEDIUM FP (1-6%) — denylisted, need regex tightening to unlock
  'ATR-2026-00030', // Cross-Agent Attack — 6% FP (multi-agent communication patterns)
  'ATR-2026-00032', // Goal Hijacking — 3.2% FP (instructional language)
  'ATR-2026-00002', // Indirect Prompt Injection — 2.4% FP (content-fetch patterns)
  'ATR-2026-00115', // Env Var Harvesting — 1.7% FP (legitimate env var references)
  'ATR-2026-00113', // Credential Theft — 1.5% FP (security skills reference credential files)
  'ATR-2026-00110', // eval() Injection — 1.3% FP (coding skills mention eval/exec)
  'ATR-2026-00114', // OAuth Token Interception — 1.3% FP (normal auth patterns)
  'ATR-2026-00050', // Runaway Agent Loop — 1.1% FP (loop patterns in automation skills)
  'ATR-2026-00112', // Dynamic Import — 0.9% FP (import/require references)
  'ATR-2026-00142', // Piggyback Transition — 0.6% FP (descriptive text triggers)
  'ATR-2026-00116', // A2A Message Injection — 0.4% FP (agent communication patterns)
  // LOW FP but zero wild hits — kept in denylist for precision
  'ATR-2026-00060', // MCP Skill Impersonation — 1 FP, 0 wild hits
  'ATR-2026-00074', // Cross-Agent Privilege Escalation — 1 FP, 0 wild hits
  'ATR-2026-00076', // Insecure Inter-Agent Communication — 1 FP, 0 wild hits
  'ATR-2026-00077', // Human-Agent Trust Exploitation — 1 FP, 0 wild hits
  'ATR-2026-00098', // Unauthorized Financial Action — 1 FP, 0 wild hits
  'ATR-2026-00117', // Agent Identity Spoofing — 1 FP, 0 wild hits
  'ATR-2026-00123', // Over-Privileged Skill — 1 FP, 0 wild hits
  'ATR-2026-00148', // Multilingual Prompt Injection — 1 FP, 0 wild hits
  // REMOVED from denylist (≤1 FP + has wild value):
  // ATR-2026-00117 Agent Identity Spoofing (1 FP)
  // ATR-2026-00060 MCP Skill Impersonation (1 FP)
  // ATR-2026-00077 Human-Agent Trust Exploitation (1 FP)
  // ATR-2026-00076 Insecure Inter-Agent Communication (1 FP)
  // ATR-2026-00148 Multilingual Prompt Injection (1 FP)
  // ATR-2026-00123 Over-Privileged Skill (1 FP)
  // ATR-2026-00074 Cross-Agent Privilege Escalation (1 FP)
  // ATR-2026-00098 Unauthorized Financial Action (1 FP)
]);

// --- base64 block bounds and decoder: src/engine.ts lines 111-137 ---
const BASE64_BLOCK_RE = /(?:[A-Za-z0-9+/]{32,}={0,2})/g;
const MAX_DECODE_BLOCKS = 5;

export function decodeBase64Blocks(content: string): string[] {
  const decoded: string[] = [];
  let match: RegExpExecArray | null;
  let count = 0;

  while ((match = BASE64_BLOCK_RE.exec(content)) !== null && count < MAX_DECODE_BLOCKS) {
    try {
      const raw = Buffer.from(match[0], 'base64');
      const text = raw.toString('utf-8');
      // Only keep if decoded content looks like text (not binary garbage)
      // Check: >80% printable ASCII or valid UTF-8 with common chars
      const printable = text.split('').filter(c => c.charCodeAt(0) >= 32 && c.charCodeAt(0) < 127).length;
      if (printable / text.length > 0.7 && text.length >= 10) {
        decoded.push(text.slice(0, 100_000)); // MAX_EVAL_LENGTH bound
        count++;
      }
    } catch {
      // Invalid base64, skip
    }
  }

  return decoded;
}

// --- the status skip and the skill compound gate: src/engine.ts lines 403-473 ---
    // Tier 2: Pattern matching (existing regex rules)
    const isSkillContext = event.scanContext === 'skill';
    for (const rule of this.rules) {
      // Skip deprecated and draft rules
      if (rule.status === 'deprecated' || rule.status === 'draft') continue;
      // Lane gate: keep non-stable maturities out of enforce/alert lanes
      if (!this.passesLane(rule)) continue;

      // Source type filtering: skip rules that don't apply to this event type
      // When scanContext is 'skill', skip source-type filtering — all rules fire
      if (!isSkillContext && eventSourceType && rule.agent_source.type !== eventSourceType) {
        // Allow mcp_exchange rules to also match tool_call events
        const mcpOverTool = rule.agent_source.type === 'mcp_exchange' && eventSourceType === 'tool_call';
        // Indirect prompt injection: llm_io (prompt-injection) rules must also
        // run on tool_response events. A poisoned tool / MCP / RAG output is the
        // primary indirect-injection channel — the payload never appears in a
        // direct llm_input, it rides in on tool output the model then reads.
        // tool_response maps to source type 'mcp_exchange', so without this the
        // entire llm_io family was silently skipped on every tool response.
        // (Field resolution routes event.content into user_input/agent_output
        // for tool_response events — see getFieldValue.)
        const llmIoOverToolResponse =
          rule.agent_source.type === 'llm_io' && eventSourceType === 'mcp_exchange';
        // Trace-method rules declare agent_source.type: agent_trace, which maps
        // to no event source type and would always be filtered out. Evaluate
        // them whenever the event actually carries a trace payload; evaluateRule
        // still returns null if the trace primitives don't fire, and ordinary
        // (non-trace) events are unaffected because event.trace is undefined.
        const traceWithPayload = rule.detection?.method === 'trace' && event.trace !== undefined;
        if (!mcpOverTool && !llmIoOverToolResponse && !traceWithPayload) {
          continue;
        }
      }

      const matchResult = this.evaluateRule(rule, event);
      if (matchResult) {
        // Skill context compound gating: rules not designed for SKILL.md must
        // match 2+ CONDITIONS (not patterns) to trigger. A single condition with
        // many patterns fires too easily on long documents; 2+ condition
        // co-occurrence means the document exhibits multiple distinct threat
        // signals. Rules with scan_target 'skill' or 'both' have verified FP
        // rates on SKILL.md and are exempt.
        //
        // WHAT THIS ACTUALLY DOES — read before "fixing" it (audited 2026-08-05):
        // for a rule with `condition: any`, matchedConditions.length is capped at
        // 1, because evaluateArrayConditions BREAKS on the first matching
        // condition. minRequired is never below 2. So for any-mode rules this is
        // not a 30% threshold, it is an unconditional reject, and the effective
        // policy of the SKILL.md path is "only scan_target: skill|both rules
        // run". 776 of 780 rules on main declare `condition: any`; 645 rules
        // (102 of them maturity:stable) can never match here for any input.
        //
        // That policy is load-bearing, not an accident waiting to be corrected.
        // Measured on this corpus: letting the threshold become reachable (stop
        // short-circuiting when scanContext === 'skill') takes the 466-sample
        // benign skill corpus from 1 flagged sample to 265 — 7 new rules firing,
        // 406 new FP — while malicious recall stays 32/32. Do not change this
        // without re-running both halves of that measurement.
        //
        // The measurement-side consequence (a gate that lists `skill` among its
        // shapes has NOT measured those 645 rules on it) is named by
        // skillPathCoverage() in scripts/lib/corpus-event.ts and pinned by
        // tests/skill-path-coverage.test.ts.
        if (isSkillContext && rule.tags.scan_target !== 'skill' && rule.tags.scan_target !== 'both') {
          const totalConds: number = Number(rule.detection?.conditions?.length ?? 1);
          const minRequired = Math.max(2, Math.ceil(totalConds * 0.3));
          if ((matchResult.matchedConditions?.length ?? 0) < minRequired) {
            continue;
          }
        }
        matches.push(matchResult);

// --- the any-logic short circuit: src/engine.ts lines 811-841 ---
  private evaluateArrayConditions(
    rule: ATRRule,
    conditions: unknown[],
    conditionExpr: string,
    event: AgentEvent,
    allMatchedPatterns: string[]
  ): ATRMatch | null {
    const matchedConditionIndices: number[] = [];
    const isAny = conditionExpr === 'any' || conditionExpr === 'or';

    for (let i = 0; i < conditions.length; i++) {
      const cond = conditions[i] as Record<string, unknown>;
      const result = this.evaluateArrayCondition(cond, event, rule.id, i, allMatchedPatterns);

      if (result) {
        matchedConditionIndices.push(i);
        // Short-circuit on first match for "any". NOTE: this also caps
        // matchedConditions at 1, which the skill-context compound gate in
        // evaluateRaw() reads — see the note there before changing it. Removing
        // this break is a detection-behaviour change, not an optimisation
        // cleanup: it takes the benign skill corpus from 1 to 265 flagged
        // samples out of 466.
        if (isAny) break;
      }
    }

    const matched = isAny
      ? matchedConditionIndices.length > 0
      : matchedConditionIndices.length === conditions.length;

    if (!matched) return null;

// --- skill-context field resolution: src/engine.ts lines 1390-1398 ---
  private resolveField(fieldName: string, event: AgentEvent): string | undefined {
    // Skill context: a SKILL.md is the entire document. ALL fields resolve to
    // content so every rule can scan it. FP is controlled by requiring 2+
    // condition matches in skill context (see evaluate()), not by field filtering.
    if (event.scanContext === 'skill' && event.content) {
      return event.content;
    }

    // Check explicit fields first

// --- the scanSkill entry point: src/engine.ts lines 1735-1762 ---
  scanSkill(content: string): ATRMatch[] {
    const baseEvent = {
      type: 'mcp_exchange' as const,
      timestamp: new Date().toISOString(),
      sessionId: 'skill-scan',
      fields: {},
      scanContext: 'skill' as const,
    };

    // Scan original content
    const matches = this.evaluate({ ...baseEvent, content });

    // Scan base64-decoded blocks for hidden payloads
    const decodedBlocks = decodeBase64Blocks(content);
    for (const block of decodedBlocks) {
      const blockMatches = this.evaluate({ ...baseEvent, content: block });
      for (const m of blockMatches) {
        // Tag decoded matches so consumers know the source
        matches.push({
          ...m,
          matchedPatterns: [...m.matchedPatterns, '[decoded:base64]'],
        });
      }
    }

    return matches;
  }

// --- the maximum evaluated length: src/engine.ts lines 2062-2073 ---
/** Maximum input length for regex evaluation to mitigate ReDoS */
const MAX_EVAL_LENGTH = 100_000;

/**
 * Safely test a regex pattern against input with length limits.
 * Returns false if input exceeds MAX_EVAL_LENGTH to prevent ReDoS.
 */
function safeRegexTest(regex: RegExp, input: string): boolean {
  if (input.length > MAX_EVAL_LENGTH) return false;
  return regex.test(input);
}
