// Excerpt of src/quality/rule-contract.ts at ATR faf743fee8a5018467959ec8ea7ccdb1a1aab333, MIT licensed.
// Only the spans agent_defs.loaders.atr_skill_gates reads are kept, so this fixture cannot drift into a rewrite of upstream's logic.

// --- the lane gate: src/quality/rule-contract.ts lines 60-66 ---
export function laneAllows(maturity: unknown, lane: Lane): boolean {
  const m = normalizeMaturity(maturity);
  if (m === 'deprecated') return false; // retired — never fires, in any lane
  if (lane === 'hunt') return true;
  if (lane === 'enforce') return m === 'stable';
  return m === 'stable' || m === 'test'; // alert
}
