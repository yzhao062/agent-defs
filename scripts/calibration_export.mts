/**
 * Export ATR's self-test corpus from one pinned snapshot, for calibration_gate.py.
 *
 *   tsx scripts/calibration_export.mts <workdir>/atr-<short-revision>
 *
 * The corpus lives in TypeScript source (src/eval/corpus.ts, which folds in the
 * frozen src/eval/rule-corpus.ts fixture), so reading it needs the TypeScript
 * module rather than a JSON file. Everything else the gate scores is JSON or
 * Markdown and is read directly in Python.
 *
 * This writes calibration-corpus-self.json next to the snapshot. The gate
 * verifies its sample counts and its content digest against the pins in
 * calibration_gate.py, so a re-export through a different JSON writer still
 * matches and a changed corpus does not.
 *
 * Derived from round3-e4/export-corpora.mts, narrowed to the one corpus that
 * cannot be read without Node.
 */

import { writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const root = resolve(process.argv[2] ?? '.');
const { EVAL_CORPUS } = await import(pathToFileURL(join(root, 'src/eval/corpus.ts')).href);
const out = join(root, 'calibration-corpus-self.json');
writeFileSync(out, JSON.stringify(EVAL_CORPUS));
console.log(JSON.stringify({
  root,
  out,
  samples: EVAL_CORPUS.length,
  attacks: EVAL_CORPUS.filter((s) => s.expectedDetection).length,
  benign: EVAL_CORPUS.filter((s) => !s.expectedDetection).length,
}));
