/**
 * Aragami - removal plan
 *
 * WHAT THIS IS NOT, AND WHY IT EXISTS ANYWAY.
 *
 * This tool does not delete anything. SilentCrystal's whole claim is that it changes nothing --
 * "Read-only, entirely" is the first line of its README, and a removal here would make that sentence
 * false in the way that matters most. So what is ported from the sibling project is the part that
 * survives that constraint: the PLAN. A list of files that could go, what removing each one costs,
 * and the same closed table that decides which ones may appear on the list at all.
 *
 * The value of a plan without an executioner is not zero, and it is worth stating plainly because a
 * reader will ask. It is the piece that says "these are the files, this is what each one holds, and
 * here is what you would lose" -- which is the part a person cannot work out from a file name. The
 * deletion itself is a shell command they can write in a second once they know which files they mean.
 *
 * NOTHING HERE WRITES, MOVES, OR REMOVES. There is no filesystem call at all: the plan is computed
 * from findings that another tool already produced.
 */
import { REMOVABLE } from "./checks.mjs";

export const CLEAN_PLAN_SCHEMA = "aragami-clean-plan/1";

/**
 * What a removal would touch, derived from a set of findings.
 *
 * `kept` is the more useful half and is reported separately: a file with a path whose check id is not
 * in REMOVABLE. That is where "here is a file and this tool will not touch it" gets said instead of
 * silently dropped -- saved logins, the key material protecting them, client certificates.
 */
export function planRemoval(findings = [], removable = REMOVABLE) {
  const planned = [];
  const kept = [];
  const seen = new Set();

  for (const f of Array.isArray(findings) ? findings : []) {
    if (!f || typeof f.id !== "string") continue;
    const abs = f.evidence && typeof f.evidence.abs === "string" ? f.evidence.abs : null;
    if (!abs) continue;

    const cost = removable[f.id];
    if (typeof cost !== "string") {
      kept.push({ id: f.id, path: abs, layer: f.layer ?? null, severity: f.severity ?? null });
      continue;
    }
    if (seen.has(abs)) continue;
    seen.add(abs);

    const size = typeof f.evidence.size === "number" ? f.evidence.size : null;
    const mtime = typeof f.evidence.mtime === "string" ? f.evidence.mtime : null;
    planned.push({ id: f.id, path: abs, bytes: size, mtime, layer: f.layer ?? null, severity: f.severity ?? null, cost });
  }

  const total = planned.reduce((n, p) => n + (typeof p.bytes === "number" ? p.bytes : 0), 0);
  return { planned, kept, total_bytes: total };
}

/** What a removal plan is not. */
export const CLEAN_PLAN_NOT_CLAIMED = [
  "That anything was removed. This tool performs no filesystem operation: the plan is computed from findings and nothing else.",
  "That removing these files is the right next step. A removal does not end a session (that is the sibling project's revoke layer), and it does not remove whatever starts a program again.",
  "That the list is exhaustive. Only findings that carry an absolute path and a check id in the table can appear; anything else is reported as kept, with its path, rather than guessed at.",
  "That the cost stated for each entry is the whole cost. It is the cost this project can name: what leaves the machine when that file goes.",
];
