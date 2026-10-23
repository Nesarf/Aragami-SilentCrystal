/**
 * Aragami - process matching
 *
 * WHAT THIS IS: a reader. It asks the operating system for the process table and returns the entries
 * that a request names. It ends nothing, starts nothing, and writes nothing -- which is the only form
 * this question can take in a project whose first promise is that it changes nothing.
 *
 * That limit is worth being explicit about, because the sibling project does act here and a reader
 * may expect the same. A plan that names a running process is useful: it tells a person what is
 * running right now, which of those came from a directory anything can write to, and which of them is
 * the tool's own process or its parent. The ending is theirs to do.
 *
 * The identity rule is the same one the sibling uses, for the same measured reason: a pid is reused,
 * so a path is the identity when one is readable, and a name is the weaker fallback. A pid alone is
 * never treated as naming a program.
 */
export const PROCESS_SCHEMA = "aragami-process-list/1";

function normaliseName(n) {
  const s = String(n ?? "").trim().toLowerCase();
  if (!s) return null;
  return s.endsWith(".exe") ? s.slice(0, -4) : s;
}

function normalisePath(p) {
  const s = String(p ?? "").trim().toLowerCase().replace(/\//g, "\\");
  return s || null;
}

/** Whether a path sits somewhere any process can write -- the shape a program should not live in. */
export function looksUserWritablePath(p) {
  const s = String(p ?? "").toLowerCase();
  return /(\\appdata\\|\\users\\public\\|\\programdata\\|\\temp\\|\\tmp\\|\\downloads\\|\/tmp\/|\/home\/)/.test(s);
}

/**
 * Reduce a process list to what a request names.
 *
 * `selfPids` are marked rather than dropped: "this is the process you are running the tool from, so do
 * not end it" is information, and a list that silently omitted it would look like a shorter answer
 * than it is.
 */
export function matchProcesses(processes = [], { paths = [], names = [], selfPids = [] } = {}) {
  const list = (Array.isArray(processes) ? processes : [])
    .map((p) => ({
      pid: Number(p?.ProcessId ?? p?.pid ?? p?.Id ?? 0),
      name: p?.Name ?? p?.name ?? null,
      path: p?.ExecutablePath ?? p?.path ?? null,
    }))
    .filter((p) => Number.isInteger(p.pid) && p.pid > 0);

  const self = new Set((Array.isArray(selfPids) ? selfPids : [selfPids]).filter((v) => v != null).map(Number));
  const wantPaths = (Array.isArray(paths) ? paths : []).map(normalisePath).filter(Boolean);
  const wantNames = (Array.isArray(names) ? names : []).map(normaliseName).filter(Boolean);

  const matched = [];
  const seen = new Set();
  const hitPaths = new Set();
  const hitNames = new Set();

  for (const p of list) {
    const pPath = normalisePath(p.path);
    const pName = normaliseName(p.name);
    let why = null;
    if (pPath && wantPaths.includes(pPath)) { why = "path"; hitPaths.add(pPath); }
    if (!why && pName && wantNames.includes(pName)) { why = "name"; hitNames.add(pName); }
    if (!why && pPath) {
      const base = normaliseName(pPath.split("\\").pop());
      if (base && wantNames.includes(base)) { why = "name"; hitNames.add(base); }
    }
    if (!why) continue;
    if (seen.has(p.pid)) continue;
    seen.add(p.pid);
    matched.push({
      pid: p.pid,
      name: p.name,
      path: p.path,
      matched_by: why,
      // Recorded so a later reader can tell whether the process in front of them is the one this list
      // is about. A pid on its own does not survive a reboot or an hour.
      identified_by: p.path ? "path" : "name",
      is_self: self.has(p.pid),
      user_writable_location: p.path ? looksUserWritablePath(p.path) : null,
    });
  }

  const unmatched = [
    ...wantPaths.filter((p) => !hitPaths.has(p)).map((p) => ({ kind: "path", value: p })),
    ...wantNames.filter((n) => !hitNames.has(n)).map((n) => ({ kind: "name", value: n })),
  ];

  return { matched, unmatched };
}

/** What a process list is not. */
export const PROCESS_NOT_CLAIMED = [
  "That anything was ended. This tool reads the process table and returns what a request names; it starts no process and ends none.",
  "That a process in a user-writable location is malicious. It is a place to look: an ordinary updater runs from AppData too.",
  "That a pid identifies a program. Pids are reused quickly; the path beside each entry is what makes it checkable later.",
  "That the list is complete. A process whose executable path cannot be read is listed with a name only, and the name is the weaker identity.",
];
