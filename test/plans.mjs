#!/usr/bin/env node
/**
 * Plan suite -- the three read-only tools added to this project: a removal plan, a containment plan,
 * and a process list.
 *
 * What they have in common, and what this suite is really asserting
 * ----------------------------------------------------------------
 * All three answer "what would be done" and none of them does it. That is the project's first
 * promise, and it is the one an addition like this is most likely to break. So the structural
 * assertion comes first: no module here imports a filesystem-writing call, and the only process API
 * in the tree is the one that READS the table.
 *
 * The second assertion is that an empty answer says why. `aragami_contain` with no input returns an
 * empty plan because nothing told it what to look at -- not because the machine is clean. A tool that
 * let those two read the same would be the failure mode this whole project is built against.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

const clean = await import(pathToFileURL(path.join(root, "lib", "cleanplan.mjs")).href);
const proc = await import(pathToFileURL(path.join(root, "lib", "proclist.mjs")).href);
const cont = await import(pathToFileURL(path.join(root, "lib", "containment.mjs")).href);
const core = await import(pathToFileURL(path.join(root, "lib", "core.mjs")).href);
const checks = await import(pathToFileURL(path.join(root, "lib", "checks.mjs")).href);

let pass = 0;
let fail = 0;
const failures = [];
function check(name, ok, detail = "") {
  if (ok) { console.log(`  \u001b[32m[ok]\u001b[0m ${name}`); pass++; }
  else { console.log(`  \u001b[31m[FAIL]\u001b[0m ${name}  ${detail}`); fail++; failures.push(`${name} ${detail}`); }
}
function section(t) { console.log(`\n\u001b[35m== ${t} ==\u001b[0m`); }

/* ================================================== the promise */

section("nothing here writes, moves, or removes");

const WRITES = /writeFileSync|appendFileSync|copyFileSync|mkdirSync|unlinkSync|rmSync|renameSync|utimesSync|createWriteStream/;
for (const f of ["cleanplan.mjs", "proclist.mjs", "containment.mjs"]) {
  const src = fs.readFileSync(path.join(root, "lib", f), "utf8");
  check(`${f} contains no filesystem-writing call`, !WRITES.test(src), (WRITES.exec(src) ?? [""])[0]);
}
check("containment contains no process API at all",
  !/child_process|execFileSync|spawn/.test(fs.readFileSync(path.join(root, "lib", "containment.mjs"), "utf8")));
check("cleanplan imports no filesystem module",
  !/node:fs/.test(fs.readFileSync(path.join(root, "lib", "cleanplan.mjs"), "utf8")));

/* ================================================== the removal table */

section("the removal table is the permission system");

const ids = new Set(checks.CHECK_CATALOG.map((c) => c.id));
const keys = Object.keys(checks.REMOVABLE);
check("the table is non-empty", keys.length > 0, String(keys.length));
check("every key names a real check", keys.every((k) => ids.has(k)), JSON.stringify(keys.filter((k) => !ids.has(k))));
check("every value states a cost, not an operation",
  keys.every((k) => typeof checks.REMOVABLE[k] === "string" && checks.REMOVABLE[k].length > 40),
  JSON.stringify(keys.filter((k) => !(checks.REMOVABLE[k] ?? "").length > 40)));
check("the three credential stores are not in the table",
  ["ff-logins", "ff-keys", "ff-certs"].every((id) => !(id in checks.REMOVABLE)));

/* ================================================== the removal plan */

section("a plan names what it would touch and what it will not");

const plan = clean.planRemoval([
  { id: "places", layer: "metadata", severity: "warn", evidence: { size: 100, abs: "\\p\\places.sqlite" } },
  { id: "ff-logins", layer: "crypto", severity: "warn", evidence: { size: 200, abs: "\\p\\logins.json" } },
  { id: "state-guards", layer: "metadata", severity: "warn", evidence: { guards: 3 } },
]);
check("the eligible one is planned", plan.planned.length === 1 && plan.planned[0].id === "places", JSON.stringify(plan.planned.map((p) => p.id)));
check("the credential store is kept, with its path",
  plan.kept.length === 1 && plan.kept[0].id === "ff-logins" && plan.kept[0].path === "\\p\\logins.json", JSON.stringify(plan.kept));
check("a finding with no path is in neither list", !plan.kept.some((k) => k.id === "state-guards"));
check("the byte total is the sum", plan.total_bytes === 100, String(plan.total_bytes));
check("every planned entry carries its cost", plan.planned.every((p) => typeof p.cost === "string" && p.cost.length > 40));
const dup = clean.planRemoval([
  { id: "places", evidence: { abs: "/x" } }, { id: "profile-times", evidence: { abs: "/x" } },
]);
check("one path is planned once", dup.planned.length === 1, JSON.stringify(dup.planned.map((p) => p.id)));
check("an empty input plans nothing", clean.planRemoval([]).planned.length === 0 && clean.planRemoval().kept.length === 0);

/* ================================================== process matching */

section("a process matches by path or name, and is never swept");

const procs = [
  { ProcessId: 10, Name: "updater.exe", ExecutablePath: "C:\\Users\\me\\AppData\\Roaming\\x\\updater.exe" },
  { ProcessId: 20, Name: "updater.exe", ExecutablePath: "C:\\Program Files\\Legit\\updater.exe" },
  { ProcessId: 30, Name: "agent", ExecutablePath: "/usr/local/bin/agent" },
];
const byPath = proc.matchProcesses(procs, { paths: ["C:\\Users\\me\\AppData\\Roaming\\x\\updater.exe"] });
check("a path matches exactly one of two processes with the same name", byPath.matched.length === 1 && byPath.matched[0].pid === 10, JSON.stringify(byPath.matched.map((m) => m.pid)));
check("it records that the path is what identified it", byPath.matched[0]?.identified_by === "path");
check("that entry is flagged as user-writable", byPath.matched[0]?.user_writable_location === true);
const byName = proc.matchProcesses(procs, { names: ["updater"] });
check("a name matches both", byName.matched.length === 2, JSON.stringify(byName.matched.map((m) => m.pid)));
check("a posix path matches by basename", proc.matchProcesses(procs, { names: ["agent"] }).matched.length === 1);
check("nothing is matched without a request", proc.matchProcesses(procs, {}).matched.length === 0);
check("a request that matches nothing is reported",
  proc.matchProcesses(procs, { names: ["nope"] }).unmatched.length === 1);
const self = proc.matchProcesses(procs, { names: ["updater"], selfPids: [10] });
check("the tool's own process is marked, not dropped", self.matched.find((m) => m.pid === 10)?.is_self === true);
check("the other match is not", self.matched.find((m) => m.pid === 20)?.is_self === false);

/* ================================================== containment */

section("containment derives its order and refuses to advise on a security product");

check("an executable is read out of a command line", cont.exeFromCommand('"C:\\x\\y.exe" -k') === "C:\\x\\y.exe", String(cont.exeFromCommand('"C:\\x\\y.exe" -k')));
check("a command line with a space in the path still yields the exe",
  cont.exeFromCommand("C:\\Program Files\\x\\a.exe -k") === "C:\\Program Files\\x\\a.exe", String(cont.exeFromCommand("C:\\Program Files\\x\\a.exe -k")));
check("a shortcut is not an executable", cont.exeFromCommand("C:\\x\\y.lnk") === null);
check("a directory is not an executable", cont.exeFromCommand("C:\\x\\Start") === null);

const plan1 = cont.containmentPlan({ persistence: [{ source: "run-key", subject: "HKCU\\...\\Run\\U", target: "C:\\Users\\me\\AppData\\Roaming\\u.exe", at: null }] });
check("the order puts the outbound block first", plan1.order.join(",") === "sever,disable,purge", plan1.order.join(","));
check("one program gets one block and three disable moves", plan1.steps.sever.length === 1 && plan1.steps.disable.length === 3,
  JSON.stringify({ s: plan1.steps.sever.length, d: plan1.steps.disable.length }));
check("the mechanism gets its own purge step", plan1.steps.purge.length === 1);
check("the Run key purge says it cannot be undone", plan1.steps.purge[0].reversible === false);
check("every program move states its basis", [...plan1.steps.sever, ...plan1.steps.disable].every((m) => /not a verdict/.test(m.on_what_basis ?? "")));

const def = cont.containmentPlan({ persistence: [{ source: "run-key", subject: "H", target: "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\x\\MpCmdRun.exe", at: null }] });
check("a Defender component gets no move", def.steps.sever.length === 0 && def.steps.disable.length === 0,
  JSON.stringify({ s: def.steps.sever.length, d: def.steps.disable.length }));
check("and the refusal names the product", def.unresolved.some((u) => /Defender/.test(u.why ?? "")));

const nothing = cont.containmentPlan({});
check("no input gives empty layers, all three of them", nothing.empty_layers.length === 3, JSON.stringify(nothing.empty_layers));
check("and the not-claimed list says an empty plan is not a clean machine",
  cont.CONTAINMENT_NOT_CLAIMED.some((s) => /empty plan means nothing told it what to look at/.test(s)));

/* ================================================== through the registry */

section("the three tools answer through the registry");

const tool = (n) => core.TOOLS.find((t) => t.name === n);
const cleanTool = tool("aragami_clean");
const procTool = tool("aragami_processes");
const containTool = tool("aragami_contain");
check("all three are registered", Boolean(cleanTool && procTool && containTool));
check("each declares only the static operation",
  [cleanTool, procTool, containTool].every((t) => Array.isArray(t.operations) && t.operations.length === 1 && t.operations[0] === "static"));

const c = await cleanTool.execute({});
check("clean answers with its schema", c.schema === "aragami-clean-plan/1", String(c.schema));
check("clean says it removed nothing", c.not_claimed.some((s) => /performs no filesystem operation/.test(s)));
check("clean always carries both lists", Array.isArray(c.planned) && Array.isArray(c.kept));

const p = await procTool.execute({});
check("processes answers with its schema", p.schema === "aragami-process-list/1", String(p.schema));
check("processes names the instrument that answered", typeof p.enumerator === "string" && p.enumerator.length > 0, String(p.enumerator));
check("processes says it ended nothing", p.not_claimed.some((s) => /it starts no process and ends none/.test(s)));

const k = await containTool.execute({});
check("contain answers with its schema", k.schema === "aragami-containment-plan/1", String(k.schema));
check("contain reports how many entries it was given", k.input_entries === 0, String(k.input_entries));
check("contain says an empty plan is not a clean machine",
  k.not_claimed.some((s) => /an empty plan means nothing told it what to look at/.test(s)));

/* ================================================== summary */

console.log(`\n${fail ? "\u001b[31m" : "\u001b[32m"}${pass} passed, ${fail} failed\u001b[0m`);
if (fail) { for (const f of failures) console.log(`  - ${f}`); process.exit(1); }
