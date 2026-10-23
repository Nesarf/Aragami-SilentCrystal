/**
 * Aragami - containment plan
 *
 * THE FOUR MOVES, AS A LIST AND NOT AS ACTIONS.
 *
 * The sibling project acts on these; this one does not, and the reason is the first line of its
 * README. What is portable is the reasoning: an item that can restore itself has to be starved before
 * it is struck, so the order is a derived property rather than a style choice. A file deleted from
 * disk is a file the next boot can recreate.
 *
 * The input is `persistence` -- entries shaped `{ source, subject, target, at }`, from a triage run
 * that this project does not perform. That is stated rather than hidden: with no input the plan is
 * empty, and an empty plan on this project means "nothing told me what to look at", not "the machine
 * is clean".
 */
export const CONTAINMENT_SCHEMA = "aragami-containment-plan/1";

const ON_WHAT_BASIS =
  "This program is listed because it starts itself from a location any process can write to. That is a place to look, " +
  "not a verdict: nothing here judges intent, and an ordinary updater lives in the same places.";

/** Components no plan should offer a move for, whatever their location says. */
export const KNOWN_SYSTEM_COMPONENTS = [
  { pattern: /\\windows defender\\/i, name: "Microsoft Defender", why: "blocking or renaming a Defender component removes the machine's own protection, which is the outcome an intruder would want" },
  { pattern: /\\microsoft security client\\/i, name: "Microsoft Security Client", why: "same reason: it is the anti-malware path, not a payload" },
  { pattern: /\\common files\\microsoft shared\\/i, name: "Microsoft shared runtime", why: "shared components start from here by design; disabling one breaks unrelated software" },
];

/** The first executable in a command line, or null. A shortcut or a directory is not one. */
export function exeFromCommand(command) {
  const s = String(command ?? "").trim();
  if (!s) return null;
  const m = /^"?([^"]*?\.(?:exe|com|scr|bat|cmd|ps1|dll))(?:"|\s|$)/i.exec(s);
  if (!m) return null;
  const candidate = m[1].trim().replace(/,$/, "");
  return /[\\/]/.test(candidate) ? candidate : null;
}

export function looksUserWritablePath(p) {
  const s = String(p ?? "").toLowerCase();
  return /(\\appdata\\|\\users\\public\\|\\programdata\\|\\temp\\|\\tmp\\|\\downloads\\)/.test(s);
}

/** What each autostart mechanism costs to remove, and whether undoing it is possible. */
export const PURGE_BY_SOURCE = {
  "run-key": { what: "registry Run key", command: (s) => `reg delete "${s}" /f`, cost: "the key is gone; anything else that depended on this entry stops too", reversible: false },
  service: { what: "automatic service", command: (s) => `sc.exe config "${String(s).split("\\").pop()}" start= disabled`, cost: "disabled rather than deleted, so the fact that it existed survives", reversible: true },
  task: { what: "scheduled task", command: (s) => `schtasks.exe /Change /TN "${s}" /DISABLE`, cost: "the task stops firing but keeps its definition", reversible: true },
  startup: { what: "startup folder item", command: (s) => `Move-Item -LiteralPath "${s}" -Destination "$env:USERPROFILE\\Desktop\\quarantine\\"`, cost: "moving keeps the file for inspection; it is also one drag away from being live again", reversible: true },
};

export function containmentPlan({ persistence = [] } = {}) {
  const steps = { sever: [], disable: [], purge: [] };
  const unresolved = [];
  const seenExe = new Set();

  for (const item of Array.isArray(persistence) ? persistence : []) {
    const source = String(item?.source ?? "");
    const subject = String(item?.subject ?? "");
    const target = String(item?.target ?? "");
    const exe = exeFromCommand(target);
    const system = exe ? KNOWN_SYSTEM_COMPONENTS.find((c) => c.pattern.test(exe)) : null;

    if (exe && system) {
      unresolved.push({
        layer: "sever", source, subject, target: exe,
        why: `${system.name}: ${system.why}. It is on the autostart list because of where it sits, and that is not enough to act on`,
        how_to_find_out: `confirm the signature first: Get-AuthenticodeSignature "${exe}" | Format-List Status, SignerCertificate`,
      });
    } else if (exe && looksUserWritablePath(exe)) {
      if (!seenExe.has(exe)) {
        seenExe.add(exe);
        steps.sever.push({
          layer: "sever", target: exe,
          action: "Block this program's outbound traffic with a PROGRAM rule, which needs no knowledge of the pool or controller it talks to.",
          command: `New-NetFirewallRule -DisplayName "block-${exe.split(/[\\/]/).pop()}" -Direction Outbound -Program "${exe}" -Action Block`,
          why: "stops the connection while leaving the file in place, so the next steps can be taken without it re-fetching itself",
          cost: "if this program is legitimate, whatever it updates over the network stops working",
          on_what_basis: ON_WHAT_BASIS, reversible: true,
        });
        steps.disable.push(
          { layer: "disable", target: exe, action: "Deny execute, leaving the bytes for collection.", command: `icacls "${exe}" /deny "$($env:USERNAME):(X)"`, why: "the file cannot start and is still there to hash", cost: "an administrator can restore the ACL, and the file remains readable", on_what_basis: ON_WHAT_BASIS, reversible: true },
          { layer: "disable", target: exe, action: "Rename it so a recorded path no longer resolves.", command: `Rename-Item -LiteralPath "${exe}" -NewName "$(Split-Path "${exe}" -Leaf).held"`, why: "defeats the most common restore mechanism", cost: "a restore routine that scans rather than names will find the new name", on_what_basis: ON_WHAT_BASIS, reversible: true },
          { layer: "disable", target: exe, action: "Move it into quarantine, outside every autostart path.", command: `Move-Item -LiteralPath "${exe}" -Destination "$env:USERPROFILE\\Desktop\\quarantine\\"`, why: "removes it from reach without destroying the evidence", cost: "the original path is now empty, which some installers treat as a reason to reinstall", on_what_basis: ON_WHAT_BASIS, reversible: true },
        );
      }
    } else if (exe) {
      unresolved.push({ layer: "purge", source, subject, target, why: "the autostart is real but the program is not in a user-writable place -- a temp copy may be the payload, and this does not guess which", how_to_find_out: `sc.exe qc "${subject}"  or  schtasks.exe /Query /TN "${subject}" /V /FO LIST` });
    } else {
      unresolved.push({ layer: "sever", source, subject, target, why: "the recorded command names no executable -- a shortcut, a directory or a launcher is one resolution away from the file it starts", how_to_find_out: `(New-Object -ComObject WScript.Shell).CreateShortcut("${target}").TargetPath` });
    }

    const recipe = PURGE_BY_SOURCE[source];
    if (recipe) {
      steps.purge.push({ layer: "purge", target: subject || target, action: `Remove the ${recipe.what} that would start it again.`, command: recipe.command(subject || target), why: "an entry that survives restores the program after everything above was done", cost: recipe.cost, reversible: recipe.reversible });
    } else {
      unresolved.push({ layer: "purge", source, subject, target, why: "this mechanism has no generic removal written down here; removing it by hand risks taking out a legitimate entry beside it", how_to_find_out: "read the mechanism's own listing before deleting anything from it" });
    }
  }

  return {
    steps,
    order: ["sever", "disable", "purge"],
    why_this_order: "Something on this list is recorded as starting itself, so the moves run outward-in: cut the connection, stop it starting, then remove what would bring it back. Reversing that order lets it come back before the third step is reached.",
    unresolved,
    empty_layers: ["sever", "disable", "purge"].filter((l) => steps[l].length === 0),
  };
}

export const CONTAINMENT_NOT_CLAIMED = [
  "That anything on this list was carried out. This project executes nothing: no process, no registry write, no firewall rule.",
  "That the list is complete. It is built only from the persistence entries the caller passed in -- this project performs no triage of its own, so an empty plan means nothing told it what to look at.",
  "That the order is right for every threat. It is derived from one signal: a recorded autostart. An item that restores itself some other way is not detected.",
  "That a blocked program is a contained one. The rule stops the connection from this machine and nothing else.",
];
