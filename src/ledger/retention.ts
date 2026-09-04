// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 14
//
// Run-archive retention (plan AC: newest 20 run dirs per key8 survive 25
// seeded runs). `.border/runs/<key8>-<ts>/` dir names embed a sanitised ISO-8601
// timestamp, so lexicographic sort IS chronological order and pruning is a
// slice. Ledger lines are NEVER pruned — the file is append-only; only the
// bulky report.json archives get collected. Same-key8 runs share a fingerprint,
// hence identical findings, so deleting the older report archives loses no
// information the ledger record itself does not carry.
import { existsSync, mkdirSync, readdirSync, rmSync } from "node:fs";
import { join } from "node:path";

import { RUNS_SUBDIR, runsDir } from "./records.ts";

export const KEEP_RUN_DIRS_PER_KEY8 = 20;

function codeOf(err: unknown): string | undefined {
  return typeof err === "object" && err !== null ? (err as { code?: string }).code : undefined;
}

/** ISO ts with `:` and `.` replaced — filesystem-safe, still lexicographically chronological. */
export function runDirName(key8: string, ts: string): string {
  return `${key8}-${ts.replace(/[:.]/g, "-")}`;
}

/** Collision-free dir name: same-ms runs get a `-r2`, `-r3`, ... suffix (suffix sorts last). */
export function uniqueRunDirName(repoDir: string, key8: string, ts: string): string {
  const base = runDirName(key8, ts);
  let name = base;
  for (let n = 2; existsSync(join(runsDir(repoDir), name)) && n < 1000; n += 1) {
    name = `${base}-r${String(n)}`;
  }
  return name;
}

/** Create (idempotently) the run dir for one record; returns its absolute path. */
export function ensureRunDir(repoDir: string, name: string): string {
  const dir = join(runsDir(repoDir), name);
  mkdirSync(dir, { recursive: true });
  return dir;
}

export function reportRelPath(name: string): string {
  return `${RUNS_SUBDIR}/${name}/report.json`;
}

/**
 * Keep the newest `keep` dirs whose name starts `<key8>-`; drop the rest.
 * Returns the removed dir names (empty when the runs dir does not exist yet).
 * Directories belonging to other key8s are never touched.
 */
export function pruneRunDirs(repoDir: string, key8: string, keep: number = KEEP_RUN_DIRS_PER_KEY8): string[] {
  let entries: string[];
  try {
    entries = readdirSync(runsDir(repoDir));
  } catch (err) {
    if (codeOf(err) === "ENOENT") return [];
    throw err;
  }
  const prefix = `${key8}-`;
  const mine = entries.filter((e) => e.startsWith(prefix)).sort();
  const doomed = mine.slice(0, Math.max(0, mine.length - keep));
  for (const dir of doomed) {
    rmSync(join(runsDir(repoDir), dir), { recursive: true, force: true });
  }
  return doomed;
}
