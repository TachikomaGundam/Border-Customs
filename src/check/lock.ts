// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 10
//
// G22 `.border` state discipline. ensureStateDir() idempotently creates the
// state dir and writes .border/.gitignore containing EXACTLY "*\n" so border's
// own untracked state (runs/, tmp/, lock) can never be staged by a careless
// `git add -A` in the target repo — the ROOT .gitignore is never touched.
// acquireLock() is a cooperative single-writer lock: O_EXCL write of the holder
// pid; on EEXIST the holder is liveness-probed (signal 0). A live holder means
// a concurrent check ⇒ BorderLockHeldError (border exit 2) naming the pid; a
// dead/unparseable holder is a crashed predecessor ⇒ the lock file is replaced
// and the caller surfaces the STALE_LOCK_WARNING line. releaseLock() only
// unlinks while OUR pid is still the holder, so a recovering process's lock is
// never stolen.
import { mkdirSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export const BORDER_STATE_DIR = ".border";
export const STALE_LOCK_WARNING = "stale lock recovered";

export function lockPath(repoDir: string): string {
  return join(repoDir, BORDER_STATE_DIR, "lock");
}

function codeOf(err: unknown): string | undefined {
  return typeof err === "object" && err !== null ? (err as { code?: string }).code : undefined;
}

export function ensureStateDir(repoDir: string): void {
  const stateDir = join(repoDir, BORDER_STATE_DIR);
  mkdirSync(stateDir, { recursive: true });
  const gitignore = join(stateDir, ".gitignore");
  let current: string | null = null;
  try {
    current = readFileSync(gitignore, "utf8");
  } catch (err) {
    if (codeOf(err) !== "ENOENT") throw err;
  }
  if (current !== "*\n") writeFileSync(gitignore, "*\n");
}

/** A second live border run holds the lock — exit-2 tool error, never a verdict. */
export class BorderLockHeldError extends Error {
  readonly exitCode: 2 = 2;
  readonly holderPid: number;

  constructor(holderPid: number, ourPid: number) {
    super(`lock held by pid ${String(holderPid)} — another border check is running (pid ${String(ourPid)} refuses to race it)`);
    this.name = "BorderLockHeldError";
    this.holderPid = holderPid;
  }
}

function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    // EPERM means the pid exists under another uid; ESRCH (and anything else) is dead.
    return codeOf(err) === "EPERM";
  }
}

function readHolderPid(path: string): number | null {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    return null;
  }
  const pid = Number.parseInt(text.trim(), 10);
  return Number.isSafeInteger(pid) && pid > 0 ? pid : null;
}

export type LockHandle = { readonly path: string; readonly pid: number };

export function acquireLock(repoDir: string): { readonly handle: LockHandle; readonly warning: string | null } {
  ensureStateDir(repoDir);
  const path = lockPath(repoDir);
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      writeFileSync(path, `${String(process.pid)}\n`, { flag: "wx" });
      return { handle: { path, pid: process.pid }, warning: attempt === 1 ? STALE_LOCK_WARNING : null };
    } catch (err) {
      if (codeOf(err) !== "EEXIST") throw err;
      const holder = readHolderPid(path);
      if (holder !== null && pidAlive(holder)) throw new BorderLockHeldError(holder, process.pid);
      try {
        unlinkSync(path);
      } catch (unlinkErr) {
        if (codeOf(unlinkErr) !== "ENOENT") throw unlinkErr;
      }
    }
  }
  throw new BorderLockHeldError(readHolderPid(path) ?? -1, process.pid);
}

export function releaseLock(handle: LockHandle): void {
  try {
    if (readHolderPid(handle.path) === handle.pid) unlinkSync(handle.path);
  } catch (err) {
    if (codeOf(err) !== "ENOENT") throw err;
  }
}
