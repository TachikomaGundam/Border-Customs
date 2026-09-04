// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 16
//
// Multi-remote git push executor. The command surface is frozen by the plan:
// `git push [--dry-run] <url> <branch> --follow-tags` — pushArgv is the ONLY
// argv builder, and the history-rewrite override switch is absent BY
// CONSTRUCTION: no code path in this file appends any flag beyond the four
// slots below, under any combination of border flags (the plan's grep guard on
// this source proves it literally; the AC6 test reads this file).
// The pre-flight is ALL-or-NOTHING: every (remote, ref) pair of the pending
// set is checked BEFORE any push starts, so a diverged backup also protects
// origin from a partial multi-push. Branch refs may only fast-forward
// (`merge-base --is-ancestor <remote> <local>`); tags compare as PEELED
// commits (G43) and a moved tag is never ff-able, so any tag mismatch is a
// divergence. A remote ref that is ABSENT trivially passes — first push to an
// empty remote.
import { spawnSync } from "node:child_process";

import { runGitChecked } from "../check/context.ts";
import { parseLsRemote, PushStateError } from "../pushstate.ts";
import { sanitizeUrl } from "../redact.ts";

/** The plan's exact refusal sentence (AC2 asserts it verbatim). */
export const DIVERGED_MESSAGE = "history diverged; border never force-pushes; resolve manually";

export type GitRemoteTarget = { readonly target: string; readonly url: string };
export type PushMode = "dry-run" | "execute";

/** The one and only push argv builder — dry vs execute differ by exactly the
 *  `--dry-run` slot; nothing else ever rides this array. */
export function pushArgv(url: string, branch: string, mode: PushMode): readonly string[] {
  return mode === "dry-run"
    ? ["push", "--dry-run", url, branch, "--follow-tags"]
    : ["push", url, branch, "--follow-tags"];
}

export type Divergence = {
  readonly target: string;
  readonly ref: string;
  readonly remoteSha: string;
  readonly localSha: string;
};

export type GuardResult = { readonly ok: true } | { readonly ok: false; readonly divergences: readonly Divergence[] };

export type GuardInput = {
  readonly repoDir: string;
  readonly remotes: readonly GitRemoteTarget[];
  readonly refSet: readonly string[];
  readonly env: NodeJS.ProcessEnv;
};

/**
 * Local refSet → commit map. Mirrors pushstate.ts's private localRefCommits
 * (same for-each-ref triple; %(*objectname) peels annotated tags, empty for
 * lightweight refs ⇒ %(objectname) is already the commit). Kept local because
 * the todo-15 module is frozen and does not export its helper.
 */
function localPeeledCommits(repoDir: string, refSet: readonly string[], env: NodeJS.ProcessEnv): Map<string, string> {
  const commits = new Map<string, string>();
  if (refSet.length === 0) return commits;
  const fmt = "--format=%(refname)%09%(objectname)%09%(*objectname)";
  for (const line of runGitChecked(repoDir, ["for-each-ref", fmt, ...refSet], { env }).split("\n")) {
    const [ref, obj, peeled] = line.split("\t");
    if (ref === undefined || obj === undefined) continue;
    commits.set(ref, peeled !== undefined && peeled !== "" ? peeled : obj);
  }
  return commits;
}

/**
 * Peeled remote commit for a ref. Annotated tags answer with the `^{}` line
 * (ls-remote always emits it alongside the tag-object line); a LIGHTWEIGHT tag
 * has no `^{}` line and its own line already IS the commit sha — so the same
 * fallback is truthful for both tag flavors, and localPeeledCommits applies
 * the mirror-image fallback locally. null ⇒ ref absent on the remote.
 */
function remotePeeled(remote: ReadonlyMap<string, string>, ref: string): string | null {
  if (ref.startsWith("refs/tags/")) {
    const peeled = remote.get(`${ref}^{}`);
    if (peeled !== undefined) return peeled;
  }
  return remote.get(ref) ?? null;
}

function lsRemoteMap(repoDir: string, remote: GitRemoteTarget, env: NodeJS.ProcessEnv): Map<string, string> {
  let text: string;
  try {
    text = runGitChecked(repoDir, ["ls-remote", remote.url], { env });
  } catch {
    // inner cause text deliberately dropped — it echoes the raw url; sanitizeUrl owns display (G20).
    throw new PushStateError(
      `target '${remote.target}' unreachable via git ls-remote (${sanitizeUrl(remote.url)}) — refusing to plan a push against a remote we cannot read`,
    );
  }
  return parseLsRemote(text, remote.target);
}

/** true ⇒ the remote's commit is reachable from the local one (pure fast-forward).
 *  merge-base answers via exit code (0 ancestor / 1 not); anything else —
 *  unknown object, spawn failure — fails closed as "not an ancestor". Both
 *  shas already passed parseLsRemote's shape gate, so they cannot smuggle flags. */
function isAncestor(repoDir: string, remoteSha: string, localSha: string, env: NodeJS.ProcessEnv): boolean {
  const r = spawnSync("git", ["-C", repoDir, "merge-base", "--is-ancestor", remoteSha, localSha], {
    encoding: "utf8",
    env: { ...env, GIT_CEILING_DIRECTORIES: repoDir },
  });
  return r.status === 0 && r.error === undefined;
}

/**
 * ALL-or-NOTHING pre-flight over the pending remotes: completes every remote ×
 * ref check BEFORE any push is attempted (the caller must not start the push
 * loop unless this returns ok).
 */
export function fastForwardGuard(i: GuardInput): GuardResult {
  const locals = localPeeledCommits(i.repoDir, i.refSet, i.env);
  const divergences: Divergence[] = [];
  for (const remote of i.remotes) {
    const map = lsRemoteMap(i.repoDir, remote, i.env);
    for (const ref of i.refSet) {
      const local = locals.get(ref);
      if (local === undefined) continue; // no local counterpart ⇒ nothing to transmit for this ref
      const their = remotePeeled(map, ref);
      if (their === null || their === local) continue; // absent ⇒ first push (trivially ok); equal ⇒ no-op
      const canFastForward = ref.startsWith("refs/heads/") && isAncestor(i.repoDir, their, local, i.env);
      if (!canFastForward) divergences.push({ target: remote.target, ref, remoteSha: their, localSha: local });
    }
  }
  return divergences.length === 0 ? { ok: true } : { ok: false, divergences };
}

export type PushExecInput = {
  readonly repoDir: string;
  readonly remote: GitRemoteTarget;
  readonly branch: string;
  readonly env: NodeJS.ProcessEnv;
};

export type PushExecResult = { readonly ok: true } | { readonly ok: false; readonly failure: string };

/**
 * Real push, stdio inherit: credential prompts (ssh-agent, askpass, PAT) pass
 * straight through to the user's TTY — border touches no creds and captures no
 * output. No timeout: an interactive auth prompt may legitimately outlive any
 * fixed budget.
 */
export function executePush(i: PushExecInput): PushExecResult {
  const r = spawnSync("git", ["-C", i.repoDir, ...pushArgv(i.remote.url, i.branch, "execute")], {
    stdio: "inherit",
    env: i.env,
  });
  if (r.error !== undefined) return { ok: false, failure: `git could not start (${r.error.message})` };
  if (r.status !== 0) return { ok: false, failure: `git exited ${String(r.status)}` };
  return { ok: true };
}

/**
 * Post-push proof fed to recordPushSuccess (todo 15 writer): a FRESH ls-remote
 * read of the branch just pushed. Absent answer ⇒ loud throw; border never
 * records a success it cannot confirm on the wire.
 */
export function confirmRemoteBranch(i: {
  readonly repoDir: string;
  readonly remote: GitRemoteTarget;
  readonly branch: string;
  readonly env: NodeJS.ProcessEnv;
}): string {
  const sha = lsRemoteMap(i.repoDir, i.remote, i.env).get(`refs/heads/${i.branch}`);
  if (sha === undefined) {
    throw new PushStateError(
      `target '${i.remote.target}': 'refs/heads/${i.branch}' absent on the remote immediately after a successful push — refusing to record an unconfirmed success`,
    );
  }
  return sha;
}
