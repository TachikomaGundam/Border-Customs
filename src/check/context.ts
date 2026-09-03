// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 10
//
// Check-context gathering: everything the pipeline proves something about.
//   * repoDir   — git toplevel of the invocation cwd (outside a repo ⇒ exit 2);
//   * headSha   — `rev-parse HEAD`; an unborn HEAD fails closed, border cannot
//     fingerprint a repository with no commits;
//   * porcelainDigest / dirty — sha256 of `git status --porcelain=v1` output and
//     whether that output is non-empty (todo 14 keys the skip-ledger on it);
//   * refSet    — the refs a push would touch, as FULL REFNAMES, sorted:
//     current branch tip + ALL local tags (annotated and lightweight).
// Interpretation of the plan's `rev-list --branches=<cur> --tags` basis: the
// scan universe is "commits reachable from the pushed refs". git's
// `--branches=<name>` does prefix-GLOB matching (empirically `--branches=main`
// can return nothing), so border enumerates the exact refnames instead and
// feeds them to gitleaks as positive `--log-opts` revs — same reachability
// semantics, no silent glob misses. Detached HEAD pushes no branch ⇒ refSet is
// tags only (documented; the history leg then falls back to HEAD, see check.ts).
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { dirname, resolve } from "node:path";

import { ConfigError, type BorderConfig } from "../config.ts";

export type GitCallOptions = {
  env?: Readonly<Record<string, string | undefined>>;
};

function gitSpawn(repoDir: string, args: readonly string[], o: GitCallOptions = {}): { status: number; stdout: string; stderr: string } {
  const abs = resolve(repoDir);
  const r = spawnSync("git", ["-C", abs, ...args], {
    encoding: "utf8",
    env: { ...(o.env ?? process.env), GIT_CEILING_DIRECTORIES: dirname(abs) },
    timeout: 60_000,
  });
  if (r.error !== undefined) {
    throw new ConfigError("git-failed", `git ${args.join(" ")} could not spawn: ${r.error.message}`);
  }
  return { status: r.status ?? -1, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
}

/** git inside the fenced repo; any non-zero status is a fail-closed ConfigError (exit 2). */
export function runGitChecked(repoDir: string, args: readonly string[], o: GitCallOptions = {}): string {
  const r = gitSpawn(repoDir, args, o);
  if (r.status !== 0) {
    throw new ConfigError("git-failed", `git ${args.join(" ")} in ${resolve(repoDir)} exited ${String(r.status)}: ${r.stderr.trim().slice(0, 200)}`);
  }
  return r.stdout;
}

function gitOrNull(repoDir: string, args: readonly string[], o: GitCallOptions): string | null {
  const r = gitSpawn(repoDir, args, o);
  return r.status === 0 ? r.stdout.trim() : null;
}

export function resolveRepoDir(cwd: string, o: GitCallOptions = {}): string {
  const r = gitSpawn(cwd, ["rev-parse", "--show-toplevel"], o);
  if (r.status !== 0) {
    throw new ConfigError("git-failed", `not a git repository: ${resolve(cwd)} — border check needs a repo to gate`);
  }
  return resolve(r.stdout.trim());
}

export type CheckContext = {
  readonly repoDir: string;
  readonly headSha: string;
  readonly porcelainDigest: string;
  readonly dirty: boolean;
  /** sorted full refnames a push would touch: current branch tip + all tags. */
  readonly refSet: readonly string[];
  /** current branch refname, or null when detached (push would touch tags only). */
  readonly currentBranch: string | null;
};

export function gatherContext(repoDir: string, o: GitCallOptions = {}): CheckContext {
  const headSha = gitOrNull(repoDir, ["rev-parse", "HEAD"], o);
  if (headSha === null) {
    throw new ConfigError("git-failed", `repository at ${resolve(repoDir)} has no commits at HEAD — border cannot gate an unborn branch`);
  }
  const porcelain = runGitChecked(repoDir, ["status", "--porcelain=v1"], o);
  const branch = gitOrNull(repoDir, ["symbolic-ref", "--quiet", "HEAD"], o);
  const tags = runGitChecked(repoDir, ["for-each-ref", "--format=%(refname)", "refs/tags"], o)
    .split("\n")
    .filter((ref) => ref !== "");
  const refSet = [...new Set([...(branch !== null ? [branch] : []), ...tags])].sort();
  return {
    repoDir: resolve(repoDir),
    headSha,
    porcelainDigest: createHash("sha256").update(porcelain, "utf8").digest("hex"),
    dirty: porcelain.trim() !== "",
    refSet,
    currentBranch: branch,
  };
}

/** effectiveTargets = configured target set ∩ --targets; an unconfigured request is exit 2. */
export function computeEffectiveTargets(cfg: BorderConfig, requested: readonly string[] | undefined): string[] {
  const configured = new Set<string>();
  if (cfg.targets.git.remotes.length > 0) configured.add("git");
  if (cfg.targets.npm !== undefined) configured.add("npm");
  if (cfg.targets.pypi !== undefined) configured.add("pypi");
  const wanted = requested === undefined || requested.length === 0 ? [...configured] : requested;
  for (const target of wanted) {
    if (!configured.has(target)) {
      const list = [...configured].sort().join(", ") || "none";
      throw new ConfigError("invalid-value", `--targets '${target}' is not configured in border.yaml (configured targets: ${list})`, { key: "targets" });
    }
  }
  return [...new Set(wanted)].sort();
}
