// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 7;
// --yes executor rewired by todo 16 (multi-remote git push, all-or-nothing ff guard);
// same-bytes registry legs (npm → pypi) wired into --yes and dry-run by todo 17b.
//
// `border push` — the DRY-RUN default (plan G10 + round-5 m-R5-a):
//   * bare push performs ZERO mutations — it prints the per-remote plan and
//     asks the registry's check handler (the gate seam) for the verdict the
//     gate WOULD produce: clean⇒0, gate-blocked⇒1, gate-unavailable⇒2.
//     A dry-run must never print a misleading 0.
//   * --yes is the ONLY mutation path. It derives live push-state (todo 15),
//     refuses exit 1 while ANY target is BLOCKED (gate discipline unchanged),
//     runs the ALL-or-NOTHING non-fast-forward pre-flight over the PENDING git
//     remotes (todo 16: a diverged backup protects origin too), then pushes
//     each pending remote with `stdio: inherit` (border touches no creds) and
//     appends one push-record per confirmed success. Cross-target order is
//     fixed: git remotes → npm → PyPI.
// The DRY_RUN/GIT_PUSH strings live here exactly once (plan grep guard — the
// todo 16 executor imports these constants, never retypes them).
import { computeEffectiveTargets, resolveRepoDir } from "../check/context.ts";
import { computeConfigDigest, type LoadedConfig } from "../check/rulesHash.ts";
import { EXIT_BLOCKED, EXIT_ERROR, EXIT_PASS, type BorderExit } from "../cli/exit.ts";
import type { Ctx } from "../cli/types.ts";
import { loadConfig } from "../config.ts";
import { computeFingerprint, latestPassCoveringTargets, readLedger } from "../ledger.ts";
import { derivePushState, formatTargetLine, pushableTargets, recordPushSuccess, PushStateError, type PushStateResult } from "../pushstate.ts";
import { confirmRemoteBranch, DIVERGED_MESSAGE, executePush, fastForwardGuard, type GitRemoteTarget } from "../push/git.ts";
import { runNpmPublish, type PublishInput, type PublishTarget } from "../push/npm.ts";
import { runPypiPublish } from "../push/pypi.ts";
import { sanitizeUrl } from "../redact.ts";

export const DRY_RUN_PREFIX = "DRY-RUN";
export const GIT_PUSH_DRY_RUN = "git push --dry-run";

/**
 * Credential-safe remote display: scheme URLs and scp-form git remotes carry
 * userinfo/query secrets and go through the todo-3 sanitizer; plain filesystem
 * paths (./bare.git, /srv/git/…) have no credential slot and stay verbatim.
 */
export function displayRemote(url: string): string {
  const credentialBearing =
    /^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(url) || /^[A-Za-z0-9_.+-]+@[^:@/\s]+:/.test(url);
  return credentialBearing ? sanitizeUrl(url) : url;
}

function shortSha(sha: string): string {
  return sha.slice(0, 8);
}

export async function runPush(ctx: Ctx): Promise<BorderExit> {
  const loaded = loadConfig({
    ...(ctx.flags.config !== undefined ? { configPath: ctx.flags.config } : {}),
    cwd: ctx.cwd,
    env: ctx.env,
  });
  if (loaded.kind === "no-op") {
    for (const warning of loaded.warnings) ctx.stderr(`border: ${warning}`);
    ctx.stdout("border: no targets discovered — nothing to push (NO-OP)");
    return EXIT_PASS;
  }
  return ctx.flags.yes ? executeYesPush(ctx, loaded) : dryRunPush(ctx, loaded);
}

/** The todo-17/17b registry publishers, fixed npm → PyPI order (PublishInput
 *  is shared; exhaustive switch — a new PublishTarget cannot slip through). */
function registryRunner(kind: PublishTarget): (i: PublishInput) => Promise<BorderExit> {
  switch (kind) {
    case "npm":
      return runNpmPublish;
    case "pypi":
      return runPypiPublish;
  }
}

/**
 * What --yes would do on each configured registry leg — zero network, zero
 * mutation. No PASS record under the live fingerprint key ⇒ an honest
 * cannot-list line (dry-run must not fake artifact knowledge). Record present
 * ⇒ delegate to the REAL executor in dry mode: its ledger gate and same-bytes
 * re-hash run (local I/O only) and the publish command prints; a re-hash
 * mismatch surfaces its message and the leg's exit, still with zero probes.
 * The key derives exactly like derivePushState's (same configDigest inputs).
 */
async function dryRunRegistryLegs(ctx: Ctx, loaded: LoadedConfig): Promise<BorderExit> {
  const env: NodeJS.ProcessEnv = { ...ctx.env };
  const effectiveTargets = computeEffectiveTargets(loaded.config, ctx.flags.targets);
  const kinds: readonly PublishTarget[] = (["npm", "pypi"] as const).filter(
    (k) => effectiveTargets.includes(k) && loaded.config.targets[k] !== undefined,
  );
  if (kinds.length === 0) return EXIT_PASS;
  const repoDir = resolveRepoDir(ctx.cwd, { env });
  const { fp } = await computeFingerprint(repoDir, loaded.config, computeConfigDigest(loaded), effectiveTargets, {
    env,
    ...(ctx.flags.requireEngine !== undefined && ctx.flags.requireEngine.length > 0 ? { requireOverride: ctx.flags.requireEngine } : {}),
  });
  const { records } = readLedger(repoDir);
  for (const kind of kinds) {
    if (latestPassCoveringTargets(records, fp.key, [kind]) === null) {
      ctx.stdout(`  ${DRY_RUN_PREFIX}: ${kind} registry leg: run 'border check --force' first — dry-run cannot list artifacts`);
      continue;
    }
    const code = await registryRunner(kind)({
      repoDir,
      cfg: loaded.config,
      key: fp.key,
      yes: false,
      env,
      out: (line) => ctx.stdout(`  ${DRY_RUN_PREFIX}: ${line}`),
      err: ctx.stderr,
    });
    if (code !== EXIT_PASS) return code;
  }
  return EXIT_PASS;
}

async function dryRunPush(ctx: Ctx, loaded: LoadedConfig): Promise<BorderExit> {
  ctx.stdout(`border ${DRY_RUN_PREFIX}: no --yes, so nothing runs — this is the plan (m-R5-a) contract`);
  for (const remote of loaded.config.targets.git.remotes) {
    ctx.stdout(`  ${DRY_RUN_PREFIX}: ${GIT_PUSH_DRY_RUN} ${remote.name ?? displayRemote(remote.url)} --follow-tags  (${displayRemote(remote.url)})`);
  }
  const registryCode = await dryRunRegistryLegs(ctx, loaded);
  if (registryCode !== EXIT_PASS) return registryCode;
  // Gate seam: the registry's check handler stands in for todo 10's pipeline.
  const verdict = await ctx.handlers.check({ ...ctx, command: "check" });
  if (verdict === EXIT_ERROR) {
    ctx.stderr("border: gate verdict unavailable — dry-run exits 2, never a misleading 0");
  }
  return verdict;
}

/** Pending git legs, in configured-remote order, matched to their target ids. */
function gitLegs(state: PushStateResult, loaded: LoadedConfig): GitRemoteTarget[] {
  const pending = pushableTargets(state).filter((t) => t.kind === "git");
  const legs: GitRemoteTarget[] = [];
  for (const t of pending) {
    const remote = loaded.config.targets.git.remotes.find((r) => `git:${r.name ?? sanitizeUrl(r.url)}` === t.target);
    // pushstate derives the id FROM these remotes, so a PENDING git target always resolves.
    if (remote !== undefined) legs.push({ target: t.target, url: remote.url });
  }
  return legs;
}

async function executeYesPush(ctx: Ctx, loaded: LoadedConfig): Promise<BorderExit> {
  const env: NodeJS.ProcessEnv = { ...ctx.env };
  const repoDir = resolveRepoDir(ctx.cwd, { env });
  // Same digest the check run fed into the fingerprint — else the gates won't match.
  const configDigest = computeConfigDigest(loaded);
  const effectiveTargets = computeEffectiveTargets(loaded.config, ctx.flags.targets);
  let state: PushStateResult;
  try {
    state = await derivePushState({
      repoDir,
      cfg: loaded.config,
      configDigest,
      effectiveTargets,
      env,
      ...(ctx.flags.requireEngine !== undefined && ctx.flags.requireEngine.length > 0 ? { requireOverride: ctx.flags.requireEngine } : {}),
    });
  } catch (err) {
    if (err instanceof PushStateError) {
      ctx.stderr(`border: ${err.message}`);
      return EXIT_ERROR;
    }
    throw err; // ConfigError/EngineRunError keep the run()-level exit-2 mapping
  }

  for (const t of state.targets) ctx.stdout(`border: ${formatTargetLine(t)}`);
  for (const w of state.warnings) ctx.stderr(`border: WARNING ${w}`);

  const blocked = state.targets.filter((t) => t.status === "BLOCKED");
  if (blocked.length > 0) {
    ctx.stderr(`border: push --yes refused — ${String(blocked.length)} BLOCKED target(s) above; nothing was pushed`);
    return EXIT_BLOCKED;
  }
  const pending = pushableTargets(state);
  if (pending.length === 0) {
    ctx.stdout("border: nothing pending — every target is already PUSHED (no-op)");
    return EXIT_PASS;
  }

  const legs = gitLegs(state, loaded);
  if (legs.length > 0) {
    const branchRef = state.refSet.find((r) => r.startsWith("refs/heads/"));
    if (branchRef === undefined) {
      ctx.stderr("border: detached HEAD — the push ref-set holds no branch ref; refusing to guess a branch to push");
      return EXIT_ERROR;
    }
    const branch = branchRef.slice("refs/heads/".length);
    for (const leg of legs) {
      ctx.stdout(`  ${DRY_RUN_PREFIX}: ${GIT_PUSH_DRY_RUN} ${leg.target.slice("git:".length)} ${branch} --follow-tags  (${displayRemote(leg.url)})`);
    }

    // ALL-or-NOTHING: every remote × ref checked before ANY push starts.
    const guard = fastForwardGuard({ repoDir, remotes: legs, refSet: state.refSet, env });
    if (!guard.ok) {
      ctx.stderr(`border: ${DIVERGED_MESSAGE}`);
      for (const d of guard.divergences) {
        ctx.stderr(`border:   ${d.target} ${d.ref}: remote ${shortSha(d.remoteSha)} is not an ancestor of local ${shortSha(d.localSha)} — a fast-forward is impossible`);
      }
      return EXIT_BLOCKED;
    }

    const done: string[] = [];
    for (const leg of legs) {
      const result = executePush({ repoDir, remote: leg, branch, env });
      if (!result.ok) {
        ctx.stderr(
          `border: PARTIAL push — '${leg.target}' failed (${result.failure}) after ${String(done.length)}/${String(legs.length)} remote(s) [${done.length === 0 ? "none" : done.join(", ")}] landed; rerun 'border push --yes' — landed remotes come back PUSHED(no-op)`,
        );
        return EXIT_BLOCKED;
      }
      const remoteSha = confirmRemoteBranch({ repoDir, remote: leg, branch, env });
      recordPushSuccess(repoDir, {
        key: state.key,
        target: leg.target,
        remoteName: leg.target.slice("git:".length), // configured name ?? sanitized url
        url: leg.url,
        localSha: state.headSha,
        remoteSha,
        confirmedVia: "ls-remote",
      });
      done.push(leg.target);
      ctx.stdout(`border: pushed ${leg.target} — ${shortSha(remoteSha)} confirmed via ls-remote`);
    }
  }

  // Cross-target order fixed by the plan: git remotes (done above) → npm → PyPI.
  // The literal ["npm", "pypi"] iteration below IS the order enforcement; a
  // failing leg returns its exit immediately so a later leg never publishes on
  // top of it. key: state.key — the fingerprint derivePushState itself used
  // (configDigest discipline: never recompute).
  for (const kind of ["npm", "pypi"] as const) {
    if (!pending.some((t) => t.kind === kind)) continue;
    const code = await registryRunner(kind)({
      repoDir,
      cfg: loaded.config,
      key: state.key,
      yes: true,
      env,
      out: ctx.stdout,
      err: ctx.stderr,
    });
    if (code !== EXIT_PASS) return code;
  }
  return EXIT_PASS;
}
