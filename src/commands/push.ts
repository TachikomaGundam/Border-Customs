// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 7;
// --yes executor rewired by todo 16 (multi-remote git push, all-or-nothing ff guard);
// same-bytes registry legs (npm → pypi) wired into --yes and dry-run by todo 17b;
// registry legs re-pointed at the channel descriptors by border-push-channels.md
// todo C2 — iteration order comes from each descriptor's `order` field
// (npm 1 → pypi 2), and the publish call is channel.publish (one code path).
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
//     fixed: git remotes → npm → PyPI. Every --yes run that reaches push-state
//     appends exactly one t:"push-result" verdict line (landed/blocked/partial/
//     failed/noop) — Sibyl ticket 2026-11-08 wound 2; dry-run writes nothing.
// The DRY_RUN/GIT_PUSH strings live here exactly once (plan grep guard — the
// todo 16 executor imports these constants, never retypes them).
import { spawnSync } from "node:child_process";

import { computeEffectiveTargets, resolveRepoDir } from "../check/context.ts";
import { computeConfigDigest, type LoadedConfig } from "../check/rulesHash.ts";
import { EXIT_BLOCKED, EXIT_ERROR, EXIT_PASS, type BorderExit } from "../cli/exit.ts";
import type { Ctx } from "../cli/types.ts";
import { loadConfig, remoteTrackingDrift } from "../config.ts";
import { appendRecord, buildPushResultRecord, computeFingerprint, latestPassCoveringTargets, readLedger } from "../ledger.ts";
import { derivePushState, formatTargetLine, pushableTargets, recordPushSuccess, PushStateError, type PushStateResult } from "../pushstate.ts";
import { confirmRemoteBranch, DIVERGED_MESSAGE, executePush, fastForwardGuard, preflightPushRefs, type GitRemoteTarget } from "../push/git.ts";
import { runLandingVerification } from "../push/landing.ts";
import { publishChannels } from "../channels/registry.ts";
import { sanitizeUrl } from "../redact.ts";
import { gitTargetId } from "../gitTargetId.ts";

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

/** symbolic-ref answers 1 ⇔ detached HEAD; every other failure (outside a
 *  repo, git missing) is NOT claimed as detached — the check leg owns those. */
function isDetachedHead(ctx: Ctx): boolean {
  try {
    const repoDir = resolveRepoDir(ctx.cwd, { env: ctx.env });
    const r = spawnSync("git", ["-C", repoDir, "symbolic-ref", "--quiet", "HEAD"], { encoding: "utf8", env: ctx.env });
    return r.error === undefined && r.status === 1;
  } catch {
    return false;
  }
}

export async function runPush(ctx: Ctx): Promise<BorderExit> {
  const loaded = loadConfig({
    ...(ctx.flags.config !== undefined ? { configPath: ctx.flags.config } : {}),
    cwd: ctx.cwd,
    env: ctx.env,
  });
  if (loaded.kind === "no-op") {
    for (const warning of loaded.warnings) ctx.stderr(`border: ${warning}`);
    let orphans: string[] = [];
    try {
      const drift = remoteTrackingDrift(resolveRepoDir(ctx.cwd, { env: ctx.env }));
      if (!drift.probesOk) {
        // Sibyl wound 4: an empty orphan set from a probe that never answered
        // (corrupt refs store, git spawn failure) certifies nothing — the
        // NO-OP claim would be made by a broken instrument. Fail closed, named.
        ctx.stderr(
          "border: cannot certify 'nothing to push' — the remote-tracking drift probe (git remote -v / for-each-ref) did not answer; refusing to report a no-op on a broken instrument",
        );
        return EXIT_ERROR;
      }
      orphans = drift.orphans;
    } catch (err) {
      // Only resolveRepoDir's "not a git repository" may keep the NO-OP here:
      // a non-repo structurally cannot hold remote-tracking refs. Anything
      // else is a probe failure — same broken-instrument rule, exit 2.
      if (!(err instanceof Error && err.message.startsWith("not a git repository"))) {
        const why = err instanceof Error ? err.message : String(err);
        ctx.stderr(`border: cannot certify 'nothing to push' — drift probe failed (${why}); refusing to report a no-op on a broken instrument`);
        return EXIT_ERROR;
      }
    }
    if (orphans.length > 0) {
      ctx.stderr(
        `border: remote config drift — remote-tracking refs exist for UNCONFIGURED remotes: ${orphans.join(", ")}; their remote.* entries are gone (wiped or partial clone). Restore them or prune the refs; refusing to report this as a no-op.`,
      );
      return EXIT_ERROR;
    }
    ctx.stdout("border: no targets discovered — nothing to push (NO-OP)");
    return EXIT_PASS;
  }
  return ctx.flags.yes ? executeYesPush(ctx, loaded) : dryRunPush(ctx, loaded);
}

/**
 * What --yes would do on each configured registry leg — zero network, zero
 * mutation. No PASS record under the live fingerprint key ⇒ an honest
 * cannot-list line (dry-run must not fake artifact knowledge). Record present
 * ⇒ delegate to the REAL executor in dry mode: its ledger gate and same-bytes
 * re-hash run (local I/O only) and the publish command prints; a re-hash
 * mismatch surfaces its message and the leg's exit, still with zero probes.
 * The key derives exactly like derivePushState's (same configDigest inputs).
 * Channel legs iterate in descriptor `order` (npm 1 → pypi 2, todo C2).
 */
async function dryRunRegistryLegs(ctx: Ctx, loaded: LoadedConfig): Promise<BorderExit> {
  const env: NodeJS.ProcessEnv = { ...ctx.env };
  const effectiveTargets = computeEffectiveTargets(loaded.config, ctx.flags.targets);
  const legs = publishChannels().filter((ch) => effectiveTargets.includes(ch.id) && ch.configured(loaded.config));
  if (legs.length === 0) return EXIT_PASS;
  const repoDir = resolveRepoDir(ctx.cwd, { env });
  const { fp } = await computeFingerprint(repoDir, loaded.config, computeConfigDigest(loaded), effectiveTargets, {
    env,
    ...(ctx.flags.requireEngine !== undefined && ctx.flags.requireEngine.length > 0 ? { requireOverride: ctx.flags.requireEngine } : {}),
  });
  const { records } = readLedger(repoDir);
  for (const channel of legs) {
    if (latestPassCoveringTargets(records, fp.key, [channel.id]) === null) {
      ctx.stdout(`  ${DRY_RUN_PREFIX}: ${channel.id} registry leg: run 'border check --force' first — dry-run cannot list artifacts`);
      continue;
    }
    const code = await channel.publish({
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
  if (loaded.config.targets.git.remotes.length > 0 && isDetachedHead(ctx)) {
    // plan/--yes parity: --yes refuses on detached HEAD (exit 2) — the dry-run
    // plan must say so instead of printing a push line --yes would never run.
    ctx.stderr("border: WARNING detached HEAD — the push ref-set holds no branch ref; 'border push --yes' would refuse to guess a branch to push");
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

/** Pending git legs, in configured-remote order, matched to their target ids.
 *  Resolution is a Map keyed by the SAME gitTargetId helper pushstate used to
 *  build the ids — index-keyed `git:#N` ids make every key unique, so a target
 *  can never first-match a different (unnamed) remote again. */
function gitLegs(state: PushStateResult, loaded: LoadedConfig): GitRemoteTarget[] {
  const pending = pushableTargets(state).filter((t) => t.kind === "git");
  const byId = new Map(loaded.config.targets.git.remotes.map((r, index) => [gitTargetId(r, index), r]));
  const legs: GitRemoteTarget[] = [];
  for (const t of pending) {
    const remote = byId.get(t.target);
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
  // Sibyl wound 2: one t:"push-result" verdict line per --yes run that reaches
  // push-state — minted at EVERY exit below; dry-run never reaches here. A
  // ledger this gate cannot write is a gate that fails loudly (appendRecord
  // throws → run()-level exit 2), never a verdict that vanishes unrecorded.
  const recordOutcome = (i: Parameters<typeof buildPushResultRecord>[0]): void => {
    appendRecord(repoDir, buildPushResultRecord(i));
  };
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
      recordOutcome({ verdict: "failed", targets: effectiveTargets, reason: `push-state derivation failed: ${err.message}` });
      return EXIT_ERROR;
    }
    throw err; // ConfigError/EngineRunError keep the run()-level exit-2 mapping
  }

  for (const t of state.targets) ctx.stdout(`border: ${formatTargetLine(t)}`);
  for (const w of state.warnings) ctx.stderr(`border: WARNING ${w}`);

  const blocked = state.targets.filter((t) => t.status === "BLOCKED");
  if (blocked.length > 0) {
    ctx.stderr(`border: push --yes refused — ${String(blocked.length)} BLOCKED target(s) above; nothing was pushed`);
    recordOutcome({
      key: state.key,
      verdict: "blocked",
      targets: blocked.map((t) => t.target),
      reason: blocked.map((t) => `${t.target}: ${t.reason ?? "blocked"}`).join("; "),
    });
    return EXIT_BLOCKED;
  }
  const pending = pushableTargets(state);
  if (pending.length === 0) {
    ctx.stdout("border: nothing pending — every target is already PUSHED (no-op)");
    recordOutcome({ key: state.key, verdict: "noop", targets: state.targets.map((t) => t.target) });
    return EXIT_PASS;
  }

  const pendingIds = pending.map((t) => t.target);
  const done: string[] = []; // git legs with ls-remote-confirmed landings (registry outcome reads this)
  const branchRef = state.refSet.find((r) => r.startsWith("refs/heads/"));
  const branch = branchRef?.slice("refs/heads/".length);
  const branchOpt = branch === undefined ? {} : { branch };
  const legs = gitLegs(state, loaded);
  if (legs.length > 0) {
    if (branch === undefined) {
      ctx.stderr("border: detached HEAD — the push ref-set holds no branch ref; refusing to guess a branch to push");
      recordOutcome({
        key: state.key,
        verdict: "failed",
        targets: pendingIds,
        reason: `detached HEAD — ref-set holds no refs/heads/* ref to push; remotes: ${legs.map((l) => l.target).join(", ")}`,
      });
      return EXIT_ERROR;
    }

    // Sibyl wound 3: every refspec/leg input is checked BEFORE any push spawns,
    // each problem named by ref, remote(s), and what is missing — then ledged.
    const preflight = preflightPushRefs({ repoDir, legs, branch, env });
    if (preflight.length > 0) {
      for (const p of preflight) ctx.stderr(`border: pre-flight: ${p}`);
      recordOutcome({ key: state.key, verdict: "blocked", targets: pendingIds, ...branchOpt, reason: `preflight: ${preflight.join("; ")}` });
      return EXIT_BLOCKED;
    }

    for (const leg of legs) {
      ctx.stdout(`  ${DRY_RUN_PREFIX}: ${GIT_PUSH_DRY_RUN} ${leg.target.slice("git:".length)} ${branch} --follow-tags  (${displayRemote(leg.url)})`);
    }

    // ALL-or-NOTHING: every remote × ref checked before ANY push starts.
    const guard = fastForwardGuard({ repoDir, remotes: legs, refSet: state.refSet, env });
    if (!guard.ok) {
      ctx.stderr(`border: ${DIVERGED_MESSAGE}`);
      const lines = guard.divergences.map(
        (d) =>
          `${d.target} ${d.ref}: remote ${shortSha(d.remoteSha)} is not an ancestor of local ${shortSha(d.localSha)} — a fast-forward is impossible` +
          (d.ref.startsWith("refs/tags/")
            ? "; moved tag: border has no refspec/tag-move channel — repoint or delete the local tag, or resolve with plain git yourself"
            : ""),
      );
      for (const l of lines) ctx.stderr(`border:   ${l}`);
      recordOutcome({ key: state.key, verdict: "blocked", targets: pendingIds, ...branchOpt, reason: `${DIVERGED_MESSAGE}: ${lines.join("; ")}` });
      return EXIT_BLOCKED;
    }

    for (const leg of legs) {
      const result = executePush({ repoDir, remote: leg, branch, env });
      if (!result.ok) {
        ctx.stderr(
          `border: PARTIAL push — '${leg.target}' failed (${result.failure}) after ${String(done.length)}/${String(legs.length)} remote(s) [${done.length === 0 ? "none" : done.join(", ")}] landed; rerun 'border push --yes' — landed remotes come back PUSHED(no-op)`,
        );
        recordOutcome({
          key: state.key,
          verdict: "partial",
          targets: pendingIds,
          ...branchOpt,
          reason: `push to '${leg.target}' failed (${result.failure}) after ${String(done.length)}/${String(legs.length)} remote(s) landed [${done.length === 0 ? "none" : done.join(", ")}]`,
          gitExit: result.exit,
        });
        return EXIT_BLOCKED;
      }
      let remoteSha: string;
      try {
        remoteSha = confirmRemoteBranch({ repoDir, remote: leg, branch, env });
      } catch (err) {
        // the push MAY have landed — border records the uncertainty, it never
        // records the unconfirmed success (ledger stays honest, exit stays 2).
        const why = err instanceof Error ? err.message : String(err);
        recordOutcome({
          key: state.key,
          verdict: "failed",
          targets: pendingIds,
          ...branchOpt,
          reason: `push to '${leg.target}' executed but its success could not be confirmed on the wire (landed state unknown): ${why}`,
          gitExit: null,
        });
        throw err;
      }
      recordPushSuccess(repoDir, {
        key: state.key,
        target: leg.target,
        remoteName: leg.target.slice("git:".length), // configured name, else the index key '#N'
        url: leg.url,
        localSha: state.headSha,
        remoteSha,
        confirmedVia: "ls-remote",
      });
      done.push(leg.target);
      ctx.stdout(`border: pushed ${leg.target} — ${shortSha(remoteSha)} confirmed via ls-remote`);
    }

    // S3 landing verification (plan §S3; git targets only — registry publish-byte
    // landing is the named follow-up). Runs AFTER the push executed, NEVER as a
    // rollback: unreachable ⇒ exit 2 with the push record untouched; blocking
    // hit ⇒ exit 1 "ALREADY PUBLIC; border detects, never erases"; clean ⇒
    // t:"landing" record + the executor exit preserved.
    const landing = await runLandingVerification({
      repoDir,
      key: state.key,
      legs: legs.map((leg) => ({ target: leg, branch })),
      env,
      // the SAME allow entries the certifying check honored — one standard
      // across faces (2026-10-04 incident fix; see push/landing.ts doctrine).
      allow: loaded.config.allow,
      allowAliases: loaded.config.rules.aliases,
      out: ctx.stdout,
      err: ctx.stderr,
    });
    if (landing !== null) {
      // the push landed (t:"push" records prove it on the wire); the landing
      // pass refused afterwards — bytes may already be PUBLIC (landing.ts
      // doctrine). The verdict row says exactly that.
      recordOutcome({
        key: state.key,
        verdict: "landed",
        targets: done,
        ...branchOpt,
        reason: `pushed [${done.join(", ")}] but landing verification exited ${String(landing)} — public bytes may already be exposed; see t:"landing" record`,
      });
      return landing;
    }
  }

  // Cross-target order fixed by the plan: git remotes (done above) → npm → PyPI.
  // The publishChannels() iteration below IS the order enforcement (descriptor
  // `order` field; sort stable — npm 1, pypi 2); a failing leg returns its
  // exit immediately so a later leg never publishes on top of it. key:
  // state.key — the fingerprint derivePushState itself used (configDigest
  // discipline: never recompute).
  for (const channel of publishChannels()) {
    if (!pending.some((t) => t.kind === channel.id)) continue;
    const code = await channel.publish({
      repoDir,
      cfg: loaded.config,
      key: state.key,
      yes: true,
      env,
      out: ctx.stdout,
      err: ctx.stderr,
    });
    if (code !== EXIT_PASS) {
      recordOutcome({
        key: state.key,
        verdict: done.length > 0 ? "partial" : "failed",
        targets: pendingIds,
        ...branchOpt,
        reason: `registry leg '${channel.id}' exited ${String(code)}; git legs landed: ${done.length === 0 ? "none" : done.join(", ")}`,
      });
      return code;
    }
  }
  recordOutcome({ key: state.key, verdict: "landed", targets: pendingIds, ...branchOpt });
  return EXIT_PASS;
}
