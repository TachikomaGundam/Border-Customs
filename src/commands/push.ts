// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 7
//
// `border push` — the DRY-RUN default (plan G10 + round-5 m-R5-a), wired at
// the stub layer so cli.ts stays frozen while todos 15/16 replace the
// executor:
//   * bare push performs ZERO mutations — it prints the per-remote plan and
//     asks the registry's check handler (the gate seam) for the verdict the
//     gate WOULD produce: clean⇒0, gate-blocked⇒1, gate-unavailable⇒2.
//     A dry-run must never print a misleading 0.
//   * --yes is the ONLY mutation path, and the executor behind it (pushstate
//     + multi-remote git push) arrives in todos 15/16; until then --yes
//     refuses with exit 2 instead of faking a push.
// The DRY_RUN/GIT_PUSH strings live here exactly once (plan grep guard — the
// todo 16 executor imports these constants, never retypes them).
import { loadConfig } from "../config.ts";
import { EXIT_ERROR, EXIT_PASS, type BorderExit } from "../cli/exit.ts";
import type { Ctx } from "../cli/types.ts";
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

export async function runPush(ctx: Ctx): Promise<BorderExit> {
  if (ctx.flags.yes) {
    ctx.stderr(
      "border: push --yes execution is not implemented yet (plan todos 15/16 own the executor) — refusing to mutate anything",
    );
    return EXIT_ERROR;
  }
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
  const remotes = loaded.config.targets.git.remotes;
  if (remotes.length === 0) {
    ctx.stdout("border: no git remotes configured — npm/pypi publishers arrive with plan todo 17");
  } else {
    ctx.stdout(`border ${DRY_RUN_PREFIX}: no --yes, so nothing runs — this is the plan (m-R5-a) contract`);
    for (const remote of remotes) {
      ctx.stdout(`  ${DRY_RUN_PREFIX}: ${GIT_PUSH_DRY_RUN} ${remote.name ?? displayRemote(remote.url)} --follow-tags  (${displayRemote(remote.url)})`);
    }
  }
  // Gate seam: the registry's check handler stands in for todo 10's pipeline.
  const verdict = await ctx.handlers.check({ ...ctx, command: "check" });
  if (verdict === EXIT_ERROR) {
    ctx.stderr("border: gate verdict unavailable — dry-run exits 2, never a misleading 0");
  }
  return verdict;
}
