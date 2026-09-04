// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 19
//
// `border status` — informational view over the ledger: newest check record
// plus a per-target push table (pushed / pending for its effective targets).
// Contract: exit 0 whenever the ledger is READABLE (empty ledger included —
// nothing to show is not an error); an unreadable ledger fails honestly with
// exit 2 naming the path; malformed lines are warnings, never a crash.
// Every ledger-sourced string rides through oneInertLine(): commit-message-
// shaped data can neither break the line grid nor fabricate table rows.
import { resolveRepoDir } from "../check/context.ts";
import { EXIT_ERROR, EXIT_PASS, type BorderExit } from "../cli/exit.ts";
import type { Ctx } from "../cli/types.ts";
import { loadConfig } from "../config.ts";
import { type CheckRecord, type PushRecord, readLedger } from "../ledger.ts";
import { gitTargetId } from "../gitTargetId.ts";

function oneInertLine(value: string): string {
  return value.replace(/[\x00-\x1f\x7f]+/g, " ").trim();
}

/**
 * Per-remote git push-record ids, derived EXACTLY as pushstate's gitLegs keys
 * them (the shared gitTargetId helper — `git:<name>`, or `git:#<index>` for
 * unnamed remotes). A git push-record is keyed git:<name-or-index>; the bare
 * 'git' in effectiveTargets is a kind and never matches one. Empty result
 * (unusable/absent config, or remotes []) degrades the table to the legacy
 * bare-kind match instead of printing a false pending.
 */
function gitRemoteIds(ctx: Ctx, repoDir: string): string[] {
  try {
    const load = loadConfig({
      cwd: repoDir,
      ...(ctx.flags.config !== undefined ? { configPath: ctx.flags.config } : {}),
      env: ctx.env,
    });
    const cfg = load.kind === "loaded" ? load.config : load.explicit?.config;
    return (cfg?.targets.git.remotes ?? []).map((r, index) => gitTargetId(r, index));
  } catch {
    return [];
  }
}

function describePush(p: PushRecord): string {
  const where = p.remoteSha ?? p.version ?? p.localSha;
  return `${p.confirmedVia} ${p.remoteName} ${p.url} @ ${where.slice(0, 12)} (${p.ts})`;
}

export function runStatus(ctx: Ctx): BorderExit {
  let repoDir: string;
  try {
    repoDir = resolveRepoDir(ctx.cwd, { env: ctx.env });
  } catch (err) {
    ctx.stderr(`border: status: ${err instanceof Error ? err.message : String(err)}`);
    return EXIT_ERROR;
  }
  let ledger: ReturnType<typeof readLedger>;
  try {
    ledger = readLedger(repoDir);
  } catch (err) {
    ctx.stderr(`border: status: ${err instanceof Error ? err.message : String(err)}`);
    return EXIT_ERROR;
  }
  for (const w of ledger.warnings) ctx.stderr(`border: WARNING ${w}`);

  let newest: CheckRecord | undefined;
  for (const r of ledger.records) if (r.t === "check") newest = r;
  if (newest === undefined) {
    ctx.stdout("border: no check runs recorded yet — run `border check` first.");
    return EXIT_PASS;
  }

  const pushesFor = (target: string): PushRecord | undefined => {
    let found: PushRecord | undefined;
    for (const r of ledger.records) if (r.t === "push" && r.key === newest.key && r.target === target) found = r;
    return found;
  };

  const gitIds = gitRemoteIds(ctx, repoDir);
  ctx.stdout(
    `border status — key ${newest.key8} — verdict ${newest.verdict} — head ${newest.head.slice(0, 12)} — ${newest.ts}`,
  );
  ctx.stdout(`target   state    detail`);
  const pending: string[] = [];
  for (const target of newest.effectiveTargets) {
    const rows = target === "git" && gitIds.length > 0 ? gitIds : [target];
    for (const row of rows) {
      const push = pushesFor(row);
      if (push !== undefined) {
        ctx.stdout(`${row.padEnd(8)} ${"pushed".padEnd(8)} ${oneInertLine(describePush(push))}`);
      } else {
        pending.push(row);
        ctx.stdout(`${row.padEnd(8)} ${"pending".padEnd(8)} no push record for key ${newest.key8}`);
      }
    }
  }
  if (newest.effectiveTargets.length === 0) {
    ctx.stdout(`(no effective targets — repo-local check only, nothing to push)`);
  }
  ctx.stdout(
    pending.length > 0
      ? `pending targets: ${pending.join(", ")} — run \`border push\` to publish the PASS`
      : `all effective targets pushed for key ${newest.key8}`,
  );
  return EXIT_PASS;
}
