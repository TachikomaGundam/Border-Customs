// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 10
//
// `border check` — the CLI seam over the plan todo-10 pipeline. cli.ts is
// frozen; everything gate-side lives here. Exit mapping (G11): the pipeline's
// degraded flag (required engine failed its probe) maps to exit 2 REGARDLESS of
// the verdict — a gate that could not run never reports "pass". todo 14 wired
// the skip-ledger around the pipeline: a matching non-degraded PASS record
// short-circuits the scan legs (SKIP line, cached verdict's exit code), --force
// bypasses the lookup, and every full non-degraded run appends a fresh record.
// The ledger never sees a degraded or NO-OP run — those can certify nothing.
import { loadConfig, NO_OP_MESSAGE, type BorderConfig } from "../config.ts";
import { EXIT_ERROR, EXIT_PASS, exitCodeFromVerdict, type BorderExit } from "../cli/exit.ts";
import type { Ctx } from "../cli/types.ts";
import { executeCheck, type CheckOutcome } from "../check.ts";
import { BorderLockHeldError } from "../check/lock.ts";
import { computeConfigDigest } from "../check/rulesHash.ts";
import { consultSkipLedger, formatSkipLine, recordCheckRun } from "../ledger.ts";
import { resolveRepoDir, computeEffectiveTargets } from "../check/context.ts";
import { probeEngines } from "../engines/policy.ts";
import type { EngineOptions } from "../engines/support.ts";

export async function runCheck(ctx: Ctx): Promise<BorderExit> {
  const env: EngineOptions["env"] = ctx.env;
  const load = loadConfig({
    cwd: ctx.cwd,
    ...(ctx.flags.config !== undefined ? { configPath: ctx.flags.config } : {}),
    ...(env !== undefined ? { env } : {}),
  });
  for (const warning of load.warnings) ctx.stderr(`border: ${warning}`);

  if (load.kind === "no-op") {
    // --require-engine upgrades the no-op into a health probe: an operator who
    // demanded a specific engine gets exit 2 when it is missing, even with zero
    // targets to scan. Without it: loud no-op, exit 0 (todo-2 contract).
    if (ctx.flags.requireEngine !== undefined && ctx.flags.requireEngine.length > 0) {
      const probe = await probeEngines(NO_TARGETS_PROBE_CFG, {
        requireOverride: ctx.flags.requireEngine,
        ...(env !== undefined ? { env } : {}),
      });
      if (probe.degraded) {
        for (const finding of probe.findings) ctx.stderr(`border: ${finding.message}`);
        return EXIT_ERROR;
      }
    }
    ctx.stdout(`border: ${NO_OP_MESSAGE}`);
    return EXIT_PASS;
  }

  // G21 fix (todo 14): canonical-JSON digest of the EFFECTIVE config (post
  // overlay-merge, post `${VAR}` expansion) — a border.yaml byte digest left
  // .border/config.local.yaml overlays and env-expanded remotes invisible to
  // the fingerprint. computeConfigDigest's header carries the full rationale.
  const configDigest = computeConfigDigest(load);

  const repoDir = resolveRepoDir(ctx.cwd, { env });
  const effectiveTargets = computeEffectiveTargets(load.config, ctx.flags.targets);

  if (!ctx.flags.force) {
    const decision = await consultSkipLedger({
      repoDir,
      cfg: load.config,
      configDigest,
      effectiveTargets,
      llm: ctx.flags.llm,
      ...(env !== undefined ? { env } : {}),
      ...(ctx.flags.requireEngine !== undefined && ctx.flags.requireEngine.length > 0
        ? { requireOverride: ctx.flags.requireEngine }
        : {}),
    });
    for (const warning of decision.warnings) ctx.stderr(`border: WARNING ${warning}`);
    if (decision.skip !== null) {
      ctx.stdout(formatSkipLine(decision.skip));
      return exitCodeFromVerdict(decision.skip.verdict);
    }
  }

  let outcome: CheckOutcome;
  try {
    outcome = await executeCheck({
      repoDir,
      cfg: load.config,
      configDigest,
      effectiveTargets,
      ...(env !== undefined ? { env } : {}),
      ...(ctx.flags.requireEngine !== undefined && ctx.flags.requireEngine.length > 0
        ? { requireOverride: ctx.flags.requireEngine }
        : {}),
    });
  } catch (err) {
    if (err instanceof BorderLockHeldError) {
      ctx.stderr(`border: ${err.message}`);
      return EXIT_ERROR;
    }
    throw err;
  }
  if (outcome.lockWarning !== null) ctx.stderr(`border: WARNING ${outcome.lockWarning}`);
  if (outcome.ctx.dirty) ctx.stderr("border: working tree is dirty — findings may reference uncommitted files");
  if (ctx.flags.json) {
    ctx.stdout(JSON.stringify(outcome.report, null, 2));
  } else {
    for (const line of outcome.sanitizedSummary.split("\n")) ctx.stdout(`border: ${line}`);
  }
  if (outcome.degraded) {
    ctx.stderr("border: required engine(s) degraded — verdict is UNTRUSTWORTHY (exit 2 regardless of findings)");
    return EXIT_ERROR;
  }
  // Ledgered only after the degraded gate: a degraded verdict must never be cached.
  recordCheckRun({
    repoDir,
    report: outcome.report,
    ctx: outcome.ctx,
    effectiveTargets,
    llm: ctx.flags.llm,
    ...(env !== undefined ? { env } : {}),
  });
  return exitCodeFromVerdict(outcome.report.verdict);
}

const NO_TARGETS_PROBE_CFG = {
  version: 1,
  targets: { git: { remotes: [] } },
  rules: { authors: { emails: [], names: [] }, hosts: [], ips: [], pathPatterns: [], maxFileKB: 500 },
  allow: [],
  engines: { require: [], trufflehog: false },
} satisfies BorderConfig;
