// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 10
//
// The check pipeline — keystone wiring. Order (plan D1): ctx gathering → G22
// state discipline + lock → tracked-state guard (round-5 B-R5-1, BEFORE any
// engine leg) → probeEngines (degraded short-circuits only the broken engine's
// legs) → gitleaks hostile/history/tree + tag-message stdin leg → secretlint
// tracked tree → optional trufflehog → native rules (ai-artifacts, identity) →
// Report. gitleaks has no exclude flag, so EVERY gitleaks leg passes through
// the `.border/` ingest filter here (never in the adapter).
// Findings order is the pipeline order above — deterministic per run so the
// JSON render (todo 19) is stable.
import { join } from "node:path";

import { exposureSet, type BorderConfig } from "./config.ts";
import { scanGitHistory, scanTree, detectHostileConfig } from "./engines/gitleaks.ts";
import { probeEngines } from "./engines/policy.ts";
import { scanGitTrackedFiles } from "./engines/secretlint.ts";
import type { EngineOptions } from "./engines/support.ts";
import { scanTrufflehog } from "./engines/trufflehog.ts";
import { computeVerdict, countFindings, type Finding, type Report } from "./findings.ts";
import { redact, TextSanitizer } from "./redact.ts";
import { scanAiArtifacts } from "./rules/aiArtifacts.ts";
import { scanIdentity } from "./rules/identity.ts";
import { gatherContext, runGitChecked, type CheckContext } from "./check/context.ts";
import { filterBorderStateFindings } from "./check/exclusions.ts";
import { acquireLock, BORDER_STATE_DIR, releaseLock } from "./check/lock.ts";
import { computeCheckKey, computeCheckRulesHash } from "./check/rulesHash.ts";
import { scanTagMessages, TAG_MESSAGE_RULE } from "./check/tagScan.ts";

export const TRACKED_BORDER_RULE = "repo-tracks-border-state";
export { TAG_MESSAGE_RULE };

const GUARD_PATH_CAP = 50;

export type CheckPipelineOptions = {
  readonly repoDir: string;
  readonly cfg: BorderConfig;
  readonly configDigest: string;
  readonly effectiveTargets: readonly string[];
  readonly env?: EngineOptions["env"];
  /** CLI --require-engine override for the engine policy probe. */
  readonly requireOverride?: readonly string[];
};

export type CheckOutcome = {
  readonly report: Report;
  readonly ctx: CheckContext;
  /** true ⇒ a required engine failed its probe; the CLI maps this to exit 2 REGARDLESS of verdict. */
  readonly degraded: boolean;
  readonly sanitizedSummary: string;
  readonly lockWarning: string | null;
};

/**
 * Round-5 B-R5-1: border's own state must never be committed. git tracks it ⇒
 * a repo-committed .border/** can hide state from the exclusion filters'
 * assumptions and survive pushes; this CRITICAL fires BEFORE any engine leg so
 * the verdict cannot be laundered by a broken engine.
 */
function trackedBorderStateFinding(repoDir: string, headSha: string, env?: EngineOptions["env"]): Finding | null {
  const listing = runGitChecked(repoDir, ["ls-files", "--", `${BORDER_STATE_DIR}/`], { ...(env !== undefined ? { env } : {}) })
    .split("\n")
    .filter((p) => p !== "");
  if (listing.length === 0) return null;
  const shown = listing.slice(0, GUARD_PATH_CAP);
  const rest = listing.length - shown.length;
  const [first = `${BORDER_STATE_DIR}/`] = shown;
  const message =
    `repository tracks ${String(listing.length)} file(s) under ${BORDER_STATE_DIR}/ — border's state directory must stay untracked: ` +
    `${shown.join(", ")}${rest > 0 ? ` (+${String(rest)} more)` : ""}. Remove with 'git rm -r --cached ${BORDER_STATE_DIR}/'.`;
  return {
    rule: TRACKED_BORDER_RULE,
    severity: "CRITICAL",
    target: "git",
    path: first,
    commit: headSha,
    engine: "native",
    message,
    ...redact(`${headSha}:${BORDER_STATE_DIR}`),
    snippet: `${BORDER_STATE_DIR}/ tracked`,
  };
}

function legOptions(o: CheckPipelineOptions, sanitizer: TextSanitizer) {
  return {
    ...(o.env !== undefined ? { env: o.env } : {}),
    sanitizer,
  };
}

/** History scoping: gitleaks `--log-opts` receives the refSet as positive revs = "commits reachable from the refs a push would touch" (NOT --all). Detached HEAD with no tags falls back to the HEAD sha. */
function historyRefRange(ctx: CheckContext): string {
  return ctx.refSet.length > 0 ? ctx.refSet.join(" ") : ctx.headSha;
}

export async function executeCheck(o: CheckPipelineOptions): Promise<CheckOutcome> {
  const envOpt = o.env !== undefined ? { env: o.env } : {};
  const ctx = gatherContext(o.repoDir, envOpt);
  const { handle, warning } = acquireLock(o.repoDir);
  try {
    return await runPipeline(o, ctx, warning);
  } finally {
    releaseLock(handle);
  }
}

async function runPipeline(o: CheckPipelineOptions, ctx: CheckContext, lockWarning: string | null): Promise<CheckOutcome> {
  const repoDir = ctx.repoDir;
  const envOpt = o.env !== undefined ? { env: o.env } : {};
  const findings: Finding[] = [];

  const guard = trackedBorderStateFinding(repoDir, ctx.headSha, o.env);

  const probe = await probeEngines(o.cfg, {
    ...envOpt,
    ...(o.requireOverride !== undefined ? { requireOverride: o.requireOverride } : {}),
  });
  findings.push(...probe.findings);
  if (guard !== null) findings.push(guard);
  const broken = new Set(probe.findings.map((f) => f.engine));

  const sanitizer = new TextSanitizer();
  // detectHostileConfig is pure-git plumbing: it guards against gitleaks
  // self-silencing, so it must run even when the gitleaks binary itself is degraded.
  findings.push(...filterBorderStateFindings(detectHostileConfig({ repoDir, target: "git", ...envOpt }), repoDir));
  if (!broken.has("gitleaks")) {
    const eng = legOptions(o, sanitizer);
    findings.push(...filterBorderStateFindings(scanGitHistory({ repoDir, refRange: historyRefRange(ctx), target: "git", ...eng }), repoDir));
    findings.push(...filterBorderStateFindings(scanTree({ dir: repoDir, stateDir: join(repoDir, BORDER_STATE_DIR), target: "tree", ...eng }), repoDir));
    findings.push(...filterBorderStateFindings(scanTagMessages({ repoDir, target: "git", ...eng }), repoDir));
  }
  if (!broken.has("secretlint")) {
    findings.push(...(await scanGitTrackedFiles({ repoDir, target: "git", rules: o.cfg.rules, ...legOptions(o, sanitizer) })));
  }
  if (o.cfg.engines.trufflehog && !broken.has("trufflehog")) {
    findings.push(...scanTrufflehog({ repoDir, target: "git", ...legOptions(o, sanitizer) }));
  }
  findings.push(...scanAiArtifacts({ repoDir, refSet: [...ctx.refSet], cfg: o.cfg.rules, ...envOpt }));
  findings.push(...scanIdentity({ repoDir, refSet: [...ctx.refSet], cfg: o.cfg, ...envOpt }));

  const exposure = [...exposureSet(o.cfg, { cwd: repoDir })];
  const rulesHash = await computeCheckRulesHash({ engineVersions: probe.engineVersions, configDigest: o.configDigest });
  const report: Report = {
    schemaVersion: 1,
    key: computeCheckKey({
      headSha: ctx.headSha,
      porcelainDigest: ctx.porcelainDigest,
      rulesHash,
      exposureSet: exposure,
      refSet: ctx.refSet,
      effectiveTargets: o.effectiveTargets,
    }),
    head: ctx.headSha,
    dirty: ctx.dirty,
    exposureSet: exposure,
    refSet: ctx.refSet,
    rulesHash,
    verdict: computeVerdict(findings),
    counts: countFindings(findings),
    findings,
    ts: new Date().toISOString(),
  };
  return { report, ctx, degraded: probe.degraded, sanitizedSummary: sanitizeSummary(report, sanitizer), lockWarning };
}

/** Human one-liner per finding, G23 defense-in-depth: every line rides through the run's TextSanitizer (engine messages are already digest-only). */
export function sanitizeSummary(report: Report, sanitizer: TextSanitizer): string {
  const lines = report.findings.map((f) =>
    sanitizer.sanitize(`${f.severity} ${f.rule} ${f.engine} ${f.path ?? ""} ${f.commit ?? ""} ${f.message}`.replace(/\s+/g, " ").trim()),
  );
  lines.unshift(sanitizer.sanitize(`border check ${report.verdict}: ${String(report.counts.total)} finding(s), ${String(report.counts.blocking)} blocking`));
  return lines.join("\n");
}
