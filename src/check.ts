// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 10
import { createHash } from "node:crypto";
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
import { publishChannels } from "./channels/registry.ts";
import { scanGitHistory, scanTree, detectHostileConfig } from "./engines/gitleaks.ts";
import { probeEngines } from "./engines/policy.ts";
import { scanGitTrackedFiles } from "./engines/secretlint.ts";
import type { EngineOptions } from "./engines/support.ts";
import { scanTrufflehog } from "./engines/trufflehog.ts";
import { computeVerdict, countFindings, type Finding, type Report } from "./findings.ts";
import type { LedgerArtifact } from "./ledger/records.ts";
import { readLedger } from "./ledger/records.ts";
import { redact, TextSanitizer } from "./redact.ts";
import { runRegistryProbes } from "./registry.ts";
import { scanAiArtifacts } from "./rules/aiArtifacts.ts";
import { scanIdentity } from "./rules/identity.ts";
import { gatherContext, runGitChecked, type CheckContext } from "./check/context.ts";
import { applyAllowList } from "./check/allow.ts";
import { filterBorderStateFindings, suppressGateConfigPathPatterns } from "./check/exclusions.ts";
import { acquireLock, BORDER_STATE_DIR, releaseLock } from "./check/lock.ts";
import { scanExfilTree } from "./check/exfilTreeScan.ts";
import { scanTipTreeLens } from "./check/tipTreeLens.ts";
import { scanCommitMessages } from "./check/messageScan.ts";
import { hasBlockingResidueCapability, proofFindings, RESIDUE_RULE_IDS } from "./check/proofValve.ts";
import { computeCheckKey, computeCheckRulesHash } from "./check/rulesHash.ts";
import { twinCoherenceFindings } from "./rules/releaseCoherence.ts";
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
  /** Absolute path of the border.yaml this run loaded (config self-exemption
   *  of the path-pattern family; see check/exclusions.ts). Undefined ⇒ no file
   *  was used (git-remote fallback) and nothing is exempt. */
  readonly configSource?: string;
};

export type CheckOutcome = {
  readonly report: Report;
  readonly ctx: CheckContext;
  /** true ⇒ a required engine failed its probe; the CLI maps this to exit 2 REGARDLESS of verdict. */
  readonly degraded: boolean;
  readonly sanitizedSummary: string;
  readonly lockWarning: string | null;
  /** GAP B: sha256 of the packed/built .border/dist bytes this run scanned (null ⇒ no artifact legs). */
  readonly artifacts: readonly LedgerArtifact[] | null;
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

/** Identity of one finding AS SEEN BY A LENS: two legs that report the same rule+engine bytes at the same place/line/digest are one fact, reported once (the tip lens over a clean tree mirrors the disk lens exactly). */
function lensIdentity(f: Finding): string {
  return `${f.rule}\0${f.engine}\0${f.path ?? ""}\0${String(f.line ?? -1)}\0${f.valueDigest}`;
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
  // T2/T3 exfil lens (plan §分面契约): the native tree leg carries the MEDIUM
  // family on the blob face (the HIGH family's tree face belongs to the twins
  // above), and the message leg scans `exfil-*:message` over the will-publish
  // range (endpoint unresolvable ⇒ whole ref, identity.ts:144-146). BOTH ride
  // with the native rules OUTSIDE the broken.has gates — "native 腿不吃引擎
  // 健康守卫": a degraded engine may never silence them.
  findings.push(...filterBorderStateFindings(scanExfilTree({ repoDir, hosts: o.cfg.rules.hosts, ...legOptions(o, sanitizer) }), repoDir));
  findings.push(...filterBorderStateFindings(
    scanCommitMessages({
      repoDir,
      refSet: ctx.refSet.length > 0 ? [...ctx.refSet] : [ctx.headSha],
      remotes: o.cfg.targets.git.remotes,
      hosts: o.cfg.rules.hosts,
      ...legOptions(o, sanitizer),
    }),
    repoDir,
  ));

  // TIP LENS (2026-10-04 incident fix): landing verification (S3) judges the WHOLE
  // pushed tip tree via scanTipTree; check used to certify only the range/disk
  // lenses, so a green packet had no predictive power over the public face —
  // merge-only tip bytes (git log -p skips merges) and tip files deleted from disk
  // sailed through, and pins suppressed them at check while landing had no pins.
  // The leg scans local HEAD (the exact commit push fast-forwards the branch to)
  // with the SHARED machinery; findings merge before the allow list like every
  // other leg, so owner rule+file+digest pins exempt matching tip bytes the same
  // way in both faces — one lens, one standard. Exact twins of already-present
  // disk-lens findings (same rule+engine+path+line+digest) are deduped so a clean
  // tree's counts match the pre-fix report; tip-only bytes add NEW blocking facts.
  // Any git failure throws (ConfigError ⇒ CLI exit 2 loud) — a silent empty tip
  // scan is precisely the failure mode this leg exists to make impossible; the
  // twin sub-legs inherit the existing broken-engine skips, the native leg never.
  if (o.effectiveTargets.includes("git")) {
    const tip = await scanTipTreeLens({
      repoDir,
      rev: ctx.headSha,
      ...envOpt,
      sanitizer,
      skipGitleaks: broken.has("gitleaks"),
      skipSecretlint: broken.has("secretlint"),
    });
    const seen = new Set(findings.map(lensIdentity));
    for (const f of filterBorderStateFindings(tip, repoDir)) {
      const id = lensIdentity(f);
      if (seen.has(id)) continue;
      seen.add(id);
      findings.push(f);
    }
  }

  // GAP B (todos 11+12 wired end-to-end): packed/built bytes are scanned HERE, in
  // the full-check path only — the SKIP path consults the ledger before executeCheck,
  // so a skip performs zero pack/build. Findings merge BEFORE the allow-list and the
  // verdict; the digests certify exactly these bytes to the ledger (todo 14) and to
  // publish's same-bytes chain (todo 17). Degraded engines inherit the skip flags.
  const ledgerArtifacts: LedgerArtifact[] = [];
  // Per-channel artifact stage (todo C2): each configured∩requested publish
  // channel builds/scans its own bytes (npm pack / pypi build) and returns
  // {findings, artifacts} — the ledger digests certify exactly these bytes.
  for (const channel of publishChannels()) {
    if (!o.effectiveTargets.includes(channel.id) || !channel.configured(o.cfg)) continue;
    const stage = await channel.stage({
      repoDir,
      cfg: o.cfg,
      sanitizer,
      ...envOpt,
      skipGitleaks: broken.has("gitleaks"),
      skipSecretlint: broken.has("secretlint"),
    });
    findings.push(...stage.findings);
    ledgerArtifacts.push(...stage.artifacts);
  }

  // W4.1 release.twin (plan §127-138): the ONLY statically-enforceable cross-manager
  // equality — a declared {pypi, npm} pair must ship identical versions. Runs on the
  // STAGED artifact records (wheel filename ↔ packed npm package.json), merges BEFORE
  // the allow-list like every native rule. A declared pair whose side was not staged
  // this run is MEDIUM unverifiable, never silent-clean.
  if ((o.cfg.release?.twin.length ?? 0) > 0) {
    findings.push(
      ...(await twinCoherenceFindings({
        pairs: o.cfg.release?.twin ?? [],
        artifacts: ledgerArtifacts,
        repoDir,
        ...envOpt,
        sanitizer,
      })),
    );
  }

  findings.push(...(await runRegistryProbes({ repoDir, cfg: o.cfg, effectiveTargets: o.effectiveTargets, ...envOpt })));

  // R4 residue.enabled central gate: the toggle's ONLY effect is hiding the
  // closed residue-* rule set (single home: RESIDUE_SEVERITIES keys) from the
  // merge point down — every other rule, the allow-list bookkeeping, the report
  // schema and the verdict math are untouched, so a residue-off run can never
  // launder a non-residue blocker. The scan itself already RAN above (fail-open
  // on cost, fail-closed on results: absence of the key === enabled; there is
  // no other sanctioned skip path).
  if (o.cfg.residue?.enabled === false) {
    for (let i = findings.length - 1; i >= 0; i -= 1) {
      const f = findings[i];
      if (f !== undefined && RESIDUE_RULE_IDS.has(f.rule)) findings.splice(i, 1);
    }
  }

  const rulesHash = await computeCheckRulesHash({
    engineVersions: probe.engineVersions,
    configDigest: o.configDigest,
    ...(o.env !== undefined ? { env: o.env } : {}),
  });

  // W2.2 proof valve (fail-closed-by-absence): `border check` NEVER spawns
  // docker — it only consumes the t:"roundtrip" facts `border roundtrip`
  // pre-supplied. Armed ONLY while the scan is enabled (a spliced-away row is
  // no longer a capability claim) and by blocking-severity residue-* rows;
  // then every staged artifact needs a fresh (rulesHash-matching) proof record
  // keyed by its sha256. Emitted BEFORE applyAllowList: the obligation is a
  // finding like any other — waivable through the allow-list, enumerable in
  // allowHits, never a hidden side-channel.
  if (o.cfg.residue?.requireProof === true && ledgerArtifacts.length > 0 && hasBlockingResidueCapability(findings)) {
    findings.push(...proofFindings({ artifacts: ledgerArtifacts, records: readLedger(repoDir).records, rulesHash }));
  }

  const exposure = [...exposureSet(o.cfg, { cwd: repoDir })];
  // Gate-config self-exemption (path-pattern family only, exact file the run
  // loaded): rule IDs in border.yaml trip the heuristics with context-bound
  // digests — no allow-list fixpoint exists. Suppressed count echoes as INFO
  // so a PASS states what it hid. See check/exclusions.ts for the safety case.
  const cfgExempt = suppressGateConfigPathPatterns(findings, repoDir, o.configSource);
  if (cfgExempt.suppressed > 0) {
    findings.length = 0;
    findings.push(...cfgExempt.kept);
    findings.push({
      rule: "gate-config-path-exempt",
      severity: "INFO",
      target: "config",
      ...(o.configSource !== undefined ? { path: o.configSource } : {}),
      engine: "native",
      message: `${String(cfgExempt.suppressed)} path-pattern finding(s) suppressed for the gate's own config file (self-referential rule-ID bytes; credential engines still cover it)`,
      valueDigest: createHash("sha256").update(`gate-config-exempt:${String(o.configSource)}`).digest("hex"),
      snippet: "gate-config-path-exempt",
    });
  }
  // G14 post-filter (todo 19): last gate before the verdict. Suppressed
  // findings never count/never block, but every suppression is enumerated in
  // report.allowHits — exit 0 must never hide what it hid.
  const allow = applyAllowList(findings, o.cfg.allow, repoDir);
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
    verdict: computeVerdict(allow.kept),
    counts: countFindings(allow.kept),
    findings: allow.kept,
    ...(allow.allowHits.length > 0 ? { allowHits: allow.allowHits } : {}),
    ts: new Date().toISOString(),
  };
  return {
    report,
    ctx,
    degraded: probe.degraded,
    sanitizedSummary: sanitizeSummary(report, sanitizer),
    lockWarning,
    artifacts: ledgerArtifacts.length > 0 ? ledgerArtifacts : null,
  };
}

/** Human one-liner per finding, G23 defense-in-depth: every line rides through the run's TextSanitizer (engine messages are already digest-only). */
export function sanitizeSummary(report: Report, sanitizer: TextSanitizer): string {
  const lines = report.findings.map((f) =>
    sanitizer.sanitize(`${f.severity} ${f.rule} ${f.engine} ${f.path ?? ""} ${f.commit ?? ""} ${f.message}`.replace(/\s+/g, " ").trim()),
  );
  lines.unshift(sanitizer.sanitize(`border check ${report.verdict}: ${String(report.counts.total)} finding(s), ${String(report.counts.blocking)} blocking`));
  return lines.join("\n");
}
