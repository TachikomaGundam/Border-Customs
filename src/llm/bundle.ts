// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 18
//
// `border llm-request`: derive a review bundle from the newest ledger record
// whose key matches the CURRENT fingerprint (bundle always describes the exact
// state a check certified), extract the masked diff, and hand the whole thing
// to the operator's agent. border never calls an LLM API (G30).
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

import { loadConfig } from "../config.ts";
import { computeEffectiveTargets, resolveRepoDir } from "../check/context.ts";
import { computeConfigDigest, resolvePromptTemplatePath } from "../check/rulesHash.ts";
import { computeFingerprint, readLedger, type CheckRecord, type LedgerArtifact } from "../ledger.ts";
import { EXIT_ERROR, EXIT_PASS, type BorderExit } from "../cli/exit.ts";
import type { Ctx } from "../cli/types.ts";
import type { Finding, ReportCounts, Verdict } from "../findings.ts";
import { collectRawDeltas, maskViaEngineDetection, resolveDiffBase, type DiffBase } from "./diff.ts";

/** Round-2 M9a — verbatim in every bundle and in skills/border/SKILL.md. */
export const DATA_BOUNDARY =
  "the bundle carries real reviewable source; masking covers only values the deterministic engines already flagged — a residual, still-undiscovered secret in diff context CAN reach the operator-configured LLM endpoint. That is the accepted-by-design boundary of the optional --llm layer; the deterministic layers remain the actual gate.";

/** Plan cap: no diff content > 10MB — truncated with an explicit marker. */
export const PATCH_LIMIT_BYTES = 10 * 1024 * 1024;
const TRUNCATION_MARKER = (path: string, base: string, head: string): string =>
  `\n[border: patch truncated at 10 MiB — inspect locally with: git diff ${base} ${head} -- ${path}]\n`;

export type BundleFileDelta = {
  readonly path: string;
  readonly changeType: string;
  readonly adds: number;
  readonly dels: number;
  readonly patch: string;
  readonly patchBytes: number;
  readonly truncated: boolean;
};

export type LlmRequestBundle = {
  readonly schemaVersion: 1;
  readonly generatedAt: string;
  readonly dataBoundary: string;
  readonly usage: string;
  readonly key: string;
  readonly key8: string;
  readonly head: string;
  readonly dirty: boolean;
  readonly porcelainDigest: string;
  readonly currentBranch: string | null;
  readonly rulesHash: string;
  readonly refSet: readonly string[];
  readonly exposureSet: readonly string[];
  readonly effectiveTargets: readonly string[];
  readonly base: DiffBase;
  readonly diffStat: string;
  readonly patchLimitBytes: number;
  readonly fileDeltas: readonly BundleFileDelta[];
  readonly artifacts: readonly LedgerArtifact[] | null;
  readonly deterministic: { readonly verdict: Verdict; readonly counts: ReportCounts; readonly findings: readonly Finding[] };
  readonly promptTemplate: { readonly path: string; readonly sha256: string };
};

function truncatePatch(patch: string, path: string, baseSha: string, headSha: string): { readonly patch: string; readonly truncated: boolean } {
  if (Buffer.byteLength(patch, "utf8") <= PATCH_LIMIT_BYTES) return { patch, truncated: false };
  let cut = Math.min(patch.length, PATCH_LIMIT_BYTES);
  while (cut > 0 && Buffer.byteLength(patch.slice(0, cut), "utf8") > PATCH_LIMIT_BYTES - 512) cut -= 4096;
  return { patch: `${patch.slice(0, cut)}${TRUNCATION_MARKER(path, baseSha, headSha)}`, truncated: true };
}

export async function runLlmRequestCore(ctx: Ctx): Promise<BorderExit> {
  const envOpt = ctx.env !== undefined ? { env: ctx.env } : {};
  const load = loadConfig({
    cwd: ctx.cwd,
    ...(ctx.flags.config !== undefined ? { configPath: ctx.flags.config } : {}),
    ...envOpt,
  });
  for (const warning of load.warnings) ctx.stderr(`border: ${warning}`);
  if (load.kind !== "loaded") {
    ctx.stderr("border: llm-request: no scan targets are configured — run 'border check' first (here it would itself be a NO-OP)");
    return EXIT_ERROR;
  }
  const repoDir = resolveRepoDir(ctx.cwd, envOpt);
  const effectiveTargets = computeEffectiveTargets(load.config, ctx.flags.targets);
  const configDigest = computeConfigDigest(load);
  const requireOverride = ctx.flags.requireEngine !== undefined && ctx.flags.requireEngine.length > 0 ? { requireOverride: ctx.flags.requireEngine } : {};
  const { ctx: checkCtx, fp, probeDegraded } = await computeFingerprint(repoDir, load.config, configDigest, effectiveTargets, { ...envOpt, ...requireOverride });
  if (probeDegraded) {
    ctx.stderr("border: llm-request: engine probes degraded — run 'border check' first (a degraded gate certifies nothing to review)");
    return EXIT_ERROR;
  }
  const ledger = readLedger(repoDir);
  for (const warning of ledger.warnings) ctx.stderr(`border: WARNING ${warning}`);
  let record: CheckRecord | null = null;
  for (let i = ledger.records.length - 1; i >= 0; i -= 1) {
    const r = ledger.records[i];
    if (r !== undefined && r.t === "check" && r.key === fp.key) {
      record = r;
      break;
    }
  }
  if (record === null) {
    ctx.stderr("border: llm-request: no check record for the current state — run 'border check' first (the bundle derives from the recorded ctx)");
    return EXIT_ERROR;
  }
  const absReport = join(repoDir, record.reportPath);
  if (!existsSync(absReport)) {
    ctx.stderr(`border: llm-request: report archive missing (${record.reportPath} pruned?) — run 'border check' again`);
    return EXIT_ERROR;
  }
  const report = JSON.parse(readFileSync(absReport, "utf8")) as { key: string; verdict: Verdict; counts: ReportCounts; findings: Finding[] };
  if (report.key !== record.key) {
    ctx.stderr("border: llm-request: report.json does not match its ledger record — run 'border check' again");
    return EXIT_ERROR;
  }

  const templatePath = resolvePromptTemplatePath(ctx.env);
  if (!existsSync(templatePath)) {
    // Fail closed, consistent with the GITLEAKS_VENDORED_CONFIG handling: an
    // unresolvable template (esbuild dist gap — todos 20/21 own packaging)
    // must not silently produce a bundle nobody knows how to answer.
    ctx.stderr(`border: llm-request: MISSING_TEMPLATE — prompt template not found at ${templatePath}; refusing to emit an unanswerable bundle`);
    return EXIT_ERROR;
  }

  const base = resolveDiffBase(repoDir, fp.exposureSet, envOpt);
  const { stat, deltas: raw } = collectRawDeltas(repoDir, base.sha, record.head, envOpt);
  const mask = maskViaEngineDetection(repoDir, [stat, ...raw.map((d) => d.rawPatch)], envOpt);
  const fileDeltas: BundleFileDelta[] = [];
  let budget = PATCH_LIMIT_BYTES;
  for (const d of raw) {
    const masked = mask(d.rawPatch);
    const fits = budget > 0;
    const piece = truncatePatch(fits ? masked : "", d.path, base.sha, record.head);
    const bytes = Buffer.byteLength(piece.patch, "utf8");
    budget -= bytes;
    fileDeltas.push({
      path: d.path,
      changeType: d.changeType,
      adds: d.adds,
      dels: d.dels,
      patch: piece.patch,
      patchBytes: bytes,
      truncated: piece.truncated || !fits,
    });
  }

  const bundle: LlmRequestBundle = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    dataBoundary: DATA_BOUNDARY,
    usage: "author a JSON array of findings per promptTemplate, then run: border llm-ingest <findings.json>",
    key: record.key,
    key8: record.key8,
    head: record.head,
    dirty: checkCtx.dirty,
    porcelainDigest: checkCtx.porcelainDigest,
    currentBranch: checkCtx.currentBranch,
    rulesHash: record.rulesHash,
    refSet: [...checkCtx.refSet],
    exposureSet: [...record.exposureSet],
    effectiveTargets: [...effectiveTargets],
    base,
    diffStat: mask(stat),
    patchLimitBytes: PATCH_LIMIT_BYTES,
    fileDeltas,
    artifacts: record.artifacts,
    deterministic: { verdict: report.verdict, counts: report.counts, findings: report.findings },
    promptTemplate: { path: templatePath, sha256: createHash("sha256").update(readFileSync(templatePath)).digest("hex") },
  };
  const outPath = join(dirname(absReport), "llm-request.json");
  mkdirSync(dirname(outPath), { recursive: true });
  writeFileSync(outPath, `${JSON.stringify(bundle, null, 2)}\n`, "utf8");
  const rel = outPath.slice(repoDir.length + 1);
  ctx.stdout(`border: llm-request: wrote ${rel} (base ${base.mode}, ${String(fileDeltas.length)} file deltas, ${String(report.findings.length)} deterministic findings)`);
  return EXIT_PASS;
}
