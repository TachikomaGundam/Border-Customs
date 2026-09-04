// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 14
//
// Public surface of the check-skip ledger. Two verbs bracket a check run:
// `consultSkipLedger` recomputes the fingerprint (engine probes + key, but
// NEVER the full engine pipeline) and decides SKIP vs re-check;
// `recordCheckRun` archives the report under .border/runs/<key8>-<ts>/ and
// appends the one-line record. Everything lives under .border/ (hard-excluded
// from gitleaks findings via filterBorderStateFindings). Invariants enforced
// here, not in callers: NO-OP and degraded runs never write a skippable PASS;
// the ledger file is append-only; readers tolerate corrupt lines.
import { createHash } from "node:crypto";
import { writeFileSync } from "node:fs";
import { join } from "node:path";

import type { CheckContext } from "./check/context.ts";
import { gatherContext } from "./check/context.ts";
import { computeCheckKey, computeCheckRulesHash, stableStringify } from "./check/rulesHash.ts";
import type { BorderConfig } from "./config.ts";
import { exposureSet } from "./config.ts";
import { probeEngines } from "./engines/policy.ts";
import { BORDER_STATE_DIR } from "./check/lock.ts";
import type { EngineOptions } from "./engines/support.ts";
import type { Report } from "./findings.ts";
import { packNpmArtifacts, verifyArtifactFreshness } from "./ledger/freshness.ts";
import {
  appendRecord,
  lookupSkipRecord,
  readLedger,
  type CheckRecord,
  type LedgerRead,
} from "./ledger/records.ts";
import { ensureRunDir, pruneRunDirs, reportRelPath, uniqueRunDirName } from "./ledger/retention.ts";

export * from "./ledger/records.ts";
export { packNpmArtifacts, verifyArtifactFreshness } from "./ledger/freshness.ts";
export {
  ensureRunDir,
  KEEP_RUN_DIRS_PER_KEY8,
  pruneRunDirs,
  reportRelPath,
  runDirName,
  uniqueRunDirName,
} from "./ledger/retention.ts";

export type LedgerFingerprint = {
  readonly key: string;
  readonly rulesHash: string;
  readonly exposureSet: readonly string[];
};

/** Recompute the skip-fingerprint inputs (cheap: git + probes + hashes, no engine pipeline). */
export async function computeFingerprint(
  repoDir: string,
  cfg: BorderConfig,
  configDigest: string,
  effectiveTargets: readonly string[],
  o: { readonly env?: EngineOptions["env"]; readonly requireOverride?: readonly string[] } = {},
): Promise<{ readonly ctx: CheckContext; readonly fp: LedgerFingerprint; readonly probeDegraded: boolean }> {
  const envOpt = o.env !== undefined ? { env: o.env } : {};
  const ctx = await gatherContext(repoDir, envOpt);
  const probe = await probeEngines(cfg, {
    ...envOpt,
    ...(o.requireOverride !== undefined ? { requireOverride: o.requireOverride } : {}),
  });
  const rulesHash = await computeCheckRulesHash({ engineVersions: probe.engineVersions, configDigest });
  const fp: LedgerFingerprint = {
    key: computeCheckKey({
      headSha: ctx.headSha,
      porcelainDigest: ctx.porcelainDigest,
      rulesHash,
      exposureSet: [...exposureSet(cfg, { cwd: repoDir })],
      refSet: [...ctx.refSet],
      effectiveTargets: [...effectiveTargets],
    }),
    rulesHash,
    exposureSet: [...exposureSet(cfg, { cwd: repoDir })],
  };
  return { ctx, fp, probeDegraded: probe.degraded };
}

export type SkipQuery = {
  readonly repoDir: string;
  readonly cfg: BorderConfig;
  readonly configDigest: string;
  readonly effectiveTargets: readonly string[];
  readonly llm: boolean;
  readonly env?: EngineOptions["env"];
  readonly requireOverride?: readonly string[];
};

export type SkipDecision = {
  readonly key: string;
  /** Non-null only when the plan's full skip contract holds. */
  readonly skip: CheckRecord | null;
  readonly warnings: readonly string[];
};

/**
 * May this exact fingerprint be skipped? Re-probes engines (engineVersion
 * changes flip rulesHash ⇒ key) but never runs the pipeline. A degraded probe
 * yields no skip: certification needs a healthy run, and the caller's
 * degraded ⇒ exit-2 gate stays the single source of that failure mode.
 * Best-effort by contract: any fingerprint-phase throw (missing vendored
 * rules, probe spawn error) returns "no skip" and lets the FULL pipeline run,
 * where the same failure takes its established structured exit-2 path — the
 * ledger can refuse to skip, but can never re-route an error or certify.
 */
export async function consultSkipLedger(q: SkipQuery): Promise<SkipDecision> {
  let ctx: CheckContext;
  let fp: LedgerFingerprint;
  let probeDegraded: boolean;
  try {
    ({ ctx, fp, probeDegraded } = await computeFingerprint(
      q.repoDir,
      q.cfg,
      q.configDigest,
      q.effectiveTargets,
      { ...(q.env !== undefined ? { env: q.env } : {}), ...(q.requireOverride !== undefined ? { requireOverride: q.requireOverride } : {}) },
    ));
  } catch {
    return { key: "", skip: null, warnings: [] };
  }
  if (probeDegraded) return { key: fp.key, skip: null, warnings: [] };
  const read: LedgerRead = readLedger(q.repoDir);
  const candidate = lookupSkipRecord(read.records, fp.key, q.llm);
  if (candidate === null) return { key: fp.key, skip: null, warnings: read.warnings };
  const fresh = verifyArtifactFreshness(candidate, ctx, q.repoDir, q.env !== undefined ? { env: q.env } : {});
  return { key: fp.key, skip: fresh ? candidate : null, warnings: read.warnings };
}

export type RecordInput = {
  readonly repoDir: string;
  readonly report: Report;
  readonly ctx: CheckContext;
  readonly effectiveTargets: readonly string[];
  readonly llm: boolean;
  readonly env?: EngineOptions["env"];
};

/**
 * Archive + append one check record. NEVER call for a NO-OP or degraded run —
 * the throw here is the backstop, the caller's degraded gate is the front door.
 * Artifact digests are captured only for a clean-tree PASS that includes npm,
 * so the future SKIP on that key can repack-and-compare (round-1 M8).
 */
export function recordCheckRun(i: RecordInput): CheckRecord {
  if (i.report.verdict === "NO-OP") {
    throw new Error("refusing to ledger a NO-OP report — nothing was verified, so there is nothing to skip");
  }
  const ts = new Date().toISOString();
  const key8 = i.report.key.slice(0, 8);
  const dirName = uniqueRunDirName(i.repoDir, key8, ts);
  ensureRunDir(i.repoDir, dirName);
  const relReport = reportRelPath(dirName);
  writeFileSync(join(i.repoDir, BORDER_STATE_DIR, relReport), `${JSON.stringify(i.report, null, 2)}\n`, "utf8");
  const envOpt = i.env !== undefined ? { env: i.env } : {};
  const artifacts =
    i.report.verdict === "PASS" && !i.ctx.dirty && i.effectiveTargets.includes("npm")
      ? packNpmArtifacts(i.repoDir, envOpt)
      : null;
  const record: CheckRecord = {
    t: "check",
    key: i.report.key,
    key8,
    head: i.report.head,
    dirtyDigest: i.ctx.porcelainDigest,
    refSetHash: createHash("sha256").update(stableStringify([...i.report.refSet].sort())).digest("hex"),
    exposureSet: [...i.report.exposureSet],
    effectiveTargets: [...i.effectiveTargets].sort(),
    rulesHash: i.report.rulesHash,
    artifacts,
    llm: i.llm,
    verdict: i.report.verdict,
    counts: i.report.counts,
    reportPath: `.border/${relReport}`,
    degraded: false,
    ts,
  };
  appendRecord(i.repoDir, record);
  pruneRunDirs(i.repoDir, key8);
  return record;
}
