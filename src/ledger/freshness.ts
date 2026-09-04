// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 14
//
// Round-1 M8 artifact-freshness proof on the SKIP path. A key match alone does
// not prove the PACKABLE payload unchanged: gitignored-but-packed files (a
// dist/ populated by a build) move neither HEAD nor `git status --porcelain`,
// so npm runs must re-pack and digest-compare against the PASS record's
// artifacts before a skip is honored. PyPI rebuilds are not byte-reproducible,
// so their proof degrades to head+porcelainDigest equality — which the key
// match already implies (round-2 LOW); plan accepts that residual hole.
// Anything that can go wrong (npm missing, pack failure, zero tarballs,
// artifacts never recorded) fails toward a FULL re-check: freshness is
// proven, never assumed.
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { join } from "node:path";

import type { CheckContext } from "../check/context.ts";
import type { EngineOptions } from "../engines/support.ts";
import { BORDER_STATE_DIR } from "../check/lock.ts";
import type { CheckRecord, LedgerArtifact } from "./records.ts";

const ARTIFACT_TARGETS: readonly string[] = ["npm", "pypi"];

export type FreshnessOptions = { readonly env?: EngineOptions["env"] };

function sha256File(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

let packSeq = 0;

/**
 * Re-pack via `npm pack --ignore-scripts`; null ⇒ packing unavailable, which can
 * never justify a skip. --ignore-scripts is the G33 guard (target-repo lifecycle
 * hooks must never execute inside border check — same defense as packOnce in
 * src/artifacts/npmPack.ts) AND the digest-parity requirement: the certified
 * pack is script-free, so the freshness repack must be too.
 */
export function packNpmArtifacts(repoDir: string, o: FreshnessOptions = {}): readonly LedgerArtifact[] | null {
  packSeq += 1;
  const dest = join(repoDir, BORDER_STATE_DIR, "tmp", `pack-${String(process.pid)}-${String(packSeq)}`);
  mkdirSync(dest, { recursive: true });
  try {
    const r = spawnSync("npm", ["pack", "--ignore-scripts", "--silent", `--pack-destination=${dest}`], {
      cwd: repoDir,
      encoding: "utf8",
      env: { ...(o.env ?? process.env) },
      timeout: 120_000,
    });
    if (r.error !== undefined || r.status !== 0) return null;
    const files = readdirSync(dest).filter((f) => f.endsWith(".tgz")).sort();
    if (files.length === 0) return null;
    return files.map((f) => ({ file: f, sha256: sha256File(join(dest, f)) }));
  } finally {
    rmSync(dest, { recursive: true, force: true });
  }
}

/**
 * Compare the npm tarball digests only. Records list repo-relative .border/dist
 * paths (GAP B: the pipeline's own pack) while the freshness repack yields bare
 * tarball names from a deleted tmp dir — basenames are the shared identity. The
 * .tgz subset excludes built wheels/sdists, whose digests are not reproducible
 * (round-2 LOW: pypi freshness rides the key match).
 */
function sameArtifacts(a: readonly LedgerArtifact[], b: readonly LedgerArtifact[]): boolean {
  const npmDigests = (xs: readonly LedgerArtifact[]): string[] =>
    xs
      .filter((x) => x.file.slice(x.file.lastIndexOf("/") + 1).endsWith(".tgz"))
      .map((x) => `${x.file.slice(x.file.lastIndexOf("/") + 1)}\u0000${x.sha256}`)
      .sort();
  const ka = npmDigests(a);
  const kb = npmDigests(b);
  return ka.length === kb.length && ka.every((x, i) => x === kb[i]);
}

/**
 * May this PASS record be skipped against the CURRENT tree ctx?
 * git-only runs skip untouched; artifact runs demand a clean tree; npm demands
 * a digest-identical re-pack; pypi rides the key-match proof.
 */
export function verifyArtifactFreshness(
  record: CheckRecord,
  ctx: CheckContext,
  repoDir: string,
  o: FreshnessOptions = {},
): boolean {
  if (!record.effectiveTargets.some((t) => ARTIFACT_TARGETS.includes(t))) return true;
  if (ctx.dirty) return false;
  if (!record.effectiveTargets.includes("npm")) return true;
  if (record.artifacts === null) return false;
  const now = packNpmArtifacts(repoDir, o);
  return now !== null && sameArtifacts(record.artifacts, now);
}
