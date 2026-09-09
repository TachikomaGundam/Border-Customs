// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 14,
//   extended per .omo/plans/border-push-channels.md todo C3 (shared repack-strategy lookup)
//
// Round-1 M8 artifact-freshness proof on the SKIP path. A key match alone does
// not prove the PACKABLE payload unchanged: gitignored-but-packed files (a
// dist/ populated by a build) move neither HEAD nor `git status --porcelain`,
// so repackable targets must re-pack and digest-compare against the PASS
// record's artifacts before a skip is honored. WHICH targets repack is a
// per-channel decision, one lookup site: the channel descriptor's `freshness`
// field ("repack" ⇒ digest-identical re-pack — npm pack, cargo package,
// spike-proven byte-deterministic; "key" ⇒ the key match is the whole proof,
// pypi's non-reproducible wheels). PyPI rebuilds are not byte-reproducible,
// so their proof degrades to head+porcelainDigest equality — which the key
// match already implies (round-2 LOW); plan accepts that residual hole.
// Anything that can go wrong (packer missing, pack failure, zero artifacts,
// artifacts never recorded) fails toward a FULL re-check: freshness is
// proven, never assumed.
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { join } from "node:path";

import type { CheckContext } from "../check/context.ts";
import type { EngineOptions } from "../engines/support.ts";
import { BORDER_STATE_DIR } from "../check/lock.ts";
import { publishChannels, type PublishChannelId } from "../channels/registry.ts";
import { singleTreeGemspec } from "../artifacts/rubygems.ts";
import type { CheckRecord, LedgerArtifact } from "./records.ts";

// Which targets carry packable artifacts — derived from the channel registry
// (todo C2); any registered publish channel with artifactExtensions joins here.
// Lazy (function, not top-level const): freshness sits inside the registry's
// own import subtree, so a top-level registry call here would hit uninitialized
// bindings during the initial module-evaluation pass.
function artifactTargets(): readonly string[] {
  return publishChannels().map((c) => c.id);
}

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

/** Cargo crate re-pack (todo C3): `cargo package` mirrors the check's stage
 *  recipe; CARGO_TARGET_DIR keeps the rebuild inside .border/tmp. Digest parity
 *  holds because cargo packaging is byte-deterministic per HEAD (spike §a). */
export function packCrateArtifacts(repoDir: string, o: FreshnessOptions = {}): readonly LedgerArtifact[] | null {
  packSeq += 1;
  const dest = join(repoDir, BORDER_STATE_DIR, "tmp", `cargo-pack-${String(process.pid)}-${String(packSeq)}`);
  mkdirSync(dest, { recursive: true });
  try {
    const r = spawnSync("cargo", ["package", "--allow-dirty", "--no-verify"], {
      cwd: repoDir,
      encoding: "utf8",
      env: { ...(o.env ?? process.env), CARGO_TARGET_DIR: dest },
      timeout: 120_000,
    });
    if (r.error !== undefined || r.status !== 0) return null;
    const dir = join(dest, "package");
    const files = readdirSync(dir).filter((f) => f.endsWith(".crate")).sort();
    if (files.length === 0) return null;
    return files.map((f) => ({ file: f, sha256: sha256File(join(dir, f)) }));
  } finally {
    rmSync(dest, { recursive: true, force: true });
  }
}

/** Gem re-pack (todo C4): `gem build` mirrors the check's stage recipe — the
 *  gemspec is discovered in the working tree (exactly one *.gemspec; a
 *  multi-gemspec tree, a non-literal identity or any s.date assignment makes
 *  the repack return null ⇒ full re-check every time, fail-closed never a
 *  skip ✓), built with -o into a throwaway dir under .border/tmp and digested.
 *  Digest parity holds because gem build is byte-deterministic per tree
 *  (spike §e: fixed 1980-01-02 date); the digest is blind to git HEAD, so the
 *  key match (HEAD) + this repack (worktree bytes) compose the real proof. */
export function packRubygemsArtifacts(repoDir: string, o: FreshnessOptions = {}): readonly LedgerArtifact[] | null {
  packSeq += 1;
  const ident = singleTreeGemspec(repoDir);
  if (ident === null) return null;
  const dest = join(repoDir, BORDER_STATE_DIR, "tmp", `gem-pack-${String(process.pid)}-${String(packSeq)}`);
  mkdirSync(dest, { recursive: true });
  try {
    const gemName = `${ident.name}-${ident.version}.gem`;
    const r = spawnSync("gem", ["build", ident.path, "-o", join(dest, gemName)], {
      cwd: repoDir,
      encoding: "utf8",
      env: { ...(o.env ?? process.env) },
      timeout: 120_000,
    });
    if (r.error !== undefined || r.status !== 0) return null;
    const files = readdirSync(dest).filter((f) => f.endsWith(".gem")).sort();
    if (files.length === 0) return null;
    return files.map((f) => ({ file: f, sha256: sha256File(join(dest, f)) }));
  } finally {
    rmSync(dest, { recursive: true, force: true });
  }
}

/** Re-pack implementations, keyed by channel id — the ONE look-up for the
 *  "repack" strategy (npm, crates and rubygems; a channel with no entry —
 *  pypi's key-match proof is the whole strategy — can never be a repacker). */
export const REPACKERS: Readonly<Partial<Record<PublishChannelId, (repoDir: string, o: FreshnessOptions) => readonly LedgerArtifact[] | null>>> = {
  npm: packNpmArtifacts,
  crates: packCrateArtifacts,
  rubygems: packRubygemsArtifacts,
};

/** Repack-assertable channels (descriptor freshness "repack"), in order. */
function repackChannels(): readonly PublishChannelId[] {
  return publishChannels()
    .filter((c) => c.freshness === "repack")
    .map((c) => c.id);
}

/**
 * Compare the repack-per-channel digests only (extension-filtered). Records
 * list repo-relative .border/dist paths (GAP B: the pipeline's own pack) while
 * the freshness repack yields bare tarball names from a deleted tmp dir —
 * basenames are the shared identity. The repackable subset excludes non-
 * reproducible formats (pypi wheels/sdists), whose freshness rides the
 * key match (round-2 LOW).
 */
function sameArtifacts(a: readonly LedgerArtifact[], b: readonly LedgerArtifact[], extensions: readonly string[]): boolean {
  const digests = (xs: readonly LedgerArtifact[]): string[] =>
    xs
      .filter((x) => extensions.some((ext) => x.file.slice(x.file.lastIndexOf("/") + 1).endsWith(ext)))
      .map((x) => `${x.file.slice(x.file.lastIndexOf("/") + 1)}\u0000${x.sha256}`)
      .sort();
  const ka = digests(a);
  const kb = digests(b);
  return ka.length === kb.length && ka.every((x, i) => x === kb[i]);
}

/**
 * May this PASS record be skipped against the CURRENT tree ctx?
 * git-only runs skip untouched; artifact runs demand a clean tree; repackable
 * channels (npm, crates) demand a digest-identical re-pack of ONLY their own
 * extensions; everything else (pypi) rides the key-match proof.
 */
export function verifyArtifactFreshness(
  record: CheckRecord,
  ctx: CheckContext,
  repoDir: string,
  o: FreshnessOptions = {},
): boolean {
  if (!record.effectiveTargets.some((t) => artifactTargets().includes(t))) return true;
  if (ctx.dirty) return false;
  const needed = repackChannels().filter((t) => record.effectiveTargets.includes(t));
  if (needed.length === 0) return true;
  if (record.artifacts === null) return false;
  const now: LedgerArtifact[] = [];
  for (const id of needed) {
    const pack = REPACKERS[id];
    if (pack === undefined) return false;
    const got = pack(repoDir, o);
    if (got === null) return false;
    now.push(...got);
  }
  return sameArtifacts(
    record.artifacts,
    now,
    needed.flatMap((id) => {
      const channel = publishChannels().find((c) => c.id === id);
      return channel?.artifactExtensions ?? [];
    }),
  );
}