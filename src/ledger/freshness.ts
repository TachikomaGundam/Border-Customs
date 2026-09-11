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
// W3.2 (.omo/plans/border-inspect-roadmap.md): the .gem parity metric is a
// NORMALIZED content digest, not the raw file sha256 — `gem build` embeds
// toolchain stamps (rubygems_version/gem_version, and on RubyGems versions
// without pinned timestamps also the gzip-header mtime and the metadata
// date) whose byte-stability is a property of the local toolchain, not of
// the packaged content: the raw sha is per-environment truth (spike §e held
// on the measured RubyGems 3.6.7; runner images drift — W3.1 residual, the
// gem duo was flaky-green on CI). The normalized digest is sha256 over the
// gunzipped data.tar.gz canonicalized per entry (name, typeflag, exec bits,
// content sha256 — mtimes/uid/gid/uname/gname/umask-only mode bits dropped)
// plus the gunzipped metadata minus its `rubygems_version`/`gem_version`/
// `date` stamp lines and the EMPTY deprecated-serializer keys 3.4.x emits and
// 3.6.x drops (autorequire/description/email/homepage/post_install_message/
// signing_key — a SET value still rides the digest); checksums.yaml.gz is
// excluded (it hashes the raw gz member bytes). Still caught: every shipped
// file's bytes, path, order and exec bit, and the metadata's substance.
// Tolerated: build stamps and empty legacy keys only. Ledger
// records and the publish-time same-bytes re-hash stay RAW — a drifted
// builder still uploads the exact certified bytes; only the skip-ledger
// repack comparison normalizes. Anything unparseable fails closed to null
// ⇒ parity mismatch ⇒ FULL re-check, never a skip.
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { gunzipSync } from "node:zlib";

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

/* ------------------------------------------------------------------ .gem content digest (W3.2) */

/** One member of a plain ustar archive: the header fields the content digest reads. */
type TarMember = { readonly content: Buffer; readonly typeFlag: number; readonly mode: number; readonly linkName: string };

/** Octal tar header field ("0000664\0" / "664 ") → number. */
function octalField(block: Buffer, start: number, end: number): number | null {
  const text = block.subarray(start, end).toString("utf8").replace(/[\0 ].*$/, "");
  if (text === "") return 0;
  if (!/^[0-7]+$/.test(text)) return null;
  return Number.parseInt(text, 8);
}

/**
 * Walk a plain ustar buffer into its entries, in archive order, duplicates
 * kept (parity must not let a repeated name shadow a payload entry). A
 * malformed header (bad magic, unparseable size, truncation) yields null —
 * callers treat that as "cannot prove parity" (fail closed), never as "clean".
 * The .gem members and a rubygems data.tar.gz are plain ustar; pax/GNU
 * extended-header entries (x, g, L, K) are skipped: they carry per-file
 * timestamps and long-name plumbing, i.e. exactly the toolchain truth the
 * content digest must not be sensitive to (fixture paths fit the 100-byte
 * name field in every measured RubyGems version).
 */
function tarEntries(buf: Buffer): { readonly name: string; readonly member: TarMember }[] | null {
  const magic = buf.subarray(257, 263).toString("latin1");
  if (!magic.startsWith("ustar")) return null;
  const out: { name: string; member: TarMember }[] = [];
  let off = 0;
  while (off + 512 <= buf.length) {
    const header = buf.subarray(off, off + 512);
    if (header.every((b) => b === 0)) return out;
    const size = octalField(header, 124, 136);
    if (size === null) return null;
    const mode = octalField(header, 100, 108);
    if (mode === null) return null;
    const typeFlag = header[156] ?? 0x30;
    const body = off + 512;
    if (body + size > buf.length) return null;
    const name = header.subarray(0, 100).toString("utf8").replace(/\0.*$/, "");
    const linkName = header.subarray(157, 257).toString("utf8").replace(/\0.*$/, "");
    if (typeFlag !== 0x78 && typeFlag !== 0x67 && typeFlag !== 0x4c && typeFlag !== 0x4b) {
      out.push({ name, member: { content: buf.subarray(body, body + size), typeFlag, mode, linkName } });
    }
    off = body + Math.ceil(size / 512) * 512;
  }
  return out;
}

/** Metadata lines that stamp the BUILDING toolchain / build instant, never the payload. */
const GEM_METADATA_STAMP_RE = /^(rubygems_version|gem_version|date):/;

/**
 * Deprecated Gem::Specification fields: RubyGems <= 3.4 serializes them as
 * EMPTY keys, 3.6+ drops them from the stream entirely (measured locally by
 * building the same fixture under RubyGems 3.6.7 and 3.4.20 — the runner
 * image's version). Dropping only the empty forms keeps the pin blind to the
 * serializer's housekeeping while a gemspec that actually SETS one of these
 * fields still rides the digest (a value line survives the filter).
 */
const GEM_LEGACY_EMPTY_RE = /^(autorequire|description|email|homepage|post_install_message|signing_key):[ ]*$/;

function sha256Hex(buf: Buffer): string {
  return createHash("sha256").update(buf).digest("hex");
}

/**
 * Normalized content digest of a .gem (the plain-tar container `gem build`
 * emits: metadata.gz + data.tar.gz [+ checksums.yaml.gz]). Raw byte parity
 * across two builds holds only on RubyGems versions that pin every build
 * timestamp; the content digest holds for ANY builder as long as the packaged
 * payload is identical — see module header for the exact tolerate/catch line.
 * null ⇒ not a parseable .gem ⇒ parity unprovable ⇒ fail closed to a re-check.
 */
export function gemContentDigest(bytes: Buffer): string | null {
  const outer = tarEntries(bytes);
  if (outer === null) return null;
  const meta = outer.find((e) => e.name === "metadata.gz")?.member;
  const data = outer.find((e) => e.name === "data.tar.gz")?.member;
  if (meta === undefined || data === undefined) return null;
  let metadata: string;
  let inner: Buffer;
  try {
    metadata = gunzipSync(meta.content).toString("utf8");
    inner = gunzipSync(data.content);
  } catch {
    return null;
  }
  const innerEntries = tarEntries(inner);
  if (innerEntries === null) return null;
  const chain = createHash("sha256");
  for (const { name, member: m } of innerEntries) {
    chain
      .update(name)
      .update("\u0000")
      .update(String(m.typeFlag))
      .update("\u0000")
      .update(String(m.mode & 0o111))
      .update("\u0000")
      .update(m.linkName)
      .update("\u0000")
      .update(sha256Hex(m.content))
      .update("\u0000");
  }
  const metaStripped = metadata
    .split("\n")
    .filter((line) => !GEM_METADATA_STAMP_RE.test(line) && !GEM_LEGACY_EMPTY_RE.test(line))
    .join("\n");
  return createHash("sha256").update("border-gem-content-v1\u0000").update(chain.digest("hex")).update("\u0000").update(metaStripped).digest("hex");
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
 *  Parity is the W3.2 normalized content digest (module header): raw bytes
 *  are byte-deterministic per tree only on RubyGems versions that pin every
 *  build timestamp (spike §e measured 3.6.7), so the raw sha rides the ledger
 *  for the same-bytes publish proof while the repack comparison reads
 *  content. The digest is blind to git HEAD, so the key match (HEAD) + this
 *  repack (worktree bytes) compose the real proof. */
export function packRubygemsArtifacts(repoDir: string, o: FreshnessOptions = {}): readonly RepackArtifact[] | null {
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
    return files.map((f) => {
      const raw = readFileSync(join(dest, f));
      return { file: f, sha256: sha256Hex(raw), contentDigest: gemContentDigest(raw) };
    });
  } finally {
    rmSync(dest, { recursive: true, force: true });
  }
}

/** A freshness repack entry: the recorded {file, sha256} plus, for formats
 *  whose raw bytes carry builder stamps (.gem, W3.2), the normalized content
 *  digest the parity check compares. `contentDigest: null` ⇒ the built file
 *  is not a parseable .gem ⇒ parity unprovable ⇒ fail closed to a re-check. */
export type RepackArtifact = LedgerArtifact & { readonly contentDigest?: string | null };

/** Re-pack implementations, keyed by channel id — the ONE look-up for the
 *  "repack" strategy (npm, crates and rubygems; a channel with no entry —
 *  pypi's key-match proof is the whole strategy — can never be a repacker). */
export const REPACKERS: Readonly<Partial<Record<PublishChannelId, (repoDir: string, o: FreshnessOptions) => readonly RepackArtifact[] | null>>> = {
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

/** Parity value of one .gem entry: the repack side carries the precomputed
 *  content digest; the record side is re-derived from its bytes (fail closed
 *  to null on missing/unparseable files). */
function gemParity(entry: RepackArtifact, repoDir: string): string | null {
  if (entry.contentDigest !== undefined) return entry.contentDigest;
  try {
    return gemContentDigest(readFileSync(join(repoDir, entry.file)));
  } catch {
    return null;
  }
}

/**
 * Compare the repack-per-channel digests only (extension-filtered). Records
 * list repo-relative .border/dist paths (GAP B: the pipeline's own pack) while
 * the freshness repack yields bare tarball names from a deleted tmp dir —
 * basenames are the shared identity. The repackable subset excludes non-
 * reproducible formats (pypi wheels/sdists), whose freshness rides the
 * key match (round-2 LOW). .gem entries compare by the W3.2 normalized
 * content digest; any unprovable parity (null) fails closed to a re-check.
 */
function sameArtifacts(a: readonly LedgerArtifact[], b: readonly RepackArtifact[], extensions: readonly string[], repoDir: string): boolean {
  const digests = (xs: readonly RepackArtifact[]): string[] | null => {
    const out: string[] = [];
    for (const x of xs) {
      const base = x.file.slice(x.file.lastIndexOf("/") + 1);
      const ext = extensions.find((e) => base.endsWith(e));
      if (ext === undefined) continue;
      const parity = ext === ".gem" ? gemParity(x, repoDir) : x.sha256;
      if (parity === null) return null;
      out.push(`${base}\u0000${parity}`);
    }
    return out.sort();
  };
  const ka = digests(a);
  const kb = digests(b);
  return ka !== null && kb !== null && ka.length === kb.length && ka.every((x, i) => x === kb[i]);
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
  const now: RepackArtifact[] = [];
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
    repoDir,
  );
}