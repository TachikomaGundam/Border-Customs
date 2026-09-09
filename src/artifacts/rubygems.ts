// provenance: original clean-room implementation per .omo/plans/border-push-channels.md todo C4
//
// gem build-once artifact pipeline (plan C4 Scope + CHANNEL-CONTRACTS.md §d/§e).
// ONE `gem build <gemspec> -o <repo>/.border/dist/<name>-<version>.gem` is the
// single source of bytes for the whole gate chain: the recorded {file, sha256,
// bytes} is what the push core re-hashes before publish and the ledger pins —
// nothing downstream rebuilds. The -o flag is MANDATORY (contract trap §d:
// without it the output name derives from the SPEC name-version, not the
// gemspec filename — the recorded name would be a guess). gem build is
// byte-deterministic for a given tree (spike §e: date fixed 1980-01-02, member
// bytes stable) — which is what makes the freshness repack sound; caveats: an
// explicit s.date assignment makes builds legitimately non-deterministic
// (REJECTED here and at coords), and the digest is blind to git HEAD (the
// fingerprint key covers HEAD; the repack covers worktree bytes — compose).
// The .gem is a PLAIN tar (outer members metadata.gz / data.tar.gz /
// checksums.yaml.gz) that gitleaks 8.30.1 provably does NOT scan natively
// (contract §d), so it is extracted ONE pass (`tar -xf` — NOT -xzf, .gem is
// not gzipped) to a throwaway sandbox under .border/tmp/ and the EXTRACTED
// TREE is scanned: gitleaks descends into the inner data.tar.gz itself at
// --max-archive-depth 2 (paths arrive `data.tar.gz!lib/x.rb` — the inner
// archive is never double-extracted), secretlint covers the top-level members.
// The sandbox is removed on success AND failure.
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { join, relative } from "node:path";
import { spawnSync } from "node:child_process";
import { gunzipSync } from "node:zlib";

import type { BorderConfig } from "../config.ts";
import type { Finding } from "../findings.ts";
import { BORDER_STATE_DIR, ensureStateDir } from "../check/lock.ts";
import { extractArchive, removeSandbox } from "./extract.ts";
import { type ResidueHit, residueFindings } from "./residue.ts";
import { residueGemHits } from "./residueGem.ts";
import { scanTree } from "../engines/gitleaks.ts";
import { scanPaths, type SecretlintMode } from "../engines/secretlint.ts";
import { EngineMissingError, EngineRunError, type EngineOptions } from "../engines/support.ts";
import type { TextSanitizer } from "../redact.ts";
import { ConfigError } from "../channels/errors.ts";
import { selectGemspec } from "../channels/gemspec.ts";

/** Native-finding target label shared across the artifact-stage scans. */
export const RUBYGEMS_TARGET_LABEL = "artifact";

/** Directories never descended into when hunting for *.gemspec files. */
const SKIP_DIRECTORIES = new Set([".git", ".border"]);

export type GemArtifactRecord = {
  /** repo-relative path of the single built gem (`.border/dist/<file>`). */
  readonly file: string;
  readonly sha256: string;
  readonly bytes: number;
};

export type GemStageOptions = {
  readonly repoDir: string;
  readonly cfg: BorderConfig;
  readonly env?: EngineOptions["env"];
  readonly sanitizer?: TextSanitizer;
  readonly skipGitleaks?: boolean;
  readonly skipSecretlint?: boolean;
  readonly secretlintMode?: SecretlintMode;
  /** Exact gem binary seam (tests / pinned toolchains); default "gem" on PATH. */
  readonly gemBinPath?: string;
  /** shared engine/extract timeout. */
  readonly timeoutMs?: number;
  readonly gemTimeoutMs?: number;
};

export type GemStageResult = {
  readonly findings: readonly Finding[];
  readonly artifact: GemArtifactRecord | null;
};

function scopeFindingPath(f: Finding, extractDir: string): Finding {
  if (f.path === undefined) return f;
  const bang = f.path.indexOf("!");
  if (bang > 0) {
    const rel = relative(extractDir, f.path.slice(0, bang));
    if (!rel.startsWith("..")) return { ...f, path: rel === "" ? f.path.slice(bang + 1) : `${rel}${f.path.slice(bang)}` };
  }
  const rel = relative(extractDir, f.path);
  return rel === "" || rel.startsWith("..") ? f : { ...f, path: rel };
}

function listFiles(dir: string): string[] {
  const out: string[] = [];
  const stack = [dir];
  while (stack.length > 0) {
    const cur = stack.pop() as string;
    for (const ent of readdirSync(cur, { withFileTypes: true })) {
      const p = join(cur, ent.name);
      if (ent.isDirectory()) stack.push(p);
      else if (ent.isFile()) out.push(p);
    }
  }
  return out;
}

/** *.gemspec candidates from the WORKING TREE (gem build packages the tree,
 *  not HEAD — same doctrine as cargo's working-tree identity). */
function treeGemspecCandidates(repoDir: string): { path: string; body: string }[] {
  const out: { path: string; body: string }[] = [];
  const stack = [repoDir];
  while (stack.length > 0) {
    const cur = stack.pop() as string;
    for (const ent of readdirSync(cur, { withFileTypes: true })) {
      const p = join(cur, ent.name);
      if (ent.isDirectory()) {
        if (!SKIP_DIRECTORIES.has(ent.name)) stack.push(p);
      } else if (ent.isFile() && ent.name.toLowerCase().endsWith(".gemspec")) {
        out.push({ path: relative(repoDir, p), body: readFileSync(p, "utf8") });
      }
    }
  }
  return out.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
}

/** Read the single gemspec's {name, version} FROM THE WORKING TREE — gem
 *  builds the tree, so the gem identity is the tree's identity. Returns null
 *  when the tree cannot yield an unambiguous literal identity (zero/multiple
 *  gemspecs, computed values, s.date): the freshness repack then fails closed
 *  to a full re-check (null can never justify a skip). */
export function singleTreeGemspec(repoDir: string, cfg?: BorderConfig): { path: string; name: string; version: string } | null {
  const candidates = treeGemspecCandidates(repoDir);
  if (candidates.length !== 1) return null;
  try {
    const identity = selectGemspec(candidates, cfg?.targets.rubygems?.name, "targets.rubygems", "in the working tree");
    return { path: (candidates[0] as { path: string }).path, ...identity };
  } catch (e) {
    if (e instanceof ConfigError) return null;
    throw e;
  }
}

/**
 * Run the rubygems artifact stage. Throws EngineMissingError/EngineRunError
 * + ConfigError (exit 2 via translateError) for anything that must NOT read
 * as "clean": gem absent, build failure, missing .gem output, ambiguous or
 * non-literal gemspecs, s.date assignments.
 */
export async function runRubygemsArtifactStage(o: GemStageOptions): Promise<GemStageResult> {
  if (o.cfg.targets.rubygems === undefined) {
    throw new EngineRunError("runRubygemsArtifactStage invoked without targets.rubygems configured — pipeline bug", null);
  }
  const { repoDir } = o;
  const bin = o.gemBinPath ?? "gem";

  const candidates = treeGemspecCandidates(repoDir);
  let identity: { name: string; version: string };
  try {
    identity = selectGemspec(candidates, o.cfg.targets.rubygems?.name, "targets.rubygems", "in the working tree");
  } catch (e) {
    if (e instanceof ConfigError) throw new EngineRunError(e.message, null);
    throw e;
  }
  const gemName = `${identity.name}-${identity.version}.gem`;

  const versionCheck = spawnSync(bin, ["--version"], {
    encoding: "utf8",
    stdio: "ignore",
    ...(o.env === undefined ? {} : { env: { ...o.env } }),
  });
  if (versionCheck.error !== undefined || versionCheck.status !== 0) {
    throw new EngineMissingError(
      `gem (RubyGems) is not available (\`${bin} --version\` failed) — install it (apt-get install ruby-full on Debian/Ubuntu, or via rbenv/rvm) or pass gemBinPath before running border check (border exit 2)`,
    );
  }

  ensureStateDir(repoDir);
  const stateDir = join(repoDir, BORDER_STATE_DIR);
  const distDir = join(stateDir, "dist");
  mkdirSync(distDir, { recursive: true });

  const dist = join(distDir, gemName);
  const result = spawnSync(bin, ["build", (candidates[0] as { path: string }).path, "-o", dist], {
    cwd: repoDir,
    encoding: "utf8",
    timeout: o.gemTimeoutMs ?? 120_000,
    ...(o.env === undefined ? {} : { env: { ...o.env } }),
  });
  if (result.error !== undefined || result.status !== 0) {
    throw new EngineRunError(
      `gem build failed (exit ${String(result.status)}) — nothing to gate: ${(result.stderr ?? "").trim().slice(0, 400)}`,
      result.status,
    );
  }
  if (!existsSync(dist)) {
    throw new EngineRunError(`gem build produced no ${gemName} in ${relative(repoDir, distDir)} — failing closed (was the gemspec's literal name/version re-read?)`, null);
  }

  const bytes = readFileSync(dist);
  const sha256 = createHash("sha256").update(bytes).digest("hex");

  // raw .gem is a gitleaks native miss (contract §d) — scan the EXTRACTED tree
  const findings: Finding[] = [];
  const extractDir = join(stateDir, "tmp", sha256.slice(0, 8));
  rmSync(extractDir, { recursive: true, force: true });
  mkdirSync(extractDir, { recursive: true });
  // R3b sibling sandbox — deliberately OUTSIDE extractDir: gitleaks already descends the inner
  // data.tar.gz natively (contract §d double-scan trap); a second copy inside would duplicate rows.
  const dataDir = `${extractDir}-data`;
  try {
    extractArchive(dist, extractDir, {
      ...(o.env !== undefined ? { env: o.env } : {}),
      ...(o.timeoutMs !== undefined ? { timeoutMs: o.timeoutMs } : {}),
    });
    const relPaths = listFiles(extractDir).map((p) => relative(extractDir, p));
    if (relPaths.length === 0) throw new EngineRunError("extracted artifact is empty — unusable gem package output", null);

    if (o.skipGitleaks !== true) {
      const tree = scanTree({
        dir: extractDir,
        stateDir,
        target: RUBYGEMS_TARGET_LABEL,
        ...(o.env !== undefined ? { env: o.env } : {}),
        ...(o.sanitizer !== undefined ? { sanitizer: o.sanitizer } : {}),
        ...(o.timeoutMs !== undefined ? { timeoutMs: o.timeoutMs } : {}),
      });
      for (const f of tree) findings.push(scopeFindingPath(f, extractDir));
    }
    if (o.skipSecretlint !== true) {
      const linted = await scanPaths({
        dir: extractDir,
        files: relPaths,
        target: RUBYGEMS_TARGET_LABEL,
        rules: o.cfg.rules,
        ...(o.secretlintMode !== undefined ? { mode: o.secretlintMode } : {}),
        ...(o.env !== undefined ? { env: o.env } : {}),
        ...(o.sanitizer !== undefined ? { sanitizer: o.sanitizer } : {}),
        ...(o.timeoutMs !== undefined ? { timeoutMs: o.timeoutMs } : {}),
      });
      findings.push(...linted);
    }

    // R3b residue lane (plan border-residue-gate): additive-only — every finding above this line
    // is emitted exactly as before the leg existed. Non-gem-layout containers (no metadata.gz/
    // data.tar.gz members) keep their pre-R3b behavior: engine rows only, no residue rows.
    const members = new Set(relPaths);
    if (members.has("metadata.gz") && members.has("data.tar.gz")) {
      let metadata: string;
      try {
        metadata = gunzipSync(readFileSync(join(extractDir, "metadata.gz"))).toString("utf8");
      } catch {
        throw new EngineRunError(`${gemName}: metadata.gz is not gunzip-readable — the extensions declaration cannot be verified, failing closed`, null);
      }
      rmSync(dataDir, { recursive: true, force: true });
      mkdirSync(dataDir, { recursive: true });
      extractArchive(join(extractDir, "data.tar.gz"), dataDir, {
        ...(o.env !== undefined ? { env: o.env } : {}),
        ...(o.timeoutMs !== undefined ? { timeoutMs: o.timeoutMs } : {}),
      });
      const dataRels = listFiles(dataDir).map((p) => relative(dataDir, p));
      let hits: ResidueHit[];
      try {
        hits = residueGemHits(dataDir, dataRels, metadata);
      } catch (e) {
        throw new EngineRunError(`${gemName}: ${e instanceof Error ? e.message : String(e)} — failing closed`, null);
      }
      for (const f of residueFindings(hits, {
        root: "data.tar.gz",
        sep: "!",
        identity: gemName,
        ...(o.sanitizer !== undefined ? { sanitizer: o.sanitizer } : {}),
      })) {
        findings.push(f);
      }
    }
  } finally {
    removeSandbox(extractDir);
    removeSandbox(dataDir);
  }

  return {
    findings,
    artifact: { file: `${BORDER_STATE_DIR}/dist/${gemName}`, sha256, bytes: bytes.length },
  };
}