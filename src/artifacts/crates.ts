// provenance: original clean-room implementation per .omo/plans/border-push-channels.md todo C3
//
// cargo package-once artifact pipeline (plan C3 Scope + CHANNEL-CONTRACTS.md §a/§c).
// ONE `cargo package --allow-dirty --no-verify` into <repo>/.border/dist/ is the
// single source of bytes for the whole gate chain: the recorded {file, sha256,
// bytes} is what the push core re-hashes before publish and todo 14 pins in the
// ledger — nothing downstream rebuilds. The package is byte-deterministic for a
// given HEAD (spike §a: fixed tar member mtimes, gzip MTIME 0, digest bound to
// the .cargo_vcs_info.json sha1) — which is what makes the pre-publish repack
// digest-assert and the freshness repack sound. The .crate is a raw gzip tar
// that gitleaks 8.30.1 provably does NOT scan natively (spike §c), so it is
// extracted to a throwaway sandbox under .border/tmp/ and the EXTRACTED TREE is
// scanned (gitleaks dir + secretlint paths); the sandbox is removed on success
// AND failure. Build output lands in CARGO_TARGET_DIR under .border/tmp/
// (plan) so no target/ dir can pollute the repo tree.
import { existsSync, mkdirSync, readFileSync, readdirSync, renameSync, rmSync } from "node:fs";
import { createHash } from "node:crypto";
import { join, relative } from "node:path";
import { spawnSync } from "node:child_process";

import type { BorderConfig } from "../config.ts";
import type { Finding } from "../findings.ts";
import { BORDER_STATE_DIR, ensureStateDir } from "../check/lock.ts";
import { extractArchive, removeSandbox } from "./extract.ts";
import { residueFindings } from "./residue.ts";
import { residueCratesHits } from "./residueRust.ts";
import { cratesCoherenceFindings } from "../rules/releaseCoherence.ts";
import { scanTree } from "../engines/gitleaks.ts";
import { scanPaths, type SecretlintMode } from "../engines/secretlint.ts";
import { EngineMissingError, EngineRunError, type EngineOptions } from "../engines/support.ts";
import type { TextSanitizer } from "../redact.ts";

/** Native-finding target label shared across the artifact-stage scans. */
export const CRATES_TARGET_LABEL = "artifact";

export type CrateArtifactRecord = {
  /** repo-relative path of the single packed crate (`.border/dist/<file>`). */
  readonly file: string;
  readonly sha256: string;
  readonly bytes: number;
};

export type CrateStageOptions = {
  readonly repoDir: string;
  readonly cfg: BorderConfig;
  readonly env?: EngineOptions["env"];
  readonly sanitizer?: TextSanitizer;
  readonly skipGitleaks?: boolean;
  readonly skipSecretlint?: boolean;
  readonly secretlintMode?: SecretlintMode;
  /** Exact cargo binary seam (tests / pinned toolchains); default "cargo" on PATH. */
  readonly cargoBinPath?: string;
  /** shared engine/extract timeout. */
  readonly timeoutMs?: number;
  readonly cargoTimeoutMs?: number;
};

export type CrateStageResult = {
  readonly findings: readonly Finding[];
  readonly artifact: CrateArtifactRecord | null;
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

/** Read `name` + `version` from the WORKING-TREE Cargo.toml — cargo packages
 *  the working tree, not HEAD, so the crate identity is the tree's identity. */
function manifestIdentity(repoDir: string, cfg: BorderConfig): { name: string; version: string } {
  const manifestPath = join(repoDir, "Cargo.toml");
  if (!existsSync(manifestPath)) {
    throw new EngineRunError("targets.crates is configured but the repo has no Cargo.toml to package", null);
  }
  const raw = readFileSync(manifestPath, "utf8");
  const pkg = /^\[package\]/m.test(raw);
  if (!pkg) throw new EngineRunError("Cargo.toml has no [package] section — nothing cargo package can publish", null);
  const name = cfg.targets.crates?.name ?? /^name\s*=\s*"([^"]+)"/m.exec(raw)?.[1];
  if (name === undefined) {
    throw new EngineRunError("Cargo.toml has no literal package name in the [package] section (and no targets.crates.name override)", null);
  }
  const version = /^version\s*=\s*"([^"]+)"/m.exec(raw)?.[1];
  if (version === undefined) {
    throw new EngineRunError(
      "Cargo.toml has no literal package version — workspace-inherited or computed versions (version.workspace = true) are not supported; publish by setting a literal version",
      null,
    );
  }
  return { name, version };
}

/**
 * Run the crates artifact stage. Throws EngineMissingError/EngineRunError
 * (exit 2 via translateError) for anything that must NOT read as "clean":
 * cargo absent, package failure, missing .crate output.
 */
export async function runCargoArtifactStage(o: CrateStageOptions): Promise<CrateStageResult> {
  if (o.cfg.targets.crates === undefined) {
    throw new EngineRunError("runCargoArtifactStage invoked without targets.crates configured — pipeline bug", null);
  }
  const { repoDir } = o;
  const bin = o.cargoBinPath ?? "cargo";
  const identity = manifestIdentity(repoDir, o.cfg);
  const crateName = `${identity.name}-${identity.version}.crate`;

  const versionCheck = spawnSync(bin, ["--version"], {
    encoding: "utf8",
    stdio: "ignore",
    ...(o.env === undefined ? {} : { env: { ...o.env } }),
  });
  if (versionCheck.error !== undefined || versionCheck.status !== 0) {
    throw new EngineMissingError(
      `cargo is not available (\`${bin} --version\` failed) — install Rust via rustup (https://rustup.rs) or pass cargoBinPath before running border check (border exit 2)`,
    );
  }

  ensureStateDir(repoDir);
  const stateDir = join(repoDir, BORDER_STATE_DIR);
  const distDir = join(stateDir, "dist");
  const targetDir = join(stateDir, "tmp", "cargo-target");
  mkdirSync(distDir, { recursive: true });
  rmSync(targetDir, { recursive: true, force: true }); // stale build output from an interrupted run
  mkdirSync(targetDir, { recursive: true });

  try {
    const result = spawnSync(bin, ["package", "--allow-dirty", "--no-verify"], {
      cwd: repoDir,
      encoding: "utf8",
      timeout: o.cargoTimeoutMs ?? 120_000,
      env: {
        ...(o.env === undefined ? process.env : { ...o.env }),
        CARGO_TARGET_DIR: targetDir,
      },
    });
    if (result.error !== undefined || result.status !== 0) {
      throw new EngineRunError(
        `cargo package failed (exit ${String(result.status)}) — nothing to gate: ${(result.stderr ?? "").trim().slice(0, 400)}`,
        result.status,
      );
    }

    // cargo writes the crate to <target-dir>/package/<name>-<version>.crate
    const packedDir = join(targetDir, "package");
    const packed = join(packedDir, crateName);
    if (!existsSync(packed)) {
      throw new EngineRunError(`cargo package produced no ${crateName} in ${relative(repoDir, packedDir)} — failing closed`, null);
    }
    const dist = join(distDir, crateName);
    renameSync(packed, dist);

    const bytes = readFileSync(dist);
    const sha256 = createHash("sha256").update(bytes).digest("hex");

    // raw .crate is a gitleaks native miss (contract §c) — scan the EXTRACTED tree
    const findings: Finding[] = [];
    const extractDir = join(stateDir, "tmp", sha256.slice(0, 8));
    rmSync(extractDir, { recursive: true, force: true });
    mkdirSync(extractDir, { recursive: true });
    try {
      extractArchive(dist, extractDir, {
        ...(o.env !== undefined ? { env: o.env } : {}),
        ...(o.timeoutMs !== undefined ? { timeoutMs: o.timeoutMs } : {}),
      });
      const relPaths = listFiles(extractDir).map((p) => relative(extractDir, p));
      if (relPaths.length === 0) throw new EngineRunError("extracted artifact is empty — unusable cargo package output", null);

      if (o.skipGitleaks !== true) {
        const tree = scanTree({
          dir: extractDir,
          stateDir,
          target: CRATES_TARGET_LABEL,
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
          target: CRATES_TARGET_LABEL,
          rules: o.cfg.rules,
          ...(o.secretlintMode !== undefined ? { mode: o.secretlintMode } : {}),
          ...(o.env !== undefined ? { env: o.env } : {}),
          ...(o.sanitizer !== undefined ? { sanitizer: o.sanitizer } : {}),
          ...(o.timeoutMs !== undefined ? { timeoutMs: o.timeoutMs } : {}),
        });
        findings.push(...linted);
      }
      // R3a residue leg (plan §57): build.rs OUT_DIR confinement + [build-dependencies] net scan
      // + artifact-wide T4; inner rels keep the `<name>-<version>/` wrapper (crates convention).
      findings.push(...residueFindings(residueCratesHits(extractDir, relPaths), {
        root: "",
        identity: crateName,
        ...(o.sanitizer !== undefined ? { sanitizer: o.sanitizer } : {}),
      }));
      // W4.1 release coherence: Cargo.toml [package].version ↔ the packed Cargo.lock's
      // [[package]] entry for this crate. cargo only ships Cargo.lock when packed —
      // ABSENT-SOURCE BOUNDARY: unpacked lock is not drift, never a finding.
      const lockRel = `${identity.name}-${identity.version}/Cargo.lock`;
      findings.push(...cratesCoherenceFindings({
        name: identity.name,
        version: identity.version,
        lockText: relPaths.includes(lockRel) ? readFileSync(join(extractDir, lockRel), "utf8") : null,
        lockRelPath: lockRel,
        identity: crateName,
        ...(o.sanitizer !== undefined ? { sanitizer: o.sanitizer } : {}),
      }));
    } finally {
      removeSandbox(extractDir);
    }

    return {
      findings,
      artifact: { file: `${BORDER_STATE_DIR}/dist/${crateName}`, sha256, bytes: bytes.length },
    };
  } finally {
    rmSync(targetDir, { recursive: true, force: true });
  }
}