// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 11
//
// npm pack-once artifact pipeline (plan G38/G39/G33/G23). ONE `npm pack` into
// <repo>/.border/dist/ is the single source of bytes for the whole gate chain:
// the recorded {file, sha256, bytes} is what todo 17 re-hashes before publish
// and todo 14 pins in the ledger — nothing downstream rebuilds. The tarball is
// extracted to a throwaway sandbox under .border/tmp/, content-scanned (gitleaks
// dir + secretlint paths), manifest-diffed against the `files` whitelist, then
// the sandbox is removed on success AND failure. publint runs against the
// tarball itself, never the working tree.
//
// PATH CONTRACT (the false-green trap, round-3 M-A): packs live under
// `.border/`, which filterBorderStateFindings hard-excludes at the user-repo
// root — so EVERY finding path emitted here is scoped to the artifact root
// (`package/<rel>`), never containing a `.border` segment. test/artifacts.npm.test.ts
// pins this end-to-end with a secret planted inside a packed file.
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { join, relative } from "node:path";

import type { BorderConfig } from "../config.ts";
import type { Finding, Severity } from "../findings.ts";
import { redact, type TextSanitizer } from "../redact.ts";
import { BORDER_STATE_DIR, ensureStateDir } from "../check/lock.ts";
import { extractArchive, removeSandbox } from "./extract.ts";
import { scanTree } from "../engines/gitleaks.ts";
import { scanPaths, type SecretlintMode } from "../engines/secretlint.ts";
import { EngineRunError, type EngineOptions } from "../engines/support.ts";
import { LIFECYCLE_SCRIPT_KEYS, parseNpmManifest, unexpectedEntries } from "./manifestDiff.ts";
import {
  NPM_LIFECYCLE_RULE,
  NPM_PUBLINT_RULE,
  NPM_PRIVATE_RULE,
  NPM_TARGET_LABEL,
  NPM_UNEXPECTED_RULE,
  packOnce,
  publintFinding,
  sanitizeOut,
  tail,
} from "./npmPack.ts";

export { NPM_LIFECYCLE_RULE, NPM_PUBLINT_RULE, NPM_PRIVATE_RULE, NPM_TARGET_LABEL, NPM_UNEXPECTED_RULE };

export type NpmArtifactRecord = {
  /** repo-relative path of the single packed tarball (`.border/dist/<file>`). */
  readonly file: string;
  readonly sha256: string;
  readonly bytes: number;
};

export type NpmStageOptions = {
  readonly repoDir: string;
  readonly cfg: BorderConfig;
  readonly env?: EngineOptions["env"];
  readonly sanitizer?: TextSanitizer;
  readonly skipGitleaks?: boolean;
  readonly skipSecretlint?: boolean;
  readonly secretlintMode?: SecretlintMode;
  readonly npmBinPath?: string;
  readonly publintBinPath?: string;
  /** shared engine/extract timeout; npm/publint have their own knobs. */
  readonly timeoutMs?: number;
  readonly npmTimeoutMs?: number;
  readonly publintTimeoutMs?: number;
};

export type NpmStageResult = {
  readonly findings: readonly Finding[];
  readonly artifact: NpmArtifactRecord | null;
};

function nativeFinding(
  rule: string,
  severity: Severity,
  message: string,
  path: string,
  identity: string,
  sanitizer: TextSanitizer | undefined,
): Finding {
  const digest = redact(identity);
  return {
    rule,
    severity,
    target: NPM_TARGET_LABEL,
    path,
    engine: "native",
    message: sanitizeOut(sanitizer, message),
    valueDigest: digest.valueDigest,
    snippet: digest.snippet,
  };
}

/**
 * GAP B (todo 11 wired into `border check`): re-attribute stage findings from
 * artifact-root-relative (`package/<rel>`, publint's `package.json`) to the
 * exact packed bytes: `<tarball>!<rel>`. The tarball basename never contains a
 * `!` and carries no `.border` segment, so it survives the repo-scoped filter.
 */
export function attributeToTarball(findings: readonly Finding[], artifact: NpmArtifactRecord | null): readonly Finding[] {
  if (artifact === null) return findings;
  const name = artifact.file.slice(artifact.file.lastIndexOf("/") + 1);
  return findings.map((f) => {
    const p = f.path ?? "";
    const rel = p === "package.json" ? p : p.startsWith("package/") ? p.slice("package/".length) : null;
    return rel === null || rel === "" ? f : { ...f, path: `${name}!${rel}` };
  });
}

/** Re-scope engine findings (absolute / `<abs>!<inner>` shapes) to artifact-root-relative. */
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

/**
 * Run the npm artifact stage. Throws EngineMissingError/EngineRunError (exit 2
 * via translateError) for anything that must NOT read as "clean": npm absent,
 * pack failure, unparseable manifests, digest mismatch, unusable publint.
 */
export async function runNpmArtifactStage(o: NpmStageOptions): Promise<NpmStageResult> {
  if (o.cfg.targets.npm === undefined) {
    throw new EngineRunError("runNpmArtifactStage invoked without targets.npm configured — pipeline bug", null);
  }
  const { repoDir } = o;
  const manifestPath = join(repoDir, "package.json");
  if (!existsSync(manifestPath)) {
    throw new EngineRunError("targets.npm is configured but the repo has no package.json to pack", null);
  }
  const manifest = parseNpmManifest(readFileSync(manifestPath, "utf8"));
  const identity = `${manifest.name ?? "?"}@${manifest.version ?? "?"}`;

  if (manifest.isPrivate) {
    return {
      findings: [nativeFinding(
        NPM_PRIVATE_RULE,
        "CRITICAL",
        `package.json is private:true but border.yaml configures targets.npm — nothing can ever publish from this repo; drop the private flag or the npm target`,
        "package.json",
        `${identity}:private`,
        o.sanitizer,
      )],
      artifact: null,
    };
  }

  ensureStateDir(repoDir);
  const stateDir = join(repoDir, BORDER_STATE_DIR);
  const distDir = join(stateDir, "dist");
  mkdirSync(distDir, { recursive: true });
  const { filename, sha256, bytes, tarballAbs } = packOnce({
    repoDir,
    distDir,
    ...(o.env !== undefined ? { env: o.env } : {}),
    ...(o.npmBinPath !== undefined ? { npmBinPath: o.npmBinPath } : {}),
    ...(o.npmTimeoutMs !== undefined ? { npmTimeoutMs: o.npmTimeoutMs } : {}),
  });

  const findings: Finding[] = [];
  const extractDir = join(stateDir, "tmp", sha256.slice(0, 8));
  rmSync(extractDir, { recursive: true, force: true }); // stale sandbox from an interrupted run
  mkdirSync(extractDir, { recursive: true });
  try {
    extractArchive(tarballAbs, extractDir, {
      ...(o.env !== undefined ? { env: o.env } : {}),
      ...(o.timeoutMs !== undefined ? { timeoutMs: o.timeoutMs } : {}),
    });
    const relPaths = listFiles(extractDir).map((p) => relative(extractDir, p));
    if (relPaths.length === 0) throw new EngineRunError("extracted artifact is empty — unusable npm pack output", null);
    const root = relPaths[0]?.split("/")[0] ?? "package";
    if (!relPaths.every((p) => p.startsWith(`${root}/`))) {
      throw new EngineRunError("extracted artifact mixes multiple top-level roots — unexpected tar layout, failing closed", null);
    }
    const packedManifestRel = `${root}/package.json`;
    if (!relPaths.includes(packedManifestRel)) throw new EngineRunError("extracted artifact has no package/package.json", null);
    // lifecycle gate reads the PUBLISHED manifest (the bytes consumers install),
    // not the working tree — npm may rewrite package.json inside the tarball.
    const packedManifest = parseNpmManifest(readFileSync(join(extractDir, packedManifestRel), "utf8"));

    for (const key of LIFECYCLE_SCRIPT_KEYS) {
      const cmd = packedManifest.scripts[key];
      if (cmd === undefined) continue;
      findings.push(nativeFinding(
        NPM_LIFECYCLE_RULE,
        "CRITICAL",
        `package.json script '${key}' is a lifecycle hook — npm executes it on every consumer install (G33): ${tail(sanitizeOut(o.sanitizer, cmd))}`,
        packedManifestRel,
        `${identity}:lifecycle:${key}`,
        o.sanitizer,
      ));
    }
    const entries = relPaths.filter((p) => p !== packedManifestRel).map((p) => p.slice(root.length + 1));
    for (const entry of unexpectedEntries(entries, manifest.files)) {
      findings.push(nativeFinding(
        NPM_UNEXPECTED_RULE,
        "HIGH",
        `packed entry '${entry}' matches no package.json files whitelist pattern and is not an always-packed name — force-packed via main/bin or default inclusion (G39); publish only intentional bytes`,
        `${root}/${entry}`,
        `${identity}:unexpected:${entry}`,
        o.sanitizer,
      ));
    }

    if (o.skipGitleaks !== true) {
      const tree = scanTree({
        dir: extractDir,
        stateDir,
        target: NPM_TARGET_LABEL,
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
        target: NPM_TARGET_LABEL,
        rules: o.cfg.rules,
        ...(o.secretlintMode !== undefined ? { mode: o.secretlintMode } : {}),
        ...(o.env !== undefined ? { env: o.env } : {}),
        ...(o.sanitizer !== undefined ? { sanitizer: o.sanitizer } : {}),
        ...(o.timeoutMs !== undefined ? { timeoutMs: o.timeoutMs } : {}),
      });
      findings.push(...linted);
    }
  } finally {
    removeSandbox(extractDir);
  }

  const publint = publintFinding(
    {
      ...(o.env !== undefined ? { env: o.env } : {}),
      ...(o.publintBinPath !== undefined ? { publintBinPath: o.publintBinPath } : {}),
      ...(o.publintTimeoutMs !== undefined ? { publintTimeoutMs: o.publintTimeoutMs } : {}),
      ...(o.sanitizer !== undefined ? { sanitizer: o.sanitizer } : {}),
    },
    tarballAbs,
    identity,
  );
  if (publint !== null) findings.push(publint);

  return {
    findings,
    artifact: { file: `${BORDER_STATE_DIR}/dist/${filename}`, sha256, bytes },
  };
}
