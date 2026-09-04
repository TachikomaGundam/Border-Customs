// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 11
//
// Tool-invocation layer of the npm artifact stage: the single `npm pack`
// (G38 pack-once) and the publint gate. Every failure here throws typed
// (EngineMissingError/EngineRunError → exit 2 via translateError); nothing
// may read as a silent pass. Kept apart from the scan/findings orchestration
// in npm.ts so each module stays single-purpose.
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import type { Finding } from "../findings.ts";
import { redact, type TextSanitizer } from "../redact.ts";
import {
  binaryCandidates,
  EngineMissingError,
  EngineRunError,
  spawnEngine,
  type EngineOptions,
} from "../engines/support.ts";
import { parsePackReport } from "./manifestDiff.ts";

export const NPM_PRIVATE_RULE = "npm-target-but-private";
export const NPM_UNEXPECTED_RULE = "artifact-unexpected-file";
export const NPM_LIFECYCLE_RULE = "lifecycle-script";
export const NPM_PUBLINT_RULE = "publint-fail";
export const NPM_TARGET_LABEL = "artifact";

const DEFAULT_TOOL_TIMEOUT_MS = 120_000;
const MESSAGE_TAIL_CHARS = 600;
/** repo root as seen from src/artifacts/ or dist/ — same convention as the secretlint adapter's node_modules/.bin lookup. */
const PACKAGE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

export function tail(text: string): string {
  const trimmed = text.trim();
  return trimmed.length > MESSAGE_TAIL_CHARS ? `${trimmed.slice(-MESSAGE_TAIL_CHARS)}…` : trimmed;
}

export function sanitizeOut(sanitizer: TextSanitizer | undefined, text: string): string {
  return sanitizer?.sanitize(text) ?? text;
}

export type PackOutcome = {
  readonly filename: string;
  readonly sha256: string;
  readonly bytes: number;
  readonly tarballAbs: string;
};

export type PackToolOptions = {
  readonly repoDir: string;
  readonly distDir: string;
  readonly env?: EngineOptions["env"];
  readonly npmBinPath?: string;
  readonly npmTimeoutMs?: number;
};

/**
 * One `npm pack` into distDir — `--ignore-scripts` so the TARGET REPO's hooks
 * never execute (G33 defense-in-depth) and `--json` so the report's shasum/size
 * are cross-checked against the actual bytes before anything trusts them.
 */
export function packOnce(o: PackToolOptions): PackOutcome {
  const opts: EngineOptions = {
    timeoutMs: o.npmTimeoutMs ?? DEFAULT_TOOL_TIMEOUT_MS,
    ...(o.env !== undefined ? { env: o.env } : {}),
    ...(o.npmBinPath !== undefined ? { binPath: o.npmBinPath } : {}),
  };
  let result;
  try {
    result = spawnEngine(
      binaryCandidates("npm", opts),
      ["pack", o.repoDir, "--ignore-scripts", "--json", "--pack-destination", o.distDir],
      opts,
    );
  } catch (err) {
    if (err instanceof EngineMissingError) {
      throw new EngineMissingError("npm-target requires npm — npm must be on PATH (or npmBinPath set); border fails closed");
    }
    throw err;
  }
  if (result.status !== 0) {
    throw new EngineRunError(`npm pack failed (exit ${String(result.status)}): ${tail(result.stderr)}`, result.status);
  }
  const report = parsePackReport(result.stdout);
  const tarballAbs = join(o.distDir, report.filename);
  if (!existsSync(tarballAbs)) {
    throw new EngineRunError(`npm pack reported '${report.filename}' but no tarball landed in ${o.distDir}`, null);
  }
  const data = readFileSync(tarballAbs);
  const sha256 = createHash("sha256").update(data).digest("hex");
  const sha1 = createHash("sha1").update(data).digest("hex");
  if (sha1 !== report.shasum || data.byteLength !== report.size) {
    throw new EngineRunError(`npm pack report disagrees with the tarball bytes for ${report.filename} — corrupted or swapped artifact, failing closed`, null);
  }
  return { filename: report.filename, sha256, bytes: data.byteLength, tarballAbs };
}

/** publint against the TARBALL itself (never the working tree). exit 0 clean, 1 ⇒ finding, else tool error. */
export function publintFinding(
  o: { env?: EngineOptions["env"]; publintBinPath?: string; publintTimeoutMs?: number; sanitizer?: TextSanitizer },
  tarballAbs: string,
  identity: string,
): Finding | null {
  const candidates = o.publintBinPath !== undefined
    ? [o.publintBinPath]
    : [
        join(PACKAGE_ROOT, "node_modules", ".bin", "publint"),
        ...binaryCandidates("publint", o.env !== undefined ? { env: o.env } : {}),
      ];
  const result = spawnEngine(candidates, [tarballAbs, "--level", "error"], {
    timeoutMs: o.publintTimeoutMs ?? DEFAULT_TOOL_TIMEOUT_MS,
    ...(o.env !== undefined ? { env: o.env } : {}),
  });
  if (result.status === 0) return null;
  if (result.status !== 1) {
    throw new EngineRunError(`publint exited ${String(result.status)} (only 0/1 are translatable): ${tail(result.stderr)}`, result.status);
  }
  const digest = redact(`${identity}:publint`);
  return {
    rule: NPM_PUBLINT_RULE,
    severity: "HIGH",
    target: NPM_TARGET_LABEL,
    path: "package.json",
    engine: "native",
    message: `publint --level error flagged the packed artifact:\n${tail(sanitizeOut(o.sanitizer, [result.stdout, result.stderr].filter((s) => s.trim() !== "").join("\n")))}`,
    valueDigest: digest.valueDigest,
    snippet: digest.snippet,
  };
}
