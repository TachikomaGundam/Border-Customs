// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 4
//
// Archive-extraction shim for formats the gitleaks 8.30.1 `dir` leg provably
// misses. Spike evidence (ADAPTER-CONTRACT.md): archive dispatch in 8.30.1 is
// extension-based, NOT magic-based — `.tgz` (the `npm pack` format) and any
// unknown-extension archive yield 0 findings, while `.tar.gz`, `.zip`, `.tar`,
// `.gz` and `.tar.bz2` are scanned natively. Only the native-miss formats are
// extracted here; extracted trees are temporary and always removed.
import { spawnSync } from "node:child_process";
import { readdirSync, rmSync } from "node:fs";
import { join } from "node:path";

import { type EngineOptions, engineErrorFromSpawn } from "../engines/support.ts";

/** Extensions gitleaks `dir --max-archive-depth 2` does NOT read (spike-proven). */
const NATIVE_MISS_EXTENSIONS = [".tgz"] as const;

/** Directories never descended into when hunting for miss-format archives. */
const SKIP_DIRECTORIES = new Set([".git", ".border"]);

export function findNativeMissArchives(dir: string): string[] {
  const found: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (!SKIP_DIRECTORIES.has(entry.name)) found.push(...findNativeMissArchives(join(dir, entry.name)));
    } else if (entry.isFile() && NATIVE_MISS_EXTENSIONS.some((ext) => entry.name.toLowerCase().endsWith(ext))) {
      found.push(join(dir, entry.name));
    }
  }
  return found.sort();
}

/**
 * Extract one native-miss archive into `destDir` (caller-owned temp path,
 * created by the caller). Dispatch is by extension; `.tgz` uses `tar -xzf`.
 * A missing `tar` binary is EngineMissing (fail closed, never "clean").
 */
export function extractArchive(archivePath: string, destDir: string, opts: EngineOptions = {}): void {
  const lower = archivePath.toLowerCase();
  let argv: readonly string[];
  if (lower.endsWith(".tgz") || lower.endsWith(".tar.gz")) {
    argv = ["tar", "-xzf", archivePath, "-C", destDir];
  } else {
    throw new Error(`extractArchive: unsupported native-miss format: ${archivePath}`);
  }
  const [bin, ...rest] = argv;
  const result = spawnSync(bin as string, [...rest], { encoding: "utf8", timeout: opts.timeoutMs ?? 120_000 });
  if (result.error !== undefined) {
    throw engineErrorFromSpawn(result.error, bin as string);
  }
  if (result.status !== 0) {
    throw new Error(`failed to extract ${archivePath} (exit ${String(result.status)}): ${(result.stderr ?? "").trim()}`);
  }
}

/** Remove an extraction sandbox tree. Idempotent; used on BOTH success and failure paths. */
export function removeSandbox(dir: string): void {
  rmSync(dir, { recursive: true, force: true });
}
