// provenance: security advisory 2026-10-17 / handoff B0 (reproduced 2026-10-19).
//
// `npm pack --ignore-scripts` is not a portable safety primitive. Measured on
// npm 10.9.7 (the line bundled with Node 22): the target package's `prepare`
// script STILL EXECUTES, even with the flag and even with
// npm_config_ignore_scripts=true. npm 11.19.1 is clean. The ignored hook is
// `prepare`; prepack/postpack stayed silent in the same probe, but they are
// guarded too — the defect is a platform behaviour, and this guard must not
// assume a future npm 10 patch keeps the exact same hole.
//
// border's promise is "it never executes the code it reads" (README). The
// guard is therefore fail-closed: on npm < 11 a package that declares a
// pack-phase hook is refused with a named EngineRunError (exit 2) BEFORE pack
// is spawned. A package with no such hook has nothing for npm to run, so it
// stays scannable on npm 10. The alternative (require npm >= 11 for every npm
// target) would break the Node 22 default install for the common case; the
// hook-presence test is the narrowest condition under which the npm 10 bug can
// fire.
//
// Residual risk, stated rather than hidden: a live process that rewrites
// package.json between this read and the spawn can still race the guard. The
// repo bytes are the audited input; border does not defend against a repo that
// mutates itself while being scanned. Static target bytes are covered.
//
// Scope (sibyl must_fix 2026-10-23: the root-only read missed workspaces):
// every package.json in the tree is scanned, not just the root manifest, and an
// unreadable/unparseable subtree or manifest counts as a hook (unknown is
// never assumed safe). Repo .npmrc needs no probe here: the CLI flag wins the
// config precedence for ignore-scripts, and npm 11 was measured clean even for
// repos shipping one; the measured attack is the npm 10 pack-phase hole this
// guard already refuses.
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

import {
  binaryCandidates,
  EngineMissingError,
  EngineRunError,
  spawnEngine,
  type EngineOptions,
} from "../engines/support.ts";

/** First npm major whose `pack --ignore-scripts` was measured clean. */
export const NPM_SAFE_PACK_MAJOR = 11;

/** Hooks npm may run while packing; guarded conservatively (see header). */
export const NPM_PACK_PHASE_SCRIPTS = ["prepack", "prepare", "postpack"] as const;

export type NpmPackSafety =
  | { readonly ok: true; readonly version: string; readonly major: number }
  | {
      readonly ok: false;
      readonly version: string | null;
      readonly major: number | null;
      readonly reason: string;
    };

const VERSION_TIMEOUT_MS = 10_000;

/** Directory-walk bounds (sibyl must_fix 2026-10-23 scope extension). */
const MANIFEST_SCAN_DEPTH = 6;
const MANIFEST_SCAN_CAP = 200;
/** npm-managed trees pack their own dependency manifests; the pack never
 *  builds them, and walking them is noise and symlink-trap territory. */
const MANIFEST_SCAN_SKIP = new Set(["node_modules", ".git", ".svn", ".hg"]);

function packScriptsOf(manifest: unknown, where: string): string[] {
  if (typeof manifest !== "object" || manifest === null || Array.isArray(manifest)) return [];
  const scripts = (manifest as { scripts?: unknown }).scripts;
  if (typeof scripts !== "object" || scripts === null || Array.isArray(scripts)) return [];
  const record = scripts as Record<string, unknown>;
  return NPM_PACK_PHASE_SCRIPTS.filter((key) => {
    const value = record[key];
    return typeof value === "string" && value.trim() !== "";
  }).map((key) => (where === "package.json" ? key : `${key} (${where})`));
}

function collectManifests(
  dir: string,
  rel: string,
  depth: number,
  out: { dir: string; rel: string }[],
  unreadable: string[],
  cap: number,
): void {
  if (out.length >= cap) {
    unreadable.push(`${rel === "" ? "." : rel}: manifest cap ${String(cap)} reached`);
    return;
  }
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    unreadable.push(rel === "" ? "." : rel);
    return;
  }
  if (entries.some((e) => e.isFile() && e.name === "package.json")) {
    out.push({ dir, rel });
  }
  if (depth >= MANIFEST_SCAN_DEPTH) return;
  for (const e of entries) {
    if (!e.isDirectory() || e.isSymbolicLink() || MANIFEST_SCAN_SKIP.has(e.name)) continue;
    collectManifests(join(dir, e.name), rel === "" ? e.name : `${rel}/${e.name}`, depth + 1, out, unreadable, cap);
  }
}

/**
 * Pack-phase scripts declared anywhere in the repo's working tree — union
 * over every package.json EXCEPT dependency trees (node_modules is not packed
 * nor built by `npm pack`). Unknown is never assumed safe: an unreadable or
 * unparseable manifest counts as a hook, and hitting the walk cap counts too.
 * A hook on the root manifest is labelled bare (`prepare`); a nested one names
 * its manifest (`prepare (packages/child/package.json)`).
 */
export function readNpmPackScripts(repoDir: string): string[] {
  const manifests: { dir: string; rel: string }[] = [];
  const unreadable: string[] = [];
  collectManifests(repoDir, "", 0, manifests, unreadable, MANIFEST_SCAN_CAP);

  const rootPath = join(repoDir, "package.json");
  try {
    // Value re-read by the loop below; this gate only pins the root contract:
    // unreadable/unparseable root = EngineRunError, never a silent [].
    JSON.parse(readFileSync(rootPath, "utf8")) as unknown;
  } catch {
    throw new EngineRunError(`cannot read or parse ${rootPath} to check npm pack hooks — failing closed`, null);
  }

  const found: string[] = [];
  for (const m of manifests) {
    const relPath = m.rel === "" ? "package.json" : `${m.rel}/package.json`;
    let manifest: unknown;
    try {
      manifest = JSON.parse(readFileSync(join(m.dir, "package.json"), "utf8")) as unknown;
    } catch {
      found.push(`${relPath}: unreadable or unparseable`);
      continue;
    }
    found.push(...packScriptsOf(manifest, relPath));
  }
  for (const u of unreadable) found.push(`${u}: manifest tree unreadable`);
  return found;
}

/**
 * Decide whether `npm pack --ignore-scripts` can be trusted for this repo on
 * this machine. Throws EngineMissingError when npm is absent (callers map that
 * to exit 2); every other unsafe state is a typed `ok:false` so the caller can
 * choose throw-vs-skip without a second version probe.
 */
export function npmPackSafety(o: {
  readonly repoDir: string;
  readonly env?: EngineOptions["env"];
  readonly npmBinPath?: string;
  readonly timeoutMs?: number;
}): NpmPackSafety {
  const opts: EngineOptions = {
    timeoutMs: o.timeoutMs ?? VERSION_TIMEOUT_MS,
    ...(o.env !== undefined ? { env: o.env } : {}),
    ...(o.npmBinPath !== undefined ? { binPath: o.npmBinPath } : {}),
  };
  let result;
  try {
    result = spawnEngine(binaryCandidates("npm", opts), ["--version"], opts);
  } catch (err) {
    if (err instanceof EngineMissingError) {
      throw new EngineMissingError(
        "npm-target requires npm — npm must be on PATH (or npmBinPath set); border fails closed",
      );
    }
    throw err;
  }
  const version = result.stdout.trim().split(/\s+/)[0] ?? "";
  const match = /^(\d+)\.\d+\.\d+/.exec(version);
  if (result.status !== 0 || match === null) {
    return {
      ok: false,
      version: version === "" ? null : version,
      major: null,
      reason: `cannot determine npm version (exit ${String(result.status)}, output ${JSON.stringify(version)}) — refusing to pack without the ignore-scripts safety probe`,
    };
  }
  const major = Number(match[1]);
  const hooks = readNpmPackScripts(o.repoDir);
  if (major < NPM_SAFE_PACK_MAJOR && hooks.length > 0) {
    return {
      ok: false,
      version,
      major,
      reason:
        `npm ${version} executes the target package's ${hooks.map((h) => `'${h}'`).join(", ")} ` +
        `hook(s) during 'npm pack --ignore-scripts' (measured on npm 10; fixed in npm 11). ` +
        `border refuses to run code from the repo it audits — install npm >= ${String(NPM_SAFE_PACK_MAJOR)} ` +
        `or remove the pack-phase scripts; failing closed`,
    };
  }
  return { ok: true, version, major };
}
