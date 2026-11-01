// Build identity (provenance wave, 2026-10-23).
//
// Invariant: a verdict is attributable. Every check/push record and
// `border --version` names the exact code that decided it — the HR decoupling
// audit showed a whole machine running gates off an unpinned worktree bundle
// with nothing on disk saying which commit produced a PASS.
//
// Two supply modes:
//  - bundle: tools/build.mjs bakes __BORDER_BUILD__ via esbuild --define;
//  - source (tests via the ts loader, or a bare checkout): resolved at call
//    time from border's OWN repo — package.json version + git HEAD + dirty.
// Resolution never throws and is cached per process; "unknown" is honest for
// an unpacked tree with no git, and it still prints on the record face.
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export type BuildStamp = {
  readonly version: string;
  readonly commit: string;
  readonly dirty: boolean;
  readonly builtAt: string;
};

declare const __BORDER_BUILD__: BuildStamp | undefined;

function git(cwd: string, args: readonly string[]): string {
  try {
    const r = spawnSync("git", ["-C", cwd, ...args], { encoding: "utf8", timeout: 5_000 });
    return r.status === 0 ? r.stdout.trim() : "";
  } catch {
    return "";
  }
}

function sourceStamp(): BuildStamp {
  // src/buildInfo.ts (source run) and dist/index.js (unbaked bundle) both sit
  // one level below the package root.
  const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
  let version = "unknown";
  try {
    version = (JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as { version?: string }).version ?? "unknown";
  } catch {
    // fall through honest
  }
  const commit = git(root, ["rev-parse", "HEAD"]);
  return {
    version,
    commit: commit === "" ? "unknown" : commit,
    dirty: commit !== "" && git(root, ["status", "--porcelain"]) !== "",
    builtAt: "source",
  };
}

let cached: BuildStamp | undefined;

export function buildStamp(): BuildStamp {
  if (cached !== undefined) return cached;
  const baked = typeof __BORDER_BUILD__ === "undefined" ? undefined : __BORDER_BUILD__;
  cached = baked !== undefined && typeof baked === "object" ? baked : sourceStamp();
  return cached;
}

/** Compact stamp for records and --version: `<version>+<commit>[.dirty]`. */
export function engineBuild(): string {
  const s = buildStamp();
  return `${s.version}+${s.commit}${s.dirty ? ".dirty" : ""}`;
}
