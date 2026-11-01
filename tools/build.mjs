#!/usr/bin/env node
// Bundles border with its build identity baked in (provenance wave, 2026-10-23).
//
// The owner-machine consumption audit showed every gate verdict on this machine
// was produced by an UNPINNED worktree build (`node <sibling-repo>/dist/index.js`)
// with nothing on the record naming the code that decided it. Fix: the bundle
// carries {version, commit, dirty, builtAt}; every check/push record and
// `border --version` echo it. Unpinned use becomes visible on the record face.
//
// Usage: node tools/build.mjs [--outfile <path>]   (default dist/index.js)
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import * as esbuild from "esbuild";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function git(args) {
  const r = spawnSync("git", ["-C", repoRoot, ...args], { encoding: "utf8" });
  return r.status === 0 ? r.stdout.trim() : "";
}

const pkg = JSON.parse(readFileSync(join(repoRoot, "package.json"), "utf8"));
const commit = git(["rev-parse", "HEAD"]);
const stamp = {
  version: pkg.version,
  commit: commit === "" ? "unknown" : commit,
  dirty: commit === "" ? false : git(["status", "--porcelain"]) !== "",
  builtAt: new Date().toISOString(),
};

const eqArg = process.argv.find((a) => a.startsWith("--outfile="));
const spaceIdx = process.argv.indexOf("--outfile");
const rawOut = eqArg?.slice("--outfile=".length) ?? (spaceIdx === -1 ? undefined : process.argv[spaceIdx + 1]);
const unknown = process.argv.slice(2).filter((a) => a !== "--outfile" && !a.startsWith("--outfile=") && a !== rawOut);
if (unknown.length > 0) {
  console.error(`build.mjs: unknown argument(s): ${unknown.join(" ")} (usage: node tools/build.mjs [--outfile <path>])`);
  process.exit(2);
}
const outfile = rawOut === undefined ? join(repoRoot, "dist", "index.js") : resolve(repoRoot, rawOut);

await esbuild.build({
  entryPoints: [join(repoRoot, "src", "index.ts")],
  bundle: true,
  format: "esm",
  platform: "node",
  external: ["typescript"],
  banner: {
    js: 'import{createRequire as __borderRequire}from"node:module";const require=__borderRequire(import.meta.url);',
  },
  define: { __BORDER_BUILD__: JSON.stringify(stamp) },
  outfile,
});

const assetsDir = join(dirname(outfile), "assets");
const copy = spawnSync(process.execPath, [join(repoRoot, "tools", "copy-assets.mjs"), assetsDir], {
  stdio: "inherit",
  cwd: repoRoot,
});
if (copy.status !== 0) process.exit(copy.status ?? 1);
console.log(`build: ${outfile} stamped ${stamp.version}+${stamp.commit.slice(0, 7)}${stamp.dirty ? " (dirty)" : ""}`);
