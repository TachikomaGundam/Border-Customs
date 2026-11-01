#!/usr/bin/env node
// Platform-behavior probe (roadmap W6, 2026-10-23 audit item "no platform
// probes"): npmPackSafety.ts encodes a MEASURED npm behavior — npm <= 10
// executes a repo's `prepare` hook during `npm pack --ignore-scripts`; npm 11
// does not. Platform facts expire. This probe re-measures the fact on the
// CURRENT npm and fails the build when the encoded premise is violated, so CI
// — not a victim machine — discovers the drift.
// Exit codes: 0 premise holds (npm >= 11 non-execution, or either branch on
// npm < 11 where the guard fires regardless of execution); 1 premise broken
// (npm >= 11 EXECUTED the hook — the guard's safe-side claim is now false).
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const versionProbe = spawnSync("npm", ["--version"], { encoding: "utf8", timeout: 60_000 });
const npmVersion = (versionProbe.stdout ?? "").trim();
const major = Number(/^(\d+)\./.exec(npmVersion)?.[1] ?? NaN);
if (versionProbe.status !== 0 || !Number.isInteger(major)) {
  console.error(`probe-npm-pack: cannot determine npm version (exit ${String(versionProbe.status)}, output ${JSON.stringify(npmVersion)}) — failing closed`);
  process.exit(1);
}

const dir = mkdtempSync(join(tmpdir(), "border-pack-probe-"));
try {
  const repo = join(dir, "repo");
  const out = join(dir, "out");
  const marker = join(repo, "HOOK-RAN");
  mkdirSync(repo, { recursive: true });
  mkdirSync(out, { recursive: true });
  // The marker path arrives via env, NOT shell/JS string nesting: quote
  // characters in temp paths must never decide what the probe executes.
  writeFileSync(
    join(repo, "package.json"),
    JSON.stringify({
      name: "border-pack-probe",
      version: "1.0.0",
      scripts: { prepare: 'node -e "require(\'fs\').writeFileSync(process.env.BORDER_PROBE_MARKER, \'x\')"' },
    }),
  );
  const r = spawnSync("npm", ["pack", repo, "--ignore-scripts", "--pack-destination", out], {
    encoding: "utf8",
    timeout: 120_000,
    env: { ...process.env, BORDER_PROBE_MARKER: marker },
  });
  const executed = existsSync(marker);
  if (r.error !== undefined) {
    console.error(`probe-npm-pack: npm pack spawn failed (${r.error.message}) — failing closed`);
    process.exit(1);
  }
  const line = `probe-npm-pack: npm ${npmVersion} pack --ignore-scripts executed prepare=${String(executed)} (pack exit ${String(r.status)})`;
  if (major >= 11 && executed) {
    console.error(`${line} — PREMISE BROKEN: npmPackSafety declares npm >= 11 clean; re-derive the guard (and this probe) before shipping`);
    process.exit(1);
  }
  if (major < 11) {
    console.log(`${line} — npm<11 line; the hook-presence guard ${executed ? "is load-bearing here" : "stays conservative on this patch (the guard never relies on the flag holding)"}`);
  } else {
    console.log(`${line} — matches the encoded premise`);
  }
} finally {
  rmSync(dir, { recursive: true, force: true });
}
