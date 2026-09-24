#!/usr/bin/env node
// provenance: 2026-09-24 border-customs impersonation wave, owner option B.
// Drift watchdog + purge for opencode's Route-B plugin cache.
//
// Why this exists (empirically established 2026-09-24, opencode 1.18.32):
// a dist-tag spec like "pkg@latest" is cached by the SPEC STRING and never
// re-resolved on cold start — the cache stayed on 0.5.0 for 11 days across
// the 0.5.1 security fix. Silent staleness is unacceptable for a gate, so
// the release ritual is: publish -> run this with --purge (or let cron run
// it as a watchdog; drift exits 1 loud). Exact pinning (blueprint §7) stays
// the default recommendation; this tool serves owners who keep @latest and
// accept the purge ritual.
//
// Usage: node tools/plugin-drift-watch.mjs [pkg] [--purge] [--json]
//   pkg default: border-customs
//   --purge: delete every cache dir for pkg (next cold start re-fetches)
// Exit codes: 0 fresh | 1 DRIFT (or stale-not-cached, informational) | 2 cannot-answer.
import { existsSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

const argv = process.argv.slice(2);
const jsonMode = argv.includes("--json");
const purge = argv.includes("--purge");
const pkg = argv.find((a) => !a.startsWith("--")) ?? "border-customs";

function report(fields) {
  if (jsonMode) {
    process.stdout.write(`${JSON.stringify(fields)}\n`);
    return;
  }
  const dirs = fields.cacheDirs ?? [];
  const lines = [
    `plugin-drift: ${fields.pkg ?? pkg}`,
    `  config spec: ${fields.spec ?? "?"}`,
    `  registry version: ${String(fields.registryVersion ?? "?")}`,
    `  cache: ${dirs.map((c) => `${c.dir} -> ${c.version ?? "unreadable"}`).join(", ") || "(none)"}`,
    `  verdict: ${fields.verdict}${fields.detail ? ` — ${fields.detail}` : ""}`,
  ];
  if (fields.purged !== undefined) lines.push(`  purged: ${fields.purged.join(", ") || "(nothing)"}`);
  process.stdout.write(`${lines.join("\n")}\n`);
}

function configSpec() {
  const cfgPath = join(
    process.env["XDG_CONFIG_HOME"] || join(homedir(), ".config"),
    "opencode",
    "opencode.jsonc",
  );
  const text = readFileSync(cfgPath, "utf8");
  const m = text.match(new RegExp(`"${pkg}@([^"]+)"`));
  if (m === null) throw new Error(`${pkg} not declared in ${cfgPath}`);
  return m[1];
}

function cacheDirs() {
  const root = join(process.env["XDG_CACHE_HOME"] || join(homedir(), ".cache"), "opencode", "packages");
  if (!existsSync(root)) return [];
  return readdirSync(root)
    .filter((d) => d === `${pkg}@latest` || d.startsWith(`${pkg}@`))
    .map((d) => {
      const pkgJson = join(root, d, "node_modules", pkg, "package.json");
      let version = null;
      try {
        version = JSON.parse(readFileSync(pkgJson, "utf8")).version ?? null;
      } catch {
        version = null;
      }
      return { dir: join(root, d), version };
    });
}

try {
  const spec = configSpec();
  const res = await fetch(`https://registry.npmjs.org/${encodeURIComponent(pkg)}/${encodeURIComponent(spec)}`, {
    signal: AbortSignal.timeout(15_000),
  });
  if (res.status === 404) throw new Error(`registry has no version for ${pkg}@${spec} (HTTP 404)`);
  if (!res.ok) throw new Error(`registry returned HTTP ${res.status}`);
  const registryVersion = (await res.json()).version ?? null;

  const dirs = cacheDirs();
  const stale = dirs.filter((d) => d.version !== registryVersion);
  let verdict = stale.length === 0 && dirs.length > 0 ? "FRESH" : dirs.length === 0 ? "NOT-CACHED" : "DRIFT";

  let purged;
  if (purge) {
    for (const d of dirs) {
      rmSync(d.dir, { recursive: true, force: true });
    }
    purged = dirs.map((d) => d.dir);
    if (purged.length > 0) verdict = "PURGED (cold start will re-fetch)";
  }

  report({
    spec,
    registryVersion,
    cacheDirs: dirs,
    verdict,
    detail: verdict === "DRIFT" ? `cache holds ${stale.map((d) => d.version).join(",")}, registry serves ${registryVersion}` : undefined,
    purged,
  });
  process.exitCode = purge ? 0 : verdict === "DRIFT" ? 1 : 0;
} catch (error) {
  report({ verdict: "CANNOT-ANSWER", detail: String(error instanceof Error ? error.message : error) });
  process.exitCode = 2;
}
