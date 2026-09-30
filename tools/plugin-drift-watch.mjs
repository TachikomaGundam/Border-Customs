#!/usr/bin/env node
// provenance: 2026-09-24 border-customs impersonation wave, owner option B;
// retired to a thin shell by .omo/plans/border-opencode-inspect.md T4 (0.8.0 wave).
//
// Drift watchdog + purge for opencode's Route-B plugin cache. THE VERDICT
// SINGLE-SOURCE IS NOW `border opencode inspect --json` — this shell owns only
// (a) the aspect -> rc mapping below and (b) the --purge file removal. It
// duplicates no checking logic; inspect itself is pure read-only.
//
// rc mapping (plan B2 — crontab contract, zero changes to the cron line
// `[ $rc -eq 1 ] && purge`; the guard only acts on DRIFT, rc 2 must never
// touch the cache):
//   aspects "cache-version" + "spec-freshness" ONLY (identity/route/scope
//   aspects are deliberately OUT of the purge trigger — an identity FAIL must
//   never wipe the cache):
//     any FAIL                    -> rc 1  DRIFT
//     cache-version CANNOT with detail starting "NOT-CACHED"
//                                 -> rc 0  NOT-CACHED (backward-compat special
//                                    case: the pre-shell script :84/:103 mapped
//                                    NOT-CACHED to 0)
//     any other CANNOT            -> rc 2  CANNOT-ANSWER (registry/parse/config)
//     else                        -> rc 0  FRESH
//
// Binary resolution (plan M4 — `border` is NOT on PATH on this machine):
//   1. BORDER_BIN env var (the cron line may set it; wins alone)
//   2. this repo's absolute dist/index.js
// Accepted-with-a-name consequence: an un-overridden cron run lands on the
// repo dist, i.e. the mutable worktree; the resolved path is reported in the
// JSON output ("bin" field) so each run's landing is recorded as evidence.
//
// Usage: node tools/plugin-drift-watch.mjs [pkg] [--purge] [--json]
//   pkg must be border-customs (default) — inspect audits this gate's own
//   package only; any other name is CANNOT-ANSWER, never a guessed purge.
//   --purge: delete every cache dir for the pkg (next cold start re-fetches)
// Exit codes: 0 fresh/not-cached/(purged) | 1 DRIFT | 2 cannot-answer.
import { execFile } from "node:child_process";
import { existsSync, readdirSync, rmSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const argv = process.argv.slice(2);
const jsonMode = argv.includes("--json");
const purge = argv.includes("--purge");
const pkg = argv.find((a) => !a.startsWith("--")) ?? "border-customs";

const INSPECT_TIMEOUT_MS = 90_000;
const MAPPED_ASPECTS = ["cache-version", "spec-freshness"];

function resolveBin() {
  const configured = process.env["BORDER_BIN"];
  if (configured !== undefined && configured.length > 0) {
    return { bin: configured, prefix: [], label: `BORDER_BIN=${configured}` };
  }
  const repoRoot = fileURLToPath(new URL("..", import.meta.url));
  const dist = join(repoRoot, "dist", "index.js");
  return { bin: process.execPath, prefix: [dist], label: `repo dist under node (${dist})` };
}

function cacheDirs() {
  if (pkg !== "border-customs") return [];
  const root = join(process.env["XDG_CACHE_HOME"] || join(homedir(), ".cache"), "opencode", "packages");
  if (!existsSync(root)) return [];
  return readdirSync(root)
    .filter((d) => d.startsWith(`${pkg}@`))
    .map((d) => join(root, d));
}

function runInspect(resolved) {
  return new Promise((resolve) => {
    execFile(
      resolved.bin,
      [...resolved.prefix, "opencode", "inspect", "--json"],
      { timeout: INSPECT_TIMEOUT_MS, maxBuffer: 1024 * 1024, shell: false },
      (error, stdout) => {
        if (error !== null && (error.code === "ENOENT" || error.code === "EACCES" || error.code === "ENOEXEC")) {
          resolve({ ok: false, why: `could not spawn ${resolved.label} (${String(error.code)})` });
          return;
        }
        try {
          const report = JSON.parse(stdout);
          if (report.schemaVersion !== 1 || !Array.isArray(report.aspects)) {
            resolve({ ok: false, why: `inspect report has an unexpected shape from ${resolved.label}` });
            return;
          }
          resolve({ ok: true, report });
        } catch {
          resolve({ ok: false, why: `no JSON inspect report on stdout from ${resolved.label}` });
        }
      },
    );
  });
}

function mapVerdict(report) {
  const aspects = report.aspects.filter((a) => MAPPED_ASPECTS.includes(a.id));
  if (aspects.length !== MAPPED_ASPECTS.length) {
    return { verdict: "CANNOT-ANSWER", detail: `inspect returned no ${MAPPED_ASPECTS.join("/")} aspect(s) — mapping impossible`, rc: 2 };
  }
  const failed = aspects.filter((a) => a.verdict === "FAIL");
  if (failed.length > 0) {
    return { verdict: "DRIFT", detail: failed.map((a) => `${a.id}: ${a.detail}`).join("; "), rc: 1 };
  }
  const cannot = aspects.filter((a) => a.verdict === "CANNOT");
  if (cannot.length > 0) {
    const notCached = cannot.find((a) => a.id === "cache-version" && typeof a.detail === "string" && a.detail.startsWith("NOT-CACHED"));
    if (notCached !== undefined && cannot.length === 1) {
      return { verdict: "NOT-CACHED", detail: notCached.detail, rc: 0 };
    }
    return { verdict: "CANNOT-ANSWER", detail: cannot.map((a) => `${a.id}: ${a.detail}`).join("; "), rc: 2 };
  }
  return { verdict: "FRESH", detail: aspects.map((a) => a.detail).join("; "), rc: 0 };
}

function report(fields) {
  const out = { ...fields, bin: resolvedLabel };
  if (jsonMode) {
    process.stdout.write(`${JSON.stringify(out)}\n`);
    return;
  }
  const lines = [
    `plugin-drift: ${pkg} (single-source: border opencode inspect --json)`,
    `  cache: ${out.cacheDirs.join(", ") || "(none)"}`,
    `  verdict: ${out.verdict}${out.detail ? ` — ${out.detail}` : ""}`,
  ];
  if (out.purged !== undefined) lines.push(`  purged: ${out.purged.join(", ") || "(nothing)"}`);
  process.stdout.write(`${lines.join("\n")}\n`);
}

const resolved = resolveBin();
const resolvedLabel = resolved.label;

if (pkg !== "border-customs") {
  report({ verdict: "CANNOT-ANSWER", detail: `border opencode inspect audits border-customs only, got pkg '${pkg}'`, cacheDirs: [] });
  process.exitCode = 2;
} else {
  const result = await runInspect(resolved);
  if (!result.ok) {
    report({ verdict: "CANNOT-ANSWER", detail: result.why, cacheDirs: cacheDirs() });
    process.exitCode = 2;
  } else {
    const mapped = mapVerdict(result.report);
    const dirs = cacheDirs();
    if (purge && mapped.rc !== 2) {
      for (const d of dirs) rmSync(d, { recursive: true, force: true });
      report({ verdict: "PURGED (cold start will re-fetch)", detail: mapped.detail, cacheDirs: dirs, purged: dirs, inspectVerdict: result.report.verdict });
      process.exitCode = 0;
    } else {
      report({ verdict: mapped.verdict, detail: mapped.detail, cacheDirs: dirs, purged: undefined, inspectVerdict: result.report.verdict });
      process.exitCode = mapped.rc;
    }
  }
}
