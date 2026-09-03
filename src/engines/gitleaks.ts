// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 4
//
// Gitleaks 8.30.1 adapter. Empirical contract (spike in ADAPTER-CONTRACT.md):
//   - history leg: `gitleaks git <repo> --log-opts "<range>"` reports secrets
//     from commits unreachable at HEAD, carrying the full leaking sha in .Commit;
//   - dir leg requires `--max-archive-depth 2` (default 0 = no archive entry)
//     and natively reads .tar.gz/.zip/.tar/.gz/.tar.bz2 but NOT .tgz —
//     scanTree() extracts .tgz via src/artifacts/extract.ts and reattributes
//     findings to `<archive>!<inner>` paths;
//   - `-f json --report-path -` is the ONLY stdout report mechanism; the
//     report is parsed from the pipe in-memory and never touches disk;
//   - exit 0 ⇒ clean, 1 ⇒ findings, ANYTHING else (incl. 126 usage error)
//     ⇒ EngineRunError (border exit 2), never "clean";
//   - a repo-committed .gitleaksignore is obeyed UNCONDITIONALLY even with an
//     empty -i file (1→0 findings in the spike), so detectHostileConfig()
//     turns its mere presence in the HEAD tree into a CRITICAL finding;
//   - the vendored --config explicitly replaces target-repo auto-discovered
//     .gitleaks.toml (a committed rules=[] config no longer silences scans).
// G23: no --redact (it would collapse valueDigest to sha256("REDACTED")); raw
// Secret/Match values stay process-memory only — every finding is ingested
// through redact(), and the optional TextSanitizer keeps the raw values for
// free-text scrubbing during the process lifetime only.
import { existsSync, mkdirSync, mkdtempSync, rmdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { extractArchive, findNativeMissArchives, removeSandbox } from "../artifacts/extract.ts";
import type { Finding } from "../findings.ts";
import { redact, type TextSanitizer } from "../redact.ts";
import {
  binaryCandidates,
  EngineRunError,
  spawnEngine,
  stripEngineEnv,
  type EngineOptions,
} from "./support.ts";

export { EngineMissingError, EngineRunError as GitleaksRunError } from "./support.ts";

export const GITLEAKS_VENDORED_CONFIG = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "assets",
  "gitleaks-defaults-v8.30.1.toml",
);

export const HOSTILE_CONFIG_RULE = "repo-self-ignores-findings";
const HOSTILE_CONFIG_BASENAMES = new Set([".gitleaksignore", ".gitleaks.toml"]);
const ARCHIVE_DEPTH = "2";

export type ScanOptions = EngineOptions & {
  /** Finding.target label chosen by the caller (e.g. "git", "tree", "artifact"). */
  target: string;
  /** Optional G23 scrubbing registry receiving every matched raw value. */
  sanitizer?: TextSanitizer;
};
export type GitScanOptions = ScanOptions & { repoDir: string; refRange?: string };
export type TreeScanOptions = ScanOptions & { dir: string; stateDir?: string };
export type HostileConfigOptions = EngineOptions & { repoDir: string; target?: string };

function requireString(value: unknown, field: string): string {
  if (typeof value !== "string") {
    throw new EngineRunError(`gitleaks report entry lacks string field '${field}'`, null);
  }
  return value;
}

function toFinding(raw: unknown, o: ScanOptions): Finding {
  if (typeof raw !== "object" || raw === null) {
    throw new EngineRunError("gitleaks report entry is not an object", null);
  }
  const r = raw as Record<string, unknown>;
  const rule = requireString(r.RuleID, "RuleID");
  const path = requireString(r.File, "File");
  const description = typeof r.Description === "string" && r.Description !== "" ? r.Description : rule;
  const secret = typeof r.Secret === "string" ? r.Secret : "";
  const match = typeof r.Match === "string" ? r.Match : "";
  const value = secret !== "" ? secret : match;
  const { valueDigest, snippet } = redact(value);
  if (value !== "") o.sanitizer?.register(valueDigest, value);
  const commit = typeof r.Commit === "string" && r.Commit !== "" ? r.Commit : undefined;
  const line = typeof r.StartLine === "number" && Number.isInteger(r.StartLine) ? r.StartLine : undefined;
  return {
    rule,
    severity: "CRITICAL",
    target: o.target,
    path,
    engine: "gitleaks",
    message: description,
    valueDigest,
    snippet,
    ...(line !== undefined ? { line } : {}),
    ...(commit !== undefined ? { commit } : {}),
  };
}

/** Exit translation + stdout-report-only ingestion (never an on-disk report). */
function runGitleaks(args: readonly string[], o: EngineOptions): string {
  if (!existsSync(GITLEAKS_VENDORED_CONFIG)) {
    throw new EngineRunError(`vendored gitleaks config missing: ${GITLEAKS_VENDORED_CONFIG}`, null);
  }
  const result = spawnEngine(binaryCandidates("gitleaks", o), args, {
    ...o,
    env: stripEngineEnv(o.env ?? process.env),
  });
  if (result.status === 0 || result.status === 1) return result.stdout;
  const stderrTail = result.stderr.trim().slice(-400);
  throw new EngineRunError(
    `gitleaks exited ${String(result.status)}; only 0 (clean) and 1 (findings) are translatable — any other code (incl. 126 usage error) is a border exit-2 tool failure. stderr: ${stderrTail}`,
    result.status,
  );
}

function parseFindings(stdout: string, o: ScanOptions): Finding[] {
  const trimmed = stdout.trim();
  if (trimmed === "" || trimmed === "[]") return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    throw new EngineRunError("gitleaks exited with an unparseable JSON report on stdout", null);
  }
  if (!Array.isArray(parsed)) {
    throw new EngineRunError("gitleaks JSON report is not an array", null);
  }
  return parsed.map((entry) => toFinding(entry, o));
}

function baseArgs(ignorePath: string): string[] {
  return [
    "--no-banner",
    "-f",
    "json",
    "--report-path",
    "-",
    "--config",
    GITLEAKS_VENDORED_CONFIG,
    "--gitleaks-ignore-path",
    ignorePath,
  ];
}

/**
 * Both legs ALWAYS pass an empty --gitleaks-ignore-path file plus the vendored
 * config: the empty file opts out of the engine walking up to a stray
 * .gitleaksignore relative to cwd; hostile repo-committed ones are handled by
 * detectHostileConfig(), never by flags. The temp file is empty and removed
 * in the finally — it carries no secret bytes.
 */
function withEmptyIgnoreFile<T>(fn: (ignorePath: string) => T): T {
  const dir = mkdtempSync(join(tmpdir(), "border-gitleaks-ignore-"));
  const file = join(dir, ".gitleaksignore");
  writeFileSync(file, "");
  try {
    return fn(file);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function scanDirLeg(dir: string, ignorePath: string, o: ScanOptions): Finding[] {
  const stdout = runGitleaks(["dir", dir, "--max-archive-depth", ARCHIVE_DEPTH, ...baseArgs(ignorePath)], o);
  return parseFindings(stdout, o);
}

/** History leg over `repoDir` (the .git store is read by gitleaks itself; border never scans .git as a tree). */
export function scanGitHistory(o: GitScanOptions): Finding[] {
  const repoDir = resolve(o.repoDir);
  return withEmptyIgnoreFile((ignorePath) => {
    const logOpts = o.refRange !== undefined && o.refRange !== "" ? [`--log-opts=${o.refRange}`] : [];
    const stdout = runGitleaks(["git", repoDir, ...logOpts, ...baseArgs(ignorePath)], o);
    return parseFindings(stdout, o);
  });
}

/**
 * Tree/artifact leg. `.tgz` archives (spike-proven native MISS, the npm-pack
 * format) are extracted one-by-one into `<stateDir>/tmp/` and scanned there;
 * findings are reattributed to `<archive>!<inner>` so no sandbox path ever
 * leaks into a Finding. Sandboxes are removed on BOTH paths; the tmp root is
 * only pruned when empty (a sibling border run may share it).
 */
export function scanTree(o: TreeScanOptions): Finding[] {
  const dir = resolve(o.dir);
  const stateDir = o.stateDir !== undefined ? resolve(o.stateDir) : join(dir, ".border");
  const archives = findNativeMissArchives(dir);
  return withEmptyIgnoreFile((ignorePath) => {
    const findings = scanDirLeg(dir, ignorePath, o);
    if (archives.length === 0) return findings;
    const tmpRoot = join(stateDir, "tmp");
    mkdirSync(tmpRoot, { recursive: true });
    try {
      for (const archive of archives) {
        const dest = mkdtempSync(join(tmpRoot, "extract-"));
        try {
          extractArchive(archive, dest, o);
          for (const f of scanDirLeg(dest, ignorePath, o)) {
            findings.push(reattributeToArchive(f, archive, dest));
          }
        } finally {
          removeSandbox(dest);
        }
      }
    } finally {
      try {
        rmdirSync(tmpRoot);
      } catch {
        // non-empty: a concurrent run owns sandboxes inside — todo 10 GCs .border/tmp
      }
    }
    return findings;
  });
}

function reattributeToArchive(f: Finding, archive: string, extractDir: string): Finding {
  const inner = f.path !== undefined ? relative(extractDir, f.path) : "";
  const path = f.path !== undefined && !inner.startsWith("..") ? `${archive}!${inner}` : f.path;
  return { ...f, ...(path !== undefined ? { path } : {}) };
}

/**
 * Hostile-config detector — MUST run before trusting any scan of `repoDir`.
 * Existence (any depth) of .gitleaksignore/.gitleaks.toml in the HEAD tree is
 * itself the CRITICAL finding: the engine would silently obey it (spike), and
 * a refuse-to-trust posture is the only fail-closed option. Path + HEAD sha
 * are named so the finding is actionable.
 */
export function detectHostileConfig(o: HostileConfigOptions): Finding[] {
  const head = runGit(o.repoDir, ["rev-parse", "HEAD"], o).trim();
  const listing = runGit(o.repoDir, ["ls-tree", "-r", "HEAD", "--name-only"], o);
  const target = o.target ?? "git";
  const findings: Finding[] = [];
  for (const tracked of listing.split("\n")) {
    if (tracked === "") continue;
    const base = tracked.slice(tracked.lastIndexOf("/") + 1);
    if (!HOSTILE_CONFIG_BASENAMES.has(base)) continue;
    findings.push({
      rule: HOSTILE_CONFIG_RULE,
      severity: "CRITICAL",
      target,
      path: tracked,
      commit: head,
      engine: "gitleaks",
      message:
        `HEAD ${head.slice(0, 12)} tracks '${tracked}': gitleaks obeys repo-committed ignore/rules files, ` +
        "so the repository could silently disable the secret gate. border refuses to trust it " +
        "(vendored --config and an empty --gitleaks-ignore-path are forced; remove the file).",
      valueDigest: redact(`${head}:${tracked}`).valueDigest,
      snippet: tracked,
    });
  }
  return findings;
}

function runGit(repoDir: string, args: readonly string[], o: EngineOptions): string {
  const result = spawnEngine(binaryCandidates("git", o), ["-C", resolve(repoDir), ...args], { ...o });
  if (result.status !== 0) {
    throw new EngineRunError(
      `git ${args.join(" ")} in ${repoDir} exited ${String(result.status)}: ${result.stderr.trim().slice(-200)}`,
      result.status,
    );
  }
  return result.stdout;
}

/** `gitleaks --version` string for the G21 rulesHash engineVersions map. */
export function gitleaksVersion(o: EngineOptions = {}): string {
  const result = spawnEngine(binaryCandidates("gitleaks", o), ["--version"], {
    ...o,
    env: stripEngineEnv(o.env ?? process.env),
  });
  if (result.status !== 0) {
    throw new EngineRunError(`gitleaks --version exited ${String(result.status)}`, result.status);
  }
  return result.stdout.trim();
}
