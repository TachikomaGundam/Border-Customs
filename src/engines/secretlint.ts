// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 5
//
// secretlint adapter. DEFAULT MODE: in-process @secretlint/core 13.0.5
// (lintSource), API contract spike-verified in tools/spike-secretlint.mjs —
// the fact table lives in src/engines/ADAPTER-CONTRACT.md. A pinned CLI
// fallback (node_modules/.bin/secretlint --format json --secretlintrcJSON
// <inline> --no-gitignore --no-glob <explicit files>) is selectable via
// `mode: "cli"`; both modes normalize into the SAME Finding pipeline, so
// callers (todo 6 orchestrator, todos 11/12 artifact scans) never learn
// which transport ran.
//
// Rule set: preset-recommend (with enableIDScanRule:true — upstream DEFAULTS
// IT FALSE, see contract) + no-homedir + no-dotenv + generated border
// pattern rules from border.yaml rules.hosts/ips/pathPatterns (always
// regex-escaped — literals stay literals) plus BUILT-IN DEFAULT path patterns
// covering Windows/UNC/drive-letter AND POSIX homes (G40: no-homedir only
// knows the running user's $HOME and misses `C:\Users\…`).
//
// G23: secretlint messages ECHO the matched value verbatim
// ("found AWS Access Key ID: AKIA…"). Every raw value is sliced from the
// in-memory source, routed through redact(), registered with the optional
// TextSanitizer, and stripped out of Finding.message before return. Nothing
// engine-shaped ever touches disk.
import { createHash } from "node:crypto";
import { existsSync, readFileSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { lintSource } from "@secretlint/core";
import { creator as noDotenvCreator } from "@secretlint/secretlint-rule-no-dotenv";
import { creator as noHomedirCreator } from "@secretlint/secretlint-rule-no-homedir";
import { creator as patternCreator, type PatternType } from "@secretlint/secretlint-rule-pattern";
import { creator as presetRecommendCreator } from "@secretlint/secretlint-rule-preset-recommend";
import type { SecretLintCoreConfig, SecretLintCoreResultMessage } from "@secretlint/types";

import { type Finding } from "../findings.ts";
import { redact, type TextSanitizer } from "../redact.ts";
import {
  binaryCandidates,
  EngineRunError,
  spawnEngine,
  type EngineOptions,
} from "./support.ts";

export { EngineMissingError, EngineRunError as SecretlintRunError } from "./support.ts";

export const SECRETLINT_ENGINE = "secretlint" as const;

const PRESET_ID = "@secretlint/secretlint-rule-preset-recommend";
const HOMEDIR_ID = "@secretlint/secretlint-rule-no-homedir";
const DOTENV_ID = "@secretlint/secretlint-rule-no-dotenv";
const PATTERN_RULE_ID = "border-pattern";
/** Package identity — what the CLI loader reports as ruleId (meta id), vs our in-process config alias. */
const PATTERN_PKG_ID = "@secretlint/secretlint-rule-pattern";
const AWS_RULE_ID = "@secretlint/secretlint-rule-aws";
/** CLI argv per spawn — keeps long file lists under ARG_MAX. */
const CLI_CHUNK_FILES = 200;
/** Beyond this a "match" is a file-level report, not a credential; never digest megabytes. */
const MAX_VALUE_CHARS = 1024;

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

export type SecretlintRulesInput = {
  readonly hosts?: readonly string[];
  readonly ips?: readonly string[];
  readonly pathPatterns?: readonly string[];
};

export type SecretlintMode = "in-process" | "cli";

export type SecretlintScanOptions = EngineOptions & {
  /** Finding.target stamp — "git" | "tree" | "artifact" per orchestrator leg. */
  target: string;
  /** Transport. Default "in-process"; "cli" exercises the pinned CLI fallback. */
  mode?: SecretlintMode;
  /** border.yaml rules.hosts/ips/pathPatterns (strings treated as LITERALS). */
  rules?: SecretlintRulesInput;
  sanitizer?: TextSanitizer;
};

export type TrackedScanOptions = SecretlintScanOptions & { repoDir: string };
export type PathsScanOptions = SecretlintScanOptions & {
  dir: string;
  /** Explicit file list, relative to `dir` (artifact dirs come from todos 11/12). */
  files: readonly string[];
};

/**
 * BUILT-IN default path patterns — REGEX SOURCES (border-authored, unlike
 * config strings which are escaped literals). G40: Windows homes and UNC
 * paths are invisible to no-homedir; POSIX homes are matched literally.
 */
export const DEFAULT_PATH_PATTERNS: readonly string[] = [
  "/home/[a-z]+/",
  "/Users/[a-z]+/",
  String.raw`C:\\Users\\\w+`, // C:\Users\<name>
  String.raw`[A-Za-z]:\\`, // <drive>:\ roots
  String.raw`\\\\[^\\]+\\`, // UNC \\server\
];

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

type GeneratedPattern = { readonly name: string; readonly source: string; readonly regex: RegExp };

function makePattern(name: string, source: string, literal: boolean, compiled: GeneratedPattern[]): PatternType {
  const src = literal ? escapeRegex(source) : source;
  if (src.length === 0) {
    throw new EngineRunError(`secretlint pattern '${name}': empty pattern string; border fails closed`, null);
  }
  try {
    // Mirror @textlint/regexp-string-matcher's compile (flags "ug") so an
    // uncompilable literal fails HERE with the offending name, not deep
    // inside the engine.
    compiled.push({ name, source: src, regex: new RegExp(src, "ug") });
  } catch (error) {
    throw new EngineRunError(
      `secretlint pattern '${name}' does not compile as a unicode regex: ${String(error)}`,
      null,
    );
  }
  // Slash-wrap => matcher parses it as a regex literal with OUR source,
  // bypassing its auto-escape guess on bare strings (spike-verified).
  return { name, patterns: [`/${src}/`] };
}

function generatePatterns(rules: SecretlintRulesInput | undefined): {
  readonly optionPatterns: PatternType[];
  readonly compiled: GeneratedPattern[];
} {
  const optionPatterns: PatternType[] = [];
  const compiled: GeneratedPattern[] = [];
  for (const host of rules?.hosts ?? []) optionPatterns.push(makePattern(`internal-host:${host}`, host, true, compiled));
  for (const ip of rules?.ips ?? []) optionPatterns.push(makePattern(`internal-ip:${ip}`, ip, true, compiled));
  for (const pp of rules?.pathPatterns ?? []) optionPatterns.push(makePattern(`path-pattern:${pp}`, pp, true, compiled));
  for (const dflt of DEFAULT_PATH_PATTERNS) optionPatterns.push(makePattern(`path-pattern:${dflt}`, dflt, false, compiled));
  return { optionPatterns, compiled };
}

const AWS_OVERRIDE = [{ id: AWS_RULE_ID, options: { enableIDScanRule: true } }] as const;

function buildCoreConfig(optionPatterns: readonly PatternType[]): SecretLintCoreConfig {
  return {
    rules: [
      { id: PRESET_ID, rule: presetRecommendCreator, rules: AWS_OVERRIDE.map(({ id, options }) => ({ id, options })) },
      { id: HOMEDIR_ID, rule: noHomedirCreator, severity: "error" },
      { id: DOTENV_ID, rule: noDotenvCreator, severity: "error" },
      { id: PATTERN_RULE_ID, rule: patternCreator, severity: "error", options: { patterns: [...optionPatterns] } },
    ],
  };
}

/** secretlintrc descriptor for CLI mode — rule ids resolve from border's node_modules. */
function buildCliDescriptor(optionPatterns: readonly PatternType[]): string {
  return JSON.stringify({
    rules: [
      { id: PRESET_ID, rule: PRESET_ID, rules: AWS_OVERRIDE.map(({ id, options }) => ({ id, options })) },
      { id: HOMEDIR_ID, rule: HOMEDIR_ID, severity: "error" },
      { id: DOTENV_ID, rule: DOTENV_ID, severity: "error" },
      // CLI mode: config-loader resolves `rule` as an npm package name and the
      // report carries the rule's META id, not our alias — hence PATTERN_PKG_ID.
      { id: PATTERN_PKG_ID, rule: PATTERN_PKG_ID, severity: "error", options: { patterns: [...optionPatterns] } },
    ],
  });
}

type ScanFile = { readonly absPath: string; readonly relPath: string };

/** `.border/` is border's own state dir — hard-excluded at LISTING time, never via .gitignore. */
function isBorderPath(relPath: string): boolean {
  return relPath.split("/").includes(".border");
}

type NormalizedMessage = Pick<SecretLintCoreResultMessage, "ruleId" | "messageId" | "message" | "severity" | "range"> & {
  readonly line: number;
};

type NormalizedResult = {
  readonly absPath: string;
  readonly relPath: string;
  readonly content: string;
  readonly messages: readonly NormalizedMessage[];
};

function readScanFile(absPath: string): { content: string; contentType: "text" | "binary" } | null {
  if (!existsSync(absPath) || !statSync(absPath).isFile()) return null; // tracked-then-deleted race: skip
  const buffer = readFileSync(absPath);
  const contentType = buffer.includes(0) ? "binary" : "text";
  return { content: buffer.toString("utf8"), contentType };
}

async function lintInProcess(files: readonly ScanFile[], config: SecretLintCoreConfig): Promise<NormalizedResult[]> {
  const results: NormalizedResult[] = [];
  for (const file of files) {
    const source = readScanFile(file.absPath);
    if (source === null) continue;
    let outcome;
    try {
      outcome = await lintSource({
        source: { content: source.content, filePath: file.absPath, contentType: source.contentType },
        options: { config, locale: "en" },
      });
    } catch (error) {
      // a lint crash is NEVER "clean" — border exit 2 via SecretlintRunError (G11).
      throw new EngineRunError(
        `secretlint (in-process) crashed on ${file.relPath}: ${error instanceof Error ? error.message : String(error)}`,
        null,
      );
    }
    results.push({
      absPath: file.absPath,
      relPath: file.relPath,
      content: source.content,
      messages: outcome.messages.map((m) => ({ ...m, line: m.loc.start.line })),
    });
  }
  return results;
}

type CliMessage = {
  ruleId?: unknown;
  messageId?: unknown;
  message?: unknown;
  severity?: unknown;
  range?: unknown;
  loc?: unknown;
};
type CliFileResult = { filePath?: unknown; sourceContent?: unknown; messages?: unknown };

function requireString(value: unknown, what: string): string {
  if (typeof value !== "string") throw new EngineRunError(`secretlint CLI report malformed: ${what} is not a string`, null);
  return value;
}

function stripSecretlintEnv(env: Readonly<Record<string, string | undefined>>): Record<string, string | undefined> {
  const out: Record<string, string | undefined> = {};
  for (const [name, value] of Object.entries(env)) {
    if (!name.startsWith("SECRETLINT")) out[name] = value;
  }
  return out;
}

function lintCli(files: readonly ScanFile[], descriptor: string, o: EngineOptions): Promise<NormalizedResult[]> {
  const candidates =
    o.binPath !== undefined
      ? [o.binPath]
      : [join(packageRoot, "node_modules", ".bin", "secretlint"), ...binaryCandidates("secretlint", o)];
  const results: NormalizedResult[] = [];
  for (let i = 0; i < files.length; i += CLI_CHUNK_FILES) {
    const chunk = files.slice(i, i + CLI_CHUNK_FILES);
    const byAbs = new Map(chunk.map((f) => [f.absPath, f] as const));
    // --no-maskSecrets: the CLI masks secrets in its report by default, which
    // would make valueDigest digest the mask instead of the raw value.
    const out = spawnEngine(candidates, ["--format", "json", "--secretlintrcJSON", descriptor, "--no-gitignore", "--no-glob", "--no-maskSecrets", ...chunk.map((f) => f.absPath)], {
      ...o,
      env: stripSecretlintEnv(o.env ?? process.env),
    });
    // secretlint convention: 0 clean, 1 findings, 2 crash. Anything else is
    // fail-closed (never "clean") — same exit-translation discipline as gitleaks.
    if (out.status !== 0 && out.status !== 1) {
      throw new EngineRunError(`secretlint CLI exited ${String(out.status)} (expected 0/1): ${out.stderr.slice(0, 400)}`, out.status);
    }
    let report: unknown;
    try {
      report = JSON.parse(out.stdout);
    } catch {
      throw new EngineRunError("secretlint CLI --format json produced unparseable stdout", out.status);
    }
    if (!Array.isArray(report)) throw new EngineRunError("secretlint CLI report is not a JSON array", out.status);
    for (const entry of report as CliFileResult[]) {
      const abs = requireString(entry.filePath, "filePath");
      const file = byAbs.get(abs);
      if (file === undefined) continue; // engine reported a path we never asked for — ignore, findings come from our list
      const content = typeof entry.sourceContent === "string" ? entry.sourceContent : readScanFile(abs)?.content ?? "";
      if (!Array.isArray(entry.messages)) throw new EngineRunError(`secretlint CLI report malformed for ${abs}: messages`, out.status);
      results.push({
        absPath: abs,
        relPath: file.relPath,
        content,
        messages: (entry.messages as CliMessage[]).map((m) => {
          const loc = m.loc as { start?: { line?: number } } | undefined;
          return {
            ruleId: requireString(m.ruleId, "ruleId"),
            messageId: typeof m.messageId === "string" ? m.messageId : "",
            message: requireString(m.message, "message"),
            severity: requireString(m.severity, "severity") as SecretLintCoreResultMessage["severity"],
            range: m.range as SecretLintCoreResultMessage["range"],
            line: loc?.start?.line ?? 1,
          };
        }),
      });
    }
  }
  return Promise.resolve(results);
}

function severityOf(level: NormalizedMessage["severity"]): Finding["severity"] {
  switch (level) {
    case "warning":
      return "MEDIUM"; // non-blocking record — border registers only error-severity rules today
    case "info":
      return "LOW";
    case "error":
    default:
      return "CRITICAL"; // every preset-recommend + generated pattern hit gates
  }
}

/** Which generated pattern actually produced this range? (pattern rule reports carry no rule name structurally) */
function patternNameFor(compiled: readonly GeneratedPattern[], content: string, start: number, end: number): string | null {
  for (const g of compiled) {
    g.regex.lastIndex = 0;
    for (const m of content.matchAll(g.regex)) {
      if (m.index === start && m[0] === content.slice(start, end)) return g.name;
    }
  }
  return null;
}

/**
 * secretlint 13.0.5 reports a WRONG range for AWSSecretAccessKey:
 * [fullMatchStart, fullMatchStart + groupLength], so range-slicing yields the
 * label prefix, not the credential. The engine message always echoes the true
 * match verbatim — trust the slice only when the message quotes it; otherwise
 * recover the `…: <credential>` tail and adopt it only if present in source.
 */
function recoverRawValue(content: string, slice: string, message: string): string {
  if (slice.length > 0 && message.includes(slice)) return slice;
  const sep = message.lastIndexOf(": ");
  if (sep >= 0) {
    const cred = message.slice(sep + 2);
    if (cred.length > 0 && content.includes(cred)) return cred;
  }
  return slice;
}

function toFindings(results: readonly NormalizedResult[], o: SecretlintScanOptions, compiled: readonly GeneratedPattern[]): Finding[] {
  const findings: Finding[] = [];
  const seen = new Set<string>();
  for (const res of results) {
    for (const m of res.messages) {
      const [start = 0, end = 0] = m.range ?? [];
      const slice = res.content.slice(start, end);
      const recovered = recoverRawValue(res.content, slice, m.message);
      // file-level reports (e.g. FOUND_DOTENV_FILE over whole content) have no
      // credential to digest — fall back to a stable non-secret identity token.
      const raw = recovered.length > 0 && recovered.length <= MAX_VALUE_CHARS ? recovered : m.messageId;
      const { valueDigest, snippet } = redact(raw);
      o.sanitizer?.register(valueDigest, raw);
      const isPatternHit = m.ruleId === PATTERN_RULE_ID || m.ruleId === PATTERN_PKG_ID;
      const rule = isPatternHit
        ? (patternNameFor(compiled, res.content, start, end) ?? `${PATTERN_RULE_ID}/${m.messageId}`)
        : `${m.ruleId}/${m.messageId}`;
      // G23: the engine message echoes the raw match — replace it with the snippet.
      let message = raw.length > 0 ? m.message.split(raw).join(snippet) : m.message;
      if (o.sanitizer !== undefined) message = o.sanitizer.sanitize(message);
      const key = `${rule}\u0000${res.relPath}\u0000${String(m.line)}\u0000${valueDigest}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push({
        rule,
        severity: severityOf(m.severity),
        target: o.target,
        path: res.relPath,
        line: m.line,
        engine: SECRETLINT_ENGINE,
        message,
        valueDigest,
        snippet,
      });
    }
  }
  return findings;
}

async function runScan(files: readonly ScanFile[], o: SecretlintScanOptions): Promise<Finding[]> {
  const { optionPatterns, compiled } = generatePatterns(o.rules);
  const results =
    o.mode === "cli"
      ? lintCli(files, buildCliDescriptor(optionPatterns), o)
      : lintInProcess(files, buildCoreConfig(optionPatterns));
  return toFindings(await results, o, compiled);
}

/** Scan an explicit file list (artifact dirs: callers enumerate per todos 11/12). */
export async function scanPaths(o: PathsScanOptions): Promise<Finding[]> {
  const files: ScanFile[] = [];
  for (const rel of o.files) {
    if (isBorderPath(rel)) continue;
    files.push({ relPath: rel, absPath: resolve(o.dir, rel) });
  }
  return runScan(files, o);
}

/** Scan the git-TRACKED working-tree set (git ls-files; never .gitignore logic). */
export async function scanGitTrackedFiles(o: TrackedScanOptions): Promise<Finding[]> {
  const out = spawnEngine(binaryCandidates("git", o), ["-C", o.repoDir, "ls-files", "-z"], {
    ...o,
    env: { ...(o.env ?? process.env), GIT_CEILING_DIRECTORIES: dirname(o.repoDir) },
  });
  if (out.status !== 0) {
    throw new EngineRunError(`git ls-files failed (${String(out.status)}): ${out.stderr.slice(0, 400)}`, out.status);
  }
  const files: ScanFile[] = out.stdout
    .split("\0")
    .filter((rel) => rel.length > 0 && !isBorderPath(rel))
    .map((rel) => ({ relPath: rel, absPath: resolve(o.repoDir, rel) }));
  return runScan(files, o);
}

/**
 * G21 rulesHash fingerprint (round-2 M8): in-process secretlint has no
 * `--version` — hash the package-lock RESOLVED entries of the secretlint
 * family instead. Deterministic sha256 over sorted `name@version` lines.
 */
export async function secretlintVersionFingerprint(o?: { lockPath?: string }): Promise<string> {
  const lockPath = o?.lockPath ?? join(packageRoot, "package-lock.json");
  let raw: string;
  try {
    raw = readFileSync(lockPath, "utf8");
  } catch (error) {
    throw new EngineRunError(
      `cannot read ${lockPath} for the secretlint version fingerprint: ${String(error)}`,
      null,
    );
  }
  let lock: unknown;
  try {
    lock = JSON.parse(raw);
  } catch (error) {
    throw new EngineRunError(`${lockPath} is not valid JSON: ${String(error)}`, null);
  }
  const packages = (lock as { packages?: Record<string, { version?: unknown }> }).packages;
  if (packages === undefined || typeof packages !== "object") {
    throw new EngineRunError(`${lockPath} has no "packages" map — cannot fingerprint the secretlint family`, null);
  }
  const lines: string[] = [];
  for (const [key, entry] of Object.entries(packages)) {
    if (!/^node_modules\/(@secretlint\/[^/]+|secretlint)$/.test(key)) continue;
    if (typeof entry?.version !== "string") {
      throw new EngineRunError(`${lockPath}: ${key} has no resolved version`, null);
    }
    lines.push(`${key.slice("node_modules/".length)}@${entry.version}`);
  }
  if (lines.length === 0) {
    throw new EngineRunError(`${lockPath} contains no @secretlint/* family entries — border fails closed`, null);
  }
  return createHash("sha256").update(lines.sort().join("\n"), "utf8").digest("hex");
}
