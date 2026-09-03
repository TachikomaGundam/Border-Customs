// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 10
//
// Tag-message scanning leg. The plan's D1 pipeline must catch secrets planted
// in ANNOTATED TAG MESSAGES — invisible to the git-history leg (gitleaks reads
// diffs, not tag objects) and to any file scan. Mechanism: enumerate refs/tags,
// pipe each `git for-each-ref --format=%(contents)` body through
// `gitleaks stdin` (v8.30.1 subcommand verified empirically; report on stdout
// only, G23 — nothing engine-shaped touches disk). Attribution choice (one,
// documented, per AC "CRITICAL with tag ref"): Finding.path = the tag REFNAME,
// commit = the tag's commit when dereferenceable, message names the ref too.
// The adapter's own parse/exit discipline (0 clean, 1 findings, anything else
// ⇒ EngineRunError ⇒ border exit 2) is mirrored here; spawnSync-with-input is
// needed because support.ts's spawnEngine cannot pipe stdin.
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { ConfigError } from "../config.ts";
import { GITLEAKS_VENDORED_CONFIG } from "../engines/gitleaks.ts";
import { binaryCandidates, engineErrorFromSpawn, EngineRunError, stripEngineEnv, type EngineOptions } from "../engines/support.ts";
import type { Finding } from "../findings.ts";
import { redact, type TextSanitizer } from "../redact.ts";
import { runGitChecked } from "./context.ts";

export const TAG_MESSAGE_RULE = "tag-message-secret";

export type TagScanOptions = EngineOptions & {
  repoDir: string;
  /** Finding.target label (default "git", matching the history leg). */
  target?: string;
  sanitizer?: TextSanitizer;
};

function isEnoent(error: unknown): boolean {
  return typeof error === "object" && error !== null && (error as { code?: unknown }).code === "ENOENT";
}

function stdinFindings(text: string, ignorePath: string, o: EngineOptions): unknown[] {
  const args = [
    "stdin",
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
  let lastError: unknown;
  for (const bin of binaryCandidates("gitleaks", o)) {
    const r = spawnSync(bin, args, {
      encoding: "utf8",
      input: text,
      timeout: o.timeoutMs ?? 300_000,
      maxBuffer: o.maxBufferBytes ?? 32 * 1024 * 1024,
      env: stripEngineEnv(o.env ?? process.env),
    });
    if (r.error !== undefined) {
      if (isEnoent(r.error)) {
        lastError = r.error;
        continue;
      }
      throw engineErrorFromSpawn(r.error, bin);
    }
    if (r.status === null) throw new EngineRunError(`gitleaks stdin was killed by signal ${String(r.signal)}`, null);
    if (r.status !== 0 && r.status !== 1) {
      throw new EngineRunError(
        `gitleaks stdin exited ${String(r.status)}; only 0 (clean) and 1 (findings) are translatable. stderr: ${(r.stderr ?? "").trim().slice(-200)}`,
        r.status,
      );
    }
    const stdout = (r.stdout ?? "").trim();
    if (stdout === "" || stdout === "[]") return [];
    let parsed: unknown;
    try {
      parsed = JSON.parse(stdout);
    } catch {
      throw new EngineRunError("gitleaks stdin produced an unparseable JSON report", r.status);
    }
    if (!Array.isArray(parsed)) throw new EngineRunError("gitleaks stdin JSON report is not an array", r.status);
    return parsed;
  }
  throw engineErrorFromSpawn(lastError ?? new Error("no candidate binaries"), "gitleaks");
}

function toTagFinding(raw: unknown, ref: string, commit: string | undefined, o: TagScanOptions): Finding {
  if (typeof raw !== "object" || raw === null) throw new EngineRunError("gitleaks stdin report entry is not an object", null);
  const r = raw as Record<string, unknown>;
  const rule = typeof r.RuleID === "string" ? r.RuleID : "unknown";
  const description = typeof r.Description === "string" && r.Description !== "" ? r.Description : rule;
  const secret = typeof r.Secret === "string" ? r.Secret : "";
  const match = typeof r.Match === "string" ? r.Match : "";
  const value = secret !== "" ? secret : match;
  const { valueDigest, snippet } = redact(value);
  if (value !== "") o.sanitizer?.register(valueDigest, value);
  const line = typeof r.StartLine === "number" && Number.isInteger(r.StartLine) ? r.StartLine : undefined;
  return {
    rule: TAG_MESSAGE_RULE,
    severity: "CRITICAL",
    target: o.target ?? "git",
    path: ref,
    ...(commit !== undefined ? { commit } : {}),
    engine: "gitleaks",
    message: `secret in tag message of ${ref}: ${description}`,
    valueDigest,
    snippet,
    ...(line !== undefined ? { line } : {}),
  };
}

function dereferenceTagCommit(repoDir: string, ref: string, o: EngineOptions): string | undefined {
  try {
    return runGitChecked(repoDir, ["rev-parse", "--verify", "--quiet", `${ref}^{commit}`], { ...(o.env !== undefined ? { env: o.env } : {}) }).trim() || undefined;
  } catch (err) {
    // a tag pointing at a blob/tree has no commit — the ref alone satisfies the AC
    if (err instanceof ConfigError) return undefined;
    throw err;
  }
}

export function scanTagMessages(o: TagScanOptions): Finding[] {
  const repoDir = resolve(o.repoDir);
  const gitOpts = { ...(o.env !== undefined ? { env: o.env } : {}) };
  const refs = runGitChecked(repoDir, ["for-each-ref", "--format=%(refname)", "refs/tags"], gitOpts)
    .split("\n")
    .filter((ref) => ref !== "");
  if (refs.length === 0) return [];
  const ignoreDir = mkdtempSync(join(tmpdir(), "border-gitleaks-ignore-"));
  const ignorePath = join(ignoreDir, ".gitleaksignore");
  writeFileSync(ignorePath, "");
  try {
    const findings: Finding[] = [];
    for (const ref of refs) {
      const message = runGitChecked(repoDir, ["for-each-ref", `--format=%(contents)`, ref], gitOpts);
      if (message.trim() === "") continue;
      const commit = dereferenceTagCommit(repoDir, ref, o);
      for (const raw of stdinFindings(message, ignorePath, o)) {
        findings.push(toTagFinding(raw, ref, commit, o));
      }
    }
    return findings;
  } finally {
    rmSync(ignoreDir, { recursive: true, force: true });
  }
}
