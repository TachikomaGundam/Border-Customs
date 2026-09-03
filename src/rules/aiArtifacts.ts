// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 8
//
// Native-rule layer (D7 gap) for AI-session artifacts, env files, executed
// notebooks, junk, checked-in binaries and oversized blobs. The closed list
// (G35) lives in artifactMatchers.ts and nowhere else — every pattern
// addition ships as border.yaml `rules.pathPatterns`, never as code. Two legs
// feed one matcher pipeline so user patterns ride the same path as the
// built-ins:
//   * HEAD tree  — `git ls-tree -r --long HEAD` (path, blob sha, size);
//   * history    — `git log --diff-filter=A --name-only` over the ref-set
//     (todo 10 supplies refSet; default = every ref), so an .env removed
//     before the push but present in any pushed commit still gates (AC2).
// Content is read ONLY for notebook JSON + NUL sniffing, via
// `git cat-file --batch` on HEAD-tree blobs (never the working tree, never a
// checkout). Paths under `.border/` are skipped — todo 10's tracked-state
// guard owns that prefix for native rules.
//
// Dedupe key: (rule, normalized-path) — one finding per pair. commit:
// HEAD sha when the path is tree-resident, else the lexicographically
// smallest adding commit (deterministic across ref-walk order).
// G23: findings carry redact(path) digest/snippet only; file content —
// notebook or otherwise — never rides on a Finding.
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";

import { DEFAULT_MAX_FILE_KB } from "../config.ts";
import { EngineRunError } from "../engines/support.ts";
import type { Finding, Severity } from "../findings.ts";
import { redact, type TextSanitizer } from "../redact.ts";
import {
  closedMatchers,
  normalizePath,
  type PathMatcher,
  type PathPatternEntry,
  userMatchers,
} from "./artifactMatchers.ts";

export type { PathPatternEntry } from "./artifactMatchers.ts";

export const AI_ARTIFACTS_ENGINE = "ai-artifacts";
export const BINARY_SNIFF_BYTES = 8000;
const BORDER_PREFIX = ".border/";

const NOTEBOOK_RULE = "notebook-outputs";
const BINARY_RULE = "checked-in-binary";
const OVERSIZED_RULE = "oversized-file";

export type AiArtifactsRules = {
  readonly pathPatterns?: readonly (string | PathPatternEntry)[];
  readonly maxFileKB?: number;
};

export type ScanAiArtifactsOptions = {
  readonly repoDir: string;
  /** Refs whose history contributes path-additions; default = every ref (for-each-ref). */
  readonly refSet?: readonly string[];
  readonly cfg?: AiArtifactsRules;
  readonly sanitizer?: TextSanitizer;
  readonly env?: Readonly<Record<string, string | undefined>>;
  readonly timeoutMs?: number;
  /** cat-file --batch cap; ENOBUFS fails closed as EngineRunError, never "clean". */
  readonly maxBufferBytes?: number;
};

type Ctx = {
  readonly repoDir: string;
  readonly env: Record<string, string | undefined>;
  readonly timeoutMs: number;
  readonly maxBufferBytes: number;
};

function makeCtx(o: ScanAiArtifactsOptions): Ctx {
  const repoDir = resolve(o.repoDir);
  const env: Record<string, string | undefined> = {};
  for (const [name, value] of Object.entries(o.env ?? process.env)) {
    if (!name.startsWith("GIT_")) env[name] = value; // no GIT_DIR/GIT_WORK_TREE hijack
  }
  env.GIT_CEILING_DIRECTORIES = dirname(repoDir);
  env.GIT_OPTIONAL_LOCKS = "0";
  return { repoDir, env, timeoutMs: o.timeoutMs ?? 300_000, maxBufferBytes: o.maxBufferBytes ?? 32 * 1024 * 1024 };
}

function gitSpawn(c: Ctx, args: readonly string[], input?: Buffer): { ok: boolean; stdout: Buffer; stderr: string } {
  const r = spawnSync("git", ["-C", c.repoDir, ...args], {
    encoding: "buffer",
    timeout: c.timeoutMs,
    maxBuffer: c.maxBufferBytes,
    env: c.env,
    ...(input !== undefined ? { input } : {}),
  });
  if (r.error !== undefined) {
    throw new EngineRunError(`git ${args.join(" ")} in ${c.repoDir} failed to spawn: ${r.error.message}`, null);
  }
  return { ok: r.status === 0, stdout: r.stdout ?? Buffer.alloc(0), stderr: r.stderr?.toString("utf8") ?? "" };
}

function gitText(c: Ctx, args: readonly string[]): string {
  const r = gitSpawn(c, args);
  if (!r.ok) {
    throw new EngineRunError(`git ${args.join(" ")} in ${c.repoDir} exited non-zero: ${r.stderr.trim().slice(-200)}`, null);
  }
  return r.stdout.toString("utf8");
}

// ---------------------------------------------------------------- git legs

type TreeEntry = { readonly path: string; readonly blobSha: string; readonly size: number };

function headTree(c: Ctx, headSha: string): TreeEntry[] {
  const out: TreeEntry[] = [];
  for (const line of gitText(c, ["-c", "core.quotePath=false", "ls-tree", "-r", "--long", headSha]).split("\n")) {
    if (line === "") continue;
    // empirically: `--long` right-aligns the size after the sha with SPACES, then a TAB before the path
    const m = /^(\d{6}) (\w+) ([0-9a-f]{40})\s+(\d+)\t(.+)$/.exec(line);
    if (m === null || m[2] !== "blob") continue; // gitlinks (160000 commit) carry no blob to sniff
    out.push({ path: normalizePath(m[5] ?? ""), blobSha: m[3] ?? "", size: Number(m[4]) });
  }
  return out;
}

function allRefs(c: Ctx): string[] {
  return gitText(c, ["for-each-ref", "--format=%(refname)"]).split("\n").filter((l) => l !== "");
}

/** path -> commits that ADDED it, across the ref-set (merge-diffs skipped by git log defaults). */
function historyAdditions(c: Ctx, refs: readonly string[]): Map<string, string[]> {
  const out = new Map<string, string[]>();
  if (refs.length === 0) return out;
  const text = gitText(c, ["-c", "core.quotePath=false", "log", "--diff-filter=A", "--name-only", "--format=%x00%H", ...refs]);
  let sha: string | undefined;
  for (const line of text.split("\n")) {
    if (line === "") continue;
    if (line.startsWith("\0")) {
      sha = line.slice(1);
      continue;
    }
    if (sha === undefined) continue;
    const path = normalizePath(line);
    const arr = out.get(path);
    if (arr !== undefined) {
      if (arr[arr.length - 1] !== sha) arr.push(sha);
    } else {
      out.set(path, [sha]);
    }
  }
  return out;
}

/** sha -> content (null: object missing). One batched, read-only plumbing call. */
function blobContents(c: Ctx, shas: readonly string[]): Map<string, Buffer | null> {
  const map = new Map<string, Buffer | null>();
  if (shas.length === 0) return map;
  const out = gitSpawn(c, ["cat-file", "--batch", "--buffer"], Buffer.from(`${shas.join("\n")}\n`, "utf8"));
  if (!out.ok) {
    throw new EngineRunError(`git cat-file --batch in ${c.repoDir} exited non-zero: ${out.stderr.trim().slice(-200)}`, null);
  }
  let pos = 0;
  while (pos < out.stdout.length) {
    const nl = out.stdout.indexOf(0x0a, pos);
    if (nl === -1) break;
    const parts = out.stdout.subarray(pos, nl).toString("utf8").split(" ");
    pos = nl + 1;
    const sha = parts[0] ?? "";
    if (parts[1] === "missing" || parts.length < 3) {
      map.set(sha, null);
      continue;
    }
    const size = Number(parts[2]);
    map.set(sha, out.stdout.subarray(pos, pos + size));
    pos += size + 1; // trailing LF after content
  }
  return map;
}

function notebookHasOutputs(buf: Buffer): boolean {
  let nb: unknown;
  try {
    nb = JSON.parse(buf.toString("utf8")); // unparseable ipynb ⇒ treated as no outputs
  } catch {
    return false;
  }
  if (typeof nb !== "object" || nb === null) return false;
  const cells = (nb as Record<string, unknown>)["cells"];
  if (!Array.isArray(cells)) return false;
  for (const cell of cells) {
    if (typeof cell !== "object" || cell === null) continue;
    const outputs = (cell as Record<string, unknown>)["outputs"];
    if (Array.isArray(outputs) && outputs.length > 0) return true;
  }
  return false;
}

// ---------------------------------------------------------------- scan

type Hit = { rule: string; severity: Severity; path: string; message: string; commits: string[]; inTree: boolean };

export function scanAiArtifacts(o: ScanAiArtifactsOptions): Finding[] {
  const c = makeCtx(o);
  const headProbe = gitSpawn(c, ["rev-parse", "--verify", "HEAD"]);
  const headSha = headProbe.ok && headProbe.stdout.length > 0 ? headProbe.stdout.toString("utf8").trim() : undefined;
  const tree = headSha === undefined ? [] : headTree(c, headSha);
  const refs = o.refSet !== undefined ? o.refSet : allRefs(c);
  const maxKB = o.cfg?.maxFileKB ?? DEFAULT_MAX_FILE_KB;

  const hits = new Map<string, Hit>();
  const record = (rule: string, severity: Severity, path: string, message: string, commits: readonly string[], inTree: boolean): void => {
    if (path.startsWith(BORDER_PREFIX)) return; // todo 10: native rules skip the .border/ prefix
    const key = `${rule}\0${path}`;
    const existing = hits.get(key);
    if (existing !== undefined) {
      existing.commits.push(...commits);
      existing.inTree ||= inTree;
      return;
    }
    hits.set(key, { rule, severity, path, message, commits: [...commits], inTree });
  };

  const matchers: PathMatcher[] = [...closedMatchers(), ...userMatchers(o.cfg?.pathPatterns ?? [])];
  for (const entry of tree) {
    for (const m of matchers) {
      if (headSha !== undefined && m.test(entry.path)) record(m.rule, m.severity, entry.path, m.message, [headSha], true);
    }
  }
  for (const [path, shas] of historyAdditions(c, refs)) {
    for (const m of matchers) {
      if (m.test(path)) record(m.rule, m.severity, path, m.message, shas, false);
    }
  }

  // Content rules: HEAD-tree blobs only (history-only paths get path-shape rules).
  const contents = blobContents(c, [...new Set(tree.map((e) => e.blobSha))]);
  for (const e of tree) {
    if (e.size > maxKB * 1024) {
      record(OVERSIZED_RULE, "MEDIUM", e.path, `Tracked blob is ${String(e.size)} bytes > rules.maxFileKB=${String(maxKB)}.`, [], true);
    }
    const content = contents.get(e.blobSha);
    if (content === null || content === undefined) continue;
    if (content.subarray(0, BINARY_SNIFF_BYTES).includes(0x00)) {
      record(BINARY_RULE, "HIGH", e.path, "Binary content detected (NUL byte within first 8000 bytes): checked-in binaries bloat every clone and hide payloads.", [], true);
    }
    if (e.path.endsWith(".ipynb") && notebookHasOutputs(content)) {
      record(NOTEBOOK_RULE, "MEDIUM", e.path, "Executed notebook committed with non-empty cell outputs: outputs embed real data, paths and credentials; run nbstripout before committing.", [], true);
    }
  }

  const findings: Finding[] = [];
  for (const hit of hits.values()) {
    const { valueDigest, snippet } = redact(hit.path);
    o.sanitizer?.register(valueDigest, hit.path);
    const commit = hit.inTree && headSha !== undefined ? headSha : [...new Set(hit.commits)].sort()[0];
    findings.push({
      rule: hit.rule,
      severity: hit.severity,
      target: "git",
      path: hit.path,
      ...(commit !== undefined ? { commit } : {}),
      engine: AI_ARTIFACTS_ENGINE,
      message: hit.message,
      valueDigest,
      snippet,
    });
  }
  return findings.sort((a, b) => a.rule.localeCompare(b.rule) || (a.path ?? "").localeCompare(b.path ?? ""));
}
