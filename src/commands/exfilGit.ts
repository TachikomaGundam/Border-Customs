// provenance: .omo/plans/border-exfil-lens.md T4 — git read-plumbing for the
// `border exfil` fast face (argv-only spawns, 55 s per-call cap under the
// 60 s doctrine, explicit status checks — a failed or timed-out spawn is a
// typed throw, never an empty success; blob contents come from ONE batched
// read-only cat-file call, aiArtifacts mechanics).
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";

import { ConfigError } from "../channels/errors.ts";
import type { MessageGitRunner } from "../check/messageScan.ts";

export const GIT_TIMEOUT_MS = 55_000;
export const MAX_BUFFER_BYTES = 32 * 1024 * 1024;
export const MAX_BLOB_BYTES = 2 * 1024 * 1024;
export const BATCH_SHAS = 500;

export type BlobRef = { readonly sha: string; readonly path: string; readonly size: number };

export type CliGit = { readonly run: MessageGitRunner; readonly runBuffer: (args: readonly string[], input?: string) => Buffer };

export function makeGit(repoDir: string, env: Readonly<Record<string, string | undefined>>): CliGit {
  const clean: Record<string, string | undefined> = {};
  for (const [name, value] of Object.entries(env)) {
    if (!name.startsWith("GIT_")) clean[name] = value;
  }
  clean.GIT_CEILING_DIRECTORIES = dirname(resolve(repoDir));
  clean.GIT_OPTIONAL_LOCKS = "0";
  clean.GIT_TERMINAL_PROMPT = "0"; // a credential prompt would hang the fast face — fail closed instead
  const spawnWith = (args: readonly string[], input?: string): { stdout: Buffer; fail: string | null } => {
    const r = spawnSync("git", ["-C", resolve(repoDir), ...args], {
      timeout: GIT_TIMEOUT_MS,
      maxBuffer: MAX_BUFFER_BYTES,
      env: clean,
      ...(input !== undefined ? { input } : {}),
    });
    if (r.error !== undefined) return { stdout: Buffer.alloc(0), fail: `git ${args.slice(0, 2).join(" ")}: ${r.error.message}` };
    if (r.status !== 0) {
      const why = r.status === null ? `killed by ${String(r.signal)} (timeout ${String(GIT_TIMEOUT_MS)}ms)` : `exited ${String(r.status)}`;
      return { stdout: Buffer.alloc(0), fail: `git ${args.slice(0, 3).join(" ")} ${why}: ${(r.stderr?.toString("utf8") ?? "").trim().slice(0, 200)}` };
    }
    return { stdout: r.stdout ?? Buffer.alloc(0), fail: null };
  };
  const runBuffer = (args: readonly string[], input?: string): Buffer => {
    const r = spawnWith(args, input);
    if (r.fail !== null) throw new ConfigError("git-failed", r.fail);
    return r.stdout;
  };
  return { run: (args) => runBuffer(args).toString("utf8"), runBuffer };
}

function parseLsTree(line: string): BlobRef | null {
  const m = /^\d{6} (\w+) ([0-9a-f]{40})\s+(\d+)\t(.+)$/.exec(line);
  if (m === null || m[1] !== "blob") return null; // gitlinks carry no blob to scan
  return { sha: m[2] ?? "", path: m[4] ?? "", size: Number(m[3]) };
}

export function tipTree(git: CliGit, rev: string): BlobRef[] {
  return git
    .run(["-c", "core.quotePath=false", "ls-tree", "-r", "--long", rev])
    .split("\n")
    .map(parseLsTree)
    .filter((b): b is BlobRef => b !== null);
}

/** reachable-history blobs: rev-list --objects (given revs only, NOT --all), typed via batch-check. */
export function historyBlobs(git: CliGit, rev: string): BlobRef[] {
  const paths = new Map<string, string>();
  for (const line of git.run(["rev-list", "--objects", rev]).split("\n")) {
    if (line === "") continue;
    const sp = line.indexOf(" ");
    if (sp <= 0) continue;
    if (!paths.has(line.slice(0, sp))) paths.set(line.slice(0, sp), line.slice(sp + 1));
  }
  const shas = [...paths.keys()];
  const out: BlobRef[] = [];
  for (let i = 0; i < shas.length; i += BATCH_SHAS) {
    const checked = git.runBuffer(["cat-file", "--batch-check"], `${shas.slice(i, i + BATCH_SHAS).join("\n")}\n`).toString("utf8");
    for (const line of checked.split("\n")) {
      const m = /^([0-9a-f]{40}) (\w+) (\d+)$/.exec(line);
      if (m === null || m[2] !== "blob") continue;
      const path = paths.get(m[1] ?? "");
      if (path !== undefined) out.push({ sha: m[1] ?? "", path, size: Number(m[3]) });
    }
  }
  return out;
}

/** sha → text (omitted: binary or > MAX_BLOB_BYTES — NUL-content blobs belong to the binary rule). */
export function blobTexts(git: CliGit, blobs: readonly BlobRef[]): Map<string, string> {
  const sizes = new Map(blobs.map((b) => [b.sha, b.size] as const));
  const wanted = [...new Set(blobs.map((b) => b.sha))].filter((s) => (sizes.get(s) ?? 0) <= MAX_BLOB_BYTES);
  const out = new Map<string, string>();
  for (let i = 0; i < wanted.length; i += BATCH_SHAS) {
    const buf = git.runBuffer(["cat-file", "--batch", "--buffer"], `${wanted.slice(i, i + BATCH_SHAS).join("\n")}\n`);
    let pos = 0;
    while (pos < buf.length) {
      const nl = buf.indexOf(0x0a, pos);
      if (nl === -1) break;
      const parts = buf.subarray(pos, nl).toString("utf8").split(" ");
      pos = nl + 1;
      const sha = parts[0] ?? "";
      if (parts[1] === "missing" || parts.length < 3) continue;
      const size = Number(parts[2]);
      const body = buf.subarray(pos, pos + size);
      pos += size + 1; // trailing LF after content
      if (!body.includes(0x00)) out.set(sha, body.toString("utf8"));
    }
  }
  return out;
}
