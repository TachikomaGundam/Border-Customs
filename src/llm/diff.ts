// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 18
//
// The review-diff half of the llm bundle: base selection (newest
// remote-tracking tip among the EXPOSED remotes, else the empty tree for a
// first push), raw `git diff` extraction, and G23 masking of patch text.
//
// Masking model (round-2 M9a, see DATA_BOUNDARY in src/llm.ts): raw secret
// values are never persisted by border, so the ledger cannot hand this process
// the values to scrub. Instead the mask re-runs the gitleaks detector over the
// patch text itself (scanTree registers every matched raw value into a
// process-lifetime TextSanitizer, findings discarded) — so every value the
// deterministic engines WOULD flag in this text becomes [REDACTED:<sha8>] with
// exactly the digest token the check record carries. A still-undiscovered
// residual secret passes through by design; that is the accepted boundary of
// the optional layer, stated verbatim in every bundle. Engine absence fails
// closed: no detector, no patches out the door.
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";

import { ConfigError } from "../config.ts";
import { BORDER_STATE_DIR } from "../check/lock.ts";
import { sanitizeUrl, TextSanitizer } from "../redact.ts";
import { scanTree } from "../engines/gitleaks.ts";
import type { EngineOptions } from "../engines/support.ts";

export type GitCall = { readonly env?: EngineOptions["env"] };

// Diff patches are bounded only by the 10 MiB plan cap, so spawnSync needs a
// buffer above its 1 MiB default (ENOBUFS killed the naive runGitChecked path).
const GIT_DIFF_MAX_BUFFER = 64 * 1024 * 1024;

function gitOut(repoDir: string, args: readonly string[], o: GitCall, allowFail = false): string | null {
  const abs = resolve(repoDir);
  const r = spawnSync("git", ["-C", abs, ...args], {
    encoding: "utf8",
    env: { ...(o.env ?? process.env), GIT_CEILING_DIRECTORIES: dirname(abs) },
    timeout: 120_000,
    maxBuffer: GIT_DIFF_MAX_BUFFER,
  });
  if (r.error !== undefined) {
    throw new ConfigError("git-failed", `git ${args.join(" ")} could not spawn: ${r.error.message}`);
  }
  if ((r.status ?? -1) !== 0) {
    if (allowFail) return null;
    throw new ConfigError("git-failed", `git ${args.join(" ")} in ${abs} exited ${String(r.status)}: ${(r.stderr ?? "").trim().slice(0, 200)}`);
  }
  return r.stdout ?? "";
}

function engineEnv(o: GitCall): Record<string, never> | { env: Readonly<Record<string, string | undefined>> } {
  return o.env !== undefined ? { env: o.env } : {};
}

/** Well-known SHA-1 of git's empty tree; only used if hash-object is unavailable. */
const EMPTY_TREE_FALLBACK = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";

export type DiffBase = {
  readonly mode: "remote-tip" | "full-tree";
  readonly sha: string;
  readonly ref: string | null;
  readonly note: string;
};

/**
 * base := newest remote-tracking tip among the git remotes whose sanitized URL
 * is in the exposureSet (G20: exposureSet carries sanitizeUrl'd remotes, so
 * match on the same transform). No such tip (first push / remote never
 * fetched) ⇒ full-tree diff from the empty tree, stated in `note`.
 */
export function resolveDiffBase(repoDir: string, exposure: readonly string[], o: GitCall = {}): DiffBase {
  const exposed = new Set(exposure);
  const remotes = (gitOut(repoDir, ["remote"], o) ?? "")
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l !== "")
    .filter((name) => {
      try {
        const url = gitOut(repoDir, ["remote", "get-url", name], o)!.trim();
        return exposed.has(sanitizeUrl(url));
      } catch {
        return false;
      }
    });
  const patterns = remotes.map((name) => `refs/remotes/${name}`);
  if (patterns.length > 0) {
    const out = gitOut(repoDir, ["for-each-ref", "--sort=-committerdate", "--format=%(objectname) %(refname)", ...patterns], o) ?? "";
    const line = out
      .split("\n")
      .map((l) => l.trim())
      .find((l) => l !== "" && !l.endsWith("/HEAD"));
    if (line !== undefined) {
      const [sha, ref] = line.split(" ") as [string, string];
      return { mode: "remote-tip", sha, ref, note: `base = newest remote-tracking tip of the exposed remotes (${ref})` };
    }
  }
  let emptyTree = EMPTY_TREE_FALLBACK;
  try {
    emptyTree = gitOut(repoDir, ["hash-object", "-t", "tree", "--stdin"], o)!.trim() || EMPTY_TREE_FALLBACK;
  } catch {
    /* keep the documented constant */
  }
  return {
    mode: "full-tree",
    sha: emptyTree,
    ref: null,
    note: "first push / no remote-tracking tip for the exposed remotes — FULL-TREE diff from the root of the history (empty tree base); every file the push would add is reviewed",
  };
}

export type RawDelta = { readonly path: string; readonly changeType: string; readonly adds: number; readonly dels: number; readonly rawPatch: string };

function nulFields(chunk: string): string[] {
  return chunk.split("\0");
}

/**
 * Raw (UNMASKED — caller masks) per-file deltas between base and head, in
 * git's deterministic diff order. -z everywhere: paths and rename pairs are
 * NUL-delimited, immune to quoting/unicode games.
 */
export function collectRawDeltas(repoDir: string, baseSha: string, headSha: string, o: GitCall = {}): { readonly stat: string; readonly deltas: RawDelta[] } {
  const nameStatus = gitOut(repoDir, ["diff", "--name-status", "-z", baseSha, headSha], o) ?? "";
  const numstat = gitOut(repoDir, ["diff", "--numstat", "-z", baseSha, headSha], o) ?? "";
  const stat = gitOut(repoDir, ["diff", "--stat", baseSha, headSha], o) ?? "";
  const counts = new Map<string, { adds: number; dels: number }>();
  for (const rec of numstat.split("\0")) {
    if (rec === "") continue;
    const [adds, dels, path] = nulFields(rec);
    if (path === undefined) continue;
    counts.set(path, { adds: Number(adds) || 0, dels: Number(dels) || 0 });
  }
  const entries: { path: string; changeType: string }[] = [];
  const fields = nulFields(nameStatus);
  for (let i = 0; i < fields.length; i += 1) {
    const status = fields[i];
    if (status === undefined || status === "") continue;
    const a = fields[i + 1] as string;
    if (status.startsWith("R") || status.startsWith("C")) {
      entries.push({ path: a, changeType: status[0] as string });
      const b = fields[i + 2];
      if (b !== undefined) {
        const c = counts.get(b);
        if (c !== undefined) counts.set(a, c);
      }
      i += 2;
    } else {
      entries.push({ path: a, changeType: status[0] as string });
      i += 1;
    }
  }
  const deltas: RawDelta[] = entries.map((e) => {
    const patch = gitOut(repoDir, ["diff", baseSha, headSha, "--", e.path], o) ?? "";
    const c = counts.get(e.path) ?? { adds: 0, dels: 0 };
    return { path: e.path, changeType: e.changeType, adds: c.adds, dels: c.dels, rawPatch: patch };
  });
  return { stat, deltas };
}

/**
 * G23 patch masker: feed every raw text through the gitleaks detector (inside
 * a .border sandbox so nothing escapes the state dir) and return the scrubber.
 * Inputs are chunked well under the engine's 10 MiB max-target-mb default
 * (2M UTF-16 chars ≤ 8 MiB even fully 3-byte-encoded) so no patch region is
 * silently skipped by size.
 */
const MASK_CHUNK_CHARS = 2_000_000;

export function maskViaEngineDetection(repoDir: string, texts: readonly string[], o: GitCall = {}): (text: string) => string {
  const sanitizer = new TextSanitizer();
  const sandbox = mkdtempSync(join(repoDir, BORDER_STATE_DIR, "llm-mask-"));
  try {
    let idx = 0;
    for (const text of texts) {
      if (text === "") continue;
      for (let off = 0; off < text.length; off += MASK_CHUNK_CHARS, idx += 1) {
        writeFileSync(join(sandbox, `detect-${String(idx)}.txt`), text.slice(off, off + MASK_CHUNK_CHARS), "utf8");
      }
    }
    scanTree({
      dir: sandbox,
      stateDir: join(repoDir, BORDER_STATE_DIR),
      target: "llm-mask",
      sanitizer,
      ...engineEnv(o),
    });
  } finally {
    rmSync(sandbox, { recursive: true, force: true });
  }
  return (text: string) => sanitizer.sanitize(text);
}
