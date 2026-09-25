// provenance: .omo/plans/border-exfil-lens.md T3 — the commit-message facet leg
// (分面契约 row 2): scanMessageText over the WILL-PUBLISH range, `exfil-*:message`
// ids, path = commit sha. Commit messages are a public face too (incident
// exhibit `04b8323`), and this facet is native-EXCLUSIVE — the twins never see
// messages, so this leg does NOT eat the engine-health suppression (broken.has
// never gates it, check.ts wires it with the native rules).
//
// Range doctrine (plan §S3, identity.ts:140-180): per refSet ref and each named
// remote, the will-publish set is `git rev-list <endpoint>..<ref>` with
// endpoint = the remote-tracking ref carrying `ref` (full refname first, then
// the conventional short). An UNRESOLVABLE endpoint means the remote never had
// the ref ⇒ the WHOLE ref is about to be transmitted ⇒ scan all of it
// (identity.ts:144-146). No remotes configured at all still scans the whole
// refs: "will publish" is anything not provably already on the far side.
//
// ARGV discipline: every git call is a spawnSync argv array (no shell), status
// checked fail-closed (any non-zero/signal/timeout is a typed throw, never an
// empty success), per-call timeout BELOW the 60 s context cap, message reads
// chunked at REV_BATCH=200 shas per `git log --no-walk` (E2BIG + 60 s guard).
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";

import { ConfigError } from "../channels/errors.ts";
import type { GitRemote } from "../config.ts";
import { scanMessageText, type ExfilFinding } from "../exfil/scan.ts";
import type { Finding } from "../findings.ts";
import type { TextSanitizer } from "../redact.ts";

/** Plan §分面契约: messageScan enumeration reuses the identity-leg REV_BATCH (identity.ts:88). */
export const MESSAGE_REV_BATCH = 200;
/** Generously under the 60 s per-call cap (context.ts:35) so a chunk can never outrun the gate. */
export const MESSAGE_GIT_TIMEOUT_MS = 55_000;

export type MessageGitRunner = (args: readonly string[]) => string;

export type MessageScanOptions = {
  readonly repoDir: string;
  /** refs the push would touch (full refnames, sorted — ctx.refSet). */
  readonly refSet: readonly string[];
  /** configured git remotes; names drive the endpoint probe. */
  readonly remotes: readonly GitRemote[];
  readonly hosts?: readonly string[];
  readonly env?: Readonly<Record<string, string | undefined>>;
  readonly sanitizer?: TextSanitizer;
  /** test seam: the checked argv-only spawn (default: real git below). */
  readonly runGit?: MessageGitRunner;
  readonly timeoutMs?: number;
  readonly maxBufferBytes?: number;
};

function defaultRunner(o: MessageScanOptions): MessageGitRunner {
  const repoDir = resolve(o.repoDir);
  const env: Record<string, string | undefined> = {};
  for (const [name, value] of Object.entries(o.env ?? process.env)) {
    if (!name.startsWith("GIT_")) env[name] = value;
  }
  env.GIT_CEILING_DIRECTORIES = dirname(repoDir);
  env.GIT_OPTIONAL_LOCKS = "0";
  return (args) => {
    const r = spawnSync("git", ["-C", repoDir, ...args], {
      encoding: "utf8",
      env,
      timeout: o.timeoutMs ?? MESSAGE_GIT_TIMEOUT_MS,
      maxBuffer: o.maxBufferBytes ?? 32 * 1024 * 1024,
    });
    if (r.error !== undefined) {
      throw new ConfigError("git-failed", `git ${args.slice(0, 2).join(" ")} in ${repoDir}: ${r.error.message}`);
    }
    if (r.status === null) {
      throw new ConfigError("git-failed", `git ${args.slice(0, 2).join(" ")} in ${repoDir} killed by ${String(r.signal)} (timeout ${String(o.timeoutMs ?? MESSAGE_GIT_TIMEOUT_MS)}ms) — fail closed, never a silent clean`);
    }
    if (r.status !== 0) {
      throw new ConfigError("git-failed", `git ${args.slice(0, 2).join(" ")} in ${repoDir} exited ${String(r.status)}: ${(r.stderr ?? "").trim().slice(0, 200)}`);
    }
    return r.stdout ?? "";
  };
}

function revExists(run: MessageGitRunner, rev: string): boolean {
  try {
    run(["rev-parse", "--verify", "--quiet", rev]);
    return true;
  } catch {
    return false;
  }
}

/** identity.ts:136-153 doctrine: full remote-tracking refname, then the conventional short. */
function trackingEndpoint(run: MessageGitRunner, remoteName: string, ref: string): string | null {
  const candidates = [`refs/remotes/${remoteName}/${ref}`];
  const short = ref.replace(/^refs\/(?:heads|tags)\//, "");
  if (short !== ref) candidates.push(`refs/remotes/${remoteName}/${short}`);
  return candidates.find((c) => revExists(run, c)) ?? null;
}

/** Will-publish shas: union of per-remote endpoint..ref ranges; whole ref when NO endpoint resolves. */
export function willPublishShas(run: MessageGitRunner, refSet: readonly string[], remotes: readonly GitRemote[]): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const collect = (revs: readonly string[]): void => {
    for (const sha of run(["rev-list", ...revs]).split("\n")) {
      if (sha !== "" && !seen.has(sha)) {
        seen.add(sha);
        out.push(sha);
      }
    }
  };
  for (const ref of refSet) {
    if (!revExists(run, ref)) continue; // not a single resolvable ref — the history leg's fail-closed territory
    const ranges: string[] = [];
    for (const remote of remotes) {
      const name = remote.name;
      if (name === undefined) continue;
      const endpoint = trackingEndpoint(run, name, ref);
      if (endpoint !== null) ranges.push(`${endpoint}..${ref}`);
    }
    if (ranges.length === 0) collect([ref]); // endpoint unresolvable (or no named remotes) ⇒ whole ref is being transmitted
    else collect(ranges);
  }
  return out;
}

/** %x1e record separator + %H%x00%B body — the T5-proven parse; message text can never contain RS. */
const MESSAGE_LOG_FORMAT = "--format=%x1e%H%x00%B";

function scanOneRecord(record: string, o: MessageScanOptions, findings: Finding[]): void {
  const trimmed = record.replace(/^\n/, "");
  if (trimmed === "") return;
  const nul = trimmed.indexOf("\0");
  if (nul === -1) {
    throw new ConfigError("git-failed", "git log message record malformed (no NUL separator) — fail closed");
  }
  const sha = trimmed.slice(0, nul);
  const body = trimmed.slice(nul + 1).replace(/\n$/, "");
  for (const f of scanMessageText({
    text: body,
    source: sha,
    ...(o.hosts !== undefined ? { hosts: o.hosts } : {}),
    ...(o.sanitizer !== undefined ? { onMatch: (raw: string, digest: string): void => o.sanitizer?.register(digest, raw) } : {}),
  })) {
    findings.push(toMessageFinding(f, sha));
  }
}

function toMessageFinding(f: ExfilFinding, sha: string): Finding {
  return {
    rule: f.id,
    severity: f.severity,
    target: "git",
    path: f.source, // = sha: toRepoRelative passes it through unchanged (exclusions.ts:20-25) ⇒ per-commit allow rows
    commit: sha,
    line: f.line,
    engine: f.engine,
    message: f.message,
    valueDigest: f.valueDigest,
    snippet: f.snippet,
  };
}

export function scanCommitMessages(o: MessageScanOptions): Finding[] {
  const run = o.runGit ?? defaultRunner(o);
  const shas = willPublishShas(run, o.refSet, o.remotes);
  const findings: Finding[] = [];
  for (let i = 0; i < shas.length; i += MESSAGE_REV_BATCH) {
    const batch = shas.slice(i, i + MESSAGE_REV_BATCH);
    const out = run(["log", "--no-walk", MESSAGE_LOG_FORMAT, ...batch]);
    for (const record of out.split("\x1e")) scanOneRecord(record, o, findings);
  }
  return findings;
}
