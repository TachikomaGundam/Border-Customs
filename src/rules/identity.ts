// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 9
//
// Git identity allowlist. Pushing a ref-set publishes every author/committer
// name+email and every annotated-tag tagger it contains to the remote
// forever; this rule fails closed on any identity not explicitly allowlisted
// in rules.authors.{emails,names}. Two commit legs feed one identity scan:
//   * history leg — `git log <refSet>` walks the full reachable history of
//     every ref/range in the set (a ref the remote has never seen, or has
//     only partially, is covered whole by this leg);
//   * transmitted-object leg — for each configured named remote and each
//     refSet ref whose remote-tracking endpoint resolves, `git rev-list
//     <remote-endpoint>..<ref>` names exactly the objects the push would
//     transmit; unresolvable endpoints are skipped silently (remote never
//     had the ref ⇒ the whole ref is transmitted and the history leg
//     already scanned it), and a repo with no configured remotes is pure
//     history-leg (full history per ref), which was always the behavior.
// Read-only git plumbing only (git log / git rev-list / git rev-parse
// --verify / git for-each-ref) — border never mutates the scanned repository.
//
// Co-authored-by trailers are IGNORED by design: they are free-text commit
// message content, not git metadata, and the identity that actually gets
// exposed by a push is the author/committer ident recorded in the object.
// Parsing them would also open a spoofing surface (anyone can write the
// trailer); the plan (todo 9) explicitly lists this as a MUST NOT.
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";

import type { BorderConfig, GitRemote } from "../config.ts";
import type { Finding } from "../findings.ts";
import { redact, type TextSanitizer } from "../redact.ts";
import { identityAllowed, type AuthorsConfig } from "./allowlist.ts";

export { identityAllowed, matchGlob, type AuthorsConfig } from "./allowlist.ts";

export const IDENTITY_RULE = "identity-not-allowlisted";
const IDENTITY_TARGET = "git";
const IDENTITY_ENGINE = "native";
const MAX_LISTED_LOCATIONS = 50;
const US = "\x1f";
const MAX_TAGGER_NAME_SEGMENTS = 20;

// ---------------------------------------------------------------- collection

type OffendingEntry = {
  readonly name: string;
  readonly email: string;
  /** object key (commit sha or tag refname) -> role labels, insertion-ordered. */
  readonly objects: Map<string, string>;
};

function addRole(entries: Map<string, OffendingEntry>, key: string, entry: Omit<OffendingEntry, "objects">, obj: string, role: string): void {
  let found = entries.get(key);
  if (found === undefined) {
    found = { name: entry.name, email: entry.email, objects: new Map() };
    entries.set(key, found);
  }
  const prev = found.objects.get(obj);
  found.objects.set(obj, prev === undefined ? role : `${prev}+${role}`);
  // re-set preserves first-insertion order only for NEW keys; existing keys
  // keep their original position — exactly what we want for role merging.
}

function runGit(repoDir: string, args: readonly string[]): string {
  // GIT_CEILING_DIRECTORIES fences repo discovery to the target: a directory
  // without .git fails loudly (fail closed) instead of scanning border's own
  // repository upward — same guard the gitleaks adapter fixtures rely on.
  const r = spawnSync("git", args, {
    cwd: repoDir,
    encoding: "utf8",
    env: { ...process.env, GIT_CEILING_DIRECTORIES: dirname(resolve(repoDir)) },
  });
  if (r.status !== 0) {
    throw new Error(
      `git ${args.join(" ")} in ${repoDir} exited ${String(r.status)}: ${(r.stderr ?? "").trim().slice(-400)}`,
    );
  }
  return r.stdout ?? "";
}

/**
 * Plan format '%an%x1f%ae%x1f%cn%x1f%ce%x1f%P' plus %H prepended: findings
 * must list the offending commit shas, so the line needs its own hash.
 */
const LOG_FIELDS = 6;
const LOG_FORMAT = "--format=%H%x1f%an%x1f%ae%x1f%cn%x1f%ce%x1f%P";

/** Argv budget for `git log --no-walk <shas>` batches (E2BIG guard on wide ranges). */
const REV_BATCH = 200;

type CommitScan = {
  readonly repoDir: string;
  readonly authors: AuthorsConfig;
  readonly entries: Map<string, OffendingEntry>;
  /** shas whose ident fields are already folded into entries (legs may overlap). */
  readonly seen: Set<string>;
};

function collectCommits(s: CommitScan, revs: readonly string[]): void {
  const out = runGit(s.repoDir, ["log", LOG_FORMAT, ...revs]);
  for (const line of out.split("\n")) {
    if (line === "") continue;
    const f = line.split(US);
    if (f.length !== LOG_FIELDS) {
      throw new Error(`unexpected git log line shape: ${line.slice(0, 80)}`);
    }
    const [sha = "", an = "", ae = "", cn = "", ce = "", p = ""] = f;
    if (s.seen.has(sha)) continue;
    s.seen.add(sha);
    const parents = p.trim();
    const parentCount = parents === "" ? 0 : parents.split(/\s+/).length;
    const pairs: ReadonlyArray<readonly [string, string, string]> =
      // Merge commits check the COMMITTER ONLY (plan todo 9): a merge's
      // authorship legitimately belongs to whoever wrote the merged side;
      // the person who chose to expose it is the one who recorded the merge.
      parentCount >= 2
        ? [["committer", cn, ce]]
        : [
            ["author", an, ae],
            ["committer", cn, ce],
          ];
    for (const [role, name, email] of pairs) {
      const key = `${name}${US}${email}`;
      if (!identityAllowed(name, email, s.authors)) {
        addRole(s.entries, key, { name, email }, sha, role);
      }
    }
  }
}

/** rev-parse --verify without the fail-closed throw: presence probe only. */
function revExists(repoDir: string, rev: string): boolean {
  const r = spawnSync("git", ["rev-parse", "--verify", "--quiet", rev], {
    cwd: repoDir,
    encoding: "utf8",
    env: { ...process.env, GIT_CEILING_DIRECTORIES: dirname(resolve(repoDir)) },
  });
  return r.status === 0;
}

/**
 * Remote-tracking endpoint carrying `ref` for remote `remoteName`, or null
 * when that remote never had the ref. Full refname first (`origin/refs/heads/main`
 * shape is legal when the operator mapped such fetch refs), then the
 * conventional short (`refs/heads/main` ⇒ `origin/main`, `refs/tags/v1` ⇒
 * `origin/v1`). A null endpoint is NOT an error: the whole ref is about to
 * be transmitted and the history leg already scanned all of it.
 */
function trackingEndpoint(repoDir: string, remoteName: string, ref: string): string | null {
  const candidates = [`refs/remotes/${remoteName}/${ref}`];
  const short = ref.replace(/^refs\/(?:heads|tags)\//, "");
  if (short !== ref) candidates.push(`refs/remotes/${remoteName}/${short}`);
  return candidates.find((c) => revExists(repoDir, c)) ?? null;
}

/**
 * Transmitted-object leg: per named remote and resolvable refSet ref, union
 * `git rev-list <endpoint>..<ref>` — the objects that specific push would
 * upload. Endpoints that do not resolve and refSet entries that are not
 * single refs (range syntax) are skipped: range semantics are already the
 * history leg's job, and a bad plain ref threw there first (fail closed).
 */
function scanTransmitted(s: CommitScan, refSet: readonly string[], remotes: readonly GitRemote[]): void {
  const names = remotes.map((r) => r.name).filter((n): n is string => n !== undefined);
  if (names.length === 0) return;
  for (const ref of refSet) {
    if (!revExists(s.repoDir, ref)) continue;
    for (const name of names) {
      const endpoint = trackingEndpoint(s.repoDir, name, ref);
      if (endpoint === null) continue;
      const out = runGit(s.repoDir, ["rev-list", `${endpoint}..${ref}`]);
      const fresh: string[] = [];
      for (const sha of out.split("\n")) {
        if (sha !== "" && !s.seen.has(sha)) fresh.push(sha);
      }
      for (let i = 0; i < fresh.length; i += REV_BATCH) {
        collectCommits(s, ["--no-walk", ...fresh.slice(i, i + REV_BATCH)]);
      }
    }
  }
}

/**
 * Tag objects: '%(refname) %(taggername) %(taggeremail)' (plan format, space
 * separated). refname never contains a space (git ref format forbids it) and
 * the ident email never contains a space, so first/last-token splitting is
 * unambiguous even for multi-word tagger names. Lightweight tags have EMPTY
 * tagger fields — no tagger exists, nothing to check, skip.
 */
function scanTags(repoDir: string, authors: AuthorsConfig): Map<string, OffendingEntry> {
  const entries = new Map<string, OffendingEntry>();
  const out = runGit(repoDir, ["for-each-ref", "--format=%(refname) %(taggername) %(taggeremail)", "refs/tags"]);
  for (const line of out.split("\n")) {
    if (line === "") continue;
    const firstSpace = line.indexOf(" ");
    const lastSpace = line.lastIndexOf(" ");
    if (firstSpace < 0) continue;
    const refname = line.slice(0, firstSpace);
    const email = line.slice(lastSpace + 1).trim().replace(/^<|>$/g, "");
    if (email === "") continue; // lightweight tag (or degenerate ident) ⇒ no tagger to check
    const nameTokens = line.slice(firstSpace + 1, lastSpace).split(" ").filter((t) => t !== "");
    if (nameTokens.length > MAX_TAGGER_NAME_SEGMENTS) {
      throw new Error(`unparsable tagger line for ${refname}`);
    }
    const name = nameTokens.join(" ");
    const key = `${name}${US}${email}`;
    if (!identityAllowed(name, email, authors)) {
      addRole(entries, key, { name, email }, refname, "tagger");
    }
  }
  return entries;
}

// ---------------------------------------------------------------- findings

function mergeEntries(target: Map<string, OffendingEntry>, extra: Map<string, OffendingEntry>): void {
  for (const [key, entry] of extra) {
    let existing = target.get(key);
    if (existing === undefined) {
      existing = { name: entry.name, email: entry.email, objects: new Map() };
      target.set(key, existing);
    }
    for (const [obj, roles] of entry.objects) {
      const prev = existing.objects.get(obj);
      existing.objects.set(obj, prev === undefined ? roles : `${prev}+${roles}`);
    }
  }
}

export type IdentityScanOptions = {
  repoDir: string;
  /** Revs/ranges to walk (todo 10 supplies the push ref-set); [] ⇒ commits skipped.
   *  With named remotes configured, each ref additionally gets a
   *  transmitted-object rev-list leg (see module header). */
  refSet: readonly string[];
  cfg: BorderConfig;
  /** Optional G23 registry; identities are evidence and intentionally NOT registered. */
  sanitizer?: TextSanitizer;
};

/**
 * CRITICAL `identity-not-allowlisted` — one finding per DISTINCT offending
 * identity (not per commit), listing up to 50 `role of <sha|refname>`
 * locations, newest first (git log order), then `(+N more)`. Commits come
 * from BOTH the history leg (full `git log` over refSet — first pushes and
 * restored tags are covered whole) and the per-remote transmitted-object
 * leg (`rev-list <endpoint>..<ref>`); SHAs dedupe, so overlap cannot
 * double-count roles. The remediation is documentation only: border NEVER
 * rewrites history.
 */
export function scanIdentity(o: IdentityScanOptions): Finding[] {
  const authors = o.cfg.rules.authors;
  const s: CommitScan = { repoDir: o.repoDir, authors, entries: new Map(), seen: new Set() };
  if (o.refSet.length > 0) {
    // empty push scope ⇒ no commits; tag leg is unconditional below
    collectCommits(s, o.refSet);
    scanTransmitted(s, o.refSet, o.cfg.targets.git.remotes);
  }
  mergeEntries(s.entries, scanTags(o.repoDir, authors));

  const findings: Finding[] = [];
  for (const entry of s.entries.values()) {
    const locations = [...entry.objects].map(([obj, roles]) => `${roles} of ${obj}`);
    const shown = locations.slice(0, MAX_LISTED_LOCATIONS);
    const more = locations.length - shown.length;
    const suffix = more > 0 ? ` (+${String(more)} more)` : "";
    const identity = `${entry.name} <${entry.email}>`;
    const firstCommit = [...entry.objects.entries()].find(([obj]) => /^[0-9a-f]{40}$/.test(obj));
    // G23: the identity string is the finding's EVIDENCE (the whole point is
    // to show the operator what will be exposed), so it is digested like any
    // engine value but deliberately NOT registered with the sanitizer —
    // registering would scrub it out of this very message downstream.
    const { valueDigest, snippet } = redact(identity);
    const raw =
      `'${identity}' is not allowlisted in rules.authors — push would expose this git identity forever: ` +
      `${shown.join("; ")}${suffix}. ` +
      `Remediation: use git filter-repo manually (out of scope for border; border never rewrites history).`;
    const finding: Finding = {
      rule: IDENTITY_RULE,
      severity: "CRITICAL",
      target: IDENTITY_TARGET,
      engine: IDENTITY_ENGINE,
      message: o.sanitizer?.sanitize(raw) ?? raw,
      valueDigest,
      snippet,
    };
    if (firstCommit !== undefined) finding.commit = firstCommit[0];
    findings.push(finding);
  }
  return findings;
}
