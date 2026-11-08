// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 9
//
// Git identity allowlist. Pushing a ref-set publishes every author/committer
// name+email and every annotated-tag tagger it contains; this rule fails
// closed on any identity not explicitly allowlisted in rules.authors.
//
// EXPOSURE CLASS (owner escalation 2026-11-08, Sibyl field test): an
// "identity would be exposed" claim is only true of objects leaving THIS
// MACHINE FOR THE FIRST TIME. The walk collects the full reachable history of
// every refSet ref (cheap, offline), then each configured remote's LIVE
// `git ls-remote` (never a stale local remote-tracking ref) splits the
// offenders:
//   * fresh (unreachable from every remote endpoint) → CRITICAL
//     `identity-not-allowlisted`, remediation = filter-repo (legitimate: the
//     history is not public yet);
//   * already public (reachable from some remote endpoint; tags: the exact
//     tag object already on the remote) → INFO `identity-already-public`,
//     NO remediation — rewriting published history is pure damage (it cannot
//     un-publish the remote objects or GitHub's own PR records).
// A repo with no configured remotes has no endpoints: the whole walk is
// fresh (first-push semantics, the pre-escalation behavior). A configured
// remote that cannot be reached while offenders exist THROWS (exit 2):
// the exposure class cannot be decided and border never guesses a verdict —
// same posture as the registry pre-flight ("silence never means absent").
// The live-remote probe fires ONLY when offenders exist (clean repos stay
// zero-network). Read-only git plumbing throughout.
//
// Co-authored-by trailers are IGNORED by design: they are free-text commit
// message content, not git metadata, and the identity that actually gets
// exposed by a push is the author/committer ident recorded in the object.
// Parsing them would also open a spoofing surface (anyone can write the
// trailer); the plan (todo 9) explicitly lists this as a MUST NOT.
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";

import { parseLsRemote } from "../lsremote.ts";
import type { BorderConfig } from "../config.ts";
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

function revParse(repoDir: string, rev: string): string {
  return runGit(repoDir, ["rev-parse", rev]).trim();
}

// ---------------------------------------------------------------- live remote truth

/** url → refname→sha exactly as `git ls-remote` answers it (test seam). */
export type LsRemoteFn = (url: string) => Map<string, string>;

const LS_REMOTE_TIMEOUT_MS = 30_000;

/** Credentials never ride the error message: user:pass@ is stripped, file:// echoed whole. */
function urlForMessage(url: string): string {
  try {
    const u = new URL(url);
    if (u.protocol === "file:") return url;
    return `${u.protocol}//${u.host}/***`;
  } catch {
    return "***";
  }
}

function lsRemoteFetch(repoDir: string, url: string, env: Readonly<Record<string, string | undefined>>): Map<string, string> {
  const r = spawnSync("git", ["ls-remote", url], {
    cwd: repoDir,
    encoding: "utf8",
    env: { ...process.env, ...env, GIT_CEILING_DIRECTORIES: dirname(resolve(repoDir)) },
    timeout: LS_REMOTE_TIMEOUT_MS,
  });
  if (r.error !== undefined || r.status !== 0) {
    const why = r.error !== undefined ? r.error.message : (r.stderr ?? "").trim().slice(-200);
    throw new Error(
      `identity: remote ${urlForMessage(url)} is unreachable via git ls-remote (${why}) — the exposure class of the offending identities cannot be decided and border never guesses it; restore connectivity or scope the check and retry`,
    );
  }
  return parseLsRemote(r.stdout ?? "", urlForMessage(url));
}

/** What the configured remotes ALREADY hold, split out of the scanned walk. */
type RemoteTruth = {
  /** commits reachable from some remote endpoint — already off this machine. */
  readonly published: Set<string>;
  /** annotated-tag refnames whose EXACT tag object the remote already holds. */
  readonly publishedTags: Set<string>;
  /** remote urls the truth was computed from (for the INFO message). */
  readonly remoteLabels: string[];
};

function remoteTruth(o: IdentityScanOptions, walkShas: ReadonlySet<string>): RemoteTruth {
  const truth: RemoteTruth = { published: new Set(), publishedTags: new Set(), remoteLabels: [] };
  // Only exact refnames get endpoint matching (range syntax belongs to the walk, never
  // to an endpoint diff). No resolvable ref ⇒ no remote truth is derivable ⇒ NO fetch
  // happens and the whole walk stays fresh — the safe direction, and clean repos
  // never touch the network at all (entries.size gate at the caller).
  const resolvable = o.refSet.filter((ref) => revExists(o.repoDir, ref));
  const urls = [...new Set(o.cfg.targets.git.remotes.map((r) => r.url).filter((u): u is string => u !== undefined && u.length > 0))];
  if (resolvable.length === 0 || urls.length === 0) return truth;
  const env = o.env ?? (process.env as Readonly<Record<string, string | undefined>>);
  const fetch = o.lsRemote ?? ((url: string) => lsRemoteFetch(o.repoDir, url, env));
  for (const url of urls) {
    const map = fetch(url);
    truth.remoteLabels.push(urlForMessage(url));
    for (const ref of resolvable) {
      const ep = map.get(ref) ?? map.get(`${ref}^{}`);
      if (ep === undefined) continue; // the remote never had this ref: whole ref is first-time out
      if (!/^[0-9a-f]{40}$|^[0-9a-f]{64}$/.test(ep)) {
        throw new Error(`identity: remote ${urlForMessage(url)} reports a malformed endpoint sha for ${ref} — refusing to interpret (fail closed)`);
      }
      if (ref.startsWith("refs/tags/")) {
        // A tag is published when the remote holds this exact object (ls-remote answers the
        // tag object at refs/tags/X and the peel at refs/tags/X^{}); a moved/local-only tag
        // object is fresh even if the refname exists remotely.
        const localObj = revParse(o.repoDir, ref);
        const localPeel = revParse(o.repoDir, `${ref}^{}`);
        if (map.get(ref) === localObj || map.get(`${ref}^{}`) === localPeel) truth.publishedTags.add(ref);
        continue;
      }
      if (!revExists(o.repoDir, ep)) {
        throw new Error(
          `identity: remote ${urlForMessage(url)} points ${ref} at ${ep.slice(0, 12)}, which is not an object in this repository — the transmitted set cannot be computed; run 'git fetch ${urlForMessage(url)}' and retry (fail closed)`,
        );
      }
      const fresh = new Set(runGit(o.repoDir, ["rev-list", `${ep}..${ref}`]).split("\n").filter((s) => s !== ""));
      for (const sha of walkShas) if (!fresh.has(sha)) truth.published.add(sha);
    }
  }
  return truth;
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
   *  With configured remotes the offenders among the walk are split against LIVE
   *  `git ls-remote` endpoints into fresh-CRITICAL vs already-public-INFO. */
  refSet: readonly string[];
  cfg: BorderConfig;
  /** Optional G23 registry; identities are evidence and intentionally NOT registered. */
  sanitizer?: TextSanitizer;
  env?: Readonly<Record<string, string | undefined>>;
  /** Test seam for the live ls-remote probe (production = lsRemoteFetch). */
  lsRemote?: LsRemoteFn;
};

export const IDENTITY_PUBLIC_RULE = "identity-already-public";

function locationsSuffix(objects: ReadonlyArray<readonly [string, string]>): { shown: string; suffix: string } {
  const locations = objects.map(([obj, roles]) => `${roles} of ${obj}`);
  const shownList = locations.slice(0, MAX_LISTED_LOCATIONS);
  const more = locations.length - shownList.length;
  return { shown: shownList.join("; "), suffix: more > 0 ? ` (+${String(more)} more)` : "" };
}

/**
 * Two rungs, one truth source (see module header):
 *   CRITICAL `identity-not-allowlisted` — offending objects reaching a remote
 *     for the FIRST time via this push; remediation advice applies (history
 *     is not public yet);
 *   INFO `identity-already-public` — the identity is offending but every
 *     object carrying it is already on a configured remote: nothing new
 *     leaves this machine. Recorded as fact WITHOUT remediation; border does
 *     not recommend rewriting published history.
 * One finding per (identity, rung). SHAs dedupe across legs.
 */
export function scanIdentity(o: IdentityScanOptions): Finding[] {
  const authors = o.cfg.rules.authors;
  const s: CommitScan = { repoDir: o.repoDir, authors, entries: new Map(), seen: new Set() };
  if (o.refSet.length > 0) collectCommits(s, o.refSet);
  mergeEntries(s.entries, scanTags(o.repoDir, authors));

  const truth = s.entries.size > 0 ? remoteTruth(o, s.seen) : { published: new Set<string>(), publishedTags: new Set<string>(), remoteLabels: [] as string[] };

  const findings: Finding[] = [];
  for (const entry of s.entries.values()) {
    const freshObjects: [string, string][] = [];
    const publicObjects: [string, string][] = [];
    for (const [obj, roles] of entry.objects) {
      const isCommit = /^[0-9a-f]{40}$/.test(obj);
      const published = isCommit ? truth.published.has(obj) : truth.publishedTags.has(obj);
      (published ? publicObjects : freshObjects).push([obj, roles]);
    }
    const identity = `${entry.name} <${entry.email}>`;
    // G23: the identity string is the finding's EVIDENCE (the whole point is
    // to show the operator what will be exposed), so it is digested like any
    // engine value but deliberately NOT registered with the sanitizer —
    // registering would scrub it out of this very message downstream.
    const { valueDigest, snippet } = redact(identity);
    const firstCommit = [...freshObjects, ...publicObjects].find(([obj]) => /^[0-9a-f]{40}$/.test(obj));

    if (freshObjects.length > 0) {
      const { shown, suffix } = locationsSuffix(freshObjects);
      const raw =
        `'${identity}' is not allowlisted in rules.authors — push would expose this git identity forever: ` +
        `${shown}${suffix}. ` +
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
    if (publicObjects.length > 0) {
      const { shown, suffix } = locationsSuffix(publicObjects);
      const raw =
        `'${identity}' is not allowlisted in rules.authors — but every object carrying it is already public on the configured remote(s) ` +
        `(${truth.remoteLabels.join(", ") || "remotes probed"}): ${shown}${suffix}. Nothing new leaves this machine with this push; ` +
        `recorded as fact for housekeeping (add it to rules.authors, or keep it out of new commits). ` +
        `border detects, never erases — rewriting published history is not offered.`;
      const publishedFinding: Finding = {
        rule: IDENTITY_PUBLIC_RULE,
        severity: "INFO",
        target: IDENTITY_TARGET,
        engine: IDENTITY_ENGINE,
        message: o.sanitizer?.sanitize(raw) ?? raw,
        valueDigest: redact(`${identity}:already-public`).valueDigest,
        snippet,
      };
      if (firstCommit !== undefined) publishedFinding.commit = firstCommit[0];
      findings.push(publishedFinding);
    }
  }
  return findings;
}
