// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 9
//
// Git identity allowlist. Pushing a ref-set publishes every author/committer
// name+email and every annotated-tag tagger it contains to the remote
// forever; this rule fails closed on any identity not explicitly allowlisted
// in rules.authors.{emails,names}. Read-only git plumbing only (git log /
// git for-each-ref) — border never mutates the scanned repository.
//
// Co-authored-by trailers are IGNORED by design: they are free-text commit
// message content, not git metadata, and the identity that actually gets
// exposed by a push is the author/committer ident recorded in the object.
// Parsing them would also open a spoofing surface (anyone can write the
// trailer); the plan (todo 9) explicitly lists this as a MUST NOT.
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";

import type { BorderConfig } from "../config.ts";
import type { Finding } from "../findings.ts";
import { redact, type TextSanitizer } from "../redact.ts";

export const IDENTITY_RULE = "identity-not-allowlisted";
const IDENTITY_TARGET = "git";
const IDENTITY_ENGINE = "native";
const MAX_LISTED_LOCATIONS = 50;
const US = "\x1f";
const MAX_TAGGER_NAME_SEGMENTS = 20;

/**
 * allowBots covers the GitHub noreply-bot email shape, which includes
 * dependabot (`49699333+dependabot[bot]@users.noreply.github.com`) and
 * github-actions bots — `[` and `]` are glob LITERALS in matchGlob, so this
 * one pattern is the whole hardcoded allowance (plan todo 9).
 */
const BOT_EMAIL_PATTERN = "*[bot]@users.noreply.github.com";

// ---------------------------------------------------------------- glob

function segmentMatchesAt(segment: string, value: string, pos: number): boolean {
  let vi = pos;
  for (const ch of segment) {
    if (vi >= value.length) return false;
    if (ch !== "?" && value[vi] !== ch) return false;
    vi += 1;
  }
  return true;
}

/**
 * Hand-rolled `*`/`?` glob (no new deps; plan: "minimatch-equivalent").
 * Anchored at BOTH ends; `*` spans any run, `?` exactly one character; every
 * other char (incl. `[`) is a literal. Split-on-`*` segments are matched
 * greedily-leftmost: between `*` gaps an earlier occurrence of a segment can
 * only ever leave MORE room for the remaining segments (the preceding `*`
 * absorbs the displaced span), so leftmost scanning is decision-complete —
 * no backtracking, O(n·m) worst case.
 *
 * Case: the matcher is deliberately CASE-SENSITIVE. Case-normalisation is the
 * caller's policy (see identityAllowed): emails compare lowercased, names
 * compare as written.
 */
export function matchGlob(pattern: string, value: string): boolean {
  const segments = pattern.split("*");
  const first = segments[0] ?? "";
  if (segments.length === 1) return segmentMatchesAt(first, value, 0) && value.length === first.length;
  const last = segments[segments.length - 1] ?? "";
  if (!segmentMatchesAt(first, value, 0)) return false;
  let pos = [...first].length;
  for (let i = 1; i < segments.length - 1; i += 1) {
    const seg = segments[i] ?? "";
    if (seg === "") continue;
    let found = -1;
    for (let p = pos; p <= value.length; p += 1) {
      if (segmentMatchesAt(seg, value, p)) {
        found = p;
        break;
      }
    }
    if (found < 0) return false;
    pos = found + [...seg].length;
  }
  const suffixStart = value.length - [...last].length;
  if (suffixStart < pos) return false;
  return segmentMatchesAt(last, value, suffixStart);
}

// ---------------------------------------------------------------- allowlist decision

type AuthorsConfig = BorderConfig["rules"]["authors"];

/**
 * An identity is allowed iff its email matches some emails[] glob
 * (case-insensitive — RFC 5321 treats the local part as case-dependent but
 * every real provider folds case, and the plan's threat is exposure, not
 * impersonation) AND its name matches some names[] glob CASE-SENSITIVELY
 * (display names are free text; exact/glob match is the operator's contract).
 * allowBots replaces both checks with the hardcoded noreply-bot email shape
 * only when explicitly true.
 */
function identityAllowed(name: string, email: string, authors: AuthorsConfig): boolean {
  const lowerEmail = email.toLowerCase();
  if (authors.allowBots === true && matchGlob(BOT_EMAIL_PATTERN, lowerEmail)) {
    return true;
  }
  const emailOk = authors.emails.some((p) => matchGlob(p.toLowerCase(), lowerEmail));
  if (!emailOk) return false;
  return authors.names.some((p) => matchGlob(p, name));
}

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

function scanCommits(repoDir: string, refSet: readonly string[], authors: AuthorsConfig): Map<string, OffendingEntry> {
  const entries = new Map<string, OffendingEntry>();
  if (refSet.length === 0) return entries; // empty push scope ⇒ no commits; tag leg is unconditional below
  const format = "--format=%H%x1f%an%x1f%ae%x1f%cn%x1f%ce%x1f%P";
  const out = runGit(repoDir, ["log", format, ...refSet]);
  for (const line of out.split("\n")) {
    if (line === "") continue;
    const f = line.split(US);
    if (f.length !== LOG_FIELDS) {
      throw new Error(`unexpected git log line shape: ${line.slice(0, 80)}`);
    }
    const [sha = "", an = "", ae = "", cn = "", ce = "", p = ""] = f;
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
      if (!identityAllowed(name, email, authors)) {
        addRole(entries, key, { name, email }, sha, role);
      }
    }
  }
  return entries;
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
  /** Revs/ranges to walk (todo 10 supplies the push ref-set); [] ⇒ commits skipped. */
  refSet: readonly string[];
  cfg: BorderConfig;
  /** Optional G23 registry; identities are evidence and intentionally NOT registered. */
  sanitizer?: TextSanitizer;
};

/**
 * CRITICAL `identity-not-allowlisted` — one finding per DISTINCT offending
 * identity (not per commit), listing up to 50 `role of <sha|refname>`
 * locations, newest first (git log order), then `(+N more)`. The remediation
 * is documentation only: border NEVER rewrites history.
 */
export function scanIdentity(o: IdentityScanOptions): Finding[] {
  const authors = o.cfg.rules.authors;
  const entries = new Map<string, OffendingEntry>();
  mergeEntries(entries, scanCommits(o.repoDir, o.refSet, authors));
  mergeEntries(entries, scanTags(o.repoDir, authors));

  const findings: Finding[] = [];
  for (const entry of entries.values()) {
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
