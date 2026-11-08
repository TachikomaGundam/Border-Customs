// provenance: 2026-11-08 owner escalation (Sibyl release field test) — the push gate
// must convict the PUSHABLE surface, not the whole disk.
//
// Doctrine (README "Untracked and dirty files are inputs too"): untracked files ride a
// `git add -A`, so they are in scope. But `git add` HONOURS .gitignore: a path that is
// .gitignore'd AND tracked by zero commits provably cannot reach a push through any
// normal workflow. Before this module, such paths (e.g. a tool's own .omo/ evidence
// tree full of digest-shaped synthetic bytes) blocked every user's push with engine
// CRITICALs on files that can never be pushed, training operators to paper over the
// allow-list — a fail-closed gate that cries wolf is a gate that gets muted.
//
// Semantics (strictly a DEMOTION, never a silence): every finding on the tree facet of
// an ignored-and-untracked path keeps its rule id, keeps its place in the report, and
// rides to INFO severity with a named note. Facet discipline: history findings (they
// carry a commit) and artifact findings (channel targets) are UNTOUCHED — a blob once
// committed is push surface forever, and registry bytes are exactly what ships.
// Tracked-but-ignored paths (force-added at some point) stay fully blocking: they are
// on the pushable surface by definition. The allow-list ledger is untouched.

import { runGitChecked } from "./context.ts";
import type { GitCallOptions } from "./context.ts";
import type { Finding } from "../findings.ts";

export const IGNORED_SURFACE_NOTE =
  " — path is .gitignore'd and untracked: git add honours .gitignore, so it cannot reach a push; informational surface, never blocking";

function nulList(stdout: string): Set<string> {
  return new Set(stdout.split("\0").filter((p) => p !== ""));
}

/** Exact entry, or ANY ancestor directory entry: git lists a fully-ignored dir as
 * `dir/` and never descends into a NESTED repository (a clone inside .omo/ keeps its
 * own .git), so files under it match only through the ancestor entry. */
function ignoredHit(rel: string, ignored: Set<string>): boolean {
  if (ignored.has(rel)) return true;
  let cut = rel.indexOf("/");
  while (cut > 0) {
    if (ignored.has(`${rel.slice(0, cut)}/`)) return true;
    cut = rel.indexOf("/", cut + 1);
  }
  return false;
}

/** Tree-facet finding with its path normalized to repo-relative (engines answer both
 * shapes; archive attribution is keyed on the OUTER path before '!'). */
function relFacetPath(f: Finding, repoDir: string): string | null {
  if (f.path === undefined || f.commit !== undefined) return null;
  if (f.target !== "git" && f.target !== "tree") return null;
  const outer = f.path.split("!")[0] ?? f.path;
  const prefix = `${repoDir}/`;
  return outer.startsWith(prefix) ? outer.slice(prefix.length) : outer;
}

/** Demote tree-facet findings on ignored-and-untracked paths to INFO (visible, never
 * silent, never blocking). Returns the count for caller-side bookkeeping. */
export function demoteIgnoredUntracked(findings: Finding[], repoDir: string, o: GitCallOptions = {}): number {
  const candidates = findings.filter((f) => f.severity !== "INFO" && relFacetPath(f, repoDir) !== null);
  if (candidates.length === 0) return 0;
  const tracked = nulList(runGitChecked(repoDir, ["ls-files", "-z"], o));
  const ignored = nulList(runGitChecked(repoDir, ["ls-files", "--others", "--ignored", "--exclude-standard", "-z"], o));
  if (ignored.size === 0) return 0;
  let demoted = 0;
  for (const f of findings) {
    if (f.severity === "INFO") continue;
    const rel = relFacetPath(f, repoDir);
    if (rel === null || !ignoredHit(rel, ignored) || tracked.has(rel)) continue;
    f.severity = "INFO";
    f.message = `${f.message}${IGNORED_SURFACE_NOTE}`;
    demoted += 1;
  }
  return demoted;
}
