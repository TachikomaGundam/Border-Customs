// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 19
//
// G14 allow post-filter — the pipeline tail that turns cfg.allow entries into
// suppressed findings + enumerated allow-hits. Runs AFTER every engine/native
// leg and BEFORE verdict/counts, so a suppressed finding can neither block the
// gate nor vanish unrecorded. Matching contract:
//   entry.rule  — `*`/`?` glob (identity.matchGlob, the project's single glob
//                 dialect) against Finding.rule;
//   entry.match — same glob against Finding.valueDigest (exact, preferred:
//                 64-hex pins one value) OR Finding.snippet (shape pin; safe
//                 because snippets are the masked view, never the raw value);
//   entry.file  — same glob against the repo-relative finding path with any
//                 archive `!<inner>` attribution stripped; a finding without a
//                 path (identity, engine-policy) can never match a scoped entry.
// Blanket `{rule:"*"}` / `{match:"*"}` shapes are rejected at CONFIG LOAD
// (src/config.ts), so every suppression here traces to a concrete, authored
// entry. First matching entry wins (config order = precedence).
import type { BorderConfig } from "../config.ts";
import type { AllowHit, Finding } from "../findings.ts";
import { matchGlob } from "../rules/identity.ts";
import { toRepoRelative } from "./exclusions.ts";

type AllowEntry = BorderConfig["allow"][number];

export type AllowOutcome = {
  readonly kept: Finding[];
  readonly allowHits: AllowHit[];
};

function scopePath(finding: Finding, repoDir: string): string | null {
  const rel = toRepoRelative(finding.path, repoDir);
  if (rel === null) return null;
  const bang = rel.indexOf("!");
  return bang === -1 ? rel : rel.slice(0, bang);
}

function entryMatches(entry: AllowEntry, finding: Finding, repoDir: string): boolean {
  if (!matchGlob(entry.rule, finding.rule)) return false;
  if (entry.file !== undefined) {
    const scoped = scopePath(finding, repoDir);
    if (scoped === null || !matchGlob(entry.file, scoped)) return false;
  }
  return matchGlob(entry.match, finding.valueDigest) || matchGlob(entry.match, finding.snippet);
}

function sampleOf(finding: Finding): string {
  return finding.path ?? finding.commit ?? finding.target;
}

/** Split `findings` into (kept, hits): kept preserves pipeline order; hits are
 * one row per entry that suppressed at least one finding, in entry order. */
export function applyAllowList(findings: readonly Finding[], allow: readonly AllowEntry[], repoDir: string): AllowOutcome {
  if (allow.length === 0) return { kept: [...findings], allowHits: [] };
  const kept: Finding[] = [];
  const hits = new Map<number, AllowHit>();
  for (const finding of findings) {
    let suppressedBy = -1;
    for (let i = 0; i < allow.length; i += 1) {
      const entry = allow[i];
      if (entry !== undefined && entryMatches(entry, finding, repoDir)) {
        suppressedBy = i;
        break;
      }
    }
    if (suppressedBy < 0) {
      kept.push(finding);
      continue;
    }
    const prev = hits.get(suppressedBy);
    if (prev === undefined) {
      const entry = allow[suppressedBy] as AllowEntry;
      hits.set(suppressedBy, { rule: entry.rule, count: 1, sample: sampleOf(finding), entryIndex: suppressedBy });
    } else {
      hits.set(suppressedBy, { ...prev, count: prev.count + 1 });
    }
  }
  return { kept, allowHits: [...hits.values()] };
}
