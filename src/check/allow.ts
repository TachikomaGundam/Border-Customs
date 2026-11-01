// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 19
//
// G14 allow post-filter — the pipeline tail that turns cfg.allow entries into
// suppressed findings + enumerated allow-hits. Runs AFTER every engine/native
// leg and BEFORE verdict/counts, so a suppressed finding can neither block the
// gate nor vanish unrecorded. Matching contract:
//   entry.rule  — `*`/`?` glob (identity.matchGlob, the project's single glob
//                 dialect) against Finding.rule, and (rules.aliases) against
//                 every old name the current rule migrated from;
//   entry.match — same glob against Finding.valueDigest (exact, preferred:
//                 64-hex pins one value) OR Finding.snippet (shape pin; safe
//                 because snippets are the masked view, never the raw value);
//   entry.values — list of 64-hex value digests; one entry waives a fixture
//                 set while ANY value outside the list stays red (HR decoupling
//                 safety floor: waivers never cover "new file, new value");
//   entry.file  — same glob against the repo-relative finding path with any
//                 archive `!<inner>` attribution stripped, EXCEPT when the
//                 entry spells `\!` — then the full attributed path matches and
//                 archive members become addressable (HR demand 3);
//   entry.until — UTC `YYYY-MM-DD` sunset; past that date the entry is inert
//                 and enumerated in AllowOutcome.expiredEntries, never silently
//                 honored.
// A finding without a path (identity, engine-policy) can never match a
// file-scoped entry. Blanket `{rule:"*"}` / `{match:"*"}` shapes are rejected
// at CONFIG LOAD (src/config.ts), so every suppression traces to a concrete,
// authored entry. First matching entry wins (config order = precedence) —
// expired entries are skipped and cannot shadow a live entry behind them.
import type { BorderConfig } from "../config.ts";
import type { AllowHit, Finding } from "../findings.ts";
import { matchGlob } from "../rules/identity.ts";
import { toRepoRelative } from "./exclusions.ts";

type AllowEntry = BorderConfig["allow"][number];
type RuleAliases = NonNullable<BorderConfig["rules"]["aliases"]>;

export type AllowOutcome = {
  readonly kept: Finding[];
  readonly allowHits: AllowHit[];
  /** config-order indices of entries whose `until` date has passed (never applied). */
  readonly expiredEntries: number[];
};

function utcDate(): string {
  return new Date().toISOString().slice(0, 10);
}

function pathScopeMatches(entryFile: string, finding: Finding, repoDir: string): boolean {
  const rel = toRepoRelative(finding.path, repoDir);
  if (rel === null) return false;
  if (entryFile.includes("\\!")) {
    return matchGlob(entryFile.split("\\!").join("!"), rel);
  }
  const bang = rel.indexOf("!");
  return matchGlob(entryFile, bang === -1 ? rel : rel.slice(0, bang));
}

function ruleMatches(entryRule: string, findingRule: string, aliases: RuleAliases): boolean {
  if (matchGlob(entryRule, findingRule)) return true;
  for (const [oldName, currentName] of Object.entries(aliases)) {
    if (currentName === findingRule && matchGlob(entryRule, oldName)) return true;
  }
  return false;
}

function entryMatches(entry: AllowEntry, finding: Finding, repoDir: string, aliases: RuleAliases): boolean {
  if (!ruleMatches(entry.rule, finding.rule, aliases)) return false;
  if (entry.file !== undefined && !pathScopeMatches(entry.file, finding, repoDir)) return false;
  if (entry.values !== undefined && entry.values.includes(finding.valueDigest)) return true;
  return (
    entry.match !== undefined &&
    (matchGlob(entry.match, finding.valueDigest) || matchGlob(entry.match, finding.snippet))
  );
}

function sampleOf(finding: Finding): string {
  return finding.path ?? finding.commit ?? finding.target;
}

/** Split `findings` into (kept, hits): kept preserves pipeline order; hits are
 * one row per entry that suppressed at least one finding, in entry order. */
export function applyAllowList(
  findings: readonly Finding[],
  allow: readonly AllowEntry[],
  repoDir: string,
  aliases: RuleAliases = {},
): AllowOutcome {
  if (allow.length === 0) return { kept: [...findings], allowHits: [], expiredEntries: [] };
  const today = utcDate();
  const expiredEntries: number[] = [];
  const live: { index: number; entry: AllowEntry }[] = [];
  allow.forEach((entry, index) => {
    if (entry.until !== undefined && entry.until < today) expiredEntries.push(index);
    else live.push({ index, entry });
  });
  const kept: Finding[] = [];
  const hits = new Map<number, AllowHit>();
  for (const finding of findings) {
    let suppressedBy = -1;
    for (const { index, entry } of live) {
      if (entryMatches(entry, finding, repoDir, aliases)) {
        suppressedBy = index;
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
  return { kept, allowHits: [...hits.values()], expiredEntries };
}
