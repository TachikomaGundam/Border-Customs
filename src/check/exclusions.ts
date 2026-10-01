// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 10
//
// Exclusion mechanics. gitleaks has NO exclude flag, so every gitleaks finding
// is hard-filtered at INGEST here (never in the adapter): a finding whose path
// touches the `.border/` state dir cannot gate, because border itself writes
// that directory mid-run. The filter must normalise before matching because the
// two legs report different shapes — the git-history leg yields repo-relative
// paths, the dir/tree leg absolute ones, and archive reattribution appends
// `!<inner>` to the archive path. Segment-wise matching (`.border` as ANY path
// component, not a prefix) keeps the guard honest for subdirectory lookalikes
// and matches secretlint/aiArtifacts' own skip semantics. Report-level findings
// about `.border/` state still reach the verdict through the dedicated
// `repo-tracks-border-state` guard, so filtering here never silences a real leak.
import { resolve } from "node:path";

import type { Finding } from "../findings.ts";
import { BORDER_STATE_DIR } from "./lock.ts";

/** Rule-family prefix of secretlint's path heuristics (src/engines/secretlint.ts). */
export const PATH_PATTERN_RULE_PREFIX = "path-pattern:";

/** repo-relative form of a finding path; absolute paths under repoDir are stripped, others pass through. */
export function toRepoRelative(path: string | undefined, repoDir: string): string | null {
  if (path === undefined || path === "") return null;
  const abs = resolve(repoDir, path);
  const prefix = `${resolve(repoDir)}/`;
  return abs.startsWith(prefix) ? abs.slice(prefix.length) : path;
}

export function isBorderStatePath(repoRelPath: string | null): boolean {
  return repoRelPath !== null && repoRelPath.split("/").includes(BORDER_STATE_DIR);
}

export function filterBorderStateFindings(findings: readonly Finding[], repoDir: string): Finding[] {
  return findings.filter((f) => !isBorderStatePath(toRepoRelative(f.path, repoDir)));
}

/** The gate's own border.yaml FEEDS the path heuristics: rule IDs embed byte runs
 *  (`:\\`, `\\x\\`) the signatures detect, and digests are context-bound, so every
 *  allow-entry written to silence a self-hit mints fresh findings on the next scan
 *  (observed live 2026-10-02: 46 → 17 → no fixpoint). This filter exempts EXACTLY the
 *  file the run loaded its config from, and ONLY the path-pattern family — gitleaks,
 *  trufflehog, secretlint credential rules and identity history still scan the config,
 *  so stashing secrets in border.yaml keeps failing the gate. Suppressions are echoed
 *  as an INFO finding by the caller: exit 0 never hides what it hid. */
export function suppressGateConfigPathPatterns(
  findings: readonly Finding[],
  repoDir: string,
  configSource: string | undefined,
): { kept: Finding[]; suppressed: number } {
  const kept: Finding[] = [];
  let suppressed = 0;
  const cfgAbs = configSource === undefined ? "" : resolve(configSource);
  if (cfgAbs === "") return { kept: [...findings], suppressed: 0 };
  for (const f of findings) {
    const outer = (f.path ?? "").split("!")[0] ?? "";
    if (f.rule.startsWith(PATH_PATTERN_RULE_PREFIX) && outer !== "" && resolve(repoDir, outer) === cfgAbs) {
      suppressed += 1;
      continue;
    }
    kept.push(f);
  }
  return { kept, suppressed };
}
