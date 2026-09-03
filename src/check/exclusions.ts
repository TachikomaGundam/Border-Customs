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
