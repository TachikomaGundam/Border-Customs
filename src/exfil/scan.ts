// provenance: .omo/plans/border-exfil-lens.md T1 — scan surfaces for the native
// exfil legs: scanTreeText (blob/tree facet) and scanMessageText (commit
// message facet). Findings carry facet+channel attribution resolved through
// severity.ts's matrix — the ONLY emitter of severities in this package; the
// predicates in rules.ts decide detection, the matrix decides what is emitted
// where and how loud (plan §"分面契约").
//
// Native emission per the matrix:
//   * tree facet    → MEDIUM family only (home-path, cred-location,
//                     host-profile). The HIGH family's tree face belongs to
//                     the twin engines (T2); the v2 native double-emission
//                     was revoked, and a native tree rfc1918/ssh-target
//                     finding is UNREPRESENTABLE here (emitRulesFor returns
//                     none for those cells).
//   * message facet → all five rules under the `exfil-*:message` id family;
//                     attribution `source` is the commit sha, which the
//                     pipeline passes through toRepoRelative unchanged
//                     (exclusions.ts:20-25), enabling per-commit allow rows.
//   * tagNote facet → never scanned by the core (engine tag-message-secret
//                     leg owns it, tagScan.ts:26,101); there is deliberately
//                     no scanTagNoteText export.
//
// G23 masking invariant: the matched value leaves this module only as
// {valueDigest, snippet}. maskValue() mirrors redact.ts exactly (code-point
// based, ≤12 fully masked, else first4…last4) but is re-implemented locally
// because the import-audit pins src/exfil/** to node builtins + local files;
// the equivalence is pinned by a guard test against the real redact().
import { createHash } from "node:crypto";

import {
  emitRulesFor,
  exfilFindingId,
  EXFIL_SECRET_VALUE_RULES,
  observedSeverity,
  type ExfilChannel,
  type ExfilFacet,
  type ExfilRuleId,
  type ExfilSeverity,
} from "./severity.ts";
import {
  matchCredLocation,
  matchHomePath,
  matchMachineBinding,
  matchHostProfile,
  matchRfc1918,
  matchSshTarget,
  type RuleHit,
  type RuleOptions,
} from "./rules.ts";

/** Engine label for native exfil findings (mirrors "ai-artifacts" naming style). */
export const EXFIL_ENGINE = "border-exfil";

const FULL_MASK = "\u25ae\u25ae\u25ae\u25ae";
const ELLIPSIS = "\u2026";

/** redact.ts-equivalent masking (G23): sha256 digest + code-point-safe snippet. */
export function maskValue(value: string): { valueDigest: string; snippet: string } {
  const valueDigest = createHash("sha256").update(value, "utf8").digest("hex");
  const points = [...value];
  const snippet = points.length <= 12 ? FULL_MASK : `${points.slice(0, 4).join("")}${ELLIPSIS}${points.slice(-4).join("")}`;
  return { valueDigest, snippet };
}

export type ExfilScanInput = {
  /** the text being audited (blob content or one commit message). */
  readonly text: string;
  /** attribution: file path (tree) or commit sha (message). */
  readonly source: string;
  /** operator's rules.hosts (config.ts:102) for the ssh-target predicate. */
  readonly hosts?: readonly string[];
  /**
   * Ingest hook mirroring the redact.ts adapter contract ("every adapter
   * registers every value it ingests"): the check pipeline passes
   * (raw, digest) => sanitizer.register(digest, raw) so flagged literals are
   * scrubbed from all rendered text; stays local so the import-audit holds.
   */
  readonly onMatch?: (rawValue: string, valueDigest: string) => void;
};

export type ExfilFinding = {
  /** severity.ts-resolved id: bare rule on tree, `exfil-*:message` on messages. */
  readonly id: string;
  readonly rule: ExfilRuleId;
  readonly severity: ExfilSeverity;
  readonly facet: ExfilFacet;
  readonly channel: ExfilChannel;
  /** parity with Finding.engine: string (src/findings.ts); native legs stamp EXFIL_ENGINE. */
  readonly engine: string;
  readonly message: string;
  readonly source: string;
  readonly line: number;
  readonly valueDigest: string;
  readonly snippet: string;
};

const PREDICATES: Readonly<Record<ExfilRuleId, (text: string, o: RuleOptions) => RuleHit[]>> = {
  "exfil-rfc1918": matchRfc1918,
  "exfil-ssh-target": matchSshTarget,
  "exfil-home-path": matchHomePath,
  "exfil-cred-location": matchCredLocation,
  "exfil-host-profile": matchHostProfile,
  "exfil-machine-binding": matchMachineBinding,
};

/**
 * One emitter for both facets: iterate exactly the rules the matrix ALLOWS for
 * (facet × native), stamp severity from the same lookup (single source, no
 * re-decision), and mask the evidence. Deterministic order: line, then id,
 * then digest.
 */
function scanFacet(input: ExfilScanInput, facet: Extract<ExfilFacet, "tree" | "message">): ExfilFinding[] {
  const channel: ExfilChannel = "native";
  const options: RuleOptions = { facet, ...(input.hosts !== undefined ? { hosts: input.hosts } : {}) };
  const findings: ExfilFinding[] = [];
  for (const rule of emitRulesFor(facet, channel)) {
    const severity = observedSeverity(rule, facet, channel);
    if (severity === null) continue; // emitRulesFor excludes nulls; type narrowing kept honest.
    for (const hit of PREDICATES[rule](input.text, options)) {
      const { valueDigest, snippet } = maskValue(hit.matched);
      if (EXFIL_SECRET_VALUE_RULES.includes(rule)) input.onMatch?.(hit.matched, valueDigest); // F4: location class never registers
      findings.push({
        id: exfilFindingId(rule, facet),
        rule,
        severity,
        facet,
        channel,
        engine: EXFIL_ENGINE,
        message: hit.message,
        source: input.source,
        line: hit.line,
        valueDigest,
        snippet,
      });
    }
  }
  return findings.sort((a, b) => a.line - b.line || a.id.localeCompare(b.id) || a.valueDigest.localeCompare(b.valueDigest));
}

/** Native tree/blob leg: MEDIUM-family rules only, per the matrix (HIGH family = twins). */
export function scanTreeText(input: ExfilScanInput): ExfilFinding[] {
  return scanFacet(input, "tree");
}

/** Commit-message leg: all five rules under the `:message` id family, sha attribution. */
export function scanMessageText(input: ExfilScanInput): ExfilFinding[] {
  return scanFacet(input, "message");
}
