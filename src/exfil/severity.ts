// provenance: .omo/plans/border-exfil-lens.md T1 — the single home of the
// (rule × facet × channel → observed severity) matrix, plan §"分面契约" (R2).
//
// THE MATRIX IS THE PRODUCT DECISION and lives here and nowhere else; the
// later README rule table (T8) and the check-pipeline stages (T2/T3) render
// this table, they never re-decide it. Cell semantics:
//
//   * tree facet, twin channels — the HIGH family (exfil-rfc1918,
//     exfil-ssh-target) rides the vendored gitleaks TOML + secretlint border
//     patterns (T2 ships them with the ids VERBATIM equal to these rule ids).
//     Observed severity is CRITICAL, not the table HIGH, because that is the
//     channels' mechanical truth: gitleaks.ts:81 hardcodes severity
//     "CRITICAL" for every finding it ingests, and secretlint.ts severityOf
//     (299-309) maps error→CRITICAL with NO HIGH rung ("不硬掰，如实表").
//   * tree facet, native channel — the MEDIUM family (exfil-home-path,
//     exfil-cred-location, exfil-host-profile) only. The v2 native tree/blob
//     double-emission of the HIGH family was REVOKED in plan REV v3
//     ("撤销 v2 的 native 树/blob 双发 stage"): source-level elimination of
//     triple-firing. A null cell here is a FORBIDDEN emission, and the guard
//     tests pin it.
//   * message facet — native EXCLUSIVE (`exfil-*:message` id family, T3's
//     messageScan leg): all five rules at their table severity. The twins do
//     not scan commit messages; a (message, twin) cell is null.
//   * tagNote facet — owned by the EXISTING engine leg: the tagScan stdin leg
//     (tagScan.ts:26,101) rides the vendored TOML and re-labels every hit
//     `tag-message-secret` CRITICAL (path = the tag refname). The core
//     therefore NEVER scans tag notes and no exfil-* finding id may be
//     observed on this facet — every tagNote cell is null, eliminating
//     double-firing by construction. The `:message` family covers commit
//     messages only.
//
// Isolation note (plan §分面契约): allow-list entries are matched EXACTLY on
// the rule id (allow.ts:38 → matchGlob with no wildcards in a plain id), so a
// blob-face exemption `{rule: "exfil-rfc1918"}` never pierces the
// `exfil-rfc1918:message` id and vice versa — the ids are kept structurally
// distinct HERE (exfilFindingId) so the two families can never collide.
//
// Import-audit (plan §分面契约 last bullet): this directory imports only node
// builtins and local exfil files — hence the severity union is re-declared
// here instead of importing src/findings.ts; T2's pipeline maps these cells
// onto Finding verbatim, and the guard test pins ordering compatibility.

/** Mirrors SEVERITIES in src/findings.ts (re-declared: exfil core stays import-free). */
export const EXFIL_SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"] as const;
export type ExfilSeverity = (typeof EXFIL_SEVERITIES)[number];

/** The five exfil-lens rule ids, verbatim; twins must ship these ids byte-equal (T2 guard). */
export const EXFIL_RULE_IDS = [
  "exfil-rfc1918",
  "exfil-ssh-target",
  "exfil-home-path",
  "exfil-cred-location",
  "exfil-host-profile",
] as const;
export type ExfilRuleId = (typeof EXFIL_RULE_IDS)[number];

/** Message-facet attribution id family, e.g. "exfil-rfc1918:message" (plan §分面契约 row 2). */
export const EXFIL_MESSAGE_ID_SUFFIX = ":message";
export type ExfilMessageRuleId = `${ExfilRuleId}:message`;

export const EXFIL_FACETS = ["tree", "message", "tagNote"] as const;
export type ExfilFacet = (typeof EXFIL_FACETS)[number];

export const EXFIL_CHANNELS = ["native", "gitleaks-twin", "secretlint-twin"] as const;
export type ExfilChannel = (typeof EXFIL_CHANNELS)[number];

/** Intent severities from the plan's 规则语义表 (what the rule means, before channel mechanics). */
export const EXFIL_TABLE_SEVERITY: Readonly<Record<ExfilRuleId, ExfilSeverity>> = {
  "exfil-rfc1918": "HIGH",
  "exfil-ssh-target": "HIGH",
  "exfil-home-path": "MEDIUM",
  "exfil-cred-location": "MEDIUM",
  "exfil-host-profile": "MEDIUM",
};

/** HIGH family: the two identity-carrying location rules; tree face belongs to the twins. */
export const EXFIL_HIGH_FAMILY: readonly ExfilRuleId[] = ["exfil-rfc1918", "exfil-ssh-target"];
/** MEDIUM family: privacy-shape rules; native carries them on both scanned facets. */
export const EXFIL_MEDIUM_FAMILY: readonly ExfilRuleId[] = ["exfil-home-path", "exfil-cred-location", "exfil-host-profile"];

/** null = FORBIDDEN cell: that channel must never emit that rule on that facet. */
export type ObservedSeverity = ExfilSeverity | null;

const TWIN_HIGH: Readonly<Record<ExfilRuleId, ObservedSeverity>> = {
  "exfil-rfc1918": "CRITICAL",
  "exfil-ssh-target": "CRITICAL",
  "exfil-home-path": null,
  "exfil-cred-location": null,
  "exfil-host-profile": null,
};
const NULL_ROW: Readonly<Record<ExfilRuleId, ObservedSeverity>> = {
  "exfil-rfc1918": null,
  "exfil-ssh-target": null,
  "exfil-home-path": null,
  "exfil-cred-location": null,
  "exfil-host-profile": null,
};

/** The full (facet × channel × rule) truth table — the plan's 分面契约, machine-readable. */
export const EXFIL_MATRIX: Readonly<Record<ExfilFacet, Readonly<Record<ExfilChannel, Readonly<Record<ExfilRuleId, ObservedSeverity>>>>>> = {
  tree: {
    // native tree leg = MEDIUM family补发 only (v2 double-emission revoked).
    native: { ...NULL_ROW, "exfil-home-path": "MEDIUM", "exfil-cred-location": "MEDIUM", "exfil-host-profile": "MEDIUM" },
    // gitleaks.ts:81 hardcodes CRITICAL for every ingested finding.
    "gitleaks-twin": TWIN_HIGH,
    // secretlint.ts:299-309 has no HIGH rung — error maps to CRITICAL as-is.
    "secretlint-twin": TWIN_HIGH,
  },
  message: {
    // native-exclusive `:message` family at table severity.
    native: { ...EXFIL_TABLE_SEVERITY },
    "gitleaks-twin": NULL_ROW,
    "secretlint-twin": NULL_ROW,
  },
  tagNote: {
    // engine既有腿 owns this facet as `tag-message-secret` (a non-exfil id);
    // NO exfil-* emission is legal on tag notes through ANY channel.
    native: NULL_ROW,
    "gitleaks-twin": NULL_ROW,
    "secretlint-twin": NULL_ROW,
  },
};

/** Observed severity for one (rule × facet × channel) cell; null = that emission is forbidden. */
export function observedSeverity(rule: ExfilRuleId, facet: ExfilFacet, channel: ExfilChannel): ObservedSeverity {
  return EXFIL_MATRIX[facet][channel][rule];
}

/** Every rule a (facet × channel) combination is ALLOWED to emit, in EXFIL_RULE_IDS order. */
export function emitRulesFor(facet: ExfilFacet, channel: ExfilChannel): readonly ExfilRuleId[] {
  return EXFIL_RULE_IDS.filter((rule) => observedSeverity(rule, facet, channel) !== null);
}

/**
 * The finding id for a (rule × facet) pair: the `:message` family ONLY on the
 * message facet; tree/tagNote carry the bare rule id (the id must stay
 * exactly "exfil-*" for the twin-id-equality and blob-face allow-list match).
 */
export function exfilFindingId(rule: ExfilRuleId, facet: ExfilFacet): string {
  switch (facet) {
    case "message":
      return `${rule}${EXFIL_MESSAGE_ID_SUFFIX}`;
    case "tree":
    case "tagNote":
      return rule;
  }
}
