// provenance: original clean-room scaffold, no external code copied
//
// Findings model — the single source of truth for the gate's severity
// semantics. The severity ordering, the isBlocking() gate rule, and the
// Report shape live HERE only; later todos import them rather than re-decide
// (G11 exit-code matrix, todos 7/14/17 consume isBlocking()).
//
// erasableSyntaxOnly forbids TS enums, so Severity is a union of string
// literals backed by the SEVERITIES tuple; SEVERITY_ORDER gives an ordinal
// for sorting when a later todo needs it.

export const SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"] as const;
export type Severity = (typeof SEVERITIES)[number];

export const SEVERITY_ORDER: Readonly<Record<Severity, number>> = {
  INFO: 0,
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
};

/**
 * GATE RULE — the only place the blocking decision is defined.
 *
 * CRITICAL and HIGH block the push; MEDIUM, LOW and INFO are warnings.
 * Every consumer (exit codes, verdict computation, rendering) must call this
 * function; never re-code `severity === "HIGH"` anywhere else.
 */
export function isBlocking(severity: Severity): boolean {
  return severity === "HIGH" || severity === "CRITICAL";
}

export type Finding = {
  rule: string;
  severity: Severity;
  target: string;
  path?: string;
  line?: number;
  commit?: string;
  engine: string;
  message: string;
  /** hex sha256 of the matched raw value (G23: never the raw value itself). */
  valueDigest: string;
  /** masking-invariant output of redact(); safe to persist and print. */
  snippet: string;
};

export type Verdict = "PASS" | "FAIL" | "NO-OP";

/**
 * G14 allow-list provenance: one row per border.yaml `allow` entry that
 * actually suppressed findings this run. The report NEVER omits a suppression
 * silently — `findings` carries only what survived the post-filter, and this
 * ledger of what was dropped (count + one sample location + the entry index
 * into cfg.allow) rides beside it. Additive optional field: schemaVersion
 * stays 1 and consumers written before todo 19 keep parsing every byte.
 */
export type AllowHit = {
  /** the allow entry's rule glob verbatim (category identity for review). */
  rule: string;
  /** number of findings this entry suppressed. */
  count: number;
  /** first suppressed finding's path, else commit, else target (review sample). */
  sample: string;
  /** 0-based index into cfg.allow — resolves match/file/justification in border.yaml. */
  entryIndex: number;
};

export type ReportCounts = {
  [S in Severity]: number;
} & {
  total: number;
  /** HIGH + CRITICAL findings. */
  blocking: number;
  /** MEDIUM + LOW + INFO findings. */
  warnings: number;
};

export type Report = {
  schemaVersion: 1;
  key: string;
  head: string;
  dirty: boolean;
  /** sanitized URLs of every exposed location (userinfo stripped). */
  exposureSet: readonly string[];
  /** local refs and remote names the push would touch. */
  refSet: readonly string[];
  /** G21 fingerprint from computeRulesHash(). */
  rulesHash: string;
  verdict: Verdict;
  counts: ReportCounts;
  findings: readonly Finding[];
  /** G14: present (non-empty) only when the allow post-filter suppressed findings. */
  allowHits?: readonly AllowHit[];
  /** ISO-8601 timestamp of report creation. */
  ts: string;
};

/** FAIL iff at least one finding is blocking; otherwise PASS. NO-OP is a caller decision. */
export function computeVerdict(findings: readonly Finding[]): "PASS" | "FAIL" {
  return findings.some((f) => isBlocking(f.severity)) ? "FAIL" : "PASS";
}

export function countFindings(findings: readonly Finding[]): ReportCounts {
  const perSeverity: Record<Severity, number> = { INFO: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
  for (const f of findings) {
    perSeverity[f.severity] += 1;
  }
  const blocking = perSeverity.HIGH + perSeverity.CRITICAL;
  const warnings = perSeverity.INFO + perSeverity.LOW + perSeverity.MEDIUM;
  return { ...perSeverity, total: findings.length, blocking, warnings };
}

export class InvalidFindingError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InvalidFindingError";
  }
}

const HEX_SHA256 = /^[0-9a-f]{64}$/;

/**
 * Runtime validator for findings ingested from outside the process
 * (llm-ingest, report.json re-load). Throws InvalidFindingError on the first
 * malformed field; accepts well-formed findings unchanged.
 */
export function validateFinding(value: unknown): Finding {
  if (typeof value !== "object" || value === null) {
    throw new InvalidFindingError("finding must be an object");
  }
  const o = value as Record<string, unknown>;

  const expectString = (field: string): string => {
    const v = o[field];
    if (typeof v !== "string") {
      throw new InvalidFindingError(`finding.${field} must be a string, got ${typeof v}`);
    }
    return v;
  };

  const severity = expectString("severity");
  if (!(SEVERITIES as readonly string[]).includes(severity)) {
    throw new InvalidFindingError(`finding.severity must be one of ${SEVERITIES.join("|")}, got '${severity}'`);
  }
  const valueDigest = expectString("valueDigest");
  if (!HEX_SHA256.test(valueDigest)) {
    throw new InvalidFindingError("finding.valueDigest must be 64 lowercase hex characters");
  }
  for (const field of ["path", "commit"] as const) {
    if (o[field] !== undefined && typeof o[field] !== "string") {
      throw new InvalidFindingError(`finding.${field} must be a string when present`);
    }
  }
  if (o.line !== undefined && (typeof o.line !== "number" || !Number.isInteger(o.line))) {
    throw new InvalidFindingError("finding.line must be an integer when present");
  }
  for (const field of ["rule", "target", "engine", "message", "snippet"] as const) {
    expectString(field);
  }
  return value as Finding;
}