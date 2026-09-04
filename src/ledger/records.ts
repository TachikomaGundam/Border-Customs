// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 14
//
// The ledger record schema and its corruption-tolerant reader/writer. Parsing
// is the trust boundary: `.border/ledger.jsonl` may be hand-edited or
// half-written (SIGKILL mid-append leaves a torn last line), so every line is
// validated into a typed record and anything malformed is SKIPPED with a
// warning — never a crash, never silent (plan failure AC). Records are
// append-only: no API here rewrites or deletes past lines. The push record
// constructor is the single place a url enters the ledger, so G20 sanitation
// (sanitizeUrl) cannot be forgotten by consumers (todos 15/16/17).
import { appendFileSync, readFileSync } from "node:fs";
import { join } from "node:path";

import type { ReportCounts } from "../findings.ts";
import { sanitizeUrl } from "../redact.ts";
import { BORDER_STATE_DIR, ensureStateDir } from "../check/lock.ts";

export const LEDGER_FILE = "ledger.jsonl";
export const RUNS_SUBDIR = "runs";

const HEX64 = /^[0-9a-f]{64}$/;
const HEX40 = /^[0-9a-f]{40}$/; // git SHA-1 commit ids
const HEX8 = /^[0-9a-f]{8}$/;

export type LedgerArtifact = { readonly file: string; readonly sha256: string };

export type CheckRecord = {
  readonly t: "check";
  readonly key: string;
  readonly key8: string;
  readonly head: string;
  readonly dirtyDigest: string;
  readonly refSetHash: string;
  readonly exposureSet: readonly string[];
  readonly effectiveTargets: readonly string[];
  readonly rulesHash: string;
  readonly artifacts: readonly LedgerArtifact[] | null;
  readonly llm: boolean;
  readonly verdict: "PASS" | "FAIL";
  readonly counts: ReportCounts;
  /** repo-relative path of the archived report.json, e.g. `.border/runs/<key8>-<ts>/report.json`. */
  readonly reportPath: string;
  readonly degraded: false;
  readonly ts: string;
};

export const PUSH_CONFIRMED_VIA = ["ls-remote", "npm-view", "pypi-json"] as const;
export type PushConfirmedVia = (typeof PUSH_CONFIRMED_VIA)[number];

/** G20 proof-of-push record; consumed by todos 15/16/17 (push state machine, status). */
export type PushRecord = {
  readonly t: "push";
  readonly key: string;
  readonly target: string;
  readonly remoteName: string;
  readonly url: string;
  readonly localSha: string;
  readonly remoteSha?: string;
  readonly version?: string;
  readonly confirmedVia: PushConfirmedVia;
  readonly ts: string;
};

export type LedgerRecord = CheckRecord | PushRecord;

export function ledgerPath(repoDir: string): string {
  return join(repoDir, BORDER_STATE_DIR, LEDGER_FILE);
}

export function runsDir(repoDir: string): string {
  return join(repoDir, BORDER_STATE_DIR, RUNS_SUBDIR);
}

/** The plan's exact skip provenance line (D6): `SKIP <key8> — PASS <ISO ts> report <path>`. */
export function formatSkipLine(record: CheckRecord): string {
  return `SKIP ${record.key8} — PASS ${record.ts} report ${record.reportPath}`;
}

/** Push records are constructed here so the url can never land unsanitized (G20). */
export function buildPushRecord(i: {
  readonly key: string;
  readonly target: string;
  readonly remoteName: string;
  readonly url: string;
  readonly localSha: string;
  readonly remoteSha?: string;
  readonly version?: string;
  readonly confirmedVia: PushConfirmedVia;
  readonly ts?: string;
}): PushRecord {
  return {
    t: "push",
    key: i.key,
    target: i.target,
    remoteName: i.remoteName,
    url: sanitizeUrl(i.url),
    localSha: i.localSha,
    ...(i.remoteSha !== undefined ? { remoteSha: i.remoteSha } : {}),
    ...(i.version !== undefined ? { version: i.version } : {}),
    confirmedVia: i.confirmedVia,
    ts: i.ts ?? new Date().toISOString(),
  };
}

// ---------------------------------------------------------------- validation

function bad(msg: string): never {
  throw new Error(msg);
}

function needString(o: Record<string, unknown>, field: string): string {
  const v = o[field];
  if (typeof v !== "string" || v === "") bad(`${field} must be a non-empty string`);
  return v as string;
}

function needHex(o: Record<string, unknown>, field: string, re: RegExp): string {
  const v = needString(o, field);
  if (!re.test(v)) bad(`${field} is not hex-shaped`);
  return v;
}

function needStringArray(o: Record<string, unknown>, field: string): string[] {
  const v = o[field];
  if (!Array.isArray(v) || !v.every((x) => typeof x === "string")) bad(`${field} must be an array of strings`);
  return v as string[];
}

function parseCounts(value: unknown): ReportCounts {
  if (typeof value !== "object" || value === null) bad("counts must be an object");
  const o = value as Record<string, unknown>;
  for (const field of ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL", "total", "blocking", "warnings"] as const) {
    if (typeof o[field] !== "number" || !Number.isInteger(o[field])) bad(`counts.${field} must be an integer`);
  }
  return o as unknown as ReportCounts;
}

function parseArtifacts(o: Record<string, unknown>): readonly LedgerArtifact[] | null {
  if (o.artifacts === null) return null;
  const v = o.artifacts;
  if (!Array.isArray(v)) bad("artifacts must be null or an array");
  return (v as unknown[]).map((item, i) => {
    if (typeof item !== "object" || item === null) bad(`artifacts[${String(i)}] must be an object`);
    const a = item as Record<string, unknown>;
    return { file: needString(a, "file"), sha256: needHex(a, "sha256", HEX64) };
  });
}

/** Runtime parse of one ledger line into a typed record; throws on any malformed field. */
export function parseLedgerRecord(value: unknown): LedgerRecord {
  if (typeof value !== "object" || value === null) bad("record must be an object");
  const o = value as Record<string, unknown>;
  const t = o.t;
  if (t === "check") {
    const key = needHex(o, "key", HEX64);
    const key8 = needHex(o, "key8", HEX8);
    if (key.slice(0, 8) !== key8) bad("key8 must be the first 8 hex chars of key");
    const verdict = needString(o, "verdict");
    if (verdict !== "PASS" && verdict !== "FAIL") bad(`verdict must be PASS or FAIL, got '${verdict}'`);
    if (o.degraded !== false) bad("degraded must be false — degraded runs are never ledgered");
    if (typeof o.llm !== "boolean") bad("llm must be a boolean");
    return {
      t: "check",
      key,
      key8,
      head: needHex(o, "head", HEX40),
      dirtyDigest: needHex(o, "dirtyDigest", HEX64),
      refSetHash: needHex(o, "refSetHash", HEX64),
      exposureSet: needStringArray(o, "exposureSet"),
      effectiveTargets: needStringArray(o, "effectiveTargets"),
      rulesHash: needHex(o, "rulesHash", HEX64),
      artifacts: parseArtifacts(o),
      llm: o.llm,
      verdict,
      counts: parseCounts(o.counts),
      reportPath: needString(o, "reportPath"),
      degraded: false,
      ts: needString(o, "ts"),
    };
  }
  if (t === "push") {
    const confirmedVia = needString(o, "confirmedVia");
    if (!(PUSH_CONFIRMED_VIA as readonly string[]).includes(confirmedVia)) {
      bad(`confirmedVia must be one of ${PUSH_CONFIRMED_VIA.join("|")}`);
    }
    const remoteSha = o.remoteSha;
    const version = o.version;
    if (remoteSha === undefined && version === undefined) bad("push record needs remoteSha or version");
    if (remoteSha !== undefined && typeof remoteSha !== "string") bad("remoteSha must be a string");
    if (version !== undefined && typeof version !== "string") bad("version must be a string");
    return {
      t: "push",
      key: needHex(o, "key", HEX64),
      target: needString(o, "target"),
      remoteName: needString(o, "remoteName"),
      url: needString(o, "url"),
      localSha: needString(o, "localSha"),
      ...(remoteSha !== undefined ? { remoteSha } : {}),
      ...(version !== undefined ? { version } : {}),
      confirmedVia: confirmedVia as PushConfirmedVia,
      ts: needString(o, "ts"),
    };
  }
  return bad(`unknown record type ${JSON.stringify(t)}`);
}

// ---------------------------------------------------------------- read / append

function codeOf(err: unknown): string | undefined {
  return typeof err === "object" && err !== null ? (err as { code?: string }).code : undefined;
}

export type LedgerRead = { readonly records: readonly LedgerRecord[]; readonly warnings: readonly string[] };

/** Missing file ⇒ empty ledger; malformed lines ⇒ WARNING + skip, never a crash. */
export function readLedger(repoDir: string): LedgerRead {
  let text: string;
  try {
    text = readFileSync(ledgerPath(repoDir), "utf8");
  } catch (err) {
    if (codeOf(err) === "ENOENT") return { records: [], warnings: [] };
    throw err;
  }
  const records: LedgerRecord[] = [];
  const warnings: string[] = [];
  text.split("\n").forEach((line, i) => {
    if (line.trim() === "") return;
    try {
      records.push(parseLedgerRecord(JSON.parse(line) as unknown));
    } catch (err) {
      const reason = err instanceof Error ? err.message : String(err);
      warnings.push(`ledger line ${String(i + 1)} unreadable (${reason.slice(0, 160)}) — line skipped`);
    }
  });
  return { records, warnings };
}

/** Single-buffer O_APPEND write of exactly one line — no torn records. */
export function appendRecord(repoDir: string, record: LedgerRecord): void {
  ensureStateDir(repoDir);
  appendFileSync(ledgerPath(repoDir), `${JSON.stringify(record)}\n`, "utf8");
}

// ---------------------------------------------------------------- queries

/** Newest check-record for key, ANY verdict — the reference point for skip authority. */
function newestRecordOf(records: readonly LedgerRecord[], key: string): CheckRecord | null {
  for (let i = records.length - 1; i >= 0; i -= 1) {
    const r = records[i] as LedgerRecord;
    if (r.t === "check" && r.key === key) return r;
  }
  return null;
}

function isSkippable(r: CheckRecord | null): r is CheckRecord {
  return r !== null && r.verdict === "PASS" && r.degraded === false;
}

/**
 * Skip authority (plan lookup clause): the NEWEST record with matching key must be
 * PASS, non-degraded, and same llm mode (round-1 m7). Reading "newest PASS record"
 * past a later FAIL would re-certify a state that was just blocked — the newest
 * record for the key is the only verdict that counts.
 */
export function lookupSkipRecord(records: readonly LedgerRecord[], key: string, llm: boolean): CheckRecord | null {
  const newest = newestRecordOf(records, key);
  return isSkippable(newest) && newest.llm === llm ? newest : null;
}

/** Push-scope rule (round-1 B2): the newest PASS under key whose effectiveTargets cover all requested. */
export function latestPassCoveringTargets(
  records: readonly LedgerRecord[],
  key: string,
  targets: readonly string[],
): CheckRecord | null {
  const newest = newestRecordOf(records, key);
  return isSkippable(newest) && targets.every((t) => newest.effectiveTargets.includes(t)) ? newest : null;
}

export function pushRecords(records: readonly LedgerRecord[], key?: string): PushRecord[] {
  return records.filter((r): r is PushRecord => r.t === "push" && (key === undefined || r.key === key));
}
