// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 6
//
// Optional TruffleHog adapter — invoked ONLY when engines.trufflehog:true.
// G41: border never vendors/bundles/links trufflehog; this spawns the
// user-provisioned binary exactly as the plan specifies:
//   trufflehog git file://<repo> --only-verified --fail --no-update --json
// Exit translation (fail-closed like gitleaks): 183 = verified findings
// (trufflehog's documented --fail code) ⇒ parse CRITICAL findings; 0 ⇒ clean;
// ANYTHING else ⇒ EngineRunError (border exit 2) — an interpreter error or an
// unknown exit code is never silently "clean".
// G23: the JSON-lines report is parsed from the in-memory stdout only — no
// raw engine output ever touches disk. Every Raw value goes through redact()
// and the optional TextSanitizer; Finding fields carry digest/snippet.
import { resolve } from "node:path";

import type { Finding } from "../findings.ts";
import { redact, type TextSanitizer } from "../redact.ts";
import {
  binaryCandidates,
  EngineRunError,
  spawnEngine,
  type EngineOptions,
} from "./support.ts";

export { EngineMissingError, EngineRunError as TrufflehogRunError } from "./support.ts";

export const TRUFFLEHOG_ENGINE = "trufflehog" as const;
/** trufflehog --fail exits 183 when verified findings exist (public docs). */
const VERIFIED_EXIT = 183;

export type TrufflehogScanOptions = EngineOptions & {
  repoDir: string;
  /** Finding.target label; the git leg is the only trufflehog source. */
  target?: string;
  sanitizer?: TextSanitizer;
};

type Rec = Record<string, unknown>;

function asRecord(value: unknown): Rec | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Rec)
    : null;
}

/** git block of SourceMetadata (v3: SourceMetadata.Data.Git; older: Source.Git) — null when absent. */
function gitMetadata(raw: Rec): Rec | null {
  const data = asRecord(asRecord(raw["SourceMetadata"])?.["Data"]);
  const modern = asRecord(data?.["Git"]);
  return modern ?? asRecord(asRecord(raw["Source"])?.["Git"]);
}

function stringField(rec: Rec | null, key: string): string | undefined {
  if (rec === null) return undefined;
  const v = rec[key];
  return typeof v === "string" && v !== "" ? v : undefined;
}

/** `trufflehog/<DetectorName>` normalized to findings-safe lowercase-dash slugs. */
export function ruleForDetector(detectorName: string): string {
  const slug = detectorName
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return `trufflehog/${slug === "" ? "unknown-detector" : slug}`;
}

function toFinding(line: string, o: TrufflehogScanOptions): Finding {
  let parsed: unknown;
  try {
    parsed = JSON.parse(line);
  } catch {
    throw new EngineRunError(
      "trufflehog --json produced an unparseable stdout line — border fails closed rather than trust a partial report",
      null,
    );
  }
  const raw = asRecord(parsed);
  if (raw === null) {
    throw new EngineRunError("trufflehog --json emitted a non-object report line", null);
  }
  const detector = stringField(raw, "DetectorName") ?? "unknown-detector";
  const rule = ruleForDetector(detector);
  const git = gitMetadata(raw);
  const path = stringField(git, "File");
  const commit = stringField(git, "Commit");
  const lineNo = git?.["Line"];
  const verified = raw["Verified"] === true;

  const rawValue = stringField(raw, "Raw");
  if (rawValue === undefined) {
    // A verified-live result without a value cannot be digested — refusing to
    // invent one keeps the G23 invariant provable instead of approximate.
    throw new EngineRunError(`trufflehog result for '${detector}' lacks a string Raw value`, null);
  }
  const { valueDigest, snippet } = redact(rawValue);
  o.sanitizer?.register(valueDigest, rawValue);
  return {
    rule,
    severity: "CRITICAL",
    target: o.target ?? "git",
    ...(path !== undefined ? { path } : {}),
    ...(typeof lineNo === "number" && Number.isInteger(lineNo) ? { line: lineNo } : {}),
    ...(commit !== undefined ? { commit } : {}),
    engine: TRUFFLEHOG_ENGINE,
    message:
      `${verified ? "Verified live" : "Unverified (engine contract violation under --only-verified)"} ${detector} credential reported by trufflehog`,
    valueDigest,
    snippet,
  };
}

/**
 * Run the git-history leg over `repoDir` with trufflehog's verified-only
 * detector set. Caller MUST have confirmed engines.trufflehog (policy probe in
 * ./policy.ts) — this function itself always spawns when invoked.
 */
export function scanTrufflehog(o: TrufflehogScanOptions): Finding[] {
  const args = [
    "git",
    `file://${resolve(o.repoDir)}`,
    "--only-verified",
    "--fail",
    "--no-update",
    "--json",
  ];
  const result = spawnEngine(binaryCandidates("trufflehog", o), args, { ...o });
  if (result.status !== 0 && result.status !== VERIFIED_EXIT) {
    throw new EngineRunError(
      `trufflehog exited ${String(result.status)}; only 0 (clean) and 183 (--fail verified findings) ` +
        "are translatable — any other code is a border exit-2 tool failure. " +
        `stderr: ${result.stderr.trim().slice(-400)}`,
      result.status,
    );
  }
  const findings: Finding[] = [];
  for (const line of result.stdout.split("\n")) {
    const trimmed = line.trim();
    if (trimmed === "") continue;
    findings.push(toFinding(trimmed, o));
  }
  return findings;
}

/** `trufflehog --version` output for the G21 rulesHash engineVersions map. */
export function trufflehogVersion(o: EngineOptions = {}): string {
  const result = spawnEngine(binaryCandidates("trufflehog", o), ["--version"], { ...o });
  if (result.status !== 0) {
    throw new EngineRunError(`trufflehog --version exited ${String(result.status)}`, result.status);
  }
  // some releases print the version banner to stderr — accept either stream
  return `${result.stdout}\n${result.stderr}`.trim();
}
