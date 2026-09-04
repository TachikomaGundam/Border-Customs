// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 7
//
// The single source of the border exit-code contract (plan G11):
//   0 = pass (MEDIUM/INFO/LOW warnings allowed)
//   1 = gate-blocked (CRITICAL/HIGH — predicate single-sourced in findings.isBlocking,
//       todo 3) or a partial push
//   2 = config/tool error (bad config, missing/broken engine, unreachable registry,
//       malformed ingest, unknown CLI arguments)
// The table below also pins the adapter-native translations from G11: gitleaks
// 0⇒clean, 1⇒findings, ANY other code incl. 126 (usage error) ⇒ 2 — never 126 as
// "clean" (round-3 B1.4); trufflehog 183(findings)⇒findings; secretlint 2⇒2.
import { ConfigError } from "../config.ts";
import { EnginePolicyError } from "../engines/policy.ts";
import { InvalidFindingError, isBlocking, type Finding, type Verdict } from "../findings.ts";
import { EngineMissingError, EngineRunError } from "../engines/support.ts";
import { sanitizeUrl } from "../redact.ts";

export const EXIT_PASS = 0;
export const EXIT_BLOCKED = 1;
export const EXIT_ERROR = 2;

export type BorderExit = typeof EXIT_PASS | typeof EXIT_BLOCKED | typeof EXIT_ERROR;

/** An engine's native code means "it found findings" — the verdict decides 0 vs 1. */
export type FindingsShaped = "findings";

/** Unknown/malformed CLI argument — a tool error, never a silent ignore. */
export class UnknownArgError extends Error {
  override readonly name = "UnknownArgError";
  readonly exitCode: 2 = 2;
}

export type EngineExitRow = {
  readonly engine: string;
  readonly code: number;
  readonly meaning: string;
  readonly border: BorderExit | FindingsShaped;
};

/** G11 adapter-native matrix. translateEngineCode below is derived from these rows. */
export const ENGINE_EXIT_TABLE: readonly EngineExitRow[] = [
  { engine: "gitleaks", code: 0, meaning: "clean tree/history", border: EXIT_PASS },
  { engine: "gitleaks", code: 1, meaning: "findings reported", border: "findings" },
  { engine: "gitleaks", code: 126, meaning: "usage/syntax error — never 'clean' (round-3 B1.4)", border: EXIT_ERROR },
  { engine: "trufflehog", code: 0, meaning: "clean", border: EXIT_PASS },
  { engine: "trufflehog", code: 183, meaning: "findings reported", border: "findings" },
  { engine: "secretlint", code: 0, meaning: "clean", border: EXIT_PASS },
  { engine: "secretlint", code: 1, meaning: "lint messages reported", border: "findings" },
  { engine: "secretlint", code: 2, meaning: "tool/config failure", border: EXIT_ERROR },
];

/**
 * Map an engine's native exit code. ANY code not explicitly translatable —
 * unknown engine, gitleaks 2..∞, trufflehog 1, signal-killed (null) — is 2:
 * border fails closed and never reads silence as "clean".
 */
export function translateEngineCode(engine: string, code: number): BorderExit | FindingsShaped {
  for (const row of ENGINE_EXIT_TABLE) {
    if (row.engine === engine && row.code === code) return row.border;
  }
  return EXIT_ERROR;
}

/** Verdict-side of G11: blocked iff any finding trips findings.isBlocking. */
export function exitCodeFromFindings(findings: readonly Finding[]): BorderExit {
  return findings.some((f) => isBlocking(f.severity)) ? EXIT_BLOCKED : EXIT_PASS;
}

/** Report-side of G11: NO-OP (nothing exposed to scan) passes with a loud warning. */
export function exitCodeFromVerdict(verdict: Verdict): BorderExit {
  return verdict === "FAIL" ? EXIT_BLOCKED : EXIT_PASS;
}

// ---------------------------------------------------------------- translateError

const MESSAGE_CAP = 512;

// URL-ish substrings inside free-form error text get credential-scrubbed via
// the todo-3 sanitizer; the surrounding prose survives. Bare `user@host:path`
// scp remotes and scheme URLs both match; plain paths never do.
const URL_IN_TEXT_RE = /(?:\w+:\/\/\S+|[A-Za-z0-9_.+-]+@[A-Za-z0-9_.+-]+:\S+)/g;

function sanitizeMessage(message: string): string {
  const oneLine = message.replace(/\s+/g, " ").trim();
  const scrubbed = oneLine.replace(URL_IN_TEXT_RE, (candidate) => sanitizeUrl(candidate));
  return scrubbed.length > MESSAGE_CAP ? `${scrubbed.slice(0, MESSAGE_CAP - 3)}...` : scrubbed;
}

function labelFor(err: unknown): string | undefined {
  if (err instanceof ConfigError) return "config error";
  if (err instanceof EnginePolicyError) return "engine policy error";
  if (err instanceof EngineRunError) return "engine run error";
  if (err instanceof EngineMissingError) return "engine missing";
  if (err instanceof UnknownArgError) return "argument error";
  if (err instanceof InvalidFindingError) return "malformed finding";
  const code = (err as NodeJS.ErrnoException | undefined)?.code;
  if (code === "EACCES" || code === "EPERM") return "permission denied";
  if (code === "ENOENT") return "spawn failed (binary missing)";
  if (err instanceof Error) return "unexpected error";
  return "unexpected failure";
}

/**
 * One-line sanitized stderr translation for every typed failure the CLI may
 * surface. All of these are border exit 2 per G11; credentials in embedded
 * URLs are stripped and newlines collapsed so a failure can never smuggle a
 * secret or a multi-line stack into operator logs.
 */
export function translateError(err: unknown): { readonly code: typeof EXIT_ERROR; readonly message: string } {
  const label = labelFor(err);
  const detail = err instanceof Error ? err.message : String(err);
  return { code: EXIT_ERROR, message: `${label}: ${sanitizeMessage(detail)}` };
}
