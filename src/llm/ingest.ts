// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 18
//
// `border llm-ingest <findings.json>`: the trust boundary for agent-authored
// findings. EVERY item is validated against the C1 Finding schema (plus the
// rule slug regex and the bundle's file list — an unknown path is a
// `finding-unknown-location`, never a finding about nowhere), the agent's free
// text is scrubbed through the same gitleaks-detector masker the bundle used
// (a pasted secret becomes its [REDACTED:<sha8>] token before it can be
// persisted), engine is FORCED to "agent" and valueDigest is computed here —
// never taken from input. Verdict is recomputed over deterministic + agent
// findings and persisted via the todo-14 seam: report.json into a run dir and
// an {llm:true} ledger record (which can never satisfy a plain-check skip —
// lookupSkipRecord matches on record.llm === q.llm).
import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { isAbsolute, join, resolve } from "node:path";

import { loadConfig } from "../config.ts";
import { computeEffectiveTargets, gatherContext, resolveRepoDir } from "../check/context.ts";
import { stableStringify } from "../check/rulesHash.ts";
import { recordCheckRun, runsDir } from "../ledger.ts";
import { EXIT_ERROR, exitCodeFromVerdict, type BorderExit } from "../cli/exit.ts";
import type { Ctx } from "../cli/types.ts";
import { countFindings, computeVerdict, SEVERITIES, validateFinding, type Finding, type Report, type Severity } from "../findings.ts";
import { redact } from "../redact.ts";
import type { LlmRequestBundle } from "./bundle.ts";
import { maskViaEngineDetection } from "./diff.ts";

const RULE_RE = /^[a-z0-9-]+$/;
const MAX_TEXT = 4000;
const ALLOWED_KEYS = new Set(["rule", "severity", "target", "path", "line", "commit", "message", "snippet", "engine", "valueDigest"]);

function sha256(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

function usageError(ctx: Ctx, why: string): BorderExit {
  ctx.stderr(`border: llm-ingest: ${why}`);
  return EXIT_ERROR;
}

function findLatestBundle(repoDir: string): { readonly dir: string; readonly bundle: LlmRequestBundle } | string {
  let dirs: string[] = [];
  try {
    dirs = readdirSync(runsDir(repoDir));
  } catch {
    return "no llm-request bundle found — run 'border llm-request' first";
  }
  for (const d of dirs.sort().reverse()) {
    const p = join(runsDir(repoDir), d, "llm-request.json");
    if (!existsSync(p)) continue;
    let parsed: unknown;
    try {
      parsed = JSON.parse(readFileSync(p, "utf8")) as unknown;
    } catch (err) {
      return `bundle ${p} is not valid JSON (${err instanceof Error ? err.message : String(err)}) — re-run 'border llm-request'`;
    }
    if (typeof parsed !== "object" || parsed === null) return `bundle ${p} is not an object — re-run 'border llm-request'`;
    const b = parsed as Partial<LlmRequestBundle>;
    if (b.schemaVersion !== 1 || typeof b.key !== "string" || !/^[0-9a-f]{64}$/.test(b.key) || typeof b.head !== "string" || !/^[0-9a-f]{40}$/.test(b.head) || !Array.isArray(b.fileDeltas) || b.deterministic === undefined) {
      return `bundle ${p} fails its own schema — re-run 'border llm-request'`;
    }
    return { dir: join(runsDir(repoDir), d), bundle: b as LlmRequestBundle };
  }
  return "no llm-request bundle found — run 'border llm-request' first";
}

function validateItem(value: unknown, bundle: LlmRequestBundle): Finding | string {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return "item is not an object";
  const o = value as Record<string, unknown>;
  const unknown = Object.keys(o).filter((k) => !ALLOWED_KEYS.has(k));
  if (unknown.length > 0) return `unknown key "${String(unknown[0])}" (allowed: rule, severity, target, path?, line?, commit?, message, snippet?)`;
  const { rule, severity, target, path, line, commit, message, snippet } = o;
  if (typeof rule !== "string" || !RULE_RE.test(rule)) return `rule must match ${String(RULE_RE)}, got ${JSON.stringify(rule)}`;
  if (typeof severity !== "string" || !(SEVERITIES as readonly string[]).includes(severity)) return `severity must be one of ${SEVERITIES.join("|")}, got ${JSON.stringify(severity)}`;
  if (typeof target !== "string" || target === "") return "target must be a non-empty string";
  if (typeof message !== "string" || message === "") return "message must be a non-empty string";
  if (message.length > MAX_TEXT) return `message exceeds ${String(MAX_TEXT)} chars`;
  if (path !== undefined && typeof path !== "string") return "path must be a string when present";
  if (typeof path === "string" && !bundle.fileDeltas.some((d) => d.path === path)) {
    return `finding-unknown-location (path "${path}" is not a file in the request bundle)`;
  }
  if (line !== undefined && (typeof line !== "number" || !Number.isInteger(line) || line < 1)) return "line must be a positive integer when present";
  if (commit !== undefined && typeof commit !== "string") return "commit must be a string when present";
  if (snippet !== undefined && (typeof snippet !== "string" || snippet.length > MAX_TEXT)) return `snippet must be a string of at most ${String(MAX_TEXT)} chars`;
  return {
    rule,
    severity: severity as Severity,
    target,
    ...(typeof path === "string" ? { path } : {}),
    ...(typeof line === "number" ? { line } : {}),
    ...(typeof commit === "string" ? { commit } : {}),
    // masked by the caller BEFORE digesting; engine/valueDigest are ingester-owned (C1)
    engine: "agent",
    message,
    valueDigest: "",
    snippet: typeof snippet === "string" ? snippet : "",
  };
}

export async function runLlmIngestCore(ctx: Ctx): Promise<BorderExit> {
  const arg = ctx.positionals[0];
  if (arg === undefined) return usageError(ctx, "usage: border llm-ingest <findings.json>");
  const envOpt = ctx.env !== undefined ? { env: ctx.env } : {};
  const load = loadConfig({
    cwd: ctx.cwd,
    ...(ctx.flags.config !== undefined ? { configPath: ctx.flags.config } : {}),
    ...envOpt,
  });
  for (const warning of load.warnings) ctx.stderr(`border: ${warning}`);
  if (load.kind !== "loaded") return usageError(ctx, "no scan targets are configured — run 'border check' first");
  const repoDir = resolveRepoDir(ctx.cwd, envOpt);
  const found = findLatestBundle(repoDir);
  if (typeof found === "string") return usageError(ctx, found);
  const { bundle } = found;

  const findingsPath = isAbsolute(arg) ? arg : resolve(ctx.cwd, arg);
  let text: string;
  try {
    text = readFileSync(findingsPath, "utf8");
  } catch {
    return usageError(ctx, `findings file not found: ${arg}`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
  } catch (err) {
    return usageError(ctx, `findings file is not valid JSON (${err instanceof Error ? err.message : String(err)})`);
  }
  if (!Array.isArray(parsed)) return usageError(ctx, "findings file root is not a JSON array");

  const fresh = gatherContext(repoDir, envOpt);
  if (fresh.headSha !== bundle.head) {
    return usageError(ctx, `HEAD moved since llm-request (${bundle.head.slice(0, 8)} → ${fresh.headSha.slice(0, 8)}) — the bundle is stale; re-run 'border check' && 'border llm-request'`);
  }

  const agentFindings: Finding[] = [];
  const errors: string[] = [];
  parsed.forEach((item, i) => {
    const v = validateItem(item, bundle);
    if (typeof v === "string") errors.push(`border: llm-ingest: item ${String(i)}: ${v}`);
    else agentFindings.push(v);
  });
  if (errors.length > 0) {
    for (const e of errors) ctx.stderr(e);
    return EXIT_ERROR;
  }

  const mask = maskViaEngineDetection(repoDir, agentFindings.map((f) => `${f.message}\n${f.snippet}`), envOpt);
  const cleaned = agentFindings.map((f) => {
    const message = mask(f.message);
    const snippet = f.snippet === "" ? "" : mask(f.snippet);
    const core = stableStringify({ rule: f.rule, target: f.target, path: f.path ?? null, line: f.line ?? null, commit: f.commit ?? null, message, snippet });
    const complete: Finding = {
      ...f,
      message,
      snippet: snippet === "" ? redact(core).snippet : snippet,
      valueDigest: sha256(core),
    };
    return validateFinding(complete);
  });

  const findings = [...bundle.deterministic.findings, ...cleaned];
  const verdict = computeVerdict(findings);
  const report: Report = {
    schemaVersion: 1,
    key: bundle.key,
    head: bundle.head,
    dirty: bundle.dirty,
    exposureSet: bundle.exposureSet,
    refSet: bundle.refSet,
    rulesHash: bundle.rulesHash,
    verdict,
    counts: countFindings(findings),
    findings,
    ts: new Date().toISOString(),
  };
  const record = recordCheckRun({
    repoDir,
    report,
    ctx: {
      repoDir,
      headSha: bundle.head,
      porcelainDigest: bundle.porcelainDigest,
      dirty: bundle.dirty,
      refSet: bundle.refSet,
      currentBranch: bundle.currentBranch,
    },
    effectiveTargets: computeEffectiveTargets(load.config, ctx.flags.targets),
    llm: true,
    ...envOpt,
  });
  for (const f of cleaned) {
    ctx.stdout(`border: agent ${f.severity} ${f.rule} ${f.path ?? "-"} — ${f.message}`);
  }
  ctx.stdout(`border: llm-ingest: verdict ${verdict} — ${String(cleaned.length)} agent findings recorded (llm:true, key ${bundle.key8}) report ${record.reportPath}`);
  if (cleaned.length === 0) {
    ctx.stdout("border: llm-ingest: the agent reported an empty findings array — PASS statement recorded as-is");
  }
  return exitCodeFromVerdict(verdict);
}
