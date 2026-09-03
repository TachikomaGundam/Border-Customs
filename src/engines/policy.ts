// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 6
//
// G8 fail-closed engine policy. Every engine the run REQUIRES (cfg.engines.require,
// default gitleaks+secretlint, overridable via --require-engine) must answer its
// probe; a missing/failing probe produces one CRITICAL `DEGRADED-ENGINE` finding
// per engine (engine field = the missing engine) and sets the returned
// `degraded` flag that the ledger layer (todo 14) uses to forbid writable PASS
// records. The CLI (todo 7) must exit 2 whenever degraded:true, regardless of
// the rest of the findings.
// Probes: gitleaks `--version` (subprocess), secretlint package-lock fingerprint
// (in-process — it has no --version), trufflehog `--version` ONLY when
// engines.trufflehog:true (G41: subprocess of the user-installed binary).
// A probe that runs but prints an unparseable version is NOT a degraded finding:
// it is an EnginePolicyError (border exit 2) naming the engine — border never
// assumes an unknown engine is current. Library layer throws typed errors only,
// never process.exit.
import type { BorderConfig } from "../config.ts";
import type { Finding } from "../findings.ts";
import { redact } from "../redact.ts";
import { gitleaksVersion } from "./gitleaks.ts";
import { secretlintVersionFingerprint } from "./secretlint.ts";
import { EngineMissingError, EngineRunError, type EngineOptions } from "./support.ts";
import { trufflehogVersion } from "./trufflehog.ts";

export const DEGRADED_ENGINE_RULE = "DEGRADED-ENGINE";
export const ENGINE_REMEDIATION = "run border's engine provisioning or install manually";
/** Finding.target label for policy findings (they describe the toolchain, not a scan leg). */
export const ENGINE_POLICY_TARGET = "engines";

/** Untranslatable probe output — the CLI maps exitCode 2 onto the process. */
export class EnginePolicyError extends Error {
  readonly exitCode: 2 = 2;

  constructor(message: string) {
    super(message);
    this.name = "EnginePolicyError";
  }
}

export type ProbeOptions = {
  /** `--require-engine <list>` override: REPLACES cfg.engines.require when provided. */
  requireOverride?: readonly string[];
  /** Environment for subprocess probes (tests: private PATH). Default: process.env. */
  env?: EngineOptions["env"];
  /** Exact gitleaks binary path (tests/odd installs); bypasses PATH/~/.local/bin lookup. */
  gitleaksBinPath?: string;
  /** Exact trufflehog binary path; same semantics, only used when engines.trufflehog:true. */
  trufflehogBinPath?: string;
  /** Alternate package-lock for the secretlint fingerprint (tests). */
  secretlintLockPath?: string;
};

export type EngineProbeResult = {
  /** true ⇒ at least one required engine failed its probe; the run exits 2 and the ledger (todo 14) must not record a writable PASS. */
  degraded: boolean;
  /** One CRITICAL DEGRADED-ENGINE finding per failed probe (empty when healthy). */
  findings: Finding[];
  /** Probed versions for the G21 rulesHash input: gitleaks/trufflehog semver, secretlint lock fingerprint (hex). */
  engineVersions: Record<string, string>;
};

const VERSION_RE = /\d+\.\d+(?:\.\d+)?/;

function extractVersion(engine: string, probeOutput: string): string {
  const m = VERSION_RE.exec(probeOutput);
  if (m === null) {
    throw new EnginePolicyError(
      `${engine} probe returned an unparseable version string: '${probeOutput.slice(0, 160)}' — ` +
        `border fails closed instead of assuming a current engine; ${ENGINE_REMEDIATION}`,
    );
  }
  return m[0];
}

function degradedFinding(engine: string, reason: string): Finding {
  return {
    rule: DEGRADED_ENGINE_RULE,
    severity: "CRITICAL",
    target: ENGINE_POLICY_TARGET,
    engine,
    message: `required engine '${engine}' failed its probe: ${reason}; ${ENGINE_REMEDIATION}`,
    ...redact(`degraded-engine:${engine}`),
  };
}

function isProbeFailure(error: unknown): error is EngineMissingError | EngineRunError {
  return error instanceof EngineMissingError || error instanceof EngineRunError;
}

function engineOptions(env: ProbeOptions["env"], binPath: string | undefined): EngineOptions {
  return {
    ...(env !== undefined ? { env } : {}),
    ...(binPath !== undefined ? { binPath } : {}),
  };
}

function probeGitleaks(opts: ProbeOptions, versions: Record<string, string>): Finding | null {
  try {
    const output = gitleaksVersion(engineOptions(opts.env, opts.gitleaksBinPath));
    versions.gitleaks = extractVersion("gitleaks", output);
    return null;
  } catch (error) {
    if (!isProbeFailure(error)) throw error;
    return degradedFinding("gitleaks", error.message);
  }
}

async function probeSecretlint(opts: ProbeOptions, versions: Record<string, string>): Promise<Finding | null> {
  try {
    versions.secretlint = await secretlintVersionFingerprint(
      opts.secretlintLockPath !== undefined ? { lockPath: opts.secretlintLockPath } : {},
    );
    return null;
  } catch (error) {
    if (!isProbeFailure(error)) throw error;
    return degradedFinding("secretlint", error.message);
  }
}

function probeTrufflehog(opts: ProbeOptions, versions: Record<string, string>): Finding | null {
  try {
    const output = trufflehogVersion(engineOptions(opts.env, opts.trufflehogBinPath));
    versions.trufflehog = extractVersion("trufflehog", output);
    return null;
  } catch (error) {
    if (!isProbeFailure(error)) throw error;
    return degradedFinding("trufflehog", error.message);
  }
}

/**
 * Probe every engine this run requires. The required set is
 * `requireOverride ?? cfg.engines.require`; trufflehog joins it only when
 * `cfg.engines.trufflehog:true` (an optional engine that is absent degrades
 * the run exactly like a missing required one — enabling it is a requirement).
 */
export async function probeEngines(cfg: BorderConfig, opts: ProbeOptions = {}): Promise<EngineProbeResult> {
  const required = [...new Set([
    ...(opts.requireOverride ?? cfg.engines.require),
    ...(cfg.engines.trufflehog ? ["trufflehog"] : []),
  ])];

  const findings: Finding[] = [];
  const engineVersions: Record<string, string> = {};
  for (const engine of required) {
    let finding: Finding | null;
    switch (engine) {
      case "gitleaks":
        finding = probeGitleaks(opts, engineVersions);
        break;
      case "secretlint":
        finding = await probeSecretlint(opts, engineVersions);
        break;
      case "trufflehog":
        finding = probeTrufflehog(opts, engineVersions);
        break;
      default:
        // An engine border cannot probe cannot be trusted present — fail closed.
        finding = degradedFinding(engine, "unknown required engine — border has no probe for it");
    }
    if (finding !== null) findings.push(finding);
  }
  return { degraded: findings.length > 0, findings, engineVersions };
}
