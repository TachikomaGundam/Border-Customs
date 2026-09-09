// provenance: original clean-room implementation per .omo/plans/border-push-channels.md todo C2
//
// npm channel descriptor — EVERY npm platform truth lives here (C2): the
// config schema fragment, ${VAR} env-expand field, HEAD coordinate reader,
// exposureSet coordinate reader, registry probe (version-exists + owner),
// artifact stage, publish executor + argv source, exposureSet item,
// confirmedVia ledger value, artifact extensions and publish order. The probe
// bodies are moved VERBATIM from the pre-C2 src/registry.ts (todo 13) — the
// polarity table (exit 0 + JSON body ⇒ present, E404 ⇒ absent, anything else
// ⇒ EngineRunError exit 2) and the owner-verdict messages are unchanged,
// fail-closed, and pinned by test/registry.test.ts.
import { spawn } from "node:child_process";

import { z } from "zod";

import { attributeToTarball, runNpmArtifactStage } from "../artifacts/npm.ts";
import { runGitChecked } from "../check/context.ts";
import { ConfigError, isRecord } from "./errors.ts";
import type { BorderConfig } from "../config.ts";
import { EngineRunError } from "../engines/support.ts";
import type { Finding } from "../findings.ts";
import { recordPushSuccess } from "../pushstate.ts";
import { publishSpawnCommand, runPublishCore, type PublishInput } from "../push/core.ts";
import type { BorderExit } from "../cli/exit.ts";
import {
  BUMP_VERSION_MESSAGE,
  NAME_AVAILABLE_RULE,
  VERSION_EXISTS_RULE,
  extractOwnerSignals,
  ownerVerdict,
  regFinding,
} from "./registry.ts";
import type {
  ChannelProbeOptions,
  ChannelStageOptions,
  ChannelStageResult,
  NpmViewOutcome,
  PublishChannel,
  PublishCoords,
} from "./types.ts";

/** npm CLI per-attempt bound; the plan forbids retries, this is the only wait. */
export const NPM_DEFAULT_REGISTRY = "https://registry.npmjs.org";

export const NPM_ARTIFACT_EXTENSIONS: readonly string[] = [".tgz"];

/** Config fragment validated at `targets.npm` (zod .strict() — an unknown
 *  npm config key is the same exit-2 unknown-key ConfigError as pre-C2). */
export const npmTargetSchema = z
  .object({
    name: z.string().optional(),
    registry: z.string().optional(),
  })
  .strict()
  .optional();

export type NpmPublishInput = PublishInput & {
  /** Exact npm binary seam (tests / pinned toolchains); default "npm" on PATH. */
  readonly npmBinPath?: string;
};

function headFile(repoDir: string, rel: string, env?: NodeJS.ProcessEnv): string {
  try {
    return runGitChecked(repoDir, ["show", `HEAD:${rel}`], { ...(env === undefined ? {} : { env }) });
  } catch {
    throw new ConfigError("invalid-value", `${rel} not found at HEAD — publish target configured but nothing to publish`, { key: `targets.${rel}` });
  }
}

export function readNpmCoords(repoDir: string, cfg: BorderConfig, env?: NodeJS.ProcessEnv): PublishCoords {
  const raw = headFile(repoDir, "package.json", env);
  let doc: unknown;
  try {
    doc = JSON.parse(raw);
  } catch {
    throw new ConfigError("invalid-value", "package.json at HEAD is not valid JSON", { key: "targets.npm" });
  }
  const pkg = doc as { name?: unknown; version?: unknown };
  const name = cfg.targets.npm?.name ?? (typeof pkg.name === "string" ? pkg.name : undefined);
  if (name === undefined) throw new ConfigError("invalid-value", "package.json at HEAD has no name (and no targets.npm.name override)", { key: "targets.npm.name" });
  if (typeof pkg.version !== "string") throw new ConfigError("invalid-value", "package.json at HEAD has no version", { key: "targets.npm" });
  return { name, version: pkg.version };
}

/**
 * exposureSet coordinate reader: same HEAD-bytes reading as readNpmCoords, but
 * the config-facing error-message contract of the pre-C2 exposureSet block in
 * src/config.ts (no keys; `read` is the caller's `git show HEAD:<rel>`).
 */
export function npmExposureCoords(cfg: BorderConfig, read: (rel: string) => string): PublishCoords {
  const raw = read("package.json");
  let pkg: unknown;
  try {
    pkg = JSON.parse(raw);
  } catch {
    throw new ConfigError("invalid-value", "package.json at HEAD is not valid JSON");
  }
  const version = isRecord(pkg) && typeof pkg["version"] === "string" ? pkg["version"] : undefined;
  if (version === undefined) {
    throw new ConfigError("invalid-value", "cannot read 'version' from package.json at HEAD");
  }
  const name = cfg.targets.npm?.name ?? (isRecord(pkg) && typeof pkg["name"] === "string" ? pkg["name"] : undefined);
  if (name === undefined) throw new ConfigError("invalid-value", "cannot read npm package name (config + package.json at HEAD)");
  return { name, version };
}

/**
 * Plan classification table, verbatim:
 *   exit 0 + JSON body            ⇒ "present"
 *   non-zero + E404/404 Not Found ⇒ "absent"
 *   anything else                 ⇒ EngineRunError (fail-closed)
 * Exported for table-driven tests of the edges without spawning npm.
 */
export function classifyNpmVersionView(o: NpmViewOutcome): "present" | "absent" {
  const fail = (why: string): never => {
    throw new EngineRunError(
      `npm registry probe inconclusive (${why}); refusing to assume the version is absent — registry unreachable or returned unexpected output, push blocked until the probe succeeds`,
      o.status,
    );
  };
  if (o.status === 0) {
    const text = o.stdout.trim();
    if (text.length === 0) return fail("exit 0 with empty stdout");
    let body: unknown;
    try {
      body = JSON.parse(text);
    } catch {
      return fail("exit 0 with malformed JSON body");
    }
    // null / scalars are JSON but carry no packument ⇒ treat as malformed
    if (typeof body !== "object" || body === null) return fail("exit 0 with non-object JSON body");
    return "present";
  }
  if (/code E404\b/.test(o.stderr) || /\b404 Not Found\b/.test(o.stderr)) return "absent";
  const m = /code (E[A-Z0-9_]+|ERR_[A-Z0-9_]+)/.exec(o.stderr);
  return fail(m === null ? `exit ${String(o.status)} without a 404 marker` : `npm error ${m[1]}`);
}

/**
 * Name-level query polarity: exit 0 ⇒ the name RESOLVES (claimed), even when
 * the requested fields are empty (stdout '''); non-zero + E404 ⇒ unclaimed;
 * anything else ⇒ fail-closed via the shared classifier.
 */
export function npmNameClaimed(o: NpmViewOutcome): boolean {
  if (o.status === 0) return true;
  if (/code E404\b/.test(o.stderr) || /\b404 Not Found\b/.test(o.stderr)) return false;
  classifyNpmVersionView(o);
  return true; // unreachable: classify throws for every non-404 failure
}

function npmViewJson(args: readonly string[], registry: string, timeoutMs: number, env?: NodeJS.ProcessEnv): Promise<NpmViewOutcome> {
  return new Promise((resolve, reject) => {
    const child = spawn("npm", ["view", ...args, "--registry", registry, "--fetch-retries=0", "--json"], {
      stdio: ["ignore", "pipe", "pipe"],
      ...(env === undefined ? {} : { env }),
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d: Buffer) => (stdout += d.toString()));
    child.stderr.on("data", (d: Buffer) => (stderr += d.toString()));
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new EngineRunError(`npm view ${args[0] ?? ""} timed out after ${String(timeoutMs)}ms against ${registry} — registry unreachable, push blocked (fail-closed)`, null));
    }, timeoutMs);
    child.on("error", (err) => {
      clearTimeout(timer);
      reject(new EngineRunError(`failed to spawn npm for registry probe: ${String(err)}`, null));
    });
    child.on("close", (status) => {
      clearTimeout(timer);
      resolve({ status: status ?? -1, stdout, stderr });
    });
  });
}

async function npmProbe(o: ChannelProbeOptions): Promise<Finding[]> {
  const registry = o.cfg.targets.npm?.registry ?? NPM_DEFAULT_REGISTRY;
  const coords = readNpmCoords(o.repoDir, o.cfg, o.env);
  const findings: Finding[] = [];
  const version = classifyNpmVersionView(await npmViewJson([`${coords.name}@${coords.version}`], registry, o.timeoutMs, o.env));
  if (version === "present") findings.push(regFinding("npm", VERSION_EXISTS_RULE, "CRITICAL", BUMP_VERSION_MESSAGE, `${coords.name}@${coords.version}`));
  const owner = await npmViewJson([coords.name, "maintainers", "repository.url"], registry, o.timeoutMs, o.env);
  if (!npmNameClaimed(owner)) {
    findings.push(regFinding("npm", NAME_AVAILABLE_RULE, "INFO", `name '${coords.name}' is unclaimed on the npm registry`, coords.name));
    return findings;
  }
  // Claimed. exit 0 + empty stdout = the queried owner fields do not exist on
  // the packument ⇒ ambiguous provenance, loud-fail via zero-signal verdict.
  const text = owner.stdout.trim();
  let signals: { readonly emails: readonly string[]; readonly urls: readonly string[] } = { emails: [], urls: [] };
  if (text.length > 0) {
    let body: unknown;
    try {
      body = JSON.parse(text);
    } catch {
      throw new EngineRunError(`npm owner query for '${coords.name}' returned a malformed JSON body — cannot prove ownership`, owner.status);
    }
    signals = extractOwnerSignals(body);
  }
  const f = ownerVerdict("npm", coords, signals, o.cfg);
  if (f !== null) findings.push(f);
  return findings;
}

async function npmStage(o: ChannelStageOptions): Promise<ChannelStageResult> {
  const stage = await runNpmArtifactStage({
    repoDir: o.repoDir,
    cfg: o.cfg,
    ...(o.env === undefined ? {} : { env: o.env }),
    ...(o.sanitizer === undefined ? {} : { sanitizer: o.sanitizer }),
    ...(o.skipGitleaks === undefined ? {} : { skipGitleaks: o.skipGitleaks }),
    ...(o.skipSecretlint === undefined ? {} : { skipSecretlint: o.skipSecretlint }),
  });
  const findings = attributeToTarball(stage.findings, stage.artifact);
  const artifacts = stage.artifact === null ? [] : [{ file: stage.artifact.file, sha256: stage.artifact.sha256 }];
  return { findings, artifacts };
}

/** Exactly `npm publish <file.tgz> --registry <url?>` — --registry only when
 *  configured; NO --access, NO --tag, nothing else (plan MUST NOT list). */
function npmPublishArgv(files: readonly string[], cfg: BorderConfig): readonly string[][] {
  const registry = cfg.targets.npm?.registry;
  return files.map((f) => ["publish", f, ...(registry === undefined ? [] : ["--registry", registry])]);
}

export function runNpmPublish(i: NpmPublishInput): Promise<BorderExit> {
  const bin = i.npmBinPath ?? "npm";
  return runPublishCore(
    {
      kind: "npm",
      label: "npm",
      artifactExtensions: NPM_ARTIFACT_EXTENSIONS,
      argvFor: npmPublishArgv,
      spawnCommands: (_i, files, argvRows) => files.map((f, idx) => publishSpawnCommand(bin, argvRows[idx] ?? [], f)),
      coords: (i2) => readNpmCoords(i2.repoDir, i2.cfg, i2.env),
      recordPush: (i2, record, version) => {
        recordPushSuccess(i2.repoDir, {
          key: i2.key,
          target: "npm",
          remoteName: "npm",
          url: i2.cfg.targets.npm?.registry ?? NPM_DEFAULT_REGISTRY,
          localSha: record.head,
          version,
          confirmedVia: "npm-view",
        });
      },
      successLine: (version) => `published ${version}; push-record appended`,
      failureMessage: (code, file) =>
        `npm publish failed for ${file ?? "unknown file"} (exit ${String(code)}) — no retry loop; inspect the registry state before running again`,
    },
    i,
  );
}

export type NpmChannelDescriptor = PublishChannel & { readonly configSchema: typeof npmTargetSchema };

export const npmChannel: NpmChannelDescriptor = {
  id: "npm",
  order: 1,
  configSchema: npmTargetSchema,
  envExpandFields: ["registry"],
  artifactExtensions: NPM_ARTIFACT_EXTENSIONS,
  confirmedVia: "npm-view",
  defaultUrl: NPM_DEFAULT_REGISTRY,
  freshness: "repack",
  configured: (cfg: BorderConfig): boolean => cfg.targets.npm !== undefined,
  coords: readNpmCoords,
  exposureCoords: npmExposureCoords,
  probe: npmProbe,
  stage: npmStage,
  publish: (i: PublishInput) => runNpmPublish(i),
  publishArgv: npmPublishArgv,
  exposureItem: (coords: PublishCoords): string => `npm:${coords.name}@${coords.version}`,
};