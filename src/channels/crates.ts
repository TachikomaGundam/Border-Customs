// provenance: original clean-room implementation per .omo/plans/border-push-channels.md todo C3
//
// crates channel descriptor — EVERY crates.io platform truth lives here (C3):
// the config schema fragment, ${VAR} env-expand fields (NONE: the crates
// target has no url/host — public crates.io only, per the plan guardrail),
// HEAD coordinate reader, exposureSet coordinate reader, registry probe
// (200+{version:{...}} ⇒ present; 404 "does not have a version" ⇒ absent;
// 404 "does not exist" ⇒ name-available; anything else ⇒ fail-closed
// EngineRunError, CHANNEL-CONTRACTS.md §b as measured), owner signals from
// the NAME-query crate metadata (repository/homepage/documentation — plan
// Scope L43: the /owners endpoint's profile-url-only payload can never match
// the repo-url/email comparison, so /owners is never requested), artifact
// stage, publish executor + argv source, exposureSet item, confirmedVia
// ledger value, artifact extensions and publish order.
//
// HTTP polarity + User-Agent doctrine (spike §b, measured 2026-09-05):
// crates.io answers GET /api/v1/crates/{name}/{version} with 200
// {version:{...}} when the version exists and 404 JSON errors[].detail
// "crate `X` does not have a version `Y`" when it does not; a crate that
// never existed yields 404 "... does not exist". The 404 detail string is the
// discriminator. Crucially, crates.io responds 403 to ANY request without a
// non-library User-Agent header (absent/empty/curl-default all rejected), so
// the probe sends a self-identifying UA and a 403 is fail-closed, never
// "absent". The pre-publish repackage digest-assert (plan Scope) covers
// R-race: cargo publish repackages internally, so the gate re-packages into
// a throwaway CARGO_TARGET_DIR and compares bytes against the staged .crate —
// cargo package is byte-deterministic per HEAD (spike §a), and any divergence
// from the checked bytes refires the check (exit 2, fail-closed).
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

import { z } from "zod";

import { runCargoArtifactStage } from "../artifacts/crates.ts";
import { runGitChecked } from "../check/context.ts";
import { ConfigError } from "./errors.ts";
import { BORDER_STATE_DIR } from "../check/lock.ts";
import type { BorderConfig } from "../config.ts";
import { EngineRunError } from "../engines/support.ts";
import type { Finding } from "../findings.ts";
import { recordPushSuccess } from "../pushstate.ts";
import { publishSpawnCommand, runPublishCore, type PublishInput } from "../push/core.ts";
import type { BorderExit } from "../cli/exit.ts";
import { EXIT_ERROR } from "../cli/exit.ts";
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
  PublishChannel,
  PublishCoords,
  PypiFetcher,
  PypiResponse,
} from "./types.ts";

/** crates.io API base (public registry; the crates target has no url override — plan guardrail). */
export const CRATES_IO_DEFAULT_URL = "https://crates.io";

/**
 * crates.io API base the PROBES target. The crates target deliberately has NO
 * config url (public-only guardrail — cratesTargetSchema rejects a registry
 * key), so the only way a test can keep a crates probe on a loopback stub is
 * this env seam — the TWINE_BIN precedent (src/channels/pypi.ts resolveTwine
 * reads i.env?.TWINE_BIN). Why re-homing the probe URL is harmless:
 *   * it re-homes the PROBE only — `cargo publish` uploads to the registry
 *     configured in the crate manifest / ~/.cargo, never to a URL border
 *     fetches, so the seam cannot redirect an upload;
 *   * recordPush still records CRATES_IO_DEFAULT_URL and the pre-publish
 *     repackage digest-assert is url-independent (the same-bytes proof holds
 *     for whatever registry the real cargo talks to);
 *   * the config schema stays url-less (zod .strict()).
 * C5 integration tests MUST point this at a 127.0.0.1 stub in every run.
 */
export function cratesApiBase(o: { readonly env?: NodeJS.ProcessEnv }): string {
  const override = o.env?.CRATES_IO_URL ?? process.env.CRATES_IO_URL;
  return (override ?? CRATES_IO_DEFAULT_URL).replace(/\/+$/u, "");
}

/** Self-identifying User-Agent — MANDATORY: crates.io 403s any request whose
 *  UA is absent, empty, or a library/curl default (spike §b). */
export const CRATES_PROBE_USER_AGENT = "border-customs/0.1.0 (border push-gate crates.io probe)";

export const CRATES_ARTIFACT_EXTENSIONS: readonly string[] = [".crate"];

/** Config fragment validated at `targets.crates` (zod .strict() — an unknown
 *  crates config key is the same exit-2 unknown-key ConfigError as pre-C2).
 *  NO registry/host field exists: public crates.io only (plan guardrail). */
export const cratesTargetSchema = z
  .object({
    name: z.string().optional(),
  })
  .strict()
  .optional();

export type CargoPublishInput = PublishInput & {
  /** Exact cargo binary seam (tests / pinned toolchains); default "cargo" on PATH. */
  readonly cargoBinPath?: string;
};

const TOML_PACKAGE = /\[package\][^[]*/;
const TOML_NAME = /^\s*name\s*=\s*"([^"]+)"|^\s*name\s*=\s*'([^']+)'/m;
const TOML_VERSION = /^\s*version\s*=\s*"([^"]+)"|^\s*version\s*=\s*'([^']+)'/m;

function headFile(repoDir: string, rel: string, env?: NodeJS.ProcessEnv): string {
  try {
    return runGitChecked(repoDir, ["show", `HEAD:${rel}`], { ...(env === undefined ? {} : { env }) });
  } catch {
    throw new ConfigError("invalid-value", `${rel} not found at HEAD — publish target configured but nothing to publish`, { key: `targets.${rel}` });
  }
}

/** Literal-only [package] keys from `git show HEAD:Cargo.toml` — the repo's
 *  TOML_PLAIN doctrine (mirror of readPypiCoords): a non-literal value
 *  (version.workspace = true, computed version) is a typed exit-2 ConfigError,
 *  never a guess. */
export function readCratesCoords(repoDir: string, cfg: BorderConfig, env?: NodeJS.ProcessEnv): PublishCoords {
  const raw = headFile(repoDir, "Cargo.toml", env);
  return cratesCoordsFrom(raw, cfg, "targets.crates");
}

function cratesCoordsFrom(raw: string, cfg: BorderConfig, key: string): PublishCoords {
  const pkg = TOML_PACKAGE.exec(raw)?.[0] ?? raw;
  const pick = (re: RegExp): string | undefined => {
    const m = re.exec(pkg);
    return m?.[1] ?? m?.[2];
  };
  const name = cfg.targets.crates?.name ?? pick(TOML_NAME);
  if (name === undefined) {
    throw new ConfigError("invalid-value", `Cargo.toml at HEAD has no package name in the [package] section (and no targets.crates.name override)`, { key });
  }
  const version = pick(TOML_VERSION);
  if (version === undefined) {
    throw new ConfigError(
      "invalid-value",
      "Cargo.toml at HEAD has no literal version in the [package] section — workspace-inherited or computed versions (version.workspace = true) are not supported; publish by setting a literal version",
      { key },
    );
  }
  return { name, version };
}

/**
 * exposureSet coordinate reader: same HEAD-bytes reading as readCratesCoords,
 * but the config-facing error-message contract of the pre-C2 exposureSet block
 * (`read` is the caller's `git show HEAD:<rel>`).
 */
export function cratesExposureCoords(cfg: BorderConfig, read: (rel: string) => string): PublishCoords {
  return cratesCoordsFrom(read("Cargo.toml"), cfg, "targets.crates");
}

type CratesResponse = PypiResponse;

async function cratesGet(url: string, timeoutMs: number, fetcher: PypiFetcher): Promise<CratesResponse> {
  try {
    return await fetcher(url, {
      signal: AbortSignal.timeout(timeoutMs),
      headers: { "user-agent": CRATES_PROBE_USER_AGENT },
    });
  } catch (err) {
    const reason = err instanceof Error && err.name === "TimeoutError" ? `timed out after ${String(timeoutMs)}ms` : `network failure: ${String(err)}`;
    throw new EngineRunError(`crates.io probe ${reason} for ${url} — registry unreachable, push blocked (fail-closed)`, null);
  }
}

async function cratesJson(res: CratesResponse, url: string): Promise<unknown> {
  const text = await res.text();
  try {
    return JSON.parse(text);
  } catch {
    throw new EngineRunError(`crates.io probe returned a malformed JSON body for ${url} (parse error) — refusing to interpret`, res.status);
  }
}

/** The crates.io 404 error envelope is `{"errors":[{"detail":"..."}]}` — the
 *  detail string is the status discriminator; a 404 without it is ambiguous
 *  and can never read as "absent". */
async function cratesErrorDetail(res: CratesResponse, url: string): Promise<string> {
  const body = await cratesJson(res, url);
  const errors = (body as { errors?: unknown }).errors;
  if (Array.isArray(errors) && errors.length > 0) {
    const first = errors[0] as { detail?: unknown };
    if (typeof first?.detail === "string") return first.detail;
  }
  throw new EngineRunError(`crates.io probe got HTTP ${String(res.status)} for ${url} with an unrecognizable error body — refusing to classify, push blocked (fail-closed)`, res.status);
}

/** 200 + {version:{...}} ⇒ present; 404 'does not have a version' / 'does not
 *  exist' ⇒ absent; 403 (UA policy) / 400 / 5xx / malformed / timeout ⇒
 *  fail-closed EngineRunError (contract §b) — silence never means absent. */
async function cratesVersionPresent(res: CratesResponse, url: string, name: string, version: string): Promise<boolean> {
  if (res.status === 200) {
    const body = await cratesJson(res, url);
    const v = (body as { version?: unknown }).version;
    if (typeof v !== "object" || v === null) {
      throw new EngineRunError(`crates.io version probe for ${name}@${version} returned a 200 body without a version object — cannot classify, push blocked (fail-closed)`, res.status);
    }
    return true;
  }
  if (res.status === 404) {
    const detail = await cratesErrorDetail(res, url);
    if (detail.includes("does not have a version") || detail.includes("does not exist")) return false;
    throw new EngineRunError(`crates.io version probe for ${name}@${version} returned a 404 with an unrecognized detail (${detail.slice(0, 120)}) — refusing to classify, push blocked (fail-closed)`, res.status);
  }
  throw failClosedStatus(res, url);
}

/** Name-level query polarity: 200 ⇒ claimed — the parsed crate-metadata body
 *  is the owner-signal SOURCE (plan Scope L43: repository/homepage/
 *  documentation are the pypi-project-JSON analogues the shared
 *  extractOwnerSignals/ownerVerdict compare against); 404 'does not exist' ⇒
 *  unclaimed; any other 404/status ⇒ fail-closed via failClosedStatus. */
async function cratesNameClaimed(res: CratesResponse, url: string, name: string): Promise<unknown | null> {
  if (res.status === 200) return cratesJson(res, url);
  if (res.status === 404) {
    const detail = await cratesErrorDetail(res, url);
    if (detail.includes("does not exist")) return null;
    throw new EngineRunError(`crates.io name probe for '${name}' returned a 404 with an unrecognized detail (${detail.slice(0, 120)}) — refusing to classify, push blocked (fail-closed)`, res.status);
  }
  throw failClosedStatus(res, url);
}

function failClosedStatus(res: CratesResponse, url: string): never {
  const uaHint = res.status === 403 ? ` (crates.io rejects absent/default User-Agent headers; border sends '${CRATES_PROBE_USER_AGENT}')` : "";
  throw new EngineRunError(`crates.io probe got HTTP ${String(res.status)} for ${url}${uaHint} — cannot classify as absent, push blocked (fail-closed)`, res.status);
}

async function cratesProbe(o: ChannelProbeOptions): Promise<Finding[]> {
  const fetcher = o.fetcher ?? cratesGlobalFetcher;
  const coords = readCratesCoords(o.repoDir, o.cfg, o.env);
  const name = encodeURIComponent(coords.name);
  const findings: Finding[] = [];

  const versionUrl = `${cratesApiBase(o)}/api/v1/crates/${name}/${encodeURIComponent(coords.version)}`;
  const present = await cratesVersionPresent(await cratesGet(versionUrl, o.timeoutMs, fetcher), versionUrl, coords.name, coords.version);
  if (present) {
    findings.push(regFinding("crates", VERSION_EXISTS_RULE, "CRITICAL", BUMP_VERSION_MESSAGE, `${coords.name}@${coords.version}`));
    return findings;
  }

  const nameUrl = `${cratesApiBase(o)}/api/v1/crates/${name}`;
  const nameBody = await cratesNameClaimed(await cratesGet(nameUrl, o.timeoutMs, fetcher), nameUrl, coords.name);
  if (nameBody === null) {
    findings.push(regFinding("crates", NAME_AVAILABLE_RULE, "INFO", `name '${coords.name}' is unclaimed on crates.io`, coords.name));
    return findings;
  }
  const f = ownerVerdict("crates", coords, extractOwnerSignals(nameBody), o.cfg);
  if (f !== null) findings.push(f);
  return findings;
}

const cratesGlobalFetcher: PypiFetcher = (url, init) => fetch(url, init).then((r) => ({ status: r.status, json: () => r.json(), text: () => r.text() }));

async function cratesStage(o: ChannelStageOptions): Promise<ChannelStageResult> {
  const stage = await runCargoArtifactStage({
    repoDir: o.repoDir,
    cfg: o.cfg,
    ...(o.env === undefined ? {} : { env: o.env }),
    ...(o.sanitizer === undefined ? {} : { sanitizer: o.sanitizer }),
    ...(o.skipGitleaks === undefined ? {} : { skipGitleaks: o.skipGitleaks }),
    ...(o.skipSecretlint === undefined ? {} : { skipSecretlint: o.skipSecretlint }),
  });
  const artifacts = stage.artifact === null ? [] : [{ file: stage.artifact.file, sha256: stage.artifact.sha256 }];
  return { findings: stage.findings, artifacts };
}

/** Exactly `cargo publish --allow-dirty --no-verify` per staged .crate. cargo
 *  publish takes NO positional .crate argument (measured `cargo publish
 *  --help`, cargo 1.93.1: no <file> — the package is always repackaged from
 *  the manifest), so every per-file row is byte-identical: the rows exist for
 *  the same per-file accounting the npm leg gives, and the DRY-RUN print and
 *  the real spawn render the SAME argv (contract §f, single source). */
export function cratesPublishArgv(files: readonly string[], _cfg: BorderConfig): readonly string[][] {
  return files.map(() => ["publish", "--allow-dirty", "--no-verify"]);
}

/** R-race backstop (plan C3 Scope; contract §a): `cargo publish` repackages
 *  internally, so immediately before the spawn the gate re-packages exactly
 *  like the check did and compares the fresh .crate digest against the staged
 *  .border/dist one. Determinism is spike-proven for an unchanged
 *  HEAD+worktree — the comparison is the proof either way (fail-closed). */
function repackageSameBytes(
  i: PublishInput,
  bin: string,
): { readonly ok: true } | { readonly ok: false; readonly message: string; readonly exit: BorderExit } {
  const targetDir = join(resolve(i.repoDir), BORDER_STATE_DIR, "tmp", "publish-repackage");
  rmSync(targetDir, { recursive: true, force: true });
  mkdirSync(targetDir, { recursive: true });
  try {
    const r = spawnSync(bin, ["package", "--allow-dirty", "--no-verify"], {
      cwd: i.repoDir,
      encoding: "utf8",
      timeout: 120_000,
      env: { ...(i.env ?? process.env), CARGO_TARGET_DIR: targetDir },
    });
    if (r.error !== undefined) {
      return { ok: false, message: `cargo package (pre-publish repackage) could not spawn ${bin} (${String(r.error)}) — install Rust via rustup (https://rustup.rs) before publishing (border exit 2)`, exit: EXIT_ERROR };
    }
    if (r.status !== 0) {
      return { ok: false, message: `cargo package --allow-dirty --no-verify (pre-publish repackage) exited ${String(r.status)} — no retry loop, push blocked (fail-closed): ${(r.stderr ?? "").trim().slice(0, 300)}`, exit: EXIT_ERROR };
    }
    const packedDir = join(targetDir, "package");
    const crates = readdirSync(packedDir).filter((f) => f.endsWith(".crate")).sort();
    if (crates.length !== 1) {
      return { ok: false, message: `pre-publish repackage produced ${String(crates.length)} .crate file(s) — expected exactly 1, push blocked (fail-closed)`, exit: EXIT_ERROR };
    }
    const crateFile = crates[0] ?? "";
    const freshSha = createHash("sha256").update(readFileSync(join(packedDir, crateFile))).digest("hex");
    const staged = join(resolve(i.repoDir), BORDER_STATE_DIR, "dist", crateFile);
    if (!existsSync(staged)) {
      return { ok: false, message: `${crateFile} is missing from .border/dist — the PASSED check recorded no such crate; re-run border check (push blocked)`, exit: EXIT_ERROR };
    }
    const stagedSha = createHash("sha256").update(readFileSync(staged)).digest("hex");
    if (stagedSha !== freshSha) {
      return { ok: false, message: `package bytes changed since check — the pre-publish repackage hashes to ${freshSha} but .border/dist/${crateFile} (checked) hashes to ${stagedSha}; push blocked (fail-closed); re-run border check`, exit: EXIT_ERROR };
    }
    return { ok: true };
  } finally {
    rmSync(targetDir, { recursive: true, force: true });
  }
}

export function runCratesPublish(i: CargoPublishInput): Promise<BorderExit> {
  const bin = i.cargoBinPath ?? "cargo";
  return runPublishCore(
    {
      kind: "crates",
      label: "cargo",
      artifactExtensions: CRATES_ARTIFACT_EXTENSIONS,
      argvFor: cratesPublishArgv,
      prePublishGate: (i2) => repackageSameBytes(i2, bin),
      spawnCommands: (_i2, files, argvRows) => files.map((f, idx) => publishSpawnCommand(bin, argvRows[idx] ?? [], f)),
      coords: (i2) => readCratesCoords(i2.repoDir, i2.cfg, i2.env),
      recordPush: (i2, record, version) => {
        recordPushSuccess(i2.repoDir, {
          key: i2.key,
          target: "crates",
          remoteName: "crates",
          url: CRATES_IO_DEFAULT_URL,
          localSha: record.head,
          version,
          confirmedVia: "crates-json",
        });
      },
      successLine: (version) => `published ${version}; push-record appended`,
      failureMessage: (code, file) =>
        `cargo publish failed for ${file ?? "the .crate"} (exit ${String(code)}) — no retry loop; inspect the registry state before running again`,
    },
    i,
  );
}

export type CratesChannelDescriptor = PublishChannel & { readonly configSchema: typeof cratesTargetSchema };

export const cratesChannel: CratesChannelDescriptor = {
  id: "crates",
  order: 3,
  configSchema: cratesTargetSchema,
  envExpandFields: [],
  artifactExtensions: CRATES_ARTIFACT_EXTENSIONS,
  confirmedVia: "crates-json",
  defaultUrl: CRATES_IO_DEFAULT_URL,
  freshness: "repack",
  configured: (cfg: BorderConfig): boolean => cfg.targets.crates !== undefined,
  coords: readCratesCoords,
  exposureCoords: cratesExposureCoords,
  probe: cratesProbe,
  stage: cratesStage,
  publish: (i: PublishInput) => runCratesPublish(i),
  publishArgv: cratesPublishArgv,
  exposureItem: (coords: PublishCoords): string => `crates:${coords.name}@${coords.version}`,
};