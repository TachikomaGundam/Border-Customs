// provenance: original clean-room implementation per .omo/plans/border-push-channels.md todo C2
//
// pypi channel descriptor — EVERY PyPI platform truth lives here (C2): the
// config schema fragment, ${VAR} env-expand field, HEAD coordinate reader,
// exposureSet coordinate reader, registry probe (200/404/else-throw polarity),
// artifact stage, publish executor + argv source, exposureSet item,
// confirmedVia ledger value, artifact extensions and publish order. Probe
// bodies are moved VERBATIM from the pre-C2 src/registry.ts (todo 13): HTTP
// 200 ⇒ version JSON ⇒ CRITICAL bump; 404 ⇒ absent; anything else (5xx,
// timeout, malformed body) ⇒ EngineRunError ⇒ CLI exit 2, fail-closed.
// Twine machinery is moved verbatim from the pre-C2 src/push/pypi.ts
// (todo 17): twine is probed BEFORE the pre-publish registry re-probe, the
// registered artifact convention is BOTH .whl and .tar.gz (single twine
// upload of exactly that set), and the fuzz seam stays twineBinPath/TWINE_BIN.
import { spawnSync } from "node:child_process";
import { relative } from "node:path";

import { z } from "zod";

import { scanPyPiArtifacts } from "../artifacts/pypi.ts";
import { runGitChecked } from "../check/context.ts";
import { ConfigError } from "./errors.ts";
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
} from "./types.ts";

/** PyPI upload default repository URL. */
export const PYPI_DEFAULT_REPOSITORY = "https://pypi.org";

export const PYPI_ARTIFACT_EXTENSIONS: readonly string[] = [".whl", ".tar.gz"];

/** Config fragment validated at `targets.pypi` (zod .strict() — an unknown
 *  pypi config key is the same exit-2 unknown-key ConfigError as pre-C2). */
export const pypiTargetSchema = z
  .object({
    name: z.string().optional(),
    repository: z.string().optional(),
  })
  .strict()
  .optional();

export type PypiPublishInput = PublishInput & {
  /**
   * Exact twine binary seam; the env var TWINE_BIN is honored when this is
   * unset. Default (neither set): `python3 -m twine` — mirroring how the
   * todo-12 stage invokes `python3 -m build` / `python3 -m twine check`.
   */
  readonly twineBinPath?: string;
};

const TOML_PLAIN = /^\s*name\s*=\s*"([^"]+)"|^\s*name\s*=\s*'([^']+)'/m;
const TOML_VERSION = /^\s*version\s*=\s*"([^"]+)"|^\s*version\s*=\s*'([^']+)'/m;

function headFile(repoDir: string, rel: string, env?: NodeJS.ProcessEnv): string {
  try {
    return runGitChecked(repoDir, ["show", `HEAD:${rel}`], { ...(env === undefined ? {} : { env }) });
  } catch {
    throw new ConfigError("invalid-value", `${rel} not found at HEAD — publish target configured but nothing to publish`, { key: `targets.${rel}` });
  }
}

export function readPypiCoords(repoDir: string, cfg: BorderConfig, env?: NodeJS.ProcessEnv): PublishCoords {
  const raw = headFile(repoDir, "pyproject.toml", env);
  const project = /\[project\][^[]*/.exec(raw)?.[0] ?? raw;
  const pick = (re: RegExp, where: string): string => {
    const m = re.exec(project);
    const v = m?.[1] ?? m?.[2];
    if (v === undefined) throw new ConfigError("invalid-value", `pyproject.toml at HEAD has no ${where}`, { key: `targets.pypi` });
    return v;
  };
  return {
    name: cfg.targets.pypi?.name ?? pick(TOML_PLAIN, "project name"),
    version: pick(TOML_VERSION, "project version"),
  };
}

/** TOML key lookup used by the exposureSet coordinate reader (moved from
 *  src/config.ts verbatim). */
function tomlField(raw: string, key: string, file: string): string {
  const m = new RegExp(`^\\s*${key}\\s*=\\s*["']([^"']+)["']`, "m").exec(raw);
  const value = m?.[1];
  if (value === undefined) {
    throw new ConfigError("invalid-value", `cannot read '${key}' from ${file} at HEAD`);
  }
  return value;
}

/**
 * exposureSet coordinate reader: same HEAD-bytes reading as readPypiCoords, but
 * the config-facing error-message contract of the pre-C2 exposureSet block in
 * src/config.ts (`read` is the caller's `git show HEAD:<rel>`).
 */
export function pypiExposureCoords(cfg: BorderConfig, read: (rel: string) => string): PublishCoords {
  const raw = read("pyproject.toml");
  return {
    name: cfg.targets.pypi?.name ?? tomlField(raw, "name", "pyproject.toml"),
    version: tomlField(raw, "version", "pyproject.toml"),
  };
}

type PypiResponse = {
  readonly status: number;
  json(): Promise<unknown>;
  text(): Promise<string>;
};

type PypiFetcher = (url: string, init: { signal: AbortSignal }) => Promise<PypiResponse>;

async function pypiGet(url: string, timeoutMs: number, fetcher: PypiFetcher): Promise<PypiResponse> {
  try {
    return await fetcher(url, { signal: AbortSignal.timeout(timeoutMs) });
  } catch (err) {
    const reason = err instanceof Error && err.name === "TimeoutError" ? `timed out after ${String(timeoutMs)}ms` : `network failure: ${String(err)}`;
    throw new EngineRunError(`PyPI probe ${reason} for ${url} — registry unreachable, push blocked (fail-closed)`, null);
  }
}

/** 200 ⇒ parse JSON (malformed ⇒ typed EngineRunError); 404 ⇒ null; else fail-closed. */
async function pypiJson(res: PypiResponse, url: string): Promise<unknown | null> {
  if (res.status === 404) return null;
  if (res.status !== 200) throw new EngineRunError(`PyPI probe got HTTP ${String(res.status)} for ${url} — cannot classify as absent, push blocked (fail-closed)`, res.status);
  const body = await res.text();
  try {
    return JSON.parse(body);
  } catch {
    throw new EngineRunError(`PyPI probe returned a malformed JSON body for ${url} (parse error) — refusing to interpret`, res.status);
  }
}

async function pypiProbe(o: ChannelProbeOptions): Promise<Finding[]> {
  const repository = o.cfg.targets.pypi?.repository ?? PYPI_DEFAULT_REPOSITORY;
  const fetcher = o.fetcher ?? globalFetcher;
  const coords = readPypiCoords(o.repoDir, o.cfg, o.env);
  const base = repository.replace(/\/+$/u, "");
  const findings: Finding[] = [];
  const versionUrl = `${base}/pypi/${encodeURIComponent(coords.name)}/${encodeURIComponent(coords.version)}/json`;
  const versionBody = await pypiJson(await pypiGet(versionUrl, o.timeoutMs, fetcher), versionUrl);
  if (versionBody !== null) findings.push(regFinding("pypi", VERSION_EXISTS_RULE, "CRITICAL", BUMP_VERSION_MESSAGE, `${coords.name}@${coords.version}`));
  const nameUrl = `${base}/pypi/${encodeURIComponent(coords.name)}/json`;
  const nameBody = await pypiJson(await pypiGet(nameUrl, o.timeoutMs, fetcher), nameUrl);
  if (nameBody === null) {
    findings.push(regFinding("pypi", NAME_AVAILABLE_RULE, "INFO", `name '${coords.name}' is unclaimed on PyPI`, coords.name));
  } else {
    const info = (nameBody as { info?: unknown }).info ?? nameBody;
    const f = ownerVerdict("pypi", coords, extractOwnerSignals(info), o.cfg);
    if (f !== null) findings.push(f);
  }
  return findings;
}

const globalFetcher: PypiFetcher = (url, init) => fetch(url, init).then((r) => ({ status: r.status, json: () => r.json(), text: () => r.text() }));

async function pypiStage(o: ChannelStageOptions): Promise<ChannelStageResult> {
  const scan = await scanPyPiArtifacts({
    repoDir: o.repoDir,
    rules: o.cfg.rules,
    ...(o.env === undefined ? {} : { env: o.env }),
    ...(o.sanitizer === undefined ? {} : { sanitizer: o.sanitizer }),
    ...(o.skipGitleaks === undefined ? {} : { skipGitleaks: o.skipGitleaks }),
    ...(o.skipSecretlint === undefined ? {} : { skipSecretlint: o.skipSecretlint }),
  });
  const artifacts = scan.artifacts.map((a) => ({ file: relative(o.repoDir, a.path), sha256: a.sha256 }));
  return { findings: scan.findings, artifacts };
}

type TwineCommand = { readonly bin: string; readonly prefix: readonly string[] };

function resolveTwine(i: PypiPublishInput): TwineCommand {
  const bin = i.twineBinPath ?? i.env?.TWINE_BIN;
  return bin === undefined ? { bin: "python3", prefix: ["-m", "twine"] } : { bin, prefix: [] };
}

function twineAvailable(i: PypiPublishInput, command: TwineCommand): { ok: true } | { ok: false; message: string } {
  const args = [...command.prefix, "--version"];
  let status: number | null = null;
  let failed = false;
  try {
    const res = spawnSync(command.bin, args, {
      encoding: "utf8",
      stdio: "ignore",
      ...(i.env === undefined ? {} : { env: { ...i.env } }),
    });
    failed = res.error !== undefined || res.status !== 0;
    status = res.status;
  } catch {
    failed = true;
  }
  if (failed) {
    return {
      ok: false,
      message: `twine upload unavailable — \`${command.bin} ${args.join(" ")}\` failed (exit ${String(status)}); install twine (pip install twine) before running border push (border exit 2)`,
    };
  }
  return { ok: true };
}

function pypiPublishArgv(files: readonly string[], cfg: BorderConfig): readonly string[][] {
  // Exactly `twine upload [--repository-url <url>] <files...>` — the repository
  // flag only when configured; no --sign, no comment/attestation extras.
  const repository = cfg.targets.pypi?.repository;
  return [["upload", ...(repository === undefined ? [] : ["--repository-url", repository]), ...files]];
}

export function runPypiPublish(i: PypiPublishInput): Promise<BorderExit> {
  const command = resolveTwine(i);
  return runPublishCore(
    {
      kind: "pypi",
      label: "twine",
      artifactExtensions: PYPI_ARTIFACT_EXTENSIONS,
      argvFor: pypiPublishArgv,
      prePublishGate: (i2) => {
        const r = twineAvailable(i2, command);
        return r.ok ? { ok: true } : { ok: false, message: r.message, exit: EXIT_ERROR };
      },
      spawnCommands: (_i2, _files, argvRows) => [
        publishSpawnCommand(command.bin, [...command.prefix, ...(argvRows[0] ?? [])]),
      ],
      coords: (i2) => readPypiCoords(i2.repoDir, i2.cfg, i2.env),
      recordPush: (i2, record, version) => {
        recordPushSuccess(i2.repoDir, {
          key: i2.key,
          target: "pypi",
          remoteName: "pypi",
          url: i2.cfg.targets.pypi?.repository ?? PYPI_DEFAULT_REPOSITORY,
          localSha: record.head,
          version,
          confirmedVia: "pypi-json",
        });
      },
      successLine: (version) => `published ${version}; push-record appended`,
      failureMessage: (code, _what) =>
        `twine upload failed (exit ${String(code)}) — no retry loop; check which files landed before running border push again`,
    },
    i,
  );
}

export type PypiChannelDescriptor = PublishChannel & { readonly configSchema: typeof pypiTargetSchema };

export const pypiChannel: PypiChannelDescriptor = {
  id: "pypi",
  order: 2,
  configSchema: pypiTargetSchema,
  envExpandFields: ["repository"],
  artifactExtensions: PYPI_ARTIFACT_EXTENSIONS,
  confirmedVia: "pypi-json",
  defaultUrl: PYPI_DEFAULT_REPOSITORY,
  freshness: "key",
  configured: (cfg: BorderConfig): boolean => cfg.targets.pypi !== undefined,
  coords: readPypiCoords,
  exposureCoords: pypiExposureCoords,
  probe: pypiProbe,
  stage: pypiStage,
  publish: (i: PublishInput) => runPypiPublish(i),
  publishArgv: pypiPublishArgv,
  exposureItem: (coords: PublishCoords): string => `pypi:${coords.name}@${coords.version}`,
};