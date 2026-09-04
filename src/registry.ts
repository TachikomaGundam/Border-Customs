// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 13
//
// Registry pre-flight: publish-target immutability + name provenance probes.
// Polarity (round-3 B1 fix, pinned by plan L189): `npm view <name>@<version>
// --json` exit 0 WITH a JSON body means the version is ALREADY PUBLISHED
// (registries are immutable ⇒ CRITICAL `version-exists`, "bump version
// required", never silent-skip); non-zero with `code E404`/`404 Not Found`
// means absent ⇒ proceed. ANY other outcome (connection refused, timeout,
// transport error, malformed body, empty stdout) raises EngineRunError ⇒
// CLI exit 2 — silence is never read as "absent" and unreachability is never
// warn-and-proceed (plan L190, fail-closed).
//
// The npm leg shells out via async `spawn` (never spawnSync: the probe runs
// concurrently with in-process stub servers under test, and a synchronous
// spawn deadlocks the event loop). Exactly ONE attempt per call — the plan
// forbids retries ("no retries beyond 1"); a dead registry must fail fast.
import { spawn } from "node:child_process";

import { ConfigError, type BorderConfig } from "./config.ts";
import { EngineRunError } from "./engines/support.ts";
import { runGitChecked } from "./check/context.ts";
import type { Finding, Severity } from "./findings.ts";
import { redact } from "./redact.ts";

export const REGISTRY_ENGINE = "registry";
export const VERSION_EXISTS_RULE = "version-exists";
export const FOREIGN_OWNER_RULE = "name-foreign-owner";
export const NAME_AVAILABLE_RULE = "name-available";
/** plan L189 + AC: exact message string, pinned. */
export const BUMP_VERSION_MESSAGE = "bump version required";

export const NPM_DEFAULT_REGISTRY = "https://registry.npmjs.org";
export const PYPI_DEFAULT_REPOSITORY = "https://pypi.org";

/** npm CLI per-attempt bound; the plan forbids retries, this is the only wait. */
export const REGISTRY_TIMEOUT_MS = 15_000;

/** Normalized outcome of one `npm view --json` invocation. */
export type NpmViewOutcome = {
  readonly status: number;
  readonly stdout: string;
  readonly stderr: string;
};

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

/** Name + version to publish, read from the manifest AT HEAD (provenance AC). */
export type PublishCoords = {
  readonly name: string;
  readonly version: string;
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

const TOML_PLAIN = /^\s*name\s*=\s*"([^"]+)"|^\s*name\s*=\s*'([^']+)'/m;
const TOML_VERSION = /^\s*version\s*=\s*"([^"]+)"|^\s*version\s*=\s*'([^']+)'/m;

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

/** Registry finding helper: native rules carry no path/line/commit. */
function regFinding(target: "npm" | "pypi", rule: string, severity: Severity, message: string, value: string): Finding {
  const r = redact(value);
  return { rule, severity, target, engine: REGISTRY_ENGINE, message, valueDigest: r.valueDigest, snippet: r.snippet };
}

export function normalizeGitLocation(url: string): string {
  return url
    .trim()
    .replace(/^[a-z][a-z0-9+.-]*:\/\//i, "") // https:// git+https:// git+ssh:// ssh:// git://
    .replace(/^ssh:\/\//i, "")
    .replace(/^[^@/]+@([^:]+):/i, "$1/") // git@host:group/ → host/group/
    .replace(/^([^/]+):/u, "$1/") // host:path (no user) → host/path
    .replace(/\.git$/i, "")
    .replace(/\/+$/i, "")
    .toLowerCase();
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

type OwnerSignals = {
  readonly emails: readonly string[];
  readonly urls: readonly string[];
};

function collectStrings(v: unknown, out: string[]): void {
  if (typeof v === "string") out.push(v);
  else if (Array.isArray(v)) for (const e of v) collectStrings(e, out);
  else if (typeof v === "object" && v !== null) for (const e of Object.values(v)) collectStrings(e, out);
}

/** Emails + repo URLs embedded anywhere in an owner-query body. */
export function extractOwnerSignals(body: unknown): OwnerSignals {
  const strings: string[] = [];
  collectStrings(body, strings);
  const emails = new Set<string>();
  const urls = new Set<string>();
  for (const s of strings) {
    for (const m of s.matchAll(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g)) emails.add(m[0].toLowerCase());
    for (const m of s.matchAll(/\b(?:https?|git\+https?|ssh|git):\/\/\S+/gi)) urls.add(normalizeGitLocation(m[0]));
    const scp = /^[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})[:/]\S+$/u.exec(s);
    if (scp?.[1] !== undefined) urls.add(normalizeGitLocation(s));
  }
  return { emails: [...emails], urls: [...urls] };
}

function ownerVerdict(
  target: "npm" | "pypi",
  coords: PublishCoords,
  signals: OwnerSignals,
  cfg: BorderConfig,
): Finding | null {
  const wantEmails = new Set(cfg.rules.authors.emails.map((e) => e.toLowerCase()));
  const wantUrls = new Set(cfg.targets.git.remotes.map((r) => normalizeGitLocation(r.url)));
  if (signals.emails.some((e) => wantEmails.has(e)) || signals.urls.some((u) => wantUrls.has(u))) return null; // ours — silent
  if (signals.emails.length === 0 && signals.urls.length === 0) {
    // Claimed (name query answered) but nothing to compare against: documented
    // heuristic boundary — FAIL loud, never silently treat as ours or foreign.
    return regFinding(
      target,
      FOREIGN_OWNER_RULE,
      "CRITICAL",
      `name '${coords.name}' is registered but exposes no comparable owner signal (ambiguous provenance) — resolve ownership manually before publishing, refusing to guess`,
      `${coords.name}:ambiguous`,
    );
  }
  return regFinding(
    target,
    FOREIGN_OWNER_RULE,
    "CRITICAL",
    `name '${coords.name}' is already registered to a foreign owner (maintainer/repo mismatch) — publishing would target someone else's package`,
    `${coords.name}:foreign`,
  );
}

// ------------------------------------------------------------------ subprocess / fetch runners

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

// ------------------------------------------------------------------ orchestration

export type RegistryProbeOptions = {
  readonly repoDir: string;
  readonly cfg: BorderConfig;
  readonly effectiveTargets: readonly string[];
  readonly env?: NodeJS.ProcessEnv;
  readonly timeoutMs?: number;
  /** Test seam for the PyPI leg; production path is global fetch. */
  readonly fetcher?: PypiFetcher;
};

async function probeNpm(o: RegistryProbeOptions, registry: string, timeoutMs: number): Promise<Finding[]> {
  const coords = readNpmCoords(o.repoDir, o.cfg, o.env);
  const findings: Finding[] = [];
  const version = classifyNpmVersionView(await npmViewJson([`${coords.name}@${coords.version}`], registry, timeoutMs, o.env));
  if (version === "present") findings.push(regFinding("npm", VERSION_EXISTS_RULE, "CRITICAL", BUMP_VERSION_MESSAGE, `${coords.name}@${coords.version}`));
  const owner = await npmViewJson([coords.name, "maintainers", "repository.url"], registry, timeoutMs, o.env);
  if (!npmNameClaimed(owner)) {
    findings.push(regFinding("npm", NAME_AVAILABLE_RULE, "INFO", `name '${coords.name}' is unclaimed on the npm registry`, coords.name));
    return findings;
  }
  // Claimed. exit 0 + empty stdout = the queried owner fields do not exist on
  // the packument ⇒ ambiguous provenance, loud-fail via zero-signal verdict.
  const text = owner.stdout.trim();
  let signals: OwnerSignals = { emails: [], urls: [] };
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

async function probePypi(o: RegistryProbeOptions, repository: string, timeoutMs: number, fetcher: PypiFetcher): Promise<Finding[]> {
  const coords = readPypiCoords(o.repoDir, o.cfg, o.env);
  const base = repository.replace(/\/+$/u, "");
  const findings: Finding[] = [];
  const versionUrl = `${base}/pypi/${encodeURIComponent(coords.name)}/${encodeURIComponent(coords.version)}/json`;
  const versionBody = await pypiJson(await pypiGet(versionUrl, timeoutMs, fetcher), versionUrl);
  if (versionBody !== null) findings.push(regFinding("pypi", VERSION_EXISTS_RULE, "CRITICAL", BUMP_VERSION_MESSAGE, `${coords.name}@${coords.version}`));
  const nameUrl = `${base}/pypi/${encodeURIComponent(coords.name)}/json`;
  const nameBody = await pypiJson(await pypiGet(nameUrl, timeoutMs, fetcher), nameUrl);
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

/**
 * Run every configured publish-target probe. Returns findings (CRITICAL
 * version-exists / name-foreign-owner, INFO name-available); rejects with
 * EngineRunError on ANY unreachable/ambiguous registry outcome so the CLI
 * boundary exits 2 — the gate cannot be bypassed by a dead registry.
 */
export async function runRegistryProbes(o: RegistryProbeOptions): Promise<Finding[]> {
  const timeoutMs = o.timeoutMs ?? REGISTRY_TIMEOUT_MS;
  const want = (t: "npm" | "pypi"): boolean =>
    (o.effectiveTargets as readonly string[]).includes(t) && (t === "npm" ? o.cfg.targets.npm !== undefined : o.cfg.targets.pypi !== undefined);
  const legs: Array<Promise<Finding[]>> = [];
  if (want("npm")) legs.push(probeNpm(o, o.cfg.targets.npm?.registry ?? NPM_DEFAULT_REGISTRY, timeoutMs));
  if (want("pypi")) legs.push(probePypi(o, o.cfg.targets.pypi?.repository ?? PYPI_DEFAULT_REPOSITORY, timeoutMs, o.fetcher ?? globalFetcher));
  const results = await Promise.all(legs);
  return results.flat();
}
