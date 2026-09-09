// provenance: original clean-room implementation per .omo/plans/border-push-channels.md todo C4
//
// rubygems channel descriptor — EVERY rubygems.org platform truth lives here
// (C4): the config schema fragment, the ${VAR} env-expand field (host ONLY,
// mirroring how npm's registry field expands in src/config.ts expandInConfig),
// HEAD coordinate reader, exposureSet coordinate reader, registry probe
// (v2 200 ⇒ present ⇒ CRITICAL bump; v2 404 "This version could not be found."
// ⇒ version-absent; v2 404 "This gem could not be found" ⇒ name-available;
// v1 404 "This rubygem could not be found." ⇒ unclaimed; anything else ⇒
// fail-closed EngineRunError — CHANNEL-CONTRACTS.md §g as measured, all 404
// bodies TEXT, classified by text match, never JSON-parsed), owner signals
// from the NAME-query v1 gem body (project_uri/homepage_uri/source_code_uri/
// documentation_uri/mailing_list_uri/bug_tracker_uri/funding_uri/wiki_uri/
// changelog_uri + authors/info strings — the owners.json endpoint is NEVER
// requested: same doctrine as the crates leg, the v1 body's url/email-hosting
// strings are exactly what the shared extractOwnerSignals/ownerVerdict can
// match, so a second request adds nothing; an empty-signal claimed gem lands
// in the existing ambiguous-CRITICAL path), artifact stage, publish executor +
// argv source, exposureSet item, confirmedVia ledger value, artifact
// extensions and publish order.
//
// FRESHNESS (plan L44 premise overturned — spike §e measured the opposite):
// gem build embeds the FIXED date 1980-01-02 00:00:00 UTC and is otherwise
// byte-deterministic, so the descriptor is freshness "repack":
// packRubygemsArtifacts (src/ledger/freshness.ts) re-builds into a throwaway
// dir and digests, like the npm/crates repackers. Caveats, documented: (a)
// gemspecs assigning s.date are REJECTED at coords (ConfigError) and stage
// (EngineRunError) — an explicit date makes the digest legitimately change
// (spike §e), so border refuses to certify it; (b) the gem digest is blind to
// git HEAD (no .cargo_vcs_info analogue) — the fingerprint key covers HEAD,
// the repack covers worktree bytes: compose, don't re-implement.
//
// HTTP polity (contract §g, measured 2026-09-05): rubygems.org has NO
// crates-style UA gate (no-UA ⇒ 200) — the probe still sends a self-
// identifying UA as good registry citizenship. The v2/versions endpoint is
// version-specific: 200 full-version JSON ⇒ present; 404 text "This version
// could not be found." ⇒ the gem exists but this version does not ⇒ continue
// to the v1 name leg; 404 text "This gem could not be found" (no period —
// distinct message) ⇒ the gem was never published ⇒ name-available. The v1
// gem-query 404 is text "This rubygem could not be found." ⇒ unclaimed.
//
// PUBLISH (measured gem push --help, RubyGems 3.6.7): `gem push GEM` takes a
// POSITIONAL .gem file; `--host HOST` pushes to another gemcutter-compatible
// host; auth is `-k/--key` + `--otp` reading ~/.gem/credentials — the gem
// binary handles credentials itself, border spawns stdio:'inherit' and never
// touches GEM_HOST_API_KEY (same doctrine as npm/pypi). Per-file argv rows:
// `["push", <file>, "--host", <host>?]`. NO prePublishGate: `gem push`
// uploads EXACTLY the recorded .gem bytes (true same-bytes upload, npm/twine
// class) — no internal repack race to assert, in contrast with the crates
// leg, whose `cargo publish` repackages internally and needs the digest-assert.
import { z } from "zod";

import { runRubygemsArtifactStage } from "../artifacts/rubygems.ts";
import { runGitChecked } from "../check/context.ts";
import { ConfigError } from "./errors.ts";
import { selectGemspec, type GemGemspecCandidate } from "./gemspec.ts";
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
import type { ChannelProbeOptions, ChannelStageOptions, ChannelStageResult, PublishChannel, PublishCoords, PypiFetcher, PypiResponse } from "./types.ts";

/** Default rubygems.org push/query host. */
export const RUBYGEMS_DEFAULT_URL = "https://rubygems.org";

/** Self-identifying User-Agent — sent on every probe request (rubygems.org
 *  has no UA gate — measured §g — but a probe should never be anonymous). */
export const RUBYGEMS_PROBE_USER_AGENT = "border-customs/0.1.0 (border push-gate rubygems.org probe)";

export const RUBYGEMS_ARTIFACT_EXTENSIONS: readonly string[] = [".gem"];

/** Config fragment validated at `targets.rubygems` (zod .strict() — an unknown
 *  rubygems config key is the same exit-2 unknown-key ConfigError as pre-C2).
 *  `name` disambiguates multi-gemspec repos; `host` overrides the registry
 *  (${VAR}-expandable — the ONLY env-expand field rthis channel). */
export const rubygemsTargetSchema = z
  .object({
    name: z.string().optional(),
    host: z.string().optional(),
  })
  .strict()
  .optional();

export type GemPublishInput = PublishInput & {
  /** Exact gem binary seam (tests / pinned toolchains); default "gem" on PATH. */
  readonly gemBinPath?: string;
};

/** *.gemspec paths at HEAD via `git ls-tree -r HEAD --name-only` (plan C4:
 *  discovery ALWAYS from the committed tree, never the working tree). */
function lsTreeGemspecPaths(repoDir: string | undefined, key: string): string[] {
  if (repoDir === undefined) {
    throw new ConfigError("invalid-value", "cannot discover *.gemspec files without a repo directory (internal exposureSet contract)", { key });
  }
  let tree: string;
  try {
    tree = runGitChecked(repoDir, ["ls-tree", "-r", "HEAD", "--name-only"]);
  } catch (err) {
    throw new ConfigError("git-failed", `git ls-tree -r HEAD failed (${String(err)}) — cannot discover *.gemspec files`, { key });
  }
  return tree.split("\n").filter((p) => /\.gemspec$/i.test(p));
}

/** Candidates from HEAD bytes (git show HEAD:<path> — never the working tree). */
function headGemspecCandidates(repoDir: string | undefined, env: NodeJS.ProcessEnv | undefined, key: string): GemGemspecCandidate[] {
  return lsTreeGemspecPaths(repoDir, key).map((path) => {
    let body: string;
    try {
      body = runGitChecked(repoDir as string, ["show", `HEAD:${path}`], { ...(env === undefined ? {} : { env }) });
    } catch {
      throw new ConfigError("invalid-value", `${path} not found at HEAD — publish target configured but nothing to publish`, { key: `targets.${path}` });
    }
    return { path, body };
  });
}

/** HEAD coordinate reader: discover *.gemspec at HEAD, read literal
 *  s.name/s.version (config name override disambiguates; anything computed is
 *  a typed exit-2 ConfigError — gemspec.ts doctrine, never eval). */
export function readRubygemsCoords(repoDir: string, cfg: BorderConfig, env?: NodeJS.ProcessEnv): PublishCoords {
  const candidates = headGemspecCandidates(repoDir, env, "targets.rubygems");
  return selectGemspec(candidates, cfg.targets.rubygems?.name, "targets.rubygems", "at HEAD");
}

/**
 * exposureSet coordinate reader: same HEAD-bytes reading as readRubygemsCoords
 * (bodies via the caller's `git show HEAD:<rel>`), but gemspec DISCOVERY needs
 * git plumbing the `read` callback cannot express (no fixed manifest path like
 * package.json/Cargo.toml) — so the caller (src/config.ts exposureSet) passes
 * the repo dir as the third argument, which every other channel's fixed-path
 * reader ignores. Config-facing error-message contract of the pre-C2 block.
 */
export function rubygemsExposureCoords(cfg: BorderConfig, read: (rel: string) => string, repoDir?: string): PublishCoords {
  const candidates = lsTreeGemspecPaths(repoDir, "targets.rubygems").map((path) => ({ path, body: read(path) }));
  return selectGemspec(candidates, cfg.targets.rubygems?.name, "targets.rubygems", "at HEAD");
}

async function rubygemsGet(url: string, timeoutMs: number, fetcher: PypiFetcher): Promise<PypiResponse> {
  try {
    return await fetcher(url, {
      signal: AbortSignal.timeout(timeoutMs),
      headers: { "user-agent": RUBYGEMS_PROBE_USER_AGENT },
    });
  } catch (err) {
    const reason = err instanceof Error && err.name === "TimeoutError" ? `timed out after ${String(timeoutMs)}ms` : `network failure: ${String(err)}`;
    throw new EngineRunError(`rubygems.org probe ${reason} for ${url} — registry unreachable, push blocked (fail-closed)`, null);
  }
}

/** 200 ⇒ parse JSON (malformed ⇒ typed EngineRunError). */
async function rubygemsJson(res: PypiResponse, url: string): Promise<unknown> {
  const text = await res.text();
  try {
    return JSON.parse(text);
  } catch {
    throw new EngineRunError(`rubygems.org probe returned a malformed JSON body for ${url} (parse error) — refusing to interpret`, res.status);
  }
}

/** 404 bodies are TEXT, not JSON (contract §g) — classify by text match, NEVER JSON.parse. */
async function rubygemsText(res: PypiResponse, url: string): Promise<string> {
  const text = await res.text();
  if (text.length === 0) {
    throw new EngineRunError(`rubygems.org probe got an EMPTY body for ${url} (status ${String(res.status)}) — refusing to interpret`, res.status);
  }
  return text;
}

/** v2 version leg polarity (contract §g as measured):
 *  200 ⇒ present ⇒ CRITICAL bump; 404 "…could not be found." ⇒ version-absent;
 *  404 "This gem could not be found" ⇒ name-absent (never existed); any other
 *  404/status/timeout/malformed ⇒ fail-closed EngineRunError — silence never
 *  means absent. */
async function rubygemsVersionLeg(res: PypiResponse, url: string, name: string, version: string): Promise<"present" | "version-absent" | "name-absent"> {
  if (res.status === 200) {
    await rubygemsJson(res, url); // JSON is EXPECTED on 200 — malformed fails closed, never "present"
    return "present";
  }
  if (res.status === 404) {
    const text = await rubygemsText(res, url);
    if (text.includes("This version could not be found.")) return "version-absent";
    if (text.includes("This gem could not be found")) return "name-absent";
    throw new EngineRunError(
      `rubygems.org version probe for ${name}@${version} returned a 404 with an unrecognized body (${text.slice(0, 120)}) — refusing to classify, push blocked (fail-closed)`,
      res.status,
    );
  }
  throw failClosedStatus(res, url);
}

/** v1 name leg polarity: 200 ⇒ claimed — the parsed gem body IS the
 *  owner-signal SOURCE (urls/emails embedded in project_uri/…/authors/info);
 *  404 text "This rubygem could not be found." ⇒ unclaimed; anything else ⇒
 *  fail-closed. */
async function rubygemsNameClaimed(res: PypiResponse, url: string, name: string): Promise<unknown | null> {
  if (res.status === 200) return rubygemsJson(res, url);
  if (res.status === 404) {
    const text = await rubygemsText(res, url);
    if (text.includes("This rubygem could not be found.")) return null;
    throw new EngineRunError(
      `rubygems.org name probe for '${name}' returned a 404 with an unrecognized body (${text.slice(0, 120)}) — refusing to classify, push blocked (fail-closed)`,
      res.status,
    );
  }
  throw failClosedStatus(res, url);
}

function failClosedStatus(res: PypiResponse, url: string): never {
  throw new EngineRunError(`rubygems.org probe got HTTP ${String(res.status)} for ${url} — cannot classify as absent, push blocked (fail-closed)`, res.status);
}

async function rubygemsProbe(o: ChannelProbeOptions): Promise<Finding[]> {
  const fetcher = o.fetcher ?? rubygemsGlobalFetcher;
  const coords = readRubygemsCoords(o.repoDir, o.cfg, o.env);
  const host = (o.cfg.targets.rubygems?.host ?? RUBYGEMS_DEFAULT_URL).replace(/\/+$/u, "");
  const name = encodeURIComponent(coords.name);
  const findings: Finding[] = [];

  const versionUrl = `${host}/api/v2/rubygems/${name}/versions/${encodeURIComponent(coords.version)}.json`;
  const versionLeg = await rubygemsVersionLeg(await rubygemsGet(versionUrl, o.timeoutMs, fetcher), versionUrl, coords.name, coords.version);
  if (versionLeg === "present") {
    findings.push(regFinding("rubygems", VERSION_EXISTS_RULE, "CRITICAL", BUMP_VERSION_MESSAGE, `${coords.name}@${coords.version}`));
    return findings;
  }
  if (versionLeg === "name-absent") {
    findings.push(regFinding("rubygems", NAME_AVAILABLE_RULE, "INFO", `name '${coords.name}' is unclaimed on rubygems.org`, coords.name));
    return findings;
  }

  const nameUrl = `${host}/api/v1/gems/${name}.json`;
  const nameBody = await rubygemsNameClaimed(await rubygemsGet(nameUrl, o.timeoutMs, fetcher), nameUrl, coords.name);
  if (nameBody === null) {
    findings.push(regFinding("rubygems", NAME_AVAILABLE_RULE, "INFO", `name '${coords.name}' is unclaimed on rubygems.org`, coords.name));
    return findings;
  }
  const f = ownerVerdict("rubygems", coords, extractOwnerSignals(nameBody), o.cfg);
  if (f !== null) findings.push(f);
  return findings;
}

const rubygemsGlobalFetcher: PypiFetcher = (url, init) => fetch(url, init).then((r) => ({ status: r.status, json: () => r.json(), text: () => r.text() }));

async function rubygemsStage(o: ChannelStageOptions): Promise<ChannelStageResult> {
  const stage = await runRubygemsArtifactStage({
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

/** Exactly `gem push <file.gem> [--host <host>]` per staged .gem (measured
 *  `gem push --help`, RubyGems 3.6.7: positional GEM argument; --host HOST
 *  "Push to another gemcutter-compatible host"). ONE row per file — the DRY-RUN
 *  print and the real spawn render the SAME argv (contract §f, single source). */
export function rubygemsPublishArgv(files: readonly string[], cfg: BorderConfig): readonly string[][] {
  const host = cfg.targets.rubygems?.host;
  return files.map((f) => ["push", f, ...(host === undefined ? [] : ["--host", host])]);
}

export function runRubygemsPublish(i: GemPublishInput): Promise<BorderExit> {
  const bin = i.gemBinPath ?? "gem";
  return runPublishCore(
    {
      kind: "rubygems",
      label: "gem",
      artifactExtensions: RUBYGEMS_ARTIFACT_EXTENSIONS,
      argvFor: rubygemsPublishArgv,
      // True same-bytes upload (npm/twine class): `gem push` uploads EXACTLY
      // the recorded .gem — no internal repack race, so no prePublishGate,
      // in contrast with the crates leg's repackage digest-assert.
      spawnCommands: (_i2, files, argvRows) => files.map((f, idx) => publishSpawnCommand(bin, argvRows[idx] ?? [], f)),
      coords: (i2) => readRubygemsCoords(i2.repoDir, i2.cfg, i2.env),
      recordPush: (i2, record, version) => {
        recordPushSuccess(i2.repoDir, {
          key: i2.key,
          target: "rubygems",
          remoteName: "rubygems",
          url: i2.cfg.targets.rubygems?.host ?? RUBYGEMS_DEFAULT_URL,
          localSha: record.head,
          version,
          confirmedVia: "rubygems-json",
        });
      },
      successLine: (version) => `published ${version}; push-record appended`,
      failureMessage: (code, file) =>
        `gem push failed for ${file ?? "the .gem"} (exit ${String(code)}) — no retry loop; inspect the registry state before running again`,
    },
    i,
  );
}

export type RubygemsChannelDescriptor = PublishChannel & { readonly configSchema: typeof rubygemsTargetSchema };

export const rubygemsChannel: RubygemsChannelDescriptor = {
  id: "rubygems",
  order: 4,
  configSchema: rubygemsTargetSchema,
  envExpandFields: ["host"],
  artifactExtensions: RUBYGEMS_ARTIFACT_EXTENSIONS,
  confirmedVia: "rubygems-json",
  defaultUrl: RUBYGEMS_DEFAULT_URL,
  freshness: "repack",
  configured: (cfg: BorderConfig): boolean => cfg.targets.rubygems !== undefined,
  coords: readRubygemsCoords,
  exposureCoords: rubygemsExposureCoords,
  probe: rubygemsProbe,
  stage: rubygemsStage,
  publish: (i: PublishInput) => runRubygemsPublish(i),
  publishArgv: rubygemsPublishArgv,
  exposureItem: (coords: PublishCoords): string => `rubygems:${coords.name}@${coords.version}`,
};