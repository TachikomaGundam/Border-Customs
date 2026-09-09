// provenance: original clean-room implementation per .omo/plans/border-push-channels.md todo C2
//
// Channel-registry contract (option B: future platforms are DESCRIPTORS, not
// switch-cases). A publish channel is one descriptor module under
// src/channels/ carrying EVERY per-platform truth in one place: config schema
// fragment, ${VAR} env-expand fields, HEAD coordinate reader(s), registry
// probe, artifact stage, publish executor + argv source, exposureSet item,
// confirmedVia value, artifact extensions and publish order. Adding a channel
// = 1 descriptor file + 1 test file + registry/enum additions — no switch
// anywhere in src/ grows.
//
// Library contract: descriptors never call process.exit — typed errors
// (ConfigError exit 2 / EngineRunError exit 2 / BorderExit returns) flow to
// the CLI layer unchanged from the pre-C2 code paths.
import { z } from "zod";

import type { BorderExit } from "../cli/exit.ts";
import type { BorderConfig } from "../config.ts";
import type { Finding } from "../findings.ts";
import type { LedgerArtifact } from "../ledger/records.ts";
import type { PushConfirmedVia } from "../ledger/records.ts";
import type { PublishInput } from "../push/core.ts";
import type { TextSanitizer } from "../redact.ts";

/** Name + version to publish, read from the manifest AT HEAD (provenance AC). */
export type PublishCoords = {
  readonly name: string;
  readonly version: string;
};

/** Normalized outcome of one `npm view --json` invocation. */
export type NpmViewOutcome = {
  readonly status: number;
  readonly stdout: string;
  readonly stderr: string;
};

/** Minimal fetch response surface a registry probe needs (test stub shape). */
export type PypiResponse = {
  readonly status: number;
  json(): Promise<unknown>;
  text(): Promise<string>;
};

/** Generic injected-fetcher seam for registry probes (todo C3: pypi AND crates
 *  probes consume it; production path is global fetch via each descriptor's
 *  globalFetcher). `headers` lets a probe supply a mandatory request header —
 *  crates.io rejects absent/default User-Agents with 403. */
export type PypiFetcher = (
  url: string,
  init: { signal: AbortSignal; headers?: Record<string, string> },
) => Promise<PypiResponse>;

/** Per-probe input, resolved by the src/registry.ts dispatcher (timeoutMs
 *  defaults to REGISTRY_TIMEOUT_MS; fetcher defaults to global fetch). */
export type ChannelProbeOptions = {
  readonly repoDir: string;
  readonly cfg: BorderConfig;
  readonly env?: NodeJS.ProcessEnv;
  readonly timeoutMs: number;
  /** Injected-fetcher test seam, shared by the pypi and crates probes
   *  (production path is global fetch); pypi behavior is byte-identical. */
  readonly fetcher?: PypiFetcher;
};

/** Per-stage input, resolved by the check pipeline (src/check.ts). */
export type ChannelStageOptions = {
  readonly repoDir: string;
  readonly cfg: BorderConfig;
  readonly env?: NodeJS.ProcessEnv;
  readonly sanitizer?: TextSanitizer;
  /** Degraded-engine inheritance (todo 10 policy): the pipeline skips the leg
   *  whose engine failed its probe. */
  readonly skipGitleaks?: boolean;
  readonly skipSecretlint?: boolean;
};

/** Unified stage output: findings plus the ledger-certified artifact digests
 *  (`file` repo-relative, e.g. `.border/dist/<name>.tgz`). */
export type ChannelStageResult = {
  readonly findings: readonly Finding[];
  readonly artifacts: readonly LedgerArtifact[];
};

/**
 * One publish platform. `configSchema` is zod .strict() (wrapped in .optional()
 * for the config fragment); the assembled targets object rejects unknown keys
 * with the same exit-2 unknown-key ConfigError as the pre-C2 schema.
 */
export type PublishChannel = {
  readonly id: string;
  /** Fixed execution order: git(0) → npm(1) → pypi(2) → future platforms. */
  readonly order: number;
  /** zod .strict() fragment validated at `targets.<id>` (schema is .optional()). */
  readonly configSchema: z.ZodTypeAny;
  /** The ONLY config fields that receive `${VAR}` expansion under this id. */
  readonly envExpandFields: readonly string[];
  /** Dist-convention the publish core re-hashes against the ledger record. */
  readonly artifactExtensions: readonly string[];
  /** Ledger `confirmedVia` value for this platform's t:"push" records. */
  readonly confirmedVia: PushConfirmedVia;
  /** Registry URL used when the config omits the platform's url field. */
  readonly defaultUrl: string;
  /** SKIP-path artifact-freshness strategy (todo 14, todo C3):
   *  "repack" ⇒ a PASS skip is honored only after a digest-identical re-pack
   *   (byte-deterministic packers: `npm pack`, `cargo package` — spike-proven);
   *  "key" ⇒ the fingerprint key match is the whole proof (non-reproducible
   *   builds: pypi). One lookup site decides: src/ledger/freshness.ts. */
  readonly freshness: "repack" | "key";
  /** targets.<id> configured in this config? */
  configured(cfg: BorderConfig): boolean;
  /** HEAD coordinate reader (registry/publish probes; `git show HEAD:` only). */
  coords(repoDir: string, cfg: BorderConfig, env?: NodeJS.ProcessEnv): PublishCoords;
  /** exposureSet coordinate reader: same HEAD bytes, the config-facing
   *  error-message contract of the pre-C2 exposureSet block. `read` is the
   *  caller's `git show HEAD:<rel>` plumbing; the optional `repoDir` exists
   *  for channels whose HEAD coordinates need git plumbing beyond a fixed
   *  manifest path (C4: rubygems discovers *.gemspec via `git ls-tree` — an
   *  enum-able read has no fixed path), and fixed-path readers ignore it. */
  exposureCoords(cfg: BorderConfig, read: (rel: string) => string, repoDir?: string): PublishCoords;
  /** Registry pre-flight probe (version-exists / owner verdicts; fail-closed:
   *  any unreachable/ambiguous outcome throws EngineRunError ⇒ CLI exit 2). */
  probe(o: ChannelProbeOptions): Promise<Finding[]>;
  /** Build-once artifact stage for the check pipeline (.border/dist + scans). */
  stage(o: ChannelStageOptions): Promise<ChannelStageResult>;
  /** Publish executor (gate → re-hash → probe → warn → spawn → record). */
  publish(i: PublishInput): Promise<BorderExit>;
  /** ONE source for the publish argv: the DRY-RUN print and the real spawn
   *  both render exactly what this returns (per-file argv rows). */
  publishArgv(files: readonly string[], cfg: BorderConfig): readonly string[][];
  /** exposureSet item, e.g. `npm:<name>@<version>`. */
  exposureItem(coords: PublishCoords): string;
};

/** GitLeg channel: registered for CLI validation / configured-check /
 *  effective-target derivation only — deep logic stays in src/push/git.ts and
 *  pushstate gitState (untouched by C2). */
export type GitChannel = {
  readonly id: string;
  readonly order: number;
  configured(cfg: BorderConfig): boolean;
};

export type ChannelDescriptor = PublishChannel | GitChannel;