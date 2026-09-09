// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 13,
//   re-wired per .omo/plans/border-push-channels.md todo C2 (thin dispatcher)
//
// Registry pre-flight: publish-target immutability + name provenance probes.
// C2 moved every per-platform probe body into the channel descriptors
// (src/channels/npm.ts / src/channels/pypi.ts); this file is now the thin
// dispatcher over `publishChannels()` plus the legacy re-export surface the
// pre-C2 import paths (tests included) rely on. Polarity contract unchanged:
// `npm view <name>@<version> --json` exit 0 WITH a JSON body means the version
// is ALREADY PUBLISHED (registries are immutable ⇒ CRITICAL `version-exists`,
// "bump version required", never silent-skip); non-zero with `code E404`/
// `404 Not Found` means absent ⇒ proceed. ANY other outcome (connection
// refused, timeout, transport error, malformed body, empty stdout) raises
// EngineRunError ⇒ CLI exit 2 — silence is never read as "absent" and
// unreachability is never warn-and-proceed (plan L190, fail-closed).
//
// The npm leg shells out via async `spawn` (never spawnSync: the probe runs
// concurrently with in-process stub servers under test, and a synchronous
// spawn deadlocks the event loop). Exactly ONE attempt per call — the plan
// forbids retries ("no retries beyond 1"); a dead registry must fail fast.
import type { BorderConfig } from "./config.ts";
import type { Finding } from "./findings.ts";
import { publishChannels, REGISTRY_TIMEOUT_MS } from "./channels/registry.ts";

export {
  REGISTRY_ENGINE,
  VERSION_EXISTS_RULE,
  FOREIGN_OWNER_RULE,
  NAME_AVAILABLE_RULE,
  BUMP_VERSION_MESSAGE,
  REGISTRY_TIMEOUT_MS,
  normalizeGitLocation,
  extractOwnerSignals,
  ownerVerdict,
} from "./channels/registry.ts";

export { NPM_DEFAULT_REGISTRY, readNpmCoords, classifyNpmVersionView, npmNameClaimed } from "./channels/npm.ts";
export { PYPI_DEFAULT_REPOSITORY, readPypiCoords } from "./channels/pypi.ts";
export type { PublishCoords, NpmViewOutcome } from "./channels/types.ts";

export type RegistryProbeOptions = {
  readonly repoDir: string;
  readonly cfg: BorderConfig;
  readonly effectiveTargets: readonly string[];
  readonly env?: NodeJS.ProcessEnv;
  readonly timeoutMs?: number;
  /** Injected-fetcher test seam, shared by the pypi and crates probes (todo C3);
   *  production path is global fetch. */
  readonly fetcher?: PypiFetcher;
};

/** Minimal fetch response surface the probes need (test stub shape). */
export type PypiResponse = {
  readonly status: number;
  json(): Promise<unknown>;
  text(): Promise<string>;
};

export type PypiFetcher = (url: string, init: { signal: AbortSignal; headers?: Record<string, string> }) => Promise<PypiResponse>;

/**
 * Run every configured∩requested publish-channel probe (C2 dispatcher: the
 * descriptor modules own the probe bodies — this loop can never flip their
 * polarity or messages). Returns findings (CRITICAL version-exists /
 * name-foreign-owner, INFO name-available); rejects with EngineRunError on
 * ANY unreachable/ambiguous registry outcome so the CLI boundary exits 2 —
 * the gate cannot be bypassed by a dead registry.
 */
export async function runRegistryProbes(o: RegistryProbeOptions): Promise<Finding[]> {
  const timeoutMs = o.timeoutMs ?? REGISTRY_TIMEOUT_MS;
  const legs: Array<Promise<Finding[]>> = [];
  for (const channel of publishChannels()) {
    if (!o.effectiveTargets.includes(channel.id) || !channel.configured(o.cfg)) continue;
    legs.push(
      channel.probe({
        repoDir: o.repoDir,
        cfg: o.cfg,
        timeoutMs,
        ...(o.env === undefined ? {} : { env: o.env }),
        ...(o.fetcher === undefined ? {} : { fetcher: o.fetcher }),
      }),
    );
  }
  const results = await Promise.all(legs);
  return results.flat();
}