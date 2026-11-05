// provenance: border dual-face remediation wave 2026-11-05 (sibyl run 45, B2) — aspect 7.
//
// One gate-owned field answering "which border build answers on which face,
// and is the ACTIVE face older than the registry's latest". The 2026-11-05
// ruling found two silent faces on this machine (cron landing on the mutable
// worktree; the PATH fallback handing argv to an older published CLI because
// the identity handshake verifies identity, never version) — this aspect makes
// both faces observable without adding any new authority: it spawns only
// `--version` probes and one registry metadata read, writes nothing, and its
// lag rung is WARN (see contract.ts: lag ≠ defect under pinned consumption).
//
// The active face is BORDER_BIN when set (the override wins alone on every
// resolution route, so it is what actually runs) and `border` on PATH
// otherwise; the packaged face's stamp is reported for context on both
// branches. Registry unreachable => CANNOT named "registry unreachable"
// (the shell maps that name to warn-only UNREACHABLE, never to rc 2, because
// this aspect's inability must not disturb the cache-verdict contract).
import { existsSync } from "node:fs";

import { REGISTRY_TIMEOUT_MS, type AspectResult, type Env, type InspectRunner, type SpawnTarget } from "../contract.ts";
import { defaultInspectRunner } from "./identity.ts";
import { defaultRegistryFetcher, fetchRegistryVersion, npmTagUrl } from "../registry.ts";
import type { ScanFetcher } from "../../scan/fetch.ts";

export const VERSION_ARGV: readonly string[] = ["--version"];

/** The CLI's --version contract (src/cli.ts): one line `border <version>+<commit>[.dirty]`.
 * The digit anchor is load-bearing: the banner line (`border — fail-closed gate…`)
 * must NOT parse as a version stamp. */
export function parseVersionStamp(stdout: string): string | null {
  const m = /^border\s+(\d[^\s]*)/m.exec(stdout);
  return m?.[1] ?? null;
}

export type GlobalResolutionDeps = {
  readonly runner?: InspectRunner;
  readonly distEntry: string;
  readonly env: Env;
  readonly pkg: string;
  readonly fetcher?: ScanFetcher;
  readonly registryBase?: string;
  readonly timeoutMs?: number;
};

type FaceProbe = { readonly label: string; readonly stamp: string };

async function probe(runner: InspectRunner, target: SpawnTarget): Promise<string> {
  const out = await runner(target, VERSION_ARGV);
  if (out.status === null) return "unspawnable";
  return parseVersionStamp(out.stdout) ?? "no version stamp";
}

export async function verifyGlobalResolution(deps: GlobalResolutionDeps): Promise<AspectResult> {
  const id = "global-resolution" as const;
  if ((deps.env["BORDER_INSPECT_OFFLINE"] ?? "") === "1") {
    return { id, verdict: "WARN", detail: "skipped (BORDER_INSPECT_OFFLINE=1) — freshness not evaluated; an unevaluated face is never reported as fresh" };
  }
  const runner = deps.runner ?? defaultInspectRunner;
  const override = deps.env["BORDER_BIN"];
  const hasOverride = override !== undefined && override.length > 0;

  const faces: FaceProbe[] = [];
  let active: string | null = null;

  if (hasOverride) {
    const stamp = await probe(runner, { bin: override as string, prefix: [], label: `BORDER_BIN=${override}` });
    faces.push({ label: `env BORDER_BIN=${override}`, stamp });
    active = stamp;
  } else {
    if (existsSync(deps.distEntry)) {
      const packaged = { bin: deps.distEntry, prefix: [], label: "packaged dist" };
      let stamp = await probe(runner, packaged);
      if (stamp === "unspawnable") {
        stamp = await probe(runner, { bin: "node", prefix: [deps.distEntry], label: "packaged dist" });
      }
      faces.push({ label: "packaged dist", stamp });
    }
    const pathStamp = await probe(runner, { bin: "border", prefix: [], label: "border on PATH" });
    faces.push({ label: "border on PATH", stamp: pathStamp });
    active = pathStamp === "unspawnable" ? null : pathStamp;
  }

  const faceLine = faces.map((f) => `${f.label}: ${f.stamp}`).join("; ");
  const fetcher = deps.fetcher ?? defaultRegistryFetcher;
  let latest: string;
  try {
    latest = await fetchRegistryVersion(fetcher, npmTagUrl(deps.pkg, "latest", deps.registryBase), deps.timeoutMs ?? REGISTRY_TIMEOUT_MS);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { id, verdict: "CANNOT", detail: `registry unreachable for global-resolution: ${message}; ${faceLine}` };
  }

  if (active === null) {
    return { id, verdict: "PASS", detail: `no active CLI face (no BORDER_BIN, no PATH border); registry latest ${latest}; ${faceLine}` };
  }
  // The CLI stamp carries +<commit>[.dirty]; the registry answers the bare
  // version — comparing the cores is what keeps a same-version face PASSing.
  const activeCore = active.split("+")[0];
  if (activeCore === latest) {
    return { id, verdict: "PASS", detail: `active face matches registry latest ${latest}; ${faceLine}` };
  }
  if (active === "unspawnable" || active === "no version stamp") {
    return { id, verdict: "WARN", detail: `active CLI face carries no version stamp (registry latest ${latest}) — informational: identity may be fine, age is unknown; ${faceLine}` };
  }
  return { id, verdict: "WARN", detail: `active CLI face is ${active}, registry latest is ${latest} — informational only: pinned consumption is a legitimate steady state, the decision to update stays with the human; ${faceLine}` };
}
