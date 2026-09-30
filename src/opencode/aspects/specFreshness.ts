// provenance: .omo/plans/border-opencode-inspect.md T1 — aspect 2: spec-freshness.
//
// The cache against the spec's SHOULD-BE version: an exact pin is judged
// offline (no network), a dist-tag/range is resolved through the injected
// ScanFetcher seam (unit tests script it; the real registry is reached only
// when the config uses a tag). The registry is consulted BEFORE the
// no-cache-directory short-circuit — fail-closed ordering mirrored from the
// 2026-09-24 drift-watch script: a dead registry must stay rc 2 there, never
// collapse into NOT-CACHED rc 0.
import { defaultRegistryFetcher, fetchRegistryVersion, npmTagUrl } from "../registry.ts";
import { splitNpmSpec } from "../jsonconfig.ts";
import { REGISTRY_TIMEOUT_MS, type AspectResult, type Facts } from "../contract.ts";
import type { ScanFetcher } from "../../scan/fetch.ts";

export type FreshnessDeps = {
  readonly fetcher?: ScanFetcher;
  readonly registryBase?: string;
  readonly timeoutMs?: number;
};

const isExactVersion = (spec: string): boolean => /^\d+\.\d+\.\d+([-+].*)?$/.test(spec);

export async function verifySpecFreshness(facts: Facts, deps: FreshnessDeps = {}): Promise<AspectResult> {
  const id = "spec-freshness" as const;
  const { configs, cacheDirs, pkg } = facts;
  const errored = configs.filter((c) => c.status === "error").map((c) => c.path);
  if (errored.length > 0) {
    return { id, verdict: "CANNOT", detail: `configuration unreadable (${errored.join(", ")}) — the expected version cannot be determined` };
  }
  const specs = [...new Set(configs.flatMap((c) => [...c.specs]).map((s) => splitNpmSpec(s).spec).filter((s): s is string => s !== null))];
  if (specs.length === 0) {
    return { id, verdict: "PASS", detail: `no ${pkg} spec declared in opencode config — nothing to be fresh` };
  }

  const expected = new Map<string, string>();
  const fetcher = deps.fetcher ?? defaultRegistryFetcher;
  const timeoutMs = deps.timeoutMs ?? REGISTRY_TIMEOUT_MS;
  for (const spec of specs) {
    if (isExactVersion(spec)) {
      expected.set(spec, spec);
      continue;
    }
    try {
      expected.set(spec, await fetchRegistryVersion(fetcher, npmTagUrl(pkg, spec, deps.registryBase), timeoutMs));
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return { id, verdict: "CANNOT", detail: `registry unreachable for spec '${pkg}@${spec}': ${message} — border never reads silence as fresh` };
    }
  }

  if (cacheDirs.length === 0) {
    return { id, verdict: "PASS", detail: `nothing cached to compare (see cache-version); spec resolves to ${[...new Set(expected.values())].join(", ")}` };
  }
  const wanted = new Set(expected.values());
  const judged = cacheDirs.filter((d): d is (typeof d & { packageVersion: string }) => d.packageVersion !== null);
  const stale = judged.filter((d) => !wanted.has(d.packageVersion));
  if (judged.length > 0 && stale.length > 0) {
    return {
      id,
      verdict: "FAIL",
      detail: `cache holds ${stale.map((d) => `${d.tag}->${d.packageVersion}`).join(",")}, spec expects ${[...wanted].join(",")}`,
    };
  }
  return { id, verdict: "PASS", detail: `cache matches spec: ${[...wanted].join(",")}` };
}
