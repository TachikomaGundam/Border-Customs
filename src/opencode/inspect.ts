// provenance: .omo/plans/border-opencode-inspect.md T1 — `border opencode inspect` core.
//
// The V1 load-surface self-audit as ONE gate-owned surface (institutionalising
// what 2026-09-24 scattered across plugin/border.ts, tools/plugin-drift-watch.mjs,
// and the installer's status). Six read-only aspects, aggregated fail-closed:
// any FAIL -> exit 1; no FAIL but any CANNOT -> exit 2; all PASS -> exit 0.
// Zero ledger writes, zero check-pipeline dependency (the scan import-audit
// contract, copied); every side effect (fs roots, registry, process spawn)
// rides an injected seam so unit tests script the whole surface offline.
// --json carries scope:"v1" as the consumer-facing certificate bound (plan B3).
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { EXIT_BLOCKED, EXIT_ERROR, EXIT_PASS, type BorderExit } from "../cli/exit.ts";
import type { Ctx } from "../cli/types.ts";
import type { ScanFetcher } from "../scan/fetch.ts";
import { verifyCacheVersion } from "./aspects/cacheVersion.ts";
import { verifyDualRoute } from "./aspects/dualRoute.ts";
import { verifyIdentity } from "./aspects/identity.ts";
import { verifyRouteAParity } from "./aspects/routeA.ts";
import { verifyScope } from "./aspects/scope.ts";
import { verifySpecFreshness } from "./aspects/specFreshness.ts";
import {
  BORDER_PACKAGE,
  opencodeCacheRoot,
  opencodeConfigRoot,
  packagedAssetPath,
  packagedDistEntry,
  routeAPluginPath,
  type AspectResult,
  type AspectVerdict,
  type Env,
  type Facts,
  type InspectReport,
  type InspectRunner,
} from "./contract.ts";
import { listCacheDirs, readPluginDeclarations } from "./jsonconfig.ts";

export type InspectDeps = {
  readonly package?: string;
  readonly cacheRoot?: string;
  readonly globalConfigPath?: string;
  readonly registryFetcher?: ScanFetcher;
  readonly registryBase?: string;
  readonly runner?: InspectRunner;
  readonly distEntry?: string;
};

export function aggregateVerdict(aspects: readonly AspectResult[]): AspectVerdict {
  if (aspects.some((a) => a.verdict === "FAIL")) return "FAIL";
  if (aspects.some((a) => a.verdict === "CANNOT")) return "CANNOT";
  return "PASS";
}

export function inspectExit(verdict: AspectVerdict): BorderExit {
  switch (verdict) {
    case "FAIL":
      return EXIT_BLOCKED;
    case "CANNOT":
      return EXIT_ERROR;
    case "PASS":
      return EXIT_PASS;
  }
}

function readPackagedPlugin(path: string): Buffer | null {
  try {
    return readFileSync(path);
  } catch {
    return null;
  }
}

export function gatherFacts(env: Env, cwd: string, deps: InspectDeps): Facts {
  const pkg = deps.package ?? BORDER_PACKAGE;
  const pluginDrop = routeAPluginPath(env);
  const cacheRoot = deps.cacheRoot ?? opencodeCacheRoot(env);
  const globalPath = deps.globalConfigPath ?? join(opencodeConfigRoot(env), "opencode", "opencode.jsonc");
  const routeAInstalled = existsSync(pluginDrop);
  return {
    pkg,
    env,
    cacheRoot,
    cacheDirs: listCacheDirs(cacheRoot, pkg),
    configs: [readPluginDeclarations(globalPath, pkg), readPluginDeclarations(join(cwd, "opencode.jsonc"), pkg)],
    packagedPlugin: readPackagedPlugin(packagedAssetPath(import.meta.url, "border.ts")),
    routeAPlugin: pluginDrop,
    routeAInstalled,
    routeABytes: routeAInstalled ? readPackagedPlugin(pluginDrop) : null,
  };
}

export async function runInspectCore(ctx: Ctx, deps: InspectDeps = {}): Promise<BorderExit> {
  const facts = gatherFacts(ctx.env, ctx.cwd, deps);
  const aspects: AspectResult[] = [
    verifyCacheVersion(facts),
    await verifySpecFreshness(facts, {
      ...(deps.registryFetcher !== undefined ? { fetcher: deps.registryFetcher } : {}),
      ...(deps.registryBase !== undefined ? { registryBase: deps.registryBase } : {}),
    }),
    await verifyIdentity({
      ...(deps.runner !== undefined ? { runner: deps.runner } : {}),
      distEntry: deps.distEntry ?? packagedDistEntry(import.meta.url),
      env: facts.env,
    }),
    verifyRouteAParity(facts),
    verifyDualRoute(facts),
    verifyScope(),
  ];
  const verdict = aggregateVerdict(aspects);
  const report: InspectReport = { schemaVersion: 1, scope: "v1", verdict, aspects };
  if (ctx.flags.json) {
    ctx.stdout(JSON.stringify(report));
  } else {
    ctx.stdout(`border opencode inspect [${report.scope}] ${verdict}`);
    for (const a of aspects) {
      ctx.stdout(`  ${a.verdict.padEnd(6)} ${a.id}: ${a.detail}`);
    }
  }
  return inspectExit(verdict);
}
