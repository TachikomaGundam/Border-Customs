// provenance: .omo/plans/border-opencode-inspect.md T5 — seams + worlds for the
// inspect suite. Every side channel (fs roots, registry fetcher, spawn runner)
// is scripted here; nothing in these helpers touches the real HOME/XDG profile.
import { chmodSync, existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import type { Ctx, Flags } from "../../src/cli/types.ts";
import { handlers } from "../../src/commands/index.ts";
import type { Env, Facts, SpawnOutcome, SpawnTarget } from "../../src/opencode/contract.ts";
import type { CacheDir, ConfigSource } from "../../src/opencode/jsonconfig.ts";
import type { ScanFetcher } from "../../src/scan/fetch.ts";
import { BORDER_ROOT, makeFixtureDir, removeDir } from "./fixtures.ts";

export { BORDER_ROOT };

export const HELP_RESPONDER = join(BORDER_ROOT, "test", "fixtures", "opencode", "border-help-responder.mjs");
export const IMPOSTOR = join(BORDER_ROOT, "test", "fixtures", "opencode", "opencode-impostor.mjs");
export const FAKE_INSPECT_CLI = join(BORDER_ROOT, "test", "fixtures", "opencode", "fake-inspect-cli.mjs");

export function chmodFixtures(): void {
  for (const f of [HELP_RESPONDER, IMPOSTOR, FAKE_INSPECT_CLI]) {
    if (existsSync(f)) chmodSync(f, 0o755);
  }
}

/** A hermetic opencode world: HOME/XDG roots in test/tmp, nothing declared anywhere. */
export type World = {
  readonly home: string;
  readonly env: Record<string, string>;
  readonly cwd: string;
  readonly cacheRoot: string;
  readonly globalConfig: string;
  readonly routeADrop: string;
};

export function makeWorld(prefix: string): World {
  const home = makeFixtureDir(prefix);
  const xdgConfig = join(home, ".config");
  const xdgCache = join(home, ".cache");
  const cwd = join(home, "proj");
  mkdirSync(join(xdgConfig, "opencode"), { recursive: true });
  mkdirSync(xdgCache, { recursive: true });
  mkdirSync(cwd, { recursive: true });
  return {
    home,
    cwd,
    env: { HOME: home, XDG_CONFIG_HOME: xdgConfig, XDG_CACHE_HOME: xdgCache, PATH: process.env["PATH"] ?? "/usr/bin:/bin" },
    cacheRoot: join(xdgCache, "opencode", "packages"),
    globalConfig: join(xdgConfig, "opencode", "opencode.jsonc"),
    routeADrop: join(xdgConfig, "opencode", "plugins", "border.ts"),
  };
}

export function removeWorld(world: World): void {
  removeDir(world.home);
}

/** Write an opencode.jsonc declaring the plugin — carries a // comment, an https
 * URL, and trailing commas so the string-aware jsonc reader is exercised on
 * every path, mirroring the real global file's anatomy. */
export function writeConfig(path: string, specs: readonly string[]): void {
  mkdirSync(join(path, ".."), { recursive: true });
  const entries = specs.map((s) => `    "${s}",`).join("\n");
  writeFileSync(path, `{
  "$schema": "https://opencode.ai/config.json", // url double-slash must survive comment stripping
  "plugin": [
${entries}
  ],
}
`);
}

export type CachePlant = {
  readonly version?: string | null;
  readonly marker?: string | null | "foreign";
  readonly noPackageJson?: boolean;
  readonly noPluginFile?: boolean;
};

/** Plant `<cacheRoot>/border-customs@<tag>/node_modules/border-customs/...` bytes. */
export function plantCacheDir(world: World, tag: string, plant: CachePlant): void {
  const pkgRoot = join(world.cacheRoot, `border-customs@${tag}`, "node_modules", "border-customs");
  mkdirSync(join(pkgRoot, "plugin"), { recursive: true });
  if (plant.noPackageJson !== true) {
    writeFileSync(join(pkgRoot, "package.json"), JSON.stringify({ name: "border-customs", version: plant.version ?? "0.0.0" }));
  }
  if (plant.noPluginFile !== true) {
    const first =
      plant.marker === "foreign" ? "// someone else's plugin" : plant.marker === null ? "// no marker here" : `// border-opencode-plugin v${plant.marker}`;
    writeFileSync(join(pkgRoot, "plugin", "border.ts"), `${first}\n// rest\n`);
  }
}

export function plantRouteADrop(world: World, bytes: string | Buffer): void {
  mkdirSync(join(world.routeADrop, ".."), { recursive: true });
  writeFileSync(world.routeADrop, bytes);
}

// ---------------------------------------------------------------- Facts (pure)

export function configSource(path: string, status: ConfigSource["status"], specs: readonly string[] = []): ConfigSource {
  return { path, status, specs };
}

export function cacheDir(tag: string, packageVersion: string | null, markerVersion: string | null, markerLine?: string | null): CacheDir {
  return {
    dir: `/fake/cache/border-customs@${tag}`,
    tag,
    packageVersion,
    markerVersion,
    markerLine: markerLine ?? (markerVersion === null ? null : `// border-opencode-plugin v${markerVersion}`),
  };
}

export function factsOver(over: Partial<Facts>): Facts {
  return {
    pkg: "border-customs",
    env: {},
    cacheRoot: "/fake/cache",
    cacheDirs: [],
    configs: [configSource("/fake/global.jsonc", "absent"), configSource("/fake/project.jsonc", "absent")],
    packagedPlugin: null,
    routeAPlugin: "/fake/config/opencode/plugins/border.ts",
    routeAInstalled: false,
    routeABytes: null,
    ...over,
  };
}

// ---------------------------------------------------------------- registry seam

export type FakeRegistry = { readonly fetcher: ScanFetcher; readonly calls: string[] };

export function fakeRegistry(script: (url: string) => { status: number; json?: unknown } | { error: string }): FakeRegistry {
  const calls: string[] = [];
  const fetcher: ScanFetcher = async (url) => {
    calls.push(url);
    const r = script(url);
    if ("error" in r) throw new Error(r.error);
    const body = Buffer.from(JSON.stringify(r.json ?? {}));
    return { status: r.status, contentLength: body.byteLength, chunks: async function* () { yield body; } };
  };
  return { fetcher, calls };
}

export const registryForbidsCalls: FakeRegistry = {
  calls: [],
  fetcher: async () => {
    throw new Error("offline aspect: the registry must not be consulted");
  },
};

// ---------------------------------------------------------------- runner seam

export type ScriptedRunner = {
  readonly runner: (target: SpawnTarget, argv: readonly string[]) => Promise<SpawnOutcome>;
  readonly seen: { target: SpawnTarget; argv: readonly string[] }[];
};

export function scriptedRunner(outcome: (target: SpawnTarget) => SpawnOutcome | Promise<SpawnOutcome>): ScriptedRunner {
  const seen: { target: SpawnTarget; argv: readonly string[] }[] = [];
  return {
    seen,
    runner: async (target, argv) => {
      seen.push({ target, argv });
      return outcome(target);
    },
  };
}

export const SPAWNED_OK: SpawnOutcome = { status: 0, stdout: "border — gate\nusage: border <command>\n", stderr: "" };

// ---------------------------------------------------------------- ctx

export type CapturedCtx = { readonly ctx: Ctx; readonly out: string[]; readonly err: string[] };

export function inspectCtx(env: Env, cwd: string, json: boolean): CapturedCtx {
  const out: string[] = [];
  const err: string[] = [];
  const flags: Flags = { force: false, yes: false, llm: false, json };
  return { ctx: { command: "opencode", flags, positionals: ["inspect"], cwd, env, stdout: (l) => out.push(l), stderr: (l) => err.push(l), handlers }, out, err };
}
