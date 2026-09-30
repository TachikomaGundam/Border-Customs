// provenance: .omo/plans/border-opencode-inspect.md T1 — the inspect contract leaf.
//
// Types, identity markers, path rules, and pure byte helpers shared by the V1
// load-surface self-audit. DAG root: node builtins + `import type` only. It
// never reaches the ledger or the check pipeline (import-audit contract pinned
// by test/opencode.inspect.test.ts) and never writes anything.
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import os from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import type { CacheDir, ConfigSource } from "./jsonconfig.ts";


// Single home for the installer/inspector marker definitions (L-SINGLE-SOURCE);
// src/commands/opencode.ts re-exports them for its existing importers.
/** First-line identity markers (the packaged assets must start with these prefixes). */
export const PLUGIN_MARKER = "// border-opencode-plugin v";
export const COMMAND_MARKER = "<!-- border-opencode-command -->";

export const BORDER_PACKAGE = "border-customs";
export const DEFAULT_REGISTRY_BASE = "https://registry.npmjs.org";
/** Registry probe bound — mirrors the 15 s cap of the 2026-09-24 drift-watch script. */
export const REGISTRY_TIMEOUT_MS = 15_000;

export type AspectVerdict = "PASS" | "FAIL" | "CANNOT";

export type AspectId =
  | "cache-version"
  | "spec-freshness"
  | "identity-handshake"
  | "route-a-parity"
  | "dual-route"
  | "scope";

/** The six aspects in the plan's table order — the --json array order. */
export const ASPECT_IDS: readonly AspectId[] = [
  "cache-version",
  "spec-freshness",
  "identity-handshake",
  "route-a-parity",
  "dual-route",
  "scope",
];

export type AspectResult = {
  readonly id: AspectId;
  readonly verdict: AspectVerdict;
  readonly detail: string;
};

/** The --json contract (plan 表面契约): scope:"v1" is the consumer-facing certificate bound. */
export type InspectReport = {
  readonly schemaVersion: 1;
  readonly scope: "v1";
  readonly verdict: AspectVerdict;
  readonly aspects: readonly AspectResult[];
};

/** One spawn candidate, mirroring plugin/border.ts's BinResolution shape verbatim. */
export type SpawnTarget = {
  readonly bin: string;
  readonly prefix: readonly string[];
  readonly label: string;
};

/** status null = the child could not be spawned at all (ENOENT/EACCES/ENOEXEC). */
export type SpawnOutcome = {
  readonly status: number | null;
  readonly stdout: string;
  readonly stderr: string;
};

/** The identity-probe seam (M2): unit tests script the handshake without ever spawning. */
export type InspectRunner = (target: SpawnTarget, argv: readonly string[]) => Promise<SpawnOutcome>;

export type Env = Readonly<Record<string, string | undefined>>;

/** Everything the six aspects read — gathered once, read-only, by runInspectCore. */
export type Facts = {
  readonly pkg: string;
  readonly env: Env;
  readonly cacheRoot: string;
  readonly cacheDirs: readonly CacheDir[];
  /** [global, project] opencode.jsonc plugin declarations, in that order. */
  readonly configs: readonly ConfigSource[];
  readonly packagedPlugin: Buffer | null;
  readonly routeAPlugin: string;
  readonly routeAInstalled: boolean;
  /** Snapshot read of the drop file: null = present-but-unreadable (or absent). */
  readonly routeABytes: Buffer | null;
};

export function sha256Hex(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}

export function firstLine(bytes: Buffer): string {
  const text = bytes.toString("utf8");
  const newline = text.indexOf("\n");
  return newline < 0 ? text : text.slice(0, newline);
}

/** The opencode config root: $XDG_CONFIG_HOME or $HOME/.config (os.homedir() as last resort). */
export function opencodeConfigRoot(env: Env): string {
  const xdg = env["XDG_CONFIG_HOME"] ?? "";
  if (xdg.length > 0) return xdg;
  const home = env["HOME"] ?? "";
  return join(home.length > 0 ? home : os.homedir(), ".config");
}

/** The Route-B package cache root: $XDG_CACHE_HOME or $HOME/.cache, then opencode/packages. */
export function opencodeCacheRoot(env: Env): string {
  const xdg = env["XDG_CACHE_HOME"] ?? "";
  const base = xdg.length > 0 ? xdg : join(env["HOME"] ?? os.homedir(), ".cache");
  return join(base, "opencode", "packages");
}

/** Route A destination for the plugin file (what `border opencode install` drops). */
export function routeAPluginPath(env: Env): string {
  return join(opencodeConfigRoot(env), "opencode", "plugins", "border.ts");
}

/** The `<root>/plugin/<file>` asset next to (or two-up from) the running module — installer idiom. */
export function packagedAssetPath(moduleUrl: string, fileName: string): string {
  const here = dirname(fileURLToPath(moduleUrl));
  const candidates = [
    join(here, "..", "plugin", fileName), // dist (bundled) mode: <root>/plugin/<f>
    join(here, "..", "..", "plugin", fileName), // src mode: <root>/plugin/<f>
  ];
  return candidates.find((p) => existsSync(p)) ?? (candidates[1] as string);
}

/** The package's own dist entry — the identity candidate a plugin host resolves as ../dist/index.js. */
export function packagedDistEntry(moduleUrl: string): string {
  const here = dirname(fileURLToPath(moduleUrl));
  const candidates = [
    join(here, "index.js"), // dist (bundled) mode: <root>/dist/index.js
    join(here, "..", "dist", "index.js"), // src/opencode mode one level under root
    join(here, "..", "..", "dist", "index.js"), // src mode: <root>/dist/index.js
  ];
  return candidates.find((p) => existsSync(p)) ?? (candidates[2] as string);
}
