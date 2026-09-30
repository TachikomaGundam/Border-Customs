// provenance: .omo/plans/border-opencode-inspect.md T1 — opencode surface readers.
//
// The three read-only parsers the aspects run on: an opencode.jsonc plugin
// array (string-aware: a "https://" inside a string must survive comment
// stripping), the `name@spec` grammar split, and the Route-B cache directory
// enumeration. No network, no writes.
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { PLUGIN_MARKER, firstLine } from "./contract.ts";

// String-aware comment stripping + trailing-comma removal, then JSON.parse.
// Naive regex stripping would eat the "//" inside "https://…" string values,
// and the real global config carries both comments and URLs.

export function stripJsoncComments(text: string): string {
  let out = "";
  let inString = false;
  let inLine = false;
  let inBlock = false;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i] as string;
    const next = text[i + 1] ?? "";
    if (inLine) {
      if (ch === "\n") {
        inLine = false;
        out += ch;
      }
      continue;
    }
    if (inBlock) {
      if (ch === "*" && next === "/") {
        inBlock = false;
        i += 1;
        out += " ";
      }
      continue;
    }
    if (inString) {
      if (ch === "\\") {
        out += ch + next;
        i += 1;
        continue;
      }
      if (ch === '"') inString = false;
      out += ch;
      continue;
    }
    if (ch === '"') {
      inString = true;
      out += ch;
      continue;
    }
    if (ch === "/" && next === "/") {
      inLine = true;
      i += 1;
      continue;
    }
    if (ch === "/" && next === "*") {
      inBlock = true;
      i += 1;
      continue;
    }
    out += ch;
  }
  return out;
}

export function parseJsonc(text: string): unknown {
  return JSON.parse(stripJsoncComments(text).replace(/,(\s*[}\]])/g, "$1"));
}

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null;

/** `${pkg}@[spec]` split — npm disambiguation: scoped names split at the LAST '@'. */
export function splitNpmSpec(entry: string): { readonly name: string; readonly spec: string | null } {
  const at = entry.lastIndexOf("@");
  if (at <= 0) return { name: entry, spec: null };
  return { name: entry.slice(0, at), spec: entry.slice(at + 1) };
}

export type ConfigSource = {
  readonly path: string;
  readonly status: "absent" | "ok" | "error";
  /** Raw plugin-array entries naming pkg ("border-customs@latest", bare names included). */
  readonly specs: readonly string[];
};

/** Read ONE opencode.jsonc's plugin array; a missing file is "absent", never an error. */
export function readPluginDeclarations(path: string, pkg: string): ConfigSource {
  const none: ConfigSource = { path, status: "absent", specs: [] };
  let text: string;
  try {
    if (!existsSync(path)) return none;
    text = readFileSync(path, "utf8");
  } catch {
    return { path, status: "error", specs: [] };
  }
  let parsed: unknown;
  try {
    parsed = parseJsonc(text);
  } catch {
    return { path, status: "error", specs: [] };
  }
  if (!isRecord(parsed)) return { path, status: "error", specs: [] };
  const plugin = Array.isArray(parsed["plugin"]) ? (parsed["plugin"] as unknown[]) : [];
  const specs = plugin.filter((e): e is string => typeof e === "string" && splitNpmSpec(e).name === pkg);
  return { path, status: "ok", specs };
}



export type CacheDir = {
  readonly dir: string;
  /** The cached spec string: `border-customs@latest` -> "latest". */
  readonly tag: string;
  readonly packageVersion: string | null;
  readonly markerVersion: string | null;
  readonly markerLine: string | null;
};

/** Enumerate `<cacheRoot>/<pkg>@*` dirs, reading each package.json version + plugin marker line. */
export function listCacheDirs(cacheRoot: string, pkg: string): readonly CacheDir[] {
  let names: string[];
  try {
    names = readdirSync(cacheRoot, { withFileTypes: true })
      .filter((e) => e.isDirectory() && e.name.startsWith(`${pkg}@`))
      .map((e) => e.name)
      .sort();
  } catch {
    return [];
  }
  return names.map((name) => {
    const pkgRoot = join(cacheRoot, name, "node_modules", pkg);
    let packageVersion: string | null = null;
    try {
      const meta = parseJsonc(readFileSync(join(pkgRoot, "package.json"), "utf8"));
      if (isRecord(meta) && typeof meta["version"] === "string") packageVersion = meta["version"];
    } catch {
      packageVersion = null;
    }
    let markerLine: string | null = null;
    try {
      markerLine = firstLine(readFileSync(join(pkgRoot, "plugin", "border.ts")));
    } catch {
      markerLine = null;
    }
    const markerVersion =
      markerLine !== null && markerLine.startsWith(PLUGIN_MARKER)
        ? markerLine.slice(PLUGIN_MARKER.length).trim()
        : null;
    return { dir: join(cacheRoot, name), tag: name.slice(pkg.length + 1), packageVersion, markerVersion, markerLine };
  });
}
