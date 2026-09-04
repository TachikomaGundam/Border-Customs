// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 11
//
// Pure manifest logic for the npm artifact stage (G39): parse what the tools
// say (package.json, `npm pack --json`) into typed shapes, then diff the
// ACTUAL packed entries against what the declared `files` whitelist accounts
// for. `main`/`bin` force-packed files that match no whitelist glob are the
// leak shape this rule exists to catch — build output shipping unpublished.
//
// Accounting is deliberately over-inclusive (the plan documents this as the
// safe direction): a packed entry is accounted if ANY of these match —
//   * exact path or directory prefix (`src` accounts `src/a.js`);
//   * bare-name path segment (`js` accounts `deep/js/x.js`, npm-packlist style);
//   * the whitelist pattern as a root-anchored glob, a `**/`-prefixed glob
//     (npm packlist applies patterns to nested dirs too), or the basename;
//   * the ALWAYS_PACKED name set {package.json, README*, CHANGELOG*, LICENSE*}
//     at any depth/case. CHANGELOG membership is npm-version-dependent
//     (round-4 m-R4-2: not force-packed on 11.19.1) — over-accounting a name
//     npm no longer packs is harmless; under-accounting is a false HIGH.
import { globToRegExp, normalizePath } from "../rules/artifactMatchers.ts";
import { EngineRunError } from "../engines/support.ts";

/** npm keys whose presence in the PUBLISHED manifest executes code at install time (G33). */
export const LIFECYCLE_SCRIPT_KEYS: readonly string[] = ["preinstall", "install", "postinstall", "prepare"];

const ALWAYS_PACKED_BASE = [/^package\.json$/i, /^readme(\.[^/]*)?$/i, /^changelog(\.[^/]*)?$/i, /^license(\.[^/]*)?$/i];

const HEX40_RE = /^[0-9a-f]{40}$/;

export type NpmManifest = {
  readonly name: string | null;
  readonly version: string | null;
  /** truthy `private` field — npm blocks publish on any truthy value. */
  readonly isPrivate: boolean;
  /** `files` whitelist; null = field absent ⇒ npm's default inclusion owns the set. */
  readonly files: readonly string[] | null;
  readonly scripts: Readonly<Record<string, string>>;
};

export type PackReport = {
  readonly filename: string;
  readonly name: string;
  readonly version: string;
  /** sha1 hex npm reports for the tarball — cross-checked against the real bytes. */
  readonly shasum: string;
  readonly size: number;
};

function asRecord(value: unknown, what: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new EngineRunError(`${what} is not a JSON object`, null);
  }
  return value as Record<string, unknown>;
}

/** Parse a package.json body. Malformed JSON / wrong shapes are tool errors, never silent passes. */
export function parseNpmManifest(text: string): NpmManifest {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    throw new EngineRunError(`cannot parse package.json — ${detail}`, null);
  }
  const obj = asRecord(raw, "package.json");
  const name = typeof obj["name"] === "string" ? obj["name"] : null;
  const version = typeof obj["version"] === "string" ? obj["version"] : null;
  let files: readonly string[] | null = null;
  if (obj["files"] !== undefined) {
    if (!Array.isArray(obj["files"]) || obj["files"].some((f) => typeof f !== "string")) {
      throw new EngineRunError("cannot parse package.json — files field must be an array of strings", null);
    }
    files = obj["files"] as readonly string[];
  }
  let scripts: Record<string, string> = {};
  if (obj["scripts"] !== undefined) {
    const s = asRecord(obj["scripts"], "package.json scripts field");
    scripts = Object.fromEntries(Object.entries(s).filter(([, v]) => typeof v === "string")) as Record<string, string>;
  }
  return { name, version, isPrivate: Boolean(obj["private"]), files, scripts };
}

/** Validate one `npm pack --json` report entry. Exactly one package or fail closed. */
export function parsePackReport(text: string): PackReport {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    throw new EngineRunError(`cannot parse npm pack --json output — ${detail}`, null);
  }
  if (!Array.isArray(raw) || raw.length !== 1) {
    throw new EngineRunError("unexpected npm pack --json report: expected a single-entry array", null);
  }
  const obj = asRecord(raw[0], "npm pack report entry");
  const { filename, name, version, shasum, size } = obj;
  if (
    typeof filename !== "string" || filename.length === 0 || filename.includes("/") || filename.includes("\\") || filename.includes("..")
    || typeof name !== "string" || typeof version !== "string"
    || typeof shasum !== "string" || !HEX40_RE.test(shasum)
    || typeof size !== "number" || !Number.isInteger(size) || size < 0
  ) {
    throw new EngineRunError("unexpected npm pack --json report: malformed filename/name/version/shasum/size", null);
  }
  return { filename, name, version, shasum, size };
}

export function isAlwaysPackedName(entry: string): boolean {
  const base = entry.split("/").at(-1) ?? entry;
  return ALWAYS_PACKED_BASE.some((re) => re.test(base));
}

export function entryIsWhitelisted(entry: string, files: readonly string[]): boolean {
  const segments = entry.split("/");
  const base = segments.at(-1) ?? entry;
  for (const rawPattern of files) {
    const pattern = normalizePath(rawPattern.replace(/^\/+/, ""));
    if (pattern.length === 0 || pattern.startsWith("!")) continue;
    if (entry === pattern || entry.startsWith(`${pattern}/`)) return true;
    const plain = !/[*?{[]/.test(pattern);
    if (plain && !pattern.includes("/") && segments.includes(pattern)) return true;
    if (globToRegExp(pattern).test(entry)) return true;
    if (globToRegExp(`**/${pattern}`).test(entry)) return true;
    if (!pattern.includes("/") && globToRegExp(pattern).test(base)) return true;
  }
  return false;
}

/**
 * Packed entries that the declared whitelist + always-packed names do NOT
 * account for. No whitelist (files absent) ⇒ nothing is "unexpected": with no
 * declared set there is no diff baseline, only npm's implicit rules (owned by
 * the content scans and publint, not this rule).
 */
export function unexpectedEntries(
  entries: readonly string[],
  files: readonly string[] | null | undefined,
): string[] {
  if (files === null || files === undefined) return [];
  return entries.filter((e) => !isAlwaysPackedName(e) && !entryIsWhitelisted(e, files)).sort();
}
