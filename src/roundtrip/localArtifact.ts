// provenance: border-inspect-roadmap.md W2.4(b) — G-LOCAL: `border roundtrip`
// may prove a LOCAL artifact file (an unpublished wheel, a locally packed
// tarball) instead of a registry spec.
//
// Why the input table is CLOSED (four extensions, no sniffing): ecosystem IS
// manager semantics. Reading magic bytes to "guess" the lane would grade an
// artifact through a package manager nobody chose, and a wrong guess silently
// produces a wrong residue verdict — the exact silent-clean failure this tool
// exists to refuse. A file whose extension is not in the table gets exit 2
// listing the table; the user then says, unambiguously, which manager's
// install/uninstall contract is under test.
//
// Why the digest IS the identity: a local artifact has no registry coordinate
// to vouch for it, so the only portable fact left is the bytes themselves.
// The streaming sha256 minted here is what the ledger proof keys on and what
// the requireProof valve later matches against the staged artifact — the same
// RoundtripRecord field the registry lane fills from fetched bytes, consumed
// unchanged.
//
// argv discipline (inherited from the W2.1 profiles): the user's path NEVER
// reaches a docker argv or a shell string. The bytes are staged to a temp
// file exactly like the registry flow, and the container only ever sees the
// fixed /root/p.<ext> name derived from the closed table.
import { createReadStream, existsSync, statSync } from "node:fs";
import { createHash } from "node:crypto";
import { basename, resolve } from "node:path";

import { UnknownArgError } from "../cli/exit.ts";
import { EngineRunError } from "../engines/support.ts";
import { SCAN_MAX_ARTIFACT_BYTES, safeArtifactName } from "../scan/fetch.ts";
import type { ScanEcosystem } from "../scan/spec.ts";

/** Closed extension→ecosystem table. Lowercase canonical names, no aliases. */
const EXT_TABLE: ReadonlyMap<string, ScanEcosystem> = new Map<string, ScanEcosystem>([
  [".whl", "pypi"],
  [".tgz", "npm"],
  [".crate", "crates"],
  [".gem", "rubygems"],
]);

const EXT_LIST = ".whl (pypi), .tgz (npm), .crate (crates), .gem (rubygems)";

/** Canonical in-container artifact name per extension (registry lanes use the same fixed names). */
const CONTAINER_NAME: ReadonlyMap<string, string> = new Map<string, string>([
  [".tgz", "/root/p.tgz"],
  [".crate", "/root/p.crate"],
  [".gem", "/root/p.gem"],
]);

// Why wheels are the one exception (live docker proof, W2.4b): pip grades a
// wheel by parsing its FILENAME (PEP 427 tags) before it ever reads a byte —
// a fixed "/root/p.whl" is rejected outright ("not a valid wheel filename").
// So the pypi lane carries the artifact's own basename in, sanitized through
// safeArtifactName (basename-only + [A-Za-z0-9._+-] whitelist): the grammar
// check above already guarantees >= 5 dash fields in the whitelist charset,
// and sanitization can never re-introduce a directory or shell metacharacter.
//
// Wheel-lane honesty boundary (VERIFIER-REPORT-W24B-SHADOW, live-proven
// 2026-09-11 on pip 25.0.1 AND 24.0): the LOCAL PyPI-wheel lane is
// residue-INERT by construction. pip fully records the files it installs and
// prunes its own directories, so even a wheel planted with hostile
// `.data/data/...` entries leaves a ZERO survivor set after uninstall — a
// PASS on such a plant is pip's contract working, not a missed detection, and
// claiming a planted wheel would flag residue here would be fabricated.
// The wheel local roundtrip still earns its keep — installability,
// benign-clean, and exact-bytes (digest-is-identity) proof — but
// planted-detection demos belong to the lanes whose managers EXECUTE install
// hooks: npm (.tgz postinstall runs under `npm install -g
// --foreground-scripts`), gem (extconf custom writes), crates (build.rs).
// The container-name exception above exists purely so pip ACCEPTS the file;
// it is not, and never was, a residue surface.
const wheelContainerPath = (base: string, name: string, version: string): string =>
  `/root/${safeArtifactName(base, `${name}-${version}-py3-none-any.whl`)}`;

export type LocalArtifactInput = {
  readonly absPath: string;
  readonly ecosystem: ScanEcosystem;
  /** filename-derived package identity — the uninstall leg's coordinate. */
  readonly name: string;
  readonly version: string;
  readonly containerPath: string;
  /** provenance marker rendered verbatim into human + JSON output. */
  readonly source: string;
};

const bad: (why: string) => never = (why) => {
  throw new UnknownArgError(`border roundtrip: ${why}`);
};

/**
 * Per-ecosystem filename grammars (closed): wheel PEP 427 dash fields, npm
 * pack/registry `<name>-<semver>.tgz`, cargo `<name>-<version>.crate` (crates
 * names never contain '-', so the FIRST digit-leading split wins), rubygems
 * `<name>-<version>.gem`. These grammars only produce [A-Za-z0-9._+-] classes,
 * keeping every derived name inside the profiles' shArgv whitelist. An
 * artifact whose filename does not match its lane's grammar exits 2 — border
 * will not uninstall a package under a guessed coordinate (over-report and
 * residue noise are tolerated; a silent no-op uninstall is not).
 */
function identityFromFilename(base: string, eco: ScanEcosystem): { name: string; version: string } | null {
  if (eco === "pypi") {
    const parts = base.slice(0, -".whl".length).split("-");
    // PEP 427: {name}-{version}(-{build})?-{python}-{abi}-{platform}
    const name = parts[0] ?? "";
    const version = parts[1] ?? "";
    if (parts.length < 5 || !/^[A-Za-z0-9][A-Za-z0-9._]*$/.test(name) || !/^\d[A-Za-z0-9._+!]*$/.test(version)) return null;
    return { name, version };
  }
  if (eco === "npm") {
    const m = /^(.+)-(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)\.tgz$/i.exec(base);
    if (m === null || m[1] === undefined || m[2] === undefined) return null;
    return { name: m[1], version: m[2] };
  }
  if (eco === "crates") {
    const m = /^([a-z0-9_][a-z0-9._-]*?)-(\d[A-Za-z0-9._+-]*)\.crate$/i.exec(base);
    if (m === null || m[1] === undefined || m[2] === undefined) return null;
    return { name: m[1], version: m[2] };
  }
  const m = /^([A-Za-z0-9][A-Za-z0-9._-]*?)-(\d[A-Za-z0-9._+-]*)\.gem$/i.exec(base);
  if (m === null || m[1] === undefined || m[2] === undefined) return null;
  return { name: m[1], version: m[2] };
}

const GRAMMAR_HINT: Readonly<Record<ScanEcosystem, string>> = {
  pypi: "PEP 427 wheel names, e.g. jupyter_core-5.8.1-py3-none-any.whl",
  npm: "npm pack names, e.g. node-fetch-2.6.1.tgz (scoped packages flatten to scope-pkg-1.0.0.tgz)",
  crates: "cargo package names, e.g. rt-crate-1.0.0.crate",
  rubygems: "gem package names, e.g. rt-gem-1.0.0.gem",
};

/**
 * Classify a roundtrip argument. Returns null ⇒ registry lane (unchanged).
 * Throws UnknownArgError (exit 2, no fetch attempted) for: an existing
 * directory, a path-SHAPED argument (contains '/' or carries a table
 * extension) that does not resolve to an existing file, a file outside the
 * closed extension table, or a filename the lane grammar cannot parse.
 * `parsesAsRegistrySpec` keeps slash-bearing SPECS (npm:@scope/pkg@1.0.0) on
 * the registry lane even when no such file exists — detection is existence
 * first, shape second, and a valid spec is never a missing path.
 */
export function classifyLocalInput(raw: string, cwd: string, parsesAsRegistrySpec: (arg: string) => boolean): LocalArtifactInput | null {
  const abs = resolve(cwd, raw);
  if (existsSync(abs)) {
    const st = statSync(abs);
    if (st.isDirectory()) {
      bad(`'${raw}' resolves to a directory (${abs}) — local mode needs a single artifact FILE, not a directory`);
    }
    if (!st.isFile()) {
      bad(`'${raw}' resolves to something that is not a regular file (${abs})`);
    }
    const lower = basename(abs).toLowerCase();
    const ext = [...EXT_TABLE.keys()].find((e) => lower.endsWith(e)) ?? null;
    if (ext === null) {
      const known = [...EXT_TABLE.keys()].map((e) => `\`${e}\``).join(", ");
      bad(`'${basename(abs)}' exists but its extension is not in the closed local-artifact table (${known}) — no content sniffing is done; supported: ${EXT_LIST}`);
    }
    const eco = EXT_TABLE.get(ext) as ScanEcosystem;
    const identity = identityFromFilename(basename(abs), eco);
    if (identity === null) {
      bad(`cannot derive package identity from '${basename(abs)}' — expected ${GRAMMAR_HINT[eco]}`);
    }
    return {
      absPath: abs,
      ecosystem: eco,
      name: identity.name,
      version: identity.version,
      containerPath: ext === ".whl" ? wheelContainerPath(basename(abs), identity.name, identity.version) : (CONTAINER_NAME.get(ext) as string),
      source: `local:${abs}`,
    };
  }
  // missing path: only arguments that LOOK local (path separators or a table
  // extension) die here; everything else falls through to the registry lane's
  // own typed spec errors (byte-identical W2.1 behavior).
  const looksLocal = raw.includes("/") || [...EXT_TABLE.keys()].some((e) => raw.toLowerCase().endsWith(e));
  if (looksLocal && !parsesAsRegistrySpec(raw)) {
    bad(`'${raw}' (resolved: ${abs}) is not an existing file — a path-shaped argument is LOCAL mode and is never fetched; fix the path or pass a registry spec`);
  }
  return null;
}

/**
 * Streaming read + digest in one pass: the sha256 is computed per chunk (a
 * 200 MiB wheel never round-trips through a string), the size cap fails
 * closed mid-stream exactly like the registry readCapped, and the returned
 * bytes are the SAME bytes the digest covers — which are the bytes staged for
 * `docker cp`. digest-is-identity, end to end.
 */
export async function readLocalArtifact(absPath: string, cap: number = SCAN_MAX_ARTIFACT_BYTES): Promise<{ bytes: Buffer; sha256: string }> {
  const hash = createHash("sha256");
  const parts: Buffer[] = [];
  let total = 0;
  for await (const chunk of createReadStream(absPath)) {
    const b = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as ArrayBuffer);
    total += b.byteLength;
    if (total > cap) {
      throw new EngineRunError(
        `border roundtrip: ${absPath} streams past the 200 MiB artifact size cap after ${String(total)} bytes — refusing to prove a partial read (fail-closed)`,
        null,
      );
    }
    hash.update(b);
    parts.push(b);
  }
  return { bytes: Buffer.concat(parts), sha256: hash.digest("hex") };
}
