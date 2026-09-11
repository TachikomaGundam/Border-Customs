// provenance: border-inspect-roadmap.md W4.1/W4.2 — the release-coherence rule family.
//
// FOUNDING CASE (aihr incident): a wheel labeled version 0.2.2 on PyPI shipped a package whose
// `__init__.__version__` said 0.2.1 (pyproject itself said 0.2.2) — users installed "0.2.2"
// bytes carrying older module behavior. A second drift class bit border directly: the published
// npm tarball's User-Agent said 0.3.0 while package.json said 0.3.1, and package-lock.json's
// root version sat at 0.1.0 through two releases. Version truth must AGREE across every source
// packed INSIDE the artifact before anything ships. This module is the closed-table analyzers;
// the ecosystem stages (artifacts/{npm,pypi,crates,rubygems}.ts) route their extracted trees
// here and the check pipeline routes release.twin pairs after the channel loop (src/check.ts).
//
// ABSENT-SOURCE BOUNDARY (load-bearing, documented here per plan W4.1): an absent SECOND
// version source is NOT drift and NEVER a finding. package-lock.json / Cargo.lock / PKG-INFO
// are usually not packed at all (npm `files` whitelists, cargo default ignores) — a rule that
// fired on "not packed" would false-green-block honest releases and train users to pass
// --force, which is exactly how gate credibility dies. Conversely, a source that IS present
// but statically unreadable (dynamic `__version__`, malformed lock) is 'cannot-verify' — it
// emits release-coherence-unverifiable-source MEDIUM and is NEVER silently clean.
//
// Doctrine (mirrors rules/residueMatchers.ts + artifacts/manifestDiff.ts):
//   * regex/text extraction ONLY — no python/ruby/toml parsing, nothing is ever executed;
//   * every rule id in RELEASE_COHERENCE_SEVERITIES is closed-table (no user-configurable
//     patterns); severities fixed: drift CRITICAL, twin-drift CRITICAL, unverifiable MEDIUM;
//   * findings flow through the native pipeline (residueFindings-style digest keying, then
//     applyAllowList/report as for every other rule);
//   * this file rides computeCheckRulesHash's fingerprint (RELEASE_FINGERPRINT_SOURCES in
//     src/check/rulesHash.ts) so any edit here rotates rulesHash and invalidates proofs,
//     exactly like the residue sources.
import { spawnSync } from "node:child_process";
import { basename, join } from "node:path";

import { type Finding, type Severity } from "../findings.ts";
import { type LedgerArtifact } from "../ledger/records.ts";
import { redact, type TextSanitizer } from "../redact.ts";

export const RELEASE_COHERENCE_DRIFT_RULE = "release-coherence-version-drift";
export const RELEASE_COHERENCE_TWIN_RULE = "release-coherence-twin-drift";
export const RELEASE_COHERENCE_UNVERIFIABLE_RULE = "release-coherence-unverifiable-source";

/** Closed severity table — the ONLY rule ids this family may emit. */
export const RELEASE_COHERENCE_SEVERITIES: Readonly<Record<string, Severity>> = {
  [RELEASE_COHERENCE_DRIFT_RULE]: "CRITICAL",
  [RELEASE_COHERENCE_TWIN_RULE]: "CRITICAL",
  [RELEASE_COHERENCE_UNVERIFIABLE_RULE]: "MEDIUM",
};

const TARGET = "artifact";
const ENGINE = "native";
const FOUNDING = "version truth must AGREE across every source packed in the artifact (aihr: a wheel named 0.2.2 shipped __version__ 0.2.1)";

// --------------------------------------------------------------- source probes (pure text)

type Probe = { readonly status: "literal"; readonly value: string } | { readonly status: "dynamic"; readonly reason: string } | null;

/** `__version__ = "X"` literal on its own line; ANY other assignment/import shape ⇒ dynamic. */
export function probeDunderVersion(text: string): Probe {
  for (const line of text.split(/\r?\n/)) {
    const assign = /^\s*__version__\s*=\s*(.+?)\s*$/.exec(line);
    if (assign?.[1] !== undefined) {
      const lit = /^(['"])((?:(?!\1).)+)\1(?:\s*#.*)?$/.exec(assign[1]);
      return lit?.[2] !== undefined ? { status: "literal", value: lit[2] } : { status: "dynamic", reason: `__version__ assigned a non-literal (${assign[1].slice(0, 60)})` };
    }
    if (/^\s*(?:from\s+\S+\s+)?import\b.*\b__version__\b/.test(line)) {
      return { status: "dynamic", reason: "__version__ imported from another module" };
    }
  }
  return null;
}

/** Core metadata `Version:` header (PKG-INFO / wheel METADATA). */
export function probeHeaderVersion(text: string): Probe {
  const m = /^Version:[ \t]*(.*?)[ \t]*$/m.exec(text);
  if (m === null) return null;
  return m[1] !== undefined && m[1] !== "" ? { status: "literal", value: m[1] } : { status: "dynamic", reason: "Version: header present but empty" };
}

/** pyproject `[project].version` literal; [project] absent ⇒ null (legacy setup.* project). */
export function probePyprojectVersion(text: string): Probe {
  const lines = text.split(/\r?\n/);
  let inProject = false;
  const slice: string[] = [];
  for (const line of lines) {
    if (/^\s*\[/.test(line)) {
      if (inProject) break;
      inProject = /^\s*\[project\]\s*$/.test(line);
      continue;
    }
    if (inProject) slice.push(line);
  }
  if (!inProject && slice.length === 0 && !text.includes("[project]")) return null;
  const body = slice.join("\n");
  const lit = /^\s*version\s*=\s*(['"])((?:(?!\1).)+)\1\s*(?:#.*)?$/m.exec(body);
  if (lit?.[2] !== undefined) return { status: "literal", value: lit[2] };
  const dyn = /dynamic\s*=\s*\[([\s\S]*?)\]/.exec(`${body}\n]`);
  if (dyn?.[1] !== undefined && /["']version["']/.test(dyn[1])) return { status: "dynamic", reason: 'project.version listed in dynamic = ["version"]' };
  return { status: "dynamic", reason: "[project] declares no statically-readable version" };
}

/** setup.cfg `[metadata] version =` — bare scalars literal, attr:/interp ⇒ dynamic. */
export function probeSetupCfgVersion(text: string): Probe {
  // line-slice the [metadata] section (a lazy [\s\S] regex + /m $ would stop at the first
  // newline and silently lose every later key — classic multiline-anchor trap)
  const lines = text.split(/\r?\n/);
  let inSection = false;
  const slice: string[] = [];
  for (const line of lines) {
    if (/^\s*\[/.test(line)) {
      if (inSection) break;
      inSection = /^\s*\[metadata\]\s*$/.test(line);
      continue;
    }
    if (inSection) slice.push(line);
  }
  const v = /^[ \t]*version[ \t]*=[ \t]*(.+?)[ \t]*$/m.exec(slice.join("\n"));
  if (v?.[1] === undefined) return null;
  return /^[\w.+-]+$/.test(v[1]) ? { status: "literal", value: v[1] } : { status: "dynamic", reason: `setup.cfg version = '${v[1].slice(0, 40)}' is not a bare literal` };
}

/** setup.py `version="X"` string-literal kwarg ONLY (never executed). */
export function probeSetupPyVersion(text: string): Probe {
  const lit = /(?:^|[,(]\s*)version\s*=\s*(['"])((?:(?!\1).)+)\1/.exec(text);
  if (lit?.[2] !== undefined) return { status: "literal", value: lit[2] };
  return /(?:^|[,(]\s*)version\s*=/.test(text) ? { status: "dynamic", reason: "setup.py version= is not a string literal" } : null;
}

/** Wheel filename `name-version-py-abi-plat.whl` ⇒ version segment (legacy dash form). */
export function parseWheelFilenameVersion(fileName: string): { name: string; version: string } | null {
  const base = basename(fileName).replace(/\.whl$/i, "");
  const parts = base.split("-");
  if (parts.length < 5) return null;
  const name = parts[0] as string;
  const version = parts[1] as string;
  return name !== "" && version !== "" ? { name, version } : null;
}

/** `pkg-0.2.2.dist-info` directory segment ⇒ version (text after the last dash). */
export function parseDistInfoDirVersion(relPath: string): string | null {
  const dir = /(?:^|\/)([^/]+\.dist-info)\//.exec(relPath)?.[1];
  if (dir === undefined) return null;
  const stem = dir.slice(0, -".dist-info".length);
  const idx = stem.lastIndexOf("-");
  return idx >= 0 ? stem.slice(idx + 1) : null;
}

/** PEP 503 name canonicalization for cross-artifact matching. */
const normName = (s: string): string => s.toLowerCase().replace(/[-_.]+/g, "_");

// --------------------------------------------------------------- hit → Finding plumbing

type Hit = { readonly rule: string; readonly message: string; readonly path: string; readonly disc: string };

function toFindings(hits: readonly Hit[], identity: string, sanitizer?: TextSanitizer): Finding[] {
  return hits.map((hit) => {
    // digest key mirrors residueFindings: identity:family:rule:disc keeps two independent
    // drift rows on one (rule, file) pair separately allow-listable.
    const { valueDigest, snippet } = redact(`${identity}:release-coherence:${hit.rule}:${hit.disc}`);
    return {
      rule: hit.rule,
      severity: RELEASE_COHERENCE_SEVERITIES[hit.rule] as Severity,
      target: TARGET,
      path: hit.path,
      engine: ENGINE,
      message: sanitizer?.sanitize(hit.message) ?? hit.message,
      valueDigest,
      snippet,
    };
  });
}

/** One collected version declaration inside an artifact. */
type Src = { readonly label: string; readonly path: string; readonly probe: Probe };

/** Primary = first LITERAL source in ecosystem priority order; every other literal is compared
 *  to it (one CRITICAL per disagreeing source); every dynamic source ⇒ one MEDIUM row. */
function analyze(sources: readonly Src[], pathPrefix: string, hits: Hit[]): void {
  const primary = sources.find((s) => s.probe?.status === "literal");
  for (const s of sources) {
    if (s.probe === null) continue;
    if (s.probe.status === "dynamic") {
      hits.push({
        rule: RELEASE_COHERENCE_UNVERIFIABLE_RULE,
        message: `release coherence: ${s.label} (${s.path}) carries a version that cannot be verified statically — ${s.probe.reason}; surfaced, never silent-clean`,
        path: `${pathPrefix}${s.path}`,
        disc: `${s.path}:unverifiable`,
      });
      continue;
    }
    if (primary === undefined || s === primary) continue;
    if (s.probe.value !== (primary.probe as { value: string }).value) {
      hits.push({
        rule: RELEASE_COHERENCE_DRIFT_RULE,
        message: `release coherence: ${primary.label} '${(primary.probe as { value: string }).value}' disagrees with ${s.label} '${s.probe.value}' — ${FOUNDING}`,
        path: `${pathPrefix}${s.path}`,
        disc: `${s.path}:vs:${primary.label}`,
      });
    }
  }
}

// --------------------------------------------------------------- npm

/** package.json vs package-lock.json root + packages[""] — ONLY when the lock is packed.
 *  lockText null ⇒ absent source ⇒ zero rows (see boundary note at the header). */
export function npmPackCoherenceFindings(o: {
  packedVersion: string | null;
  lockText: string | null;
  lockRelPath: string;
  identity: string;
  sanitizer?: TextSanitizer;
}): Finding[] {
  if (o.lockText === null || o.packedVersion === null) return [];
  let lock: Record<string, unknown>;
  try {
    lock = JSON.parse(o.lockText) as Record<string, unknown>;
  } catch {
    return toFindings([{ rule: RELEASE_COHERENCE_UNVERIFIABLE_RULE, message: `release coherence: ${o.lockRelPath} is packed but not parseable JSON — cannot verify, never silent-clean`, path: o.lockRelPath, disc: "malformed" }], o.identity, o.sanitizer);
  }
  const hits: Hit[] = [];
  const rootVer = typeof lock["version"] === "string" ? (lock["version"] as string) : null;
  const pkgs = lock["packages"];
  const rootPkg = typeof pkgs === "object" && pkgs !== null ? (pkgs as Record<string, unknown>)[""] : undefined;
  const pkgEmptyVer = typeof rootPkg === "object" && rootPkg !== null ? ((rootPkg as Record<string, unknown>)["version"]) : null;
  const cmp = (label: string, value: string | null, disc: string): void => {
    if (value !== null && value !== o.packedVersion) {
      hits.push({ rule: RELEASE_COHERENCE_DRIFT_RULE, message: `release coherence: packed package.json version '${String(o.packedVersion)}' disagrees with ${label} '${value}' — ${FOUNDING}`, path: o.lockRelPath, disc });
    }
  };
  cmp("package-lock.json root version", rootVer, "root");
  cmp('package-lock.json packages[""] version', typeof pkgEmptyVer === "string" ? pkgEmptyVer : null, "packages-empty");
  return toFindings(hits, o.identity, o.sanitizer);
}

// --------------------------------------------------------------- pypi (wheel + sdist)

export function pypiArtifactCoherenceFindings(o: {
  kind: "wheel" | "sdist";
  archiveName: string;
  files: readonly string[];
  read: (rel: string) => string | null;
  identity: string;
  sanitizer?: TextSanitizer;
}): Finding[] {
  const sources: Src[] = [];
  const inTree = (rel: string): boolean => o.files.includes(rel);
  const textOf = (rel: string): string | null => (inTree(rel) ? o.read(rel) : null);

  if (o.kind === "wheel") {
    const metaRel = o.files.find((f) => /\.dist-info\/METADATA$/.test(f));
    if (metaRel !== undefined) {
      const body = o.read(metaRel);
      sources.push({ label: "wheel METADATA Version:", path: metaRel, probe: body === null ? null : probeHeaderVersion(body) ?? { status: "dynamic", reason: "METADATA has no Version: header" } });
      const dirVer = parseDistInfoDirVersion(metaRel);
      if (dirVer !== null) sources.push({ label: "wheel .dist-info directory name", path: metaRel, probe: { status: "literal", value: dirVer } });
    }
    const fn = parseWheelFilenameVersion(o.archiveName);
    if (fn !== null) sources.push({ label: "wheel filename", path: metaRel ?? o.archiveName, probe: { status: "literal", value: fn.version } });
  } else {
    const pyproject = textOf("pyproject.toml");
    if (pyproject !== null) sources.push({ label: "pyproject [project].version", path: "pyproject.toml", probe: probePyprojectVersion(pyproject) });
    const cfg = textOf("setup.cfg");
    if (cfg !== null) sources.push({ label: "setup.cfg [metadata] version", path: "setup.cfg", probe: probeSetupCfgVersion(cfg) });
    const py = textOf("setup.py");
    if (py !== null) sources.push({ label: "setup.py version literal", path: "setup.py", probe: probeSetupPyVersion(py) });
    const pkgInfoRel = o.files.find((f) => f === "PKG-INFO" || f.endsWith(".egg-info/PKG-INFO"));
    if (pkgInfoRel !== undefined) {
      const body = o.read(pkgInfoRel);
      if (body !== null) sources.push({ label: "PKG-INFO Version:", path: pkgInfoRel, probe: probeHeaderVersion(body) ?? { status: "dynamic", reason: "PKG-INFO has no Version: header" } });
    }
  }
  for (const initRel of o.files.filter((f) => /(?:^|\/)__init__\.py$/.test(f)).sort()) {
    const body = o.read(initRel);
    if (body === null) continue;
    const probe = probeDunderVersion(body);
    if (probe !== null) sources.push({ label: `__version__ literal in ${initRel}`, path: initRel, probe });
  }

  const hits: Hit[] = [];
  analyze(sources, `${o.archiveName}!`, hits);
  return toFindings(hits, o.identity, o.sanitizer);
}

// --------------------------------------------------------------- crates

export function cratesCoherenceFindings(o: {
  name: string;
  version: string;
  lockText: string | null;
  lockRelPath: string;
  identity: string;
  sanitizer?: TextSanitizer;
}): Finding[] {
  if (o.lockText === null) return []; // Cargo.lock not packed ⇒ absent source, not drift.
  const entries = o.lockText
    .split(/^\[\[package\]\][ \t]*$/m)
    .map((block) => ({ name: /^\s*name\s*=\s*"([^"]*)"/m.exec(block)?.[1], version: /^\s*version\s*=\s*"([^"]*)"/m.exec(block)?.[1] }))
    .filter((e): e is { name: string; version: string } => e.name !== undefined && e.version !== undefined)
    .filter((e) => e.name === o.name);
  if (entries.length === 0) {
    return toFindings([{ rule: RELEASE_COHERENCE_UNVERIFIABLE_RULE, message: `release coherence: ${o.lockRelPath} is packed but names no [[package]] '${o.name}' — cannot verify, never silent-clean`, path: o.lockRelPath, disc: "no-entry" }], o.identity, o.sanitizer);
  }
  const hits: Hit[] = [];
  for (const v of [...new Set(entries.map((e) => e.version))].sort()) {
    if (v !== o.version) {
      hits.push({ rule: RELEASE_COHERENCE_DRIFT_RULE, message: `release coherence: Cargo.toml [package].version '${o.version}' disagrees with Cargo.lock entry '${o.name}' version '${v}' — ${FOUNDING}`, path: o.lockRelPath, disc: v });
    }
  }
  return toFindings(hits, o.identity, o.sanitizer);
}

// --------------------------------------------------------------- rubygems

/**
 * The .gem FORMAT derives the registry name-version from the spec itself, so for a
 * conventionally-built gem filename↔metadata drift looks vacuous — but it is REACHABLE
 * through border's own identity seam: channels/gemspec.ts GEMSPEC_VERSION (no /m flag)
 * takes the FIRST literal `s.version = "..."`, while Ruby evaluates assignments in order
 * (the LAST wins). A gemspec with two literal s.version assignments therefore produces a
 * border-guessed `.gem` filename disagreeing with metadata.gz — the shipped bytes' own
 * claim. metadata.gz is authoritative; this closes exactly that divergence.
 */
export function gemCoherenceFindings(o: {
  specName: string;
  specVersion: string;
  metadataText: string | null;
  identity: string;
  sanitizer?: TextSanitizer;
}): Finding[] {
  if (o.metadataText === null) return []; // non-gem container layout ⇒ absent source, not drift.
  const name = /^name:[ \t]*(\S+)[ \t]*$/m.exec(o.metadataText)?.[1];
  const version = /^version:[ \t]*!ruby\/object:Gem::Version[ \t]*\n[ \t]+version:[ \t]*(\S+)[ \t]*$/m.exec(o.metadataText)?.[1];
  if (name === undefined || version === undefined) {
    return toFindings([{ rule: RELEASE_COHERENCE_UNVERIFIABLE_RULE, message: "release coherence: metadata.gz is present but its Gem::Specification name/version could not be read statically — cannot verify, never silent-clean", path: "metadata.gz", disc: "unparseable" }], o.identity, o.sanitizer);
  }
  const hits: Hit[] = [];
  if (name !== o.specName) hits.push({ rule: RELEASE_COHERENCE_DRIFT_RULE, message: `release coherence: built gem '${o.identity}' names '${o.specName}' but metadata.gz Gem::Specification name is '${name}' — ${FOUNDING}`, path: "metadata.gz", disc: "name" });
  if (version !== o.specVersion) hits.push({ rule: RELEASE_COHERENCE_DRIFT_RULE, message: `release coherence: built gem '${o.identity}' names version '${o.specVersion}' but metadata.gz Gem::Version is '${version}' — ${FOUNDING}`, path: "metadata.gz", disc: "version" });
  return toFindings(hits, o.identity, o.sanitizer);
}

// --------------------------------------------------------------- release.twin (cross-manager)

export type TwinPair = { readonly pypi: string; readonly npm: string };

/** Read a packed tgz's package.json name+version straight from the STAGED BYTES (tar -xzO;
 *  no extraction, nothing executed). Returns null when the member/JSON is unreadable. */
function packedNpmIdentity(archiveAbs: string, env?: Readonly<Record<string, string | undefined>>): { name: string; version: string } | null {
  const opts = { encoding: "utf8" as const, timeout: 30_000, ...(env !== undefined ? { env: env as NodeJS.ProcessEnv } : {}) };
  const listing = spawnSync("tar", ["-tzf", archiveAbs], opts);
  if (listing.status !== 0) return null;
  const members = (listing.stdout ?? "").split("\n").filter((l) => /^[^/]+\/package\.json$/.test(l));
  const member = members.includes("package/package.json") ? "package/package.json" : members.length === 1 ? members[0] : undefined;
  if (member === undefined) return null;
  const body = spawnSync("tar", ["-xzOf", archiveAbs, member], opts);
  if (body.status !== 0) return null;
  try {
    const pkg = JSON.parse(body.stdout as string) as Record<string, unknown>;
    return typeof pkg["name"] === "string" && typeof pkg["version"] === "string" ? { name: pkg["name"], version: pkg["version"] } : null;
  } catch {
    return null;
  }
}

/**
 * release.twin: the ONE place a cross-manager version claim is statically enforceable
 * (plan W4.1) — when a project declares {pypi, npm} twins, the wheel's version and the npm
 * twin's PACKED package.json version must be string-equal. Wheels are read by filename
 * (rule-3 already reconciled filename↔METADATA↔__version__ in the same run); the npm side
 * is read from the staged tarball bytes. Either side missing/unreadable ⇒ MEDIUM — a
 * declared obligation that cannot be proven is never silent-clean.
 */
export async function twinCoherenceFindings(o: {
  pairs: readonly TwinPair[];
  artifacts: readonly LedgerArtifact[];
  repoDir: string;
  env?: Readonly<Record<string, string | undefined>>;
  sanitizer?: TextSanitizer;
}): Promise<Finding[]> {
  const wheels = o.artifacts.filter((a) => a.file.endsWith(".whl")).sort((a, b) => a.file.localeCompare(b.file));
  const tgzs = o.artifacts.filter((a) => a.file.endsWith(".tgz")).sort((a, b) => a.file.localeCompare(b.file));
  const hits: Hit[] = [];
  for (const pair of o.pairs) {
    const wh = wheels.find((a) => {
      const parsed = parseWheelFilenameVersion(basename(a.file));
      return parsed !== null && normName(parsed.name) === normName(pair.pypi);
    });
    if (wh === undefined) {
      hits.push({ rule: RELEASE_COHERENCE_UNVERIFIABLE_RULE, message: `release coherence: release.twin pair '${pair.pypi}'/'${pair.npm}' — no staged wheel for '${pair.pypi}' in this run, so the declared cross-manager equality cannot be verified`, path: `${pair.pypi}(missing).whl`, disc: `twin:${pair.pypi}:no-wheel` });
      continue;
    }
    const wheelVersion = (parseWheelFilenameVersion(basename(wh.file)) as { version: string }).version;
    let npmSide: { file: string; version: string } | null = null;
    let npmUnreadable = false;
    for (const t of tgzs) {
      const id = packedNpmIdentity(join(o.repoDir, t.file), o.env);
      if (id === null) {
        npmUnreadable = true;
        continue;
      }
      if (id.name === pair.npm) {
        npmSide = { file: t.file, version: id.version };
        break;
      }
    }
    if (npmSide === null) {
      hits.push({
        rule: RELEASE_COHERENCE_UNVERIFIABLE_RULE,
        message: `release coherence: release.twin pair '${pair.pypi}'/'${pair.npm}' — ${npmUnreadable ? `npm twin '${pair.npm}' is staged but its package.json could not be read from the tarball bytes` : `no staged npm artifact for twin '${pair.npm}' in this run`}, so the declared cross-manager equality cannot be verified`,
        path: basename(wh.file),
        disc: `twin:${pair.pypi}:no-npm`,
      });
      continue;
    }
    if (wheelVersion !== npmSide.version) {
      hits.push({
        rule: RELEASE_COHERENCE_TWIN_RULE,
        message: `release coherence: release.twin pair '${pair.pypi}'/'${pair.npm}' — wheel '${basename(wh.file)}' says version '${wheelVersion}' but npm twin '${basename(npmSide.file)}' packed package.json says '${npmSide.version}' — ${FOUNDING}`,
        path: basename(wh.file),
        disc: `twin:${pair.pypi}:${basename(npmSide.file)}`,
      });
    }
  }
  return toFindings(hits, "release.twin", o.sanitizer);
}
