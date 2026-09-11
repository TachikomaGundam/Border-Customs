// provenance: border-inspect-roadmap.md W4.1/W4.2 — the release-coherence rule family (Wave 4).
//
// Founding case (the aihr incident): a wheel labeled 0.2.2 on PyPI shipped a package whose
// `__init__.__version__` said 0.2.1 — users installed "0.2.2" bytes carrying 0.2.1 behavior.
// A second class bit border itself: the published npm tarball's User-Agent said 0.3.0 while
// package.json said 0.3.1, and package-lock.json's root version sat at 0.1.0 through two
// releases. Version truth must AGREE across every source packed inside the artifact.
//
// Owns (closed tables, one row per drift pair):
//   * the per-ecosystem analyzers in src/rules/releaseCoherence.ts (npm lock, pypi sdist/wheel,
//     crates Cargo.lock, rubygems metadata.gz) — agree ⇒ zero rows; each drift pair ⇒ exactly
//     ONE CRITICAL quoting both versions; unparseable/dynamic source ⇒ MEDIUM unverifiable,
//     never silent-clean; ABSENT secondary source ⇒ zero rows (fail-quiet-if-absent boundary:
//     locks/egg-info typically aren't packed; absence is not drift and must not false-green-
//     train users into --force);
//   * `release.twin` strict-zod config (unknown keys ⇒ typed exit 2) + the cross-manager twin
//     check over the STAGED bytes (wheel filename version vs npm twin's packed package.json);
//   * the rulesHash fold (RELEASE_FINGERPRINT_SOURCES: releaseCoherence.ts rides the
//     fingerprint exactly like the residue sources — seam-mutation ⇒ new hash, missing input
//     ⇒ MissingRulesInputError, never a silent pass; the config digest moves with the twin list);
//   * two real end-to-end legs: drifted npm pack (runNpmArtifactStage over real packed bytes)
//     and the aihr replay via `python3 -m build` (pyproject 0.2.2 vs stale __init__ 0.2.1 —
//     the wheel leg alone catches it, exactly the founding evidence);
//   * README en+zh inventory pins (R4-DOC oracle style).
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { after, test } from "node:test";

import { runNpmArtifactStage } from "../src/artifacts/npm.ts";
import { scanPyPiArtifacts } from "../src/artifacts/pypi.ts";
import { ConfigError, parseConfig, type BorderConfig } from "../src/config.ts";
import { computeVerdict, type Finding } from "../src/findings.ts";
import { MissingRulesInputError } from "../src/redact.ts";
import { computeCheckRulesHash, computeConfigDigest, type LoadedConfig } from "../src/check/rulesHash.ts";
import {
  RELEASE_COHERENCE_DRIFT_RULE,
  RELEASE_COHERENCE_SEVERITIES,
  RELEASE_COHERENCE_TWIN_RULE,
  RELEASE_COHERENCE_UNVERIFIABLE_RULE,
  cratesCoherenceFindings,
  gemCoherenceFindings,
  npmPackCoherenceFindings,
  pypiArtifactCoherenceFindings,
  twinCoherenceFindings,
} from "../src/rules/releaseCoherence.ts";
import { requireGitleaks } from "./helpers/require-engines.ts";
import { BORDER_ROOT, gitAddCommit, gitInit, makeFixtureDir, removeDir, writeRel } from "./helpers/fixtures.ts";

requireGitleaks();

const roots: string[] = [];
after(() => {
  for (const d of roots) removeDir(d);
});

function tmpDir(prefix: string): string {
  const d = makeFixtureDir(prefix);
  roots.push(d);
  return d;
}

function byRule(findings: readonly Finding[], rule: string): Finding[] {
  return findings.filter((f) => f.rule === rule);
}

// --------------------------------------------------------------- shared config yaml

function baseYaml(extra: readonly string[] = []): string {
  return [
    "version: 1",
    "targets:",
    "  git:",
    "    remotes:",
    "      - name: origin",
    "        url: origin.example:widgets.git",
    "rules:",
    "  authors:",
    "    emails:",
    "      - wiki@sumteclab.com",
    "    names:",
    "      - Wiki.js",
    "  hosts: []",
    "  ips: []",
    "  pathPatterns: []",
    ...extra,
    "",
  ].join("\n");
}

// --------------------------------------------------------------- in-memory artifact trees

type Tree = { readonly files: readonly string[]; readonly read: (rel: string) => string | null };

function tree(entries: Readonly<Record<string, string>>): Tree {
  const files = Object.keys(entries);
  return { files, read: (rel: string) => entries[rel] ?? null };
}

const WHEEL_META = (version: string): string => `Metadata-Version: 2.1\nName: pkg\nVersion: ${version}\n`;
const DUNDER = (version: string): string => `"""Docstring."""\n__version__ = "${version}"\n`;

// --------------------------------------------------------------- 1. config schema (release.twin)

test("RC-CFG: release.twin parses declared pairs; absence ⇒ undefined (no cross-manager demand by default)", () => {
  const cfg = parseConfig(baseYaml(["release:", "  twin:", "    - pypi: aihr", "      npm: aihr-js"]));
  assert.deepEqual(cfg.release?.twin, [{ pypi: "aihr", npm: "aihr-js" }]);
  const absent = parseConfig(baseYaml());
  assert.equal(absent.release, undefined, "release key absent ⇒ no twin obligations");
});

test("RC-CFG: strict zod — unknown sibling under release:, scalar release:, unknown/missing pair fields all fail typed exit 2", () => {
  for (const yaml of [
    baseYaml(["release:", "  twin: []", "  debug: 1"]),
    baseYaml(["release: true"]),
    baseYaml(["release:", "  twin: true"]),
    baseYaml(["release:", "  twin:", "    - pypi: a"]),
    baseYaml(["release:", "  twin:", "    - pypi: a", "      npm: b", "      cargo: c"]),
    baseYaml(["release:", "  twin:", "    - pypi: \"\"", "      npm: b"]),
  ]) {
    assert.throws(
      () => parseConfig(yaml),
      (err: unknown) => err instanceof ConfigError && err.exitCode === 2,
      `expected typed exit 2 for:\n${yaml}`,
    );
  }
});

// --------------------------------------------------------------- 2. npm stage: package-lock drift

const NPM_ID = "acme@1.0.0";

function lockJson(root: string | undefined, pkgEmpty: string | undefined): string {
  return JSON.stringify({
    name: "acme",
    ...(root === undefined ? {} : { version: root }),
    lockfileVersion: 3,
    requires: true,
    packages: { "": { name: "acme", ...(pkgEmpty === undefined ? {} : { version: pkgEmpty }) } },
  });
}

test("RC-NPM: agreeing sources ⇒ zero rows; absent lock ⇒ zero rows (fail-quiet-if-absent is load-bearing, not drift)", () => {
  assert.deepEqual(npmPackCoherenceFindings({ packedVersion: "1.0.0", lockText: lockJson("1.0.0", "1.0.0"), lockRelPath: "package/package-lock.json", identity: NPM_ID }), []);
  assert.deepEqual(npmPackCoherenceFindings({ packedVersion: "1.0.0", lockText: null, lockRelPath: "package/package-lock.json", identity: NPM_ID }), []);
  assert.deepEqual(npmPackCoherenceFindings({ packedVersion: null, lockText: lockJson("1.0.0", "1.0.0"), lockRelPath: "package/package-lock.json", identity: NPM_ID }), []);
});

test("RC-NPM: lockfile root vs packages[\"\"] vs package.json — each drift pair ⇒ exactly ONE CRITICAL quoting both versions", () => {
  const rootDrift = npmPackCoherenceFindings({ packedVersion: "1.0.0", lockText: lockJson("0.1.0", "1.0.0"), lockRelPath: "package/package-lock.json", identity: NPM_ID });
  assert.equal(rootDrift.length, 1, JSON.stringify(rootDrift));
  assert.equal(rootDrift[0]?.rule, RELEASE_COHERENCE_DRIFT_RULE);
  assert.equal(rootDrift[0]?.severity, "CRITICAL");
  assert.ok(rootDrift[0]!.message.includes("1.0.0") && rootDrift[0]!.message.includes("0.1.0"), "both versions quoted");
  assert.ok(rootDrift[0]!.message.includes("package.json") && rootDrift[0]!.message.includes("package-lock"), "both sources named");
  assert.equal(rootDrift[0]?.path, "package/package-lock.json");

  const pkgEmptyDrift = npmPackCoherenceFindings({ packedVersion: "1.0.0", lockText: lockJson("1.0.0", "0.9.9"), lockRelPath: "package/package-lock.json", identity: NPM_ID });
  assert.equal(pkgEmptyDrift.length, 1);
  assert.equal(pkgEmptyDrift[0]?.rule, RELEASE_COHERENCE_DRIFT_RULE);

  // a lock that simply declares no version fields is an absent source, not drift
  assert.deepEqual(npmPackCoherenceFindings({ packedVersion: "1.0.0", lockText: JSON.stringify({ lockfileVersion: 3, packages: {} }), lockRelPath: "package/package-lock.json", identity: NPM_ID }), []);
});

test("RC-NPM: unparseable lock ⇒ MEDIUM unverifiable, never silent-clean; malformed JSON included", () => {
  const bad = npmPackCoherenceFindings({ packedVersion: "1.0.0", lockText: "{ oops not json", lockRelPath: "package/package-lock.json", identity: NPM_ID });
  assert.equal(bad.length, 1);
  assert.equal(bad[0]?.rule, RELEASE_COHERENCE_UNVERIFIABLE_RULE);
  assert.equal(bad[0]?.severity, "MEDIUM");
});

// --------------------------------------------------------------- 3. pypi wheel: filename ↔ dist-info ↔ METADATA ↔ __version__

const WHEEL_ID = "pkg-0.2.2-py3-none-any.whl";

function wheelFindings(o: { filename?: string; distInfo?: string; metadata?: string | null; init?: string | null }): Finding[] {
  const entries: Record<string, string> = {};
  const distInfo = o.distInfo ?? "0.2.2";
  if (o.metadata !== null) entries[`pkg-${distInfo}.dist-info/METADATA`] = o.metadata ?? WHEEL_META("0.2.2");
  entries["pkg-0.2.2.dist-info/WHEEL"] = "Wheel-Version: 1.0\n";
  if (o.init !== null) entries["pkg/__init__.py"] = o.init ?? DUNDER("0.2.2");
  const t = tree(entries);
  return pypiArtifactCoherenceFindings({
    kind: "wheel",
    archiveName: o.filename ?? WHEEL_ID,
    files: t.files,
    read: t.read,
    identity: o.filename ?? WHEEL_ID,
  });
}

test("RC-WHEEL: aihr replay — wheel METADATA 0.2.2 vs stale __init__ 0.2.1 ⇒ exactly ONE CRITICAL from the wheel alone", () => {
  const drift = wheelFindings({ init: DUNDER("0.2.1") });
  assert.equal(drift.length, 1, JSON.stringify(drift.map((f) => [f.rule, f.message])));
  assert.equal(drift[0]?.rule, RELEASE_COHERENCE_DRIFT_RULE);
  assert.equal(drift[0]?.severity, "CRITICAL");
  assert.ok(drift[0]!.message.includes("0.2.2") && drift[0]!.message.includes("0.2.1"), "both versions quoted");
  assert.equal(drift[0]?.path, `${WHEEL_ID}!pkg/__init__.py`);
  assert.equal(computeVerdict(drift), "FAIL");
});

test("RC-WHEEL: filename ↔ dist-info ↔ METADATA agree ⇒ zero; METADATA vs filename drift ⇒ exactly one CRITICAL", () => {
  assert.deepEqual(wheelFindings({}), []);
  // METADATA is the install-facing primary; the dir agrees with it, only the filename lies.
  const drift = wheelFindings({ distInfo: "0.2.1", metadata: WHEEL_META("0.2.1"), init: null });
  assert.equal(drift.length, 1, JSON.stringify(drift.map((f) => [f.rule, f.message])));
  assert.equal(drift[0]?.rule, RELEASE_COHERENCE_DRIFT_RULE);
  assert.ok(drift[0]!.message.includes("0.2.1") && drift[0]!.message.includes("0.2.2"));
});

test("RC-WHEEL: dynamic __version__ ⇒ MEDIUM unverifiable; silent __init__ without the name ⇒ no row; multiple __init__ literals each compared to METADATA", () => {
  const dyn = wheelFindings({ init: '"""Doc."""\nimport importlib.metadata as m\n__version__ = m.version("pkg")\n' });
  assert.equal(dyn.length, 1);
  assert.equal(dyn[0]?.rule, RELEASE_COHERENCE_UNVERIFIABLE_RULE);
  assert.equal(dyn[0]?.severity, "MEDIUM");

  const silent = wheelFindings({ init: '"""Docstring only — no __version__ anywhere."""\n' });
  assert.deepEqual(silent, [], "an __init__ that never mentions __version__ is an absent source");

  const both = wheelFindings({ init: DUNDER("0.2.1") });
  const twoFiles = tree({
    "pkg-0.2.2.dist-info/METADATA": WHEEL_META("0.2.2"),
    "pkg/__init__.py": DUNDER("0.2.1"),
    "pkg/sub/__init__.py": DUNDER("0.2.2"),
  });
  const r2 = pypiArtifactCoherenceFindings({ kind: "wheel", archiveName: WHEEL_ID, files: twoFiles.files, read: twoFiles.read, identity: WHEEL_ID });
  assert.equal(both.length, 1);
  assert.equal(r2.length, 1, "only the file that disagrees with METADATA produces a row");
});

// --------------------------------------------------------------- 4. pypi sdist: pyproject/setup.* vs PKG-INFO vs __version__

const SDIST_ID = "pkg-0.2.2.tar.gz";

function sdistFindings(o: { pyproject?: string | null; pkgInfo?: string | null; setupCfg?: string | null; setupPy?: string | null; init?: string | null }): Finding[] {
  const entries: Record<string, string> = {};
  if (o.pyproject !== null) entries["pyproject.toml"] = o.pyproject ?? '[build-system]\nrequires = ["setuptools"]\n\n[project]\nname = "pkg"\nversion = "0.2.2"\n';
  if (o.pkgInfo !== null) entries["PKG-INFO"] = o.pkgInfo ?? "Metadata-Version: 2.1\nName: pkg\nVersion: 0.2.2\n";
  if (o.setupCfg !== null && o.setupCfg !== undefined) entries["setup.cfg"] = o.setupCfg;
  if (o.setupPy !== null && o.setupPy !== undefined) entries["setup.py"] = o.setupPy;
  if (o.init !== null) entries["src/pkg/__init__.py"] = o.init ?? DUNDER("0.2.2");
  const t = tree(entries);
  return pypiArtifactCoherenceFindings({ kind: "sdist", archiveName: SDIST_ID, files: t.files, read: t.read, identity: SDIST_ID });
}

test("RC-SDIST: all sources agree ⇒ zero; PKG-INFO drift ⇒ exactly one CRITICAL; egg-info-less tree with no PKG-INFO ⇒ zero (absent boundary)", () => {
  assert.deepEqual(sdistFindings({}), []);
  const drift = sdistFindings({ pkgInfo: "Metadata-Version: 2.1\nName: pkg\nVersion: 0.2.1\n" });
  assert.equal(drift.length, 1, JSON.stringify(drift));
  assert.equal(drift[0]?.rule, RELEASE_COHERENCE_DRIFT_RULE);
  assert.equal(drift[0]?.severity, "CRITICAL");
  assert.ok(drift[0]!.message.includes("pyproject") && drift[0]!.message.includes("PKG-INFO"), "both sources named");
  assert.equal(drift[0]?.path, `${SDIST_ID}!PKG-INFO`);

  const noPkgInfo = sdistFindings({ pkgInfo: null });
  assert.deepEqual(noPkgInfo, [], "no second source ⇒ nothing to compare ⇒ zero rows, never a guess");
});

test("RC-SDIST: setup.py/setup.cfg as the only declaration source are honored; dynamic/uninterpolated values ⇒ MEDIUM, never silent", () => {
  const legacyDrift = sdistFindings({
    pyproject: null,
    setupPy: 'from setuptools import setup\nsetup(name="pkg", version="0.3.0")\n',
    pkgInfo: "Metadata-Version: 2.1\nName: pkg\nVersion: 0.2.9\n",
    init: null,
  });
  assert.equal(legacyDrift.length, 1);
  assert.equal(legacyDrift[0]?.rule, RELEASE_COHERENCE_DRIFT_RULE);

  const dynamicPyproject = sdistFindings({ pyproject: '[project]\nname = "pkg"\ndynamic = ["version"]\n', init: null });
  assert.equal(dynamicPyproject.length, 1, JSON.stringify(dynamicPyproject));
  assert.equal(dynamicPyproject[0]?.rule, RELEASE_COHERENCE_UNVERIFIABLE_RULE);
  assert.equal(dynamicPyproject[0]?.severity, "MEDIUM");

  const attrCfg = sdistFindings({
    pyproject: null,
    pkgInfo: "Metadata-Version: 2.1\nName: pkg\nVersion: 0.2.2\n",
    setupCfg: "[metadata]\nname = pkg\nversion = attr: pkg.__version__\n",
    init: null,
  });
  assert.equal(attrCfg.length, 1);
  assert.equal(attrCfg[0]?.rule, RELEASE_COHERENCE_UNVERIFIABLE_RULE, "version = attr: … is unparseable statically ⇒ MEDIUM, never silent-clean");
});

// --------------------------------------------------------------- 5. crates: Cargo.toml vs packed Cargo.lock

const CRATE_ID = "acme-1.0.0.crate";

function crateLock(version: string): string {
  return `# generated\nversion = 3\n\n[[package]]\nname = "other-dep"\nversion = "9.9.9"\n\n[[package]]\nname = "acme"\nversion = "${version}"\ndependencies = ["other-dep"]\n`;
}

test("RC-CRATE: lock agrees ⇒ zero; absent lock ⇒ zero (boundary); entry drift ⇒ one CRITICAL quoting both; no entry ⇒ MEDIUM", () => {
  assert.deepEqual(cratesCoherenceFindings({ name: "acme", version: "1.0.0", lockText: crateLock("1.0.0"), lockRelPath: "acme-1.0.0/Cargo.lock", identity: CRATE_ID }), []);
  assert.deepEqual(cratesCoherenceFindings({ name: "acme", version: "1.0.0", lockText: null, lockRelPath: "acme-1.0.0/Cargo.lock", identity: CRATE_ID }), []);
  const drift = cratesCoherenceFindings({ name: "acme", version: "1.0.0", lockText: crateLock("0.9.0"), lockRelPath: "acme-1.0.0/Cargo.lock", identity: CRATE_ID });
  assert.equal(drift.length, 1);
  assert.equal(drift[0]?.rule, RELEASE_COHERENCE_DRIFT_RULE);
  assert.ok(drift[0]!.message.includes("1.0.0") && drift[0]!.message.includes("0.9.0"), "both versions quoted");
  assert.equal(drift[0]?.path, "acme-1.0.0/Cargo.lock");
  const noEntry = cratesCoherenceFindings({ name: "acme", version: "1.0.0", lockText: "# generated\nversion = 3\n\n[[package]]\nname = \"other-dep\"\nversion = \"9.9.9\"\n", lockRelPath: "acme-1.0.0/Cargo.lock", identity: CRATE_ID });
  assert.equal(noEntry.length, 1);
  assert.equal(noEntry[0]?.rule, RELEASE_COHERENCE_UNVERIFIABLE_RULE);
  assert.equal(noEntry[0]?.severity, "MEDIUM");
});

// --------------------------------------------------------------- 6. rubygems: metadata.gz spec vs built filename

const GEM_ID = "acme-1.0.0.gem";

function gemMeta(name: string, version: string): string {
  return `--- !ruby/object:Gem::Specification\nname: ${name}\nversion: !ruby/object:Gem::Version\n  version: ${version}\nplatform: ruby\nsummary: x\n`;
}

test("RC-GEM: metadata.gz agrees with the built filename ⇒ zero; drift ⇒ CRITICAL naming both; unreadable metadata ⇒ MEDIUM", () => {
  assert.deepEqual(gemCoherenceFindings({ specName: "acme", specVersion: "1.0.0", metadataText: gemMeta("acme", "1.0.0"), identity: GEM_ID }), []);
  const drift = gemCoherenceFindings({ specName: "acme", specVersion: "1.0.0", metadataText: gemMeta("acme", "0.9.0"), identity: GEM_ID });
  assert.equal(drift.length, 1);
  assert.equal(drift[0]?.rule, RELEASE_COHERENCE_DRIFT_RULE);
  assert.ok(drift[0]!.message.includes("1.0.0") && drift[0]!.message.includes("0.9.0"));
  const nameDrift = gemCoherenceFindings({ specName: "acme", specVersion: "1.0.0", metadataText: gemMeta("evil", "1.0.0"), identity: GEM_ID });
  assert.equal(nameDrift.length, 1);
  assert.equal(nameDrift[0]?.rule, RELEASE_COHERENCE_DRIFT_RULE);
  const junk = gemCoherenceFindings({ specName: "acme", specVersion: "1.0.0", metadataText: "!!! not a Gem::Specification", identity: GEM_ID });
  assert.equal(junk.length, 1);
  assert.equal(junk[0]?.rule, RELEASE_COHERENCE_UNVERIFIABLE_RULE);
  // absence is NOT drift (non-gem-layout containers keep pre-W4 behavior)
  assert.deepEqual(gemCoherenceFindings({ specName: "acme", specVersion: "1.0.0", metadataText: null, identity: GEM_ID }), []);
});

// --------------------------------------------------------------- 7. release.twin cross-manager equality

function packedTgz(dir: string, name: string, version: string): string {
  // twinCoherenceFindings resolves artifact.file against repoDir — mirror the real
  // staging layout (.border/dist/) so the unit exercises exactly the CLI's paths.
  mkdirSync(join(dir, ".border", "dist"), { recursive: true });
  const stage = join(dir, `stage-${name.replace(/[^a-z0-9]/gi, "-")}`);
  mkdirSync(join(stage, "package"), { recursive: true });
  writeFileSync(join(stage, "package", "package.json"), JSON.stringify({ name, version }));
  const out = join(dir, ".border", "dist", `${name.replace("/", "-")}-${version}.tgz`);
  const r = spawnSync("tar", ["-czf", out, "-C", stage, "package"], { encoding: "utf8" });
  if (r.status !== 0) throw new Error(`tar failed: ${r.stderr}`);
  return out;
}

test("RC-TWIN: twin pair versions agree ⇒ zero; drift ⇒ CRITICAL naming both artifacts; missing side ⇒ MEDIUM, never silent", async () => {
  const dir = tmpDir("rc-twin");
  const whl = "aihr-0.2.2-py3-none-any.whl";
  mkdirSync(join(dir, ".border", "dist"), { recursive: true });
  writeFileSync(join(dir, ".border", "dist", whl), "PK\x03\x04 not a real zip — twin reads only the filename");
  packedTgz(dir, "aihr-js", "0.2.2");
  const artifacts = [
    { file: `.border/dist/${whl}`, sha256: "a".repeat(64) },
    { file: ".border/dist/aihr-js-0.2.2.tgz", sha256: "b".repeat(64) },
  ];
  const pairs = [{ pypi: "aihr", npm: "aihr-js" }];
  assert.deepEqual(await twinCoherenceFindings({ pairs, artifacts, repoDir: dir }), []);

  // drift: rebuild the npm twin at 0.2.1
  rmSync(join(dir, ".border", "dist", "aihr-js-0.2.2.tgz"));
  packedTgz(dir, "aihr-js", "0.2.1");
  const driftArt = [{ file: `.border/dist/${whl}`, sha256: "a".repeat(64) }, { file: ".border/dist/aihr-js-0.2.1.tgz", sha256: "c".repeat(64) }];
  const drift = await twinCoherenceFindings({ pairs, artifacts: driftArt, repoDir: dir });
  assert.equal(drift.length, 1, JSON.stringify(drift));
  assert.equal(drift[0]?.rule, RELEASE_COHERENCE_TWIN_RULE);
  assert.equal(drift[0]?.severity, "CRITICAL");
  assert.ok(drift[0]!.message.includes(whl) && drift[0]!.message.includes("aihr-js-0.2.1.tgz"), "both artifacts named");
  assert.ok(drift[0]!.message.includes("0.2.2") && drift[0]!.message.includes("0.2.1"), "both versions quoted");
  assert.ok(!(drift[0]?.path ?? "").split("/").includes(".border"), "twin path must survive the .border exclusion filter");

  // one side simply not staged ⇒ unverifiable, never silent-clean
  const onlyWheel = await twinCoherenceFindings({ pairs, artifacts: [artifacts[0] as (typeof artifacts)[number]], repoDir: dir });
  assert.equal(onlyWheel.length, 1);
  assert.equal(onlyWheel[0]?.rule, RELEASE_COHERENCE_UNVERIFIABLE_RULE);
});

test("RC-TWIN: wheel/npm name normalization is canonical (AIHR-Core ⇒ aihr_core dist-info segment)", async () => {
  const dir = tmpDir("rc-twin-norm");
  const whl = "aihr_core-1.0.0-py3-none-any.whl";
  mkdirSync(join(dir, ".border", "dist"), { recursive: true });
  writeFileSync(join(dir, ".border", "dist", whl), "PK\x03\x04");
  packedTgz(dir, "aihr-core", "1.0.0");
  const out = await twinCoherenceFindings({
    pairs: [{ pypi: "AIHR-Core", npm: "aihr-core" }],
    artifacts: [
      { file: `.border/dist/${whl}`, sha256: "a".repeat(64) },
      { file: ".border/dist/aihr-core-1.0.0.tgz", sha256: "b".repeat(64) },
    ],
    repoDir: dir,
  });
  assert.deepEqual(out, [], JSON.stringify(out));
});

// --------------------------------------------------------------- 8. rulesHash fold + config digest

type FingerprintApi = {
  RELEASE_FINGERPRINT_BASENAMES: readonly string[];
  resolveReleaseFingerprintFiles: (env?: Readonly<Record<string, string | undefined>>) => readonly string[];
};

async function releaseFingerprintApi(): Promise<FingerprintApi> {
  const mod = (await import("../src/check/rulesHash.ts")) as unknown as Partial<FingerprintApi>;
  assert.ok(mod.RELEASE_FINGERPRINT_BASENAMES !== undefined, "rulesHash.ts must export RELEASE_FINGERPRINT_BASENAMES (W4.2)");
  assert.ok(mod.resolveReleaseFingerprintFiles !== undefined, "rulesHash.ts must export resolveReleaseFingerprintFiles (W4.2)");
  return mod as FingerprintApi;
}

test("RC-HASH: releaseCoherence.ts rides the rules fingerprint; seam content edit ⇒ new hash; missing input ⇒ MissingRulesInputError", async () => {
  const api = await releaseFingerprintApi();
  assert.ok(api.RELEASE_FINGERPRINT_BASENAMES.includes("releaseCoherence.ts"), "the family's rule home must be a fingerprint input");
  const live = api.resolveReleaseFingerprintFiles({});
  for (const p of live) assert.ok(p.includes("/rules/"), `release fingerprint input must sit in src/rules/: ${p}`);

  // R4-HASH pattern (test/residue.config.test.ts:199): the digest folds in input PATHS, so
  // the content-sensitivity probe mutates the copy the SAME seam points at — never compares
  // a seam against live resolution.
  const seamA = tmpDir("rc-seamA");
  for (const p of live) copyFileSync(p, join(seamA, p.slice(p.lastIndexOf("/") + 1)));
  const envOf = (d: string): Record<string, string | undefined> => ({ ...process.env, BORDER_RELEASE_SRC_DIR: d });

  const hashA = await computeCheckRulesHash({ engineVersions: {}, configDigest: "a".repeat(64), env: envOf(seamA) });
  const hashAAgain = await computeCheckRulesHash({ engineVersions: {}, configDigest: "a".repeat(64), env: envOf(seamA) });
  assert.equal(hashA, hashAAgain, "same bytes ⇒ deterministic hash");

  const rc = join(seamA, "releaseCoherence.ts");
  writeFileSync(rc, `${readFileSync(rc, "utf8")}\n// sig-line-mutation\n`, "utf8");
  const hashMutated = await computeCheckRulesHash({ engineVersions: {}, configDigest: "a".repeat(64), env: envOf(seamA) });
  assert.notEqual(hashA, hashMutated, "releaseCoherence.ts content edit MUST change rulesHash");

  rmSync(rc);
  await assert.rejects(
    computeCheckRulesHash({ engineVersions: {}, configDigest: "a".repeat(64), env: envOf(seamA) }),
    (err: unknown) => err instanceof MissingRulesInputError && String((err as MissingRulesInputError).inputPath).includes("releaseCoherence.ts"),
  );
});

test("RC-HASH: release.twin config is digest-visible (pair edit rotates the fingerprint input to rulesHash)", () => {
  const asLoad = (releaseLines: readonly string[]): LoadedConfig => ({
    kind: "loaded",
    config: parseConfig(baseYaml(releaseLines)),
    warnings: [],
    source: "<test>",
  });
  const absent = computeConfigDigest(asLoad([]));
  const pairA = computeConfigDigest(asLoad(["release:", "  twin:", "    - pypi: a", "      npm: b"]));
  const pairB = computeConfigDigest(asLoad(["release:", "  twin:", "    - pypi: a", "      npm: c"]));
  assert.notEqual(absent, pairA, "adding a twin obligation moves the digest");
  assert.notEqual(pairA, pairB, "changing the pair moves the digest");
});

// --------------------------------------------------------------- 9. rule-id/severity closed table + README pins

test("RC-DOC: closed severity table + README en/zh inventory name every release-coherence rule with its severity and the aihr founding case", () => {
  assert.deepEqual(RELEASE_COHERENCE_SEVERITIES, {
    [RELEASE_COHERENCE_DRIFT_RULE]: "CRITICAL",
    [RELEASE_COHERENCE_TWIN_RULE]: "CRITICAL",
    [RELEASE_COHERENCE_UNVERIFIABLE_RULE]: "MEDIUM",
  });
  const readme = readFileSync(join(BORDER_ROOT, "README.md"), "utf8");
  const zh = readme.slice(readme.indexOf("## 中文概要"));
  assert.ok(zh.length > 100, "zh mirror section must exist");
  for (const [rule, severity] of Object.entries(RELEASE_COHERENCE_SEVERITIES)) {
    const rows = readme.split("\n").filter((l) => l.includes(`\`${rule}\``) && l.toUpperCase().includes(severity.toUpperCase()));
    assert.ok(rows.length >= 1, `README must name \`${rule}\` with severity ${severity}`);
    assert.ok(zh.includes(rule), `zh mirror must name ${rule}`);
  }
  assert.ok(readme.includes("### Release coherence"), "en inventory subsection heading");
  assert.ok(readme.includes("发布一致性"), "zh mirror heading term");
  assert.ok(readme.toLowerCase().includes("aihr"), "founding case cited in README");
  assert.ok(zh.includes("aihr"), "founding case cited in the zh mirror too");
});

// --------------------------------------------------------------- 10. real-stage end-to-end legs

const NPM_CFG: BorderConfig = {
  version: 1,
  targets: { git: { remotes: [] }, npm: {} },
  rules: { authors: { emails: [], names: [] }, hosts: [], ips: [], pathPatterns: [], maxFileKB: 500 },
  allow: [],
  engines: { require: ["gitleaks", "secretlint"], trufflehog: false },
};

test("RC-E2E npm: real `npm pack` of a package shipping its drifted lockfile ⇒ CRITICAL survives filterBorderStateFindings; agreeing lock ⇒ zero rows", async () => {
  // npm-packlist HARD-excludes package-lock.json from `files` (measured: npm packs it only
  // through an always-include channel) — the `main` field force-includes it, the exact G39
  // mechanism this suite already pins in artifacts.npm.test.ts. The stage rule ships what
  // ships: zero rows when the lock is not packed is the documented boundary, not a gap.
  const mk = (lockVersion: string): string => {
    const repo = tmpDir("rc-e2e-npm");
    gitInit(repo);
    writeRel(repo, "package.json", JSON.stringify({ name: "acme-locky", version: "1.0.0", files: ["src", "package-lock.json"], main: "package-lock.json" }));
    writeRel(repo, "src/index.js", "export const ok = 1;\n");
    writeRel(repo, "package-lock.json", JSON.stringify({
      name: "acme-locky",
      version: lockVersion,
      lockfileVersion: 3,
      packages: { "": { name: "acme-locky", version: lockVersion } },
    }));
    gitAddCommit(repo, "init");
    return repo;
  };
  const drifted = await runNpmArtifactStage({ repoDir: mk("0.1.0"), cfg: NPM_CFG, skipGitleaks: true, skipSecretlint: true });
  const rows = byRule(drifted.findings, RELEASE_COHERENCE_DRIFT_RULE);
  // the fixture drifts BOTH lock sources (root + packages[""]) ⇒ one CRITICAL per pair
  assert.equal(rows.length, 2, JSON.stringify(drifted.findings.map((f) => [f.rule, f.message])));
  assert.ok(rows.every((f) => f.severity === "CRITICAL" && (f.path ?? "").includes("package-lock.json")));
  assert.equal(computeVerdict(drifted.findings), "FAIL");

  const agreeing = await runNpmArtifactStage({ repoDir: mk("1.0.0"), cfg: NPM_CFG, skipGitleaks: true, skipSecretlint: true });
  assert.equal(byRule(agreeing.findings, RELEASE_COHERENCE_DRIFT_RULE).length, 0);
});

test("RC-E2E pypi: aihr replay through real `python3 -m build` — pyproject 0.2.2 + stale __version__ 0.2.1 ⇒ BOTH dist bytes carry the CRITICAL (wheel-leg proves it from the wheel alone)", async () => {
  const repo = tmpDir("rc-e2e-pypi");
  gitInit(repo);
  writeRel(repo, ".gitignore", ".border/\n__pycache__/\nbuild/\nsrc/*.egg-info/\n");
  writeRel(repo, "pyproject.toml", `[build-system]
requires = ["setuptools==78.1.1"]
build-backend = "setuptools.build_meta"

[project]
name = "coherence-replay"
version = "0.2.2"
readme = "README.md"
requires-python = ">=3.10"

[tool.setuptools.packages.find]
where = ["src"]
`);
  writeRel(repo, "README.md", "# coherence-replay\n\nReplay fixture for the aihr incident.\n");
  writeRel(repo, "src/coherence_replay/__init__.py", '"""Replayed bug: stale module version."""\n__version__ = "0.2.1"\n');
  gitAddCommit(repo, "fixture baseline");

  const { findings } = await scanPyPiArtifacts({ repoDir: repo, skipGitleaks: true, skipSecretlint: true });
  const rows = byRule(findings, RELEASE_COHERENCE_DRIFT_RULE);
  assert.ok(rows.length >= 1, `expected drift rows, got ${JSON.stringify(findings.map((f) => [f.rule, f.path]))}`);
  assert.ok(rows.every((f) => f.severity === "CRITICAL"));
  assert.ok(rows.every((f) => f.message.includes("0.2.2") && f.message.includes("0.2.1")));
  // wheels flatten src/ layout — the inner path inside the .whl carries no src/ prefix
  const wheelRows = rows.filter((f) => (f.path ?? "").endsWith(".whl!coherence_replay/__init__.py"));
  assert.equal(wheelRows.length, 1, "the WHEEL bytes alone must carry the aihr verdict (founding evidence)");
  const sdistRows = rows.filter((f) => (f.path ?? "").endsWith(".tar.gz!src/coherence_replay/__init__.py"));
  assert.equal(sdistRows.length, 1, "the sdist tree carries the same drift");
  assert.equal(computeVerdict(findings), "FAIL");
});
