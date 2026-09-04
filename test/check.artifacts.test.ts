// provenance: original clean-room implementation per .omo/plans/border-push-gate.md GAP B
// (success criteria 1+3): the artifact pipelines must run INSIDE `border check`, so
// packed/built bytes are scanned end-to-end — a secret in a gitignored-but-packed file
// can no longer pass the gate. Pinned here:
//   * E1 npm planted gitignored-but-packed secret ⇒ `check --force` exit 1, CRITICAL
//     path '<pkg>.tgz!<inner>'; CheckRecord + report.json list artifacts == the
//     .border/dist tarball's sha256; FAIL records are NEVER skipped (honesty core);
//   * E4 .border/dist populated unprompted by the check itself (no manual stage call);
//   * clean twin ⇒ PASS ⇒ immediate SKIP <3s with ZERO dist re-pack (mtime+size+ino
//     unchanged) — the consult re-packs to tmp only, never to dist;
//   * E2 mutating the gitignored packed output defeats the stale SKIP and the re-scan
//     catches the planted key, recording the NEW digest;
//   * E3 pypi: build-once inside check ⇒ artifacts recorded; unchanged rerun SKIPs
//     with zero rebuild (dist untouched); planted gitignored wheel member ⇒ exit 1.
// REAL gitleaks/secretlint/npm/python3-build (todo 1 culture, never stubbed); the
// registry legs ride the loopback stub (todo 13: no public network in the suite).
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { after, test } from "node:test";

import { run } from "../src/cli.ts";
import { EXIT_BLOCKED, EXIT_PASS } from "../src/cli/exit.ts";
import { readLedger, type CheckRecord } from "../src/ledger.ts";
import { requireGitleaks } from "./helpers/require-engines.ts";
import { gitAddCommit, gitInit, makeFixtureDir, randAwsPair, removeDir, writeRel } from "./helpers/fixtures.ts";
import { startRegistryStub, type RegistryStub } from "./helpers/registry-stub.ts";

type Cli = { readonly code: number; readonly out: readonly string[]; readonly err: readonly string[]; readonly ms: number };

requireGitleaks();
const npmStub: RegistryStub = await startRegistryStub([]);
const pypiStubs: RegistryStub[] = [];
const roots: string[] = [];
after(() => {
  void npmStub.close();
  for (const stub of pypiStubs) void stub.close();
  for (const dir of roots) removeDir(dir);
});

async function cli(dir: string, extra: readonly string[] = []): Promise<Cli> {
  const out: string[] = [];
  const err: string[] = [];
  const t0 = performance.now();
  const code = (await run(["check", ...extra], (l) => out.push(l), (l) => err.push(l), { cwd: dir })) as number;
  return { code, out, err, ms: performance.now() - t0 };
}

const SKIP_RE = /^SKIP ([0-9a-f]{8}) — PASS (\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z) report \.border\/runs\/(\S+)\/report\.json$/;
const skipLine = (c: Cli): string | undefined => c.out.find((l) => SKIP_RE.test(l));

function checks(dir: string): readonly CheckRecord[] {
  return readLedger(dir).records.filter((r): r is CheckRecord => r.t === "check");
}

function sha256File(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

/** dist fingerprint seam: any (re)pack/rebuild of .border/dist moves mtimeMs/size/ino. */
function distStamp(dir: string, rel: string): string {
  const s = statSync(join(dir, rel));
  return `${String(s.mtimeMs)}:${String(s.size)}:${String(s.ino)}`;
}

function reportJson(dir: string, rec: CheckRecord): { findings: readonly { path?: string; severity: string; engine: string }[]; artifacts?: readonly { file: string; sha256: string }[] } {
  return JSON.parse(readFileSync(join(dir, rec.reportPath), "utf8"));
}

// ---------------------------------------------------------------- npm fixtures

function npmYaml(): string {
  return [
    "version: 1",
    "targets:",
    "  git:",
    "    remotes:",
    "      - name: origin",
    "        url: origin.example:gapb.git",
    "  npm:",
    `    registry: ${npmStub.url}`,
    "rules:",
    "  authors:",
    "    emails:",
    "      - wiki@sumteclab.com",
    "    names:",
    "      - Wiki.js",
    "  hosts: []",
    "  ips: []",
    "  pathPatterns: []",
    "",
  ].join("\n");
}

/** lib/generated.js is GITIGNORED yet rides the pack via the files:["lib"] whitelist —
 *  invisible to history/tracked legs, the exact GAP B byte-class. */
function npmFixture(name: string): string {
  const dir = makeFixtureDir("gapb-npm");
  roots.push(dir);
  gitInit(dir);
  writeRel(dir, ".gitignore", ".border/\nlib/generated.js\n");
  writeRel(dir, "package.json", JSON.stringify({ name, version: "1.0.0", files: ["lib"] }) + "\n");
  writeRel(dir, "lib/index.js", "export const ok = 1;\n");
  writeRel(dir, "lib/generated.js", "export const generated = 1;\n");
  writeRel(dir, "border.yaml", npmYaml());
  gitAddCommit(dir, "init");
  return dir;
}

const npmTgzRel = (name: string): string => `.border/dist/${name}-1.0.0.tgz`;

// --------------------------------------------------------------- pypi fixtures

// A FRESH stub per pypi test: node's http keep-alive closes idle sockets ~5s
// after the previous test's probes, and a pooled dead socket makes the pypi
// leg's undici fetch fail closed (measured: exit 2 on the second pypi test
// against a shared stub). Ephemeral ports make per-test stubs collision-free.
function pypiYaml(repository: string): string {
  return [
    "version: 1",
    "targets:",
    "  git:",
    "    remotes:",
    "      - name: origin",
    "        url: origin.example:gapb.git",
    "  pypi:",
    `    repository: ${repository}`,
    "rules:",
    "  authors:",
    "    emails:",
    "      - wiki@sumteclab.com",
    "    names:",
    "      - Wiki.js",
    "  hosts: []",
    "  ips: []",
    "  pathPatterns: []",
    "",
  ].join("\n");
}

const PYPROJECT = `[build-system]
requires = ["setuptools==78.1.1"]
build-backend = "setuptools.build_meta"

[project]
name = "gapb-pypi"
version = "1.0.0"
readme = "README.md"
`;

function pypiFixture(repository: string): string {
  const dir = makeFixtureDir("gapb-pypi");
  roots.push(dir);
  gitInit(dir);
  writeRel(dir, ".gitignore", ".border/\nbuild/\n__pycache__/\n*.egg-info/\ngapbpypi/_version.py\n");
  writeRel(dir, "pyproject.toml", PYPROJECT);
  writeRel(dir, "README.md", "# gapb-pypi\n\nDocs.\n");
  writeRel(dir, "gapbpypi/__init__.py", '"""Clean."""\n');
  writeRel(dir, "border.yaml", pypiYaml(repository));
  gitAddCommit(dir, "init");
  return dir;
}

// ---------------------------------------------------------------------- tests

test("E1+E4 npm: gitignored-but-packed secret fails the check end-to-end; artifacts == dist bytes; FAIL never skips", { timeout: 180_000 }, async () => {
  const dir = npmFixture("gapb-e1");
  const planted = randAwsPair();
  writeRel(dir, "lib/generated.js", planted.text);

  const r1 = await cli(dir, ["--force"]);
  assert.equal(r1.code, EXIT_BLOCKED, `planted packed secret must block, got ${String(r1.code)}: ${r1.out.join(" | ")} ${r1.err.join(" | ")}`);

  // E4: the check packed it itself — no manual stage call anywhere in this file.
  const tgzRel = npmTgzRel("gapb-e1");
  const digest = sha256File(join(dir, tgzRel));

  const rec = checks(dir).at(-1);
  assert.ok(rec !== undefined && rec.verdict === "FAIL");
  assert.deepEqual(rec.artifacts, [{ file: tgzRel, sha256: digest }], "record artifacts == the .border/dist tarball digest");
  const rep = reportJson(dir, rec);
  assert.deepEqual(rep.artifacts, [{ file: tgzRel, sha256: digest }], "report.json carries the same artifacts");
  assert.ok(
    rep.findings.some((f) => f.severity === "CRITICAL" && f.path === "gapb-e1-1.0.0.tgz!lib/generated.js"),
    `finding must name the tarball-scoped path, got: ${JSON.stringify(rep.findings.map((f) => f.path))}`,
  );
  assert.ok(!JSON.stringify(rep).includes(planted.key), "G23: raw key never reaches the report");

  // Honesty core: a FAIL is never a skip candidate — every rerun is a FULL
  // check, which legitimately re-packs .border/dist; determinism means the
  // BYTES are identical (mtime moves, sha does not). Zero-repack proof for
  // the consult lives on the SKIP paths (E2/E3), which never reach the pipeline.
  const r2 = await cli(dir);
  assert.equal(skipLine(r2), undefined, "FAIL is never skipped");
  assert.equal(r2.code, EXIT_BLOCKED);
  assert.equal(checks(dir).length, 2, "the FAIL rerun appended its own audit record");
  assert.equal(sha256File(join(dir, tgzRel)), digest, "re-pack is deterministic — identical bytes");
  assert.deepEqual(checks(dir).at(-1)?.artifacts, [{ file: tgzRel, sha256: digest }], "rerun record certifies the same digest");
});

test("E2 npm clean twin: PASS records dist digests; SKIP is sub-3s with ZERO re-pack; mutating the gitignored packed output defeats it", { timeout: 180_000 }, async () => {
  const dir = npmFixture("gapb-e2");
  const tgzRel = npmTgzRel("gapb-e2");

  const r1 = await cli(dir);
  assert.equal(r1.code, EXIT_PASS, `clean packed tree must pass: ${r1.out.join(" | ")} ${r1.err.join(" | ")}`);
  const rec = checks(dir).at(-1);
  assert.ok(rec !== undefined);
  assert.deepEqual(rec.artifacts, [{ file: tgzRel, sha256: sha256File(join(dir, tgzRel)) }]);

  const stamp = distStamp(dir, tgzRel);
  const r2 = await cli(dir);
  assert.notEqual(skipLine(r2), undefined, "unchanged state must SKIP");
  assert.ok(r2.ms < 3_000, `SKIP fast-path must stay sub-3s, took ${String(Math.round(r2.ms))}ms`);
  assert.equal(distStamp(dir, tgzRel), stamp, "SKIP must not touch .border/dist (freshness re-packs to tmp only)");
  assert.equal(checks(dir).length, 1, "skip appends nothing");

  const planted = randAwsPair();
  writeRel(dir, "lib/generated.js", planted.text); // gitignored ⇒ HEAD + porcelain NEVER move
  const r3 = await cli(dir);
  assert.equal(skipLine(r3), undefined, "mutated gitignored-but-packed output must reject the stale PASS (re-pack digest differs)");
  assert.equal(r3.code, EXIT_BLOCKED, `re-scan must catch the planted key in the new tarball: ${r3.out.join(" | ")}`);
  const rec3 = checks(dir).at(-1);
  assert.ok(rec3 !== undefined && rec3.verdict === "FAIL");
  assert.notDeepEqual(rec3.artifacts, rec.artifacts, "the re-check captured the CHANGED tarball digest");
  assert.ok(
    reportJson(dir, rec3).findings.some((f) => f.severity === "CRITICAL" && f.path === "gapb-e2-1.0.0.tgz!lib/generated.js"),
  );
});

test("E3 pypi: check builds once, records dist digests; unchanged rerun SKIPs with zero rebuild", { timeout: 300_000 }, async () => {
  const stub = await startRegistryStub([]);
  pypiStubs.push(stub);
  const dir = pypiFixture(stub.url);
  const r1 = await cli(dir);
  assert.equal(r1.code, EXIT_PASS, `clean pypi fixture must pass: ${r1.out.join(" | ")} ${r1.err.join(" | ")}`);
  const rec = checks(dir).at(-1);
  assert.ok(rec !== undefined && rec.artifacts !== null);
  const distDir = join(dir, ".border", "dist");
  const listed = [...rec.artifacts].sort((a, b) => (a.file < b.file ? -1 : 1));
  assert.equal(listed.length, 2, "sdist + wheel");
  for (const a of listed) {
    assert.match(a.file, /^\.border\/dist\/.+/);
    assert.equal(a.sha256, sha256File(join(dir, a.file)), "recorded digest == the on-disk .border/dist bytes");
  }
  const stampBefore = listed.map((a) => distStamp(dir, a.file)).join("|");

  const r2 = await cli(dir);
  assert.notEqual(skipLine(r2), undefined, "unchanged pypi state must SKIP");
  assert.ok(r2.ms < 3_000, `pypi SKIP must not rebuild, took ${String(Math.round(r2.ms))}ms`);
  assert.equal(listed.map((a) => distStamp(dir, a.file)).join("|"), stampBefore, "SKIP rebuilt nothing — dist bytes untouched");
  assert.equal(checks(dir).length, 1);
  void distDir;
});

test("E3b pypi planted: gitignored packed _version.py secret fails the check via the built wheel", { timeout: 300_000 }, async () => {
  const stub = await startRegistryStub([]);
  pypiStubs.push(stub);
  const dir = pypiFixture(stub.url);
  const planted = randAwsPair();
  writeRel(dir, "gapbpypi/_version.py", `__version__ = "1.0.0"\nAWS_KEY = "${planted.key}"\nAWS_SECRET = "${planted.secret}"\n`);

  const r1 = await cli(dir, ["--force"]);
  assert.equal(r1.code, EXIT_BLOCKED, `packed wheel member must be scanned end-to-end: ${r1.out.join(" | ")} ${r1.err.join(" | ")}`);
  const rec = checks(dir).at(-1);
  assert.ok(rec !== undefined && rec.verdict === "FAIL");
  const rep = reportJson(dir, rec);
  assert.ok(
    rep.findings.some((f) => f.severity === "CRITICAL" && f.engine === "gitleaks" && (f.path ?? "").endsWith("_version.py")),
    `CRITICAL on the artifact-inner member path, got: ${JSON.stringify(rep.findings.map((f) => [f.severity, f.path]))}`,
  );
  assert.ok(rec.artifacts !== null && rec.artifacts.every((a) => a.file.startsWith(".border/dist/")));
  assert.ok(!JSON.stringify(rep).includes(planted.key));
});
