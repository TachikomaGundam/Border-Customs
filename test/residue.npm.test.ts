// provenance: R2 of .omo/plans/border-residue-gate.md — golden corpus tests for the
// residue family (src/rules/residueMatchers.ts + src/artifacts/residue.ts + npm leg).
//
// Gate-2 (regression polarity, BLOCKING): every fixture NOT matching a closed T1
// signature keeps its pre-0.3.0 `lifecycle-script` CRITICAL row BYTE-IDENTICAL —
// pinned verbatim from R1's stage-pins-0.2.0.json (copied into this corpus, sha
// covered by the spike's SHA256SUMS.manifest). The gate may only get STRICTER:
// extra residue-* rows are allowed, softer/changed/removed pinned rows are not.
//
// Fixtures are staged through the REAL pipeline (npm pack --ignore-scripts +
// extract + native rules); engine legs are skipped except where a test names
// them. No fixture lifecycle code ever executes.
import assert from "node:assert/strict";
import { cpSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { after, test } from "node:test";

import type { BorderConfig } from "../src/config.ts";
import type { Finding } from "../src/findings.ts";
import { computeVerdict } from "../src/findings.ts";
import { NPM_LIFECYCLE_RULE, runNpmArtifactStage } from "../src/artifacts/npm.ts";
import { makeFixtureDir, removeDir } from "./helpers/fixtures.ts";

const CFG: BorderConfig = {
  version: 1,
  targets: { git: { remotes: [] }, npm: {} },
  rules: { authors: { emails: [], names: [] }, hosts: [], ips: [], pathPatterns: [], maxFileKB: 500 },
  allow: [],
  engines: { require: ["gitleaks", "secretlint"], trufflehog: false },
};

const CORPUS = new URL("./fixtures/residue/", import.meta.url).pathname;
const roots: string[] = [];
after(() => {
  for (const d of roots) removeDir(d);
});

type Pin = {
  fixture: string;
  findings: Finding[];
};

const PINS: Pin[] = JSON.parse(readFileSync(join(CORPUS, "stage-pins-0.2.0.json"), "utf8"));

/** Copy a corpus fixture dir into a fresh tmp repo (content-identical; the stage
 *  packs it with `npm pack --ignore-scripts`, so hooks never execute). */
function repoFrom(fixtureDir: string): string {
  const repo = makeFixtureDir(`residue-${fixtureDir}`);
  roots.push(repo);
  cpSync(join(CORPUS, fixtureDir), repo, { recursive: true });
  return repo;
}

function stage(fixtureDir: string): Promise<{ findings: readonly Finding[] }> {
  return runNpmArtifactStage({
    repoDir: repoFrom(fixtureDir),
    cfg: CFG,
    skipGitleaks: true,
    skipSecretlint: true,
  });
}

function byRule(findings: readonly Finding[], rule: string): Finding[] {
  return findings.filter((f) => f.rule === rule);
}

function pin(fixture: string): Pin {
  const p = PINS.find((x) => x.fixture === fixture);
  assert.ok(p, `pin for ${fixture} missing from stage-pins-0.2.0.json`);
  return p;
}

/** The byte-identical lifecycle-script row(s) a non-T1 fixture must keep emitting. */
function assertLifecycleRowByteIdentical(r: { findings: readonly Finding[] }, p: Pin): void {
  const expected = p.findings.filter((f) => f.rule === NPM_LIFECYCLE_RULE);
  const actual = byRule(r.findings, NPM_LIFECYCLE_RULE);
  assert.equal(actual.length, expected.length, "exactly the pinned lifecycle rows, no more, no fewer");
  for (let i = 0; i < expected.length; i += 1) {
    assert.deepEqual(actual[i], expected[i], `lifecycle row ${String(i)} must be byte-identical to the 0.2.0 pin`);
  }
}

const SPIKE_FIXTURES: Readonly<Record<string, string>> = {
  "esbuild-postinstall": "f1-esbuild",
  "msgpackr-extract-install": "f2-msgpackr-extract",
  "thread-stream-prepare": "f3-thread-stream",
  "synthetic-curlsh": "f4-synthetic-curlsh",
};

// ------------------------------------------- gate 2: characterization pins (written FIRST, green against unchanged 0.2.0 code)

test("R2-PIN: every non-T1 spike fixture keeps its 0.2.0 lifecycle-script row byte-identical", async () => {
  for (const [pinFixture, corpusDir] of Object.entries(SPIKE_FIXTURES)) {
    const r = await stage(corpusDir);
    assertLifecycleRowByteIdentical(r, pin(pinFixture));
    assert.equal(computeVerdict(r.findings), "FAIL", `${corpusDir}: unknown-classified hook must stay blocking`);
  }
});

test("R2-PIN: no non-T1 fixture is ever downgraded to residue-in-tree-hook", async () => {
  for (const corpusDir of Object.values(SPIKE_FIXTURES)) {
    const r = await stage(corpusDir);
    assert.deepEqual(byRule(r.findings, "residue-in-tree-hook"), [], `${corpusDir}: only the closed T1 signature may reach the MEDIUM lane`);
  }
});

// ------------------------------------------- corpus (e): T0 silent pass

test("R2-E (T0): bin-shim-only package produces zero residue findings (dogfood of the ledger principle)", async () => {
  const r = await stage("e-t0-clean");
  assert.deepEqual(r.findings.filter((f) => f.rule.startsWith("residue-")), [], `T0 must stay silent, got ${JSON.stringify(r.findings.map((f) => f.rule))}`);
  assert.equal(computeVerdict(r.findings), "PASS");
});

// ------------------------------------------- failing-first goldens (written RED against unchanged code, per TDD)

test("R2-A (T1 golden): opencode fixture flips its CRITICAL row to exactly one MEDIUM residue-in-tree-hook naming signature id", async () => {
  const r = await stage("a-opencode-t1");
  // publint noise excluded per adjudication #5: the byte-honest fixture lacks the 100 MB binaries.
  assert.deepEqual(byRule(r.findings, NPM_LIFECYCLE_RULE), [], "T1-matched hook must NOT keep the CRITICAL row");
  const t1 = byRule(r.findings, "residue-in-tree-hook");
  assert.equal(t1.length, 1);
  assert.equal(t1[0]?.severity, "MEDIUM");
  assert.equal(t1[0]?.engine, "native");
  assert.equal(t1[0]?.path, "package/package.json");
  assert.match(t1[0]?.message ?? "", /opencode-in-tree-v1/, "message names the matched signature id");
  assert.equal(computeVerdict(r.findings.filter((f) => !f.rule.startsWith("publint"))), "PASS", "T1 alone must not block");
});

test("R2-B (T2): downloader hook file trips residue-install-download HIGH, CRITICAL row preserved", async () => {
  const r = await stage("b-t2-downloader");
  const lc = byRule(r.findings, NPM_LIFECYCLE_RULE);
  assert.equal(lc.length, 1);
  assert.equal(lc[0]?.severity, "CRITICAL");
  assert.match(lc[0]?.message ?? "", /node \.\/postinstall\.js$/);
  const t2 = byRule(r.findings, "residue-install-download");
  assert.equal(t2.length, 1);
  assert.equal(t2[0]?.severity, "HIGH");
  assert.equal(t2[0]?.path, "package/postinstall.js");
});

test("R2-C (T3): rc-editor hook file trips residue-out-of-tree-write HIGH incl. argv git-global shape", async () => {
  const r = await stage("c-t3-rceditor");
  const t3 = byRule(r.findings, "residue-out-of-tree-write");
  assert.equal(t3.length, 1);
  assert.equal(t3[0]?.severity, "HIGH");
  assert.equal(t3[0]?.path, "package/postinstall.js");
});

test("R2-D (T4): persistence hidden in bin/ scripts trips artifact-wide CRITICAL without any lifecycle hook", async () => {
  const r = await stage("d-t4-bin");
  assert.deepEqual(byRule(r.findings, NPM_LIFECYCLE_RULE), []);
  const t4 = byRule(r.findings, "residue-persistence-primitive");
  assert.equal(t4.length, 2, "one row per packed script file carrying persistence primitives");
  assert.ok(t4.every((f) => f.severity === "CRITICAL" && f.engine === "native"));
  assert.deepEqual(t4.map((f) => f.path).sort(), ["package/bin/evil.cmd", "package/bin/evil.sh"]);
  assert.equal(computeVerdict(r.findings), "FAIL");
});

test("R2-I (cross-manager): npm hook spawning pip/yarn/pnpm/gem/cargo/uv trips residue-cross-manager-write HIGH naming the ledgers", async () => {
  const r = await stage("i-crossmgr");
  const xm = byRule(r.findings, "residue-cross-manager-write");
  assert.equal(xm.length, 1);
  assert.equal(xm[0]?.severity, "HIGH");
  assert.equal(xm[0]?.path, "package/postinstall.js");
  assert.match(xm[0]?.message ?? "", /pip/);
});

test("R2-J (Windows PATH carriers): setx/HKCU/SetEnvironmentVariable trip T3 HIGH", async () => {
  const r = await stage("j-winpath");
  const t3 = byRule(r.findings, "residue-out-of-tree-write");
  assert.equal(t3.length, 1);
  assert.equal(t3[0]?.severity, "HIGH");
});

// ------------------------------------------- corpus (k): B2 pairing trio

test("R2-K1 (paired): marker write + symmetric remove + CLI inverse ⇒ T3 HIGH annotated pairing=verified, never downgraded", async () => {
  const r = await stage("k-paired");
  const t3 = byRule(r.findings, "residue-out-of-tree-write");
  assert.equal(t3.length, 1);
  assert.equal(t3[0]?.severity, "HIGH", "0.3.0: a verified pair NEVER softens the T3 HIGH (plan Must-NOT)");
  assert.match(t3[0]?.message ?? "", /pairing=verified/);
  assert.match(t3[0]?.message ?? "", /aihr PATH/, "names the marker id");
  assert.deepEqual(byRule(r.findings, "residue-pairing-missing"), []);
});

test("R2-K2 (write-orphan): marker write with no remove path ⇒ T3 HIGH plus residue-pairing-missing HIGH naming the id", async () => {
  const r = await stage("k-write-orphan");
  assert.equal(byRule(r.findings, "residue-out-of-tree-write").length, 1);
  const pm = byRule(r.findings, "residue-pairing-missing");
  assert.equal(pm.length, 1);
  assert.equal(pm[0]?.severity, "HIGH");
  assert.match(pm[0]?.message ?? "", /foo PATH/, "names the orphaned marker id");
  assert.equal(computeVerdict(r.findings), "FAIL");
});

test("R2-K3 (remove-orphan): dead inverse with no write path ⇒ exactly one MEDIUM note, never a blocking row", async () => {
  const r = await stage("k-remove-orphan");
  const pm = byRule(r.findings, "residue-pairing-missing");
  assert.equal(pm.length, 1);
  assert.equal(pm[0]?.severity, "MEDIUM");
  assert.match(pm[0]?.message ?? "", /bar PATH/);
  assert.deepEqual(byRule(r.findings, "residue-out-of-tree-write"), [], "remove-only emits no write finding");
  assert.equal(computeVerdict(r.findings), "PASS");
});

// ------------------------------------------- B1/B2 fail-open regression (fix round; written RED against R2 code)
//
// VERIFIER-REPORT-R2.json blockers, replicated EXACTLY as the verifier's mutants M3/M4/M5:
// each appends one line to the byte-blessed a-opencode-t1/postinstall.mjs. The mutation is
// static text only — runNpmArtifactStage packs with `npm pack --ignore-scripts`, so no hook
// code ever executes (same staging discipline as R2-A).

/** The pinned §3.2-P5 digest of the verbatim lifecycle-script CRITICAL row for
 *  spike-fixture-opencode-postinstall@1.18.29 (sha256 of `…:lifecycle:postinstall`). */
const LIFECYCLE_CRITICAL_DIGEST = "61415faf5c8c08e6bdf6ae2d5166615f1047e7d01a52c757d6633f8d19a6c512";

/** Stage the blessed T1 fixture with one mutation line appended to postinstall.mjs. */
function stageMutant(mutation: string): Promise<{ findings: readonly Finding[] }> {
  const repo = repoFrom("a-opencode-t1");
  const file = join(repo, "postinstall.mjs");
  writeFileSync(file, `${readFileSync(file, "utf8")}\n${mutation}\n`);
  return runNpmArtifactStage({
    repoDir: repo,
    cfg: CFG,
    skipGitleaks: true,
    skipSecretlint: true,
  });
}

/** B1/B2 contract: an escaped mutation keeps the verbatim CRITICAL row and NEVER the MEDIUM badge. */
function assertCriticalNotDowngraded(r: { findings: readonly Finding[] }): void {
  const lc = byRule(r.findings, NPM_LIFECYCLE_RULE);
  assert.equal(lc.length, 1, "mutation must keep exactly one verbatim lifecycle-script row");
  assert.equal(lc[0]?.severity, "CRITICAL");
  assert.equal(lc[0]?.valueDigest, LIFECYCLE_CRITICAL_DIGEST, "CRITICAL row must be the pinned P5 digest");
  assert.deepEqual(byRule(r.findings, "residue-in-tree-hook"), [], "mutation must NEVER carry the T1 MEDIUM badge (fail-open)");
}

test("R2-M3 (B2 regression): appended writeFileSync(path.join(__dirname,'..','..','escaped.txt'),'pwned') loses the T1 badge, keeps verbatim CRITICAL", async () => {
  const r = await stageMutant("fs.writeFileSync(path.join(__dirname,'..','..','escaped.txt'),'pwned')");
  assertCriticalNotDowngraded(r);
  assert.equal(computeVerdict(r.findings.filter((f) => !f.rule.startsWith("publint"))), "FAIL");
});

test("R2-M4 (B1 regression): appended await import(\"node:net\") loses the T1 badge, keeps verbatim CRITICAL, trips the T2 family row", async () => {
  const r = await stageMutant('await import("node:net")');
  assertCriticalNotDowngraded(r);
  const t2 = byRule(r.findings, "residue-install-download");
  assert.equal(t2.length, 1, "fix (b): the dynamic net-module form must trip t2-js-net-module outside T1 too");
  assert.equal(t2[0]?.severity, "HIGH");
  assert.equal(t2[0]?.path, "package/postinstall.mjs");
  assert.equal(computeVerdict(r.findings.filter((f) => !f.rule.startsWith("publint"))), "FAIL");
});

test("R2-M5 (B1 regression): appended await import(`node:${x}`) loses the T1 badge, keeps verbatim CRITICAL, trips the T2 family row", async () => {
  const r = await stageMutant("await import(`node:${x}`)");
  assertCriticalNotDowngraded(r);
  const t2 = byRule(r.findings, "residue-install-download");
  assert.equal(t2.length, 1, "backtick-interpolated dynamic specifier must also trip the T2 row");
  assert.equal(t2[0]?.path, "package/postinstall.mjs");
  assert.equal(computeVerdict(r.findings.filter((f) => !f.rule.startsWith("publint"))), "FAIL");
});

// NB1/NB2 (VERIFIER-REPORT-R2-FIX.json): the two lane-B escapes that kept riding the gate as
// silent MEDIUM. Mutation strings are the report's repro lines, character for character.

test("R2-M6 (NB1 regression): eval-obfuscated dynamic import loses the T1 badge, keeps verbatim CRITICAL", async () => {
  const r = await stageMutant('eval("im"+"port")("node:net")');
  assertCriticalNotDowngraded(r);
  assert.equal(computeVerdict(r.findings.filter((f) => !f.rule.startsWith("publint"))), "FAIL");
});

test("R2-M7 (NB2 regression): alias-bound writeFileSync + process.cwd escape loses the T1 badge, keeps verbatim CRITICAL", async () => {
  const r = await stageMutant('const w = fs.writeFileSync; w(path.join(process.cwd(),"..","x"),"p")');
  assertCriticalNotDowngraded(r);
  assert.equal(computeVerdict(r.findings.filter((f) => !f.rule.startsWith("publint"))), "FAIL");
});

// NB3 (VERIFIER-REPORT-R2-FIX3.json blockers[0]): clause-4 alternation missed child_process
// async exec/fork (matrix rows B6a/B6b/B6c/B7 kept the badge). Mutation strings are the
// report's repro lines, character for character; M10 is the orchestrator's addition proving
// the spawn verbs join the §1.6-9 call-position doctrine.

test("R2-M8 (NB3 regression): childProcess.exec shell-write AND alias-bound exec lose the T1 badge, keep verbatim CRITICAL", async () => {
  assertCriticalNotDowngraded(await stageMutant('childProcess.exec("echo pwned > ../../escape.txt")'));
  assertCriticalNotDowngraded(await stageMutant('const ex = childProcess.exec; ex("tee ../../escape.txt")'));
});

test("R2-M9 (NB3 regression): childProcess.fork of an out-of-tree payload loses the T1 badge, keeps verbatim CRITICAL", async () => {
  assertCriticalNotDowngraded(await stageMutant('childProcess.fork("../../payload.js")'));
});

test("R2-M10 (NB3 regression): alias-bound spawnSync with rm-rf argv loses the T1 badge, keeps verbatim CRITICAL", async () => {
  assertCriticalNotDowngraded(await stageMutant('const sp = childProcess.spawnSync; sp("evil-sh", ["-c", "rm -rf ../../x"])'));
});

// Found while tracing M10 (RED probe): `Sync?` in the clause-5 verb regexes quantified only the
// 'c', so ALL bare async write forms escaped T1_WRITE_CALL/T1_WRITE_NAME entirely — a fourth
// instance of the enumeration-gap class; golden carries zero bare-form tokens (measured) so the
// `(?:Sync)?` fix costs nothing.

test("R2-M11 (clause-5 async gap): bare fs.writeFile out-of-tree escape loses the T1 badge, keeps verbatim CRITICAL", async () => {
  assertCriticalNotDowngraded(await stageMutant("fs.writeFile(path.join(__dirname,'..','..','escaped.txt'),'pwned',()=>{})"));
});
