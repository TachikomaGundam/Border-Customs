// provenance: original clean-room implementation per .omo/plans/border-push-channels.md todo C3
//
// crates channel acceptance suite. Every C3 AC maps to one test, driven by
// REAL cargo 1.93.1 (gated by requireCargo) on git-init'd tmp repos:
//   * polarity table on a LOOPBACK stub server (127.0.0.1 http, never real
//     crates.io) via the injected-fetcher seam — the ONLY way the crates probe
//     is testable, since the crates target carries no config url (public-only
//     guardrail): the seam passes the border UA through and re-homes URLs to
//     the stub; production code is untouched;
//   * HEAD coordinate reader (name/version from git show HEAD:Cargo.toml,
//     workspace-inherited version ⇒ typed exit-2 ConfigError, never a guess);
//   * stage with REAL cargo package: deterministic .crate lands in
//     .border/dist/, extracted-tree scans (gitleaks dir + secretlint paths)
//     attribute findings artifact-root-relative so they survive
//     filterBorderStateFindings (the false-green trap this suite pins);
//   * honesty: planted high-entropy AWS pair (randAwsPair — fresh per fixture,
//     base32-safe key) inside packaged source ⇒ .crate stage finding ⇒ FAIL
//     verdict ⇒ push refused at the gate with exit 1 (zero cargo spawn, zero
//     network — the FAIL record, not a repack, is what blocks);
//   * publish argv is printed from the ONE source (publishArgv) on dry-run —
//     zero network, zero cargo spawn (cargoBinPath points at /nonexistent);
//     --yes legs terminate before any probe (no config url ⇒ the re-probe would
//     hit real crates.io, which this suite never does): gates exercised are
//     missing-PASS (exit 1), rehash mismatch (exit 2) and the pre-publish
//     repackage digest-assert (exit 2) — the R-race backstop, driven through
//     the cargoBinPath seam with a scripted fake cargo that emits the wrong
//     bytes;
//   * the shared repack-strategy lookup (freshness.ts): npm and crates both
//     live in REPACKERS, pypi never does (its key-match proof is the whole
//     strategy) — no parallel if-structure, one lookup site;
//   * registration: publishChannels() order, --targets crates validity,
//     schema strictness (unknown key rejected, 'registry' key does not exist).
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, existsSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { after, test } from "node:test";

import type { BorderConfig } from "../src/config.ts";
import type { CheckRecord, LedgerArtifact } from "../src/ledger/records.ts";
import { appendRecord } from "../src/ledger/records.ts";
import { computeFingerprint } from "../src/ledger.ts";
import type { CheckContext } from "../src/check/context.ts";
import { stableStringify } from "../src/check/rulesHash.ts";
import { computeVerdict, isBlocking, type Finding } from "../src/findings.ts";
import { filterBorderStateFindings } from "../src/check/exclusions.ts";
import { EngineMissingError, EngineRunError } from "../src/engines/support.ts";
import { EXIT_BLOCKED, EXIT_ERROR, EXIT_PASS } from "../src/cli/exit.ts";
import {
  BUMP_VERSION_MESSAGE,
  FOREIGN_OWNER_RULE,
  NAME_AVAILABLE_RULE,
  VERSION_EXISTS_RULE,
  allChannels,
  cratesChannel,
  targetIds,
} from "../src/channels/registry.ts";
import {
  CRATES_IO_DEFAULT_URL,
  CRATES_PROBE_USER_AGENT,
  cratesPublishArgv,
  readCratesCoords,
  runCratesPublish,
} from "../src/channels/crates.ts";
import { runCargoArtifactStage } from "../src/artifacts/crates.ts";
import { packCrateArtifacts, packNpmArtifacts, verifyArtifactFreshness, REPACKERS } from "../src/ledger/freshness.ts";
import { requireGitleaks } from "./helpers/require-engines.ts";
import { startRegistryStub } from "./helpers/registry-stub.ts";
import {
  gitAddCommit,
  gitInit,
  gitRevParseHead,
  makeFixtureDir,
  randAwsPair,
  removeDir,
  writeRel,
} from "./helpers/fixtures.ts";

requireGitleaks();

const HEX64 = "0".repeat(64);

function emptyCounts(): CheckRecord["counts"] {
  return { INFO: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0, total: 0, blocking: 0, warnings: 0 };
}

function borderCfg(crates: { name?: string } = {}, remotes: readonly string[] = []): BorderConfig {
  return {
    version: 1,
    targets: { git: { remotes: [...remotes].map((url) => ({ url })) }, crates },
    rules: { authors: { emails: [], names: [] }, hosts: [], ips: [], pathPatterns: [], maxFileKB: 500 },
    allow: [],
    engines: { require: ["gitleaks", "secretlint"], trufflehog: false },
  };
}

const roots: string[] = [];
const openStubs: { close(): Promise<void> }[] = [];
after(async () => {
  for (const s of openStubs) await s.close();
  for (const d of roots) removeDir(d);
});

function fixture(name: string): string {
  const dir = makeFixtureDir(`crates-${name}`);
  roots.push(dir);
  gitInit(dir);
  return dir;
}

/** Minimal publishable cargo crate; .border is gitignored so stage output
 *  never dirties the tree (which would flip the fingerprint key). */
function writeCrate(repo: string, name: string, version: string, extraSource = ""): void {
  writeRel(repo, "Cargo.toml", `[package]\nname = "${name}"\nversion = "${version}"\nedition = "2021"\n`);
  writeRel(repo, "src/lib.rs", `pub fn answer() -> u32 { 42 }\n${extraSource}`);
  writeRel(repo, "README.md", `# ${name}\n`);
  writeRel(repo, ".gitignore", `.border/\n`);
  gitAddCommit(repo, "init");
}

/** Real cargo presence gate (same shape as requireGitleaks): a missing cargo
 *  must fail the suite loudly, never skip — stubs can never satisfy a
 *  real-engine AC. */
function requireCargo(): string {
  const r = spawnSync("cargo", ["--version"], { encoding: "utf8" });
  if (r.error !== undefined || r.status !== 0) {
    throw new Error(`ENGINE MISSING: cargo not found (${String(r.error ?? r.stderr)}). border fails closed — install Rust via rustup (https://rustup.rs) before running the crates suite.`);
  }
  return r.stdout.trim();
}

requireCargo();

function sha256File(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function byRule(findings: readonly Finding[], rule: string): Finding[] {
  return findings.filter((f) => f.rule === rule);
}

function sha256Str(s: string): string {
  return createHash("sha256").update(s).digest("hex");
}

function cratesHits(stub: { hits: readonly string[] }): string[] {
  return stub.hits.filter((h) => h.startsWith("/api/v1/crates/"));
}

/** Re-homes crates.io URLs to the loopback stub and records the request
 *  headers — the crates probe's ONLY seam (the crates target carries no config
 *  url). The UA it observes is the border self-identifying header; production
 *  code does not know the stub exists. */
function cratesFetcher(stub: { url: string; port: number }, log: { headers: Record<string, string>[] }) {
  return async (url: string, init: { signal: AbortSignal; headers?: Record<string, string> }): Promise<{ status: number; json(): Promise<unknown>; text(): Promise<string> }> => {
    if (!url.startsWith(CRATES_IO_DEFAULT_URL)) throw new Error(`probe left the crates.io base: ${url}`);
    log.headers.push(init.headers ?? {});
    const target = `${stub.url}${url.slice(CRATES_IO_DEFAULT_URL.length)}`;
    const res = await fetch(target, init.headers === undefined ? { signal: init.signal } : { signal: init.signal, headers: init.headers });
    return { status: res.status, json: () => res.json(), text: () => res.text() };
  };
}

// --------------------------------------------------------------- AC: registration + descriptor shape
test("crates channel is registered third; --targets crates is valid; strict schema has no registry key", () => {
  const ids = allChannels().map((c) => c.id);
  assert.deepEqual(ids.slice(0, 4), ["git", "npm", "pypi", "crates"], `registration order, got ${JSON.stringify(ids)}`);
  assert.ok(targetIds().includes("crates"), "targetIds must derive from the registry (C2 AC3 flip)");
  assert.equal(cratesChannel.id, "crates");
  assert.equal(cratesChannel.order, 3);
  assert.deepEqual(cratesChannel.artifactExtensions, [".crate"]);
  assert.equal(cratesChannel.confirmedVia, "crates-json");
  assert.equal(cratesChannel.defaultUrl, CRATES_IO_DEFAULT_URL);
  assert.deepEqual(cratesChannel.envExpandFields, []);
  // zod .strict(): an unknown crates key is an exit-2 unknown-key ConfigError,
  // and there is NO registry/host override key to set — public crates.io only.
  assert.throws(() => cratesChannel.configSchema.parse({ registry: "https://evil.example" }));
  assert.equal(cratesChannel.configSchema.parse(undefined), undefined);
  assert.deepEqual(cratesChannel.configSchema.parse({}), {});
});

// --------------------------------------------------------------- AC: HEAD coordinate reader (TOML_PLAIN doctrine)
test("readCratesCoords: name+version from git show HEAD:Cargo.toml; workspace-inherited version is a typed exit-2 ConfigError, never a guess", () => {
  const repo = fixture("coords");
  writeCrate(repo, "acme-widgets", "1.2.3");
  const coords = readCratesCoords(repo, borderCfg());
  assert.deepEqual(coords, { name: "acme-widgets", version: "1.2.3" });
  assert.equal(readCratesCoords(repo, borderCfg({ name: "renamed" })).name, "renamed", "targets.crates.name must override the manifest name");
});

test("readCratesCoords: version.workspace = true (non-literal) is a typed ConfigError with the doctrine message", () => {
  const repo = fixture("wsver");
  writeRel(repo, "Cargo.toml", `[workspace]\nmembers = []\n\n[package]\nname = "wsver"\nversion.workspace = true\n`);
  writeRel(repo, "src/lib.rs", "pub fn x() {}\n");
  gitAddCommit(repo, "init");
  assert.throws(
    () => readCratesCoords(repo, borderCfg()),
    (e: unknown) =>
      e instanceof Error && e.name === "ConfigError" && e.message.includes("no literal version") && e.message.includes("version.workspace = true"),
  );
});

// --------------------------------------------------------------- AC: probe polarity table (loopback stub, injected fetcher)
const VERSION_BODY = { version: { num: "1.0.0", checksum: "abc", yanked: false } };
// crate-metadata bodies served by the NAME query — the owner-signal source
// (plan Scope L43); CRATE_BARE carries no repository/homepage/documentation,
// so it exposes zero comparable signals (the ambiguity leg).
const CRATE_OURS = { crate: { name: "widgets", max_stable_version: "1.0.0", repository: "https://github.com/wiki-js/widgets.git" } };
const CRATE_FOREIGN = { crate: { name: "widgets", max_stable_version: "1.0.0", repository: "https://github.com/intruder/widgets.git" } };
const CRATE_BARE = { crate: { name: "widgets", max_stable_version: "1.0.0" } };

async function probeRepo(): Promise<string> {
  const dir = fixture("probe");
  writeCrate(dir, "widgets", "1.0.0");
  return dir;
}

test("probe: 200 {version:{...}} => CRITICAL version-exists bump; self-identifying UA sent on every request", async () => {
  const repo = await probeRepo();
  const stub = await startRegistryStub([
    { path: "/api/v1/crates/widgets/1.0.0", body: VERSION_BODY },
  ]);
  openStubs.push(stub);
  const log: { headers: Record<string, string>[] } = { headers: [] };
  const findings = await cratesChannel.probe({ repoDir: repo, cfg: borderCfg(), timeoutMs: 5_000, fetcher: cratesFetcher(stub, log) });
  assert.equal(findings.length, 1);
  assert.equal(findings[0]?.rule, VERSION_EXISTS_RULE);
  assert.equal(findings[0]?.severity, "CRITICAL");
  assert.equal(findings[0]?.message, BUMP_VERSION_MESSAGE);
  assert.equal(findings[0]?.valueDigest, sha256Str("widgets@1.0.0"), "the bump value must be recorded as a digest, never raw (G23)");
  for (const h of log.headers) {
    assert.equal(h["user-agent"], CRATES_PROBE_USER_AGENT, "every request must carry the self-identifying border UA (403 otherwise)");
  }
  assert.deepEqual(cratesHits(stub), ["/api/v1/crates/widgets/1.0.0"], "present version short-circuits the name leg");
});

test("probe: 404 'does not have a version' + crate body repository equals a configured git remote (normalized) => silent; owner signals come from the NAME query, never /owners", async () => {
  const repo = await probeRepo();
  const cfg = borderCfg({}, ["https://github.com/wiki-js/widgets.git"]);
  const stub = await startRegistryStub([
    { path: "/api/v1/crates/widgets/1.0.0", status: 404, raw: JSON.stringify({ errors: [{ detail: "crate `widgets` does not have a version `1.0.0`" }] }) },
    { path: "/api/v1/crates/widgets", body: CRATE_OURS },
  ]);
  openStubs.push(stub);
  const findings = await cratesChannel.probe({ repoDir: repo, cfg, timeoutMs: 5_000, fetcher: cratesFetcher(stub, { headers: [] }) });
  assert.deepEqual(findings.map((f) => f.rule), [], `repo-url owner match must clear, got ${JSON.stringify(findings.map((f) => `${f.rule}:${f.message}`))}`);
  assert.deepEqual(cratesHits(stub), [
    "/api/v1/crates/widgets/1.0.0",
    "/api/v1/crates/widgets",
  ], "owner signals come from the name-query crate metadata (plan Scope L43)");
  assert.ok(!cratesHits(stub).some((h) => h.includes("/owners")), "the /owners request must be dropped entirely");
});

test("probe: 404 'does not exist' => INFO name-available", async () => {
  const repo = await probeRepo();
  const stub = await startRegistryStub([
    { path: "/api/v1/crates/widgets/1.0.0", status: 404, raw: JSON.stringify({ errors: [{ detail: "crate `widgets` does not have a version `1.0.0`" }] }) },
    { path: "/api/v1/crates/widgets", status: 404, raw: JSON.stringify({ errors: [{ detail: "crate `widgets` does not exist" }] }) },
  ]);
  openStubs.push(stub);
  const findings = await cratesChannel.probe({ repoDir: repo, cfg: borderCfg(), timeoutMs: 5_000, fetcher: cratesFetcher(stub, { headers: [] }) });
  assert.equal(findings.length, 1);
  assert.equal(findings[0]?.rule, NAME_AVAILABLE_RULE);
  assert.equal(findings[0]?.severity, "INFO");
  assert.equal(findings[0]?.valueDigest, sha256Str("widgets"), "the name value must be a digest, never raw (G23)");
});

test("probe: claimed crate whose body repository belongs to a foreign owner => CRITICAL name-foreign-owner", async () => {
  const repo = await probeRepo();
  const cfg = borderCfg({}, ["https://github.com/wiki-js/widgets.git"]);
  const stub = await startRegistryStub([
    { path: "/api/v1/crates/widgets/1.0.0", status: 404, raw: JSON.stringify({ errors: [{ detail: "crate `widgets` does not have a version `1.0.0`" }] }) },
    { path: "/api/v1/crates/widgets", body: CRATE_FOREIGN },
  ]);
  openStubs.push(stub);
  const findings = await cratesChannel.probe({ repoDir: repo, cfg, timeoutMs: 5_000, fetcher: cratesFetcher(stub, { headers: [] }) });
  const f = findings.find((x) => x.rule === FOREIGN_OWNER_RULE);
  assert.ok(f !== undefined, `expected foreign-owner finding under a foreign repository url, got ${JSON.stringify(findings.map((x) => x.rule))}`);
  assert.equal(f?.severity, "CRITICAL");
  assert.equal(f?.valueDigest, sha256Str("widgets:foreign"));
});

test("probe: claimed crate whose body exposes NO comparable repository/email signal => CRITICAL ambiguous-provenance, fail loud", async () => {
  const repo = await probeRepo();
  const cfg = borderCfg({}, ["https://github.com/wiki-js/widgets.git"]);
  const stub = await startRegistryStub([
    { path: "/api/v1/crates/widgets/1.0.0", status: 404, raw: JSON.stringify({ errors: [{ detail: "crate `widgets` does not have a version `1.0.0`" }] }) },
    { path: "/api/v1/crates/widgets", body: CRATE_BARE },
  ]);
  openStubs.push(stub);
  const findings = await cratesChannel.probe({ repoDir: repo, cfg, timeoutMs: 5_000, fetcher: cratesFetcher(stub, { headers: [] }) });
  const a = findings.find((x) => x.rule === FOREIGN_OWNER_RULE);
  assert.ok(a !== undefined, "zero owner signals must be CRITICAL ambiguous, never a skip");
  assert.equal(a?.severity, "CRITICAL");
  assert.equal(a?.valueDigest, sha256Str("widgets:ambiguous"));
});

test("probe: 403 (UA policy wall) / timeout / malformed JSON fail closed with EngineRunError exit 2 — silence never means absent", async () => {
  const repo = await probeRepo();
  const cfg = borderCfg();

  const s403 = await startRegistryStub([
    { path: "/api/v1/crates/widgets/1.0.0", status: 403, raw: JSON.stringify({ errors: [{ detail: "adding a User-Agent header is required" }] }) },
  ]);
  openStubs.push(s403);
  await assert.rejects(
    cratesChannel.probe({ repoDir: repo, cfg, timeoutMs: 5_000, fetcher: cratesFetcher(s403, { headers: [] }) }),
    (e: unknown) => e instanceof EngineRunError && e.message.includes("403") && e.message.includes("User-Agent"),
    "403 must be fail-closed (blocked probe is never 'absent')",
  );

  const sBad = await startRegistryStub([
    { path: "/api/v1/crates/widgets/1.0.0", status: 200, raw: "this is not json" },
  ]);
  openStubs.push(sBad);
  await assert.rejects(
    cratesChannel.probe({ repoDir: repo, cfg, timeoutMs: 5_000, fetcher: cratesFetcher(sBad, { headers: [] }) }),
    (e: unknown) => e instanceof EngineRunError && e.message.includes("malformed JSON body"),
    "malformed 200 body must be fail-closed",
  );

  await assert.rejects(
    cratesChannel.probe({
      repoDir: repo,
      cfg,
      timeoutMs: 5_000,
      fetcher: async () => {
        throw new Error("boom (simulated transport failure)");
      },
    }),
    (e: unknown) => e instanceof EngineRunError && e.message.includes("registry unreachable"),
    "transport failure must be fail-closed, never classified absent",
  );
});

// --------------------------------------------------------------- AC: stage with REAL cargo package
test("stage with real cargo: deterministic .crate in .border/dist, scan findings artifact-relative, sandbox removed", async () => {
  const repo = fixture("stage");
  writeCrate(repo, "acme-crate", "2.0.0");
  const r1 = await runCargoArtifactStage({ repoDir: repo, cfg: borderCfg() });
  assert.deepEqual(r1.findings.map((f) => `${f.rule}:${f.path}`), [], `clean crate must produce zero findings, got ${JSON.stringify(r1.findings)}`);
  assert.equal(computeVerdict(r1.findings), "PASS");
  assert.ok(r1.artifact !== null);
  assert.equal(r1.artifact?.file, ".border/dist/acme-crate-2.0.0.crate");
  const cratePath = join(repo, r1.artifact!.file);
  assert.ok(existsSync(cratePath), ".crate must land in .border/dist per repo convention");
  assert.equal(r1.artifact?.sha256, sha256File(cratePath));

  const r2 = await runCargoArtifactStage({ repoDir: repo, cfg: borderCfg() });
  assert.deepEqual(r2.artifact, r1.artifact, "cargo package must be byte-deterministic across runs (spike §a; freshness repack equality)");
  assert.deepEqual(readdirSync(join(repo, ".border", "dist")), ["acme-crate-2.0.0.crate"], "dist holds exactly one .crate");
  const tmp = join(repo, ".border", "tmp");
  assert.deepEqual(existsSync(tmp) ? readdirSync(tmp) : [], [], "cargo target dir must be removed after stage");
});

test("stage with real cargo: packed secret => .crate extraction findings survive .border filtering; verdict FAIL", async () => {
  const repo = fixture("leaky");
  const pair = randAwsPair();
  writeCrate(repo, "leaky-crate", "1.0.0", `// leaked credentials\n${pair.text}`);
  const r = await runCargoArtifactStage({ repoDir: repo, cfg: borderCfg() });
  const gk = byRule(r.findings, "aws-access-token");
  assert.ok(gk.some((f) => f.severity === "CRITICAL" && f.path === "leaky-crate-1.0.0/src/lib.rs"),
    `.crate is a gitleaks native-miss — the tar -xzf extraction route must find the secret, got ${JSON.stringify(r.findings.map((f) => `${f.engine}:${f.path}`))}`);
  const sl = r.findings.filter((f) => f.engine === "secretlint");
  assert.ok(sl.some((f) => f.severity === "CRITICAL" && f.path === "leaky-crate-1.0.0/src/lib.rs"), "secretlint must independently flag the AWS pair");
  for (const f of r.findings) {
    assert.ok(!(f.path ?? "").split("/").includes(".border"), `finding path leaks .border segment: ${f.path}`);
  }
  assert.equal(filterBorderStateFindings(r.findings, repo).length, r.findings.length, "no artifact finding may be .border-excluded");
  assert.equal(computeVerdict(r.findings), "FAIL");
  const blob = JSON.stringify(r.findings);
  assert.ok(!blob.includes(pair.key) && !blob.includes(pair.secret), "raw secret leaked into findings");
  const tmp = join(repo, ".border", "tmp");
  assert.deepEqual(existsSync(tmp) ? readdirSync(tmp) : [], [], "extraction sandbox must be removed");
});

test("stage: missing cargo binary is an EngineMissing-class exit-2 error naming the rustup install hint", async () => {
  const repo = fixture("nocargo");
  writeCrate(repo, "nocargo", "1.0.0");
  await assert.rejects(
    runCargoArtifactStage({ repoDir: repo, cfg: borderCfg(), cargoBinPath: "/nonexistent/cargo" }),
    (e: unknown) => e instanceof EngineMissingError && e.message.includes("rustup"),
    "missing cargo must surface as EngineMissingError with the install hint",
  );
});

// --------------------------------------------------------------- AC: publish legs (fake-binary seam only)
async function seedCheckRecord(repoDir: string, cfg: BorderConfig, verdict: "PASS" | "FAIL", artifacts: readonly LedgerArtifact[] | null): Promise<string> {
  const targets: readonly string[] = ["crates"];
  const { fp } = await computeFingerprint(repoDir, cfg, stableStringify(cfg), targets, {});
  const record: CheckRecord = {
    t: "check",
    key: fp.key,
    key8: fp.key.slice(0, 8),
    head: gitRevParseHead(repoDir),
    dirtyDigest: HEX64,
    refSetHash: HEX64,
    exposureSet: fp.exposureSet,
    effectiveTargets: targets,
    rulesHash: fp.rulesHash,
    artifacts,
    llm: false,
    verdict,
    counts: emptyCounts(),
    reportPath: ".border/runs/x/report.json",
    degraded: false,
    ts: new Date().toISOString(),
  };
  appendRecord(repoDir, record);
  return fp.key;
}

function collect() {
  const lines: string[] = [];
  return {
    lines,
    write: (s: string) => { lines.push(s); },
  };
}

test("publish dry-run: prints exactly the publishArgv row ('cargo publish --allow-dirty --no-verify'), zero cargo spawn, zero network", async () => {
  const repo = fixture("dryrun");
  writeCrate(repo, "dryrun-crate", "1.0.0");
  const cfg = borderCfg();
  const { artifact } = await runCargoArtifactStage({ repoDir: repo, cfg });
  assert.ok(artifact !== null);
  const key = await seedCheckRecord(repo, cfg, "PASS", [artifact]);
  const out = collect();
  const err = collect();
  const exit = await runCratesPublish({ repoDir: repo, cfg, key, yes: false, cargoBinPath: "/nonexistent/cargo", out: out.write, err: err.write });
  assert.equal(exit, EXIT_PASS);
  assert.deepEqual(out.lines, ["cargo publish --allow-dirty --no-verify"], "dry-run must print the exact spawn argv — the ONE source (publishArgv)");
  assert.deepEqual(err.lines, []);
  assert.deepEqual(cratesPublishArgv([".border/dist/dryrun-crate-1.0.0.crate"], cfg), [["publish", "--allow-dirty", "--no-verify"]]);
});

test("publish --yes with no PASS record: exit 1 'run border check first', zero cargo spawn, zero network", async () => {
  const repo = fixture("nogate");
  writeCrate(repo, "nogate-crate", "1.0.0");
  const cfg = borderCfg();
  const out = collect();
  const err = collect();
  const exit = await runCratesPublish({
    repoDir: repo, cfg, key: "0".repeat(96), yes: true, cargoBinPath: "/nonexistent/cargo", out: out.write, err: err.write,
  });
  assert.equal(exit, EXIT_BLOCKED);
  assert.ok(err.lines.some((l) => l.includes("no non-degraded PASSED check record")), `gate message missing: ${JSON.stringify(err.lines)}`);
});

test("publish --yes honest chain: FAIL record from a secret-bearing stage => exit 1 at the gate", async () => {
  const repo = fixture("honest");
  const pair = randAwsPair();
  writeCrate(repo, "honest-crate", "1.0.0", `// leaked\n${pair.text}`);
  const cfg = borderCfg();
  const { findings, artifact } = await runCargoArtifactStage({ repoDir: repo, cfg });
  assert.equal(computeVerdict(findings), "FAIL", "the staged .crate carries the planted secret — check must fail");
  assert.ok(findings.some((f) => isBlocking(f.severity) && f.engine === "gitleaks"));
  const key = await seedCheckRecord(repo, cfg, "FAIL", artifact === null ? null : [artifact]);
  const out = collect();
  const err = collect();
  const exit = await runCratesPublish({ repoDir: repo, cfg, key, yes: true, cargoBinPath: "/nonexistent/cargo", out: out.write, err: err.write });
  assert.equal(exit, EXIT_BLOCKED, "a FAIL check record must refuse the push (exit 1)");
  assert.ok(err.lines.some((l) => l.includes("no non-degraded PASSED check record")),
    `push must be refused at the gate with zero cargo spawn, got ${JSON.stringify(err.lines)}`);
});

test("publish --yes rehash mismatch: staged .crate differs from the PASS record => exit 2 BEFORE the repackage gate", async () => {
  const repo = fixture("tampered");
  writeCrate(repo, "tampered-crate", "1.0.0");
  const cfg = borderCfg();
  const seed = await seedCheckRecord(repo, cfg, "PASS", [{ file: ".border/dist/tampered-crate-1.0.0.crate", sha256: "f".repeat(64) }]);
  const out = collect();
  const err = collect();
  const exit = await runCratesPublish({ repoDir: repo, cfg, key: seed, yes: true, cargoBinPath: "/nonexistent/cargo", out: out.write, err: err.write });
  assert.equal(exit, EXIT_ERROR);
  assert.ok(err.lines.some((l) => l.includes("artifact changed since check")), `rehash gate message missing: ${JSON.stringify(err.lines)}`);
});

test("publish --yes digest-assert (R-race backstop): repackaged bytes differ from the staged .crate => exit 2 fail-closed, no network", async () => {
  const repo = fixture("repackage");
  writeCrate(repo, "repack-crate", "1.0.0");
  const cfg = borderCfg();
  const { artifact } = await runCargoArtifactStage({ repoDir: repo, cfg });
  assert.ok(artifact !== null);
  const key = await seedCheckRecord(repo, cfg, "PASS", [artifact]);
  // Fake cargo seam: the pre-publish repackage calls `cargo package` and this
  // script answers with DIFFERENT bytes at CARGO_TARGET_DIR/package — the
  // digest-assert must catch it before any network leg (crates has no config
  // url, so reaching the probes would be a real crates.io hit — never allowed).
  const fakeBin = join(repo, "fakecargo");
  writeFileSync(fakeBin, "#!/bin/sh\nmkdir -p \"$CARGO_TARGET_DIR/package\"\nprintf 'TAMPERED' > \"$CARGO_TARGET_DIR/package/repack-crate-1.0.0.crate\"\nexit 0\n");
  chmodSync(fakeBin, 0o755);
  const out = collect();
  const err = collect();
  const exit = await runCratesPublish({ repoDir: repo, cfg, key, yes: true, cargoBinPath: fakeBin, out: out.write, err: err.write });
  assert.equal(exit, EXIT_ERROR);
  assert.ok(err.lines.some((l) => l.includes("package bytes changed since check")), `digest-assert must refuse the push: ${JSON.stringify(err.lines)}`);
  assert.ok(err.lines.some((l) => l.includes("fail-closed")), "fail-closed doctrine wording must name the refusal");
});

test("publish --yes: repackage spawn failure => exit 2 with the rustup install hint (zero network)", async () => {
  const repo = fixture("nobin");
  writeCrate(repo, "nobin-crate", "1.0.0");
  const cfg = borderCfg();
  const { artifact } = await runCargoArtifactStage({ repoDir: repo, cfg });
  assert.ok(artifact !== null);
  const key = await seedCheckRecord(repo, cfg, "PASS", [artifact]);
  const out = collect();
  const err = collect();
  const exit = await runCratesPublish({ repoDir: repo, cfg, key, yes: true, cargoBinPath: "/nonexistent/cargo", out: out.write, err: err.write });
  assert.equal(exit, EXIT_ERROR);
  assert.ok(err.lines.some((l) => l.includes("rustup")), `install hint missing: ${JSON.stringify(err.lines)}`);
});

// --------------------------------------------------------------- AC: shared repack-strategy lookup (freshness)
test("freshness: crates repacks via the shared REPACKERS lookup; pypi is never a repacker; dirty tree never skips", async () => {
  const repo = fixture("freshness");
  writeCrate(repo, "fresh-crate", "1.0.0");
  const ctx: CheckContext = { repoDir: repo, headSha: HEX64, porcelainDigest: HEX64, dirty: false, refSet: [], currentBranch: "main" };
  const artifacts = packCrateArtifacts(repo, {});
  assert.ok(artifacts !== null && artifacts.length === 1, "repack must produce the single .crate");
  assert.equal(artifacts[0]?.file, "fresh-crate-1.0.0.crate");
  const record: CheckRecord = {
    t: "check", key: HEX64, key8: HEX64.slice(0, 8), head: HEX64, dirtyDigest: HEX64, refSetHash: HEX64,
    exposureSet: [], effectiveTargets: ["crates"], rulesHash: HEX64, artifacts, llm: false, verdict: "PASS",
    counts: emptyCounts(), reportPath: ".border/runs/x/report.json", degraded: false, ts: new Date().toISOString(),
  };
  assert.equal(verifyArtifactFreshness(record, ctx, repo, {}), true, "digest-identical repack must prove freshness");
  assert.ok(REPACKERS["npm"] === packNpmArtifacts, "npm moves through the same lookup as crates (one site, no parallel if)");
  assert.ok(REPACKERS["crates"] === packCrateArtifacts, "crates is registered in the shared lookup");
  assert.equal(REPACKERS["pypi"], undefined, "pypi's key-match proof is the whole strategy — never repacked");
  assert.equal(ctx.dirty ? "dirty" : "clean", "clean");
  const dirtyCtx = { ...ctx, dirty: true };
  assert.equal(verifyArtifactFreshness(record, dirtyCtx, repo, {}), false, "a dirty tree can never skip");
  writeFileSync(join(repo, "src", "lib.rs"), "pub fn answer() -> u32 { 7 }\n");
  assert.equal(verifyArtifactFreshness(record, ctx, repo, {}), false, "changed bytes must invalidate the skip");
});