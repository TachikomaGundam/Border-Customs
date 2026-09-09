// provenance: original clean-room implementation per .omo/plans/border-push-channels.md todo C4
//
// rubygems channel acceptance suite. Every C4 AC maps to one test, driven by
// REAL gem (RubyGems) 3.6.7 (gated by requireGem) on git-init'd tmp repos:
//   * polarity table on a LOOPBACK stub server (127.0.0.1 http, never real
//     rubygems.org) via the config host override — the loopback URL is fed
//     through targets.rubygems.host exactly like a private gem server, so NO
//     URL re-homing hack is needed (unlike crates, whose public-only target
//     has no config url); the 404 legs are TEXT bodies classified by text
//     match (the v2 "This version could not be found." vs "This gem could not
//     be found" split and the v1 "This rubygem could not be found." — never
//     JSON.parse'd); every fail-closed branch (5xx, malformed 200, unrecognized
//     404 text, transport failure) is one EngineRunError, silence never means
//     absent; the border UA rides every probe's user-agent header;
//   * HEAD coordinate reader: *.gemspec discovery via `git ls-tree -r HEAD`
//     (zero/multiple ⇒ typed exit-2 ConfigError "ambiguous gemspec — set
//     targets.rubygems.name"), literal-only s.name/s.version regexes (dynamic
//     values ⇒ typed exit-2, never eval), targets.rubygems.name
//     disambiguation, s.date assignment rejection (non-reproducible build);
//   * stage with REAL gem build: deterministic .gem lands in .border/dist/,
//     extracted-tree scans (one outer `tar -xf` pass — gitleaks descends into
//     data.tar.gz natively, paths arrive `data.tar.gz!lib/x.rb` and are
//     scoped artifact-root-relative) attribute findings outside .border/;
//   * honesty: planted secret (literal AKIAI4Q3EXAMPL3K7X2Q + random 40-char
//     companion — generic-api-key entropy floor, randAwsPair shape) inside a
//     gemspec-declared file (s.files MUST list it — an empty files array
//     ships an empty data.tar.gz and the secret never leaves the machine) ⇒
//     stage finding ⇒ FAIL verdict ⇒ push refused at the gate (exit 1, zero
//     gem spawn, zero network);
//   * publish argv printed from the ONE source (publishArgv) on dry-run —
//     zero network, zero gem spawn (gemBinPath points at /nonexistent);
//     --yes legs: missing-PASS (exit 1), rehash mismatch (exit 2), and a
//     full happy path through a scripted fake gem binary (exit 0 ⇒ PASSED,
//     no real `gem push` ever) with the loopback host proving the pre-publish
//     re-probe; a failing fake gem (exit 7) ⇒ exit 1 + "no retry loop";
//     userinfo-bearing host urls are sanitized in the ledger (G20) and via
//     displayRemote — credentials never printed;
//   * the shared repack-strategy lookup (freshness.ts): rubygems lives in
//     REPACKERS next to npm/crates, pypi never does — one lookup site; the
//     repack mirrors the stage recipe (fail-closed null on ambiguous trees or
//     s.date assignments — null can never justify a skip).
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { after, test } from "node:test";

import type { BorderConfig } from "../src/config.ts";
import type { CheckRecord, LedgerArtifact } from "../src/ledger/records.ts";
import { appendRecord } from "../src/ledger/records.ts";
import { computeFingerprint } from "../src/ledger.ts";
import type { CheckContext } from "../src/check/context.ts";
import { stableStringify } from "../src/check/rulesHash.ts";
import { computeVerdict, isBlocking, type Finding } from "../src/findings.ts";
import { EngineMissingError, EngineRunError } from "../src/engines/support.ts";
import { EXIT_BLOCKED, EXIT_ERROR, EXIT_PASS } from "../src/cli/exit.ts";
import { displayRemote } from "../src/commands/push.ts";
import {
  FOREIGN_OWNER_RULE,
  NAME_AVAILABLE_RULE,
  VERSION_EXISTS_RULE,
  allChannels,
  rubygemsChannel,
  targetIds,
} from "../src/channels/registry.ts";
import {
  RUBYGEMS_DEFAULT_URL,
  RUBYGEMS_PROBE_USER_AGENT,
  readRubygemsCoords,
  rubygemsPublishArgv,
  runRubygemsPublish,
} from "../src/channels/rubygems.ts";
import { runRubygemsArtifactStage, singleTreeGemspec } from "../src/artifacts/rubygems.ts";
import { packRubygemsArtifacts, packNpmArtifacts, packCrateArtifacts, verifyArtifactFreshness, REPACKERS } from "../src/ledger/freshness.ts";
import { ConfigError } from "../src/channels/errors.ts";
import { recordPushSuccess } from "../src/pushstate.ts";
import { gitRevParseHead } from "./helpers/fixtures.ts";
import { requireGitleaks } from "./helpers/require-engines.ts";
import { startRegistryStub } from "./helpers/registry-stub.ts";
import {
  gitAddCommit,
  gitInit,
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

function borderCfg(rubygems: { name?: string; host?: string } = {}, remotes: readonly string[] = []): BorderConfig {
  return {
    version: 1,
    targets: { git: { remotes: [...remotes].map((url) => ({ url })) }, rubygems },
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
  const dir = makeFixtureDir(`rubygems-${name}`);
  roots.push(dir);
  gitInit(dir);
  return dir;
}

/** The gemspec PLUS its lib tree: `s.files = ["lib/<name>.rb"]` — gem build
 *  packages exactly the declared files (a missing listed file fails the
 *  build; an empty files array ships an EMPTY data.tar.gz, so honesty
 *  fixtures must always declare the secret-bearing file). */
function writeGemSource(repo: string, name: string, version: string, extraLib: string, secretFile = "lib/leaky.rb"): void {
  writeRel(repo, "lib/answer.rb", `def answer; 42; end\n`);
  writeRel(repo, secretFile, extraLib);
  writeRel(repo, `${name}.gemspec`, `Gem::Specification.new do |s|\n  s.name = "${name}"\n  s.version = "${version}"\n  s.summary = "border rubygems test gem"\n  s.authors = ["border test"]\n  s.files = ["lib/answer.rb", "${secretFile}"]\nend\n`);
  writeRel(repo, "README.md", `# ${name}\n`);
  writeRel(repo, ".gitignore", `.border/\n`);
  gitAddCommit(repo, "init");
}

/** Real gem presence gate (same shape as requireCargo): a missing gem must
 *  fail the suite loudly, never skip — stubs can never satisfy a real-engine
 *  AC. */
function requireGem(): string {
  const r = spawnSync("gem", ["--version"], { encoding: "utf8" });
  if (r.error !== undefined || r.status !== 0) {
    throw new Error(`ENGINE MISSING: gem (RubyGems) not found (${String(r.error ?? r.stderr)}). border fails closed — install ruby-full (apt) or rbenv/rvm before running the rubygems suite.`);
  }
  return r.stdout.trim();
}

requireGem();

function sha256File(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function byRule(findings: readonly Finding[], rule: string): Finding[] {
  return findings.filter((f) => f.rule === rule);
}

/** Records probe urls + headers while forwarding to the loopback stub — the
 *  host override makes the probe hit the stub directly (NO re-homing). */
function rubygemsFetcher(log: { headers: Record<string, string>[] }) {
  return async (url: string, init: { signal: AbortSignal; headers?: Record<string, string> }): Promise<{ status: number; json(): Promise<unknown>; text(): Promise<string> }> => {
    log.headers.push(init.headers ?? {});
    const res = await fetch(url, init.headers === undefined ? { signal: init.signal } : { signal: init.signal, headers: init.headers });
    return { status: res.status, json: () => res.json(), text: () => res.text() };
  };
}

async function seedCheckRecord(repoDir: string, cfg: BorderConfig, verdict: "PASS" | "FAIL", artifacts: readonly LedgerArtifact[] | null): Promise<string> {
  const targets: readonly string[] = ["rubygems"];
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

/** Stub routes for the rubygems polarity table — 404 legs are RAW TEXT
 *  bodies (contract §g: classification is by text, never JSON). */
function gemStubRoutes(name: string, version: string, v: { v2?: string; v1?: string | unknown }) {
  const routes = [];
  const v2Path = `/api/v2/rubygems/${name}/versions/${version}.json`;
  const v1Path = `/api/v1/gems/${name}.json`;
  if (v.v2 === "200") routes.push({ path: v2Path, body: { name, number: version, version } });
  else if (v.v2 !== undefined) routes.push({ path: v2Path, status: 404, raw: v.v2 });
  if (v.v1 === "200") routes.push({ path: v1Path, body: { name, version, authors: ["border test"] } });
  else if (v.v1 === null) routes.push({ path: v1Path, status: 404, raw: "This rubygem could not be found." });
  else if (v.v1 !== undefined) routes.push({ path: v1Path, body: v.v1 });
  return routes;
}

// --------------------------------------------------------------- AC: registration + descriptor shape
test("rubygems channel is registered fourth; --targets rubygems is valid; strict schema (name/host only)", () => {
  const ids = allChannels().map((c) => c.id);
  assert.deepEqual(ids.slice(0, 5), ["git", "npm", "pypi", "crates", "rubygems"], `registration order, got ${JSON.stringify(ids)}`);
  assert.ok(targetIds().includes("rubygems"), "targetIds must derive from the registry (C4 AC flip)");
  assert.equal(rubygemsChannel.id, "rubygems");
  assert.equal(rubygemsChannel.order, 4);
  assert.deepEqual(rubygemsChannel.artifactExtensions, [".gem"]);
  assert.equal(rubygemsChannel.confirmedVia, "rubygems-json");
  assert.equal(rubygemsChannel.defaultUrl, RUBYGEMS_DEFAULT_URL);
  assert.deepEqual(rubygemsChannel.envExpandFields, ["host"], "host is the ${VAR}-expandable field (mirrors npm's registry)");
  assert.equal(rubygemsChannel.freshness, "repack", "gem build embeds a fixed date (spike §e) — digest parity via repack, not key");

  assert.equal(rubygemsChannel.configSchema.parse(undefined), undefined);
  assert.deepEqual(rubygemsChannel.configSchema.parse({}), {});
  assert.deepEqual(rubygemsChannel.configSchema.parse({ name: "widgets", host: "https://gems.example" }), { name: "widgets", host: "https://gems.example" });
  assert.throws(() => rubygemsChannel.configSchema.parse({ registry: "https://gems.example" }), /unrecognized_key/i, "strict schema: no registry key (crates precedent)");
});

// --------------------------------------------------------------- AC: HEAD coordinate reader (gemspec discovery)
test("coords: zero gemspecs at HEAD => typed exit-2 'ambiguous gemspec' ConfigError", () => {
  const repo = fixture("coords-none");
  writeRel(repo, "README.md", "# nothing to publish\n");
  gitAddCommit(repo, "init");
  assert.throws(
    () => readRubygemsCoords(repo, borderCfg()),
    (e: unknown) => e instanceof ConfigError && e.exitCode === 2 && /ambiguous gemspec/.test(e.message),
    "zero gemspecs without a configured name must be a typed exit-2 ambiguity",
  );
});

test("coords: multiple gemspecs at HEAD => typed exit-2 'ambiguous gemspec' (name set disambiguates)", () => {
  const repo = fixture("coords-multi");
  writeRel(repo, "lib/a.rb", "def a; 1; end\n");
  writeRel(repo, "lib/b.rb", "def b; 2; end\n");
  writeRel(repo, "a.gemspec", `Gem::Specification.new { |s| s.name = "gem-a"; s.version = "1.0.0"; s.files = ["lib/a.rb"] }\n`);
  writeRel(repo, "b.gemspec", `Gem::Specification.new { |s| s.name = "gem-b"; s.version = "1.0.0"; s.files = ["lib/b.rb"] }\n`);
  gitAddCommit(repo, "init");
  assert.throws(() => readRubygemsCoords(repo, borderCfg()), (e: unknown) => e instanceof ConfigError && e.exitCode === 2 && /ambiguous gemspec — set targets\.rubygems\.name/.test(e.message));
  const withName = readRubygemsCoords(repo, borderCfg({ name: "gem-b" }));
  assert.deepEqual(withName, { name: "gem-b", version: "1.0.0" });
});

test("coords: dynamic version/name => typed exit-2 'literal' ConfigError, never eval", () => {
  const repo = fixture("coords-dyn");
  writeRel(repo, "lib/dyn.rb", "def dyn; 3; end\n");
  writeRel(repo, "dyn.gemspec", `require_relative 'lib/dyn'\nGem::Specification.new { |s| s.name = "dyn"; s.version = Gem::Version.new("1.0.0"); s.files = ["lib/dyn.rb"] }\n`);
  gitAddCommit(repo, "init");
  assert.throws(() => readRubygemsCoords(repo, borderCfg({ name: "dyn" })), (e: unknown) => e instanceof ConfigError && e.exitCode === 2 && /literal s\.version/.test(e.message));
  const dynName = fixture("coords-dynname");
  writeRel(dynName, "lib/ver.rb", "VERSION = '1.2.3'\n");
  writeRel(dynName, "x.gemspec", `require_relative 'lib/ver'\nGem::Specification.new { |s| s.name = X::VERSION; s.version = "1.2.3"; s.files = ["lib/ver.rb"] }\n`);
  gitAddCommit(dynName, "init");
  assert.throws(() => readRubygemsCoords(dynName, borderCfg({ name: "anything" })), (e: unknown) => e instanceof ConfigError && e.exitCode === 2 && /declares a literal s\.name matching/.test(e.message));
});

test("coords: s.date assignment => typed exit-2 ConfigError (non-reproducible gem digest)", () => {
  const repo = fixture("coords-date");
  writeRel(repo, "lib/d.rb", "def d; 4; end\n");
  writeRel(repo, "d.gemspec", `Gem::Specification.new { |s| s.name = "gem-d"; s.version = "1.0.0"; s.date = "2024-01-01"; s.files = ["lib/d.rb"] }\n`);
  gitAddCommit(repo, "init");
  assert.throws(() => readRubygemsCoords(repo, borderCfg()), (e: unknown) => e instanceof ConfigError && e.exitCode === 2 && /s\.date/.test(e.message));
});

test("coords: reads HEAD, never the working tree (committed gemspec wins over uncommitted edits)", () => {
  const repo = fixture("coords-head");
  writeRel(repo, "lib/h.rb", "def h; 5; end\n");
  writeRel(repo, "h.gemspec", `Gem::Specification.new { |s| s.name = "gem-h"; s.version = "1.0.0"; s.files = ["lib/h.rb"] }\n`);
  gitAddCommit(repo, "init");
  writeRel(repo, "h.gemspec", `Gem::Specification.new { |s| s.name = "gem-h"; s.version = "9.9.9"; s.files = ["lib/h.rb"] }\n`);
  assert.deepEqual(readRubygemsCoords(repo, borderCfg()), { name: "gem-h", version: "1.0.0" }, "coords must pin the committed identity");
});

// --------------------------------------------------------------- AC: probe polarity table (loopback stub)
test("probe: v2 200 => CRITICAL version-exists bump-required; no v1 leg", async () => {
  const repo = fixture("probe-present");
  writeGemSource(repo, "gem-present", "1.0.0", "");
  const s = await startRegistryStub(gemStubRoutes("gem-present", "1.0.0", { v2: "200" }));
  openStubs.push(s);
  const headers: Record<string, string>[] = [];
  const findings = await rubygemsChannel.probe({ repoDir: repo, cfg: borderCfg({ host: s.url }), timeoutMs: 5000, fetcher: rubygemsFetcher({ headers }) });
  assert.deepEqual(findings.map((f) => f.rule), [VERSION_EXISTS_RULE]);
  assert.equal(findings[0]?.severity, "CRITICAL");
  assert.ok((headers[0]?.["user-agent"] ?? "").includes(RUBYGEMS_PROBE_USER_AGENT), "probe must self-identify");
  assert.deepEqual(s.hits, [`/api/v2/rubygems/gem-present/versions/1.0.0.json`], "v2 200 short-circuits the name leg");
});

test("probe: v2 404 'This version could not be found.' + v1 200 ours (project_uri matches a git remote) => silent", async () => {
  const repo = fixture("probe-ours");
  writeGemSource(repo, "gem-ours", "1.0.0", "");
  const s = await startRegistryStub(gemStubRoutes("gem-ours", "1.0.0", { v2: "This version could not be found.", v1: { version: "1.0.0", project_uri: "https://origin.example/widgets", authors: ["border test"] } }));
  openStubs.push(s);
  const headers: Record<string, string>[] = [];
  const findings = await rubygemsChannel.probe({ repoDir: repo, cfg: borderCfg({ host: s.url }, ["https://origin.example/widgets.git"]), timeoutMs: 5000, fetcher: rubygemsFetcher({ headers }) });
  assert.deepEqual(findings, [], "ours-silent: no finding for a claimed version owned by the configured remote");
  assert.deepEqual(s.hits, [`/api/v2/rubygems/gem-ours/versions/1.0.0.json`, `/api/v1/gems/gem-ours.json`]);
});

test("probe: v2 404 'This version could not be found.' + v1 404 'This rubygem could not be found.' => INFO name-available (text 404s)", async () => {
  const repo = fixture("probe-absent");
  writeGemSource(repo, "gem-absent", "1.0.0", "");
  const s = await startRegistryStub(gemStubRoutes("gem-absent", "1.0.0", { v2: "This version could not be found.", v1: null }));
  openStubs.push(s);
  const findings = await rubygemsChannel.probe({ repoDir: repo, cfg: borderCfg({ host: s.url }), timeoutMs: 5000 });
  assert.deepEqual(findings.map((f) => f.rule), [NAME_AVAILABLE_RULE]);
  assert.equal(findings[0]?.severity, "INFO");
});

test("probe: v2 404 'This gem could not be found' (no period) => INFO name-available, no v1 leg", async () => {
  const repo = fixture("probe-nameabsent");
  writeGemSource(repo, "gem-na", "1.0.0", "");
  const s = await startRegistryStub(gemStubRoutes("gem-na", "1.0.0", { v2: "This gem could not be found" }));
  openStubs.push(s);
  const findings = await rubygemsChannel.probe({ repoDir: repo, cfg: borderCfg({ host: s.url }), timeoutMs: 5000 });
  assert.deepEqual(findings.map((f) => f.rule), [NAME_AVAILABLE_RULE]);
  assert.deepEqual(s.hits, [`/api/v2/rubygems/gem-na/versions/1.0.0.json`]);
});

test("probe: claimed by a foreign owner => CRITICAL foreign-owner", async () => {
  const repo = fixture("probe-foreign");
  writeGemSource(repo, "gem-foreign", "1.0.0", "");
  const s = await startRegistryStub(gemStubRoutes("gem-foreign", "1.0.0", { v2: "This version could not be found.", v1: { version: "1.0.0", project_uri: "https://other.example/not-ours", source_code_uri: "https://other.example/not-ours" } }));
  openStubs.push(s);
  const findings = await rubygemsChannel.probe({ repoDir: repo, cfg: borderCfg({ host: s.url }, ["https://origin.example/widgets.git"]), timeoutMs: 5000 });
  assert.deepEqual(findings.map((f) => f.rule), [FOREIGN_OWNER_RULE]);
  assert.equal(findings[0]?.severity, "CRITICAL");
});

test("probe: claimed but signal-less body => CRITICAL ambiguous (never a silent guess)", async () => {
  const repo = fixture("probe-bare");
  writeGemSource(repo, "gem-bare", "1.0.0", "");
  const s = await startRegistryStub(gemStubRoutes("gem-bare", "1.0.0", { v2: "This version could not be found.", v1: { version: "1.0.0" } }));
  openStubs.push(s);
  const findings = await rubygemsChannel.probe({ repoDir: repo, cfg: borderCfg({ host: s.url }), timeoutMs: 5000 });
  assert.deepEqual(findings.map((f) => f.rule), [FOREIGN_OWNER_RULE], "ambiguous ownership surfaces through the foreign-owner rule's CRITICAL path");
  assert.equal(findings[0]?.severity, "CRITICAL");
});

test("probe: claimed with the authors-email (info) matching cfg rules => silent", async () => {
  const repo = fixture("probe-email");
  writeGemSource(repo, "gem-email", "1.0.0", "");
  const s = await startRegistryStub(gemStubRoutes("gem-email", "1.0.0", { v2: "This version could not be found.", v1: { version: "1.0.0", authors: ["alice@self.example"], info: "maintained by alice@self.example" } }));
  openStubs.push(s);
  const cfg = borderCfg({ host: s.url });
  cfg.rules.authors.emails = ["alice@self.example"];
  const findings = await rubygemsChannel.probe({ repoDir: repo, cfg, timeoutMs: 5000 });
  assert.deepEqual(findings, [], "authors email matching a configured author email is an ours signal");
});

test("probe fail-closed: 5xx, malformed JSON, unrecognized 404 text, transport failure => EngineRunError, silence never means absent", async () => {
  const repo = fixture("probe-failclosed");
  writeGemSource(repo, "gem-fc", "1.0.0", "");
  const v2Path = `/api/v2/rubygems/gem-fc/versions/1.0.0.json`;

  const s500 = await startRegistryStub([{ path: v2Path, status: 500, body: { error: "boom" } }]);
  openStubs.push(s500);
  await assert.rejects(rubygemsChannel.probe({ repoDir: repo, cfg: borderCfg({ host: s500.url }), timeoutMs: 5000 }), (e: unknown) => e instanceof EngineRunError && /fail-closed/.test(e.message), "5xx must fail closed");

  const sBad = await startRegistryStub([{ path: v2Path, raw: "this is not json" }]);
  openStubs.push(sBad);
  await assert.rejects(rubygemsChannel.probe({ repoDir: repo, cfg: borderCfg({ host: sBad.url }), timeoutMs: 5000 }), (e: unknown) => e instanceof EngineRunError && /malformed JSON body/.test(e.message), "malformed 200 must fail closed");

  const sUnk = await startRegistryStub([{ path: v2Path, status: 404, raw: "nope, not our words" }]);
  openStubs.push(sUnk);
  await assert.rejects(rubygemsChannel.probe({ repoDir: repo, cfg: borderCfg({ host: sUnk.url }), timeoutMs: 5000 }), (e: unknown) => e instanceof EngineRunError && /refusing to classify/.test(e.message), "unrecognized 404 text must fail closed");

  const sV1Unk = await startRegistryStub([
    { path: v2Path, status: 404, raw: "This version could not be found." },
    { path: `/api/v1/gems/gem-fc.json`, status: 404, raw: "not our words either" },
  ]);
  openStubs.push(sV1Unk);
  await assert.rejects(rubygemsChannel.probe({ repoDir: repo, cfg: borderCfg({ host: sV1Unk.url }), timeoutMs: 5000 }), (e: unknown) => e instanceof EngineRunError && /refusing to classify/.test(e.message), "unrecognized v1 404 text must fail closed");

  await assert.rejects(
    rubygemsChannel.probe({ repoDir: repo, cfg: borderCfg({ host: sBad.url }), timeoutMs: 5000, fetcher: () => Promise.reject(new Error("ECONNREFUSED")) }),
    (e: unknown) => e instanceof EngineRunError && /unreachable/.test(e.message),
    "transport failure must fail closed",
  );
});

// --------------------------------------------------------------- AC: artifact stage with REAL gem build
test("stage: real gem build lands .border/dist/<name>-<version>.gem, deterministic sha256, tmp cleaned, scans are artifact-root-relative", async () => {
  const repo = fixture("stage");
  writeGemSource(repo, "border-demo", "1.0.0", "");
  const cfg = borderCfg();
  const first = await runRubygemsArtifactStage({ repoDir: repo, cfg });
  assert.ok(first.artifact !== null);
  assert.equal(first.artifact.file, ".border/dist/border-demo-1.0.0.gem");
  assert.equal(first.artifact.bytes, readFileSync(join(repo, ".border", "dist", "border-demo-1.0.0.gem")).length);
  assert.equal(first.artifact.sha256, sha256File(join(repo, ".border", "dist", "border-demo-1.0.0.gem")));

  const distFiles = readdirSync(join(repo, ".border", "dist"));
  assert.deepEqual(distFiles, ["border-demo-1.0.0.gem"], "dist must hold exactly the single built gem");

  const second = await runRubygemsArtifactStage({ repoDir: repo, cfg });
  assert.equal(second.artifact?.sha256, first.artifact?.sha256, "gem build is byte-deterministic per tree (spike §e) — freshness repack is sound");

  assert.deepEqual(readdirSync(join(repo, ".border", "tmp")), [], "extract sandbox must be removed after the stage");
  assert.deepEqual(first.findings, [], "clean tree + clean gem => no findings");
});

test("stage honesty: secret listed in s.files lands in the EXTRACTED tree scan (data.tar.gz! path), FAIL verdict, sandbox removed, blob silent", async () => {
  const repo = fixture("stage-honest");
  // randAwsPair OK: KEY side is the pinned literal; blob-absence of pair.secret is trivially safe (findings never carry raw values)
  const pair = randAwsPair();
  const literal = "AKIAI4Q3EXAMPL3K7X2Q"; // the plan-pinned fixture value — entropy floor already proven in the C2/C3 goldens
  const leak = `# leaked credentials\naws_access_key_id = ${literal}\naws_secret_access_key = ${pair.secret}\n`;
  writeGemSource(repo, "honest-gem", "1.0.0", leak);
  const cfg = borderCfg();
  const { findings } = await runRubygemsArtifactStage({ repoDir: repo, cfg });
  assert.equal(computeVerdict(findings), "FAIL", "the staged .gem carries the planted secret — check must fail");
  assert.ok(findings.some((f) => isBlocking(f.severity) && f.engine === "gitleaks"), "gitleaks must descend into the inner data.tar.gz (max-archive-depth 2)");
  const gitleaksAws = byRule(findings, "aws-access-token");
  assert.ok(gitleaksAws.length > 0, `expected aws-access-token findings, got ${JSON.stringify(findings.map((f) => ({ rule: f.rule, path: f.path, severity: f.severity })))}`);
  for (const f of gitleaksAws) {
    assert.ok(f.path !== undefined && f.path.includes("data.tar.gz!"), `path must arrive via the inner archive: ${String(f.path)}`);
    assert.ok(!f.path.split("/").includes(".border"), `scope must be artifact-root-relative: ${String(f.path)}`);
  }
  assert.deepEqual(readdirSync(join(repo, ".border", "tmp")), [], "extract sandbox must be removed even on findings");
  const blob = readFileSync(join(repo, ".border", "dist", "honest-gem-1.0.0.gem"), "utf8");
  assert.ok(!blob.includes(pair.secret), "the raw .gem may still embed the secret (gzip members) but the sandbox is already gone");
});

test("stage: gem missing => EngineMissingError with the ruby install hint", async () => {
  const repo = fixture("stage-nogem");
  writeGemSource(repo, "no-gem", "1.0.0", "");
  await assert.rejects(runRubygemsArtifactStage({ repoDir: repo, cfg: borderCfg(), gemBinPath: "/nonexistent/gem" }), (e: unknown) => e instanceof EngineMissingError && /ruby-full/.test(e.message), "missing gem must name the install path");
});

test("stage: working-tree gemspec ambiguity / s.date => EngineRunError (same doctrine as coords)", async () => {
  const repo = fixture("stage-ambig");
  writeGemSource(repo, "one", "1.0.0", "");
  writeRel(repo, "two.gemspec", `Gem::Specification.new { |s| s.name = "two"; s.version = "1.0.0"; s.files = [] }\n`);
  gitAddCommit(repo, "add-second");
  await assert.rejects(runRubygemsArtifactStage({ repoDir: repo, cfg: borderCfg() }), (e: unknown) => e instanceof EngineRunError && /ambiguous gemspec/.test(e.message));
  const resolved = await runRubygemsArtifactStage({ repoDir: repo, cfg: borderCfg({ name: "two" }) });
  assert.equal(resolved.artifact?.file, ".border/dist/two-1.0.0.gem", "the name disambiguates the working-tree build too");

  const dated = fixture("stage-date");
  
  writeRel(dated, "lib/d2.rb", "def d2; 2; end\n");
  writeRel(dated, "d2.gemspec", `Gem::Specification.new { |s| s.name = "d2"; s.version = "1.0.0"; s.date = "2024-06-01"; s.files = ["lib/d2.rb"] }\n`);
  gitAddCommit(dated, "init");
  await assert.rejects(runRubygemsArtifactStage({ repoDir: dated, cfg: borderCfg() }), (e: unknown) => e instanceof EngineRunError && /s\.date/.test(e.message));
});

// --------------------------------------------------------------- AC: publish — dry-run argv, gates, fake-gem happy path
test("publish dry-run: prints exactly the publishArgv row ('gem push <file>' / '--host' when configured), zero gem spawn, zero network", async () => {
  const repo = fixture("dryrun");
  writeGemSource(repo, "dryrun-gem", "1.0.0", "");
  const cfg = borderCfg();
  const { artifact } = await runRubygemsArtifactStage({ repoDir: repo, cfg });
  assert.ok(artifact !== null);
  const key = await seedCheckRecord(repo, cfg, "PASS", [artifact]);
  const out = collect();
  const err = collect();
  const exit = await runRubygemsPublish({ repoDir: repo, cfg, key, yes: false, gemBinPath: "/nonexistent/gem", out: out.write, err: err.write });
  assert.equal(exit, EXIT_PASS);
  assert.deepEqual(out.lines, ["gem push .border/dist/dryrun-gem-1.0.0.gem"], "dry-run must print the exact spawn argv — the ONE source (publishArgv)");
  assert.deepEqual(err.lines, []);
  assert.deepEqual(rubygemsPublishArgv([".border/dist/dryrun-gem-1.0.0.gem"], cfg), [["push", ".border/dist/dryrun-gem-1.0.0.gem"]]);
});

test("publish dry-run honors the host override in the argv row (private gem server)", async () => {
  const repo = fixture("dryrun-host");
  writeGemSource(repo, "host-gem", "1.0.0", "");
  const s = await startRegistryStub([{ path: "/" }]);
  openStubs.push(s);
  const cfg = borderCfg({ host: s.url });
  const { artifact } = await runRubygemsArtifactStage({ repoDir: repo, cfg });
  assert.ok(artifact !== null);
  const key = await seedCheckRecord(repo, cfg, "PASS", [artifact]);
  const out = collect();
  const err = collect();
  const exit = await runRubygemsPublish({ repoDir: repo, cfg, key, yes: false, gemBinPath: "/nonexistent/gem", out: out.write, err: err.write });
  assert.equal(exit, EXIT_PASS);
  assert.deepEqual(out.lines, [`gem push .border/dist/host-gem-1.0.0.gem --host ${s.url}`], "the configured host must ride the --host flag");
  assert.deepEqual(s.hits, [], "dry-run performs ZERO registry requests");
});

test("publish --yes with no PASS record: exit 1 'run border check first', zero gem spawn, zero network", async () => {
  const repo = fixture("nogate");
  writeGemSource(repo, "nogate-gem", "1.0.0", "");
  const cfg = borderCfg();
  const out = collect();
  const err = collect();
  const exit = await runRubygemsPublish({
    repoDir: repo, cfg, key: "0".repeat(96), yes: true, gemBinPath: "/nonexistent/gem", out: out.write, err: err.write,
  });
  assert.equal(exit, EXIT_BLOCKED);
  assert.ok(err.lines.some((l) => l.includes("no non-degraded PASSED check record")), `gate message missing: ${JSON.stringify(err.lines)}`);
});

test("publish --yes honest chain: FAIL record from a secret-bearing stage => exit 1 at the gate", async () => {
  const repo = fixture("honest");
  // randAwsPair OK: FAIL verdict rides the pinned literal KEY; pair.secret is inert ballast
  const pair = randAwsPair();
  writeGemSource(repo, "honest-gem", "1.0.0", `# leaked\naws_access_key_id = AKIAI4Q3EXAMPL3K7X2Q\naws_secret_access_key = ${pair.secret}\n`);
  const cfg = borderCfg();
  const { findings, artifact } = await runRubygemsArtifactStage({ repoDir: repo, cfg });
  assert.equal(computeVerdict(findings), "FAIL", "the staged .gem carries the planted secret — check must fail");
  assert.ok(findings.some((f) => isBlocking(f.severity) && f.engine === "gitleaks"));
  const key = await seedCheckRecord(repo, cfg, "FAIL", artifact === null ? null : [artifact]);
  const out = collect();
  const err = collect();
  const exit = await runRubygemsPublish({ repoDir: repo, cfg, key, yes: true, gemBinPath: "/nonexistent/gem", out: out.write, err: err.write });
  assert.equal(exit, EXIT_BLOCKED, "a FAIL check record must refuse the push (exit 1)");
  assert.ok(err.lines.some((l) => l.includes("no non-degraded PASSED check record")),
    `push must be refused at the gate with zero gem spawn, got ${JSON.stringify(err.lines)}`);
});

test("publish --yes rehash mismatch: staged .gem differs from the PASS record => exit 2 BEFORE the spawn", async () => {
  const repo = fixture("tampered");
  writeGemSource(repo, "tampered-gem", "1.0.0", "");
  const cfg = borderCfg();
  const { artifact } = await runRubygemsArtifactStage({ repoDir: repo, cfg });
  assert.ok(artifact !== null);
  const key = await seedCheckRecord(repo, cfg, "PASS", [{ file: artifact.file, sha256: "f".repeat(64) }]);
  const out = collect();
  const err = collect();
  const exit = await runRubygemsPublish({ repoDir: repo, cfg, key, yes: true, gemBinPath: "/nonexistent/gem", out: out.write, err: err.write });
  assert.equal(exit, EXIT_ERROR);
  assert.ok(err.lines.some((l) => l.includes("artifact changed since check")), `rehash gate must name the mismatch: ${JSON.stringify(err.lines)}`);
});

test("publish --yes happy path through a scripted fake gem: loopback re-probe INFO legs pass, record appended, exit 0 (no real gem push)", async () => {
  const repo = fixture("publish-ok");
  writeGemSource(repo, "publish-gem", "1.0.0", "");
  const s = await startRegistryStub(gemStubRoutes("publish-gem", "1.0.0", { v2: "This version could not be found.", v1: null }));
  openStubs.push(s);
  const cfg = borderCfg({ host: s.url });
  const { artifact } = await runRubygemsArtifactStage({ repoDir: repo, cfg });
  assert.ok(artifact !== null);
  const key = await seedCheckRecord(repo, cfg, "PASS", [artifact]);
  const fakeGem = join(repo, "fakegem");
  writeFileSync(fakeGem, "#!/bin/sh\nexit 0\n");
  chmodSync(fakeGem, 0o755);
  const out = collect();
  const err = collect();
  const exit = await runRubygemsPublish({ repoDir: repo, cfg, key, yes: true, gemBinPath: fakeGem, out: out.write, err: err.write });
  assert.equal(exit, EXIT_PASS);
  assert.deepEqual(s.hits, [`/api/v2/rubygems/publish-gem/versions/1.0.0.json`, `/api/v1/gems/publish-gem.json`], "the --yes re-probe hits the loopback host");
});

test("publish --yes: gem push failing (exit 7) => exit 1, 'no retry loop' (credentials are gem's business, stdio inherit)", async () => {
  const repo = fixture("publish-fail");
  writeGemSource(repo, "fail-gem", "1.0.0", "");
  const s = await startRegistryStub(gemStubRoutes("fail-gem", "1.0.0", { v2: "This version could not be found.", v1: null }));
  openStubs.push(s);
  const cfg = borderCfg({ host: s.url });
  const { artifact } = await runRubygemsArtifactStage({ repoDir: repo, cfg });
  assert.ok(artifact !== null);
  const key = await seedCheckRecord(repo, cfg, "PASS", [artifact]);
  const fakeGem = join(repo, "fakegem-fail");
  writeFileSync(fakeGem, "#!/bin/sh\nexit 7\n");
  chmodSync(fakeGem, 0o755);
  const out = collect();
  const err = collect();
  const exit = await runRubygemsPublish({ repoDir: repo, cfg, key, yes: true, gemBinPath: fakeGem, out: out.write, err: err.write });
  assert.equal(exit, EXIT_BLOCKED);
  assert.ok(err.lines.some((l) => l.includes("no retry loop")), `failure doctrine must refuse retries: ${JSON.stringify(err.lines)}`);
});

test("publish record: userinfo-bearing host urls are sanitized in the ledger and via displayRemote (G20)", async () => {
  const repo = fixture("userinfo");
  writeGemSource(repo, "crypt-gem", "1.0.0", "");
  const cfg = borderCfg({ host: "http://user:sekret@127.0.0.1:9999" });
  const rec = recordPushSuccess(repo, {
    key: "0".repeat(96),
    target: "rubygems",
    remoteName: "rubygems",
    url: displayRemote("http://user:sekret@127.0.0.1:9999"),
    localSha: gitRevParseHead(repo),
    version: "crypt-gem@1.0.0",
    confirmedVia: "rubygems-json",
  });
  assert.ok(!rec.url.includes("sekret"), "G20: ledger url must be sanitized");
  assert.ok(!displayRemote("http://user:sekret@127.0.0.1:9999").includes("sekret"), "displayRemote strips userinfo");
  assert.ok(displayRemote(cfg.targets.rubygems?.host ?? "").includes("127.0.0.1:9999"), "the host survives sanitization");
});

// --------------------------------------------------------------- AC: shared repack-strategy lookup (freshness)
test("freshness: rubygems repacks via the shared REPACKERS lookup; ambiguous tree or s.date => null (fail-closed, never a skip)", async () => {
  const repo = fixture("freshness");
  writeGemSource(repo, "fresh-gem", "1.0.0", "");
  const ctx: CheckContext = { repoDir: repo, headSha: HEX64, porcelainDigest: HEX64, dirty: false, refSet: [], currentBranch: "main" };
  const { artifact } = await runRubygemsArtifactStage({ repoDir: repo, cfg: borderCfg() });
  assert.ok(artifact !== null);
  const artifacts = packRubygemsArtifacts(repo, {});
  assert.ok(artifacts !== null && artifacts.length === 1, "repack must produce the single .gem");
  assert.equal(artifacts[0]?.file, "fresh-gem-1.0.0.gem");
  assert.equal(artifacts[0]?.sha256, artifact.sha256, "repack digest must equal the stage digest (deterministic build)");
  const record: CheckRecord = {
    t: "check", key: HEX64, key8: HEX64.slice(0, 8), head: HEX64, dirtyDigest: HEX64, refSetHash: HEX64,
    exposureSet: [], effectiveTargets: ["rubygems"], rulesHash: HEX64, artifacts, llm: false, verdict: "PASS",
    counts: emptyCounts(), reportPath: ".border/runs/x/report.json", degraded: false, ts: new Date().toISOString(),
  };
  assert.equal(verifyArtifactFreshness(record, ctx, repo, {}), true, "digest-identical repack must prove freshness");
  assert.ok(REPACKERS["npm"] === packNpmArtifacts, "npm moves through the same lookup as rubygems (one site, no parallel if)");
  assert.ok(REPACKERS["crates"] === packCrateArtifacts, "crates stays in the shared lookup");
  assert.ok(REPACKERS["rubygems"] === packRubygemsArtifacts, "rubygems is registered in the shared lookup");
  assert.equal(REPACKERS["pypi"], undefined, "pypi's key-match proof is the whole strategy — never repacked");

  const dirtyCtx = { ...ctx, dirty: true };
  assert.equal(verifyArtifactFreshness(record, dirtyCtx, repo, {}), false, "a dirty tree can never skip");
  writeFileSync(join(repo, "lib", "answer.rb"), "def answer; 7; end\n");
  assert.equal(verifyArtifactFreshness(record, ctx, repo, {}), false, "changed bytes must invalidate the skip");
});

test("freshness: singleTreeGemspec mirrors the stage doctrine — multi gemspec / s.date / dynamic version => null", () => {
  const repo = fixture("fresh-null");
  writeGemSource(repo, "fresh-a", "1.0.0", "");
  writeRel(repo, "fresh-b.gemspec", `Gem::Specification.new { |s| s.name = "fresh-b"; s.version = "1.0.0"; s.files = [] }\n`);
  assert.equal(singleTreeGemspec(repo), null, "a multi-gemspec tree must fail closed to a full re-check");
  const dated = fixture("fresh-date");
  
  writeRel(dated, "lib/d3.rb", "def d3; 3; end\n");
  writeRel(dated, "d3.gemspec", `Gem::Specification.new { |s| s.name = "d3"; s.version = "1.0.0"; s.date = "2024-06-01"; s.files = ["lib/d3.rb"] }\n`);
  assert.equal(singleTreeGemspec(dated), null, "an s.date assignment must fail closed (digest would legitimately change)");
  const dyn = fixture("fresh-dyn");
  
  writeRel(dyn, "lib/d4.rb", "def d4; 4; end\n");
  writeRel(dyn, "d4.gemspec", `Gem::Specification.new { |s| s.name = "d4"; s.version = Gem::Version.new("1.0.0"); s.files = ["lib/d4.rb"] }\n`);
  assert.equal(singleTreeGemspec(dyn), null, "a dynamic version must fail closed (never eval)");
});