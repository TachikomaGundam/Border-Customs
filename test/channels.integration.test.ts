// provenance: original clean-room implementation per .omo/plans/border-push-channels.md todo C5
//
// C5 cross-channel integration suite: the 5-target fixture repo (git bare
// remote + npm + pypi + crates + rubygems) ran through the REAL CLI, proving
// the channel-registry refactor holds under real multi-platform pushes —
// every registry leg on a 127.0.0.1 loopback stub (npm/pypi via
// startRegistryStub; crates via the CRATES_IO_URL probe seam added by C5 —
// see the seam's safety note in src/channels/crates.ts; rubygems via the
// config host override), every publish spawn routed through fake binaries
// (PATH-stub npm, TWINE_BIN twine, PATH-stub cargo, PATH-stub gem) that log
// each invocation to $SPAWN_LOG — the ordering/traffic trace. Real network
// is zero BY CONSTRUCTION: the crates probe base in EVERY run is the stub
// (CRATES_IO_URL env), and no test file string is ever fetched.
//
// AC mapping:
//   C5-1 subset discipline: git-only PASS (check --targets git) cannot
//        authorize ANY leg of a full push; full PASS cannot authorize a
//        crates-only push (fingerprint effectiveTargets scope binding).
//   C5-2 all-BLOCKED: zero check runs ⇒ --yes refuses, exit 1, zero
//        publishes, zero push-records.
//   C5-3 partial: crates publish fails (fake cargo exit 7) ⇒ rubygems NEVER
//        spawned (order 3-before-4), earlier legs stay recorded, exit 1 +
//        the exact failure-message shape.
//   C5-4 ordering: publish legs execute in descriptor order git→npm→pypi→
//        crates→rubygems — the SPAWN_LOG sequence is asserted exactly.
//   C5-5 ledger round-trip: crates-json/rubygems-json records written then
//        re-parsed through the STRICT parser; a pre-C3-era ledger (only
//        ls-remote/npm-view/pypi-json records) parses verbatim with ZERO
//        warnings and the newer binary still authorizes on it.
//   C5-6 cache-invalidation matrix: adding/removing `crates: {}` changes the
//        fingerprint key ⇒ the old PASS authorizes nothing (refuse message).
//   C5-7 border status lists every leg PENDING pre-push, PUSHED post-push
//        (per-leg blocked state is asserted on the push-state lines, which
//        are status' honest twin — status only renders pushed/pending).
//   C5-8 honesty through a NEW channel end-to-end: a planted
//        AKIAI4Q3EXAMPL3K7X2Q + random 40-char companion in a rubygems-
//        packaged file ⇒ check exit 1 ⇒ --yes push refused (CLI level; the
//        crates class was already covered descriptor-level in C3).
// Cleanup contract: mkdtemp roots under test/tmp (gitignored) removed in
// after(); stub servers closed (socket-destroy first); no blind sleeps.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { after, test } from "node:test";

import { run } from "../src/cli.ts";
import { EXIT_BLOCKED, EXIT_PASS } from "../src/cli/exit.ts";
import { CRATES_IO_DEFAULT_URL } from "../src/channels/crates.ts";
import { pushRecords, readLedger, type CheckRecord, type PushRecord } from "../src/ledger.ts";
import { LEDGER_FILE, parseLedgerRecord } from "../src/ledger/records.ts";
import { PUBLISH_WARNING } from "../src/push/core.ts";
import { startRegistryStub, type RegistryStub } from "./helpers/registry-stub.ts";
import { gitAddCommit, gitInit, gitRevParseHead, makeFixtureDir, randAwsPair, removeDir, writeRel } from "./helpers/fixtures.ts";
import { requireGitleaks } from "./helpers/require-engines.ts";

requireGitleaks();

/** The plan's honesty AC literal — the fixed gitleaks-matchable key (e2e
 *  honesty precedent); the 40-char companion is a FRESH random per fixture
 *  (gitleaks content-dedupes identical secret values within one scan). */
const LEAK_KEY_ID = "AKIAI4Q3EXAMPL3K7X2Q";

const fixtureRoots: string[] = [];
const openStubs: { close(): Promise<void> }[] = [];

after(async () => {
  for (const s of openStubs) await s.close();
  for (const d of fixtureRoots) removeDir(d);
});

// ---------------------------------------------------------------- plumbing

function scratch(prefix: string): string {
  const dir = makeFixtureDir(prefix);
  fixtureRoots.push(dir);
  return dir;
}

function gitIn(cwd: string, args: readonly string[]): string {
  const r = spawnSync("git", [...args], { cwd, encoding: "utf8", env: { ...process.env, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_SYSTEM: "/dev/null" } });
  if (r.status !== 0) throw new Error(`git ${args.join(" ")} failed: ${r.stderr}`);
  return r.stdout;
}

function lsRemote(bare: string, ref: string): string | null {
  const out = spawnSync("git", ["ls-remote", `file://${bare}`, ref], { encoding: "utf8" });
  if (out.status !== 0) return null;
  const line = out.stdout.split("\n").find((l) => l.includes(ref));
  return line === undefined ? null : (line.split("\t")[0] as string);
}

type RunResult = { readonly code: number; readonly out: string[]; readonly err: string[] };
async function runBorder(argv: readonly string[], f: Fixture, extraEnv: NodeJS.ProcessEnv = {}): Promise<RunResult> {
  const out: string[] = [];
  const err: string[] = [];
  const code = await run(argv, (l) => out.push(String(l)), (l) => err.push(String(l)), { cwd: f.repo, env: { ...process.env, ...f.env, ...extraEnv } });
  return { code, out, err };
}

const dump = (r: RunResult): string => `code=${String(r.code)}\nout:\n${r.out.join("\n")}\nerr:\n${r.err.join("\n")}`;

/** Real binary path each fake forwards to (resolve ONCE per suite, I3
 *  precedent). cargo/gem are mandatory — the crates/rubygems stages build
 *  with the REAL tools (the fakes only intercept publish/repack gate edges). */
function realBin(name: string): string {
  const r = spawnSync("sh", ["-c", `command -v ${name}`], { encoding: "utf8" });
  if (r.status !== 0 || r.stdout.trim() === "") throw new Error(`ENGINE MISSING: ${name} not found on PATH — the C5 fixture needs it (check --force builds every artifact for real)`);
  return r.stdout.trim();
}

const REAL_NPM = realBin("npm");
const REAL_CARGO = realBin("cargo");
const REAL_GEM = realBin("gem");

// ---------------------------------------------------------------- stubs

/** The four registry stubs for one fixture. Every probe answer says ABSENT
 *  (404s) — that is what makes every leg PENDING under a green PASS. The
 *  npm 404 is the stub's default JSON error body (npm maps it to E404); the
 *  crates 404s must carry the JSON errors[].detail discriminators; the
 *  rubygems 404s are TEXT per contract §g. */
async function fourStubs(): Promise<[RegistryStub, RegistryStub, RegistryStub, RegistryStub]> {
  const stubs: [RegistryStub, RegistryStub, RegistryStub, RegistryStub] = [
    await startRegistryStub([{ path: "/widgets", status: 404 }]),
    await startRegistryStub([
      { path: "/pypi/widgets-pypi/1.0.0/json", status: 404 },
      { path: "/pypi/widgets-pypi/json", status: 404 },
    ]),
    await startRegistryStub([
      { path: "/api/v1/crates/widgets-crate/1.0.0", status: 404, raw: JSON.stringify({ errors: [{ detail: "crate `widgets-crate` does not have a version `1.0.0`" }] }) },
      { path: "/api/v1/crates/widgets-crate", status: 404, raw: JSON.stringify({ errors: [{ detail: "crate `widgets-crate` does not exist" }] }) },
    ]),
    await startRegistryStub([
      { path: "/api/v2/rubygems/widgets-gem/versions/1.0.0.json", status: 404, raw: "This version could not be found." },
      { path: "/api/v1/gems/widgets-gem.json", status: 404, raw: "This rubygem could not be found." },
    ]),
  ];
  for (const s of stubs) openStubs.push(s);
  return stubs;
}

// ---------------------------------------------------------------- fixture

type Fixture = {
  readonly top: string;
  readonly repo: string;
  readonly origin: string;
  readonly cfgPath: string;
  /** Per-run env base: CRATES_IO_URL seam → crates stub in EVERY run; fake
   *  binaries first on PATH; per-fixture npm cache + userconfig; SPAWN_LOG. */
  readonly env: NodeJS.ProcessEnv;
  readonly stubs: [RegistryStub, RegistryStub, RegistryStub, RegistryStub];
  readonly spawnLogPath: string;
};

function borderYaml(o: { readonly registry?: string; readonly pypi?: string; readonly crates?: boolean; readonly rubygemsHost?: string }): string {
  const lines = [
    "version: 1",
    "targets:",
    "  git:",
    "    remotes:",
    "      - name: origin",
    "        url: file://REPLACE_WITH_BARE",
    ...(o.registry === undefined ? [] : ["  npm:", `    registry: ${o.registry}`]),
    ...(o.pypi === undefined ? [] : ["  pypi:", `    repository: ${o.pypi}`]),
    ...(o.crates === true ? ["  crates: {}"] : []),
    ...(o.rubygemsHost === undefined ? [] : ["  rubygems:", `    host: ${o.rubygemsHost}`]),
    "rules:",
    "  authors:",
    "    emails: [wiki@sumteclab.com]",
    "    names: [Wiki.js]",
    "  hosts: []",
    "  ips: []",
    "  pathPatterns: []",
    "engines:",
    "  require: [gitleaks, secretlint]",
    "  trufflehog: false",
    "",
  ];
  return lines.join("\n");
}

/** Write the fake publish binaries. Each logs `NAME:ARGV1` to $SPAWN_LOG and
 *  forwards everything the CHECK stage actually needs to the real tool:
 *    npm    view/pack → real npm; publish → log + FAKE_NPM_PUBLISH_EXIT(0)
 *    cargo  --version/package → real cargo (the repackage gate MUST produce
 *           byte-identical .crate bytes or the digest-assert fails the leg);
 *           publish → log + FAKE_CARGO_PUBLISH_EXIT(0)
 *    gem    --version/build → real gem; push → log + exit 0
 *    twine  --version gate → exit 0; upload → log + exit 0
 */
function writeFakes(dir: string): void {
  mkdirSync(dir, { recursive: true });
  const npm = join(dir, "npm");
  writeFileSync(npm, `#!/bin/sh\nif [ "$1" = "publish" ]; then echo "npm:publish" >> "$SPAWN_LOG"; exit "\${FAKE_NPM_PUBLISH_EXIT:-0}"; fi\nexec ${REAL_NPM} "$@"\n`);
  const cargo = join(dir, "cargo");
  writeFileSync(cargo, `#!/bin/sh\necho "cargo:$1" >> "$SPAWN_LOG"\ncase "$1" in\n  --version|package) exec ${REAL_CARGO} "$@";;\n  publish) exit "\${FAKE_CARGO_PUBLISH_EXIT:-0}";;\n  *) exit 0;;\nesac\n`);
  const gem = join(dir, "gem");
  writeFileSync(gem, `#!/bin/sh\necho "gem:$1" >> "$SPAWN_LOG"\ncase "$1" in\n  --version|build) exec ${REAL_GEM} "$@";;\n  *) exit 0;;\nesac\n`);
  const twine = join(dir, "twine");
  writeFileSync(twine, `#!/bin/sh\necho "twine:$1" >> "$SPAWN_LOG"\nexit 0\n`);
  for (const p of [npm, cargo, gem, twine]) chmodSync(p, 0o755);
}

/** The full multi-platform fixture repo. Manifest names are per-channel
 *  unique so every leg is independently probeable: widgets (npm 1.0.0),
 *  widgets-pypi (pypi 1.0.0), widgets-crate (crates 1.0.0), widgets-gem
 *  (rubygems 1.0.0). All manifests committed in ONE commit — every sdist
 *  entry must be git-tracked or whitelisted or the pypi manifest audit
 *  fails the check (G17 class). */
async function buildFixture(top: string, o: { readonly targets: ReadonlyArray<"npm" | "pypi" | "crates" | "rubygems">; readonly leakyGem?: boolean }): Promise<Fixture> {
  const stubs = await fourStubs();
  const [npmStub, pypiStub, cratesStub, rubygemsStub] = stubs;
  const repo = join(top, "repo");
  mkdirSync(repo, { recursive: true });
  gitInit(repo);
  writeRel(repo, ".gitignore", ".border/\nnode_modules/\nbuild/\ntarget/\nsrc/*.egg-info/\n__pycache__/\n");
  writeRel(repo, "package.json", JSON.stringify({ name: "widgets", version: "1.0.0", description: "border C5 integration fixture", author: "Wiki.js <wiki@sumteclab.com>" }) + "\n");
  writeRel(repo, "README.md", "# widgets\n\nC5 multi-target fixture.\n");
  writeRel(
    repo,
    "pyproject.toml",
    `[build-system]
requires = ["setuptools==78.1.1"]
build-backend = "setuptools.build_meta"

[project]
name = "widgets-pypi"
version = "1.0.0"
readme = "README.md"
requires-python = ">=3.10"

[tool.setuptools.packages.find]
where = ["src"]
`,
  );
  writeRel(repo, "src/widgets_pypi/__init__.py", '"""Widgets PyPI fixture package."""\n');
  writeRel(repo, "Cargo.toml", `[package]\nname = "widgets-crate"\nversion = "1.0.0"\nedition = "2021"\n`);
  writeRel(repo, "src/lib.rs", "pub fn answer() -> u32 { 42 }\n");
  writeRel(
    repo,
    "widgets-gem.gemspec",
    `Gem::Specification.new do |s|\n  s.name = "widgets-gem"\n  s.version = "1.0.0"\n  s.summary = "border C5 rubygems fixture"\n  s.authors = ["border test"]\n  s.files = ["lib/answer.rb"]\nend\n`,
  );
  writeRel(repo, "lib/answer.rb", "module Answer\n  def self.answer = 42\nend\n");
  if (o.leakyGem === true) {
    // randAwsPair OK: the flagged half is the pinned LEAK_KEY_ID literal; pair.secret only guarantees a fresh unique value (dedupe)
    const pair = randAwsPair();
    writeRel(repo, "lib/leaky.rb", `# leaked credentials\ndef leaked = { key: "${LEAK_KEY_ID}", secret: "${pair.secret}" }\n`);
    const gemspec = readFileSync(join(repo, "widgets-gem.gemspec"), "utf8");
    writeRel(repo, "widgets-gem.gemspec", gemspec.replace('"lib/answer.rb"', '"lib/answer.rb", "lib/leaky.rb"'));
  }
  gitAddCommit(repo, "init");

  const origin = join(top, "origin.git");
  gitIn(top, ["init", "-q", "--bare", "-b", "main", origin]);

  const fakesDir = join(top, "fakes");
  const spawnLogPath = join(top, "spawn.log");
  writeFakes(fakesDir);

  const cfgPath = join(top, "border.yaml");
  const yaml = borderYaml({
    ...(o.targets.includes("npm") ? { registry: `${npmStub.url}/` } : {}),
    ...(o.targets.includes("pypi") ? { pypi: `${pypiStub.url}/` } : {}),
    ...(o.targets.includes("crates") ? { crates: true } : {}),
    ...(o.targets.includes("rubygems") ? { rubygemsHost: rubygemsStub.url } : {}),
  }).replace("file://REPLACE_WITH_BARE", `file://${origin}`);
  writeFileSync(cfgPath, yaml, "utf8");

  const env: NodeJS.ProcessEnv = {
    CRATES_IO_URL: cratesStub.url,
    SPAWN_LOG: spawnLogPath,
    TWINE_BIN: join(fakesDir, "twine"),
    PATH: `${fakesDir}:${process.env.PATH ?? ""}`,
  };
  if (o.targets.includes("npm")) {
    const cache = join(top, "npm-cache");
    mkdirSync(cache, { recursive: true });
    const rc = join(top, "userconfig.npmrc");
    writeFileSync(rc, `//127.0.0.1:${String(npmStub.port)}/:_authToken=test-only-token-border-never-reads-this\n`, "utf8");
    env.npm_config_cache = cache;
    env.npm_config_userconfig = rc;
  }
  return { top, repo, origin, cfgPath, env, stubs, spawnLogPath };
}

// ---------------------------------------------------------------- helpers

function resetSpawnLog(f: Fixture): void {
  writeFileSync(f.spawnLogPath, "", "utf8");
}

function spawnLines(f: Fixture): string[] {
  return readFileSync(f.spawnLogPath, "utf8").split("\n").filter((l) => l !== "");
}

async function checkForce(f: Fixture): Promise<RunResult> {
  return runBorder(["check", "--force", "--config", f.cfgPath], f);
}

function pushTargets(f: Fixture): PushRecord[] {
  return pushRecords(readLedger(f.repo).records);
}

const RECORD_TARGET_ORDER = ["crates", "git:origin", "npm", "pypi", "rubygems"] as const;

// ================================================================ C5-1

test("C5-1 subset discipline: a git-only PASS authorizes NO publish leg; a full PASS authorizes no crates-only push (fingerprint effectiveTargets scope binding)", async () => {
  const f = await buildFixture(scratch("c5-1"), { targets: ["npm", "pypi", "crates", "rubygems"] });

  // git-only certification: check --force --targets git (zero registry
  // probes — nothing but the git leg in effectiveTargets).
  const chk = await checkForce(f);
  assert.equal(chk.code, EXIT_PASS, dump(chk));
  const pass = readLedger(f.repo).records.filter((r): r is CheckRecord => r.t === "check" && r.effectiveTargets.length === 1);
  assert.equal(pass.length, 1, "exactly one check record, git-scoped");
  assert.deepEqual(pass[0]?.effectiveTargets, ["git"], "the PASS is git-only");
  assert.ok(readLedger(f.repo).records.length >= 1);

  // full push under the git-only PASS: every leg UNCHECKED ⇒ refusal, no
  // publish, no records. The refusal message class comes verbatim from
  // src/commands/push.ts.
  resetSpawnLog(f);
  const r = await runBorder(["push", "--yes", "--config", f.cfgPath], f);
  assert.equal(r.code, EXIT_BLOCKED, dump(r));
  assert.ok(r.err.some((l) => l.includes("border: push --yes refused — 5 BLOCKED target(s) above; nothing was pushed")), `refusal line expected:\n${r.err.join("\n")}`);
  for (const id of ["crates", "rubygems", "npm", "pypi"]) {
    assert.ok(r.out.some((l) => l.includes(`unchecked: no PASS record for '${id}' under the current fingerprint key`)), `unchecked reason for ${id}:\n${r.out.join("\n")}`);
  }
  assert.deepEqual(spawnLines(f), [], "zero publish spawns — the git-only PASS authorizes no registry leg");
  assert.deepEqual(pushTargets(f), [], "zero push-records");

  // reverse direction: a FULL 5-target PASS must not authorize a crates-only
  // push either (effectiveTargets participates in the fingerprint key).
  const f2 = await buildFixture(scratch("c5-1b"), { targets: ["npm", "pypi", "crates", "rubygems"] });
  assert.equal((await checkForce(f2)).code, EXIT_PASS);
  resetSpawnLog(f2);
  const r2 = await runBorder(["push", "--yes", "--targets", "crates", "--config", f2.cfgPath], f2);
  assert.equal(r2.code, EXIT_BLOCKED, dump(r2));
  assert.ok(r2.err.some((l) => l.includes("border: push --yes refused — 1 BLOCKED target(s) above; nothing was pushed")), `refusal line expected:\n${r2.err.join("\n")}`);
  assert.ok(r2.out.some((l) => l.includes("unchecked: no PASS record for 'crates'")), `crates leg shown BLOCKED:\n${r2.out.join("\n")}`);
  assert.deepEqual(spawnLines(f2), [], "crates-only push under a full PASS spawns nothing");
  assert.deepEqual(pushTargets(f2), [], "zero push-records");
});

// ================================================================ C5-2

test("C5-2 all-BLOCKED: --yes with every leg blocked (no check at all) ⇒ exit 1, zero publishes, zero push-records", async () => {
  const f = await buildFixture(scratch("c5-2"), { targets: ["npm", "pypi", "crates", "rubygems"] });
  resetSpawnLog(f);
  const r = await runBorder(["push", "--yes", "--config", f.cfgPath], f);
  assert.equal(r.code, EXIT_BLOCKED, dump(r));
  assert.ok(r.err.some((l) => l.includes("border: push --yes refused — 5 BLOCKED target(s) above; nothing was pushed")), `refusal line expected:\n${r.err.join("\n")}`);
  assert.ok(r.out.some((l) => l.includes("git:origin  BLOCKED")), "git leg surfaced as BLOCKED");
  assert.ok(r.out.some((l) => l.includes("crates  BLOCKED")) && r.out.some((l) => l.includes("rubygems  BLOCKED")), "new-channel legs surfaced as BLOCKED");
  assert.deepEqual(spawnLines(f), [], "zero publish spawns");
  assert.deepEqual(pushTargets(f), [], "zero push-records");
});

// ================================================================ C5-3

test("C5-3 PARTIAL: crates publish fails (fake cargo exit 7) ⇒ rubygems NEVER spawned, earlier legs stay recorded, exit 1 with the failure-message shape", async () => {
  const f = await buildFixture(scratch("c5-3"), { targets: ["npm", "pypi", "crates", "rubygems"] });
  assert.equal((await checkForce(f)).code, EXIT_PASS);
  resetSpawnLog(f);
  const r = await runBorder(["push", "--yes", "--config", f.cfgPath], f, { FAKE_CARGO_PUBLISH_EXIT: "7" });
  assert.equal(r.code, EXIT_BLOCKED, dump(r));
  // the exact failure message class (src/channels/crates.ts failureMessage)
  assert.ok(
    r.err.some((l) => l.includes("cargo publish failed for .border/dist/widgets-crate-1.0.0.crate (exit 7) — no retry loop; inspect the registry state before running again")),
    `crates failure message expected:\n${r.err.join("\n")}`,
  );
  // earlier legs ARE recorded (git + npm + pypi), later legs never ran
  assert.ok(r.out.some((l) => l.includes("pushed git:origin")), "git leg landed");
  assert.ok(r.out.some((l) => l.includes("published widgets@1.0.0; push-record appended")), "npm leg landed");
  assert.ok(r.out.some((l) => l.includes("published widgets-pypi@1.0.0; push-record appended")), "pypi leg landed");
  assert.ok(r.out.some((l) => l.includes(PUBLISH_WARNING)), "the immutability warning precedes the first publish spawn");
  const lines = spawnLines(f);
  assert.ok(!lines.some((l) => l.startsWith("gem:")), `rubygems must NEVER spawn after a crates failure, got ${JSON.stringify(lines)}`);
  const records = pushTargets(f);
  assert.deepEqual([...records].map((x) => x.target).sort(), ["git:origin", "npm", "pypi"], "ledger carries exactly the landed legs");
  // order 3-before-4 at the atomic level: the crates publish DID spawn (exit 7)
  assert.ok(lines.some((l) => l === "cargo:publish"), `crates publish spawn logged:\n${JSON.stringify(lines)}`);
  assert.ok(lines.some((l) => l === "cargo:package"), "the pre-publish repackage gate ran (digest-assert)");
});

// ================================================================ C5-4

test("C5-4 ordering: publish legs execute in descriptor order git→npm→pypi→crates→rubygems (exact spawn sequence), all five push-records under ONE key", async () => {
  const f = await buildFixture(scratch("c5-4"), { targets: ["npm", "pypi", "crates", "rubygems"] });
  const chk = await checkForce(f);
  assert.equal(chk.code, EXIT_PASS, dump(chk));
  const key = readLedger(f.repo).records.filter((r): r is CheckRecord => r.t === "check" && r.verdict === "PASS").at(-1)?.key;
  assert.ok(key !== undefined, "PASS record carries the fingerprint key");
  resetSpawnLog(f);
  const r = await runBorder(["push", "--yes", "--config", f.cfgPath], f);
  assert.equal(r.code, EXIT_PASS, dump(r));

  // git leg first (bare remote moved; success line printed)
  const head = gitRevParseHead(f.repo);
  assert.equal(lsRemote(f.origin, "refs/heads/main"), head, "git remote sha moved");
  assert.ok(r.out.some((l) => l.includes("pushed git:origin")), `git success line:\n${r.out.join("\n")}`);

  // registry legs: the SPAWN_LOG sequence is the exact ordered trace
  assert.deepEqual(spawnLines(f), ["npm:publish", "twine:upload", "cargo:package", "cargo:publish", "gem:push"], "publish spawns in descriptor .order (git 0 → npm 1 → pypi 2 → crates 3 → rubygems 4); the repackage gate precedes the crates spawn");

  // ledger round-trip: five records, one key, new confirmedVia values
  const records = pushTargets(f);
  assert.deepEqual([...records].map((x) => x.target).sort(), [...RECORD_TARGET_ORDER], "one push-record per leg");
  const byTarget = new Map(records.map((x) => [x.target, x]));
  assert.equal(byTarget.get("git:origin")?.confirmedVia, "ls-remote");
  assert.equal(byTarget.get("npm")?.confirmedVia, "npm-view");
  assert.equal(byTarget.get("pypi")?.confirmedVia, "pypi-json");
  assert.equal(byTarget.get("crates")?.confirmedVia, "crates-json");
  assert.equal(byTarget.get("rubygems")?.confirmedVia, "rubygems-json");
  assert.equal(byTarget.get("crates")?.url, CRATES_IO_DEFAULT_URL, "the crates record keeps the DEFAULT url — the probe seam can never rewrite the recorded destination");
  for (const rec of records) assert.equal(rec.key, key, "state.key discipline: every push-record carries the PASS fingerprint key");
});

// ================================================================ C5-5

test("C5-5 ledger round-trip: new confirmedVia values re-parse through the STRICT parser; a pre-C3-era ledger parses verbatim and the newer binary still authorizes on it", async () => {
  // (a) strict-parser round trip over the live five-leg ledger
  const f = await buildFixture(scratch("c5-5a"), { targets: ["npm", "pypi", "crates", "rubygems"] });
  assert.equal((await checkForce(f)).code, EXIT_PASS);
  resetSpawnLog(f);
  assert.equal((await runBorder(["push", "--yes", "--config", f.cfgPath], f)).code, EXIT_PASS);
  const ledgerPath = join(f.repo, ".border", LEDGER_FILE);
  for (const line of readFileSync(ledgerPath, "utf8").split("\n").filter((l) => l !== "")) {
    parseLedgerRecord(JSON.parse(line)); // throws on any strict-parser rejection
  }
  const { warnings } = readLedger(f.repo);
  assert.deepEqual(warnings, [], "the live five-leg ledger parses with ZERO warnings");

  // (b) pre-C3-era ledger: the OLD heritric world — git+npm+pypi only. A full
  //     check+push produces a ledger whose push records carry ONLY the
  //     ls-remote/npm-view/pypi-json confirmedVia values; re-running push
  //     must authorize from those records and stay exit-0.
  const legacy = await buildFixture(scratch("c5-5b"), { targets: ["npm", "pypi"] });
  assert.equal((await checkForce(legacy)).code, EXIT_PASS);
  resetSpawnLog(legacy);
  assert.equal((await runBorder(["push", "--yes", "--config", legacy.cfgPath], legacy)).code, EXIT_PASS);
  const legacyRecs = pushTargets(legacy);
  assert.deepEqual([...legacyRecs].map((x) => x.target).sort(), ["git:origin", "npm", "pypi"]);
  assert.deepEqual([...legacyRecs].map((x) => x.confirmedVia).sort(), ["ls-remote", "npm-view", "pypi-json"], "no crates-json/rubygems-json exists in the pre-C3-era ledger");
  const legacyRead = readLedger(legacy.repo);
  assert.deepEqual(legacyRead.warnings, [], "the pre-C3-era ledger parses VERBATIM — zero warnings");
  resetSpawnLog(legacy);
  const again = await runBorder(["push", "--yes", "--config", legacy.cfgPath], legacy);
  assert.equal(again.code, EXIT_PASS, dump(again));

  // (c) a HAND-WRITTEN pre-C3-era ledger (an older binary's exact output
  //     shape: PASS + only legacy confirmedVia push records) must re-parse
  //     verbatim through the strict parser, line by line.
  const hand = await buildFixture(scratch("c5-5c"), { targets: ["npm", "pypi"] });
  assert.equal((await checkForce(hand)).code, EXIT_PASS);
  const handPass = readLedger(hand.repo).records.filter((r): r is CheckRecord => r.t === "check" && r.verdict === "PASS").at(-1);
  assert.ok(handPass !== undefined);
  const headSha = gitRevParseHead(hand.repo);
  const legacyPushRecords = [
    { t: "push", key: handPass.key, target: "git:origin", remoteName: "origin", url: `file://${hand.origin}`, localSha: headSha, remoteSha: headSha, confirmedVia: "ls-remote", ts: new Date().toISOString() },
    { t: "push", key: handPass.key, target: "npm", remoteName: "npm", url: hand.stubs[0].url, localSha: headSha, version: "widgets@1.0.0", confirmedVia: "npm-view", ts: new Date().toISOString() },
    { t: "push", key: handPass.key, target: "pypi", remoteName: "pypi", url: hand.stubs[1].url, localSha: headSha, version: "widgets-pypi@1.0.0", confirmedVia: "pypi-json", ts: new Date().toISOString() },
  ];
  const lines = readFileSync(join(hand.repo, ".border", LEDGER_FILE), "utf8").split("\n").filter((l) => l !== "");
  assert.equal(lines.length, 1, "the fresh ledger holds just the PASS line");
  const oldEra = [...lines, ...legacyPushRecords.map((x) => JSON.stringify(x))].join("\n");
  writeFileSync(join(hand.repo, ".border", LEDGER_FILE), `${oldEra}\n`, "utf8");
  const legacyRead2 = readLedger(hand.repo);
  assert.deepEqual(legacyRead2.warnings, [], "hand-written pre-C3-era ledger parses verbatim with ZERO warnings");
  for (const line of oldEra.split("\n")) parseLedgerRecord(JSON.parse(line)); // throws on any strict-parser rejection
  // and the newer binary STILL authorizes the same flows on it
  const st = await runBorder(["status", "--config", hand.cfgPath], hand);
  assert.equal(st.code, EXIT_PASS, dump(st));
  assert.ok(st.out.some((l) => l.includes("all effective targets pushed for key")), `status summarized the old-era ledger as fully pushed:\n${st.out.join("\n")}`);
});

// ================================================================ C5-6

test("C5-6 cache-invalidation matrix: adding/removing `crates: {}` changes the fingerprint key ⇒ the old PASS authorizes NO publish leg", async () => {
  // add direction: PASS under the 4-leg config, then crates joins the config
  const f = await buildFixture(scratch("c5-6a"), { targets: ["npm", "pypi", "rubygems"] });
  assert.equal((await checkForce(f)).code, EXIT_PASS);
  const yamlWithCrates = readFileSync(f.cfgPath, "utf8").replace("  rubygems:", "  crates: {}\n  rubygems:");
  writeFileSync(f.cfgPath, yamlWithCrates, "utf8");
  resetSpawnLog(f);
  const r = await runBorder(["push", "--yes", "--config", f.cfgPath], f);
  assert.equal(r.code, EXIT_BLOCKED, dump(r));
  assert.ok(r.err.some((l) => l.includes("border: push --yes refused — 5 BLOCKED target(s) above; nothing was pushed")), `refusal line expected:\n${r.err.join("\n")}`);
  assert.ok(r.out.some((l) => l.includes("unchecked: no PASS record for 'crates'")), `crates shown BLOCKED:\n${r.out.join("\n")}`);
  assert.deepEqual(spawnLines(f), [], "the old PASS cannot authorize ANY publish leg — zero spawns");
  assert.deepEqual(pushTargets(f), [], "zero push-records");

  // remove direction: PASS under the 5-leg config, then crates leaves it
  const f2 = await buildFixture(scratch("c5-6b"), { targets: ["npm", "pypi", "crates", "rubygems"] });
  assert.equal((await checkForce(f2)).code, EXIT_PASS);
  const yamlWithoutCrates = readFileSync(f2.cfgPath, "utf8").replace("  crates: {}\n", "");
  writeFileSync(f2.cfgPath, yamlWithoutCrates, "utf8");
  resetSpawnLog(f2);
  const r2 = await runBorder(["push", "--yes", "--config", f2.cfgPath], f2);
  assert.equal(r2.code, EXIT_BLOCKED, dump(r2));
  assert.ok(r2.err.some((l) => l.includes("border: push --yes refused — 4 BLOCKED target(s) above; nothing was pushed")), `refusal line expected:\n${r2.err.join("\n")}`);
  assert.ok(r2.out.some((l) => l.includes("unchecked: no PASS record for 'rubygems'")), "the surviving legs' gate holes are honest");
  assert.deepEqual(spawnLines(f2), [], "zero spawns after the leg was dropped");
  assert.deepEqual(pushTargets(f2), [], "zero push-records");
});

// ================================================================ C5-7

test("C5-7 border status lists every leg: PENDING rows pre-push, PUSHED rows with per-leg confirmedVia details post-push", async () => {
  const f = await buildFixture(scratch("c5-7"), { targets: ["npm", "pypi", "crates", "rubygems"] });
  assert.equal((await checkForce(f)).code, EXIT_PASS);
  const before = await runBorder(["status", "--config", f.cfgPath], f);
  assert.equal(before.code, EXIT_PASS, dump(before));
  assert.ok(before.out.some((l) => /^border status — key [0-9a-f]{8} — verdict PASS/.test(l)), `status header:\n${before.out.join("\n")}`);
  for (const row of ["crates", "git:origin", "npm", "pypi", "rubygems"]) {
    assert.ok(before.out.some((l) => l.startsWith(`${row.padEnd(8)} pending`)), `pre-push row for ${row}:\n${before.out.join("\n")}`);
  }
  assert.ok(before.out.some((l) => l.includes("pending targets: crates, git:origin, npm, pypi, rubygems — run `border push` to publish the PASS")), `pending summary:\n${before.out.join("\n")}`);

  resetSpawnLog(f);
  const push = await runBorder(["push", "--yes", "--config", f.cfgPath], f);
  assert.equal(push.code, EXIT_PASS, dump(push));

  const after = await runBorder(["status", "--config", f.cfgPath], f);
  assert.equal(after.code, EXIT_PASS, dump(after));
  for (const row of ["crates", "git:origin", "npm", "pypi", "rubygems"]) {
    assert.ok(after.out.some((l) => l.startsWith(`${row.padEnd(8)} pushed`)), `post-push row for ${row}:\n${after.out.join("\n")}`);
  }
  assert.ok(after.out.some((l) => l.includes("crates-json")), `crates detail carries its confirmedVia:\n${after.out.join("\n")}`);
  assert.ok(after.out.some((l) => l.includes("rubygems-json")), `rubygems detail carries its confirmedVia:\n${after.out.join("\n")}`);
  assert.ok(after.out.some((l) => l.includes("all effective targets pushed for key")), `pushed summary:\n${after.out.join("\n")}`);
});

// ================================================================ C5-8

test("C5-8 honesty through a NEW channel end-to-end: planted AKIAI4Q3... + 40-char companion in a rubygems-packaged file ⇒ check exit 1 ⇒ --yes push refused", async () => {
  const f = await buildFixture(scratch("c5-8"), { targets: ["rubygems"], leakyGem: true });
  // the leak is in a gem-packaged file, committed at HEAD
  const chk = await checkForce(f);
  assert.equal(chk.code, EXIT_BLOCKED, dump(chk));
  const failRecord = readLedger(f.repo).records.filter((r) => r.t === "check").at(-1);
  assert.equal(failRecord?.verdict, "FAIL", "the check record is FAIL — the planted pair survives the gem build");
  assert.ok(failRecord?.artifacts != null, "the FAIL record still lists the staged artifact digests");

  resetSpawnLog(f);
  const push = await runBorder(["push", "--yes", "--config", f.cfgPath], f);
  assert.equal(push.code, EXIT_BLOCKED, dump(push));
  assert.ok(push.err.some((l) => l.includes("border: push --yes refused — 2 BLOCKED target(s) above; nothing was pushed")), `refusal line expected:\n${push.err.join("\n")}`);
  assert.deepEqual(spawnLines(f), [], "zero publish spawns — the FAIL record blocks before any spawn");
  assert.deepEqual(pushTargets(f), [], "zero push-records");
  // no raw secret survives in border's own state (G23)
  const ledgerText = readFileSync(join(f.repo, ".border", LEDGER_FILE), "utf8");
  assert.ok(!ledgerText.includes(LEAK_KEY_ID), "the ledger must never carry the planted literal");
});