// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 17
//
// Same-bytes publish-executor acceptance suite (plan AC1–AC5):
//   AC1  VERDACCIO E2E npm leg — the REAL pinned devDependency verdaccio 6
//        (node_modules/.bin/verdaccio) on an ephemeral loopback port; dry-run
//        prints the exact `npm publish` line with ZERO registry hits; --yes
//        publishes, the version becomes visible via the todo-13 probe, a
//        t:"push" record lands in the ledger, and the immutability WARNING is
//        printed before the spawn.
//        ANONYMITY CHOICE: verdaccio runs with NO auth provider and
//        `access/publish: $all`. npm ≥ 10 refuses client-side to publish with
//        zero credentials (ENEEDAUTH fires in publish.js before any PUT), so
//        the TEST points npm at an isolated throwaway userconfig holding a
//        fake token (npm_config_userconfig env, test scope only). Border
//        product code never constructs, reads, or forwards a token (G28) —
//        the spawn only inherits env; the grep-guard test at the bottom pins
//        that the executor sources contain no credential vocabulary.
//   AC2  one tampered byte in .border/dist/<tgz> after the PASSED check ⇒
//        exit 2 `artifact changed since check`, verdaccio hit count unchanged.
//   AC3  double-publish: second --yes attempt ⇒ version-exists re-probe hard
//        FAILs (exit 1, bump message); zero new PUT lines in the server log.
//   AC4  PyPI: full twine-exec e2e NOT covered (no local PyPI index in
//        devDeps — documented gap). Dry-run line, re-hash/tamper, twine-absent
//        (TWINE_BIN seam) and version-exists re-probe all run against the
//        todo-13 loopback registry-stub (404/200 JSON fixtures).
//   AC5  missing / key-mismatched / superseded-by-FAIL record ⇒ exit 1
//        `run border check first`.
// Cleanup contract: every verdaccio child is SIGTERM'd and its port polled
// free; fixture dirs live under mkdtemp roots removed in after(). No blind
// sleeps — readiness is a bounded GET-poll, teardown a bounded connect-poll.
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, openSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { createConnection, createServer } from "node:net";
import { basename, join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, test } from "node:test";

import type { BorderConfig } from "../src/config.ts";
import type { ReportCounts } from "../src/findings.ts";
import { appendRecord, computeFingerprint, readLedger, type CheckRecord, type LedgerArtifact, type PushRecord } from "../src/ledger.ts";
import { stableStringify } from "../src/check/rulesHash.ts";
import { runRegistryProbes, VERSION_EXISTS_RULE } from "../src/registry.ts";
import { PUBLISH_WARNING, runNpmPublish } from "../src/push/npm.ts";
import { runPypiPublish } from "../src/push/pypi.ts";
import { buildPypiArtifacts } from "../src/artifacts/pypi.ts";
import { gitAddCommit, gitInit, gitRevParseHead, makeFixtureDir, removeDir, writeRel } from "./helpers/fixtures.ts";
import { startRegistryStub, type RegistryStub } from "./helpers/registry-stub.ts";

const HEX64 = "0".repeat(64);
const VERDACCIO_BIN = fileURLToPath(new URL("../node_modules/.bin/verdaccio", import.meta.url));

const fixtureRoots: string[] = [];
const openStubs: RegistryStub[] = [];
const runningVerdaccios: LiveVerdaccio[] = [];

after(async () => {
  for (const v of runningVerdaccios) await v.stop();
  for (const s of openStubs) await s.close();
  for (const d of fixtureRoots) removeDir(d);
});

// ---------------------------------------------------------------- fixtures

function scratchDir(prefix: string): string {
  const dir = makeFixtureDir(prefix);
  fixtureRoots.push(dir);
  return dir;
}

function borderCfg(npmRegistry?: string, pypiRepository?: string): BorderConfig {
  return {
    version: 1,
    targets: {
      git: { remotes: [] },
      ...(npmRegistry === undefined ? {} : { npm: { registry: npmRegistry } }),
      ...(pypiRepository === undefined ? {} : { pypi: { repository: pypiRepository } }),
    },
    rules: { authors: { emails: ["wiki@sumteclab.com"], names: ["Wiki.js"] }, hosts: [], ips: [], pathPatterns: [], maxFileKB: 500 },
    allow: [],
    engines: { require: [], trufflehog: false },
  };
}

function emptyCounts(): ReportCounts {
  return { INFO: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0, total: 0, blocking: 0, warnings: 0 };
}

/** Seed a genuine PASSED ledger record exactly the way todo 10/14 produce
 *  them: the real computeFingerprint key + the todo-14 appendRecord writer. */
async function seedPassRecord(
  repoDir: string,
  cfg: BorderConfig,
  kind: "npm" | "pypi",
  artifacts: readonly LedgerArtifact[] | null,
): Promise<string> {
  const { fp } = await computeFingerprint(repoDir, cfg, stableStringify(cfg), [kind], {});
  const record: CheckRecord = {
    t: "check",
    key: fp.key,
    key8: fp.key.slice(0, 8),
    head: gitRevParseHead(repoDir),
    dirtyDigest: HEX64,
    refSetHash: HEX64,
    exposureSet: [],
    effectiveTargets: [kind],
    rulesHash: HEX64,
    artifacts,
    llm: false,
    verdict: "PASS",
    counts: emptyCounts(),
    reportPath: ".border/runs/x/report.json",
    degraded: false,
    ts: new Date().toISOString(),
  };
  appendRecord(repoDir, record);
  return fp.key;
}

function appendFailFor(repoDir: string, key: string): void {
  const checks = readLedger(repoDir).records.filter((r): r is CheckRecord => r.t === "check" && r.key === key);
  const latest = checks[checks.length - 1];
  if (latest === undefined) throw new Error("FAIL-append needs an existing PASS for the key");
  appendRecord(repoDir, { ...latest, verdict: "FAIL", ts: new Date().toISOString() });
}

function sha256OfFile(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

/** npm fixture: committed package.json + a REAL `npm pack` tarball recorded
 *  under .border/dist — todo 11's home for packed bytes. */
function npmFixture(prefix: string): { repo: string; cache: string; artifact: LedgerArtifact; distFile: string } {
  const repo = scratchDir(prefix);
  gitInit(repo);
  writeRel(repo, ".gitignore", ".border/\n");
  writeRel(repo, "package.json", JSON.stringify({ name: "widgets", version: "1.0.0", description: "border todo-17 fixture" }) + "\n");
  gitAddCommit(repo, "init");
  const cache = scratchDir(`${prefix}-cache`);
  const distDir = join(repo, ".border", "dist");
  mkdirSync(distDir, { recursive: true }); // npm pack refuses a missing --pack-destination dir
  const packed = spawnSync("npm", ["pack", "--silent", "--pack-destination", distDir], {
    cwd: repo,
    encoding: "utf8",
    env: { ...process.env, npm_config_cache: cache },
  });
  if (packed.status !== 0) throw new Error(`npm pack fixture failed: ${packed.stderr || packed.stdout}`);
  const lines = packed.stdout.trim().split("\n");
  const file = lines[lines.length - 1] as string;
  const distFile = join(distDir, basename(file));
  return { repo, cache, artifact: { file: basename(file), sha256: sha256OfFile(distFile) }, distFile };
}

function tamperOneByte(path: string): void {
  const bytes = readFileSync(path);
  const at = Math.floor(bytes.length / 2);
  bytes[at] = ((bytes[at] ?? 0) ^ 0xff) & 0xff;
  writeFileSync(path, bytes);
}

/** PyPI fixture: committed pyproject + a REAL `python3 -m build` (todo-12
 *  build-once) producing sdist+wheel under .border/dist. */
function pypiFixture(prefix: string): { repo: string; artifacts: readonly LedgerArtifact[]; wheel: string; distDir: string } {
  const repo = scratchDir(prefix);
  gitInit(repo);
  writeRel(repo, ".gitignore", ".border/\n__pycache__/\nbuild/\nsrc/*.egg-info/\n");
  writeRel(
    repo,
    "pyproject.toml",
    `[build-system]
requires = ["setuptools==78.1.1"]
build-backend = "setuptools.build_meta"

[project]
name = "pushdemo"
version = "0.1.0"

[tool.setuptools.packages.find]
where = ["src"]
`,
  );
  writeRel(repo, "src/pushdemo/__init__.py", '"""Docstring only."""\n');
  gitAddCommit(repo, "init");
  const { artifacts, distDir } = buildPypiArtifacts({ repoDir: repo });
  const wheel = artifacts.find((a) => a.kind === "wheel");
  if (wheel === undefined) throw new Error("fixture build produced no wheel");
  return {
    repo,
    artifacts: artifacts.map((a) => ({ file: basename(a.path), sha256: a.sha256 })),
    wheel: wheel.path,
    distDir,
  };
}

async function stubWith(routes: Parameters<typeof startRegistryStub>[0]): Promise<RegistryStub> {
  const s = await startRegistryStub(routes);
  openStubs.push(s);
  return s;
}

// ---------------------------------------------------------------- verdaccio

type LiveVerdaccio = {
  readonly port: number;
  readonly url: string;
  /** verdaccio logs every request as an `http <--` line — the zero-network
   *  assertions count these before/after the tested call. */
  requestCount(): number;
  /** count of `PUT /widgets` publish attempts seen by the server. */
  putCount(): number;
  stop(): Promise<void>;
};

function freePort(): Promise<number> {
  return new Promise<number>((ok, err) => {
    const s = createServer();
    s.on("error", err);
    s.listen(0, "127.0.0.1", () => {
      const addr = s.address();
      const port = typeof addr === "object" && addr !== null ? addr.port : -1;
      s.close(() => (port > 0 ? ok(port) : err(new Error("ephemeral port probe failed"))));
    });
  });
}

function verdaccioConfig(dir: string, port: number): string {
  // `$all` groups + NO auth provider ⇒ fully anonymous server: it never
  // validates (nor even assigns meaning to) the test-scope fake token.
  const yaml = [
    `storage: ${join(dir, "storage")}`,
    `listen: 127.0.0.1:${String(port)}`,
    "log: { type: stdout, level: http }",
    "uplinks: {}",
    "packages:",
    "  '**':",
    "    access: $all",
    "    publish: $all",
    "    proxy: $all",
    "",
  ].join("\n");
  const path = join(dir, "config.yaml");
  writeFileSync(path, yaml, "utf8");
  return path;
}

async function startVerdaccio(): Promise<LiveVerdaccio> {
  const dir = scratchDir("v17-server");
  const logPath = join(dir, "verdaccio.log");
  const port = await freePort();
  const cfgPath = verdaccioConfig(dir, port);
  const fd = openSync(logPath, "a");
  const child = spawn(VERDACCIO_BIN, ["--config", cfgPath], { stdio: ["ignore", fd, fd] });
  const url = `http://127.0.0.1:${String(port)}`;
  let spawnErr: Error | null = null;
  child.on("error", (e) => {
    spawnErr = e;
  });
  const readyDeadline = Date.now() + 20_000;
  for (;;) {
    if (spawnErr !== null) throw spawnErr;
    if (child.exitCode !== null) {
      throw new Error(`verdaccio exited ${String(child.exitCode)}: ${readFileSync(logPath, "utf8").slice(-400)}`);
    }
    try {
      // ANY HTTP answer (even the 404 for an unpublished name) proves the
      // listener is accepting requests — no version-specific health route needed.
      const res = await fetch(`${url}/widgets`, { signal: AbortSignal.timeout(500) });
      void res;
      break;
    } catch {
      if (Date.now() > readyDeadline) throw new Error(`verdaccio not ready in 20s: ${readFileSync(logPath, "utf8").slice(-400)}`);
      await new Promise((r) => setTimeout(r, 50));
    }
  }
  const logLines = (): string[] => readFileSync(logPath, "utf8").split("\n");
  let stopped = false;
  return {
    port,
    url,
    requestCount: () => logLines().filter((l) => l.includes("http <--")).length,
    // one "requested 'PUT'" info line per publish attempt (http lines repeat)
    putCount: () => logLines().filter((l) => l.includes("requested 'PUT")).length,
    stop: async () => {
      if (stopped) return;
      stopped = true;
      if (child.exitCode === null) child.kill("SIGTERM");
      const exitDeadline = Date.now() + 10_000;
      while (child.exitCode === null && Date.now() < exitDeadline) await new Promise((r) => setTimeout(r, 50));
      const releaseDeadline = Date.now() + 10_000;
      for (;;) {
        if (await portReleased(port)) break;
        if (Date.now() > releaseDeadline) throw new Error(`verdaccio port ${String(port)} never released`);
        await new Promise((r) => setTimeout(r, 50));
      }
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

function portReleased(port: number): Promise<boolean> {
  return new Promise<boolean>((ok) => {
    const s = createConnection({ host: "127.0.0.1", port });
    const done = (released: boolean): void => {
      s.destroy();
      ok(released);
    };
    s.setTimeout(150, () => done(false));
    s.on("connect", () => done(false));
    s.on("error", () => done(true));
  });
}

/** TEST-ONLY credentials seam (see file header): the fake token lives ONLY in
 *  this throwaway npmrc + test-scope env. G28: border's argv/config/ledger and
 *  executor sources never carry or construct credential material. */
function testNpmEnv(cache: string, port: number): NodeJS.ProcessEnv {
  const rc = join(cache, "userconfig.npmrc");
  writeFileSync(rc, `//127.0.0.1:${String(port)}/:_authToken=test-only-token-border-never-reads-this\n`, "utf8");
  return { ...process.env, npm_config_cache: cache, npm_config_userconfig: rc };
}

/** verdaccio's log stream flushes asynchronously: request lines can land in the
 *  log file a beat AFTER the client-side call resolved. Poll with a deadline
 *  (never a bare sleep) before asserting on positive hit counts. */
async function waitUntil(pred: () => boolean, timeoutMs = 5_000): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (pred()) return true;
    if (Date.now() > deadline) return false;
    await new Promise((r) => setTimeout(r, 50));
  }
}

type Collected = { readonly lines: string[]; readonly write: (l: string) => void };
function collect(): Collected {
  const lines: string[] = [];
  return { lines, write: (l: string) => lines.push(l) };
}

function expectPushRecord(repo: string, target: string): PushRecord {
  const push = readLedger(repo).records.filter((r): r is PushRecord => r.t === "push" && r.target === target);
  const rec = push[push.length - 1];
  assert.ok(rec !== undefined, `expected a t:"push" record for ${target}`);
  return rec;
}

// ---------------------------------------------------------------- AC1 — npm E2E (verdaccio)

test("AC1 npm E2E: dry-run prints exact command with ZERO verdaccio hits; --yes publishes with warning-before-spawn, visible version, push-record", async () => {
  const v = await startVerdaccio();
  runningVerdaccios.push(v);
  const { repo, cache, artifact } = npmFixture("v17-ac1");
  const cfg = borderCfg(`${v.url}/`);
  const key = await seedPassRecord(repo, cfg, "npm", [artifact]);
  const env = testNpmEnv(cache, v.port);
  const baseHits = v.requestCount();

  const dry = collect();
  const dryExit = await runNpmPublish({ repoDir: repo, cfg, key, yes: false, env, out: dry.write, err: dry.write });
  assert.equal(dryExit, 0, "dry-run exits 0");
  assert.deepEqual(
    dry.lines,
    [`npm publish .border/dist/${artifact.file} --registry ${v.url}/`],
    "dry-run prints the exact publish command, nothing else",
  );
  assert.equal(v.requestCount(), baseHits, "AC1: dry-run made ZERO registry hits");

  const pub = collect();
  const pubExit = await runNpmPublish({ repoDir: repo, cfg, key, yes: true, env, out: pub.write, err: pub.write });
  assert.equal(pubExit, 0, "--yes publish exits 0");
  assert.ok(pub.lines.includes(PUBLISH_WARNING), `immutability WARNING must be printed before spawn: ${JSON.stringify(pub.lines)}`);
  assert.ok(
    await waitUntil(() => v.requestCount() > baseHits),
    "--yes path did contact the registry (probe + PUT)",
  );

  const probe = await runRegistryProbes({ repoDir: repo, cfg, effectiveTargets: ["npm"], env });
  assert.ok(
    probe.some((f) => f.rule === VERSION_EXISTS_RULE && f.target === "npm"),
    "published version must be visible via the todo-13 GET probe",
  );

  const rec = expectPushRecord(repo, "npm");
  assert.equal(rec.confirmedVia, "npm-view");
  assert.equal(rec.version, "widgets@1.0.0");
  assert.ok(
    !readFileSync(join(repo, ".border", "ledger.jsonl"), "utf8").includes("test-only-token"),
    "G20/G28: token must never enter the ledger",
  );
});

// ---------------------------------------------------------------- AC2 — tamper ⇒ exit 2, no network

test("AC2 npm tamper: one flipped byte in .border/dist after the PASS ⇒ exit 2 before ANY registry hit", async () => {
  const v = await startVerdaccio();
  runningVerdaccios.push(v);
  const { repo, cache, artifact, distFile } = npmFixture("v17-ac2");
  const cfg = borderCfg(`${v.url}/`);
  const key = await seedPassRecord(repo, cfg, "npm", [artifact]);
  tamperOneByte(distFile);
  const env = testNpmEnv(cache, v.port);
  const baseHits = v.requestCount();

  const out = collect();
  const exit = await runNpmPublish({ repoDir: repo, cfg, key, yes: true, env, out: out.write, err: out.write });
  assert.equal(exit, 2, "tampered artifact ⇒ exit 2");
  assert.ok(out.lines.some((l) => l.includes("artifact changed since check")), JSON.stringify(out.lines));
  assert.equal(v.requestCount(), baseHits, "AC2: re-hash gate must short-circuit BEFORE any network");
  assert.equal(v.putCount(), 0);
});

// ---------------------------------------------------------------- AC3 — double-publish race re-probe

test("AC3 npm double-publish: second --yes attempt re-probes, hard-FAILs with bump message, issues no PUT", async () => {
  const v = await startVerdaccio();
  runningVerdaccios.push(v);
  const { repo, cache, artifact } = npmFixture("v17-ac3");
  const cfg = borderCfg(`${v.url}/`);
  const key = await seedPassRecord(repo, cfg, "npm", [artifact]);
  const env = testNpmEnv(cache, v.port);

  const first = collect();
  assert.equal(await runNpmPublish({ repoDir: repo, cfg, key, yes: true, env, out: first.write, err: first.write }), 0);
  // The publish PUT itself is proven by the todo-13 GET probe below seeing the
  // version; the log line is polled because verdaccio flushes async.
  assert.ok(await waitUntil(() => v.putCount() >= 1), "first attempt performs exactly one publish PUT");
  const basePuts = v.putCount();
  assert.equal(basePuts, 1, "exactly one PUT after first publish");
  const second = collect();
  const exit = await runNpmPublish({ repoDir: repo, cfg, key, yes: true, env, out: second.write, err: second.write });
  assert.equal(exit, 1, "AC3: re-probe finds the version ⇒ hard FAIL exit 1");
  assert.ok(
    second.lines.some((l) => l.includes(VERSION_EXISTS_RULE) && l.includes("bump")),
    `message must reference the version-exists bump rule: ${JSON.stringify(second.lines)}`,
  );
  assert.equal(v.putCount(), basePuts, "AC3: second attempt must never reach the publish PUT");
});

// ---------------------------------------------------------------- AC4 — PyPI legs (loopback stub)

test("AC4 pypi dry-run: exact twine upload line with repository-url, ZERO probe requests", async () => {
  const s = await stubWith([]); // every path 404
  const { repo, artifacts, distDir } = pypiFixture("v17-ac4dry");
  const cfg = borderCfg(undefined, `${s.url}/`);
  const key = await seedPassRecord(repo, cfg, "pypi", artifacts);

  const out = collect();
  const exit = await runPypiPublish({ repoDir: repo, cfg, key, yes: false, out: out.write, err: out.write });
  assert.equal(exit, 0);
  const names = readdirSync(distDir).sort();
  assert.equal(names.length, 2, "fixture must carry both sdist and wheel");
  assert.deepEqual(
    out.lines,
    [`twine upload --repository-url ${s.url}/ ${names.map((n) => `.border/dist/${n}`).join(" ")}`],
    "exact argv-shaped dry-run line, no extra flags",
  );
  assert.deepEqual([...s.hits], [], "AC4: dry-run performs ZERO registry requests");
});

test("AC4 pypi tamper: flipped byte in the wheel ⇒ exit 2 `artifact changed since check`, zero network", async () => {
  const s = await stubWith([]);
  const { repo, artifacts, wheel } = pypiFixture("v17-ac4tamper");
  const cfg = borderCfg(undefined, `${s.url}/`);
  const key = await seedPassRecord(repo, cfg, "pypi", artifacts);
  tamperOneByte(wheel);

  const out = collect();
  const exit = await runPypiPublish({ repoDir: repo, cfg, key, yes: true, out: out.write, err: out.write });
  assert.equal(exit, 2);
  assert.ok(out.lines.some((l) => l.includes("artifact changed since check")), JSON.stringify(out.lines));
  assert.deepEqual([...s.hits], [], "re-hash gate must precede any probe");
});

test("AC4 pypi version-exists re-probe ⇒ exit 1 citing bump; twine never spawned", async () => {
  const s = await stubWith([{ path: "/pypi/pushdemo/0.1.0/json", body: { info: { version: "0.1.0" } } }]);
  const { repo, artifacts } = pypiFixture("v17-ac4exists");
  const cfg = borderCfg(undefined, `${s.url}/`);
  const key = await seedPassRecord(repo, cfg, "pypi", artifacts);

  const out = collect();
  const exit = await runPypiPublish({ repoDir: repo, cfg, key, yes: true, out: out.write, err: out.write });
  assert.equal(exit, 1);
  assert.ok(out.lines.some((l) => l.includes(VERSION_EXISTS_RULE) && l.includes("bump")), JSON.stringify(out.lines));
  assert.ok(s.hits.includes("/pypi/pushdemo/0.1.0/json"), "re-probe must consult the configured repository");
});

test("AC4 pypi twine absent (TWINE_BIN seam) ⇒ clean exit 2 before any network, no partial", async () => {
  const s = await stubWith([]);
  const { repo, artifacts } = pypiFixture("v17-ac4notwine");
  const cfg = borderCfg(undefined, `${s.url}/`);
  const key = await seedPassRecord(repo, cfg, "pypi", artifacts);

  const out = collect();
  const exit = await runPypiPublish({
    repoDir: repo,
    cfg,
    key,
    yes: true,
    twineBinPath: "/nonexistent-twine-for-border-test",
    out: out.write,
    err: out.write,
  });
  assert.equal(exit, 2);
  assert.ok(out.lines.some((l) => /twine/i.test(l) && l.length < 400), `clean one-line tool error expected: ${JSON.stringify(out.lines)}`);
  assert.deepEqual([...s.hits], [], "missing twine must short-circuit before the probe");
  assert.equal(readLedger(repo).records.filter((r) => r.t === "push").length, 0, "no push-record on failure");
});

// ---------------------------------------------------------------- AC5 — check gate

test("AC5 missing / key-mismatched / superseded-by-FAIL record ⇒ exit 1 `run border check first`, zero network", async () => {
  const s = await stubWith([]);
  const { repo, cache, artifact } = npmFixture("v17-ac5");
  const cfgMatch = borderCfg(`${s.url}/`);
  const env = testNpmEnv(cache, s.port);

  const noRecord = collect();
  assert.equal(
    await runNpmPublish({ repoDir: repo, cfg: cfgMatch, key: HEX64, yes: true, env, out: noRecord.write, err: noRecord.write }),
    1,
  );
  assert.ok(noRecord.lines.some((l) => l.includes("run border check first")), JSON.stringify(noRecord.lines));

  const key = await seedPassRecord(repo, cfgMatch, "npm", [artifact]);
  const otherCfg = borderCfg(`${s.url}/other-registry`); // digest changes ⇒ different key
  const staleKey = (await computeFingerprint(repo, otherCfg, stableStringify(otherCfg), ["npm"], {})).fp.key;
  const stale = collect();
  assert.equal(
    await runNpmPublish({ repoDir: repo, cfg: otherCfg, key: staleKey, yes: true, env, out: stale.write, err: stale.write }),
    1,
    "no PASS record covers the NEW key",
  );
  assert.ok(stale.lines.some((l) => l.includes("run border check first")));

  appendFailFor(repo, key); // newest record for the key is now FAIL
  const superseded = collect();
  assert.equal(
    await runNpmPublish({ repoDir: repo, cfg: cfgMatch, key, yes: true, env, out: superseded.write, err: superseded.write }),
    1,
    "a later FAIL revokes the PASS",
  );
  assert.ok(superseded.lines.some((l) => l.includes("run border check first")));
  assert.deepEqual([...s.hits], [], "AC5: gate failures precede any probe");
});

// ---------------------------------------------------------------- G28 source guard

test("G28: executor sources never construct or forward credential material", () => {
  for (const rel of ["src/push/npm.ts", "src/push/pypi.ts"]) {
    const path = fileURLToPath(new URL(`../${rel}`, import.meta.url));
    assert.ok(existsSync(path), `${rel} must exist`);
    const src = readFileSync(path, "utf8");
    for (const forbidden of ["_auth", "NPM_TOKEN", "npm_config_userconfig", "password", "apiKey", "--token"]) {
      assert.ok(!src.includes(forbidden), `${rel} must not mention ${forbidden} (G28: border never handles tokens/creds)`);
    }
  }
});
