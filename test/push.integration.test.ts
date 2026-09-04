// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 17b
//
// GAP-A integration suite: `border push` end-to-end with BOTH a git remote and
// a live registry leg wired through the real CLI (src/cli.ts run seam, same
// pattern as test/push.git.test.ts — helpers here are deliberately replicated
// from test/push.registries.test.ts because that file exports none).
//   I1  git+npm both PENDING ⇒ push --yes lands the bare AND publishes to a
//       real verdaccio AND the ledger carries BOTH push-records under ONE key.
//   I2  diverged backup + npm PENDING ⇒ exit 1 DIVERGED with ZERO publish
//       attempts — the order invariant: every git pre-flight precedes ANY
//       registry mutation.
//   I3  npm publish fails after the re-probe (PATH-stub npm that forwards
//       reads and refuses `publish` — the AC5 seam precedent) ⇒ exit 1 with
//       git ALREADY landed: the honest cross-target partial, ledger = git only.
//       NOTE (deviation, documented in .omo/evidence): the task's suggested
//       "pre-seed the version" tamper can NEVER reach the executor through the
//       CLI — derivePushState pre-probes and turns an existing version into
//       PUSHED(no-op) or BLOCKED-before-anything (pushstate.ts:187-194); the
//       executor re-probe only ever fires on a genuine race.
//   I4  dry-run registry lines: no PASS record ⇒ honest 'cannot list
//       artifacts'; PASS record without .border/dist bytes ⇒ re-hash message
//       + its exit 2; record + packed bytes ⇒ the exact `npm publish` line
//       with ZERO verdaccio requests and zero mutations.
// Same-bytes finding (todo 11 stage wiring): `border check --force` records
// .tgz digests via packNpmArtifacts (tmp dir, deleted — src/ledger/freshness.ts)
// but does NOT populate .border/dist; the fixtures therefore run the real pack
// stage (runNpmArtifactStage → packOnce) explicitly and assert its bytes hash
// to the recorded digests (verified byte-identical argv families, 2026-09-04).
// Cleanup contract: verdaccio SIGTERM + port-release poll, mkdtemp roots in
// after(), no blind sleeps (bounded polls only).
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, openSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createConnection, createServer } from "node:net";
import { basename, join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, test } from "node:test";

import type { BorderConfig } from "../src/config.ts";
import { run } from "../src/cli.ts";
import { EXIT_BLOCKED, EXIT_ERROR, EXIT_PASS } from "../src/cli/exit.ts";
import { DIVERGED_MESSAGE } from "../src/push/git.ts";
import { PUBLISH_WARNING } from "../src/push/npm.ts";
import { runNpmArtifactStage } from "../src/artifacts/npm.ts";
import { pushRecords, readLedger, type CheckRecord } from "../src/ledger.ts";
import { gitAddCommit, gitInit, gitRevParseHead, makeFixtureDir, removeDir, writeRel } from "./helpers/fixtures.ts";

const VERDACCIO_BIN = fileURLToPath(new URL("../node_modules/.bin/verdaccio", import.meta.url));

const fixtureRoots: string[] = [];
const runningVerdaccios: LiveVerdaccio[] = [];

after(async () => {
  for (const v of runningVerdaccios) await v.stop();
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

function addBare(top: string, name: string): string {
  const p = join(top, `${name}.git`);
  gitIn(top, ["init", "-q", "--bare", "-b", "main", p]);
  return p;
}

function lsRemote(bare: string, ref: string): string | null {
  const out = spawnSync("git", ["ls-remote", `file://${bare}`, ref], { encoding: "utf8" });
  if (out.status !== 0) return null;
  const line = out.stdout.split("\n").find((l) => l.includes(ref));
  return line === undefined ? null : (line.split("\t")[0] as string);
}

type RunResult = { readonly code: number; readonly out: string[]; readonly err: string[] };
async function runBorder(argv: readonly string[], cwd: string, env: NodeJS.ProcessEnv): Promise<RunResult> {
  const out: string[] = [];
  const err: string[] = [];
  const code = await run(argv, (l) => out.push(String(l)), (l) => err.push(String(l)), { cwd, env });
  return { code, out, err };
}

const dump = (r: RunResult): string => `code=${String(r.code)}\nout:\n${r.out.join("\n")}\nerr:\n${r.err.join("\n")}`;

function sha256File(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

// ---------------------------------------------------------------- verdaccio
// (replicated minimal config from test/push.registries.test.ts — not exported)

type LiveVerdaccio = {
  readonly port: number;
  readonly url: string;
  requestCount(): number;
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
  // Anonymous server: no auth provider, access/publish $all (G28: border never
  // handles credentials — the TEST userconfig token below is a client-side
  // formality; the server never validates it).
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
  const dir = scratch("i-server");
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
    if (child.exitCode !== null) throw new Error(`verdaccio exited ${String(child.exitCode)}: ${readFileSync(logPath, "utf8").slice(-400)}`);
    try {
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
    // registries.test.ts:283 contract — the info line renders "requested 'PUT /widgets'"
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

/** verdaccio flushes its log asynchronously — bounded poll, never a bare sleep. */
async function waitUntil(pred: () => boolean, timeoutMs = 5_000): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (pred()) return true;
    if (Date.now() > deadline) return false;
    await new Promise((r) => setTimeout(r, 50));
  }
}

// ---------------------------------------------------------------- fixtures

function npmCfg(registry: string): BorderConfig {
  return {
    version: 1,
    targets: { git: { remotes: [] }, npm: { registry } },
    rules: { authors: { emails: ["wiki@sumteclab.com"], names: ["Wiki.js"] }, hosts: [], ips: [], pathPatterns: [], maxFileKB: 500 },
    allow: [],
    engines: { require: [], trufflehog: false },
  };
}

function cfgYaml(remotes: readonly { name: string; bare: string }[], registry: string): string {
  const remoteLines = remotes.map((r) => `      - name: ${r.name}\n        url: file://${r.bare}`).join("\n");
  return [
    "version: 1",
    "targets:",
    "  git:",
    "    remotes:",
    remoteLines,
    "  npm:",
    `    registry: ${registry}`,
    "rules:",
    "  authors:",
    "    emails: [wiki@sumteclab.com]",
    "    names: [Wiki.js]",
    "  hosts: []",
    "  ips: []",
    "  pathPatterns: []",
    "engines:",
    "  require: []",
    "  trufflehog: false",
    "",
  ].join("\n");
}

/** TEST-ONLY credential seam (registries.test.ts precedent): npm >= 10 refuses
 *  client-side publish with zero credentials; border never reads this file. */
function testNpmEnv(cache: string, port: number): NodeJS.ProcessEnv {
  mkdirSync(cache, { recursive: true });
  const rc = join(cache, "userconfig.npmrc");
  writeFileSync(rc, `//127.0.0.1:${String(port)}/:_authToken=test-only-token-border-never-reads-this\n`, "utf8");
  return { ...process.env, npm_config_cache: cache, npm_config_userconfig: rc };
}

type Fixture = {
  readonly top: string;
  readonly repo: string;
  readonly origin: string;
  readonly cfgPath: string;
  readonly env: NodeJS.ProcessEnv;
  readonly registryCfg: BorderConfig;
};

/** git repo (widgets@1.0.0, clean tree) + empty bare origin + border.yaml with
 *  that remote AND the verdaccio registry — the CLI reads the SAME file at
 *  check and push, so one fingerprint key covers both (configDigest rule). */
function npmRepoFixture(top: string, v: LiveVerdaccio): Fixture {
  const repo = join(top, "repo");
  mkdirSync(repo, { recursive: true });
  gitInit(repo);
  writeRel(repo, ".gitignore", ".border/\nnode_modules/\n");
  writeRel(repo, "package.json", JSON.stringify({ name: "widgets", version: "1.0.0", description: "border todo-17b integration fixture", author: "Wiki.js <wiki@sumteclab.com>" }) + "\n");
  writeRel(repo, "README.md", "release demo\n");
  gitAddCommit(repo, "init");
  const origin = addBare(top, "origin");
  const cfgPath = join(top, "border.yaml");
  writeFileSync(cfgPath, cfgYaml([{ name: "origin", bare: origin }], `${v.url}/`), "utf8");
  return { top, repo, origin, cfgPath, env: testNpmEnv(join(top, "npm-cache"), v.port), registryCfg: npmCfg(`${v.url}/`) };
}

/** certify the repo (check --force) AND materialize the recorded bytes via the
 *  real todo-11 pack stage; returns the latest PASS record. */
async function checkForceAndPack(f: Fixture): Promise<CheckRecord> {
  const chk = await runBorder(["check", "--force", "--config", f.cfgPath], f.repo, f.env);
  assert.equal(chk.code, EXIT_PASS, dump(chk));
  const records = readLedger(f.repo).records;
  const passes = records.filter((r): r is CheckRecord => r.t === "check" && r.verdict === "PASS");
  const passRec = passes[passes.length - 1];
  assert.ok(passRec !== undefined, "check --force must append a PASS record");
  assert.notEqual(passRec.artifacts, null, "PASS + clean tree ⇒ the record carries artifact digests");
  const stage = await runNpmArtifactStage({ repoDir: f.repo, cfg: f.registryCfg, env: f.env, skipGitleaks: true, skipSecretlint: true });
  assert.ok(stage.artifact !== null, "pack stage produced an artifact");
  return passRec;
}

// ---------------------------------------------------------------- I1

test("I1 git+npm PENDING: push --yes lands the bare, publishes to verdaccio, and writes BOTH push-records under the PASS key", async () => {
  const v = await startVerdaccio();
  runningVerdaccios.push(v);
  const f = npmRepoFixture(scratch("i1"), v);

  // GAP B closed the §2 FINDING: `check --force` now populates .border/dist
  // itself via the wired todo-11 stage. The pre-stage absence below still
  // holds (the fixture only builds sources, never packs), and the manual
  // stage call in checkForceAndPack stays as a same-bytes equivalence guard.
  assert.equal(existsSync(join(f.repo, ".border", "dist", "widgets-1.0.0.tgz")), false, "pre-check: dist starts empty (fixture packs nothing)");
  const passRec = await checkForceAndPack(f);
  const distFile = join(f.repo, ".border", "dist", "widgets-1.0.0.tgz");
  assert.ok(existsSync(distFile), "the real pack stage materialized .border/dist");
  const recorded = (passRec.artifacts ?? []).find((a) => a.file.endsWith(".tgz"));
  assert.ok(recorded !== undefined, "record lists the .tgz");
  assert.equal(sha256File(distFile), recorded.sha256, "stage bytes hash to the recorded digest (same-bytes proof)");

  const state = await runBorder(["push", "--yes", "--config", f.cfgPath], f.repo, f.env);
  assert.equal(state.code, EXIT_PASS, dump(state));
  assert.ok(state.out.some((l) => /^border: npm  PENDING/.test(l)), `npm leg was PENDING before execution:\n${state.out.join("\n")}`);
  assert.ok(state.out.includes(PUBLISH_WARNING), "immutability warning precedes the publish spawn");

  const head = gitRevParseHead(f.repo);
  assert.equal(lsRemote(f.origin, "refs/heads/main"), head, "git remote sha moved");
  assert.ok(await waitUntil(() => v.putCount() >= 1), "verdaccio saw the publish PUT");
  const meta = (await (await fetch(`${v.url}/widgets`)).json()) as { versions?: Record<string, unknown> };
  assert.ok(meta.versions !== undefined && "1.0.0" in meta.versions, "widgets@1.0.0 visible on verdaccio");

  const recs = pushRecords(readLedger(f.repo).records);
  assert.deepEqual([...recs].map((r) => r.target).sort(), ["git:origin", "npm"], "both push-records landed");
  const npmRec = recs.find((r) => r.target === "npm");
  assert.equal(npmRec?.version, "widgets@1.0.0");
  assert.equal(npmRec?.confirmedVia, "npm-view");
  const gitRec = recs.find((r) => r.target === "git:origin");
  assert.equal(gitRec?.remoteSha, head);
  assert.equal(gitRec?.confirmedVia, "ls-remote");
  for (const r of recs) assert.equal(r.key, passRec.key, "state.key discipline: both records carry the PASS record's fingerprint key");
});

// ---------------------------------------------------------------- I2

test("I2 diverged backup + npm PENDING: exit 1 DIVERGED, ZERO publish attempts, no npm push-record (order invariant)", async () => {
  const v = await startVerdaccio();
  runningVerdaccios.push(v);
  const top = scratch("i2");
  const f = npmRepoFixture(top, v);
  const backup = addBare(top, "backup");

  // diverge backup: land c1, then a side branch pushed from a scratch clone
  gitIn(f.repo, ["push", "-q", `file://${backup}`, "main"]);
  gitIn(top, ["clone", "-q", `file://${backup}`, "side"]);
  writeRel(join(top, "side"), "side.txt", "divergent\n");
  gitIn(join(top, "side"), ["add", "-A"]);
  gitIn(join(top, "side"), ["-c", "user.name=Wiki.js", "-c", "user.email=wiki@sumteclab.com", "commit", "-q", "-m", "side"]);
  gitIn(join(top, "side"), ["push", "-q", "origin", "main"]);
  // new local commit so the repo is ahead of origin (PENDING) and diverged from backup
  writeRel(f.repo, "README.md", "release demo v2\n");
  gitAddCommit(f.repo, "c2");

  writeFileSync(f.cfgPath, cfgYaml([{ name: "origin", bare: f.origin }, { name: "backup", bare: backup }], `${v.url}/`), "utf8");
  const passRec = await checkForceAndPack(f);
  void passRec;

  const r = await runBorder(["push", "--yes", "--config", f.cfgPath], f.repo, f.env);
  assert.equal(r.code, EXIT_BLOCKED, dump(r));
  assert.ok(r.err.some((l) => l.includes(DIVERGED_MESSAGE)), `expected DIVERGED stderr:\n${r.err.join("\n")}`);
  assert.ok(r.out.some((l) => /^border: npm  PENDING/.test(l)), "npm was a ready PENDING leg when the guard fired");
  assert.equal(v.putCount(), 0, "order invariant: every git pre-flight precedes ANY publish");
  assert.equal(lsRemote(f.origin, "refs/heads/main"), null, "BLOCKED run mutates no git remote");
  const recs = pushRecords(readLedger(f.repo).records);
  assert.equal(recs.length, 0, "no push-records at all — npm record absent by construction");
});

// ---------------------------------------------------------------- I3

test("I3 publish spawn fails after git landed (PATH-stub npm): exit 1 cross-target partial, ledger = git record only", async () => {
  const v = await startVerdaccio();
  runningVerdaccios.push(v);
  const f = npmRepoFixture(scratch("i3"), v);
  await checkForceAndPack(f);

  const realNpm = spawnSync("sh", ["-c", "command -v npm"], { encoding: "utf8" }).stdout.trim();
  assert.notEqual(realNpm, "", "real npm must exist to forward reads");
  const stubDir = join(f.top, "npm-stub");
  mkdirSync(stubDir, { recursive: true });
  const stub = join(stubDir, "npm");
  writeFileSync(stub, `#!/bin/sh\nif [ "$1" = "publish" ]; then exit 1; fi\nexec ${realNpm} "$@"\n`, "utf8");
  chmodSync(stub, 0o755);
  const env2: NodeJS.ProcessEnv = { ...f.env, PATH: `${stubDir}:${f.env.PATH ?? ""}` };

  const r = await runBorder(["push", "--yes", "--config", f.cfgPath], f.repo, env2);
  assert.equal(r.code, EXIT_BLOCKED, dump(r));
  const head = gitRevParseHead(f.repo);
  assert.equal(lsRemote(f.origin, "refs/heads/main"), head, "cross-target partial: git ALREADY landed when the registry leg failed");
  assert.ok(r.out.some((l) => l.includes("pushed git:origin")), `git success line printed:\n${r.out.join("\n")}`);
  assert.ok(r.err.some((l) => l.includes("npm publish failed")), `executor failure surfaced:\n${r.err.join("\n")}`);
  assert.equal(v.putCount(), 0, "the stub refused locally — registry untouched");
  const recs = pushRecords(readLedger(f.repo).records);
  assert.deepEqual([...recs].map((x) => x.target), ["git:origin"], "ledger carries the git record ONLY");
});

// ---------------------------------------------------------------- I4

test("I4 dry-run registry lines: no-record honesty, then missing-bytes exit 2, then exact npm publish line with ZERO verdaccio hits", async () => {
  const v = await startVerdaccio();
  runningVerdaccios.push(v);
  const f = npmRepoFixture(scratch("i4"), v);

  // (a) no PASS record yet — honest cannot-list line (and the check seam still
  //     certifies the run: this dry-run's gate leg executes a full check ⇒ 0).
  const a = await runBorder(["push", "--config", f.cfgPath], f.repo, f.env);
  assert.equal(a.code, EXIT_PASS, dump(a));
  assert.ok(
    a.out.some((l) => l.includes("npm registry leg") && l.includes("border check --force") && l.includes("dry-run cannot list artifacts")),
    `no-record honesty line expected:\n${a.out.join("\n")}`,
  );
  assert.ok(a.out.some((l) => l.includes("git push --dry-run") && l.includes("origin")), "git plan line intact");

  // (b) PASS record exists (appended by (a)'s gate) but the certified bytes
  //     are gone from .border/dist — GAP B makes check materialize them, so
  //     the missing-bytes state is constructed explicitly (post-certification
  //     loss: crash, hand-cleaned state dir, tamper). The re-hash gate prints
  //     its message and its exit, no network.
  rmSync(join(f.repo, ".border", "dist", "widgets-1.0.0.tgz"));
  const b = await runBorder(["push", "--config", f.cfgPath], f.repo, f.env);
  assert.equal(b.code, EXIT_ERROR, dump(b));
  assert.ok(b.err.some((l) => l.includes("artifact changed since check") && l.includes("missing")), `re-hash mismatch surfaced:\n${b.err.join("\n")}`);

  // (c) real pack stage materializes the certified bytes — now the dry-run
  //     prints the exact publish command and touches the registry ZERO times.
  const stage = await runNpmArtifactStage({ repoDir: f.repo, cfg: f.registryCfg, env: f.env, skipGitleaks: true, skipSecretlint: true });
  assert.ok(stage.artifact !== null);
  const hits0 = v.requestCount();
  const c = await runBorder(["push", "--config", f.cfgPath], f.repo, f.env);
  assert.equal(c.code, EXIT_PASS, dump(c));
  assert.ok(
    c.out.some((l) => l.includes(`npm publish .border/dist/${basename("widgets-1.0.0.tgz")} --registry ${v.url}/`)),
    `exact publish line expected:\n${c.out.join("\n")}`,
  );
  assert.equal(v.requestCount(), hits0, "dry-run made ZERO verdaccio requests (no probe, no re-pack network)");
  assert.equal(lsRemote(f.origin, "refs/heads/main"), null, "dry-run mutates no git remote");
  assert.equal(pushRecords(readLedger(f.repo).records).length, 0, "dry-run appends no push-record");
});
