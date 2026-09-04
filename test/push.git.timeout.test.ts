// provenance: F2 polish — bounded stdio timeout on the real `git push`
// (src/push/git.ts executePush). Pre-fix the executor spawned with
// stdio:"inherit" and NO timeout, so a hung remote (stalled auth agent, frozen
// transport, flaky link) wedged `border push` forever. These tests pin the
// contract: BORDER_PUSH_TIMEOUT_MS (default 120_000, see the constant's doc in
// src/push/git.ts) bounds the spawn; a killed push answers {ok:false} ⇒ the
// caller records NOTHING (fail closed), exits BLOCKED, and the message tells
// the user the remote state is indeterminate — verify via git ls-remote.
//
// Fixture technique follows test/push.git.test.ts AC5: a PATH-stub `git` that
// passes EVERYTHING through to the real git except `push`, which becomes
// `exec sleep 10`. exec keeps the PID, so the stub records $$ to a pidfile
// before replacing its image — after the timeout the pid must be gone (the
// sleeper killed, not lingering).
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { after, test } from "node:test";

import { run } from "../src/cli.ts";
import { EXIT_BLOCKED } from "../src/cli/exit.ts";
import { computeConfigDigest } from "../src/check/rulesHash.ts";
import { loadConfig } from "../src/config.ts";
import { computeFingerprint } from "../src/ledger.ts";
import { appendRecord, pushRecords, readLedger, type CheckRecord } from "../src/ledger/records.ts";
import type { ReportCounts } from "../src/findings.ts";
import { PushStateError } from "../src/pushstate.ts";
import { executePush } from "../src/push/git.ts";
import { gitAddCommit, gitInit, gitRevParseHead, makeFixtureDir, removeDir, writeRel } from "./helpers/fixtures.ts";

const fixtureRoots: string[] = [];
after(() => {
  for (const d of fixtureRoots) removeDir(d);
});

/** git fenced to the fixture subtree, hermetic identity (no global config). */
function git(cwd: string, args: readonly string[]): string {
  const r = spawnSync("git", args, {
    cwd,
    encoding: "utf8",
    env: { ...process.env, GIT_CEILING_DIRECTORIES: cwd, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_SYSTEM: "/dev/null" },
  });
  if (r.status !== 0) throw new Error(`git ${args.join(" ")} failed (${String(r.status)}): ${r.stderr}`);
  return r.stdout;
}

const ID = ["-c", "user.name=Wiki.js", "-c", "user.email=wiki@sumteclab.com"];
const HEX64 = "0".repeat(64);

function scratch(prefix: string): string {
  const dir = makeFixtureDir(`pgto-${prefix}`);
  fixtureRoots.push(dir);
  return dir;
}

function addBare(top: string, name: string): string {
  const path = join(top, `${name}.git`);
  git(top, ["init", "-q", "--bare", "-b", "main", path]);
  return path;
}

function seedRepo(top: string): string {
  const repo = join(top, "repo");
  mkdirSync(repo);
  gitInit(repo);
  writeRel(repo, "a.txt", "one\n");
  gitAddCommit(repo, "c1");
  git(repo, [...ID, "tag", "-a", "v1", "-m", "release v1"]);
  return repo;
}

function writeCfg(top: string, remotes: readonly { name?: string; url: string }[]): string {
  const path = join(top, "border.yaml");
  const lines = remotes.map((r) => (r.name === undefined ? `      - url: ${r.url}` : `      - name: ${r.name}\n        url: ${r.url}`));
  writeFileSync(
    path,
    [
      "version: 1",
      "targets:",
      "  git:",
      `    remotes:${lines.length === 0 ? " []" : ""}`,
      ...lines,
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
    ].join("\n"),
  );
  return path;
}

async function seedPass(repoDir: string, cfgPath: string, env: NodeJS.ProcessEnv): Promise<string> {
  const load = loadConfig({ cwd: repoDir, configPath: cfgPath, env });
  if (load.kind !== "loaded") throw new Error("fixture config must load, got no-op");
  const digest = computeConfigDigest(load);
  const { fp } = await computeFingerprint(repoDir, load.config, digest, ["git"], { env });
  const counts: ReportCounts = { INFO: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0, total: 0, blocking: 0, warnings: 0 };
  const record: CheckRecord = {
    t: "check",
    key: fp.key,
    key8: fp.key.slice(0, 8),
    head: gitRevParseHead(repoDir),
    dirtyDigest: HEX64,
    refSetHash: HEX64,
    exposureSet: [],
    effectiveTargets: ["git"],
    rulesHash: HEX64,
    artifacts: null,
    llm: false,
    verdict: "PASS",
    counts,
    reportPath: ".border/runs/x/report.json",
    degraded: false,
    ts: new Date().toISOString(),
  };
  appendRecord(repoDir, record);
  return fp.key;
}

function lsRemoteHas(barePath: string, ref: string): boolean {
  return git(barePath, ["ls-remote", barePath]).split("\n").some((line) => line.split("\t")[1] === ref);
}

function countPushRecords(repoDir: string, key?: string): number {
  return pushRecords(readLedger(repoDir).records, key).length;
}

/** Builds a `git` shim: passthrough except `push` ⇒ record $$ then `exec sleep 10`. */
function sleepOnPushStub(top: string): { readonly env: NodeJS.ProcessEnv; readonly pidFile: string } {
  const realGit = spawnSync("/bin/sh", ["-c", "command -v git"], { encoding: "utf8" }).stdout.trim();
  assert.notEqual(realGit, "");
  const binDir = join(top, "stub-bin");
  mkdirSync(binDir);
  const pidFile = join(top, "stub.pid");
  const shim = join(binDir, "git");
  writeFileSync(
    shim,
    [
      "#!/bin/sh",
      'for a in "$@"; do',
      '  if [ "$a" = "push" ]; then',
      '    echo $$ > "$BORDER_TEST_STUB_PID"',
      "    exec sleep 10",
      "  fi",
      "done",
      `exec ${realGit} "$@"`,
      "",
    ].join("\n"),
  );
  chmodSync(shim, 0o755);
  return { env: { ...process.env, PATH: `${binDir}:${process.env.PATH ?? ""}`, BORDER_TEST_STUB_PID: pidFile }, pidFile };
}

/** The pid the stub recorded IS the sleeper (exec keeps the pid) — it must be dead. */
function assertStubDead(pidFile: string): void {
  assert.ok(existsSync(pidFile), "stub git must have been invoked for `push` (pidfile written)");
  const pid = Number(readFileSync(pidFile, "utf8").trim());
  assert.ok(Number.isInteger(pid) && pid > 0, `bogus stub pid in ${pidFile}`);
  let alive = true;
  try {
    process.kill(pid, 0);
  } catch {
    alive = false;
  }
  assert.ok(!alive, `stub git sleeper (pid ${String(pid)}) survived the timeout — lingering process`);
}

type RunResult = { readonly code: number; readonly out: readonly string[]; readonly err: readonly string[] };

async function runBorder(argv: readonly string[], cwd: string, env: NodeJS.ProcessEnv): Promise<RunResult> {
  const out: string[] = [];
  const err: string[] = [];
  const code = await run(
    argv,
    (l) => {
      out.push(String(l));
    },
    (l) => {
      err.push(String(l));
    },
    { cwd, env },
  );
  return { code, out, err };
}

// ---------------------------------------------------------------- unit

test("executePush kills a hung `git push` at BORDER_PUSH_TIMEOUT_MS, answers ok:false, leaves no lingering process", () => {
  const top = scratch("unit");
  const repo = seedRepo(top);
  const bare = addBare(top, "origin");
  const { env, pidFile } = sleepOnPushStub(top);
  const t0 = Date.now();
  const res = executePush({ repoDir: repo, remote: { target: "git:origin", url: `file://${bare}` }, branch: "main", env: { ...env, BORDER_PUSH_TIMEOUT_MS: "250" } });
  const elapsed = Date.now() - t0;
  assert.ok(!res.ok, `a 10s-sleeping push with a 250ms budget must NOT report success, got: ${JSON.stringify(res)}`);
  assert.match(res.failure, /timed out/i);
  assert.match(res.failure, /indeterminate/i);
  assert.match(res.failure, /ls-remote/i, "failure must tell the user how to verify the remote state");
  assert.ok(elapsed < 5_000, `timeout must bound the wait (took ${String(elapsed)}ms — the budget was not enforced)`);
  assertStubDead(pidFile);
  assert.ok(!lsRemoteHas(bare, "refs/heads/main"), "nothing landed on the remote");
});

test("a malformed BORDER_PUSH_TIMEOUT_MS fails closed BEFORE spawning (positive-integer ms only)", () => {
  const top = scratch("malformed");
  const repo = seedRepo(top);
  const bare = addBare(top, "origin");
  const { env } = sleepOnPushStub(top);
  for (const bad of ["0", "-5", "abc", "12.5"]) {
    assert.throws(
      () => executePush({ repoDir: repo, remote: { target: "git:origin", url: `file://${bare}` }, branch: "main", env: { ...env, BORDER_PUSH_TIMEOUT_MS: bad } }),
      PushStateError,
      `BORDER_PUSH_TIMEOUT_MS='${bad}' must be rejected, not silently defaulted`,
    );
  }
});

// ---------------------------------------------------------------- e2e

test("e2e: hung remote + tiny budget ⇒ exit BLOCKED, fail-closed message on stderr, ZERO push records", async () => {
  const top = scratch("e2e");
  const repo = seedRepo(top);
  const bare = addBare(top, "origin");
  const cfgPath = writeCfg(top, [{ name: "origin", url: `file://${bare}` }]);
  const { env, pidFile } = sleepOnPushStub(top);
  const timeoutEnv: NodeJS.ProcessEnv = { ...env, BORDER_PUSH_TIMEOUT_MS: "300" };
  const key = await seedPass(repo, cfgPath, timeoutEnv);

  const r = await runBorder(["push", "--yes", "--config", cfgPath], repo, timeoutEnv);
  assert.equal(r.code, EXIT_BLOCKED, `expected exit 1, got ${String(r.code)}\nout: ${r.out.join("\n")}\nerr: ${r.err.join("\n")}`);
  const err = r.err.join("\n");
  assert.match(err, /timed out/i, `stderr must name the timeout:\n${err}`);
  assert.match(err, /indeterminate/i, `stderr must flag the indeterminate remote state:\n${err}`);
  assert.match(err, /ls-remote/i, `stderr must tell the user to verify with git ls-remote:\n${err}`);
  assert.equal(countPushRecords(repo, key), 0, "a killed push records NOTHING (fail closed)");
  assertStubDead(pidFile);
});
