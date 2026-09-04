// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 15
//
// Push-state machine, live-derivation ACs — ALL offline: git legs run against
// LOCAL bare-repo fixtures (file:// urls), registry legs against the loopback
// stub (todo-13 helper). Covers the plan matrix:
//   * two bare remotes A+B fully synced ⇒ both PUSHED(no-op);
//   * tag deleted on B only ⇒ B PENDING, A stays PUSHED (G43: branch-tip
//     equality must not mask a missing tag);
//   * remote dir deleted ⇒ exit-2 error naming the target;
//   * squatter: 200-packument + NO t:"push" record ⇒ BLOCKED via the todo-13
//     version-exists loud FAIL, never PUSHED (round-1 M4);
//   * our push record present ⇒ PUSHED; owner==self ⇒ PUSHED; 404 ⇒ PENDING;
//   * unreachable registry ⇒ EngineRunError propagates (fail-closed);
//   * malformed ls-remote line ⇒ fail-closed parse;
//   * PUSHED derives from probes alone (no ledger, dirty worktree — the
//     porcelainDigest keying cannot gate a no-op).
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { rmSync } from "node:fs";
import { join } from "node:path";
import { after, test } from "node:test";

import { stableStringify } from "../src/check/rulesHash.ts";
import { computeFingerprint } from "../src/ledger.ts";
import { appendRecord, type CheckRecord } from "../src/ledger/records.ts";
import type { BorderConfig } from "../src/config.ts";
import type { ReportCounts } from "../src/findings.ts";
import { EngineRunError } from "../src/engines/support.ts";
import { BUMP_VERSION_MESSAGE, VERSION_EXISTS_RULE } from "../src/registry.ts";
import {
  PushStateError,
  derivePushState,
  formatTargetLine,
  parseLsRemote,
  pushableTargets,
  recordPushSuccess,
  type PushStateResult,
} from "../src/pushstate.ts";
import { gitAddCommit, gitInit, gitRevParseHead, makeFixtureDir, removeDir, writeRel } from "./helpers/fixtures.ts";
import { PACKUMENT_WIDGETS_100, closedEphemeralPort, startRegistryStub, type RegistryStub } from "./helpers/registry-stub.ts";

const fixtureRoots: string[] = [];
const openStubs: RegistryStub[] = [];

after(async () => {
  for (const s of openStubs) await s.close();
  for (const d of fixtureRoots) removeDir(d);
});

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

function scratchDir(prefix: string): string {
  const dir = makeFixtureDir(prefix);
  fixtureRoots.push(dir);
  return dir;
}

function bareRemote(parent: string, name: string): { path: string; url: string } {
  const path = join(parent, `${name}.git`);
  git(parent, ["init", "-q", "--bare", "-b", "main", path]);
  return { path, url: `file://${path}` };
}

function fileCfg(remotes: readonly { name: string; url: string }[], npmRegistry?: string, emails?: readonly string[]): BorderConfig {
  return {
    version: 1,
    targets: {
      git: { remotes: remotes.map((r) => ({ name: r.name, url: r.url })) },
      ...(npmRegistry === undefined ? {} : { npm: { registry: npmRegistry } }),
    },
    rules: { authors: { emails: [...(emails ?? [])], names: [] }, hosts: [], ips: [], pathPatterns: [], maxFileKB: 500 },
    allow: [],
    engines: { require: [], trufflehog: false },
  };
}

function emptyCounts(): ReportCounts {
  return { INFO: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0, total: 0, blocking: 0, warnings: 0 };
}

const HEX64 = "0".repeat(64);

async function passLedgerFor(repoDir: string, cfg: BorderConfig, targets: readonly string[]): Promise<string> {
  const digest = stableStringify(cfg);
  const { fp } = await computeFingerprint(repoDir, cfg, digest, targets, {});
  const record: CheckRecord = {
    t: "check",
    key: fp.key,
    key8: fp.key.slice(0, 8),
    head: gitRevParseHead(repoDir),
    dirtyDigest: HEX64,
    refSetHash: HEX64,
    exposureSet: [],
    effectiveTargets: [...targets].sort(),
    rulesHash: HEX64,
    artifacts: null,
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

function pushRepo(repoDir: string, url: string): void {
  git(repoDir, [...ID, "push", "-q", url, "main"]);
  git(repoDir, [...ID, "push", "-q", url, "--tags"]);
}

function targetOf(result: PushStateResult, id: string) {
  const t = result.targets.find((x) => x.target === id);
  assert.ok(t !== undefined, `target ${id} missing from ${JSON.stringify(result.targets)}`);
  return t;
}

// ---------------------------------------------------------------- git legs: bare-repo fixtures

function gitFixture(name: string): { repo: string; a: { path: string; url: string }; b: { path: string; url: string }; cfg: BorderConfig } {
  const repo = scratchDir(`ps-${name}`);
  gitInit(repo);
  writeRel(repo, "a.txt", "one\n");
  gitAddCommit(repo, "c1");
  git(repo, [...ID, "tag", "-a", "v1", "-m", "release v1"]);
  git(repo, [...ID, "tag", "v2"]);
  const top = scratchDir(`ps-${name}-top`);
  const a = bareRemote(top, "a");
  const b = bareRemote(top, "b");
  const cfg = fileCfg([
    { name: "a", url: a.url },
    { name: "b", url: b.url },
  ]);
  return { repo, a, b, cfg };
}

test("two synced bare remotes ⇒ both PUSHED(no-op); tag deleted on B only ⇒ B PENDING, A stays PUSHED (G43)", async () => {
  const { repo, a, b, cfg } = gitFixture("ab");
  await passLedgerFor(repo, cfg, ["git"]);
  const base = await derivePushState({ repoDir: repo, cfg, configDigest: stableStringify(cfg), effectiveTargets: ["git"] });
  assert.deepEqual(
    base.targets.map((t) => `${t.target}:${t.status}`).sort(),
    ["git:a:PENDING", "git:b:PENDING"],
  );
  assert.deepEqual(pushableTargets(base).map((t) => t.target).sort(), ["git:a", "git:b"]);

  pushRepo(repo, a.url);
  pushRepo(repo, b.url);
  const synced = await derivePushState({ repoDir: repo, cfg, configDigest: stableStringify(cfg), effectiveTargets: ["git"] });
  assert.equal(targetOf(synced, "git:a").status, "PUSHED");
  assert.equal(targetOf(synced, "git:b").status, "PUSHED");
  assert.match(formatTargetLine(targetOf(synced, "git:a")), /PUSHED\(no-op\)/);
  assert.deepEqual(pushableTargets(synced), []);

  git(b.path, ["update-ref", "-d", "refs/tags/v1"]); // annotated tag deleted on B only
  const split = await derivePushState({ repoDir: repo, cfg, configDigest: stableStringify(cfg), effectiveTargets: ["git"] });
  assert.equal(targetOf(split, "git:a").status, "PUSHED", "untouched remote must stay no-op");
  assert.equal(targetOf(split, "git:b").status, "PENDING", "missing tag must not be masked by branch-tip equality");
  assert.match(formatTargetLine(targetOf(split, "git:b")), /refs\/tags\/v1@absent/);
  assert.deepEqual(pushableTargets(split).map((t) => t.target), ["git:b"]);
});

test("remote directory deleted ⇒ exit-2 PushStateError naming the target", async () => {
  const { repo, a, b, cfg } = gitFixture("dead");
  await passLedgerFor(repo, cfg, ["git"]);
  pushRepo(repo, b.url);
  rmSync(a.path, { recursive: true, force: true });
  await assert.rejects(
    derivePushState({ repoDir: repo, cfg, configDigest: stableStringify(cfg), effectiveTargets: ["git"] }),
    (err: unknown) =>
      err instanceof PushStateError &&
      err.exitCode === 2 &&
      err.message.includes("git:a") &&
      /unreachable/i.test(err.message),
  );
});

test("PUSHED derives from probes alone: no ledger at all, dirty worktree, detached HEAD", async () => {
  const { repo, a, cfg } = gitFixture("live");
  pushRepo(repo, a.url);
  git(repo, ["checkout", "-q", "--detach"]); // refSet = tags only; branch tip refname vanishes
  writeRel(repo, "dirt.txt", "untracked\n"); // dirty ⇒ porcelainDigest shifts, yet no-op stands
  const res = await derivePushState({ repoDir: repo, cfg, configDigest: stableStringify(cfg), effectiveTargets: ["git"] });
  assert.equal(targetOf(res, "git:a").status, "PUSHED", "no-op proof must not depend on ledger or worktree");
  assert.equal(targetOf(res, "git:a").gate, "UNCHECKED");
});

test("parseLsRemote: fail-closed on garbage, peeled lines kept, sha-256 widths accepted", () => {
  const sha40 = "f".repeat(40);
  const sha64 = "e".repeat(64);
  const ok = parseLsRemote(`${sha40}\tHEAD\n${sha40}\trefs/heads/main\n${sha40}\trefs/tags/v1\n${sha64}\trefs/tags/v1^{}\n\n`, "git:x");
  assert.equal(ok.get("refs/tags/v1^{}"), sha64);
  assert.equal(ok.has("HEAD"), false, "git's HEAD convenience line is parsed but never enters the ref map");
  assert.throws(() => parseLsRemote("total garbage line\n", "git:x"), PushStateError);
  assert.throws(() => parseLsRemote(`${sha40} refs/heads/main\n`, "git:x"), PushStateError);
  assert.throws(() => parseLsRemote("z".repeat(40) + "\trefs/heads/main\n", "git:x"), PushStateError);
});

// ---------------------------------------------------------------- npm legs: loopback stub

function npmFixture(name: string): { repo: string; cfg: BorderConfig } {
  const repo = scratchDir(`ps-${name}`);
  gitInit(repo);
  writeRel(repo, "package.json", JSON.stringify({ name: "widgets", version: "1.0.0" }) + "\n");
  gitAddCommit(repo, "init");
  return { repo, cfg: fileCfg([], undefined) };
}

async function stubWith(routes: Parameters<typeof startRegistryStub>[0]): Promise<RegistryStub> {
  const s = await startRegistryStub(routes);
  openStubs.push(s);
  return s;
}

test("squatter: 200-packument, no t:push record ⇒ BLOCKED via version-exists loud FAIL, never PUSHED", async () => {
  const { repo } = npmFixture("squatter");
  const s = await stubWith([{ path: "/widgets", body: PACKUMENT_WIDGETS_100 }]);
  const cfg = fileCfg([], s.url, ["notalice@other.example"]); // maintainers are alice@self.example ⇒ foreign
  await passLedgerFor(repo, cfg, ["npm"]);
  const res = await derivePushState({ repoDir: repo, cfg, configDigest: stableStringify(cfg), effectiveTargets: ["npm"] });
  const npm = targetOf(res, "npm");
  assert.equal(npm.status, "BLOCKED");
  assert.ok(npm.findings.some((f) => f.rule === VERSION_EXISTS_RULE && f.message === BUMP_VERSION_MESSAGE));
  assert.match(formatTargetLine(npm), /BLOCKED.*version-exists.*bump version required/);
  assert.deepEqual(pushableTargets(res), []);
});

test("squatter defeated by our own t:push record ⇒ PUSHED; and recordPushSuccess writes a sanitized ls/npm/pypi record", async () => {
  const { repo } = npmFixture("record");
  const s = await stubWith([{ path: "/widgets", body: PACKUMENT_WIDGETS_100 }]);
  const cfg = fileCfg([], s.url, ["notalice@other.example"]);
  const key = await passLedgerFor(repo, cfg, ["npm"]);
  const rec = recordPushSuccess(repo, {
    key,
    target: "npm",
    remoteName: "npm",
    url: `http://user:sekret@127.0.0.1:${String(s.port)}/`,
    localSha: gitRevParseHead(repo),
    version: "widgets@1.0.0",
    confirmedVia: "npm-view",
  });
  assert.ok(!rec.url.includes("sekret"), "G20: ledger url must be sanitized");
  const res = await derivePushState({ repoDir: repo, cfg, configDigest: stableStringify(cfg), effectiveTargets: ["npm"] });
  const npm = targetOf(res, "npm");
  assert.equal(npm.status, "PUSHED");
  assert.match(formatTargetLine(npm), /push record/);
});

test("version present + owner==self (no push record) ⇒ PUSHED (lost-ledger recovery)", async () => {
  const { repo } = npmFixture("owner");
  const s = await stubWith([{ path: "/widgets", body: PACKUMENT_WIDGETS_100 }]);
  const cfg = fileCfg([], s.url, ["alice@self.example"]);
  await passLedgerFor(repo, cfg, ["npm"]);
  const res = await derivePushState({ repoDir: repo, cfg, configDigest: stableStringify(cfg), effectiveTargets: ["npm"] });
  const npm = targetOf(res, "npm");
  assert.equal(npm.status, "PUSHED");
  assert.match(formatTargetLine(npm), /owner/);
});

test("registry answers 404 (nothing published) ⇒ PENDING when PASSED, BLOCKED-unchecked without a PASS", async () => {
  const { repo } = npmFixture("absent");
  const s = await stubWith([]); // every path 404 ⇒ name unclaimed, version absent
  const cfg = fileCfg([], s.url);
  const unchecked = await derivePushState({ repoDir: repo, cfg, configDigest: stableStringify(cfg), effectiveTargets: ["npm"] });
  const before = targetOf(unchecked, "npm");
  assert.equal(before.status, "BLOCKED");
  assert.equal(before.gate, "UNCHECKED");
  assert.match(formatTargetLine(before), /BLOCKED.*no PASS record/);
  await passLedgerFor(repo, cfg, ["npm"]);
  const res = await derivePushState({ repoDir: repo, cfg, configDigest: stableStringify(cfg), effectiveTargets: ["npm"] });
  const npm = targetOf(res, "npm");
  assert.equal(npm.status, "PENDING");
  assert.equal(npm.gate, "PASSED");
});

test("unreachable npm registry (closed port) ⇒ EngineRunError propagates, fail-closed", async () => {
  const { repo } = npmFixture("deadreg");
  const cfg = fileCfg([], `http://127.0.0.1:${String(await closedEphemeralPort())}`);
  await passLedgerFor(repo, cfg, ["npm"]);
  await assert.rejects(
    derivePushState({ repoDir: repo, cfg, configDigest: stableStringify(cfg), effectiveTargets: ["npm"] }),
    (err: unknown) => err instanceof EngineRunError && /npm/.test(err.message),
  );
});
