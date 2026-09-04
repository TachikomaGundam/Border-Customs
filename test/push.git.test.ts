// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 16
//
// Multi-remote git push executor — e2e over LOCAL bare-repo fixtures (mkdtemp
// under test/tmp, zero network). AC matrix:
//   AC1 clean multi-remote --yes lands BOTH bares (branch + peeled tag), 2
//       push-records appended;
//   AC2 diverged backup (created by clone→commit→push-back on the scratch work
//       repo — NEVER reset --hard a bare, it has no worktree) ⇒ ALL-or-NOTHING
//       pre-flight finds it ⇒ origin gets NOTHING (ls-remote sha unchanged),
//       exit 1, exact divergence message, 0 new push-records;
//   AC3 dry-run (no --yes) prints `git push --dry-run` lines verbatim, zero
//       ls-remote sha changes;
//   AC4 remote ref ABSENT ⇒ guard trivially passes, first push succeeds;
//   AC5 mid-loop transport failure via a PATH-stubbed git that fails on the
//       2nd push invocation (marker file) ⇒ exit 1, first record present,
//       message names the partial state;
//   AC6 the force flag is literally absent from the executor source.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { after, test } from "node:test";

import { run } from "../src/cli.ts";
import { EXIT_BLOCKED, EXIT_PASS } from "../src/cli/exit.ts";
import { computeConfigDigest } from "../src/check/rulesHash.ts";
import { loadConfig } from "../src/config.ts";
import { computeFingerprint } from "../src/ledger.ts";
import { appendRecord, pushRecords, readLedger, type CheckRecord } from "../src/ledger/records.ts";
import type { ReportCounts } from "../src/findings.ts";
import { setHandler } from "../src/commands/index.ts";
import { DIVERGED_MESSAGE, fastForwardGuard, pushArgv } from "../src/push/git.ts";
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
  const dir = makeFixtureDir(`pg-${prefix}`);
  fixtureRoots.push(dir);
  return dir;
}

function addBare(top: string, name: string): string {
  const path = join(top, `${name}.git`);
  git(top, ["init", "-q", "--bare", "-b", "main", path]);
  return path;
}

/** seed repo: one commit + one ANNOTATED tag (reachable ⇒ --follow-tags lands it). */
function seedRepo(top: string): string {
  const repo = join(top, "repo");
  mkdirSync(repo);
  gitInit(repo);
  writeRel(repo, "a.txt", "one\n");
  gitAddCommit(repo, "c1");
  git(repo, [...ID, "tag", "-a", "v1", "-m", "release v1"]);
  return repo;
}

/**
 * border.yaml OUTSIDE the work tree (--config) so the repo stays porcelain-clean
 * and the fingerprint seed / production derive paths key identically. Authors
 * allow the fixture identity; engines.require [] keeps the probe env-invariant
 * (the AC5 PATH stub must not shift the fingerprint key).
 */
function writeCfg(top: string, remotes: readonly { name: string; url: string }[]): string {
  const path = join(top, "border.yaml");
  const lines = remotes.map((r) => `      - name: ${r.name}\n        url: ${r.url}`);
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

/** The todo-15 ledger PASS that unlocks the git gate — same config + digest +
 *  target scope production will recompute from the SAME border.yaml on disk. */
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

function lsRemote(barePath: string, ref: string): string | null {
  for (const line of git(barePath, ["ls-remote", barePath]).split("\n")) {
    const [sha, name] = line.split("\t");
    if (name === ref) return sha ?? null;
  }
  return null;
}

function countPushRecords(repoDir: string, key?: string): number {
  return pushRecords(readLedger(repoDir).records, key).length;
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

// ---------------------------------------------------------------- AC1 + AC4

test("AC1/AC4 clean --yes lands origin AND backup (branch + peeled tag), 2 push-records, first-push guard trivially passes", async () => {
  const top = scratch("ac1");
  const repo = seedRepo(top);
  const origin = addBare(top, "origin");
  const backup = addBare(top, "backup");
  const cfgPath = writeCfg(top, [
    { name: "origin", url: `file://${origin}` },
    { name: "backup", url: `file://${backup}` },
  ]);
  const env: NodeJS.ProcessEnv = { ...process.env };
  const key = await seedPass(repo, cfgPath, env);
  assert.equal(countPushRecords(repo, key), 0, "pre-condition: no push records yet");

  const r = await runBorder(["push", "--yes", "--config", cfgPath], repo, env);
  assert.equal(r.code, EXIT_PASS, `expected exit 0, got ${String(r.code)}\nout: ${r.out.join("\n")}\nerr: ${r.err.join("\n")}`);

  const head = gitRevParseHead(repo);
  const v1Peeled = git(repo, ["rev-parse", "v1^{commit}"]).trim();
  for (const [bare, label] of [
    [origin, "origin"],
    [backup, "backup"],
  ] as const) {
    assert.equal(lsRemote(bare, "refs/heads/main"), head, `${label}: branch tip must equal local HEAD`);
    assert.equal(lsRemote(bare, "refs/tags/v1^{}"), v1Peeled, `${label}: annotated tag must arrive peeled`);
  }

  const recs = pushRecords(readLedger(repo).records, key);
  assert.deepEqual(
    recs.map((x) => x.target).sort(),
    ["git:backup", "git:origin"],
  );
  for (const rec of recs) {
    assert.equal(rec.remoteName, rec.target.replace("git:", ""));
    assert.ok(rec.url.startsWith("file://"));
    assert.equal(rec.localSha, head);
    assert.equal(rec.remoteSha, head);
    assert.equal(rec.confirmedVia, "ls-remote");
  }

  // AC4 direct: an absent remote ref is trivially guard-passable (first push).
  const guard = fastForwardGuard({
    repoDir: repo,
    remotes: [{ target: "git:origin", url: `file://${origin}` }],
    refSet: ["refs/heads/main", "refs/tags/v1"],
    env,
  });
  assert.ok(guard.ok, "empty remote ⇒ nothing diverged");
});

// ---------------------------------------------------------------- AC2

test("AC2 diverged backup ⇒ pre-flight blocks EVERYTHING (origin untouched), exit 1 with the exact message, 0 new records", async () => {
  const top = scratch("ac2");
  const repo = seedRepo(top);
  const origin = addBare(top, "origin");
  const backup = addBare(top, "backup");

  // seed backup with the base commit, then diverge it the plan-sanctioned way:
  // clone the bare into a scratch work repo, commit there, push BACK (never
  // reset --hard — a bare has no worktree).
  git(repo, ["push", "-q", `file://${backup}`, "main"]);
  git(top, ["clone", "-q", `file://${backup}`, "scratch"]);
  const scratchWork = join(top, "scratch");
  writeRel(scratchWork, "side.txt", "side branch\n");
  git(scratchWork, ["add", "-A"]);
  git(scratchWork, [...ID, "commit", "-q", "--no-gpg-sign", "-m", "side"]);
  git(scratchWork, ["push", "-q", "origin", "main"]);

  // main repo moves on independently ⇒ true divergence against backup
  writeRel(repo, "b.txt", "two\n");
  gitAddCommit(repo, "c2");

  const cfgPath = writeCfg(top, [
    { name: "origin", url: `file://${origin}` },
    { name: "backup", url: `file://${backup}` },
  ]);
  const env: NodeJS.ProcessEnv = { ...process.env };
  const key = await seedPass(repo, cfgPath, env);
  const backupShaBefore = lsRemote(backup, "refs/heads/main");
  assert.notEqual(backupShaBefore, gitRevParseHead(repo));

  const r = await runBorder(["push", "--yes", "--config", cfgPath], repo, env);
  assert.equal(r.code, EXIT_BLOCKED, `expected exit 1, got ${String(r.code)}\nout: ${r.out.join("\n")}\nerr: ${r.err.join("\n")}`);
  assert.ok(
    r.err.some((l) => l === `border: ${DIVERGED_MESSAGE}`),
    `stderr must carry the exact divergence line; got:\n${r.err.join("\n")}`,
  );
  assert.equal(DIVERGED_MESSAGE, "history diverged; border never force-pushes; resolve manually");

  // ALL-or-NOTHING: the untouched origin received NOTHING (still empty).
  assert.equal(lsRemote(origin, "refs/heads/main"), null, "origin must be untouched — guard is all-or-nothing");
  assert.equal(lsRemote(backup, "refs/heads/main"), backupShaBefore, "backup must keep its diverged sha");
  assert.equal(countPushRecords(repo, key), 0, "a blocked run appends zero push-records");
});

test("AC2b guard unit: ancestor branch passes, moved tag and non-ancestor branch are divergences", () => {
  const top = scratch("ac2b");
  const repo = seedRepo(top);
  const bare = addBare(top, "sync");
  git(repo, ["push", "-q", `file://${bare}`, "main", "--tags"]);
  // advance the branch (fast-forwardable) but re-point the tag (never ff-able)
  writeRel(repo, "b.txt", "two\n");
  gitAddCommit(repo, "c2");
  git(repo, [...ID, "tag", "-f", "-a", "v1", "-m", "moved", "HEAD"]);
  const env: NodeJS.ProcessEnv = { ...process.env };
  const guard = fastForwardGuard({
    repoDir: repo,
    remotes: [{ target: "git:sync", url: `file://${bare}` }],
    refSet: ["refs/heads/main", "refs/tags/v1"],
    env,
  });
  assert.ok(!guard.ok);
  assert.deepEqual(guard.divergences.map((d) => d.ref), ["refs/tags/v1"], "branch is ancestor-ok; a moved tag is a divergence");
});

// ---------------------------------------------------------------- AC3

test("AC3 dry-run prints verbatim `git push --dry-run` lines and mutates ZERO shas", async () => {
  const top = scratch("ac3");
  const repo = seedRepo(top);
  const origin = addBare(top, "origin");
  const backup = addBare(top, "backup");
  const cfgPath = writeCfg(top, [
    { name: "origin", url: `file://${origin}` },
    { name: "backup", url: `file://${backup}` },
  ]);
  const env: NodeJS.ProcessEnv = { ...process.env };
  const restore = setHandler("check", () => EXIT_PASS);
  let r: RunResult;
  try {
    r = await runBorder(["push", "--config", cfgPath], repo, env);
  } finally {
    restore();
  }
  assert.equal(r.code, EXIT_PASS, r.err.join("\n"));
  const planLines = r.out.filter((l) => l.includes("git push --dry-run"));
  assert.equal(planLines.length, 2, `two plan lines expected:\n${r.out.join("\n")}`);
  assert.ok(planLines.every((l) => l.includes("--follow-tags")));
  assert.ok(planLines.some((l) => l.includes("origin")));
  assert.ok(planLines.some((l) => l.includes("backup")));
  assert.equal(lsRemote(origin, "refs/heads/main"), null);
  assert.equal(lsRemote(backup, "refs/heads/main"), null);
});

// ---------------------------------------------------------------- AC5

test("AC5 mid-loop transport failure (PATH-stub git, 2nd push invocation) ⇒ exit 1, partial state named, first record kept", async () => {
  const top = scratch("ac5");
  const repo = seedRepo(top);
  const first = addBare(top, "alpha");
  const second = addBare(top, "bravo");

  // Deterministic mid-loop failure: a git shim that passes EVERYTHING through
  // except the 2nd `push` invocation, which it fails via a marker counter.
  // (chmod-000 could not land between the guard and the loop without a race.)
  const realGit = spawnSync("/bin/sh", ["-c", "command -v git"], { encoding: "utf8" }).stdout.trim();
  assert.notEqual(realGit, "");
  const binDir = join(top, "stub-bin");
  mkdirSync(binDir);
  const countFile = join(top, "push-count");
  writeFileSync(countFile, "0\n");
  const shim = join(binDir, "git");
  writeFileSync(
    shim,
    [
      "#!/bin/sh",
      'is_push=0',
      'for a in "$@"; do if [ "$a" = "push" ]; then is_push=1; fi; done',
      'if [ "$is_push" = "1" ]; then',
      '  n=$(cat "$BORDER_TEST_PUSH_COUNT" 2>/dev/null || echo 0)',
      '  n=$((n + 1))',
      '  echo "$n" > "$BORDER_TEST_PUSH_COUNT"',
      '  if [ "$n" -ge 2 ]; then echo "stub-git: simulated transport failure on push invocation $n" >&2; exit 128; fi',
      "fi",
      `exec ${realGit} "$@"`,
      "",
    ].join("\n"),
  );
  chmodSync(shim, 0o755);

  const cfgPath = writeCfg(top, [
    { name: "alpha", url: `file://${first}` },
    { name: "bravo", url: `file://${second}` },
  ]);
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    PATH: `${binDir}:${process.env.PATH ?? ""}`,
    BORDER_TEST_PUSH_COUNT: countFile,
  };
  const key = await seedPass(repo, cfgPath, env);

  const r = await runBorder(["push", "--yes", "--config", cfgPath], repo, env);
  assert.equal(r.code, EXIT_BLOCKED, `expected exit 1, got ${String(r.code)}\nerr: ${r.err.join("\n")}`);
  assert.match(r.err.join("\n"), /partial/i);
  assert.equal(lsRemote(first, "refs/heads/main"), gitRevParseHead(repo), "the pre-failure remote landed");
  assert.equal(lsRemote(second, "refs/heads/main"), null, "the failed remote received nothing");
  const recs = pushRecords(readLedger(repo).records, key);
  assert.deepEqual(recs.map((x) => x.target), ["git:alpha"]);
});

// ---------------------------------------------------------------- AC6

test("AC6 the force flag is literally absent from the executor source (plan grep guard)", () => {
  const source = readFileSync(new URL("../src/push/git.ts", import.meta.url), "utf8");
  assert.equal(source.split("--force").length - 1, 0, "'--force' must never appear in src/push/git.ts");
});

test("pushArgv builds exactly the plan command lines, dry and execute, with no extra flags", () => {
  assert.deepEqual(pushArgv("git@host:acme/thing.git", "main", "dry-run"), [
    "push",
    "--dry-run",
    "git@host:acme/thing.git",
    "main",
    "--follow-tags",
  ]);
  assert.deepEqual(pushArgv("file:///srv/b.git", "release", "execute"), ["push", "file:///srv/b.git", "release", "--follow-tags"]);
  assert.deepEqual(
    pushArgv("u", "b", "dry-run").filter((a) => a.startsWith("--")),
    ["--dry-run", "--follow-tags"],
  );
  assert.deepEqual(
    pushArgv("u", "b", "execute").filter((a) => a.startsWith("--")),
    ["--follow-tags"],
  );
  assert.ok(![...pushArgv("u", "b", "dry-run"), ...pushArgv("u", "b", "execute")].some((a) => a.toLowerCase().includes("force")), "no history-rewrite override may ride the argv");
});
