// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 10
//
// Check-orchestration suite: ctx gathering, G22 `.border` discipline (gitignore/
// lock/stale-recovery), the tracked-state guard (round-5 B-R5-1), the D1 pipeline
// (probe → gitleaks hist/tree/tag/hostile → secretlint → optional trufflehog →
// native rules) and the Report contract. Plan ACs 1-5 each get a named test;
// real gitleaks/secretlint engines run (require-engines guards toolchain presence).
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { after, test } from "node:test";

import { run } from "../src/cli.ts";
import { EXIT_BLOCKED, EXIT_ERROR, EXIT_PASS } from "../src/cli/exit.ts";
import { ConfigError, NO_OP_MESSAGE } from "../src/config.ts";
import type { Finding, Report } from "../src/findings.ts";
import { TRACKED_BORDER_RULE, executeCheck, type CheckOutcome } from "../src/check.ts";
import {
  BORDER_STATE_DIR,
  BorderLockHeldError,
  STALE_LOCK_WARNING,
  acquireLock,
  ensureStateDir,
  lockPath,
  releaseLock,
} from "../src/check/lock.ts";
import { computeEffectiveTargets, gatherContext, resolveRepoDir } from "../src/check/context.ts";
import { computeCheckKey, computeCheckRulesHash, computeConfigDigest, stableStringify } from "../src/check/rulesHash.ts";
import { scanTagMessages } from "../src/check/tagScan.ts";
import { requireGitleaks } from "./helpers/require-engines.ts";
import { BORDER_ROOT, gitAddCommit, gitInit, makeFixtureDir, randAwsPair, removeDir, writeRel } from "./helpers/fixtures.ts";
import type { BorderConfig } from "../src/config.ts";

requireGitleaks();

const fixtureRoots: string[] = [];
const scratchDirs: string[] = [];

after(() => {
  for (const d of fixtureRoots) removeDir(d);
  for (const d of scratchDirs) removeDir(d);
});

function fixture(name: string): string {
  const root = makeFixtureDir(`chk-${name}`);
  fixtureRoots.push(root);
  return root;
}

function borderYamlFor(remoteUrl: string): string {
  return [
    "version: 1",
    "targets:",
    "  git:",
    "    remotes:",
    "      - name: origin",
    `        url: ${remoteUrl}`,
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

/** git repo with a committed border.yaml; scp-form remote keeps the file free of /home/... strings that border's own built-in path patterns would (rightly) flag. */
function checkRepo(name: string, extraFiles: Record<string, string> = {}): string {
  const dir = fixture(name);
  gitInit(dir);
  writeRel(dir, "border.yaml", borderYamlFor("origin.example:widgets.git"));
  for (const [rel, content] of Object.entries(extraFiles)) writeRel(dir, rel, content);
  gitAddCommit(dir, "init");
  return dir;
}

function cfgFor(repoDir: string): BorderConfig {
  return {
    version: 1,
    targets: { git: { remotes: [{ url: `file://${repoDir}/origin.git` }] } },
    rules: {
      authors: { emails: ["wiki@sumteclab.com"], names: ["Wiki.js"] },
      hosts: [],
      ips: [],
      pathPatterns: [],
      maxFileKB: 500,
    },
    allow: [],
    engines: { require: ["gitleaks", "secretlint"], trufflehog: false },
  };
}

function runPipeline(repoDir: string, overrides: { env?: NodeJS.ProcessEnv; requireOverride?: readonly string[] } = {}): Promise<CheckOutcome> {
  return executeCheck({
    repoDir,
    cfg: cfgFor(repoDir),
    configDigest: "f".repeat(64),
    effectiveTargets: ["git"],
    ...(overrides.env !== undefined ? { env: overrides.env } : {}),
    ...(overrides.requireOverride !== undefined ? { requireOverride: overrides.requireOverride } : {}),
  });
}

async function runCli(argv: readonly string[], cwd: string, env?: NodeJS.ProcessEnv) {
  const out: string[] = [];
  const err: string[] = [];
  const code = await run(
    argv,
    (line) => { out.push(line); },
    (line) => { err.push(line); },
    { cwd, ...(env !== undefined ? { env } : {}) },
  );
  return { code, out, err };
}

function git(dir: string, args: readonly string[]): string {
  const r = spawnSync("git", ["-C", dir, ...args], {
    encoding: "utf8",
    env: { ...process.env, GIT_CEILING_DIRECTORIES: join(dir, "..") },
  });
  if (r.status !== 0) throw new Error(`git ${args.join(" ")} failed: ${r.stderr}`);
  return r.stdout;
}

// ------------------------------------------------------------------ ctx gathering

test("gatherContext: head sha, porcelain digest, dirty flag, sorted refSet of current branch + all tags", () => {
  const dir = checkRepo("ctx", { "notes.txt": "clean\n" });
  git(dir, ["tag", "v0.1"]); // lightweight
  writeFileSync(join(dir, "notes.txt"), "dirty now\n");
  git(dir, ["tag", "-a", "v0.2", "-m", "annotated release"]);
  const ctx = gatherContext(dir);
  assert.match(ctx.headSha, /^[0-9a-f]{40}$/);
  assert.match(ctx.porcelainDigest, /^[0-9a-f]{64}$/);
  assert.equal(ctx.dirty, true, "modified notes.txt ⇒ dirty");
  assert.deepEqual([...ctx.refSet], ["refs/heads/main", "refs/tags/v0.1", "refs/tags/v0.2"]);
});

test("gatherContext: detached HEAD drops the branch entry (push from detached touches tags only)", () => {
  const dir = checkRepo("ctx-detached", { "notes.txt": "clean\n" });
  git(dir, ["tag", "only-tag"]);
  git(dir, ["checkout", "-q", "--detach"]);
  const ctx = gatherContext(dir);
  assert.deepEqual([...ctx.refSet], ["refs/tags/only-tag"]);
});

test("gatherContext: empty repository (no commits) fails closed with ConfigError", () => {
  const dir = fixture("ctx-empty");
  gitInit(dir);
  assert.throws(() => gatherContext(dir), (err: unknown) => err instanceof ConfigError && /no commits/i.test(err.message));
  assert.throws(() => resolveRepoDir(fixture("ctx-nonrepo")), (err: unknown) => err instanceof ConfigError && /not a git repository/i.test(err.message));
});

test("computeEffectiveTargets: config set + --targets intersection; unknown target is a ConfigError exit 2", () => {
  const cfg = cfgFor("/x");
  assert.deepEqual(computeEffectiveTargets(cfg, undefined), ["git"]);
  assert.deepEqual(computeEffectiveTargets(cfg, ["git"]), ["git"]);
  assert.throws(
    () => computeEffectiveTargets(cfg, ["npm"]),
    (err: unknown) => err instanceof ConfigError && err.exitCode === 2 && /not configured/i.test(err.message),
  );
});

// ------------------------------------------------------------------ G22 discipline

test("G22: ensureStateDir writes .border/.gitignore with exactly '*' and NEVER touches the root .gitignore", () => {
  const dir = checkRepo("g22");
  ensureStateDir(dir);
  ensureStateDir(dir); // idempotent
  assert.equal(readFileSync(join(dir, BORDER_STATE_DIR, ".gitignore"), "utf8"), "*\n");
  assert.equal(existsSync(join(dir, ".gitignore")), false, "root .gitignore must stay absent");
});

test("G22 lock: held by a live pid ⇒ BorderLockHeldError naming the holder; dead pid ⇒ recovered with WARNING", () => {
  const dir = checkRepo("lock");
  const held = acquireLock(dir);
  assert.equal(held.warning, null);
  assert.equal(readFileSync(lockPath(dir), "utf8").trim(), String(process.pid));
  assert.throws(
    () => acquireLock(dir),
    (err: unknown) => err instanceof BorderLockHeldError && err.exitCode === 2 && err.message.includes(String(process.pid)),
  );
  releaseLock(held.handle);
  assert.equal(existsSync(lockPath(dir)), false);

  writeFileSync(lockPath(dir), "999999999\n"); // pid beyond any plausible allocation ⇒ stale
  const recovered = acquireLock(dir);
  assert.equal(recovered.warning, STALE_LOCK_WARNING);
  assert.equal(readFileSync(lockPath(dir), "utf8").trim(), String(process.pid));
  releaseLock(recovered.handle);
});

test(`guard: committed .border/ content ⇒ CRITICAL '${TRACKED_BORDER_RULE}' naming the path, verdict FAIL, engine legs still filtered (AC2)`, async () => {
  const planted = randAwsPair();
  const dir = checkRepo("guard", { [`${BORDER_STATE_DIR}/planted.env`]: planted.text });
  const outcome = await runPipeline(dir);
  const guards = outcome.report.findings.filter((f) => f.rule === TRACKED_BORDER_RULE);
  assert.equal(guards.length, 1);
  const guard = guards[0] as Finding;
  assert.equal(guard.severity, "CRITICAL");
  assert.ok(guard.path === undefined || guard.path.includes(`${BORDER_STATE_DIR}/planted.env`), "guard names the tracked path");
  assert.match(guard.message, /\.border\/planted\.env/);
  assert.equal(outcome.report.verdict, "FAIL");
  assert.equal(outcome.degraded, false);
  // the exclusion contract holds even on hostile repos: no ENGINE finding may
  // carry a .border/ path (the guard is the only sanctioned reporter there).
  for (const f of outcome.report.findings) {
    if (f.rule === TRACKED_BORDER_RULE) continue;
    assert.ok(!(f.path ?? "").split("/").includes(BORDER_STATE_DIR), `engine finding leaked .border/ path: ${f.path}`);
  }
  // exit-code mapping (CLI wiring proven in cli tests): FAIL ⇒ 1
  assert.notEqual(outcome.report.verdict, "PASS");
});

test("guard lists at most 50 tracked .border paths", async () => {
  const dir = fixture("guard50");
  gitInit(dir);
  writeRel(dir, "border.yaml", borderYamlFor("file:///x/origin.git"));
  for (let i = 0; i < 55; i += 1) writeRel(dir, `${BORDER_STATE_DIR}/runs/junk/f${i}.txt`, "x\n");
  gitAddCommit(dir, "commit border state");
  const outcome = await runPipeline(dir);
  const guard = outcome.report.findings.find((f) => f.rule === TRACKED_BORDER_RULE);
  assert.ok(guard !== undefined);
  const listed = (guard.message.match(/\.border\/runs\/junk\/f\d+\.txt/g) ?? []).length;
  assert.ok(listed <= 50, `guard listed ${listed} paths, must cap at 50`);
  assert.match(guard.message, /\+5 more/);
});

// ------------------------------------------------------------------ D1 pipeline / AC1

test("AC1 self-exclusion: planted secret in UNTRACKED .border/runs/junk/report.json ⇒ clean scan, zero .border findings, exit 0", async () => {
  const dir = checkRepo("ac1");
  const planted = randAwsPair();
  writeRel(dir, `${BORDER_STATE_DIR}/runs/junk/report.json`, JSON.stringify({ secret: planted.text }));
  writeRel(dir, "scratch.tmp", "ephemeral working file\n"); // non-.border dirt ⇒ proves the dirty flag is real, not .border noise
  const outcome = await runPipeline(dir);
  assert.equal(outcome.report.findings.length, 0, `expected clean, got: ${JSON.stringify(outcome.report.findings.map((f) => [f.rule, f.path]), null, 2)}`);
  assert.equal(outcome.report.verdict, "PASS");
  assert.equal(outcome.degraded, false);
  assert.equal(outcome.ctx.dirty, true);
  // the report is a value — nothing was written to disk by the run itself
  const cli = await runCli(["check"], dir);
  assert.equal(cli.code, EXIT_PASS);
  assert.match(cli.out.join("\n"), /PASS/);
});

test("pipeline builds the Report per schema: key/digests/counts/exposure/refSet/rulesHash all present and stable", async () => {
  const dir = checkRepo("report");
  const outcome = await runPipeline(dir);
  const report = outcome.report;
  assert.equal(report.schemaVersion, 1);
  assert.match(report.head, /^[0-9a-f]{40}$/);
  assert.equal(typeof report.dirty, "boolean");
  assert.deepEqual([...report.exposureSet], [`file://${dir}/origin.git`].map((u) => new URL(u).toString()));
  assert.deepEqual([...report.refSet], ["refs/heads/main"]);
  assert.match(report.rulesHash, /^[0-9a-f]{64}$/);
  assert.match(report.key, /^[0-9a-f]{64}$/);
  assert.equal(report.counts.total, report.findings.length);
  assert.equal(report.counts.blocking, report.counts.CRITICAL + report.counts.HIGH);
  assert.equal(Number.isNaN(Date.parse(report.ts)), false);
});

test("native identity rule runs in the pipeline: disallowed commit author ⇒ identity-not-allowlisted (after engine legs)", async () => {
  const dir = fixture("identity");
  gitInit(dir);
  writeRel(dir, "border.yaml", borderYamlFor("file:///x/origin.git"));
  writeRel(dir, "code.js", "export const a = 1;\n");
  git(dir, ["add", "-A"]);
  git(dir, ["-c", "user.name=Mallory", "-c", "user.email=mallory@evil.test", "commit", "-q", "-m", "sneaky"]);
  const outcome = await runPipeline(dir);
  const hits = outcome.report.findings.filter((f) => f.rule === "identity-not-allowlisted");
  assert.ok(hits.length >= 1, "identity leg must fire for a non-allowlisted author");
  assert.equal(hits[0]?.engine, "native");
  assert.equal(outcome.report.verdict, "FAIL");
});

// ------------------------------------------------------------------ tag-message leg / AC3

test("AC3 tag-message leg: secret in annotated tag message ⇒ CRITICAL finding with the tag ref as path", async () => {
  const dir = checkRepo("ac3", { "a.txt": "clean\n" });
  const planted = randAwsPair();
  git(dir, ["tag", "-a", "v-secret", "-m", `release with ${planted.text}`]);
  const findings = scanTagMessages({ repoDir: dir, target: "git" });
  assert.ok(findings.length >= 1, "expected a CRITICAL finding from the tag message");
  const f = findings[0] as Finding;
  assert.equal(f.severity, "CRITICAL");
  assert.equal(f.path, "refs/tags/v-secret");
  assert.match(f.commit ?? "", /^[0-9a-f]{40}$/);
  assert.match(f.message, /v-secret/);
  assert.equal(f.engine, "gitleaks");
  const outcome = await runPipeline(dir);
  assert.equal(outcome.report.verdict, "FAIL");
});

test("clean tag message produces zero tag-leg findings", () => {
  const dir = checkRepo("tagclean", { "a.txt": "clean\n" });
  git(dir, ["tag", "-a", "v-ok", "-m", "boring release"]);
  assert.deepEqual(scanTagMessages({ repoDir: dir, target: "git" }), []);
});

// ------------------------------------------------------------------ degraded engines / AC5

function stubBin(name: string, body: string): { readonly dir: string; readonly env: NodeJS.ProcessEnv } {
  const dir = mkdtempSync(join(BORDER_ROOT, "test", "tmp", "stub-"));
  scratchDirs.push(dir);
  const file = join(dir, name);
  writeFileSync(file, `#!/bin/sh\n${body}\n`, { mode: 0o755 });
  return { dir, env: { ...process.env, PATH: `${dir}:${process.env.PATH ?? ""}` } as NodeJS.ProcessEnv };
}

test("AC5 degraded engine: gitleaks stub exits 99 ⇒ CRITICAL DEGRADED-ENGINE collected, run survives, lock released", async () => {
  const dir = checkRepo("ac5");
  const stub = stubBin("gitleaks", "exit 99");
  const outcome = await runPipeline(dir, { env: stub.env });
  assert.equal(outcome.degraded, true);
  const degraded = outcome.report.findings.filter((f) => f.rule === "DEGRADED-ENGINE");
  assert.equal(degraded.length, 1);
  assert.equal(degraded[0]?.severity, "CRITICAL");
  assert.equal(degraded[0]?.engine, "gitleaks");
  assert.equal(existsSync(lockPath(dir)), false, "lock must be released on every exit path");
  // CLI translation: degraded ⇒ exit 2 even though the rest of the run is healthy
  const cli = await runCli(["check"], dir, stub.env);
  assert.equal(cli.code, EXIT_ERROR);
  assert.match(cli.err.join("\n"), /degraded/i);
  assert.equal(existsSync(lockPath(dir)), false);
});

test("crash during a scan leg (probe passes, scan exits 99) ⇒ EngineRunError propagates, lock released", async () => {
  const dir = checkRepo("crash");
  const stub = stubBin("gitleaks", 'case "$*" in *--version*) echo "gitleaks version 8.30.1"; exit 0;; esac\nexit 99');
  await assert.rejects(() => runPipeline(dir, { env: stub.env }), /gitleaks exited 99/);
  assert.equal(existsSync(lockPath(dir)), false, "lock must be released even when a leg throws");
  const cli = await runCli(["check"], dir, stub.env);
  assert.equal(cli.code, EXIT_ERROR);
  assert.match(cli.err.join("\n"), /engine run error/i);
});

test("second concurrent run is refused with exit 2 naming the holder pid (AC4, real child process)", async () => {
  const dir = checkRepo("ac4");
  const held = acquireLock(dir); // acts as the first live border run (holder pid = this process)
  const wrapper = join(dir, ".border", "runner.mjs");
  writeFileSync(
    wrapper,
    `process.chdir(${JSON.stringify(dir)});
const { run } = await import("file://${BORDER_ROOT}/src/cli.ts");
const out = [];
const code = await run(["check"], (l) => out.push(l), (l) => out.push(l));
process.stdout.write(JSON.stringify({ code, lines: out }));
`,
  );
  try {
    const child = spawnSync(process.execPath, ["--import", join(BORDER_ROOT, "tools/register-ts.mjs"), wrapper], {
      cwd: dir,
      encoding: "utf8",
      env: process.env,
      timeout: 60_000,
    });
    const payload = JSON.parse(child.stdout) as { code: number; lines: string[] };
    assert.equal(payload.code, EXIT_ERROR, `child must exit 2, got ${String(payload.code)}: ${child.stderr}`);
    assert.match(payload.lines.join("\n"), new RegExp(`lock held by pid ${process.pid}`));
  } finally {
    releaseLock(held.handle);
  }
});

// ------------------------------------------------------------------ rulesHash / key

test("stableStringify sorts nested keys; configDigest is deterministic per effective config", () => {
  assert.equal(stableStringify({ b: 1, a: { d: [3, 2], c: "x" } }), '{"a":{"c":"x","d":[3,2]},"b":1}');
  const cfg = cfgFor("/x");
  const digest = computeConfigDigest({ kind: "loaded", config: cfg, warnings: [], source: "/nonexistent/border.yaml" });
  assert.equal(digest, computeConfigDigest({ kind: "loaded", config: cfg, warnings: [], source: "/other/border.yaml" }), "canonical: source path itself must not leak into the digest");
  const tweaked: BorderConfig = { ...cfg, rules: { ...cfg.rules, maxFileKB: 400 } };
  assert.notEqual(digest, computeConfigDigest({ kind: "loaded", config: tweaked, warnings: [], source: "/nonexistent/border.yaml" }));
});

test("rulesHash changes with engine versions and config; key changes with refSet", async () => {
  const base = { engineVersions: { gitleaks: "8.30.1", secretlint: "a".repeat(64) }, configDigest: "b".repeat(64) };
  const h1 = await computeCheckRulesHash(base);
  assert.equal(h1, await computeCheckRulesHash({ ...base }));
  assert.notEqual(h1, await computeCheckRulesHash({ ...base, engineVersions: { ...base.engineVersions, gitleaks: "8.30.2" } }));
  const ctx = { headSha: "c".repeat(40), porcelainDigest: "d".repeat(64), refSet: ["refs/heads/main"] };
  const k1 = computeCheckKey({ ...ctx, rulesHash: h1, exposureSet: ["https://h/r.git"], effectiveTargets: ["git"] });
  assert.notEqual(k1, computeCheckKey({ ...ctx, rulesHash: h1, exposureSet: ["https://h/r.git"], effectiveTargets: ["git", "npm"] }));
  assert.notEqual(k1, computeCheckKey({ ...ctx, refSet: ["refs/heads/main", "refs/tags/v1"], rulesHash: h1, exposureSet: ["https://h/r.git"], effectiveTargets: ["git"] }));
});

// ------------------------------------------------------------------ CLI layer

test("CLI: no-op config prints NO_OP_MESSAGE and exits 0 (no remote inferred; zero-target border.yaml)", async () => {
  const dir = fixture("cli-noop");
  gitInit(dir); // git repo, no border.yaml, no remotes ⇒ no-op
  const r = await runCli(["check"], dir);
  assert.equal(r.code, EXIT_PASS);
  assert.ok(r.out.join("\n").includes(NO_OP_MESSAGE));

  const dir2 = fixture("cli-noop-yaml");
  gitInit(dir2);
  writeRel(dir2, "border.yaml", [
    "version: 1",
    "targets:",
    "  git:",
    "    remotes: []",
    "rules:",
    "  authors:",
    "    emails: []",
    "    names: []",
    "  hosts: []",
    "  ips: []",
    "  pathPatterns: []",
    "",
  ].join("\n")); // zero targets ⇒ no-op despite config
  const r2 = await runCli(["check"], dir2);
  assert.equal(r2.code, EXIT_PASS);
  assert.ok(r2.out.join("\n").includes(NO_OP_MESSAGE));
  assert.equal(existsSync(join(dir2, ".border", "lock")), false, "no-op must not engage the pipeline");
});

test("CLI --json prints the Report without raw values; plain output prints the verdict + summary", async () => {
  const dir = checkRepo("cli-json", { "a.txt": "clean\n" });
  const planted = randAwsPair();
  writeRel(dir, "leak.txt", planted.text);
  const json = await runCli(["check", "--json"], dir);
  assert.equal(json.code, EXIT_BLOCKED, "committed-in-tree leak ⇒ verdict FAIL ⇒ 1");
  const report = JSON.parse(json.out.join("\n")) as Report;
  assert.equal(report.schemaVersion, 1);
  assert.equal(report.verdict, "FAIL");
  const serialized = JSON.stringify(report);
  assert.equal(serialized.includes(planted.key), false, "raw secret key must never appear in the report");
  assert.equal(serialized.includes(planted.secret), false, "raw secret value must never appear in the report");
  const plain = await runCli(["check"], dir);
  assert.equal(plain.code, EXIT_BLOCKED);
  assert.match(plain.out.join("\n"), /FAIL/);
});

test("CLI: unknown --targets value relative to config exits 2 with a config-error line", async () => {
  const dir = checkRepo("cli-targets");
  const r = await runCli(["check", "--targets", "npm"], dir);
  assert.equal(r.code, EXIT_ERROR);
  assert.match(r.err.join("\n"), /not configured/i);
});
