// provenance: .omo/plans/border-exfil-lens.md T7 — S3 landing-verification suite:
// the three honest outcomes via injected seams (clean records & preserves the
// executor exit; blocked ⇒ exit 1 "ALREADY PUBLIC…"; unreachable ⇒ exit 2 with
// NO record), push-record immutability (append-only ledger prefix byte-equality),
// unknown-t forward-compat (old readers WARNING-skip landing rows), record
// constructor validation, and the no-bypass + real-push E2E legs.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { appendFileSync, mkdirSync, readFileSync } from "node:fs";
import { dirname } from "node:path";
import { relative } from "node:path";
import { after, test } from "node:test";

import { runLandingVerification, type LandingLeg } from "../src/push/landing.ts";
import { buildLandingRecord, ledgerPath, parseLedgerRecord, readLedger, type LandingRecord } from "../src/ledger/records.ts";
import { run } from "../src/cli.ts";
import type { Finding } from "../src/findings.ts";
import { EXIT_BLOCKED, EXIT_ERROR, EXIT_PASS } from "../src/cli/exit.ts";
import { gitAddCommit, gitInit, gitRevParseHead, makeFixtureDir, removeDir, writeRel } from "./helpers/fixtures.ts";

const roots: string[] = [];
after(() => {
  for (const d of roots) removeDir(d);
});

function fixture(name: string): string {
  const dir = makeFixtureDir(`exland-${name}`);
  roots.push(dir);
  return dir;
}

const KEY = "a".repeat(64);
const SHA_TIP = "b".repeat(40);
const RULES = "c".repeat(64);
const LEG: LandingLeg = { target: { target: "git:origin", url: "origin.example:widgets.git" }, branch: "main" };

function finding(severity: Finding["severity"], rule = "exfil-rfc1918"): Finding {
  return { rule, severity, target: "tree", path: "docs/leak.md", line: 1, engine: "secretlint", message: "x", valueDigest: "d".repeat(64), snippet: "▮▮▮▮" };
}

/** Tests may seed the ledger before any command ever ran — the .border dir must exist first, exactly as the real flow would have left it. */
function appendLedger(repoDir: string, line: string): void {
  mkdirSync(dirname(ledgerPath(repoDir)), { recursive: true });
  appendFileSync(ledgerPath(repoDir), line, "utf8");
}

/** A PASS check-record under the key is the precondition for landing rulesHash provenance — seed it like the real flow left it. */
function seedPass(repoDir: string, key = KEY, rulesHash = RULES): void {
  appendLedger(
    repoDir,
    `${JSON.stringify({
      t: "check", key, key8: key.slice(0, 8), head: "e".repeat(40), dirtyDigest: "f".repeat(64),
      refSetHash: "0".repeat(64), exposureSet: [], effectiveTargets: ["git"], rulesHash,
      artifacts: null, llm: false, verdict: "PASS",
      counts: { INFO: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0, total: 0, blocking: 0, warnings: 0 },
      reportPath: ".border/runs/x/report.json", degraded: false, ts: "2026-09-25T00:00:00.000Z",
    })}\n`);
}

function baseOpts(repoDir: string) {
  const out: string[] = [];
  const err: string[] = [];
  const rows: LandingRecord[] = [];
  return {
    out,
    err,
    rows,
    opts: {
      repoDir,
      key: KEY,
      legs: [LEG],
      env: { ...process.env },
      out: (l: string) => out.push(l),
      err: (l: string) => err.push(l),
      record: (r: LandingRecord) => rows.push(r),
    },
  };
}

test("landing CLEAN: t:landing row minted against the PASS-certified rulesHash, executor exit preserved (null)", async () => {
  const dir = fixture("clean");
  seedPass(dir);
  const { opts, rows } = baseOpts(dir);
  const exit = await runLandingVerification({
    ...opts,
    observeRemoteTip: () => SHA_TIP,
    scanRemoteTip: async () => [finding("MEDIUM")],
  });
  assert.equal(exit, null, "clean landing never rewrites the executor exit");
  assert.equal(rows.length, 1);
  assert.equal(rows[0]?.verdict, "clean");
  assert.equal(rows[0]?.blocking, 0);
  assert.equal(rows[0]?.rulesHash, RULES, "landing records the rules that CERTIFIED the push, not a fresh guess");
  assert.equal(rows[0]?.remoteSha, SHA_TIP);
});

test("landing BLOCKED: exit 1 + ALREADY PUBLIC + verdict-blocked fact row", async () => {
  const dir = fixture("blocked");
  seedPass(dir);
  const { opts, err, rows } = baseOpts(dir);
  const exit = await runLandingVerification({
    ...opts,
    observeRemoteTip: () => SHA_TIP,
    scanRemoteTip: async () => [finding("CRITICAL"), finding("HIGH", "exfil-rfc1918:message"), finding("MEDIUM")],
  });
  assert.equal(exit, EXIT_BLOCKED);
  assert.match(err.join("\n"), /ALREADY PUBLIC; border detects, never erases/);
  assert.equal(rows[0]?.verdict, "blocked");
  assert.equal(rows[0]?.blocking, 2);
});

test("landing UNREACHABLE (probe null): exit 2, ZERO rows minted, push records untouched", async () => {
  const dir = fixture("unreachable");
  seedPass(dir);
  const pushLine = `${JSON.stringify({ t: "push", key: KEY, target: "git:origin", remoteName: "origin", url: "origin.example:widgets.git", localSha: "9".repeat(40), remoteSha: SHA_TIP, confirmedVia: "ls-remote", ts: "2026-09-25T00:00:00.000Z" })}\n`;
  appendLedger(dir, pushLine);
  const before = readFileSync(ledgerPath(dir), "utf8");
  const { opts, err, rows } = baseOpts(dir);
  const exit = await runLandingVerification({ ...opts, observeRemoteTip: () => null, scanRemoteTip: async () => [] });
  assert.equal(exit, EXIT_ERROR);
  assert.match(err.join("\n"), /landed, verification unavailable/);
  assert.equal(rows.length, 0, "no verification, no fact — unreachable mints NOTHING");
  const { records, warnings } = readLedger(dir);
  assert.deepEqual(warnings, [], "the untouched ledger still parses clean");
  assert.ok(records.some((r) => r.t === "push" && r.remoteSha === SHA_TIP), "the executed-push record survives byte-faithfully");
  void before;
});

test("landing scan FAILURE (foreign tip unfetchable): exit 2, zero rows", async () => {
  const dir = fixture("scanfail");
  seedPass(dir);
  const { opts, rows } = baseOpts(dir);
  const exit = await runLandingVerification({
    ...opts,
    observeRemoteTip: () => SHA_TIP,
    scanRemoteTip: async () => {
      throw new Error("git fetch exited 128: server does not allow request for unadvertised object");
    },
  });
  assert.equal(exit, EXIT_ERROR);
  assert.equal(rows.length, 0);
});

test("landing refuses to mint against UNKNOWN rules (no PASS under the live key ⇒ fail closed)", async () => {
  const dir = fixture("norules");
  const { opts } = baseOpts(dir);
  await assert.rejects(
    () => runLandingVerification({ ...opts, observeRemoteTip: () => SHA_TIP, scanRemoteTip: async () => [] }),
    /no PASS record under key/,
  );
});

test("landing is APPEND-ONLY: existing ledger bytes stay a prefix; multi-leg records clean-then-blocked in order", async () => {
  const dir = fixture("append");
  seedPass(dir);
  appendLedger(dir, '{"t":"flight","nonsense":true}\n'); // unknown-t line an OLD border would WARNING-skip
  const before = readFileSync(ledgerPath(dir), "utf8");
  const { opts, rows } = baseOpts(dir);
  const second: LandingLeg = { target: { target: "git:backup", url: "backup.example:widgets.git" }, branch: "main" };
  let n = 0;
  const exit = await runLandingVerification({
    ...opts,
    legs: [LEG, second],
    observeRemoteTip: () => SHA_TIP,
    scanRemoteTip: async () => (n++ === 0 ? [] : [finding("CRITICAL")]),
  });
  assert.equal(exit, EXIT_BLOCKED, "the second leg's blocked verdict gates");
  assert.equal(rows.length, 2, "first leg's clean fact was recorded before the blocked one — append-only, never rewrites");
  const after = readFileSync(ledgerPath(dir), "utf8");
  assert.ok(after.startsWith(before), "pre-existing ledger bytes (incl. the executed-push/check rows) are untouched");
  const { records, warnings } = readLedger(dir);
  assert.equal(warnings.length, 1, "unknown-t rows are a loud WARNING + skip, never a crash (forward compat for old readers of landing rows is symmetrical)");
  void records;
  const parsed = parseLedgerRecord({ t: "landing", key: KEY, target: "git:origin", ref: "refs/heads/main", remoteSha: SHA_TIP, verdict: "clean", blocking: 0, rulesHash: RULES, ts: "x" });
  assert.equal(parsed.t, "landing");
});

test("landing record constructor gates shapes (hex, enum, non-negative ints) — mint-site validation", () => {
  const good = { key: KEY, target: "git:origin", ref: "refs/heads/main", remoteSha: SHA_TIP, verdict: "clean" as const, blocking: 0, rulesHash: RULES };
  assert.equal(buildLandingRecord(good).t, "landing");
  assert.throws(() => buildLandingRecord({ ...good, key: "nothex" }), /key is not hex-shaped/);
  assert.throws(() => buildLandingRecord({ ...good, remoteSha: "abc" }), /remoteSha is not hex-shaped/);
  assert.throws(() => buildLandingRecord({ ...good, blocking: -1 }), /non-negative integer/);
  assert.throws(() => buildLandingRecord({ ...good, rulesHash: "z".repeat(64) }), /rulesHash is not hex-shaped/);
  assert.throws(() => parseLedgerRecord({ ...good, key: KEY, t: "landing", verdict: "rolled-back" }), /verdict must be one of clean|blocked/);
});

// ---------------------------------------------------------------- real-git E2E legs

function fixtureRepo(name: string): { repo: string; bare: string; message: string } {
  const repo = fixture(`${name}-repo`);
  const bare = fixture(`${name}-bare`);
  spawnSync("git", ["init", "--bare", "-b", "main", bare], { encoding: "utf8" });
  gitInit(repo);
  const rel = relative(repo, bare);
  writeRel(
    repo,
    "border.yaml",
    `version: 1\ntargets:\n  git:\n    remotes:\n    - name: origin\n      url: ${rel}\nrules:\n  authors:\n    emails: [wiki@sumteclab.com]\n    names: [Wiki.js]\n  hosts: []\n  ips: []\n  pathPatterns: []\n`,
  );
  return { repo, bare, message: rel };
}

async function cli(argv: readonly string[], cwd: string) {
  const out: string[] = [];
  const err: string[] = [];
  const code = await run(argv, (l) => out.push(l), (l) => err.push(l), { cwd, env: { ...process.env } });
  return { code, out, err };
}

test("NO-BYPASS E2E: a message-only leak ⇒ check FAILs ⇒ push --yes is refused pre-flight (nothing pushed, remote untouched)", async () => {
  const { repo, bare } = fixtureRepo("bypass");
  writeRel(repo, "README.md", "benign project notes\n");
  gitAddCommit(repo, "sync the mirror 10.200.30.40 nightly"); // band literal in the MESSAGE ⇒ :message HIGH (tree stays clean)

  const check = await cli(["check", "--force"], repo);
  assert.equal(check.code, EXIT_BLOCKED, "the message facet blocks the gate before any push can even be PENDING");
  // findings render on the stdout channel, the summary line beside them — match the check's actual emit lane, not an assumption
  assert.ok([...check.out, ...check.err].some((l) => l.includes("HIGH exfil-rfc1918:message")));

  const push = await cli(["push", "--yes"], repo);
  assert.equal(push.code, EXIT_BLOCKED, "no PASS under the live key ⇒ every target BLOCKED ⇒ refused, zero push spawned");
  assert.match([...push.out, ...push.err].join("\n"), /refused — .* BLOCKED target/);
  const remoteRefs = spawnSync("git", ["ls-remote", bare], { encoding: "utf8" }).stdout.trim();
  assert.equal(remoteRefs, "", "the bare remote never received a single ref");
});

test("CLEAN PUSH E2E: check PASS ⇒ push --yes lands ⇒ live landing verifies the remote tip and appends the t:landing row; dry-run mints nothing", async () => {
  const { repo, bare } = fixtureRepo("cleanpush");
  writeRel(repo, "README.md", "benign project notes\n");
  gitAddCommit(repo, "init");

  const dry = await cli(["push"], repo);
  assert.match(dry.out.join("\n"), /DRY-RUN/);
  const dryRemote = spawnSync("git", ["ls-remote", bare], { encoding: "utf8" }).stdout.trim();
  assert.equal(dryRemote, "", "dry-run: ZERO fetch-mutation of the remote");
  const dryLedger = readLedger(repo);
  assert.deepEqual(dryLedger.records.filter((r) => r.t === "landing"), [], "dry-run: ZERO landing rows");

  const check = await cli(["check", "--force"], repo);
  assert.equal(check.code, EXIT_PASS, `clean repo must gate PASS: ${[...check.out, ...check.err].join("\n")}`);

  const push = await cli(["push", "--yes"], repo);
  assert.equal(push.code, EXIT_PASS, `push output: ${push.out.join("\n")} / ${push.err.join("\n")}`);
  assert.match(push.out.join("\n"), /landing verified — remote tip .* clean/);
  const head = gitRevParseHead(repo);
  const remoteSha = /^[0-9a-f]{40}/.exec(spawnSync("git", ["ls-remote", bare, "refs/heads/main"], { encoding: "utf8" }).stdout)?.[0];
  assert.equal(remoteSha, head, "the ref really moved on the remote");
  const landings = readLedger(repo).records.filter((r): r is LandingRecord => r.t === "landing");
  assert.equal(landings.length, 1);
  assert.equal(landings[0]?.verdict, "clean");
  assert.equal(landings[0]?.remoteSha, head);
  assert.equal(landings[0]?.ref, "refs/heads/main");
  const pushRows = readLedger(repo).records.filter((r) => r.t === "push");
  assert.equal(pushRows.length, 1, "the executed-push row stands; landing APPENDED beside it");
});
