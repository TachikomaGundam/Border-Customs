// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 14
//
// Ledger unit layer: schema roundtrip, corruption tolerance (plan failure AC:
// bad line ⇒ WARNING + skip, never a crash), skip/scope queries, retention
// (newest 20 run dirs per key8), NO-OP refusal, and the round-1 M8
// artifact-freshness gate. CLI-level PASS→SKIP lifecycle lives in
// test/ledger.check.test.ts.
import assert from "node:assert/strict";
import { existsSync, mkdirSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { after, test } from "node:test";

import type { Report, ReportCounts } from "../src/findings.ts";
import { gatherContext } from "../src/check/context.ts";
import {
  appendRecord,
  buildPushRecord,
  formatSkipLine,
  ledgerPath,
  lookupSkipRecord,
  latestPassCoveringTargets,
  pruneRunDirs,
  readLedger,
  recordCheckRun,
  verifyArtifactFreshness,
  packNpmArtifacts,
  type CheckRecord,
} from "../src/ledger.ts";
import { sanitizeUrl } from "../src/redact.ts";
import { gitAddCommit, gitInit, makeFixtureDir, removeDir, writeRel } from "./helpers/fixtures.ts";

const fixtureRoots: string[] = [];
after(() => {
  for (const d of fixtureRoots) removeDir(d);
});

function fixture(name: string): string {
  const root = makeFixtureDir(`led-${name}`);
  fixtureRoots.push(root);
  return root;
}

const KEY_A = "a".repeat(64);
const KEY_B = "b".repeat(64);
const COUNTS: ReportCounts = { INFO: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0, total: 0, blocking: 0, warnings: 0 };

function checkRecord(o: Partial<CheckRecord> & { key: string }): CheckRecord {
  return {
    t: "check",
    key8: o.key.slice(0, 8),
    head: "c".repeat(40),
    dirtyDigest: "d".repeat(64),
    refSetHash: "e".repeat(64),
    exposureSet: ["git:origin:origin.example:widgets.git"],
    effectiveTargets: ["git"],
    rulesHash: "f".repeat(64),
    artifacts: null,
    llm: false,
    verdict: "PASS",
    counts: COUNTS,
    reportPath: ".border/runs/x/report.json",
    degraded: false,
    ts: "2026-09-04T00:00:00.000Z",
    ...o,
  };
}

test("ledger: append + read roundtrips check and sanitized push records", () => {
  const dir = fixture("roundtrip");
  appendRecord(dir, checkRecord({ key: KEY_A }));
  appendRecord(dir, buildPushRecord({
    key: KEY_A, target: "git", remoteName: "origin",
    url: "https://oauth2:hunter2@git.example/x.git", localSha: "1".repeat(40),
    remoteSha: "2".repeat(40), confirmedVia: "ls-remote",
  }));
  const { records, warnings } = readLedger(dir);
  assert.deepEqual(warnings, []);
  assert.equal(records.length, 2);
  const push = records[1];
  assert.ok(push?.t === "push");
  assert.equal(push.url, sanitizeUrl("https://oauth2:hunter2@git.example/x.git"));
  assert.ok(!push.url.includes("hunter2"), "credential must never reach the ledger (G20)");
  assert.equal(push.remoteSha, "2".repeat(40));
});

test("ledger: corrupt lines are skipped with WARNING, never crash (plan failure AC)", () => {
  const dir = fixture("corrupt");
  appendRecord(dir, checkRecord({ key: KEY_A }));
  writeFileSync(ledgerPath(dir), "not json at all\n", { flag: "a" });
  writeFileSync(ledgerPath(dir), '{"t":"bogus","key":"' + KEY_A + '"}\n', { flag: "a" });
  writeFileSync(ledgerPath(dir), '{"t":"check","key":"short"', { flag: "a" }); // SIGKILL mid-append torn line: no trailing \n
  writeFileSync(ledgerPath(dir), "\n\n", { flag: "a" });
  const { records, warnings } = readLedger(dir);
  assert.equal(records.length, 1, "only the valid record survives");
  assert.equal(records[0]?.key, KEY_A);
  assert.equal(warnings.length, 3);
  for (const w of warnings) assert.match(w, /ledger line \d+ unreadable .* — line skipped/);
  assert.ok(lookupSkipRecord(records, KEY_A, false) !== null, "good records still certify after corruption");
});

test("ledger: hand-forced degraded:true line is rejected as unreadable, never skippable", () => {
  const dir = fixture("degraded");
  const forged = { ...checkRecord({ key: KEY_A }), degraded: true };
  mkdirSync(join(dir, ".border"), { recursive: true });
  writeFileSync(ledgerPath(dir), JSON.stringify(forged) + "\n", { flag: "a" });
  const { records, warnings } = readLedger(dir);
  assert.equal(records.length, 0);
  assert.equal(warnings.length, 1);
});

test("ledger: skip lookup needs newest PASS match, ignores FAIL/other keys/other llm mode", () => {
  const dir = fixture("lookup");
  appendRecord(dir, checkRecord({ key: KEY_A, verdict: "PASS", ts: "2026-09-01T00:00:00.000Z" }));
  appendRecord(dir, checkRecord({ key: KEY_A, verdict: "FAIL", ts: "2026-09-02T00:00:00.000Z" }));
  appendRecord(dir, checkRecord({ key: KEY_B, verdict: "PASS", ts: "2026-09-03T00:00:00.000Z" }));
  const { records } = readLedger(dir);
  assert.equal(lookupSkipRecord(records, KEY_A, false), null, "FAIL is never a skip candidate (plan lookup: verdict PASS)");
  assert.equal(lookupSkipRecord(records, KEY_B, true), null, "non-LLM PASS cannot skip an --llm run (round-1 m7)");
  appendRecord(dir, checkRecord({ key: KEY_A, llm: true, ts: "2026-09-05T00:00:00.000Z" }));
  const again = readLedger(dir).records;
  assert.equal(lookupSkipRecord(again, KEY_A, true)?.ts, "2026-09-05T00:00:00.000Z", "newest matching PASS wins");
});

test("ledger: push-scope rule — git-only PASS never covers npm (round-1 B2)", () => {
  const dir = fixture("scope");
  appendRecord(dir, checkRecord({ key: KEY_A, effectiveTargets: ["git"] }));
  const { records } = readLedger(dir);
  assert.ok(latestPassCoveringTargets(records, KEY_A, ["git"]) !== null);
  assert.equal(latestPassCoveringTargets(records, KEY_A, ["git", "npm"]), null);
  assert.equal(latestPassCoveringTargets(records, KEY_A, ["npm"]), null);
  appendRecord(dir, checkRecord({ key: KEY_A, effectiveTargets: ["git", "npm"], ts: "2026-09-06T00:00:00.000Z" }));
  const again = readLedger(dir).records;
  assert.equal(latestPassCoveringTargets(again, KEY_A, ["npm"])?.ts, "2026-09-06T00:00:00.000Z");
});

test("ledger: SKIP line format is exactly `SKIP <key8> — PASS <ts> report <path>` (D6)", () => {
  const line = formatSkipLine(checkRecord({
    key: "1234abcd" + "0".repeat(56),
    ts: "2026-09-04T10:11:12.000Z",
    reportPath: ".border/runs/1234abcd-2026-09-04T10-11-12-000Z/report.json",
  }));
  assert.equal(line, "SKIP 1234abcd — PASS 2026-09-04T10:11:12.000Z report .border/runs/1234abcd-2026-09-04T10-11-12-000Z/report.json");
});

test("ledger: recordCheckRun refuses to certify a NO-OP report", async () => {
  const dir = fixture("noop");
  gitInit(dir);
  writeRel(dir, "a.txt", "x\n");
  gitAddCommit(dir, "init");
  const noopReport = {
    schemaVersion: 1, key: KEY_A, head: "c".repeat(40), dirty: false,
    exposureSet: [], refSet: [], rulesHash: "f".repeat(64), verdict: "NO-OP",
    counts: COUNTS, findings: [], ts: "2026-09-04T00:00:00.000Z",
  } satisfies Report;
  const ctx = await gatherContext(dir);
  assert.throws(
    () => recordCheckRun({ repoDir: dir, report: noopReport, ctx, effectiveTargets: ["git"], llm: false }),
    /NO-OP/,
  );
  assert.ok(!existsSync(ledgerPath(dir)), "refusal must not leave a ledger file behind");
});

test("ledger: retention keeps the newest 20 run dirs per key8 (plan AC, 25 seeded)", () => {
  const dir = fixture("retention");
  const mk = (key8: string, i: number) =>
    mkdirSync(join(dir, ".border", "runs", `${key8}-2026-01-${String(i).padStart(2, "0")}T00-00-00-000Z`), { recursive: true });
  for (let i = 1; i <= 25; i += 1) mk("aaaaaaaa", i);
  for (let i = 1; i <= 3; i += 1) mk("bbbbbbbb", i);
  const removed = pruneRunDirs(dir, "aaaaaaaa");
  assert.equal(removed.length, 5);
  const left = readdirSync(join(dir, ".border", "runs")).filter((e) => e.startsWith("aaaaaaaa-"));
  assert.equal(left.length, 20);
  assert.ok(left.includes("aaaaaaaa-2026-01-25T00-00-00-000Z"), "newest survives");
  assert.ok(!left.includes("aaaaaaaa-2026-01-01T00-00-00-000Z"), "oldest is collected");
  assert.equal(readdirSync(join(dir, ".border", "runs")).filter((e) => e.startsWith("bbbbbbbb-")).length, 3, "other key8 untouched");
  assert.equal(pruneRunDirs(join(fixture("empty-retention")), "cccccccc").length, 0, "no runs dir yet ⇒ no-op");
});

// ---------------------------------------------------------------- artifact freshness (round-1 M8)

test("freshness: git-only runs skip without repack, even dirty", async () => {
  const dir = fixture("fresh-git");
  gitInit(dir);
  writeRel(dir, "a.txt", "clean\n");
  gitAddCommit(dir, "init");
  const ctx = await gatherContext(dir);
  assert.equal(verifyArtifactFreshness(checkRecord({ key: KEY_A }), ctx, dir), true);
});

test("freshness: npm runs need a clean tree + digest-identical repack (gitignored-but-packed hole)", async () => {
  const dir = fixture("fresh-npm");
  gitInit(dir);
  writeRel(dir, "package.json", JSON.stringify({ name: "widgets", version: "1.0.0", files: ["dist/"] }) + "\n");
  writeRel(dir, "dist/a.js", "export const a = 1;\n");
  writeRel(dir, ".gitignore", "dist/b.txt\n");
  gitAddCommit(dir, "init");
  const ctx = await gatherContext(dir);
  const artifacts = packNpmArtifacts(dir);
  assert.ok(artifacts !== null && artifacts.length === 1);
  const record = checkRecord({ key: KEY_A, effectiveTargets: ["git", "npm"], artifacts });

  assert.equal(verifyArtifactFreshness(record, ctx, dir), true, "identical tarball digest ⇒ skip honored");

  writeRel(dir, "dist/b.txt", "built artifact, gitignored but PACKED via files:[dist/]\n");
  const ctx2 = await gatherContext(dir); // still porcelain-clean: dist/b.txt is gitignored
  assert.equal(ctx2.dirty, false, "fixture must leave git blind to the packed change — that IS the M8 hole");
  assert.equal(verifyArtifactFreshness(record, ctx2, dir), false, "repack digest mismatch ⇒ full re-check");

  rmSync(join(dir, "dist", "b.txt"));
  assert.equal(verifyArtifactFreshness(record, await gatherContext(dir), dir), true, "back to the certified payload");

  const dirtyRecord = checkRecord({ key: KEY_A, effectiveTargets: ["npm"], artifacts: null });
  writeRel(dir, "scratch.tmp", "dirt\n");
  assert.equal(verifyArtifactFreshness(dirtyRecord, await gatherContext(dir), dir), false, "artifact runs never skip on a dirty tree");
});

test("freshness: pypi-only proof degrades to key match (non-reproducible builds, round-2 LOW)", async () => {
  const dir = fixture("fresh-pypi");
  gitInit(dir);
  writeRel(dir, "pyproject.toml", "[project]\nname='w'\n");
  gitAddCommit(dir, "init");
  const ctx = await gatherContext(dir);
  assert.equal(verifyArtifactFreshness(checkRecord({ key: KEY_A, effectiveTargets: ["pypi"] }), ctx, dir), true);
  writeRel(dir, "scratch.tmp", "dirt\n");
  assert.equal(verifyArtifactFreshness(checkRecord({ key: KEY_A, effectiveTargets: ["pypi"] }), await gatherContext(dir), dir), false);
});
