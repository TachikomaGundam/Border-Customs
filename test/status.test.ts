// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 19
//
// `border status` — informational ledger view: newest check record, per-target
// push table incl. the pending list. Exit 0 whenever the ledger is readable
// (empty ledger included); unreadable ledger fails honestly (exit 2 naming the
// path via cli translateError); malformed lines warn but never crash; ledger
// strings are rendered inert (single-line, whitespace-collapsed).
import assert from "node:assert/strict";
import { chmodSync, existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { after, test } from "node:test";

import { run } from "../src/cli.ts";
import { EXIT_ERROR, EXIT_PASS } from "../src/cli/exit.ts";
import { gatherContext } from "../src/check/context.ts";
import { appendRecord, buildPushRecord, recordCheckRun } from "../src/ledger.ts";
import type { Report } from "../src/findings.ts";
import { gitAddCommit, gitInit, makeFixtureDir, removeDir, writeRel } from "./helpers/fixtures.ts";

const roots: string[] = [];
after(() => {
  for (const d of roots) {
    const ledger = join(d, ".border", "ledger.jsonl");
    if (existsSync(ledger)) chmodSync(ledger, 0o644);
    removeDir(d);
  }
});

function fixture(name: string): string {
  const root = makeFixtureDir(`status-${name}`);
  roots.push(root);
  return root;
}

function cleanRepo(name: string): string {
  const dir = fixture(name);
  gitInit(dir);
  writeRel(dir, "notes.txt", "clean\n");
  gitAddCommit(dir, "seed");
  return dir;
}

function passReport(head: string, total = 0): Report {
  return {
    schemaVersion: 1,
    key: "e".repeat(64),
    head,
    dirty: false,
    exposureSet: ["origin.example/widgets.git"],
    refSet: ["refs/heads/main"],
    rulesHash: "1".repeat(64),
    verdict: "PASS",
    counts: { INFO: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0, total, blocking: 0, warnings: total },
    findings: [],
    ts: "2026-09-04T00:00:00.000Z",
  };
}

async function status(dir: string): Promise<{ code: number; out: string; err: string }> {
  const out: string[] = [];
  const err: string[] = [];
  const code = (await run(["status"], (l) => out.push(l), (l) => err.push(l), { cwd: dir })) as number;
  return { code, out: out.join("\n"), err: err.join("\n") };
}

test("empty ledger ⇒ exit 0, honest 'no runs' line, no crash", async () => {
  const dir = cleanRepo("empty");
  const r = await status(dir);
  assert.equal(r.code, EXIT_PASS);
  assert.match(r.out, /no check runs recorded/i);
});

test("newest check + per-target push table incl. pending list", async () => {
  const dir = cleanRepo("table");
  const ctx = gatherContext(dir, {});
  const rec = recordCheckRun({ repoDir: dir, report: passReport(ctx.headSha), ctx, effectiveTargets: ["git", "npm"], llm: false });
  appendRecord(dir, buildPushRecord({ key: rec.key, target: "git", remoteName: "origin", url: "origin.example:widgets.git", localSha: ctx.headSha, remoteSha: ctx.headSha, confirmedVia: "ls-remote" }));
  const r = await status(dir);
  assert.equal(r.code, EXIT_PASS);
  assert.ok(r.out.includes(rec.key8), `table must show the newest check key8 ${rec.key8}:\n${r.out}`);
  assert.match(r.out, /PASS/);
  assert.match(r.out, /ls-remote/);
  const lines = r.out.split("\n");
  const gitRow = lines.find((l) => l.trim().startsWith("git"));
  const npmRow = lines.find((l) => l.trim().startsWith("npm"));
  assert.ok(gitRow !== undefined && /pushed/.test(gitRow), `git row: ${gitRow}`);
  assert.ok(npmRow !== undefined && /pending/.test(npmRow), `npm row must be pending: ${npmRow}`);
  assert.match(r.out, /pending/i);
});

test("push records under an OLDER key do not mark the newest check as pushed", async () => {
  const dir = cleanRepo("stalekey");
  const ctx = gatherContext(dir, {});
  const rec = recordCheckRun({ repoDir: dir, report: passReport(ctx.headSha), ctx, effectiveTargets: ["git"], llm: false });
  appendRecord(dir, buildPushRecord({ key: "0".repeat(64), target: "git", remoteName: "origin", url: "origin.example:widgets.git", localSha: ctx.headSha, remoteSha: "1".repeat(40), confirmedVia: "ls-remote" }));
  const r = await status(dir);
  assert.equal(r.code, EXIT_PASS);
  const gitRow = r.out.split("\n").find((l) => l.trim().startsWith("git"));
  assert.ok(gitRow !== undefined && /pending/.test(gitRow), `stale-key push must not satisfy ${rec.key8}: ${gitRow}`);
});

test("malformed ledger line: warning on stderr, table still renders, exit 0", async () => {
  const dir = cleanRepo("torn");
  const ctx = gatherContext(dir, {});
  recordCheckRun({ repoDir: dir, report: passReport(ctx.headSha), ctx, effectiveTargets: ["git"], llm: false });
  writeFileSync(join(dir, ".border", "ledger.jsonl"), `{"t":"check","garbage":tru\n`, { flag: "a" });
  const r = await status(dir);
  assert.equal(r.code, EXIT_PASS);
  assert.match(r.err, /WARNING/i);
  assert.match(r.out, /git/);
});

test("hostile ledger strings render inert: one output line per record, no fabricated table rows", async () => {
  const dir = cleanRepo("hostile");
  const ctx = gatherContext(dir, {});
  const rec = recordCheckRun({ repoDir: dir, report: passReport(ctx.headSha), ctx, effectiveTargets: ["git"], llm: false });
  appendRecord(dir, buildPushRecord({ key: rec.key, target: "git", remoteName: "evil|name\nFAKE pending row", url: "origin.example:widgets.git", localSha: ctx.headSha, remoteSha: ctx.headSha, confirmedVia: "ls-remote" }));
  const r = await status(dir);
  assert.equal(r.code, EXIT_PASS);
  assert.ok(!r.out.includes("\nFAKE"), "embedded newline must not inject a table row");
  const fake = r.out.split("\n").filter((l) => l.trim().startsWith("FAKE"));
  assert.equal(fake.length, 0);
  assert.ok(r.out.includes("evil|name"), "hostile text survives as inert content of its own row");
});

test("unreadable ledger fails honestly: exit 2 naming the path", async () => {
  const dir = cleanRepo("locked");
  const ctx = gatherContext(dir, {});
  recordCheckRun({ repoDir: dir, report: passReport(ctx.headSha), ctx, effectiveTargets: [], llm: false });
  const ledger = join(dir, ".border", "ledger.jsonl");
  chmodSync(ledger, 0o000);
  try {
    const r = await status(dir);
    assert.equal(r.code, EXIT_ERROR);
    assert.ok(r.err.includes("ledger.jsonl"), `stderr must name the path: ${r.err}`);
  } finally {
    chmodSync(ledger, 0o644);
  }
});

// ---------------------------------------------------------------------------
// F3 blocker: push records are keyed `git:<name-or-sanitized-url>` (pushstate
// gitLegs), never the bare kind 'git' stored in effectiveTargets. These pin
// status-after-git-push: before the fix all three print the false-pending
// symptom ('git pending — no push record') despite matching records.

function remoteCfg(remotes: string): string {
  return `version: 1\ntargets:\n  git:\n    remotes:\n${remotes}\nrules:\n  authors:\n    emails: []\n    names: []\n  hosts: []\n  ips: []\n  pathPatterns: []\n`;
}

function pushedRepo(name: string, remotes: string, pushed: readonly string[]): { dir: string; key8: string } {
  const dir = cleanRepo(name);
  writeRel(dir, "border.yaml", remoteCfg(remotes));
  const ctx = gatherContext(dir, {});
  const rec = recordCheckRun({ repoDir: dir, report: passReport(ctx.headSha), ctx, effectiveTargets: ["git"], llm: false });
  for (const id of pushed) {
    const remoteName = id.slice("git:".length);
    appendRecord(dir, buildPushRecord({ key: rec.key, target: id, remoteName, url: `origin.example:${remoteName}.git`, localSha: ctx.headSha, remoteSha: ctx.headSha, confirmedVia: "ls-remote" }));
  }
  return { dir, key8: rec.key8 };
}

const ONE_REMOTE = `      - { name: origin, url: "origin.example:widgets.git" }\n`;
const TWO_REMOTES = `${ONE_REMOTE}      - { name: upstream, url: "upstream.example:widgets.git" }\n`;

test("F3: git-only config with named remote + git:origin push record => row shows pushed, never pending", async () => {
  const { dir, key8 } = pushedRepo("f3-pushed", ONE_REMOTE, ["git:origin"]);
  const r = await status(dir);
  assert.equal(r.code, EXIT_PASS);
  const row = r.out.split("\n").find((l) => l.trim().startsWith("git:origin"));
  assert.ok(row !== undefined && /pushed/.test(row), `git:origin must be PUSHED for key ${key8}:\n${r.out}`);
  assert.ok(!/no push record/.test(r.out), `false pending must be gone:\n${r.out}`);
});

test("F3: two named remotes both pushed => both rows pushed (no substring sloppiness)", async () => {
  const { dir } = pushedRepo("f3-both", TWO_REMOTES, ["git:origin", "git:upstream"]);
  const r = await status(dir);
  assert.equal(r.code, EXIT_PASS);
  for (const id of ["git:origin", "git:upstream"]) {
    const row = r.out.split("\n").find((l) => l.trim().startsWith(id));
    assert.ok(row !== undefined && /pushed/.test(row), `${id} must be PUSHED:\n${r.out}`);
  }
  assert.match(r.out, /all effective targets pushed/);
});

test("F3: one of two remotes pushed => per-remote pushed + pending split", async () => {
  const { dir } = pushedRepo("f3-half", TWO_REMOTES, ["git:origin"]);
  const r = await status(dir);
  assert.equal(r.code, EXIT_PASS);
  const originRow = r.out.split("\n").find((l) => l.trim().startsWith("git:origin"));
  const upstreamRow = r.out.split("\n").find((l) => l.trim().startsWith("git:upstream"));
  assert.ok(originRow !== undefined && /pushed/.test(originRow), `git:origin pushed: ${originRow}`);
  assert.ok(upstreamRow !== undefined && /pending/.test(upstreamRow), `git:upstream pending: ${upstreamRow}`);
  assert.match(r.out, /pending targets: git:upstream/);
});
