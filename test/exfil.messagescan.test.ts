// provenance: .omo/plans/border-exfil-lens.md T3 — messageScan suite:
// doctrine tests run through the injected runGit seam (happy will-publish
// range, unresolvable endpoint ⇒ whole ref, REV_BATCH chunk boundary
// 401⇒3 calls, seam failures propagate — no false-greens), and one REAL-git
// fixture proves the argv/format plumbing end to end: a commit-message red
// (synthetic 10.200.x IP) while the tree stays clean.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { after, test } from "node:test";

import { ConfigError } from "../src/channels/errors.ts";
import { MESSAGE_GIT_TIMEOUT_MS, MESSAGE_REV_BATCH, scanCommitMessages, willPublishShas } from "../src/check/messageScan.ts";
import { scanExfilTree } from "../src/check/exfilTreeScan.ts";
import type { MessageGitRunner } from "../src/check/messageScan.ts";
import { gitAddCommit, gitInit, makeFixtureDir, removeDir, writeRel } from "./helpers/fixtures.ts";

const roots: string[] = [];
after(() => {
  for (const d of roots) removeDir(d);
});

function fixture(name: string): string {
  const dir = makeFixtureDir(`exmsg-${name}`);
  roots.push(dir);
  return dir;
}

const SHA_A = "a".repeat(40);
const SHA_B = "b".repeat(40);
const SHA_E = "e".repeat(40);
const REF = "refs/heads/main";

/** %x1e%H%x00%B record shape — the exact bytes the real spawner will produce. */
function record(sha: string, message: string): string {
  return `\x1e${sha}\x00${message}\n`;
}

type Stub = { readonly run: MessageGitRunner; readonly calls: string[][] };

function stubGit(respond: (args: readonly string[]) => string): Stub {
  const calls: string[][] = [];
  return {
    calls,
    run: (args) => {
      calls.push([...args]);
      return respond(args);
    },
  };
}

function probeRev(candidate: string): string {
  return `rev-parse --verify --quiet ${candidate}`;
}

test("happy range: endpoint resolves ⇒ ONLY endpoint..ref is scanned; sha attribution + :message ids", () => {
  const stub = stubGit((args) => {
    const j = args.join(" ");
    if (j === probeRev(REF)) return `${SHA_E}\n`;
    if (j === probeRev("refs/remotes/origin/refs/heads/main")) throw new ConfigError("git-failed", "absent"); // full-name form missing
    if (j === probeRev("refs/remotes/origin/main")) return `${SHA_E}\n`; // conventional short found
    if (j === `rev-list refs/remotes/origin/main..${REF}`) return `${SHA_A}\n${SHA_B}\n`;
    if (args[0] === "log" && args[1] === "--no-walk") return record(SHA_A, "deploy via 10.200.30.40 mirror") + record(SHA_B, "docs: tidy");
    throw new Error(`unexpected git args: ${j}`);
  });
  const findings = scanCommitMessages({
    repoDir: "/unused-with-seam",
    refSet: [REF],
    remotes: [{ url: "origin.example:widgets.git", name: "origin" }],
    runGit: stub.run,
  });
  assert.deepEqual(findings.map((f) => [f.rule, f.severity, f.path]), [["exfil-rfc1918:message", "HIGH", SHA_A]]);
  assert.equal(findings[0]?.commit, SHA_A);
  assert.equal(findings[0]?.engine, "border-exfil");
  const revList = stub.calls.filter((c) => c[0] === "rev-list");
  assert.equal(revList.length, 1, "exactly one range enumeration");
  assert.deepEqual(revList[0], ["rev-list", `refs/remotes/origin/main..${REF}`], "endpoint..ref — already-public commits never re-quoted");
});

test("no-endpoint: remote never had the ref ⇒ the WHOLE ref is about to be published (identity.ts:144-146)", () => {
  const stub = stubGit((args) => {
    const j = args.join(" ");
    if (j === probeRev(REF)) return `${SHA_E}\n`;
    if (j.startsWith(probeRev("refs/remotes/origin/"))) throw new ConfigError("git-failed", "absent");
    if (j === `rev-list ${REF}`) return `${SHA_A}\n`;
    if (args[0] === "log") return record(SHA_A, "chore: nothing sensitive here");
    throw new Error(`unexpected git args: ${j}`);
  });
  const findings = scanCommitMessages({
    repoDir: "/unused-with-seam",
    refSet: [REF],
    remotes: [{ url: "https://example.invalid/w.git", name: "origin" }],
    runGit: stub.run,
  });
  assert.deepEqual(findings, []);
  const revList = stub.calls.find((c) => c[0] === "rev-list");
  assert.deepEqual(revList, ["rev-list", REF], "whole-ref enumeration, no range syntax");
});

test("chunk boundary: 401 will-publish shas ⇒ exactly 3 --no-walk calls of 200/200/1", () => {
  const shas = Array.from({ length: 401 }, (_, i) => (i + 10).toString(16).padStart(40, "0"));
  const stub = stubGit((args) => {
    const j = args.join(" ");
    if (j === probeRev(REF)) return shas[0] ?? "";
    if (j === `rev-list ${REF}`) return `${shas.join("\n")}\n`;
    if (args[0] === "log" && args[1] === "--no-walk") {
      const batch = args.slice(3);
      return batch.map((s) => record(s, `commit ${String(s.slice(0, 4))} ships to 10.200.${String(batch.length)}.7`)).join("");
    }
    throw new Error(`unexpected git args: ${j}`);
  });
  const findings = scanCommitMessages({ repoDir: "/unused", refSet: [REF], remotes: [], runGit: stub.run });
  const logs = stub.calls.filter((c) => c[0] === "log");
  assert.equal(logs.length, 3, "REV_BATCH=200 chunking (identity.ts:88 doctrine under the 60s cap)");
  assert.deepEqual(logs.map((c) => c.length - 3), [200, 200, 1]);
  assert.equal(findings.length, 401, "every chunk's message was actually scanned");
});

test("a failing spawn PROPAGATES as ConfigError — no silent empty-success anywhere in the leg", () => {
  const boom = stubGit((args) => {
    const j = args.join(" ");
    if (j === probeRev(REF)) return `${SHA_E}\n`;
    throw new ConfigError("git-failed", `git ${j} exited 128`);
  });
  assert.throws(
    () => scanCommitMessages({ repoDir: "/unused", refSet: [REF], remotes: [], runGit: boom.run }),
    (err: unknown) => err instanceof ConfigError,
  );
});

test("discipline constants: REV_BATCH=200, per-call timeout strictly under the 60s context cap", () => {
  assert.equal(MESSAGE_REV_BATCH, 200);
  assert.ok(MESSAGE_GIT_TIMEOUT_MS < 60_000, `${String(MESSAGE_GIT_TIMEOUT_MS)}ms must stay under 60s`);
});

test("REAL git E2E: commit-message red while the tree stays clean (fixture contract, plan §判据)", () => {
  const dir = fixture("e2e");
  gitInit(dir);
  writeRel(dir, "README.md", "benign project notes\n");
  gitAddCommit(dir, "sync the mirror 10.200.30.40 nightly");
  writeRel(dir, "docs.md", "more benign text\n");
  gitAddCommit(dir, "docs: only benign prose here");

  const shas = willPublishShas(
    (args) => {
      const r = spawnSync("git", ["-C", dir, ...args], { encoding: "utf8" });
      if (r.status !== 0) throw new ConfigError("git-failed", `git ${args.join(" ")}: ${r.stderr}`);
      return r.stdout;
    },
    [REF],
    [],
  );
  assert.equal(shas.length, 2, "whole-ref: both commits");

  const findings = scanCommitMessages({ repoDir: dir, refSet: [REF], remotes: [] });
  assert.equal(findings.length, 1);
  const f = findings[0];
  assert.equal(f?.rule, "exfil-rfc1918:message");
  assert.equal(f?.severity, "HIGH");
  assert.ok(!f?.message.includes("10.200.30.40"), "G23: the finding never carries the raw address");
  const r1 = spawnSync("git", ["-C", dir, "log", "--format=%H"], { encoding: "utf8" }).stdout.trim().split("\n");
  assert.equal(f?.path, r1[1], "attribution = the offending commit sha (the FIRST commit, carrying the IP)");
  assert.deepEqual(scanExfilTree({ repoDir: dir }), [], "tree facet provably clean while the message facet reddens");
});
