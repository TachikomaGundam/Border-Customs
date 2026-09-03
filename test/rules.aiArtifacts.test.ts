// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 8
//
// Acceptance tests for the closed-list AI-session/env/notebook/binary/large
// detectors against REAL throwaway git fixtures under test/tmp/ (gitignored).
// The scanner only ever touches the fixture through read-only git plumbing;
// GIT_CEILING_DIRECTORIES fencing (fixtures.ts) keeps these runs out of
// border's own repository.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { test } from "node:test";

import { validateFinding, type Finding } from "../src/findings.ts";
import { redact, TextSanitizer } from "../src/redact.ts";
import { scanAiArtifacts } from "../src/rules/aiArtifacts.ts";
import {
  gitAddCommit,
  gitInit,
  gitRevParseHead,
  gitRmCommit,
  makeFixtureDir,
  removeDir,
  writeRel,
} from "./helpers/fixtures.ts";

/** raw git escape hatch (branch surgery) — same ceiling fence as fixtures.ts */
function git(cwd: string, args: readonly string[]): string {
  if (!existsSync(join(cwd, ".git"))) {
    throw new Error(`fixture ${cwd} is not a git repo — refusing to run git with upward discovery`);
  }
  const r = spawnSync("git", [...args], {
    cwd,
    encoding: "utf8",
    env: { ...process.env, GIT_CEILING_DIRECTORIES: dirname(cwd) },
  });
  if (r.status !== 0) {
    throw new Error(`git ${args.join(" ")} failed (${String(r.status)}): ${r.stderr}`);
  }
  return r.stdout ?? "";
}

/** the scanner's documented dedupe key */
function keyOf(f: Finding): string {
  return `${f.rule}:${f.path ?? ""}`;
}

function assertWellFormed(findings: readonly Finding[]): void {
  for (const f of findings) {
    validateFinding(f);
    assert.equal(f.engine, "ai-artifacts");
    assert.equal(f.target, "git");
    if (f.commit !== undefined) {
      assert.match(f.commit, /^[0-9a-f]{40}$/, "commit must be a full sha when present");
    }
  }
  const keys = findings.map(keyOf);
  assert.equal(new Set(keys).size, keys.length, `duplicate (rule,path) findings: ${keys.join(", ")}`);
}

function notebookJson(withOutputs: boolean): string {
  return JSON.stringify({
    cells: [
      {
        cell_type: "code",
        source: ["print(1)"],
        outputs: withOutputs ? [{ output_type: "stream", text: ["1\n"] }] : [],
        execution_count: withOutputs ? 1 : null,
      },
    ],
    metadata: {},
    nbformat: 4,
    nbformat_minor: 5,
  });
}

test("AC1: every closed-list category fires EXACTLY once on a kitchen-sink fixture", () => {
  const repo = makeFixtureDir("aiac1");
  try {
    // one hit per category + decoys that must stay silent
    writeRel(repo, "README.md", "# clean repo\n");
    writeRel(repo, "src/index.ts", "export const ok = 1;\n");
    writeRel(repo, ".env.example", "API_KEY=\n");
    writeRel(repo, ".env.sample", "API_KEY=\n");
    writeRel(repo, ".omo/plans/plan.md", "planner state\n");
    writeRel(repo, "agent/transcripts/session-42.json", "{}\n");
    writeRel(repo, "notes/notes.session.jsonl", "{}\n");
    writeRel(repo, "opencode.json", "{}\n");
    writeRel(repo, ".opencode/agents/helper.md", "# helper\n");
    writeRel(repo, ".env", "AWS_TOKEN=abc123\n");
    writeRel(repo, "deploy/.env.production", "TOKEN=xyz\n");
    writeRel(repo, "analysis.ipynb", notebookJson(true));
    writeRel(repo, "scratch.ipynb", notebookJson(false));
    writeRel(repo, "broken.ipynb", "{not valid json");
    writeRel(repo, "probe_kvnet.py", "print('probe')\n");
    writeRel(repo, "patch.rej", "@@\n");
    writeRel(repo, "merge.orig", "orig\n");
    writeRel(repo, "node_modules/left-pad/index.js", "module.exports = 1;\n");
    writeRel(repo, "assets/logo.png", Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x00, 0x01, 0x02]));
    writeRel(repo, "data/big.csv", "x".repeat(513_000)); // > 500KB default
    writeRel(repo, ".border/committed.env", "SECRET=excluded-from-native-rules\n");
    gitInit(repo);
    gitAddCommit(repo, "kitchen sink");
    const head = gitRevParseHead(repo);

    const findings = scanAiArtifacts({ repoDir: repo });
    assertWellFormed(findings);

    const byKey = new Map(findings.map((f) => [keyOf(f), f]));
    const expected = [
      ["ai-session-artifact", ".omo/plans/plan.md"],
      ["ai-session-artifact", "agent/transcripts/session-42.json"],
      ["ai-session-artifact", "notes/notes.session.jsonl"],
      ["ai-session-artifact", "opencode.json"],
      ["ai-session-artifact", ".opencode/agents/helper.md"],
      ["env-file-committed", ".env"],
      ["env-file-committed", "deploy/.env.production"],
      ["notebook-outputs", "analysis.ipynb"],
      ["junk-artifact", "probe_kvnet.py"],
      ["junk-artifact", "patch.rej"],
      ["junk-artifact", "merge.orig"],
      ["junk-artifact", "node_modules/left-pad/index.js"],
      ["checked-in-binary", "assets/logo.png"],
      ["oversized-file", "data/big.csv"],
    ] as const;
    const expectedKeys = expected.map(([r, p]) => `${r}:${p}`).sort();
    assert.deepEqual(
      [...byKey.keys()].sort(),
      expectedKeys,
      "findings must equal the category matrix exactly",
    );
    // single-commit fixture: every hit is HEAD-resident (tree leg)
    for (const f of findings) {
      assert.equal(f.commit, head, `finding ${keyOf(f)} must cite the HEAD commit`);
    }
    const severityOf = new Map(findings.map((f) => [f.rule, f.severity]));
    assert.equal(severityOf.get("ai-session-artifact"), "CRITICAL");
    assert.equal(severityOf.get("env-file-committed"), "CRITICAL");
    assert.equal(severityOf.get("notebook-outputs"), "MEDIUM");
    assert.equal(severityOf.get("junk-artifact"), "MEDIUM");
    assert.equal(severityOf.get("checked-in-binary"), "HIGH");
    assert.equal(severityOf.get("oversized-file"), "MEDIUM");
  } finally {
    removeDir(repo);
  }
});

test("AC1-dedupe: path added twice in history AND present at HEAD yields one finding citing HEAD", () => {
  const repo = makeFixtureDir("aidup");
  try {
    writeRel(repo, ".omo/loop.json", "v1\n");
    gitInit(repo);
    gitAddCommit(repo, "first add");
    const firstSha = gitRevParseHead(repo);
    gitRmCommit(repo, ".omo/loop.json", "delete");
    writeRel(repo, ".omo/loop.json", "v2\n");
    gitAddCommit(repo, "second add");
    const head = gitRevParseHead(repo);

    const findings = scanAiArtifacts({ repoDir: repo });
    assertWellFormed(findings);
    const hits = findings.filter((f) => keyOf(f) === "ai-session-artifact:.omo/loop.json");
    assert.equal(hits.length, 1, "tree hit + two history additions must dedupe to one finding");
    assert.equal(hits[0]?.commit, head, "HEAD-resident path reports HEAD, not an old add");
    assert.notEqual(firstSha, head);
  } finally {
    removeDir(repo);
  }
});

test("AC2: .env removed at HEAD but present in history still fires via the history pathspec", () => {
  const repo = makeFixtureDir("aiah2");
  try {
    writeRel(repo, "src/app.ts", "export const a = 1;\n");
    writeRel(repo, ".env", "STRIPE_KEY=sk_live_secret\n");
    gitInit(repo);
    gitAddCommit(repo, "add app and env");
    const leakSha = gitRevParseHead(repo);
    gitRmCommit(repo, ".env", "remove env from tree");
    assert.notEqual(gitRevParseHead(repo), leakSha);

    const findings = scanAiArtifacts({ repoDir: repo });
    assertWellFormed(findings);
    const env = findings.filter((f) => f.rule === "env-file-committed");
    assert.equal(env.length, 1);
    assert.equal(env[0]?.path, ".env");
    assert.equal(env[0]?.commit, leakSha, "history-only finding must carry the commit that ADDED the path");
    assert.equal(env[0]?.severity, "CRITICAL");
  } finally {
    removeDir(repo);
  }
});

test("AC3: clean fixture yields zero rule-8 findings; .env.example/.env.sample must NOT fire", () => {
  const repo = makeFixtureDir("aiclean");
  try {
    writeRel(repo, "README.md", "# clean\n");
    writeRel(repo, ".env.example", "DATABASE_URL=\n");
    writeRel(repo, ".env.sample", "DATABASE_URL=\n");
    writeRel(repo, "docs/session-summary.md", "the word session appears here\n");
    writeRel(repo, "scripts/observer.ts", "export const x = 1;\n");
    writeRel(repo, "ipynb/empty-cells.ipynb", notebookJson(false));
    writeRel(repo, "ipynb/corrupt.ipynb", "{ definitely not json ");
    writeRel(repo, "src/transcript-reader.ts", "export const read = 1;\n");
    gitInit(repo);
    gitAddCommit(repo, "clean tree");

    assert.deepEqual(scanAiArtifacts({ repoDir: repo }), []);

    // empty repo (no commits, no refs) is also a legal zero-finding input
    const empty = makeFixtureDir("aiempty");
    try {
      gitInit(empty);
      assert.deepEqual(scanAiArtifacts({ repoDir: empty }), []);
    } finally {
      removeDir(empty);
    }
  } finally {
    removeDir(repo);
  }
});

test("AC4: maxFileKB is cfg-driven with a strict > boundary, and pathPatterns ride the same code path", () => {
  const repo = makeFixtureDir("aicfg4");
  try {
    writeRel(repo, "exact.bin", "a".repeat(1024)); // == 1KB: NOT oversized
    writeRel(repo, "over.bin", "b".repeat(1025)); //  > 1KB: oversized
    writeRel(repo, "internal/runbook.md", "ops\n");
    writeRel(repo, "scratch/tmp/notes.txt", "temp\n");
    gitInit(repo);
    gitAddCommit(repo, "sized files");

    const findings = scanAiArtifacts({
      repoDir: repo,
      cfg: {
        maxFileKB: 1,
        pathPatterns: [
          "internal/**",
          { pattern: "scratch\\tmp\\**", severity: "MEDIUM", message: "windows-style scratch dir" },
        ],
      },
    });
    assertWellFormed(findings);
    const byKey = new Map(findings.map((f) => [keyOf(f), f]));
    assert.equal(byKey.size, 3, `expected exactly 3 findings, got ${[...byKey.keys()].join(", ")}`);
    assert.equal(byKey.get("oversized-file:over.bin")?.severity, "MEDIUM");
    assert.ok(!byKey.has("oversized-file:exact.bin"), "size === maxFileKB must NOT fire (strict >)");
    const userPattern = byKey.get("path-pattern:internal/runbook.md");
    assert.ok(userPattern);
    assert.equal(userPattern.severity, "CRITICAL", "bare-string pathPatterns default to CRITICAL (G35 closed-list addition vehicle)");
    const winPattern = byKey.get("path-pattern:scratch/tmp/notes.txt");
    assert.ok(winPattern, "backslash pattern must normalize to POSIX and match");
    assert.equal(winPattern.severity, "MEDIUM", "object entry fires at declared severity");
    assert.equal(winPattern.message, "windows-style scratch dir");
  } finally {
    removeDir(repo);
  }
});

test("refSet scoping: branch-only artifact fires with default refs, skipped when refSet excludes the branch", () => {
  const repo = makeFixtureDir("airefs");
  try {
    writeRel(repo, "README.md", "# main\n");
    gitInit(repo);
    gitAddCommit(repo, "clean main");
    git(repo, ["checkout", "-q", "-b", "feature"]);
    writeRel(repo, ".omo/branch-state.json", "leaked on branch\n");
    gitAddCommit(repo, "branch commit with omo state");
    git(repo, ["checkout", "-q", "main"]);

    const all = scanAiArtifacts({ repoDir: repo });
    assertWellFormed(all);
    const branchHit = all.filter((f) => f.path === ".omo/branch-state.json");
    assert.equal(branchHit.length, 1, "default refSet = all refs must reach the branch");
    assert.match(branchHit[0]?.commit ?? "", /^[0-9a-f]{40}$/);

    const scoped = scanAiArtifacts({ repoDir: repo, refSet: ["refs/heads/main"] });
    assert.deepEqual(scoped, [], "explicit refSet without the branch yields nothing");
  } finally {
    removeDir(repo);
  }
});

test("G23: findings are digest+snippet over the path only; sanitizer registry receives each path", () => {
  const repo = makeFixtureDir("airedact");
  try {
    writeRel(repo, ".env", "TOKEN=topsecretvalue\n");
    gitInit(repo);
    gitAddCommit(repo, "env file");

    const sanitizer = new TextSanitizer();
    const findings = scanAiArtifacts({ repoDir: repo, sanitizer });
    assertWellFormed(findings);
    assert.equal(findings.length, 1);
    const f = findings[0] as Finding;
    assert.match(f.valueDigest, /^[0-9a-f]{64}$/);
    assert.equal(f.valueDigest, redact(".env").valueDigest, "digest is over the normalized path");
    assert.equal(f.snippet, redact(".env").snippet, "short paths carry the full mask, never the literal");
    // the path was registered with the sanitizer for free-text scrubbing
    assert.notEqual(sanitizer.sanitize("mentions .env here"), "mentions .env here");
    assert.ok(!JSON.stringify(findings).includes("topsecretvalue"), "file CONTENT never rides on a finding");
  } finally {
    removeDir(repo);
  }
});
