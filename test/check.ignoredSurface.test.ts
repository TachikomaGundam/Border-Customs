// provenance: 2026-11-08 owner escalation — the ignored-surface demotion's facet
// discipline is the whole safety case: ignored+untracked demotes, everything that can
// actually reach a push (tracked, committed-history, artifact bytes) stays blocking.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { test } from "node:test";

import { demoteIgnoredUntracked, IGNORED_SURFACE_NOTE } from "../src/check/ignoredSurface.ts";
import type { Finding } from "../src/findings.ts";
import { gitAddCommit, gitInit, makeFixtureDir, removeDir, writeRel } from "./helpers/fixtures.ts";

function dig(s: string): string {
  return createHash("sha256").update(s).digest("hex");
}

function f(over: Partial<Finding>): Finding {
  return {
    rule: "generic-api-key",
    severity: "CRITICAL",
    target: "tree",
    engine: "gitleaks",
    message: "hit",
    valueDigest: dig("v"),
    snippet: "snip",
    ...over,
  };
}

function world(): { dir: string; cleanup: () => void } {
  const dir = makeFixtureDir("ignored-surface");
  gitInit(dir);
  writeRel(dir, ".gitignore", "/evidence/\ncommitted-anyway.txt\n");
  writeRel(dir, "committed-anyway.txt", "tracked despite the ignore rule\n");
  writeRel(dir, "clean.txt", "clean\n");
  // force-add: `git add -A` honours .gitignore (the very premise of this module),
  // so a tracked-but-ignored file can only exist via -f.
  spawnSync("git", ["-C", dir, "add", "-f", "committed-anyway.txt"], { encoding: "utf8" });
  gitAddCommit(dir, "seed");
  // untracked + ignored (git add honours .gitignore, so these never reach a commit):
  writeRel(dir, "evidence/run-1/report.json", '{"head":"a".repeat(40)}\n');
  return { dir, cleanup: () => removeDir(dir) };
}

test("ignored+untracked tree finding demotes to INFO with the named note, rule id untouched", () => {
  const { dir, cleanup } = world();
  try {
    const abs = f({ path: join(dir, "evidence/run-1/report.json") });
    const rel = f({ path: "evidence/run-1/report.json", valueDigest: dig("rel") });
    const findings = [abs, rel];
    const demoted = demoteIgnoredUntracked(findings, dir);
    assert.equal(demoted, 2);
    for (const hit of findings) {
      assert.equal(hit.severity, "INFO");
      assert.equal(hit.rule, "generic-api-key", "rule id must survive untouched (allow-list vocabulary stays stable)");
      assert.ok(hit.message.endsWith(IGNORED_SURFACE_NOTE), hit.message);
    }
  } finally {
    cleanup();
  }
});

test("facet discipline: history findings, channel-target findings, and INFO rows never demote", () => {
  const { dir, cleanup } = world();
  try {
    const history = f({ path: "evidence/run-1/report.json", commit: "c".repeat(40), valueDigest: dig("h") });
    const artifact = f({ path: join(dir, "evidence/run-1/report.json"), target: "npm", valueDigest: dig("a") });
    const already = f({ path: join(dir, "evidence/run-1/report.json"), severity: "INFO", valueDigest: dig("i") });
    const findings = [history, artifact, already];
    const demoted = demoteIgnoredUntracked(findings, dir);
    assert.equal(demoted, 0);
    assert.equal(history.severity, "CRITICAL", "a committed blob is push surface forever, whatever .gitignore says today");
    assert.equal(artifact.severity, "CRITICAL", "artifact bytes are exactly what ships");
  } finally {
    cleanup();
  }
});

test("tracked-but-ignored stays FULLY blocking (it is on the pushable surface by definition)", () => {
  const { dir, cleanup } = world();
  try {
    const hit = f({ path: join(dir, "committed-anyway.txt") });
    const demoted = demoteIgnoredUntracked([hit], dir);
    assert.equal(demoted, 0);
    assert.equal(hit.severity, "CRITICAL");
  } finally {
    cleanup();
  }
});

test("archive attribution demotes on the OUTER path", () => {
  const { dir, cleanup } = world();
  try {
    const hit = f({ path: "evidence/run-1/report.json!inner/blob" });
    const demoted = demoteIgnoredUntracked([hit], dir);
    assert.equal(demoted, 1);
    assert.equal(hit.severity, "INFO");
  } finally {
    cleanup();
  }
});

test("a nested git clone under the ignored tree demotes via the ancestor directory entry", () => {
  const { dir, cleanup } = world();
  try {
    // the Sibyl shape: .omo/evidence/<audit>/raw/sibyl-remote-clone/ carries its OWN
    // .git — git lists it as ONE ignored directory entry and never enumerates inside.
    spawnSync("git", ["-C", dir, "init", "-q", "evidence/clone"], { encoding: "utf8" });
    writeRel(dir, "evidence/clone/probes.test.js", "const key = 'AKIAIOSFODNN7EXAMPLE';\n");
    const hit = f({ path: join(dir, "evidence/clone/probes.test.js"), valueDigest: dig("n") });
    const demoted = demoteIgnoredUntracked([hit], dir);
    assert.equal(demoted, 1, "nested-repo files under an ignored ancestor must demote too");
    assert.equal(hit.severity, "INFO");
  } finally {
    cleanup();
  }
});

test("no findings to demote ⇒ zero git bookkeeping, zero changes", () => {
  const { dir, cleanup } = world();
  try {
    const clean = f({ path: "clean.txt" });
    const demoted = demoteIgnoredUntracked([clean], dir);
    assert.equal(demoted, 0);
    assert.equal(clean.severity, "CRITICAL");
  } finally {
    cleanup();
  }
});
