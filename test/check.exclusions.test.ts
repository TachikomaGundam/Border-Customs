// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 10
//
// Exclusion-mechanics suite (plan §10): gitleaks has NO exclude flag, so border
// hard-filters findings whose path touches the `.border/` state dir AT INGEST,
// normalising both path shapes the engine produces (git-history leg = repo-
// relative, dir/tree leg = absolute, archive reattribution = `<abs>!<inner>`).
// secretlint already excludes `.border` at listing time — pinned here too.
import assert from "node:assert/strict";
import { join } from "node:path";
import { after, test } from "node:test";

import type { Finding } from "../src/findings.ts";
import { isBorderStatePath, toRepoRelative, filterBorderStateFindings } from "../src/check/exclusions.ts";
import { scanGitHistory, scanTree } from "../src/engines/gitleaks.ts";
import { scanGitTrackedFiles } from "../src/engines/secretlint.ts";
import { requireGitleaks } from "./helpers/require-engines.ts";
import { gitAddCommit, gitInit, makeFixtureDir, randAwsPair, removeDir, writeRel } from "./helpers/fixtures.ts";

requireGitleaks();

const roots: string[] = [];
after(() => {
  for (const d of roots) removeDir(d);
});

function fixture(name: string): string {
  const dir = makeFixtureDir(`exc-${name}`);
  roots.push(dir);
  gitInit(dir);
  return dir;
}

function finding(path: string | undefined): Finding {
  return {
    rule: "test-rule",
    severity: "CRITICAL",
    target: "git",
    engine: "unit",
    message: "m",
    valueDigest: "a".repeat(64),
    snippet: "\u25ae\u25ae\u25ae\u25ae",
    ...(path !== undefined ? { path } : {}),
  };
}

// ------------------------------------------------------------------ pure filters

test("isBorderStatePath: matches the .border segment anywhere, never lookalikes", () => {
  assert.equal(isBorderStatePath(".border/runs/x.json"), true);
  assert.equal(isBorderStatePath("src/.border/x"), true);
  assert.equal(isBorderStatePath(".border"), true);
  assert.equal(isBorderStatePath(".borderignore"), false);
  assert.equal(isBorderStatePath("a/.borderfile"), false);
  assert.equal(isBorderStatePath("src/index.ts"), false);
});

test("toRepoRelative normalises abs-under-repo, keeps relative, tolerates undefined and archive suffixes", () => {
  assert.equal(toRepoRelative(join("/repo", "config/aws.json"), "/repo"), "config/aws.json");
  assert.equal(toRepoRelative("config/aws.json", "/repo"), "config/aws.json");
  assert.equal(toRepoRelative("/repo/.border/tmp/e/inner.txt!deep/nested/x", "/repo"), ".border/tmp/e/inner.txt!deep/nested/x");
  assert.equal(toRepoRelative("/elsewhere/x", "/repo"), "/elsewhere/x");
  assert.equal(toRepoRelative(undefined, "/repo"), null);
  assert.equal(toRepoRelative("", "/repo"), null);
});

test("filterBorderStateFindings drops engine findings on repo-relative AND absolute .border paths", () => {
  const kept = filterBorderStateFindings(
    [finding("config/aws.json"), finding(".border/runs/past.env"), finding(join("/repo/.border/runs/junk/report.json")), finding(undefined), finding("/repo/.border/tmp/e/a.tgz!inner")],
    "/repo",
  );
  assert.deepEqual(kept.map((f) => f.path), ["config/aws.json", undefined]);
});

// ------------------------------------------------------------------ engine legs

test("history leg reports committed .border/ leaks repo-relative; ingest filter empties them (AC1/AC2 basis)", () => {
  const dir = fixture("hist");
  const planted = randAwsPair();
  writeRel(dir, ".border/runs/past.env", planted.text);
  gitAddCommit(dir, "commit border state");
  const raw = scanGitHistory({ repoDir: dir, refRange: "refs/heads/main", target: "git" });
  assert.ok(raw.length >= 1, "engine must have seen the committed secret (proves the filter is load-bearing)");
  assert.ok(raw.every((f) => !f.path?.startsWith("/")), "history leg paths are repo-relative");
  assert.ok(raw.some((f) => f.path === ".border/runs/past.env"));
  assert.deepEqual(filterBorderStateFindings(raw, dir), []);
});

// gitleaks has no exclude flag for the dir/tree leg — the ingest filter is the only gate
test("tree leg on a dirty fixture: .border-only secret ⇒ raw nonempty, filtered empty", () => {
  const dir = fixture("tree2");
  const planted = randAwsPair();
  writeRel(dir, "keep.txt", "clean\n");
  gitAddCommit(dir, "baseline");
  writeRel(dir, ".border/runs/junk/report.json", planted.text);
  const raw = scanTree({ dir, target: "tree" });
  assert.ok(raw.length >= 1, "unplanted run must have caught the .border secret pre-filter");
  assert.ok(raw.every((f) => (f.path ?? "").includes("/.border/")));
  assert.deepEqual(filterBorderStateFindings(raw, dir), []);
});

test("secretlint tracked-file scan skips .border/ at listing time", async () => {
  const dir = fixture("sl");
  const planted = randAwsPair();
  writeRel(dir, ".border/secret.env", planted.text);
  writeRel(dir, "ok.txt", "nothing to see\n");
  gitAddCommit(dir, "border state tracked");
  const findings = await scanGitTrackedFiles({ repoDir: dir, target: "git" });
  assert.deepEqual(findings.filter((f) => (f.path ?? "").split("/").includes(".border")), []);
});
