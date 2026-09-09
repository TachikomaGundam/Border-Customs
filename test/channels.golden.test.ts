// provenance: original clean-room implementation per .omo/plans/border-push-channels.md todo C2
//
// Golden-fingerprint suite for the channel-registry refactor. The goldens were
// captured with /tmp/opencode/golden/capture-deterministic.mjs using the
// fixture recipe below, and pinned as literals. Reproducibility requires two
// things, both encoded here:
//   (1) the fixture commit must be time-fixed (amended with pinned
//       author/committer dates) — the check key embeds headSha, so a
//       wall-clock commit would re-key every run;
//   (2) the key's rulesHash embeds the absolute vendored-config path, which
//       is checkout-location-dependent BY DESIGN (src/redact.ts hashes
//       `file:` + path + digest lines) — so the goldens are valid for a
//       checkout at this repo's location, and the pre/post-refactor
//       comparison must run at one location, not across two trees.
//
// Equivalence evidence (captured pre-refactor from a pristine `git worktree
// add --detach HEAD` checkout, same script):
//   identical across trees: configDigest (expandInConfig/schema rewire),
//   exposureSet (exposure rewire), DRY-RUN stdout + exit (publish core /
//   argv rewire), porcelainDigest, headSha (amend makes it deterministic),
//   engineVersions, vendored-config CONTENT (e163...e1 both). The only
//   divergent key input was rulesHash, differing solely because the vendored
//   config's absolute path string is hashed — a pre-existing
//   location-dependence, not a refactor regression.
//
// Artifact digests are deliberately NOT pinned: sdist/wheel/tgz bytes embed
// build timestamps, so identical builds yield different sha256s run-to-run
// (empirically three different sets on three identical runs). Their FILENAMES
// are pinned via the twine/npm DRY-RUN lines below.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { after, test } from "node:test";

import { buildPypiArtifacts } from "../src/artifacts/pypi.ts";
import { computeEffectiveTargets } from "../src/check/context.ts";
import { computeConfigDigest, stableStringify } from "../src/check/rulesHash.ts";
import { run } from "../src/cli.ts";
import { EXIT_PASS, type BorderExit } from "../src/cli/exit.ts";
import { handlers } from "../src/commands/index.ts";
import { exposureSet, loadConfig } from "../src/config.ts";
import { computeFingerprint } from "../src/ledger.ts";
import { appendRecord, type CheckRecord } from "../src/ledger/records.ts";
import { gitAddCommit, gitInit, gitRevParseHead, makeFixtureDir, removeDir, writeRel } from "./helpers/fixtures.ts";

const roots: string[] = [];
after(() => {
  for (const d of roots) removeDir(d);
});

// R4 re-pin (.omo/plans/border-residue-gate.md Wave-4 gate 4): computeCheckRulesHash
// now digests the residue fingerprint sources (src/check/rulesHash.ts
// RESIDUE_FINGERPRINT_SOURCES + residue config value via configDigest), so the
// key MOVED BY DESIGN — a residue-table edit invalidating the key IS the
// stale-PASS mechanism this pin guards. Old C2-era value:
//   3f167079ac116aadea5fc36ba8bd90f4a24683940a2c6c308eaf8d52c19b6a15
// exposureSet and DRY-RUN stdout goldens are UNTOUCHED — they still prove the
// digest extension drifted nothing else. Re-captured from two identical
// standalone runs at this location (deterministic; same fixture recipe).
const GOLDEN_KEY = "d6b83c4c366a9077e1360247f5a93d8c5026d2ef735809239709578ca5707abc";
const GOLDEN_EXPOSURE = ["https://example.com/origin.git", "npm:widgets@1.0.0", "pypi:pushdemo@0.1.0"];
const GOLDEN_DRYRUN_STDOUT = [
  "border DRY-RUN: no --yes, so nothing runs — this is the plan (m-R5-a) contract",
  "  DRY-RUN: git push --dry-run origin --follow-tags  (https://example.com/origin.git)",
  "  DRY-RUN: npm publish .border/dist/widgets-1.0.0.tgz --registry http://127.0.0.1:9999/",
  "  DRY-RUN: twine upload --repository-url http://127.0.0.1:9999/ .border/dist/pushdemo-0.1.0-py3-none-any.whl .border/dist/pushdemo-0.1.0.tar.gz",
];
const FIXED_COMMIT_DATE = "2026-01-01T00:00:00.000Z";
const EMPTY_COUNTS = {
  INFO: 0,
  LOW: 0,
  MEDIUM: 0,
  HIGH: 0,
  CRITICAL: 0,
  total: 0,
  blocking: 0,
  warnings: 0,
};

function sha256File(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

test("channels golden: check key, exposureSet and DRY-RUN stdout are byte-identical to the post-refactor capture at this location", async () => {
  // ---------------------------------------------------------------- fixture
  const repo = makeFixtureDir("golden-channels");
  roots.push(repo);
  writeRel(repo, ".gitignore", ".border/\n");
  writeRel(
    repo,
    "package.json",
    `${JSON.stringify({ name: "widgets", version: "1.0.0", description: "border C2 golden fixture" }, null, 2)}\n`,
  );
  writeRel(
    repo,
    "pyproject.toml",
    `[build-system]
requires = ["setuptools==78.1.1"]
build-backend = "setuptools.build_meta"

[project]
name = "pushdemo"
version = "0.1.0"

[tool.setuptools.packages.find]
where = ["src"]
`,
  );
  writeRel(repo, "src/pushdemo/__init__.py", '"""Docstring only."""\n');
  writeRel(
    repo,
    "border.yaml",
    `version: 1
targets:
  git:
    remotes:
      - name: origin
        url: https://example.com/origin.git
  npm:
    registry: http://127.0.0.1:9999/
  pypi:
    repository: http://127.0.0.1:9999/
rules:
  authors:
    emails: [wiki@sumteclab.com]
    names: [Wiki.js]
  hosts: []
  ips: []
  pathPatterns: []
  maxFileKB: 500
allow: []
engines:
  require: []
  trufflehog: false
`,
  );
  gitInit(repo);
  gitAddCommit(repo, "init");
  // Pin commit timestamps (both author and committer): the check key embeds
  // headSha, so a wall-clock commit would make this golden unreproducible.
  const amend = spawnSync("git", ["commit", "--amend", "--no-edit", "--reset-author"], {
    cwd: repo,
    encoding: "utf8",
    env: { ...process.env, GIT_AUTHOR_DATE: FIXED_COMMIT_DATE, GIT_COMMITTER_DATE: FIXED_COMMIT_DATE },
  });
  assert.equal(amend.status, 0, amend.stderr);
  const headSha = gitRevParseHead(repo);

  // ---------------------------------------------------------------- artifacts (real bytes, local only)
  const { artifacts: pypiArtifacts } = buildPypiArtifacts({ repoDir: repo });
  const distDir = join(repo, ".border", "dist");
  const npmPack = spawnSync("npm", ["pack", "--silent", "--pack-destination", distDir], {
    cwd: repo,
    encoding: "utf8",
    env: { ...process.env, npm_config_cache: join(repo, ".npm-cache") },
  });
  assert.equal(npmPack.status, 0, npmPack.stderr || npmPack.stdout);
  const tgz = npmPack.stdout.trim().split("\n").pop();
  assert.ok(tgz !== undefined);
  const artifactEntries = [
    { file: `.border/dist/${tgz}`, sha256: sha256File(join(distDir, tgz)) },
    ...pypiArtifacts.map((a) => ({
      file: `.border/dist/${a.path.slice(a.path.lastIndexOf("/") + 1)}`,
      sha256: a.sha256,
    })),
  ].sort((a, b) => (a.file < b.file ? -1 : 1));

  // ---------------------------------------------------------------- key + exposure (loadConfig path, like commands/push.ts)
  const loaded = loadConfig({ configPath: "border.yaml", cwd: repo, env: { ...process.env } });
  assert.equal(loaded.kind, "loaded");
  if (loaded.kind !== "loaded") return;
  const configDigest = computeConfigDigest(loaded);
  const effectiveTargets = computeEffectiveTargets(loaded.config, undefined);
  const { ctx, fp } = await computeFingerprint(repo, loaded.config, configDigest, effectiveTargets, {});
  const exposure = [...exposureSet(loaded.config, { cwd: repo })];

  // ---------------------------------------------------------------- seed a realistic PASS record (covers all three targets)
  const record = {
    t: "check",
    key: fp.key,
    key8: fp.key.slice(0, 8),
    head: headSha,
    dirtyDigest: ctx.porcelainDigest,
    refSetHash: createHash("sha256").update(stableStringify([...ctx.refSet].sort())).digest("hex"),
    exposureSet: exposure,
    effectiveTargets: [...effectiveTargets],
    rulesHash: fp.rulesHash,
    artifacts: artifactEntries,
    llm: false,
    verdict: "PASS",
    counts: EMPTY_COUNTS,
    reportPath: ".border/runs/x/report.json",
    degraded: false,
    ts: FIXED_COMMIT_DATE,
  } satisfies CheckRecord;
  appendRecord(repo, record);

  // ---------------------------------------------------------------- golden assertions
  assert.equal(fp.key, GOLDEN_KEY, "check key changed across the channel-registry refactor");
  assert.deepEqual(exposure, GOLDEN_EXPOSURE, "exposureSet changed across the channel-registry refactor");

  const out: string[] = [];
  const dryExit = await run(["push", "--config", "border.yaml"], (l) => out.push(l), () => {}, {
    cwd: repo,
    env: { ...process.env },
    handlers: { ...handlers, check: async (): Promise<BorderExit> => EXIT_PASS },
  });
  assert.equal(dryExit, EXIT_PASS, `dry-run exit changed (${dryExit})`);
  assert.deepEqual(out, GOLDEN_DRYRUN_STDOUT, "DRY-RUN stdout changed across the channel-registry refactor");
});