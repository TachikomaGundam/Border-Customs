// provenance: original clean-room implementation per .omo/plans/border-push-channels.md todo C2
//
// Golden-fingerprint suite for the channel-registry refactor, NORMALIZED per
// W3.2 (.omo/plans/border-inspect-roadmap.md). The single raw-key golden moved
// with the checkout location — rulesHash hashes `kind:<absolute path>:<digest>`
// lines (src/redact.ts), BY DESIGN per-checkout truth — so it was a dev-box
// constant that could never go green on a runner (CI-RUNNER-REDSET-2026-09-09).
// Instead of one opaque hash, the suite now pins every key component and the
// composition separately, each in the strongest environment-portable form:
//   headSha / porcelainDigest / refSet / effectiveTargets — pinned component
//                      by component: the fixture commit is time-fixed (amended
//                      with pinned author/committer dates/identity) and the
//                      porcelain entries collapse to directory lines, so all
//                      four values are checkout-location independent;
//   exposureSet      — never was location-dependent, still pinned verbatim;
//   normalizedRulesHash — rulesHash recomputed over the IDENTICAL line recipe
//                      (config digest, per-file sha256s, engine versions) with
//                      one canonicalization: absolute fingerprint-source paths
//                      are replaced by repo-root-relative labels. Everything
//                      the hash really certifies (rule/classifier bytes, prompt
//                      template bytes, engine versions, effective config) rides
//                      the pin; the checkout path string does not;
//   key composition  — sha256(stableStringify({the six components})) recomputed
//                      independently of computeCheckKey, with the env-local raw
//                      rulesHash plugged in: any field-set/order/serialization
//                      change fails even though the raw key value is env-bound;
//   raw rulesHash    — re-derived via the product recipe so the composition
//                      half cannot silently drift onto a different input.
//
// DRY-RUN stdout + exit and exposureSet keep their verbatim goldens (location
// independent). Artifact digests stay deliberately UNPINNED: sdist/wheel/tgz
// bytes embed build timestamps (npm/pypi carry no normalization story here —
// the filenames ride the DRY-RUN lines). The .gem goldens are normalized in
// test/channels.rubygems.test.ts (W3.2 sibling).
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { after, test } from "node:test";
import { fileURLToPath } from "node:url";

import { buildPypiArtifacts } from "../src/artifacts/pypi.ts";
import { computeEffectiveTargets } from "../src/check/context.ts";
import {
  computeCheckRulesHash,
  computeConfigDigest,
  resolvePromptTemplatePath,
  resolveReleaseFingerprintFiles,
  resolveResidueFingerprintFiles,
  stableStringify,
} from "../src/check/rulesHash.ts";
import { run } from "../src/cli.ts";
import { EXIT_PASS, type BorderExit } from "../src/cli/exit.ts";
import { handlers } from "../src/commands/index.ts";
import { exposureSet, loadConfig } from "../src/config.ts";
import { GITLEAKS_VENDORED_CONFIG } from "../src/engines/gitleaks.ts";
import { probeEngines } from "../src/engines/policy.ts";
import { computeFingerprint } from "../src/ledger.ts";
import { appendRecord, type CheckRecord } from "../src/ledger/records.ts";
import { gitAddCommit, gitInit, gitRevParseHead, makeFixtureDir, removeDir, writeRel } from "./helpers/fixtures.ts";

const roots: string[] = [];
after(() => {
  for (const d of roots) removeDir(d);
});

// W3.2 RE-PIN (.omo/plans/border-inspect-roadmap.md): the raw whole-key golden
// is RETIRED — its value was checkout-location-bound (rulesHash hashes the
// absolute path of every fingerprint source). The pinning below is the same
// certificate decomposed into its environment-portable parts. Rotation
// history of the old raw key (kept for provenance): C2-era
// 3f167079…6a15 → R4 (residue sources folded in) → W4 (releaseCoherence.ts
// folded in) d6b83c4c…7abc → 98c9a1e509a5ffcb4933d432095664fd69413ca5a950fd21ae8f7bf38afa92ef
// (dev-box re-capture, runner never green) → decomposed here.
// Every fingerprint source file, the prompt template, the engine versions and
// the effective config ride GOLDEN_RULES_HASH_NORMALIZED (path canonicalized);
// the fixture state rides the headSha/porcelain/refSet/targets pins; the key
// FORMULA rides the composition recompute in the test body. A residue/release
// table edit STILL invalidates the pin — the file digests moved.
const GOLDEN_HEAD_SHA = "b838689d96b1a1cda8d2919ec3c716f23210a5f2";
const GOLDEN_PORCELAIN_DIGEST = "5782837b399a70eb135d2f1c2ac96ba010ff6e13f1800e14e6b8b9416effd8e3";
const GOLDEN_REFSET = ["refs/heads/main"];
const GOLDEN_EFFECTIVE_TARGETS = ["git", "npm", "pypi"];
const GOLDEN_RULES_HASH_NORMALIZED = "a2b167c44bc8371029647790cc6a836aaecebdd1f17ff9eca3dfa00f6709412d";
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

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/**
 * The src/redact.ts computeRulesHash line recipe with ONE canonicalization:
 * the absolute fingerprint-source path becomes a repo-root-relative label, so
 * the pin certifies config + file contents + engine versions and NOT the
 * checkout location. A source path escaping the checkout fails loudly — the
 * normalized golden is only defined over repo-relative labels.
 */
async function normalizedRulesHash(input: {
  readonly bundledPaths: readonly string[];
  readonly promptPaths: readonly string[];
  readonly configDigest: string;
  readonly engineVersions: Readonly<Record<string, string>>;
}): Promise<string> {
  const label = (p: string): string => {
    const rel = relative(REPO_ROOT, resolve(p));
    assert.ok(rel !== "" && !rel.startsWith("..") && !rel.startsWith("/"), `fingerprint source outside the checkout: ${p}`);
    return rel;
  };
  const lines = [`config:${input.configDigest}`];
  for (const p of input.bundledPaths) lines.push(`rule:${label(p)}:${sha256File(resolve(p))}`);
  for (const p of input.promptPaths) lines.push(`prompt:${label(p)}:${sha256File(resolve(p))}`);
  for (const name of Object.keys(input.engineVersions).sort()) lines.push(`engine:${name}:${input.engineVersions[name]}`);
  lines.sort();
  return createHash("sha256").update(lines.join("\n"), "utf8").digest("hex");
}

test("channels golden: check-key components, normalized rulesHash, exposureSet and DRY-RUN stdout match the W3.2 capture (location-independent)", async () => {
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

  // ---------------------------------------------------------------- golden assertions (W3.2 decomposed)
  assert.deepEqual(exposure, GOLDEN_EXPOSURE, "exposureSet changed across the channel-registry refactor");
  assert.equal(ctx.headSha, GOLDEN_HEAD_SHA, "fixture headSha changed — the time/identity-pinned commit recipe drifted");
  assert.equal(ctx.porcelainDigest, GOLDEN_PORCELAIN_DIGEST, "fixture porcelain digest changed — the builds touched a new untracked path");
  assert.deepEqual([...ctx.refSet], GOLDEN_REFSET, "fixture refSet changed");
  assert.deepEqual([...effectiveTargets], GOLDEN_EFFECTIVE_TARGETS, "effectiveTargets changed");
  // fp.rulesHash is checkout-location-bound BY DESIGN (redact.ts hashes the
  // absolute source paths); pin the recipe live, then the environment-portable
  // NORMALIZED form golden. Rule/classifier/prompt bytes, engines and config
  // all ride the normalized hash — a stale-PASS rotation still moves it.
  const probe = await probeEngines(loaded.config, { env: { ...process.env } });
  assert.equal(probe.degraded, false, "engine probes must be healthy for the golden capture");
  assert.equal(
    fp.rulesHash,
    await computeCheckRulesHash({ engineVersions: probe.engineVersions, configDigest, env: { ...process.env } }),
    "fp.rulesHash is not the product recipe over the probed inputs",
  );
  const templatePath = resolvePromptTemplatePath({ ...process.env });
  assert.equal(
    await normalizedRulesHash({
      bundledPaths: [
        GITLEAKS_VENDORED_CONFIG,
        ...resolveResidueFingerprintFiles({ ...process.env }),
        ...resolveReleaseFingerprintFiles({ ...process.env }),
      ],
      promptPaths: existsSync(templatePath) ? [templatePath] : [],
      configDigest,
      engineVersions: probe.engineVersions,
    }),
    GOLDEN_RULES_HASH_NORMALIZED,
    "normalized rulesHash changed (rule/classifier/prompt bytes, engine versions, or effective config)",
  );
  // Key FORMULA: independent sha256(stableStringify(six fields)) with the
  // env-local raw rulesHash plugged in — field set/name/serialization drift
  // fails even though the raw key value itself is checkout-bound.
  const expectedKey = createHash("sha256").update(
    stableStringify({
      headSha: GOLDEN_HEAD_SHA,
      porcelainDigest: GOLDEN_PORCELAIN_DIGEST,
      rulesHash: fp.rulesHash,
      exposureSet: GOLDEN_EXPOSURE,
      refSet: GOLDEN_REFSET,
      effectiveTargets: GOLDEN_EFFECTIVE_TARGETS,
    }),
  ).digest("hex");
  assert.equal(fp.key, expectedKey, "check key composition changed across the channel-registry refactor");

  const out: string[] = [];
  const dryExit = await run(["push", "--config", "border.yaml"], (l) => out.push(l), () => {}, {
    cwd: repo,
    env: { ...process.env },
    handlers: { ...handlers, check: async (): Promise<BorderExit> => EXIT_PASS },
  });
  assert.equal(dryExit, EXIT_PASS, `dry-run exit changed (${dryExit})`);
  assert.deepEqual(out, GOLDEN_DRYRUN_STDOUT, "DRY-RUN stdout changed across the channel-registry refactor");
});