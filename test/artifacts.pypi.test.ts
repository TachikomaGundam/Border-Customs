// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 12
//
// PyPI artifact-pipeline acceptance suite. REAL `python3 -m build` /
// `python3 -m twine check` / gitleaks / secretlint run end-to-end against
// generated fixture repos under gitignored test/tmp/ (never stubbed — todo 1
// culture). Plan ACs pinned here:
//   * planted src/secrets_in_data.py + MANIFEST.in ⇒ CRITICAL via sdist scan,
//     AND the finding SURVIVES filterBorderStateFindings(findings, repoDir)
//     despite the extraction sandbox living under <repo>/.border/ (paths are
//     artifact-inner-relative — the false-green trap this todo exists to avoid);
//   * unexplained sdist entry (untracked ghost.py inside a package dir — the
//     G17/G18/G42 ".gitignore-blind sdist" class) ⇒ HIGH sdist-unexpected-file;
//   * broken RST README ⇒ HIGH twine-check (fail = finding, not crash);
//   * clean fixture ⇒ PASS with sha256 artifact records (build-once G38);
//   * stale dist ⇒ wiped, never scanned; double run is idempotent;
//   * python3 absent on PATH (stub env) ⇒ PypiPrerequisiteError naming
//     'python3 -m build' (border exit 2), and broken pyproject ⇒ typed
//     EngineRunError, never a silent PASS.
// Fresh AWS-shaped keys come from randAwsPair (fixed literals get
// content-deduped by gitleaks across fixtures; secretlint builtin-ignores
// 'AKIAIOSFODNN7EXAMPLE'). The PLAN AC literal AKIAI4Q3EXAMPL3K7X2Q is used
// for the pinned happy fixture only (regex-shaped AKIA+16, not a builtin
// example value).
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { basename, join } from "node:path";
import { after, test } from "node:test";

import { filterBorderStateFindings } from "../src/check/exclusions.ts";
import { PypiPrerequisiteError, buildPypiArtifacts, scanPyPiArtifacts } from "../src/artifacts/pypi.ts";
import { computeVerdict, type Finding } from "../src/findings.ts";
import { EngineRunError } from "../src/engines/support.ts";
import { TextSanitizer } from "../src/redact.ts";
import { gitAddCommit, gitInit, makeFixtureDir, randAwsPair, removeDir, writeRel } from "./helpers/fixtures.ts";

const AC_KEY = "AKIAI4Q3EXAMPL3K7X2Q"; // AKIA + exactly 16 [A-Z0-9], not a secretlint example value

const roots: string[] = [];
after(() => {
  for (const dir of roots) removeDir(dir);
});

function fixtureDir(): string {
  const dir = makeFixtureDir("pypi");
  roots.push(dir);
  gitInit(dir);
  writeRel(dir, ".gitignore", ".border/\n__pycache__/\nbuild/\nsrc/*.egg-info/\n");
  return dir;
}

const BUILD_SYSTEM = `[build-system]
requires = ["setuptools==78.1.1"]
build-backend = "setuptools.build_meta"
`;

const SRC_LAYOUT = `${BUILD_SYSTEM}
[project]
name = "secrets-pkg"
version = "1.0.0"
readme = "README.md"
requires-python = ">=3.10"

[tool.setuptools.packages.find]
where = ["src"]
`;

function commitAll(dir: string): void {
  gitAddCommit(dir, "fixture baseline");
}

/** Plan AC fixture: secret at src root pulled in ONLY via MANIFEST.in (untracked —
 *  the G17 trap), plus an untracked ghost.py inside the package (unexplained sdist entry). */
function secretFixture(): { dir: string; ghostKey: string } {
  const dir = fixtureDir();
  writeRel(dir, "pyproject.toml", SRC_LAYOUT);
  writeRel(dir, "README.md", "# secrets-pkg\n\nPlain package for the PyPI pipeline AC.\n");
  writeRel(dir, "src/secrets_pkg/__init__.py", '"""Docstring only."""\n');
  writeRel(dir, "MANIFEST.in", "include src/secrets_in_data.py\n");
  commitAll(dir);
  // planted AFTER the commit — .gitignore never hides these from setuptools' sdist walk
  writeRel(dir, "src/secrets_in_data.py", `AWS_KEY = "${AC_KEY}"\n`);
  const ghostKey = randAwsPair().key;
  writeRel(dir, "src/secrets_pkg/ghost.py", `GHOST_KEY = "${ghostKey}"\n`);
  return { dir, ghostKey };
}

function byRule(findings: readonly Finding[], rule: string): Finding[] {
  return findings.filter((f) => f.rule === rule);
}

test("AC1 happy: planted MANIFEST.in secret ⇒ CRITICAL surviving the repo-scoped .border filter", async () => {
  const { dir, ghostKey } = secretFixture();
  const sanitizer = new TextSanitizer();
  const { artifacts, findings } = await scanPyPiArtifacts({ repoDir: dir, sanitizer });

  // build-once record: both artifacts, content-addressed
  assert.equal(artifacts.length, 2);
  const kinds = artifacts.map((a) => a.kind).sort();
  assert.deepEqual(kinds, ["sdist", "wheel"]);
  for (const a of artifacts) {
    assert.match(a.sha256, /^[0-9a-f]{64}$/);
    assert.equal(createHash("sha256").update(readFileSync(a.path)).digest("hex"), a.sha256);
  }

  // the AC: CRITICAL secret finding attributed to the artifact-inner path
  const leak = findings.filter((f) => f.severity === "CRITICAL" && f.path === "src/secrets_in_data.py");
  assert.ok(leak.length >= 1, "planted key must surface as CRITICAL on its inner path");
  assert.ok(leak.some((f) => f.engine === "gitleaks" && f.rule === "aws-access-token"));
  assert.ok(leak.some((f) => f.engine === "secretlint"));
  assert.equal(computeVerdict(findings), "FAIL");

  // G17: untracked ghost.py rode the package walk into the sdist, unexplained
  const ghosts = byRule(findings, "sdist-unexpected-file");
  assert.equal(ghosts.length, 1, "exactly one unexplained sdist entry (secrets_in_data.py is MANIFEST-explained)");
  assert.equal(ghosts[0]?.path, "src/secrets_pkg/ghost.py");
  assert.equal(ghosts[0]?.severity, "HIGH");
  assert.equal(ghosts[0]?.engine, "pypi-manifest");
  // the ghost key itself also surfaces as a scanned CRITICAL, on both engines
  assert.ok(findings.some((f) => f.engine === "gitleaks" && f.path === "src/secrets_pkg/ghost.py" && f.severity === "CRITICAL"));

  // THE TRAP (repo-relative .border drop): the orchestrator filters with repoDir,
  // while extraction sandboxes lived under <repo>/.border/tmp/. No finding path
  // may carry a .border segment or an absolute sandbox path, and the filter must
  // drop NOTHING.
  for (const f of findings) {
    assert.ok(f.path !== undefined && !f.path.split("/").includes(".border") && !f.path.startsWith("/"));
  }
  assert.equal(filterBorderStateFindings(findings, dir).length, findings.length);

  // G23: no raw secret bytes in any finding; sanitizer scrubbed the registered values
  for (const f of findings) {
    assert.ok(!JSON.stringify(f).includes(AC_KEY));
    assert.ok(!JSON.stringify(f).includes(ghostKey));
  }
  assert.match(sanitizer.sanitize(`leaked ${AC_KEY} in prose`), /\[REDACTED:[0-9a-f]{8}\]/);

  // round-2 m3: every sandbox removed; only empty scaffolding may remain
  const tmpDir = join(dir, ".border", "tmp");
  if (existsSync(tmpDir)) assert.deepEqual(readdirSync(tmpDir), []);
});

test("dedupe: one secret in sdist AND wheel ⇒ one merged finding per (rule, relpath, digest)", async () => {
  const dir = fixtureDir();
  const key = randAwsPair().key;
  writeRel(dir, "pyproject.toml", `${BUILD_SYSTEM}
[project]
name = "flmod"
version = "0.1.0"
`);
  writeRel(dir, "flmod/__init__.py", `FL_KEY = "${key}"\n`); // flat layout: identical inner path in both artifacts
  commitAll(dir);

  const { findings } = await scanPyPiArtifacts({ repoDir: dir });
  const gk = findings.filter((f) => f.engine === "gitleaks" && f.path === "flmod/__init__.py");
  assert.equal(gk.length, 1, "sdist-scan + wheel-scan duplicate must collapse to one gitleaks finding");
  const sl = findings.filter((f) => f.engine === "secretlint" && f.path === "flmod/__init__.py");
  assert.equal(sl.length, 1);
  // dedupe key sanity: the merged set has unique rule\0path\0digest triples
  const keys = findings.map((f) => `${f.rule}\u0000${f.path}\u0000${f.valueDigest}`);
  assert.equal(new Set(keys).size, keys.length);
  assert.equal(computeVerdict(findings), "FAIL");
});

test("AC3 clean fixture: PASS with recorded artifact hashes; stale dist never scanned; idempotent rerun", async () => {
  const dir = fixtureDir();
  writeRel(dir, "pyproject.toml", `${BUILD_SYSTEM}
[project]
name = "cleanpkg"
version = "2.3.4"
readme = "README.md"

[tool.setuptools.packages.find]
where = ["src"]
`);
  writeRel(dir, "README.md", "# clean\n\nNothing secret here.\n");
  writeRel(dir, "src/cleanpkg/__init__.py", '"""Clean."""\n');
  commitAll(dir);

  // stale-state adversarial: a junk artifact left by a previous (different) build
  const distDir = join(dir, ".border", "dist");
  mkdirSync(distDir, { recursive: true });
  writeFileSync(join(distDir, "stale-junk-0.0.1.tar.gz"), "not even a tarball");

  const first = await scanPyPiArtifacts({ repoDir: dir });
  assert.deepEqual([...first.findings], []);
  assert.equal(computeVerdict(first.findings), "PASS");
  assert.deepEqual(first.artifacts.map((a) => a.kind).sort(), ["sdist", "wheel"]);
  assert.ok(first.artifacts.every((a) => a.sha256.match(/^[0-9a-f]{64}$/) !== null));
  assert.equal(existsSync(join(distDir, "stale-junk-0.0.1.tar.gz")), false, "stale dist must be wiped before build");

  // Idempotence is per-run integrity, NOT byte-identical rebuilds (zip/tar carry
  // build timestamps): every recorded sha256 must equal a fresh hash of the file
  // the SAME run produced, artifact names must be stable, and no stale junk or
  // accumulation may survive.
  const second = await scanPyPiArtifacts({ repoDir: dir });
  assert.deepEqual(second.artifacts.map((a) => basename(a.path)).sort(), first.artifacts.map((a) => basename(a.path)).sort());
  for (const a of second.artifacts) {
    assert.equal(createHash("sha256").update(readFileSync(a.path)).digest("hex"), a.sha256);
  }
  assert.deepEqual(readdirSync(distDir).sort(), second.artifacts.map((a) => basename(a.path)).sort());
  assert.deepEqual(second.findings, []);
});

test("AC4 twine gate: broken RST README ⇒ HIGH twine-check, fail is a finding not a crash", async () => {
  const dir = fixtureDir();
  writeRel(dir, "pyproject.toml", `${BUILD_SYSTEM}
[project]
name = "rstpkg"
version = "0.1.0"
readme = "README.rst"

[tool.setuptools.packages.find]
where = ["src"]
`);
  writeRel(dir, "README.rst", "Title\n=====\n\n.. bad-directive:: nope\n\nOver-short underline\n----\n");
  writeRel(dir, "src/rstpkg/__init__.py", '"""Doc."""\n');
  commitAll(dir);

  const { findings } = await scanPyPiArtifacts({ repoDir: dir });
  const twine = byRule(findings, "twine-check");
  assert.ok(twine.length >= 1, "broken long_description must produce a twine-check finding");
  assert.ok(twine.every((f) => f.severity === "HIGH" && f.engine === "twine"));
  const flagged = new Set(twine.map((f) => f.path));
  assert.ok([...flagged].some((p) => p !== undefined && p.endsWith(".whl")), "wheel failure flagged on its basename");
  assert.ok([...flagged].some((p) => p !== undefined && p.endsWith(".tar.gz")), "sdist failure flagged on its basename");
  assert.equal(computeVerdict(findings), "FAIL");
  // no secret findings expected in this fixture — the pipeline must not invent any
  assert.equal(findings.filter((f) => f.severity === "CRITICAL").length, 0);
});

test("manifest-diff scope: unexplained entry reported once from the sdist only", async () => {
  const { dir } = secretFixture();
  const { findings } = await scanPyPiArtifacts({ repoDir: dir });
  const ghosts = byRule(findings, "sdist-unexpected-file");
  assert.equal(ghosts.length, 1, "wheel contains the same ghost but the manifest-diff is sdist-anchored");
});

test("prerequisite: python3 absent from PATH ⇒ PypiPrerequisiteError naming 'python3 -m build' (exit 2)", async () => {
  const { dir } = secretFixture();
  const stub = makeFixtureDir("pypi-nopython-stub");
  roots.push(stub); // empty dir: no python3 on PATH, and HOME stub kills the ~/.local/bin fallback
  const env = { PATH: stub, HOME: stub };
  for (const run of [
    async () => scanPyPiArtifacts({ repoDir: dir, env }),
    async () => buildPypiArtifacts({ repoDir: dir, env }),
  ]) {
    await assert.rejects(
      run(),
      (err: unknown) =>
        err instanceof PypiPrerequisiteError &&
        err.exitCode === 2 &&
        /python3 -m build/.test(err.message) &&
        !err.message.includes(dir), // G23: absolute fixture paths (and thus nothing secret-shaped) need not appear
    );
  }
});

test("build failure (malformed pyproject) ⇒ typed EngineRunError, never a silent PASS", async () => {
  const dir = fixtureDir();
  writeRel(dir, "pyproject.toml", "[[[ this is not valid toml\n");
  commitAll(dir);
  await assert.rejects(
    scanPyPiArtifacts({ repoDir: dir }),
    (err: unknown) => err instanceof EngineRunError && /build/.test(err.message),
  );
});
