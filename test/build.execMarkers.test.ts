// provenance: build-stage consent wave (ruling sibyl-20261023T112953Z-7ada,
// must_fix "prove the bytes-only path invokes zero toolchains via the marker
// fixture on every channel"). One repo whose pypi backend, build.rs and
// gemspec each touch a marker file WHEN EXECUTED:
//   * withheld consent ⇒ exit 0, three `build-stage-withheld` MEDIUMs, record
//     artifacts null, and ZERO markers on disk — the scan-only promise, pinned;
//   * consented (--allow-builds) ⇒ the setup.py and gemspec markers
//     EXIST (the stages genuinely ran), while the cargo marker NEVER exists —
//     `cargo package --allow-dirty --no-verify` is pinned non-executing.
// npm is deliberately absent: its pack-phase hole is pinned end-to-end in
// test/artifacts.npmSafety.test.ts, and on npm < 11 the whole npm stage must
// refuse (EngineRunError ⇒ exit 2), which would starve the other channels in
// this shared fixture. Registries ride loopback stubs (todo 13: no public
// network); crates rides the CRATES_IO_URL probe seam.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { after, test } from "node:test";

import { run } from "../src/cli.ts";
import { EXIT_BLOCKED, EXIT_PASS } from "../src/cli/exit.ts";
import { BUILD_WITHHELD_RULE } from "../src/check/buildConsent.ts";
import { readLedger, type CheckRecord } from "../src/ledger.ts";
import { requireGitleaks, requirePythonBuild } from "./helpers/require-engines.ts";
import { gitAddCommit, gitInit, makeFixtureDir, removeDir, writeRel } from "./helpers/fixtures.ts";
import { startRegistryStub, type RegistryStub } from "./helpers/registry-stub.ts";

function requireGem(): void {
  const r = spawnSync("gem", ["--version"], { encoding: "utf8" });
  if (r.error !== undefined || r.status !== 0) {
    throw new Error(`ENGINE MISSING: gem (RubyGems) not found (${String(r.error ?? r.stderr)}). install ruby-full before running this suite.`);
  }
}
function requireCargo(): void {
  const r = spawnSync("cargo", ["--version"], { encoding: "utf8" });
  if (r.error !== undefined || r.status !== 0) {
    throw new Error(`ENGINE MISSING: cargo not found (${String(r.error ?? r.stderr)}). install rustup before running this suite.`);
  }
}

requireGitleaks();
requirePythonBuild();
requireGem();
requireCargo();

const stubs: RegistryStub[] = [];
const roots: string[] = [];
after(async () => {
  for (const s of stubs) await s.close();
  for (const d of roots) removeDir(d);
});

async function trioStubs(): Promise<{ pypi: RegistryStub; crates: RegistryStub; rubygems: RegistryStub }> {
  const pypi = await startRegistryStub([
    { path: "/pypi/b1w-markers-py/1.0.0/json", status: 404 },
    { path: "/pypi/b1w-markers-py/json", status: 404 },
  ]);
  const crates = await startRegistryStub([
    { path: "/api/v1/crates/b1w_markers_crate/0.1.0", status: 404, raw: JSON.stringify({ errors: [{ detail: "crate `b1w_markers_crate` does not have a version `0.1.0`" }] }) },
    { path: "/api/v1/crates/b1w_markers_crate", status: 404, raw: JSON.stringify({ errors: [{ detail: "crate `b1w_markers_crate` does not exist" }] }) },
  ]);
  const rubygems = await startRegistryStub([
    { path: "/api/v2/rubygems/b1w-markers-gem/versions/1.0.0.json", status: 404, raw: "This version could not be found." },
    { path: "/api/v1/gems/b1w-markers-gem.json", status: 404, raw: "This rubygem could not be found." },
  ]);
  stubs.push(pypi, crates, rubygems);
  return { pypi, crates, rubygems };
}

function yaml(stubs: { pypi: RegistryStub; rubygems: RegistryStub }): string {
  return [
    "version: 1",
    "targets:",
    "  git:",
    "    remotes:",
    "      - name: origin",
    "        url: origin.example:b1w.git",
    "  pypi:",
    `    repository: ${stubs.pypi.url}/`,
    "  crates: {}",
    "  rubygems:",
    `    host: ${stubs.rubygems.url}`,
    "rules:",
    "  authors:",
    "    emails: [bot@gate-corp.com]",
    "    names: [Wiki.js]",
    "  hosts: []",
    "  ips: []",
    "  pathPatterns: []",
    "engines:",
    "  require: [gitleaks, secretlint]",
    "  trufflehog: false",
    "",
  ].join("\n");
}

const PYPROJECT = `[build-system]
requires = ["setuptools==78.1.1"]
build-backend = "setuptools.build_meta"

[project]
name = "b1w-markers-py"
version = "1.0.0"
readme = "README.md"
`;

const GEMSPEC = `File.write("GEMSPEC-RAN", "1")
Gem::Specification.new do |s|
  s.name = "b1w-markers-gem"
  s.version = "1.0.0"
  s.summary = "consent marker fixture"
  s.description = "build-stage consent fixture"
  s.authors = ["Marker Tester"]
  s.email = ["marker@example.com"]
  s.files = ["lib/b1w.rb"]
  s.require_paths = ["lib"]
  s.homepage = "https://example.com/b1w"
  s.license = "MIT"
end
`;

function fixture(): string {
  const dir = makeFixtureDir("b1w-markers");
  roots.push(dir);
  gitInit(dir);
  writeRel(dir, ".gitignore", ".border/\nbuild/\n__pycache__/\n*.egg-info/\ntarget/\nCARGO_TARGET_DIR/\n");
  writeRel(dir, "pyproject.toml", PYPROJECT);
  writeRel(dir, "setup.py", 'import pathlib\npathlib.Path("SETUP-PY-RAN").write_text("1")\nfrom setuptools import setup\nsetup()\n');
  writeRel(dir, "README.md", "# b1w\n");
  writeRel(dir, "b1w_markers_py/__init__.py", '"""Clean."""\n');
  writeRel(dir, "Cargo.toml", '[package]\nname = "b1w_markers_crate"\nversion = "0.1.0"\nedition = "2021"\n');
  writeRel(dir, "src/lib.rs", "pub fn ok() -> u32 {\n    1\n}\n");
  writeRel(dir, "build.rs", 'fn main() {\n    std::fs::write("CARGO-BUILDRS-RAN", "1").unwrap();\n}\n');
  writeRel(dir, "b1w-markers-gem.gemspec", GEMSPEC);
  writeRel(dir, "lib/b1w.rb", "module B1w\nend\n");
  return dir;
}

type Cli = { readonly code: number; readonly out: readonly string[]; readonly err: readonly string[] };

async function cli(dir: string, yamlText: string, env: NodeJS.ProcessEnv, extra: readonly string[]): Promise<Cli> {
  writeRel(dir, "border.yaml", yamlText);
  if (existsSync(join(dir, ".git"))) {
    const r = spawnSync("git", ["add", "border.yaml"], { cwd: dir, encoding: "utf8" });
    assert.equal(r.status, 0, r.stderr);
    const c = spawnSync("git", ["commit", "-m", "config"], { cwd: dir, encoding: "utf8" });
    assert.equal(c.status, 0, c.stderr);
  }
  const out: string[] = [];
  const err: string[] = [];
  const code = (await run(["check", ...extra], (l) => out.push(l), (l) => err.push(l), { cwd: dir, env })) as number;
  return { code, out, err };
}

const MARKERS = ["SETUP-PY-RAN", "CARGO-BUILDRS-RAN", "GEMSPEC-RAN"] as const;

function checkRecords(dir: string): readonly CheckRecord[] {
  return readLedger(dir).records.filter((r): r is CheckRecord => r.t === "check");
}

test("withheld consent ⇒ zero marker touched, three withheld findings, record certifies no artifacts", { timeout: 300_000 }, async () => {
  const dir = fixture();
  const stubs = await trioStubs();
  gitAddCommit(dir, "init");
  const env: NodeJS.ProcessEnv = { ...process.env, CRATES_IO_URL: `${stubs.crates.url}/` };
  const r = await cli(dir, yaml(stubs), env, ["--force"]);
  assert.equal(r.code, EXIT_PASS, `withheld run must scan cleanly: ${[...r.out, ...r.err].join("\n")}`);
  for (const m of MARKERS) assert.equal(existsSync(join(dir, m)), false, `marker ${m} must NOT exist without consent`);
  const rec = checkRecords(dir).at(-1);
  assert.ok(rec !== undefined, "a PASS record must be written");
  const report = JSON.parse(readFileSync(join(dir, rec.reportPath), "utf8")) as {
    findings: { rule: string; severity: string; target?: string }[];
    artifacts?: unknown;
  };
  const withheld = report.findings.filter((f) => f.rule === BUILD_WITHHELD_RULE);
  assert.deepEqual(
    withheld.map((f) => f.target).sort(),
    ["crates", "pypi", "rubygems"],
    "every configured build channel must stay visible as a withheld finding",
  );
  assert.ok(withheld.every((f) => f.severity === "MEDIUM"), "withheld findings are audit-visible MEDIUMs");
  assert.equal(report.artifacts ?? null, null, "a scan-only PASS records no artifact digests");
  assert.equal(rec.artifacts, null, "the ledger record itself carries null artifacts");
});

test("consented run ⇒ pypi/gem markers prove execution, cargo marker proves non-execution", { timeout: 600_000 }, async () => {
  const dir = fixture();
  const stubs = await trioStubs();
  gitAddCommit(dir, "init");
  const env: NodeJS.ProcessEnv = { ...process.env, CRATES_IO_URL: `${stubs.crates.url}/` };
  const r = await cli(dir, yaml(stubs), env, ["--force", "--allow-builds"]);
  // exit 1 is the STAGES WORKING: the consented crates stage statically flags
  // the fixture's out-of-OUT_DIR build.rs write (residue-out-of-tree-write).
  // The withheld phase above cannot see that rule — the stage never ran there.
  assert.equal(r.code, EXIT_BLOCKED, `consented run must reach the stage verdicts: ${[...r.out, ...r.err].join("\n")}`);
  assert.ok(r.out.some((l) => l.includes("residue-out-of-tree-write") && l.includes("build.rs")), "the crates stage must flag the fixture build.rs");
  assert.equal(existsSync(join(dir, "SETUP-PY-RAN")), true, "consented pypi stage must execute the repo build backend");
  assert.equal(existsSync(join(dir, "GEMSPEC-RAN")), true, "consented rubygems stage must evaluate the gemspec");
  assert.equal(existsSync(join(dir, "CARGO-BUILDRS-RAN")), false, "cargo package --no-verify must NEVER execute build.rs");
  const rec = checkRecords(dir).at(-1);
  assert.ok(rec !== undefined && rec.artifacts !== null && rec.artifacts.length > 0, "consented FAIL must still certify artifact digests");
});
