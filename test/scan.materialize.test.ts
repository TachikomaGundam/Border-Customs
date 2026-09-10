// provenance: border-inspect-roadmap.md W1.2 — `border scan` materializer.
//
// The channels' stage() reads manifests from git HEAD (`git show HEAD:` —
// src/channels/npm.ts:62) and, for crates/gem/pypi, REBUILDS from a committed
// working tree. Hence materialize = mkdtemp → extract the fetched artifact →
// strip the ecosystem's wrapper root → git init/add/commit. Archives are
// generated at RUNTIME with system tar/gzip (zero binary fixtures in git);
// planted marker strings are benign-shaped per test/helpers/fixtures.ts
// doctrine (documentation echo lines, never runnable persistence code).
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { gzipSync } from "node:zlib";
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { after, test } from "node:test";

import { makeFixtureDir, removeDir } from "./helpers/fixtures.ts";
import { materializePackage } from "../src/scan/materialize.ts";

const roots: string[] = [];
after(() => {
  for (const d of roots) removeDir(d);
});

function base(name: string): string {
  const dir = makeFixtureDir(`scanmat-${name}`);
  roots.push(dir);
  return dir;
}

/** `tar -czf <out> -C <stageDir> <entries…>` — GNU tar, present on this machine. */
function tarGz(out: string, stageDir: string, entries: readonly string[]): void {
  const r = spawnSync("tar", ["-czf", out, "-C", stageDir, ...entries], { encoding: "utf8" });
  assert.equal(r.status, 0, `tar -czf failed: ${r.stderr}`);
}

function tarPlain(out: string, stageDir: string, entries: readonly string[]): void {
  const r = spawnSync("tar", ["-cf", out, "-C", stageDir, ...entries], { encoding: "utf8" });
  assert.equal(r.status, 0, `tar -cf failed: ${r.stderr}`);
}

function gitOut(repoDir: string, args: readonly string[]): string {
  return spawnSync("git", ["-C", repoDir, ...args], { encoding: "utf8" }).stdout.trim();
}

/** Sorted repo-relative tree, .git excluded (what materialize must NOT own). */
function relTree(dir: string, prefix = ""): string[] {
  const out: string[] = [];
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    if (e.name === ".git") continue;
    const rel = prefix.length === 0 ? e.name : `${prefix}/${e.name}`;
    if (e.isDirectory()) out.push(...relTree(join(dir, rel), rel));
    else if (e.isFile()) out.push(rel);
  }
  return out.sort();
}

function expectCommitted(repoDir: string): void {
  assert.equal(gitOut(repoDir, ["rev-parse", "--show-toplevel"]), repoDir, "repoDir is its own repo (ceiling-fenced)");
  assert.equal(gitOut(repoDir, ["log", "-1", "--format=%ae"]), "border@local");
  assert.equal(gitOut(repoDir, ["log", "-1", "--format=%s"]), "border scan");
}

const PKG_JSON = JSON.stringify({ name: "eviltwin", version: "1.0.0", bin: { evil: "bin/evil.sh" } });
// Benign-shaped T4 marker: an echo'd documentation string. The residue
// classifier matches the literal `crontab`; nothing here ever executes.
const BIN_DOC = "#!/bin/sh\necho \"upstream docs mention crontab for scheduling\"\n";

// ------------------------------------------------------------------ npm tgz

test("npm .tgz with package/ wrapper is stripped to the repo root and committed", () => {
  const b = base("npm");
  const stage = join(b, "stage");
  mkdirSync(join(stage, "package", "bin"), { recursive: true });
  writeFileSync(join(stage, "package", "package.json"), PKG_JSON);
  writeFileSync(join(stage, "package", "bin", "evil.sh"), BIN_DOC);
  const archive = join(b, "eviltwin-1.0.0.tgz");
  tarGz(archive, stage, ["package"]);

  const repo = materializePackage({ ecosystem: "npm", bytes: readFileSync(archive), filename: "eviltwin-1.0.0.tgz", baseDir: b });

  assert.deepEqual(relTree(repo), ["bin/evil.sh", "package.json"]);
  expectCommitted(repo);
  // the exact contract npm stage relies on: `git show HEAD:package.json`
  assert.equal(gitOut(repo, ["show", "HEAD:package.json"]), PKG_JSON);
});

// ------------------------------------------------------------------ pypi sdist

test("pypi sdist .tar.gz with <name>-<ver>/ root is stripped and committed", () => {
  const b = base("pypi");
  const stage = join(b, "stage");
  mkdirSync(join(stage, "nicepkg-1.2.3"), { recursive: true });
  writeFileSync(join(stage, "nicepkg-1.2.3", "pyproject.toml"), '[build-system]\nrequires = ["setuptools"]\n[project]\nname = "nicepkg"\nversion = "1.2.3"\n');
  writeFileSync(join(stage, "nicepkg-1.2.3", "setup.py"), '# upstream README quotes: "crontab -e"\nfrom setuptools import setup\nsetup()\n');
  const archive = join(b, "nicepkg-1.2.3.tar.gz");
  tarGz(archive, stage, ["nicepkg-1.2.3"]);

  const repo = materializePackage({ ecosystem: "pypi", bytes: readFileSync(archive), filename: "nicepkg-1.2.3.tar.gz", baseDir: b });

  assert.deepEqual(relTree(repo), ["pyproject.toml", "setup.py"]);
  expectCommitted(repo);
});

// ------------------------------------------------------------------ crates

// The exact envelope contents, hoisted so the forensic-log assertions can
// recompute the sha256 of the ORIGINAL bytes from the same source of truth.
const CARGO_ORIG = '[package]\nname = "fakecrate"\n# pre-normalization original\n';
const CARGO_OK = "";
const CARGO_VCS = '{"git":{"sha1":"x"}}';

const sha256Hex = (s: string): string => createHash("sha256").update(s).digest("hex");

test("crates .crate (tar.gz, <name>-<ver>/ root) is stripped and committed", () => {
  const b = base("crates");
  const stage = join(b, "stage");
  mkdirSync(join(stage, "fakecrate-0.1.0", "src"), { recursive: true });
  writeFileSync(join(stage, "fakecrate-0.1.0", "Cargo.toml"), '[package]\nname = "fakecrate"\nversion = "0.1.0"\nedition = "2021"\n');
  // crates.io envelope files a registry .crate carries but `cargo package`
  // REJECTS as reserved (measured: exit 101 "invalid inclusion of reserved
  // file name Cargo.toml.orig"). materialize must normalize the envelope.
  writeFileSync(join(stage, "fakecrate-0.1.0", "Cargo.toml.orig"), CARGO_ORIG);
  writeFileSync(join(stage, "fakecrate-0.1.0", ".cargo-ok"), CARGO_OK);
  writeFileSync(join(stage, "fakecrate-0.1.0", ".cargo_vcs_info.json"), CARGO_VCS);
  writeFileSync(join(stage, "fakecrate-0.1.0", "src", "lib.rs"), "// crate doc\n");
  const archive = join(b, "fakecrate-0.1.0.crate");
  tarGz(archive, stage, ["fakecrate-0.1.0"]);

  const notes: string[] = [];
  const repo = materializePackage({ ecosystem: "crates", bytes: readFileSync(archive), filename: "fakecrate-0.1.0.crate", baseDir: b, note: (line: string) => notes.push(line) });

  const tree = relTree(repo);
  assert.ok(tree.includes("Cargo.toml"));
  assert.ok(!tree.includes("Cargo.toml.orig"), "registry-reserved file scrubbed so the cargo package leg can run");
  assert.ok(!tree.includes(".cargo-ok"), "install-time marker scrubbed");
  assert.ok(!tree.includes(".cargo_vcs_info.json"), "VCS-info collision scrubbed (git-fenced repo regenerates it)");
  expectCommitted(repo);

  // W1.4 (verifier D1): the envelope scrub is forensically LOGGED — one line
  // per scrubbed file that EXISTED, carrying the sha256 of its original bytes
  // (taken BEFORE deletion). Silent mutation of package content is forbidden.
  assert.deepEqual(notes, [
    `border scan: crates envelope normalized: Cargo.toml.orig sha256=${sha256Hex(CARGO_ORIG)}`,
    `border scan: crates envelope normalized: .cargo-ok sha256=${sha256Hex(CARGO_OK)}`,
    `border scan: crates envelope normalized: .cargo_vcs_info.json sha256=${sha256Hex(CARGO_VCS)}`,
  ]);
});

test("crates envelope scrub logs only files that existed, to stderr by default", () => {
  // (a) a .crate with NO envelope files (vendored/offline shape) logs nothing.
  const b = base("crates-clean");
  const stage = join(b, "stage");
  mkdirSync(join(stage, "plaincrate-0.1.0", "src"), { recursive: true });
  writeFileSync(join(stage, "plaincrate-0.1.0", "Cargo.toml"), '[package]\nname = "plaincrate"\nversion = "0.1.0"\nedition = "2021"\n');
  writeFileSync(join(stage, "plaincrate-0.1.0", "src", "lib.rs"), "// crate doc\n");
  const archive = join(b, "plaincrate-0.1.0.crate");
  tarGz(archive, stage, ["plaincrate-0.1.0"]);

  const notes: string[] = [];
  materializePackage({ ecosystem: "crates", bytes: readFileSync(archive), filename: "plaincrate-0.1.0.crate", baseDir: b, note: (line: string) => notes.push(line) });
  assert.deepEqual(notes, [], "absent envelope files must not fabricate scrub records");

  // (b) the default sink is the real stderr, newline-terminated, per file.
  const b2 = base("crates-stderr");
  const stage2 = join(b2, "stage");
  mkdirSync(stage2, { recursive: true });
  mkdirSync(join(stage2, "okcrate-0.2.0"), { recursive: true });
  writeFileSync(join(stage2, "okcrate-0.2.0", "Cargo.toml"), '[package]\nname = "okcrate"\nversion = "0.2.0"\nedition = "2021"\n');
  writeFileSync(join(stage2, "okcrate-0.2.0", ".cargo-ok"), "ok");
  const archive2 = join(b2, "okcrate-0.2.0.crate");
  tarGz(archive2, stage2, ["okcrate-0.2.0"]);

  const written: string[] = [];
  const realWrite = process.stderr.write;
  try {
    process.stderr.write = ((chunk: unknown): boolean => {
      written.push(String(chunk));
      return true;
    }) as typeof process.stderr.write;
    materializePackage({ ecosystem: "crates", bytes: readFileSync(archive2), filename: "okcrate-0.2.0.crate", baseDir: b2 });
  } finally {
    process.stderr.write = realWrite;
  }
  assert.deepEqual(written, [`border scan: crates envelope normalized: .cargo-ok sha256=${sha256Hex("ok")}\n`]);
});

// ------------------------------------------------------------------ rubygems

test(".gem outer tar is opened, data.tar.gz is unpacked to the repo root (gemspec visible to stage)", () => {
  const b = base("gem");
  const flat = join(b, "dataflat");
  mkdirSync(join(flat, "lib"), { recursive: true });
  writeFileSync(join(flat, "fakegem.gemspec"), 's = Gem::Specification.new\ns.name = "fakegem"\ns.version = "0.1.0"\ns.summary = "s"\ns.authors = ["t"]\ns.homepage = "https://example.invalid"\ns.license = "MIT"\ns.files = ["lib/fakegem.rb"]\nrequire "date"\ns.date = Time.at(0).utc\ns\n');
  writeFileSync(join(flat, "lib", "fakegem.rb"), "# rb doc mentions crontab\n");
  const gemroot = join(b, "gemroot");
  mkdirSync(gemroot, { recursive: true });
  // data.tar.gz inside a real .gem holds the FLAT gem tree (lib/, *.gemspec)
  tarGz(join(gemroot, "data.tar.gz"), flat, ["fakegem.gemspec", "lib"]);
  writeFileSync(join(gemroot, "metadata.gz"), gzipSync('--- !ruby/object:Gem::Specification\nname: fakegem\nversion: 0.1.0\n'));
  const outer = join(b, "fakegem-0.1.0.gem");
  tarPlain(outer, gemroot, ["metadata.gz", "data.tar.gz"]);

  const repo = materializePackage({ ecosystem: "rubygems", bytes: readFileSync(outer), filename: "fakegem-0.1.0.gem", baseDir: b });

  assert.ok(relTree(repo).includes("fakegem.gemspec"), "gemspec must sit at the repo root for the rebuild stage");
  expectCommitted(repo);
});

// ------------------------------------------------------------------ edges

test("garbage archive bytes fail closed with a one-line cause (never a silent empty tree)", () => {
  const b = base("garbage");
  assert.throws(
    () => materializePackage({ ecosystem: "npm", bytes: Buffer.from("this is not a tarball"), filename: "junk.tgz", baseDir: b }),
    (err: unknown) => {
      assert.ok(err instanceof Error);
      assert.equal((err as Error).message.includes("\n"), false, "one-line cause");
      return true;
    },
  );
});

test("path traversal in the archive filename cannot escape the sandbox", () => {
  const b = base("traversal");
  const stage = join(b, "stage");
  mkdirSync(join(stage, "package"), { recursive: true });
  writeFileSync(join(stage, "package", "package.json"), PKG_JSON);
  const archive = join(b, "evil.tgz");
  tarGz(archive, stage, ["package"]);
  const repo = materializePackage({ ecosystem: "npm", bytes: readFileSync(archive), filename: "../../../evil.tgz", baseDir: b });
  assert.ok(repo.startsWith(b), "repo stays inside the sandbox");
  assert.equal(existsSync(join(b, "evil.tgz")), true, "archive name was basename-sanitized and landed inside baseDir");
});
