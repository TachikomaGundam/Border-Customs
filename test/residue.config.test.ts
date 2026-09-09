// provenance: R4 of .omo/plans/border-residue-gate.md — the 0.3.0 wave's config/plumbing suite.
//
// Owns: `residue: {enabled}` strict-zod schema (default = ENABLED; unknown sibling
// keys ⇒ exit 2), the CENTRAL check.ts merge-point gate (toggle-off drops ONLY the
// closed residue-* rule-id set — every other rule byte-identical through), the
// rulesHash residue digest (residueMatchers.ts + classifier modules + artifact scan
// sources ride the fingerprint; a one-byte content edit ⇒ new rulesHash ⇒ the cached
// PASS is refused by the ledger key even at the same commit+tree), and the
// README/Changelog single-source pins.
//
// Fail-closed doctrine (AGENTS.md): the ONLY sanctioned skip of the residue scan is
// the user's explicit residue.enabled:false. A digest input that cannot be read is
// a MissingRulesInputError ⇒ exit 2 (the skip path degrades to "never skip"), never
// a silent pass. This is a NEW-file suite: the five pinned residue suites stay
// untouched (brief: "prefer NEW test files for R4 tests").
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFileSync, cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { after, test } from "node:test";

import { executeCheck, type CheckOutcome } from "../src/check.ts";
import { run } from "../src/cli.ts";
import { EXIT_BLOCKED, EXIT_PASS } from "../src/cli/exit.ts";
import { ConfigError, parseConfig, type BorderConfig } from "../src/config.ts";
import { computeCheckRulesHash, computeConfigDigest, type LoadedConfig } from "../src/check/rulesHash.ts";
import { MissingRulesInputError } from "../src/redact.ts";
import { RESIDUE_SEVERITIES } from "../src/rules/residueMatchers.ts";
import { readLedger, type CheckRecord } from "../src/ledger.ts";
import { requireGitleaks } from "./helpers/require-engines.ts";
import { BORDER_ROOT, gitAddCommit, gitInit, makeFixtureDir, removeDir, writeRel } from "./helpers/fixtures.ts";
import { startRegistryStub, type RegistryStub } from "./helpers/registry-stub.ts";

requireGitleaks();

const roots: string[] = [];
const npmStub: RegistryStub = await startRegistryStub([]);
after(async () => {
  for (const d of roots) removeDir(d);
  await npmStub.close();
});

const CORPUS = new URL("./fixtures/residue/", import.meta.url).pathname;

function tmpDir(prefix: string): string {
  const d = makeFixtureDir(prefix);
  roots.push(d);
  return d;
}

// ---------------------------------------------------------------- fixture builders

function baseYaml(extra: readonly string[] = [], withNpm = false): string {
  return [
    "version: 1",
    "targets:",
    "  git:",
    "    remotes:",
    "      - name: origin",
    "        url: origin.example:widgets.git",
    ...(withNpm ? ["  npm:", `    registry: ${npmStub.url}`] : []),
    "rules:",
    "  authors:",
    "    emails:",
    "      - wiki@sumteclab.com",
    "    names:",
    "      - Wiki.js",
    "  hosts: []",
    "  ips: []",
    "  pathPatterns: []",
    ...extra,
    "",
  ].join("\n");
}

/** Corpus package dir copied into a committed identity-clean git repo. */
function npmRepo(fixture: string, yamlExtra: readonly string[] = []): string {
  const dir = tmpDir(`r4cfg-${fixture}`);
  cpSync(join(CORPUS, fixture), dir, { recursive: true });
  gitInit(dir);
  writeRel(dir, "border.yaml", baseYaml(yamlExtra, true));
  gitAddCommit(dir, "init");
  return dir;
}

function cfgWith(residueLines: readonly string[]): BorderConfig {
  return parseConfig(baseYaml(residueLines, true));
}

function runCheck(repoDir: string, cfg: BorderConfig): Promise<CheckOutcome> {
  return executeCheck({
    repoDir,
    cfg,
    configDigest: "d".repeat(64),
    effectiveTargets: ["git", "npm"],
  });
}

type Cli = { readonly code: number; readonly out: readonly string[]; readonly err: readonly string[] };

async function cli(dir: string, extra: readonly string[] = [], env?: Record<string, string>): Promise<Cli> {
  const out: string[] = [];
  const err: string[] = [];
  const code = (await run(["check", ...extra], (l) => out.push(l), (l) => err.push(l), {
    cwd: dir,
    ...(env === undefined ? {} : { env: { ...process.env, ...env } }),
  })) as number;
  return { code, out, err };
}

const SKIP_RE = /^SKIP ([0-9a-f]{8}) — PASS /;
const skipLine = (c: Cli): string | undefined => c.out.find((l) => SKIP_RE.test(l));

function gitRev(dir: string, args: readonly string[]): string {
  const r = spawnSync("git", ["-C", dir, ...args], { encoding: "utf8" });
  if (r.status !== 0) throw new Error(`git ${args.join(" ")}: ${r.stderr}`);
  return r.stdout;
}

function lastCheckRecord(dir: string): CheckRecord {
  const recs = readLedger(dir).records.filter((r): r is CheckRecord => r.t === "check");
  const last = recs.at(-1);
  if (last === undefined) throw new Error("no check record");
  return last;
}

// ---------------------------------------------------------------- 1. config schema

test("R4-CFG: residue absent ⇒ enabled (default true); `residue: {}` ⇒ {enabled:true}; explicit false parses", () => {
  type MaybeResidue = BorderConfig & { residue?: { enabled: boolean } };
  const absent = parseConfig(baseYaml()) as MaybeResidue;
  // Absent key must behave as enabled (the semantic default is proven end-to-end by
  // the gate test below); the schema may represent it as undefined or true.
  assert.notEqual(absent.residue?.enabled, false, "default must be enabled=true");
  const empty = parseConfig(baseYaml(["residue: {}"])) as MaybeResidue;
  assert.equal(empty.residue?.enabled, true, "residue:{} ⇒ inner default materializes enabled=true");
  const off = parseConfig(baseYaml(["residue:", "  enabled: false"])) as MaybeResidue;
  assert.equal(off.residue?.enabled, false);
});

test("R4-CFG: strict zod — unknown sibling under residue:, scalar residue:, non-bool enabled all fail typed exit 2", () => {
  for (const yaml of [
    baseYaml(["residue:", "  enabled: true", "  debug: 1"]),
    baseYaml(["residue: true"]),
    baseYaml(["residue:", '  enabled: "yes"']),
    baseYaml(["residue:", "  enableds: false"]),
  ]) {
    assert.throws(
      () => parseConfig(yaml),
      (err: unknown) => err instanceof ConfigError && err.exitCode === 2,
      `expected typed exit 2 for:\n${yaml}`,
    );
  }
});

// ---------------------------------------------------------------- 2. central gate

test("R4-GATE: residue.enabled:false drops ONLY residue-* rows at the check.ts merge point; every other rule unchanged", async () => {
  const repo = npmRepo("b-t2-downloader");
  const on = await runCheck(repo, cfgWith([]));
  const off = await runCheck(repo, cfgWith(["residue:", "  enabled: false"]));

  const onResidue = on.report.findings.filter((f) => f.rule.startsWith("residue-"));
  assert.ok(onResidue.length > 0, "enabled run must surface residue findings (fixture trips residue-install-download)");
  assert.ok(onResidue.some((f) => f.rule === "residue-install-download" && f.severity === "HIGH"));
  assert.equal(off.report.findings.filter((f) => f.rule.startsWith("residue-")).length, 0, "toggle-off must surface ZERO residue rows");

  // The ONLY difference between the two reports is the residue-* subset: lifecycle-script
  // CRITICAL and every other rule pass through unchanged (AGENTS.md: the toggle's sole
  // effect is skipping residue rules, every other rule unchanged).
  const nonResidue = (o: CheckOutcome) => o.report.findings.filter((f) => !f.rule.startsWith("residue-"));
  assert.deepEqual(nonResidue(off), nonResidue(on), "non-residue findings are identical across the toggle");
  assert.equal(nonResidue(on).filter((f) => f.rule === "lifecycle-script").length, 1, "control: non-residue CRITICAL survives");
  assert.equal(off.report.verdict, "FAIL", "toggle-off must NOT launder the remaining CRITICAL verdict");
});

// ---------------------------------------------------------------- 3. rulesHash digest

/** The fingerprint module gains the residue digest wiring (R4 deliverable 2).
 *  Imported dynamically so schema/gate tests keep their own granular RED. */
type FingerprintApi = {
  RESIDUE_FINGERPRINT_BASENAMES: readonly string[];
  resolveResidueFingerprintFiles: (env?: Readonly<Record<string, string | undefined>>) => readonly string[];
};

async function fingerprintApi(): Promise<FingerprintApi> {
  const mod = (await import("../src/check/rulesHash.ts")) as unknown as Partial<FingerprintApi>;
  assert.ok(mod.RESIDUE_FINGERPRINT_BASENAMES !== undefined, "rulesHash.ts must export RESIDUE_FINGERPRINT_BASENAMES (R4)");
  assert.ok(mod.resolveResidueFingerprintFiles !== undefined, "rulesHash.ts must export resolveResidueFingerprintFiles (R4)");
  return mod as FingerprintApi;
}

function seamWithCopies(seam: string, live: readonly string[]): void {
  mkdirSync(seam, { recursive: true });
  for (const p of live) copyFileSync(p, join(seam, p.slice(p.lastIndexOf("/") + 1)));
}

const seamEnv = (seam: string): Record<string, string | undefined> => ({ ...process.env, BORDER_RESIDUE_SRC_DIR: seam });

test("R4-HASH: digest covers residueMatchers.ts + classifier modules; one-byte content edit ⇒ different rulesHash", async () => {
  const api = await fingerprintApi();
  const live = api.resolveResidueFingerprintFiles({});
  assert.deepEqual(
    [...live].map((p) => p.slice(p.lastIndexOf("/") + 1)).sort(),
    [...api.RESIDUE_FINGERPRINT_BASENAMES].sort(),
    "live resolution returns exactly the fingerprint basenames",
  );
  for (const p of live) {
    const base = p.slice(p.lastIndexOf("/") + 1);
    assert.ok(
      base === "residueMatchers.ts" ? p.includes("/rules/") : p.includes("/artifacts/"),
      `live path must sit in its src dir: ${p}`,
    );
  }
  for (const name of ["residueMatchers.ts", "residue.ts", "residuePy.ts", "residueRust.ts", "residueGem.ts", "npm.ts", "pypi.ts", "crates.ts", "rubygems.ts"]) {
    assert.ok(api.RESIDUE_FINGERPRINT_BASENAMES.includes(name), `fingerprint set must cover ${name}`);
  }

  const seamA = tmpDir("r4seamA");
  const seamB = tmpDir("r4seamB");
  seamWithCopies(seamA, live);
  seamWithCopies(seamB, live);

  const hashA = await computeCheckRulesHash({ engineVersions: {}, configDigest: "a".repeat(64), env: seamEnv(seamA) });
  const hashAAgain = await computeCheckRulesHash({ engineVersions: {}, configDigest: "a".repeat(64), env: seamEnv(seamA) });
  assert.equal(hashA, hashAAgain, "same bytes ⇒ deterministic hash");

  // Plan AC (Wave-4 gate 4): editing residueMatchers.ts ⇒ new key. Mutate ONLY the
  // copy the seam points at — the shipped sources stay byte-frozen (untouchables).
  const rm = join(seamB, "residueMatchers.ts");
  writeFileSync(rm, `${readFileSync(rm, "utf8")}\n// sig-line-mutation\n`, "utf8");
  const hashB = await computeCheckRulesHash({ engineVersions: {}, configDigest: "a".repeat(64), env: seamEnv(seamB) });
  assert.notEqual(hashA, hashB, "residueMatchers.ts content edit MUST change rulesHash");

  // a classifier-module edit invalidates too (the module set, not just the table)
  const py = join(seamB, "residuePy.ts");
  writeFileSync(py, `${readFileSync(py, "utf8")}// classifier edit\n`, "utf8");
  const hashB2 = await computeCheckRulesHash({ engineVersions: {}, configDigest: "a".repeat(64), env: seamEnv(seamB) });
  assert.notEqual(hashB, hashB2, "classifier module edit MUST change rulesHash too");
});

test("R4-HASH: residue config value rides the digest via configDigest (toggle ⇒ different digest feeds rulesHash)", () => {
  const asLoad = (residueLines: readonly string[]): LoadedConfig => ({
    kind: "loaded",
    config: parseConfig(baseYaml(residueLines)),
    warnings: [],
    source: "<test>",
  });
  const on = computeConfigDigest(asLoad(["residue:", "  enabled: true"]));
  const off = computeConfigDigest(asLoad(["residue:", "  enabled: false"]));
  const absent = computeConfigDigest(asLoad([]));
  assert.notEqual(on, off, "residue.enabled MUST be visible to the config digest (feeds rulesHash)");
  assert.notEqual(absent, off, "absent-vs-off also moves the digest (default ≠ explicit off)");
});

test("R4-HASH: fail-closed — a missing fingerprint input is MissingRulesInputError, never a silent skip", async () => {
  const api = await fingerprintApi();
  const seam = tmpDir("r4seamMissing");
  seamWithCopies(seam, api.resolveResidueFingerprintFiles({}));
  rmSync(join(seam, "residueMatchers.ts"));
  await assert.rejects(
    computeCheckRulesHash({ engineVersions: {}, configDigest: "b".repeat(64), env: seamEnv(seam) }),
    (err: unknown) => err instanceof MissingRulesInputError && String((err as MissingRulesInputError).inputPath).includes("residueMatchers.ts"),
  );
});

// ---------------------------------------------------------------- 4. stale PASS via the real CLI

test("R4-PASS: same commit+tree; toggle flip or fingerprint-source edit invalidates the cached PASS (ledger key moves)", async () => {
  const dir = tmpDir("r4skip");
  gitInit(dir);
  writeRel(dir, "border.yaml", baseYaml());
  writeRel(dir, "notes.txt", "clean\n");
  gitAddCommit(dir, "init");

  const r1 = await cli(dir);
  assert.equal(r1.code, EXIT_PASS, r1.out.join("\n"));
  assert.equal(skipLine(r1), undefined, "first run never skips");
  const rec1 = lastCheckRecord(dir);

  const r2 = await cli(dir);
  const skip2 = SKIP_RE.exec(skipLine(r2) ?? "");
  assert.ok(skip2 !== null, `baseline: identical state ⇒ SKIP, got: ${r2.out.join(" | ")}`);
  assert.equal(skip2[1], rec1.key8, "SKIP cites the PASS record's key8");

  // --- cause A: residue.enabled:false via the private overlay. .border/ self-ignores,
  // so HEAD AND porcelain stay stable — the ONLY thing that moves is the digest.
  const headBefore = gitRev(dir, ["rev-parse", "HEAD"]);
  const statusBefore = gitRev(dir, ["status", "--porcelain"]);
  writeRel(dir, join(".border", "config.local.yaml"), "residue:\n  enabled: false\n");
  assert.equal(gitRev(dir, ["rev-parse", "HEAD"]), headBefore, "overlay changes no git state");
  assert.equal(gitRev(dir, ["status", "--porcelain"]), statusBefore, "overlay never dirties the tree");
  const r3 = await cli(dir);
  assert.equal(r3.code, EXIT_PASS);
  assert.equal(skipLine(r3), undefined, "residue.enabled flip MUST invalidate the cached PASS (same commit+tree)");
  const rec3 = lastCheckRecord(dir);
  assert.notEqual(rec3.rulesHash, rec1.rulesHash, "rulesHash itself moved");
  assert.notEqual(rec3.key, rec1.key, "and so did the ledger key");

  rmSync(join(dir, ".border", "config.local.yaml"));
  const r4 = await cli(dir);
  assert.notEqual(skipLine(r4), undefined, "restoring the toggle re-honors the original PASS");

  // --- cause B: residueMatchers.ts-style table edit, simulated through the
  // BORDER_RESIDUE_SRC_DIR seam (shipped sources stay byte-frozen).
  const api = await fingerprintApi();
  const seam = tmpDir("r4seamStable");
  seamWithCopies(seam, api.resolveResidueFingerprintFiles({}));
  const r5 = await cli(dir, [], { BORDER_RESIDUE_SRC_DIR: seam });
  assert.equal(r5.code, EXIT_PASS);
  assert.equal(skipLine(r5), undefined, "seam redirection alone ⇒ new key ⇒ no skip");
  const rec5 = lastCheckRecord(dir);
  const rm = join(seam, "residueMatchers.ts");
  writeFileSync(rm, `${readFileSync(rm, "utf8")}\n// planted signature-line mutation\n`, "utf8");
  const r6 = await cli(dir, [], { BORDER_RESIDUE_SRC_DIR: seam });
  assert.equal(skipLine(r6), undefined, "table-content edit ⇒ re-check fires");
  assert.notEqual(lastCheckRecord(dir).key, rec5.key, "mutation moved the key again");
  const r7 = await cli(dir, [], { BORDER_RESIDUE_SRC_DIR: seam });
  assert.notEqual(skipLine(r7), undefined, "stable mutated seam ⇒ the NEW PASS certifies again");
});

// ---------------------------------------------------------------- 5. --json schema stability

test("R4-JSON: border check --json keeps the exact report/Finding schema with the toggle off (no drift)", async () => {
  const onCli = await cli(npmRepo("b-t2-downloader"), ["--json"]);
  assert.equal(onCli.code, EXIT_BLOCKED, "fixture must block (lifecycle-script CRITICAL + residue HIGH)");
  const on = JSON.parse(onCli.out.join("")) as Record<string, unknown>;
  const onFindings = on["findings"] as Record<string, unknown>[];
  assert.ok(onFindings.some((f) => String(f["rule"]).startsWith("residue-")), "enabled: residue rows present in --json");

  const offCli = await cli(npmRepo("b-t2-downloader", ["residue:", "  enabled: false"]), ["--json"]);
  assert.equal(offCli.code, EXIT_BLOCKED, "still blocked by the non-residue CRITICAL — the toggle never launders");
  const off = JSON.parse(offCli.out.join("")) as Record<string, unknown>;
  const offFindings = off["findings"] as Record<string, unknown>[];
  assert.deepEqual(Object.keys(off).sort(), Object.keys(on).sort(), "report key set identical (schema stable)");
  assert.equal(offFindings.filter((f) => String(f["rule"]).startsWith("residue-")).length, 0);

  const keysOf = (f: unknown): string[] => Object.keys(f as object).sort();
  const onNonResidue = onFindings.filter((f) => !String(f["rule"]).startsWith("residue-"));
  assert.equal(offFindings.length, onNonResidue.length, "same non-residue findings survive");
  for (let i = 0; i < offFindings.length; i += 1) {
    assert.deepEqual(keysOf(offFindings[i]), keysOf(onNonResidue[i]), "Finding field set unchanged (no schema drift)");
  }
});

// ---------------------------------------------------------------- 6. README / Changelog pins

test("R4-DOC: README names all seven residue rule ids with severities matching the single RESIDUE_SEVERITIES home, honest-boundary lines, and the 0.3.0 bump", () => {
  const readme = readFileSync(join(BORDER_ROOT, "README.md"), "utf8");
  for (const [rule, severity] of Object.entries(RESIDUE_SEVERITIES)) {
    const rows = readme.split("\n").filter((l) => l.includes(`\`${rule}\``) && l.toUpperCase().includes(severity.toUpperCase()));
    assert.ok(rows.length >= 1, `README tier table must name \`${rule}\` with severity ${severity}`);
  }
  const lower = readme.toLowerCase();
  assert.ok(lower.includes("capability"), "boundary honesty: static proves CAPABILITY, not FACT");
  assert.ok(lower.includes("sandbox"), "explicit NOT-a-malware-sandbox disclaimer");
  assert.ok(readme.includes("RESIDUE-CONTRACT.md"), "fail-closed + named-invisible pointer to the contract (never restating the list)");
  assert.ok(readme.includes("0.4.0"), "roundtrip valve pointer = 0.4.0");
  assert.ok(readme.includes("### 0.3.0"), "Changelog 0.3.0 entry present");
  const pkg = JSON.parse(readFileSync(join(BORDER_ROOT, "package.json"), "utf8")) as { version: string };
  assert.equal(pkg.version, "0.3.0", "plan R4 line 93 pins the 0.3.0 bump");
});
