// provenance: border-inspect-roadmap.md W2.2 — the requireProof valve in the check pipeline.
//
// Doctrine (plan §cross-wave): `border check` NEVER spawns docker. The proof is
// pre-supplied by `border roundtrip` as a t:"roundtrip" ledger record; the valve
// is pure FAIL-CLOSED-BY-ABSENCE: requireProof AND a blocking residue-* finding on a
// staged artifact ⇒ channel PASS requires a FRESH roundtrip record for that artifact's
// sha256 (fresh = rulesHash equality, same pattern as check fingerprints). No record ⇒
// roundtrip-proof-missing CRITICAL; present-but-hash-mismatched ⇒ roundtrip-proof-stale
// CRITICAL. Both verdicts (clean|residue) satisfy — the FACT is the record, not the
// verdict. These are native findings: they flow through applyAllowList like every
// other rule, no special-casing.
import assert from "node:assert/strict";
import { appendFileSync, cpSync } from "node:fs";
import { join } from "node:path";
import { after, test } from "node:test";

import { executeCheck, type CheckOutcome } from "../src/check.ts";
import { parseConfig, type BorderConfig } from "../src/config.ts";
import type { Finding, Severity } from "../src/findings.ts";
import type { LedgerRecord, LedgerArtifact } from "../src/ledger.ts";
import { appendRecord, buildRoundtripRecord, readLedger } from "../src/ledger.ts";
import {
  hasBlockingResidueCapability,
  proofFindings,
  ROUNDTRIP_PROOF_MISSING_RULE,
  ROUNDTRIP_PROOF_STALE_RULE,
} from "../src/check/proofValve.ts";
import { RESIDUE_T1_RULE, RESIDUE_T3_RULE, RESIDUE_T4_RULE } from "../src/rules/residueMatchers.ts";
import { requireGitleaks } from "./helpers/require-engines.ts";
import { gitAddCommit, gitInit, makeFixtureDir, removeDir, writeRel } from "./helpers/fixtures.ts";
import { startRegistryStub, type RegistryStub } from "./helpers/registry-stub.ts";

requireGitleaks();

const roots: string[] = [];
const npmStub: RegistryStub = await startRegistryStub([]);
after(async () => {
  for (const d of roots) removeDir(d);
  await npmStub.close();
});

const CORPUS = new URL("./fixtures/residue/", import.meta.url).pathname;
const SHA_A = "a".repeat(64);
const SHA_B = "b".repeat(64);
const RH = "1".repeat(64);

function tmpDir(prefix: string): string {
  const d = makeFixtureDir(prefix);
  roots.push(d);
  return d;
}

function fake(rule: string, severity: Severity, engine = "native"): Finding {
  return { rule, severity, target: "npm", engine, message: "x", valueDigest: "0".repeat(64), snippet: "x" };
}

const ART: LedgerArtifact = { file: ".border/dist/widgets-1.0.0.tgz", sha256: SHA_A };

function rtRecord(over: Partial<Parameters<typeof buildRoundtripRecord>[0]> = {}) {
  return buildRoundtripRecord({ artifactSha256: SHA_A, verdict: "clean", rulesHash: RH, rows: 0, ...over });
}

// ---------------------------------------------------------------- unit: trigger

test("W2.2-trigger: only blocking residue-* rows arm the valve — T1 mediums and gitleaks legs never do", () => {
  assert.equal(hasBlockingResidueCapability([]), false);
  assert.equal(hasBlockingResidueCapability([fake(RESIDUE_T3_RULE, "HIGH")]), true, "T3 out-of-tree-write arms it");
  assert.equal(hasBlockingResidueCapability([fake(RESIDUE_T4_RULE, "CRITICAL")]), true, "T4 persistence primitive arms it");
  assert.equal(hasBlockingResidueCapability([fake(RESIDUE_T1_RULE, "MEDIUM")]), false, "downgraded in-tree T1 is not a capability claim");
  assert.equal(hasBlockingResidueCapability([fake("generic-api-key", "CRITICAL", "gitleaks")]), false, "the gitleaks/secretlint legs are NOT residue findings — no proof obligation");
  assert.equal(hasBlockingResidueCapability([fake("npm-provenance-absent", "HIGH", "native")]), false);
});

// ---------------------------------------------------------------- unit: valve math

test("W2.2-valve: absent record ⇒ roundtrip-proof-missing CRITICAL native keyed to the artifact", () => {
  const out = proofFindings({ artifacts: [ART], records: [], rulesHash: RH });
  assert.equal(out.length, 1);
  const f = out[0] as Finding;
  assert.equal(f.rule, ROUNDTRIP_PROOF_MISSING_RULE);
  assert.equal(f.severity, "CRITICAL");
  assert.equal(f.engine, "native");
  assert.equal(f.path, ART.file);
  assert.match(f.message, /roundtrip/);
});

test("W2.2-valve: fresh record satisfies regardless of clean|residue verdict (the FACT is the record)", () => {
  for (const verdict of ["clean", "residue"] as const) {
    const records: LedgerRecord[] = [rtRecord({ verdict, rows: verdict === "clean" ? 0 : 4 })];
    assert.deepEqual(proofFindings({ artifacts: [ART], records, rulesHash: RH }), [], `${verdict} verdict + matching rulesHash satisfies the obligation`);
  }
});

test("W2.2-valve: present record with a mismatched rulesHash ⇒ roundtrip-proof-stale (freshness = rulesHash equality)", () => {
  const records: LedgerRecord[] = [rtRecord({ rulesHash: "9".repeat(64) })];
  const out = proofFindings({ artifacts: [ART], records, rulesHash: RH });
  assert.equal(out.length, 1);
  assert.equal(out[0]?.rule, ROUNDTRIP_PROOF_STALE_RULE);
  assert.equal(out[0]?.severity, "CRITICAL");
});

test("W2.2-valve: lookup is keyed by artifact sha256 — one proven artifact does not cover its sibling", () => {
  const other: LedgerArtifact = { file: ".border/dist/other-2.0.0.tgz", sha256: SHA_B };
  const out = proofFindings({ artifacts: [ART, other], records: [rtRecord()], rulesHash: RH });
  assert.equal(out.length, 1);
  assert.equal(out[0]?.path, other.file, "only the sha256 with no record is unproven");
  assert.equal(out[0]?.rule, ROUNDTRIP_PROOF_MISSING_RULE);
});

test("W2.2-valve: a torn/invalid ledger line leaves the artifact unproven (fail-closed-by-absence)", () => {
  // readLedger's corruption tolerance drops the torn line to a WARNING; the
  // valve must then treat those bytes as UNPROVEN (fail-closed), never crash.
  const d = tmpDir("w22-torn");
  appendRecord(d, rtRecord());
  appendFileSync(join(d, ".border", "ledger.jsonl"), '{"t":"roundtrip","artifactSha256":"\n', "utf8");
  const { records, warnings } = readLedger(d);
  assert.equal(warnings.length, 1);
  assert.equal(records.length, 1, "the valid record survives, the torn one is skipped");
  assert.equal(proofFindings({ artifacts: [{ file: "x.tgz", sha256: SHA_B }], records, rulesHash: RH }).length, 1, "bytes with no surviving proof line ⇒ missing, not a crash and not a pass");
});

// ---------------------------------------------------------------- integration: executeCheck

function baseYaml(extra: readonly string[]): string {
  return [
    "version: 1",
    "targets:",
    "  git:",
    "    remotes:",
    "      - name: origin",
    "        url: origin.example:widgets.git",
    "  npm:",
    `    registry: ${npmStub.url}`,
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

/** The corpus T3 repo: ONE blocking residue row + lifecycle-script CRITICAL —
 *  the two allow lines mute them so the ONLY possible blocker is the valve. */
function proofRepo(fixture: string, extra: readonly string[]): string {
  const dir = tmpDir(`w22-${fixture}`);
  cpSync(join(CORPUS, fixture), dir, { recursive: true });
  gitInit(dir);
  writeRel(dir, "border.yaml", baseYaml(extra));
  gitAddCommit(dir, "init");
  return dir;
}

const MUTE_RESIDUE = ["allow:", '  - rule: "residue-*"', '    match: "*"', "  - rule: lifecycle-script", '    match: "*"'];

function cfg(extra: readonly string[]): BorderConfig {
  return parseConfig(baseYaml(extra));
}

async function runCheck(repoDir: string, config: BorderConfig): Promise<CheckOutcome> {
  return executeCheck({ repoDir, cfg: config, configDigest: "d".repeat(64), effectiveTargets: ["git", "npm"] });
}

const proofRows = (o: CheckOutcome): Finding[] => o.report.findings.filter((f) => f.rule.startsWith("roundtrip-proof"));

test("W2.2-integration: residue + requireProof + NO record ⇒ channel FAIL on roundtrip-proof-missing CRITICAL", async () => {
  const dir = proofRepo("c-t3-rceditor", [...MUTE_RESIDUE, "residue:", "  requireProof: true"]);
  const o = await runCheck(dir, cfg([...MUTE_RESIDUE, "residue:", "  requireProof: true"]));
  const rows = proofRows(o);
  assert.equal(rows.length, 1);
  assert.equal(rows[0]?.rule, ROUNDTRIP_PROOF_MISSING_RULE);
  assert.equal(rows[0]?.severity, "CRITICAL");
  assert.match(String(rows[0]?.path), /\.border\/dist\/fixture-t3-rceditor.*\.tgz$/);
  assert.equal(o.report.verdict, "FAIL", "the muted residue row WAS a capability claim — PASS now demands the proof record that does not exist");
  assert.equal(o.report.counts.blocking, 1, "the proof finding is the only blocker on the channel");
});

test("W2.2-integration: fresh clean roundtrip record for the artifact sha ⇒ PASS; rotated rulesHash ⇒ -stale", async () => {
  const dir = proofRepo("c-t3-rceditor", [...MUTE_RESIDUE, "residue:", "  requireProof: true"]);
  const config = cfg([...MUTE_RESIDUE, "residue:", "  requireProof: true"]);
  const first = await runCheck(dir, config);
  const artifact = first.artifacts?.[0];
  assert.ok(artifact !== undefined, "npm stage certified a digest for the valve to key on");
  appendRecord(dir, buildRoundtripRecord({ artifactSha256: artifact.sha256, verdict: "clean", rulesHash: first.report.rulesHash, rows: 0 }));
  const second = await runCheck(dir, config);
  assert.deepEqual(proofRows(second), []);
  assert.equal(second.report.verdict, "PASS", "the pre-supplied proof fact lifts the block — check itself never spawned docker");

  // Stale leg: same bytes, a rulesHash from a different world (e.g. residue
  // sources rotated since the proof ran) — the freshness pattern of check
  // fingerprints, applied to the proof record.
  const dir2 = proofRepo("c-t3-rceditor", [...MUTE_RESIDUE, "residue:", "  requireProof: true"]);
  appendRecord(dir2, buildRoundtripRecord({ artifactSha256: artifact.sha256, verdict: "clean", rulesHash: "9".repeat(64), rows: 0 }));
  const stale = await runCheck(dir2, config);
  const rows = proofRows(stale);
  assert.equal(rows.length, 1);
  assert.equal(rows[0]?.rule, ROUNDTRIP_PROOF_STALE_RULE);
  assert.equal(stale.report.verdict, "FAIL");
});

test("W2.2-integration: proof findings are ordinary native findings — allow-list suppresses them like everything else", async () => {
  const extra = [...MUTE_RESIDUE, `  - rule: ${ROUNDTRIP_PROOF_MISSING_RULE}`, '    match: "*"', "residue:", "  requireProof: true"];
  const dir = proofRepo("c-t3-rceditor", extra);
  const o = await runCheck(dir, cfg(extra));
  assert.deepEqual(proofRows(o), [], "no proof row survives the allow-list");
  const hit = (o.report.allowHits ?? []).find((h) => h.rule === ROUNDTRIP_PROOF_MISSING_RULE);
  assert.ok(hit !== undefined && hit.count === 1, "but the suppression is ENUMERATED — exit 0 never hides what it hid (G14)");
  assert.equal(o.report.verdict, "PASS");
});

test("W2.2-integration: default OFF — identical repo+findings without requireProof stay PASS, and a residue-clean repo never grows an obligation", async () => {
  const dir = proofRepo("c-t3-rceditor", MUTE_RESIDUE);
  const o = await runCheck(dir, cfg(MUTE_RESIDUE));
  assert.deepEqual(proofRows(o), [], "absent key === false === no valve (0.3.x behavior byte-identical)");
  assert.equal(o.report.verdict, "PASS");

  const clean = proofRepo("e-t0-clean", ["residue:", "  requireProof: true"]);
  const oc = await runCheck(clean, cfg(["residue:", "  requireProof: true"]));
  assert.deepEqual(proofRows(oc), [], "no blocking residue row ⇒ nothing to prove ⇒ the valve stays shut even when armed");
});
