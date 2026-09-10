// provenance: border-inspect-roadmap.md W2.2 — the `t:"roundtrip"` ledger record.
//
// `border roundtrip` pre-supplies the proof fact that the requireProof valve
// consumes (fail-closed-by-absence: `border check` NEVER runs docker itself, it
// only reads this record). The record captures the FACT of a run — artifact
// sha256 + verdict (clean OR residue, both recorded) + the roundtrip rulesHash
// + residue row count — keyed for digest lookup. Corruption tolerance mirrors
// the existing record types: a torn line is WARNING+skip, never a crash.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { appendFileSync } from "node:fs";
import { after, test } from "node:test";

import {
  appendRecord,
  buildRoundtripRecord,
  latestRoundtripForSha,
  ledgerPath,
  parseLedgerRecord,
  readLedger,
  type RoundtripRecord,
  type RoundtripVerdict,
} from "../src/ledger.ts";
import { gitInit, makeFixtureDir, removeDir } from "./helpers/fixtures.ts";

const roots: string[] = [];
after(() => {
  for (const d of roots) removeDir(d);
});

function fixture(name: string): string {
  const dir = makeFixtureDir(`led-rt-${name}`);
  gitInit(dir);
  roots.push(dir);
  return dir;
}

const SHA_A = "a".repeat(64);
const SHA_B = "b".repeat(64);
const RH_1 = "1".repeat(64);
const RH_2 = "2".repeat(64);

test("W2.2-ledger: roundtrip record appends, reads back field-complete, digest-keyed", () => {
  const dir = fixture("round");
  const rec = buildRoundtripRecord({ artifactSha256: SHA_A, verdict: "clean", rulesHash: RH_1, rows: 0, ts: "2026-09-11T00:00:00.000Z" });
  appendRecord(dir, rec);
  const { records, warnings } = readLedger(dir);
  assert.deepEqual(warnings, []);
  assert.equal(records.length, 1);
  const back = records[0];
  assert.ok(back?.t === "roundtrip");
  assert.deepEqual(back, rec);
  // The on-disk shape is exactly the task's schema: t/artifactSha256/verdict/rulesHash/rows/ts.
  const line = readFileSync(ledgerPath(dir), "utf8").trim();
  const raw = JSON.parse(line) as Record<string, unknown>;
  assert.deepEqual(Object.keys(raw).sort(), ["artifactSha256", "rows", "rulesHash", "t", "ts", "verdict"]);
  // Digest-keyed lookup: exact sha or nothing.
  assert.equal(latestRoundtripForSha(records, SHA_A)?.rulesHash, RH_1);
  assert.equal(latestRoundtripForSha(records, SHA_B), null);
});

test("W2.2-ledger: both verdicts are records — the FACT is the record, not the verdict", () => {
  const dir = fixture("verdicts");
  appendRecord(dir, buildRoundtripRecord({ artifactSha256: SHA_A, verdict: "clean", rulesHash: RH_1, rows: 0 }));
  appendRecord(dir, buildRoundtripRecord({ artifactSha256: SHA_B, verdict: "residue", rulesHash: RH_1, rows: 3 }));
  const { records } = readLedger(dir);
  assert.equal(records.length, 2);
  const a = latestRoundtripForSha(records, SHA_A);
  const b = latestRoundtripForSha(records, SHA_B);
  assert.ok(a?.t === "roundtrip" && a.verdict === "clean");
  assert.ok(b?.t === "roundtrip" && b.verdict === "residue" && b.rows === 3);
});

test("W2.2-ledger: newest record for a sha wins (append-only re-run after a fix)", () => {
  const dir = fixture("newest");
  appendRecord(dir, buildRoundtripRecord({ artifactSha256: SHA_A, verdict: "residue", rulesHash: RH_1, rows: 2, ts: "2026-09-11T00:00:00.000Z" }));
  appendRecord(dir, buildRoundtripRecord({ artifactSha256: SHA_A, verdict: "clean", rulesHash: RH_2, rows: 0, ts: "2026-09-11T01:00:00.000Z" }));
  const { records } = readLedger(dir);
  const newest = latestRoundtripForSha(records, SHA_A);
  assert.ok(newest?.t === "roundtrip");
  assert.equal(newest.rulesHash, RH_2, "a re-run supersedes: the LATEST fact about these bytes is the one the valve consumes");
});

test("W2.2-ledger: malformed roundtrip lines are WARNING+skip, never a crash (parse trust boundary)", () => {
  const dir = fixture("corrupt");
  appendRecord(dir, buildRoundtripRecord({ artifactSha256: SHA_A, verdict: "clean", rulesHash: RH_1, rows: 0 }));
  appendFileSync(ledgerPath(dir), '{"t":"roundtrip","artifactSha256":"nope","verdict":"clean","rulesHash":"ffff","rows":0,"ts":"x"}\n', "utf8");
  appendFileSync(ledgerPath(dir), "not json at all\n", "utf8");
  const { records, warnings } = readLedger(dir);
  assert.equal(records.length, 1, "only the well-formed line survives");
  assert.equal(warnings.length, 2, "torn/invalid lines warn, they never crash and never silently vanish");
});

test("W2.2-ledger: buildRoundtripRecord validates at the mint site (hex64, verdict enum, integer rows)", () => {
  assert.throws(() => buildRoundtripRecord({ artifactSha256: "short", verdict: "clean", rulesHash: RH_1, rows: 0 }), /artifactSha256/);
  assert.throws(() => buildRoundtripRecord({ artifactSha256: SHA_A, verdict: "clean", rulesHash: "XYZ", rows: 0 }), /rulesHash/);
  assert.throws(() => buildRoundtripRecord({ artifactSha256: SHA_A, verdict: "PASS" as unknown as RoundtripVerdict, rulesHash: RH_1, rows: 0 }), /verdict/);
  assert.throws(() => buildRoundtripRecord({ artifactSha256: SHA_A, verdict: "clean", rulesHash: RH_1, rows: -1 }), /rows/);
  assert.throws(() => buildRoundtripRecord({ artifactSha256: SHA_A, verdict: "clean", rulesHash: RH_1, rows: 1.5 }), /rows/);
  // parseLedgerRecord mirrors the same boundary for hand-edited lines.
  assert.throws(() => parseLedgerRecord({ t: "roundtrip", artifactSha256: SHA_A, verdict: "residue", rulesHash: RH_1, rows: "0", ts: "t" }), /rows/);
  const ok: RoundtripRecord = parseLedgerRecord({ t: "roundtrip", artifactSha256: SHA_A, verdict: "residue", rulesHash: RH_1, rows: 2, ts: "t" }) as RoundtripRecord;
  assert.equal(ok.t, "roundtrip");
  assert.equal(ok.rows, 2);
});
