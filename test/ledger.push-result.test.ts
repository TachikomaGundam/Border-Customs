// Schema contract of the t:"push-result" verdict record (Sibyl ticket 2026-11-08
// wound 2): mint-site gates, append/parse roundtrip, prose-url scrubbing of the
// why-text (sanitizeUrl's fail-closed whole-string redaction must never fire on
// prose), and the corruption-tolerant reader path.
import assert from "node:assert/strict";
import { appendFileSync, readFileSync } from "node:fs";
import { after, test } from "node:test";

import {
  appendRecord,
  buildPushResultRecord,
  ledgerPath,
  parseLedgerRecord,
  readLedger,
  type PushResultRecord,
} from "../src/ledger/records.ts";
import { makeFixtureDir, removeDir } from "./helpers/fixtures.ts";

const HEX64 = "a".repeat(64);
const roots: string[] = [];
after(() => {
  for (const d of roots) removeDir(d);
});

function scratch(): string {
  const dir = makeFixtureDir("pr-ledger");
  roots.push(dir);
  return dir;
}

test("mint gate: closed verdict enum, hex key, non-empty targets, bounded gitExit", () => {
  assert.throws(() => buildPushResultRecord({ verdict: "maybe" as "landed", targets: ["git:origin"] }), /verdict must be one of/);
  assert.throws(() => buildPushResultRecord({ verdict: "landed", key: "nothex", targets: ["git:origin"] }), /key is not hex-shaped/);
  assert.throws(() => buildPushResultRecord({ verdict: "failed", targets: [] }), /targets must be a non-empty/);
  assert.throws(() => buildPushResultRecord({ verdict: "failed", targets: ["git:origin", ""] }), /targets must be a non-empty/);
  assert.throws(() => buildPushResultRecord({ verdict: "partial", targets: ["git:origin"], gitExit: -1 }), /gitExit/);
  assert.throws(() => buildPushResultRecord({ verdict: "partial", targets: ["git:origin"], gitExit: 1.5 }), /gitExit/);
  const ok = buildPushResultRecord({ verdict: "failed", key: HEX64, targets: ["git:origin"], branch: "main", gitExit: null });
  assert.equal(ok.t, "push-result");
  assert.equal(ok.gitExit, null, "null (killed/unconfirmed) is a legal recorded value");
  assert.equal(ok.engineBuild !== undefined, true);
});

test("why-text: prose survives; url-shaped tokens inside prose lose credentials", () => {
  const prose = buildPushResultRecord({
    verdict: "blocked",
    targets: ["git:origin"],
    reason: "history diverged; border never force-pushes; resolve manually — moved tag: no refspec/tag-move channel",
  });
  assert.match(prose.reason ?? "", /tag-move channel/, "prose is NOT redacted wholesale (sanitizeUrl would fail-close it)");
  assert.equal((prose.reason ?? "").includes("[invalid-url-redacted]"), false);

  const withUrls = buildPushResultRecord({
    verdict: "partial",
    targets: ["git:origin"],
    reason: "push died at https://user:pass@github.com/acme/thing.git and scp form git@github.com:acme/thing.git too",
  });
  assert.equal((withUrls.reason ?? "").includes("user:pass"), false, "userinfo never reaches the ledger");
  assert.match(withUrls.reason ?? "", /github\.com\/acme\/thing\.git/);

  const long = buildPushResultRecord({ verdict: "failed", targets: ["git:origin"], reason: "x".repeat(4000) });
  assert.ok((long.reason ?? "").length <= 500, "one ledger line stays bounded");
});

test("append → read roundtrip preserves every field; torn line skips with a warning (never a crash)", () => {
  const dir = scratch();
  const rec = buildPushResultRecord({ verdict: "blocked", key: HEX64, targets: ["git:origin", "npm"], branch: "main", reason: "unchecked gate", gitExit: 0 });
  appendRecord(dir, rec);
  appendRecord(dir, buildPushResultRecord({ verdict: "landed", targets: ["npm"] }));

  const raw = readFileSync(ledgerPath(dir), "utf8").trimEnd();
  const { records, warnings } = readLedger(dir);
  assert.deepEqual(warnings, []);
  const rows = records.filter((r): r is PushResultRecord => r.t === "push-result");
  assert.equal(rows.length, 2);
  const first = rows[0];
  const second = rows[1];
  assert.ok(first !== undefined && second !== undefined);
  assert.deepEqual(first, parseLedgerRecord(JSON.parse(raw.split("\n")[0] ?? "")));
  assert.equal(first.verdict, "blocked");
  assert.deepEqual([...first.targets], ["git:origin", "npm"]);
  assert.equal(first.branch, "main");
  assert.equal(first.gitExit, 0, "exit code 0 must roundtrip, not vanish as falsy");
  assert.equal(second.verdict, "landed");
  assert.equal(second.key, undefined);

  appendRecord(dir, first); // valid
  appendFileSync(ledgerPath(dir), '{"t":"push-result","verdict":"nonsense","targets":["git:a"]}\n', "utf8");
  const reread = readLedger(dir);
  assert.equal(reread.warnings.length, 1, "unknown verdict on a line is loud, not fatal");
  assert.match(reread.warnings[0] ?? "", /verdict must be one of/);
  assert.equal(reread.records.filter((r) => r.t === "push-result").length, 3);
});
