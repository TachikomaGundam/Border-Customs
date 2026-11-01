// provenance: Abathur handoff 2026-11-01 (commit b61b42a) — syntax-aware
// credential-location guard. The fixture table below is the handoff's §4 table
// VERBATIM (paths and snippets); this test drives the real tree leg so the
// guard is exercised exactly as `border check` runs it.
import assert from "node:assert/strict";
import { test } from "node:test";

import { scanExfilTree } from "../src/check/exfilTreeScan.ts";
import type { Finding } from "../src/findings.ts";

const FIXTURE_ROOT = "test/fixtures-span-guard/";

const under = (names: readonly string[]): string[] => names.map((n) => `${FIXTURE_ROOT}${n}`);

function fixtureFindings(): Finding[] {
  // the tree leg fences to a repo root (GIT_CEILING_DIRECTORIES) — scan the
  // repository and select the fixture subtree by path prefix.
  return scanExfilTree({ repoDir: "." }).filter((f) => (f.path ?? "").startsWith(FIXTURE_ROOT));
}

function credFindings(): Finding[] {
  return fixtureFindings().filter((f) => f.rule === "exfil-cred-location");
}

const POS = [
  "pos/read-secret.js",
  "pos/read-nested.ts",
  "pos/doc.md",
  "pos/template.js",
];
const NEG = [
  "neg/member-access.js",
  "neg/member-access-deep.ts",
  "neg/member-short.js",
  "neg/comment.js",
];

test("span guard: the four positives are reported by exfil-cred-location", () => {
  const paths = new Set(credFindings().map((f) => f.path ?? ""));
  for (const p of under(POS)) assert.ok(paths.has(p), `expected a credential-location finding for ${p}, saw: ${[...paths].join(", ")}`);
});

test("span guard: no neg path is ever reported (members, short receivers, comments)", () => {
  const paths = new Set(credFindings().map((f) => f.path ?? ""));
  for (const n of under(NEG)) assert.ok(!paths.has(n), `path ${n} must NOT be reported; saw: ${[...paths].join(", ")}`);
});

test("span guard: non-JS/TS files keep the bare-mention behavior", () => {
  // doc.md carries NO member syntax and must behave exactly as before: one hit.
  const hits = credFindings().filter((f) => (f.path ?? "") === `${FIXTURE_ROOT}pos/doc.md`);
  assert.equal(hits.length, 1);
});

test("span guard: the home-path rule is NOT weakened by the literal-span logic", () => {
  // mixed/mix.js carries a real /home path in a literal AND a member access on
  // the next line: the home finding must still fire, the .env token must not.
  const mixed = fixtureFindings().filter((f) => (f.path ?? "").endsWith("mix.js"));
  assert.ok(mixed.some((f) => f.rule === "exfil-home-path"), `exfil-home-path must still fire, saw: ${mixed.map((f) => f.rule).join(", ")}`);
  assert.ok(!mixed.some((f) => f.rule === "exfil-cred-location"), "opts.env inside code must not fire even beside a real home path");
});
