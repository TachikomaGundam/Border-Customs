// provenance: ecc7e23-NIT closure, v0.3.2 wave — release-coherence SEED, R4-DOC oracle style.
//
// Owns exactly ONE pin: the User-Agent version literal inside SCAN_USER_AGENT
// (src/scan/fetch.ts) must equal package.json "version". The NIT was silent
// drift — 0.3.1 shipped while the UA still said border-customs/0.3.0, and
// nothing failed. This regex oracle reads the SOURCE TEXT (not the imported
// constant) so the pin also proves where the value lives: moving the literal
// into another module, or rewriting it via interpolation, breaks the match
// and fails loudly instead of vacuously passing.
//
// Deliberately narrow: full release coherence (Changelog/README version rows,
// the 0.1.0 probe UAs in src/channels/crates.ts + rubygems.ts, npm-dist-tag
// equality) stays the W4 wave per the v0.3.2 brief — do not grow this file here.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

import { BORDER_ROOT } from "./helpers/fixtures.ts";

const pkgVersion = (JSON.parse(readFileSync(join(BORDER_ROOT, "package.json"), "utf8")) as { version: string }).version;
const fetchSource = readFileSync(join(BORDER_ROOT, "src", "scan", "fetch.ts"), "utf8");

test("release coherence: src/scan/fetch.ts SCAN_USER_AGENT version literal equals package.json version", () => {
  const match = /export const SCAN_USER_AGENT = "border-customs\/([0-9]+\.[0-9]+\.[0-9]+) /.exec(fetchSource);
  assert.ok(
    match !== null,
    "SCAN_USER_AGENT literal not found in src/scan/fetch.ts — if the UA moved or changed shape, update THIS pin deliberately (fetch.ts header names this file)",
  );
  assert.equal(
    match?.[1],
    pkgVersion,
    `UA says border-customs/${match?.[1]} but package.json says ${pkgVersion} — single-source rule: bump both (src/scan/fetch.ts top comment)`,
  );
});
