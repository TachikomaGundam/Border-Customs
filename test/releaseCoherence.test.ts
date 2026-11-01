// Release coherence pins. Provenance: ecc7e23-NIT closure, v0.3.2 wave, then
// extended 2026-10-19 by the third-party audit's "version literals rotate by
// hand in seven places" finding.
//
// The original pin still guards the User-Agent: the literal inside
// SCAN_USER_AGENT (src/scan/fetch.ts) must equal package.json "version". The
// regex reads SOURCE TEXT, so moving the literal or interpolating it fails
// loudly instead of passing vacuously. The same pattern now covers the lock
// roots, the plugin header, the README install pin, and the UA project URL.
// `tools/version-sync.mjs` is the writer; this file is the independent reader.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

import { BORDER_ROOT } from "./helpers/fixtures.ts";

const pkg = JSON.parse(readFileSync(join(BORDER_ROOT, "package.json"), "utf8")) as {
  version: string;
  repository?: { url?: string };
  engines?: { node?: string };
};
const pkgVersion = pkg.version;
const fetchSource = readFileSync(join(BORDER_ROOT, "src", "scan", "fetch.ts"), "utf8");
const lock = JSON.parse(readFileSync(join(BORDER_ROOT, "package-lock.json"), "utf8")) as {
  version?: string;
  packages?: Record<string, { version?: string; engines?: { node?: string } }>;
};
const pluginFirstLine = readFileSync(join(BORDER_ROOT, "plugin", "border.ts"), "utf8").split("\n")[0] ?? "";
const readme = readFileSync(join(BORDER_ROOT, "README.md"), "utf8");

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

test("release coherence: package-lock root and packages[\"\"] carry the package.json version", () => {
  assert.equal(lock.version, pkgVersion, "package-lock.json root version drift (0.1.0 historical incident)");
  assert.equal(lock.packages?.[""]?.version, pkgVersion, "package-lock.json packages[\"\"] version drift");
});

test("release coherence: plugin header marker equals the package.json version", () => {
  assert.equal(
    pluginFirstLine,
    `// border-opencode-plugin v${pkgVersion}`,
    "plugin/border.ts line 1 marker drift — opencode inspect compares this line to package.json",
  );
});

test("release coherence: README plugin install pin equals the package.json version", () => {
  assert.ok(
    readme.includes(`"border-customs@${pkgVersion}"`),
    `README must pin border-customs@${pkgVersion} in the opencode plugin line`,
  );
});

test("release coherence: SCAN_USER_AGENT project URL matches package.json repository", () => {
  const uaUrl = /\(\+\s*(https:\/\/github\.com\/[^;)\s]+)/.exec(fetchSource)?.[1]?.replace(/\.git$/, "");
  const repoUrl = (pkg.repository?.url ?? "").replace(/^git\+/, "").replace(/\.git$/, "");
  assert.equal(uaUrl, repoUrl, "dead identity URL (2026-10-17 audit: gate-corp/border was 404)");
});

test("release coherence: the engines floor matches the transitive ini requirement", () => {
  // ini@7 (via @opencode-ai/plugin) declares ^22.22.2. A lower floor here makes
  // `npm ci` warn on a Node version border claims to support, so both floors
  // move together. Equal is intentional: raising our floor further is a
  // product decision, not an automatic follow.
  const iniRange = lock.packages?.["node_modules/ini"]?.engines?.node;
  assert.ok(typeof iniRange === "string", "node_modules/ini engines missing from package-lock.json");
  const iniFloor = /(\d+\.\d+\.\d+)/.exec(iniRange)?.[1];
  const ourFloor = /(\d+\.\d+\.\d+)/.exec(pkg.engines?.node ?? "")?.[1];
  assert.ok(iniFloor !== undefined && ourFloor !== undefined, "could not parse an engines floor");
  assert.equal(ourFloor, iniFloor, "package.json engines.node floor must match ini's requirement");
});
