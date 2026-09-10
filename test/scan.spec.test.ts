// provenance: border-inspect-roadmap.md W1.1 — `border scan` spec parser.
//
// Table-driven unit coverage of parseScanSpec: `[ecosystem:]name@version`,
// default npm, scoped `@scope/pkg@ver` split at the LAST @, every garbage
// shape rejected as an UnknownArgError (the CLI maps it to exit 2 + usage).
import assert from "node:assert/strict";
import { test } from "node:test";

import { UnknownArgError } from "../src/cli/exit.ts";
import { ECOSYSTEMS, parseScanSpec } from "../src/scan/spec.ts";

type Row = readonly [label: string, raw: string, want: { ecosystem: string; name: string; version: string }];

const OK: readonly Row[] = [
  ["plain npm", "left-pad@1.3.0", { ecosystem: "npm", name: "left-pad", version: "1.3.0" }],
  ["explicit npm prefix", "npm:puppeteer@23.11.1", { ecosystem: "npm", name: "puppeteer", version: "23.11.1" }],
  ["scoped npm, split at LAST @", "@sugar/pina-pina@1.0.0", { ecosystem: "npm", name: "@sugar/pina-pina", version: "1.0.0" }],
  ["scoped npm, version with @ in prerelease-ish dots", "@scope/pkg@0.0.1-alpha.1", { ecosystem: "npm", name: "@scope/pkg", version: "0.0.1-alpha.1" }],
  ["pypi prefix", "pypi:requests@2.32.3", { ecosystem: "pypi", name: "requests", version: "2.32.3" }],
  ["crates prefix", "crates:serde@1.0.219", { ecosystem: "crates", name: "serde", version: "1.0.219" }],
  ["rubygems prefix", "rubygems:rails@7.1.1", { ecosystem: "rubygems", name: "rails", version: "7.1.1" }],
  ["ecosystem prefix + scoped name", "npm:@scope/pkg@2.0.0", { ecosystem: "npm", name: "@scope/pkg", version: "2.0.0" }],
  ["dotted versions", "crates:a.b@1.2.3-build.4", { ecosystem: "crates", name: "a.b", version: "1.2.3-build.4" }],
  ["underscore + plus chars kept", "pypi:my_pkg+extra@1.0", { ecosystem: "pypi", name: "my_pkg+extra", version: "1.0" }],
] as const;

for (const [label, raw, want] of OK) {
  test(`parseScanSpec accepts ${label}: '${raw}'`, () => {
    assert.deepEqual(parseScanSpec(raw), want);
  });
}

const BAD: readonly string[] = [
  "", // empty
  "   ", // whitespace only
  "nameonly", // no version
  "@scope/pkg", // scoped, no version
  "@scope/pkg@1.0@2.0", // double trailing @ segments
  "pypi:requests", // prefixed, no version
  "unknownpkg:name@1.0.0", // unknown ecosystem
  "PyPI:name@1.0.0", // ecosystem must be lowercase
  ":name@1.0.0", // empty ecosystem
  "pypi:@1.0.0", // empty name
  "pypi:name@", // empty version
  "@@@", // pure garbage
  "a b@c", // whitespace in name
  "name@1.0.0 extra", // trailing junk (whitespace splits would be argv's job)
  "../evil@1.0.0", // path traversal in name
  "npm:a/b@1.0.0", // unscoped name with a slash
  "pkg@1.0.0@2.0.0", // two @ on an unscoped name
] as const;

for (const raw of BAD) {
  test(`parseScanSpec rejects '${raw}' with an actionable usage line`, () => {
    assert.throws(
      () => parseScanSpec(raw),
      (err: unknown) => {
        assert.ok(err instanceof UnknownArgError, `UnknownArgError expected, got ${String(err)}`);
        assert.match(err.message, /usage: border scan <\[ecosystem:\]name@version>/);
        return true;
      },
    );
  });
}

test("ECOSYSTEMS is the closed set npm|pypi|crates|rubygems in registry order", () => {
  assert.deepEqual([...ECOSYSTEMS], ["npm", "pypi", "crates", "rubygems"]);
});
