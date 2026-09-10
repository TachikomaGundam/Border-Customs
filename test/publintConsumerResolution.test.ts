// provenance: v0.3.2 publint-runtime-dep wave — consumer bin-shim resolution lock.
//
// publint moved from devDependencies to an exact-pinned runtime dependency so the
// npm-stage publint-fail leg works out of the box in a consumer install. That only
// pays off if the resolver actually FINDS the hoisted binary: npm installs border's
// dependency graph FLAT — a .bin-shim consumer never gets
// <proj>/node_modules/border-customs/node_modules/.bin (that directory does not
// exist), the link lives at <proj>/node_modules/.bin/publint. The third
// publintLocalBins candidate walks exactly there. Same two-layer shape as
// test/entryPoint.test.ts: pure builder unit + one spawned mechanics oracle.
import assert from "node:assert/strict";
import { chmodSync, mkdirSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

import { publintLocalBins } from "../src/artifacts/npmPack.ts";
import { spawnEngine } from "../src/engines/support.ts";
import { makeFixtureDir, removeDir } from "./helpers/fixtures.ts";

test("publintLocalBins: src layout (npm test) keeps repo/node_modules/.bin reachable", () => {
  const bins = publintLocalBins("/repo/src/artifacts");
  assert.ok(bins.includes("/repo/node_modules/.bin/publint"), `src-mode candidate missing: ${bins.join(", ")}`);
});

test("publintLocalBins: dev dist layout keeps repo/node_modules/.bin reachable", () => {
  const bins = publintLocalBins("/repo/dist");
  assert.ok(bins.includes("/repo/node_modules/.bin/publint"), `dist-mode candidate missing: ${bins.join(", ")}`);
});

test("publintLocalBins: consumer-hoisted .bin (flat npm install) is a candidate", () => {
  // the incident shape: npm install border-customs -> dist/index.js runs from
  // <proj>/node_modules/border-customs/dist; publint is hoisted beside it.
  const bins = publintLocalBins("/proj/node_modules/border-customs/dist");
  assert.ok(bins.includes("/proj/node_modules/.bin/publint"), `consumer-hoist candidate missing: ${bins.join(", ")}`);
  // nested-install fallback (npm keeps the dep inside the package dir on conflicts):
  assert.ok(bins.includes("/proj/node_modules/border-customs/node_modules/.bin/publint"), "nested candidate missing");
});

test("oracle: spawnEngine executes the hoisted .bin symlink the third candidate names", () => {
  // Proves the MECHANICS, not our math: an npm-style .bin entry is a symlink to a
  // shebang script two levels up, and spawnSync execve's it exactly like the real
  // publint link. Fixture tree:
  //   <fix>/node_modules/publint-pkg/bin.mjs        (the "installed" CLI)
  //   <fix>/node_modules/.bin/publint -> ../publint-pkg/bin.mjs
  //   <fix>/node_modules/border-customs/dist/       (HERE for the candidate walk)
  const fix = makeFixtureDir("publint-consumer-");
  try {
    mkdirSync(join(fix, "node_modules", "publint-pkg"), { recursive: true });
    mkdirSync(join(fix, "node_modules", ".bin"), { recursive: true });
    writeFileSync(
      join(fix, "node_modules", "publint-pkg", "bin.mjs"),
      "#!/usr/bin/env node\nconsole.log('publint fired: ' + process.argv.slice(2).join(' '));\n",
      { mode: 0o755 },
    );
    chmodSync(join(fix, "node_modules", "publint-pkg", "bin.mjs"), 0o755);
    const link = join(fix, "node_modules", ".bin", "publint");
    symlinkSync("../publint-pkg/bin.mjs", link);

    const here = join(fix, "node_modules", "border-customs", "dist");
    const hoisted = publintLocalBins(here).find((c) => c === link);
    assert.ok(hoisted !== undefined, "candidate builder must name the hoisted .bin link for this layout");
    const out = spawnEngine([link], ["some.tgz", "--level", "error"], { timeoutMs: 30_000 });
    assert.equal(out.status, 0, `spawn via .bin symlink failed: ${out.stderr}`);
    assert.equal(out.stdout.trim(), "publint fired: some.tgz --level error");
  } finally {
    removeDir(fix);
  }
});
