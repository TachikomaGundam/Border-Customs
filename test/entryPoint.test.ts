// provenance: original clean-room implementation — silent-bin incident regression
// (border-customs@0.3.0/0.3.1 published artifact: `node_modules/.bin/border`
// shim exited rc=0 with ZERO stdout/stderr because the old isMainModule()
// compared import.meta.url against the RAW argv[1] spelling; under
// shebang-via-shim invocation those are different paths: argv[1] is the
// symlink npm installs, import.meta.url is Node's realpath-resolved target.
// A security gate failing OPEN to rc 0. Fix: realpath-canonicalize BOTH
// sides before comparing — pinned here as a pure predicate unit + a
// self-contained node-semantics oracle spawned through a real symlink.)
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { isMainModule } from "../src/index.ts";

// ------------------------------------------------ pure predicate unit (src/index.ts)

const MODULE_URL = "file:///consumer/node_modules/border-customs/dist/index.js";

test("isMainModule: direct invocation (argv1 == module path) fires", () => {
  const identityRealpath = (p: string): string => p;
  assert.equal(
    isMainModule({ argv1: "/consumer/node_modules/border-customs/dist/index.js", moduleUrl: MODULE_URL, realpath: identityRealpath }),
    true,
  );
});

test("isMainModule: consumer-shim shape — argv1 is the symlink, moduleUrl the realpath target — fires", () => {
  // exactly what npm's bin link does: node_modules/.bin/border ->
  // ../border-customs/dist/index.js; kernel passes the LINK path as argv[1].
  const shimRealpath = (p: string): string =>
    p === "/consumer/node_modules/.bin/border" ? "/consumer/node_modules/border-customs/dist/index.js" : p;
  assert.equal(isMainModule({ argv1: "/consumer/node_modules/.bin/border", moduleUrl: MODULE_URL, realpath: shimRealpath }), true);
});

test("isMainModule: an unrelated argv1 (test runner, `node -e`) never fires", () => {
  const identityRealpath = (p: string): string => p;
  assert.equal(isMainModule({ argv1: "/elsewhere/some-other-cli.js", moduleUrl: MODULE_URL, realpath: identityRealpath }), false);
  assert.equal(isMainModule({ argv1: undefined, moduleUrl: MODULE_URL, realpath: identityRealpath }), false);
});

test("isMainModule: realpath ENOENT-safe — missing argv[1] falls back to the raw spelling, never throws", () => {
  const enoentRealpath = (p: string): string => {
    if (p === "/gone/border") {
      const err = new Error(`ENOENT: no such file or directory, realpath '/gone/border'`);
      (err as NodeJS.ErrnoException).code = "ENOENT";
      throw err;
    }
    return p;
  };
  // raw-fallback path equals the canonical module path ⇒ still detected
  assert.equal(isMainModule({ argv1: MODULE_URL.slice("file://".length), moduleUrl: MODULE_URL, realpath: enoentRealpath }), true);
  // raw-fallback differs ⇒ false, but NO exception escapes the entry gate
  assert.equal(isMainModule({ argv1: "/gone/border", moduleUrl: MODULE_URL, realpath: enoentRealpath }), false);
});

// --------------------------------- node symlink-entry semantics oracle (spawned)

// Self-contained on purpose: these scripts pin NODE's behavior (argv[1] = the
// path as invoked, import.meta.url = realpath of the main module), not our
// predicate — the predicate itself is unit-tested above and the shipped
// artifact is proven end-to-end by test/releaseArtifacts.test.ts.
const OLD_PATTERN = `import { pathToFileURL } from "node:url";
const entry = process.argv[1];
const isMain = entry !== undefined && import.meta.url === pathToFileURL(entry).href;
if (isMain) console.log("main fired");
`;

const NEW_PATTERN = `import { realpathSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
const canonical = (p) => { try { return realpathSync.native(p); } catch { return p; } };
const entry = process.argv[1];
const isMain = entry !== undefined &&
  pathToFileURL(canonical(entry)).href === pathToFileURL(canonical(fileURLToPath(import.meta.url))).href;
if (isMain) console.log("main fired");
`;

function spawnEntryScript(body: string, viaSymlink: boolean): { code: number | null; stdout: string } {
  const dir = mkdtempSync(join(tmpdir(), "border-entry-"));
  try {
    const prog = join(dir, "prog.mjs");
    const link = join(dir, "link.mjs");
    writeFileSync(prog, body, { mode: 0o755 });
    symlinkSync(prog, link);
    const r = spawnSync(process.execPath, [viaSymlink ? link : prog], { encoding: "utf8", timeout: 30_000 });
    assert.notEqual(r.status, null, `entry script must not time out: ${String(r.error)}`);
    return { code: r.status, stdout: r.stdout ?? "" };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test("node semantics oracle: realpath-hardened entry detection prints 'main fired' through a symlinked path", () => {
  const viaLink = spawnEntryScript(NEW_PATTERN, true);
  assert.equal(viaLink.code, 0);
  assert.match(viaLink.stdout, /main fired/, "realpath-hardened predicate must fire under symlink invocation");
  assert.match(spawnEntryScript(NEW_PATTERN, false).stdout, /main fired/, "and under the direct path too");
});

test("node semantics oracle: the OLD raw-spelling predicate reproduces the silent fail-open (rc 0, no 'main fired') via symlink", () => {
  const viaLink = spawnEntryScript(OLD_PATTERN, true);
  assert.equal(viaLink.code, 0, "old bug: the gate exits 0 while skipping main() — failing OPEN");
  assert.doesNotMatch(viaLink.stdout, /main fired/, "old predicate must NOT fire through a symlink (that is the incident)");
  assert.match(spawnEntryScript(OLD_PATTERN, false).stdout, /main fired/, "old predicate only fired on the direct spelling");
});
