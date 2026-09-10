// provenance: silent-bin incident regression lock (published border-customs
// @0.3.0/@0.3.1): `node_modules/.bin/border --help` exited rc=0 with ZERO
// stdout/stderr because entry detection compared import.meta.url against the
// raw argv[1] — a symlink under npm's bin shim — and silently skipped main().
// A security gate failing OPEN. This test rebuilds the exact consumer shape
// from the real artifact (npm pack -> npm install -> run the SHIM) so the bug
// can never ship again.
//
// Opt-in like the network legs (test/scan.test.ts doctrine): the offline
// suite skips it (BORDER_PACK_TEST=1 required); CI's Release gate step runs
// it against the freshly built dist before any tag is touched.
import assert from "node:assert/strict";
import { spawnSync, type SpawnSyncReturns } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { BORDER_ROOT } from "./helpers/fixtures.ts";

function runChecked(r: SpawnSyncReturns<string>, what: string, timeoutMs: number): void {
  assert.notEqual(r.status, null, `${what} was killed or timed out (${timeoutMs}ms): error=${String(r.error)}`);
  assert.equal(r.status, 0, `${what} failed (rc=${String(r.status)}):\nstderr: ${(r.stderr ?? "").slice(-2000)}`);
}

function spawnLogged(cmd: string, args: string[], opts: { cwd: string; env: NodeJS.ProcessEnv; timeout: number }, what: string): void {
  runChecked(spawnSync(cmd, args, { ...opts, encoding: "utf8" }), what, opts.timeout);
}

test("published artifact consumer smoke: border --help fires through the npm bin shim (opt-in: BORDER_PACK_TEST=1)", (t) => {
  if (process.env.BORDER_PACK_TEST !== "1") {
    t.skip("pack e2e is opt-in — offline suite stays green");
    return;
  }

  // The tarball ships files:["dist"] only — a stale dist would pack the OLD
  // predicate and prove nothing. The CI step ordering (Build -> Release gate)
  // guarantees freshness; assert it locally anyway, fail loudly, never skip.
  const distBin = join(BORDER_ROOT, "dist", "index.js");
  assert.ok(existsSync(distBin), "dist/index.js missing — run `npm run build` before BORDER_PACK_TEST=1 npm test");

  const version = (JSON.parse(readFileSync(join(BORDER_ROOT, "package.json"), "utf8")) as { version: string }).version;
  const root = mkdtempSync(join(tmpdir(), "border-pack-"));
  try {
    const home = join(root, "home");
    const project = join(root, "consumer");
    mkdirSync(home);
    mkdirSync(project);
    const env: NodeJS.ProcessEnv = { ...process.env, HOME: home }; // throwaway npm cache, no global state touched

    spawnLogged("npm", ["pack", "--pack-destination", root], { cwd: BORDER_ROOT, env, timeout: 180_000 }, "npm pack");
    const tarball = join(root, `border-customs-${version}.tgz`);
    assert.ok(existsSync(tarball), `npm pack produced no tarball at ${tarball}`);

    writeFileSync(join(project, "package.json"), '{"name":"pack-consumer","version":"1.0.0","private":true}\n');
    spawnLogged("npm", ["install", tarball, "--no-audit", "--no-fund"], { cwd: project, env, timeout: 600_000 }, "npm install <tarball>");

    // The incident's exact invocation: shebang-via-shim. Kernel hands node the
    // SYMLINK path as argv[1]; main() must still fire. rc=0 + empty stdout was
    // the fail-open signature — assert on content, not just exit code.
    const shim = join(project, "node_modules", ".bin", "border");
    assert.ok(existsSync(shim), "npm install produced no bin shim");
    const help = spawnSync(shim, ["--help"], { cwd: project, env, encoding: "utf8", timeout: 60_000 });
    runChecked(help, "border --help via shim", 60_000);
    const helpOut = help.stdout ?? "";
    assert.ok(helpOut.trim().length > 0, "silent-bin incident regression: shim --help exited 0 with ZERO stdout");
    assert.match(helpOut, /scan/, "`border --help` via shim must list the scan subcommand");
    assert.match(helpOut, /roundtrip/, "`border --help` via shim must list the roundtrip subcommand");

    // Control path the smoke step already used pre-incident: absolute dist —
    // proves both spellings now resolve to the same canonical module.
    const installedDist = join(project, "node_modules", "border-customs", "dist", "index.js");
    const direct = spawnSync(process.execPath, [installedDist, "--help"], { cwd: project, env, encoding: "utf8", timeout: 60_000 });
    runChecked(direct, "border --help via absolute dist", 60_000);
    assert.match(direct.stdout ?? "", /scan/, "`border --help` via absolute dist path must list the scan subcommand");
    assert.match(direct.stdout ?? "", /roundtrip/, "`border --help` via absolute dist path must list the roundtrip subcommand");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
