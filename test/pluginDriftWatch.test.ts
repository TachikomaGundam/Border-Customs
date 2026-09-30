// provenance: .omo/plans/border-opencode-inspect.md T5 — the drift-watch shell's
// rc mapping (plan B2) with the cron contract pinned: cache/version aspects only,
// NOT-CACHED -> 0 special case, identity FAIL must never map to a purge trigger,
// rc 2 must never touch the cache, --purge stays a local rmSync. The shell is
// driven as a real process with BORDER_BIN pointed at the fake-inspect CLI —
// offline, deterministic, no async line counting (every observation is the
// exit code, the parsed --json line, or filesystem existence).
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { before, test } from "node:test";

import { ASPECT_IDS } from "../src/opencode/contract.ts";
import { BORDER_ROOT, FAKE_INSPECT_CLI, chmodFixtures, makeWorld, plantCacheDir, removeWorld } from "./helpers/inspectWorld.ts";

const SCRIPT = join(BORDER_ROOT, "tools", "plugin-drift-watch.mjs");

before(() => {
  chmodFixtures();
});

function inspectJson(verdicts: Partial<Record<(typeof ASPECT_IDS)[number], string>>, details: Record<string, string> = {}): string {
  return JSON.stringify({
    schemaVersion: 1,
    scope: "v1",
    verdict: "X",
    aspects: ASPECT_IDS.map((id) => ({ id, verdict: verdicts[id] ?? "PASS", detail: details[id] ?? `${id} ok` })),
  });
}

function watch(args: readonly string[], env: Record<string, string>): { status: number | null; json: Record<string, unknown> | null; stdout: string } {
  const r = spawnSync(process.execPath, [SCRIPT, ...args], { env: { ...process.env, ...env }, encoding: "utf8", timeout: 120_000 });
  let json: Record<string, unknown> | null = null;
  try {
    json = JSON.parse(r.stdout) as Record<string, unknown>;
  } catch {
    json = null;
  }
  return { status: r.status, json, stdout: r.stdout };
}

function fakeEnv(world: ReturnType<typeof makeWorld>, json: string): Record<string, string> {
  return { BORDER_BIN: FAKE_INSPECT_CLI, FAKE_INSPECT_JSON: json, XDG_CACHE_HOME: world.env["XDG_CACHE_HOME"] ?? "", HOME: world.home };
}

test("shell spawns exactly 'border opencode inspect --json' and maps all-PASS to rc 0 FRESH", () => {
  const world = makeWorld("drift-fresh");
  const log = join(world.home, "spawn.log");
  try {
    const r = watch(["border-customs", "--json"], { ...fakeEnv(world, inspectJson({})), FAKE_INSPECT_LOG: log });
    assert.equal(r.status, 0, r.stdout);
    assert.equal(r.json?.verdict, "FRESH");
    assert.equal(typeof r.json?.bin, "string", "M4: the resolved binary landing must be reported every run");
    assert.equal(readSafe(log).trim(), "opencode inspect --json", "the shell must delegate the verdict to inspect with exactly this argv");
  } finally {
    removeWorld(world);
  }
});

function readSafe(path: string): string {
  try {
    return readFileSync(path, "utf8");
  } catch {
    return "";
  }
}

test("spec-freshness FAIL maps to rc 1 DRIFT (the only cron-purging state)", () => {
  const world = makeWorld("drift-1");
  try {
    const r = watch(["--json"], fakeEnv(world, inspectJson({ "spec-freshness": "FAIL" }, { "spec-freshness": "cache holds latest->0.7.1, spec expects 0.8.0" })));
    assert.equal(r.status, 1);
    assert.equal(r.json?.verdict, "DRIFT");
    assert.ok(String(r.json?.detail).includes("0.8.0"), r.stdout);
  } finally {
    removeWorld(world);
  }
});

test("cache-version FAIL maps to rc 1 DRIFT", () => {
  const world = makeWorld("drift-2");
  try {
    const r = watch(["--json"], fakeEnv(world, inspectJson({ "cache-version": "FAIL" }, { "cache-version": "marker says 0.5.0, package.json says 0.7.1" })));
    assert.equal(r.status, 1);
    assert.equal(r.json?.verdict, "DRIFT");
  } finally {
    removeWorld(world);
  }
});

test("B2 special case: cache-version NOT-CACHED CANNOT maps back to rc 0 (was the pre-shell script's NOT-CACHED -> 0)", () => {
  const world = makeWorld("drift-3");
  try {
    const r = watch(["--json"], fakeEnv(world, inspectJson({ "cache-version": "CANNOT" }, { "cache-version": "NOT-CACHED: declared but no cache dir" })));
    assert.equal(r.status, 0, r.stdout);
    assert.equal(r.json?.verdict, "NOT-CACHED");
  } finally {
    removeWorld(world);
  }
});

test("registry-class CANNOT maps to rc 2 cannot-answer", () => {
  const world = makeWorld("drift-4");
  try {
    const r = watch(["--json"], fakeEnv(world, inspectJson({ "spec-freshness": "CANNOT" }, { "spec-freshness": "registry unreachable: socket hang up" })));
    assert.equal(r.status, 2);
    assert.equal(r.json?.verdict, "CANNOT-ANSWER");
  } finally {
    removeWorld(world);
  }
});

test("NOT-CACHED does not outrank a co-occurring registry CANNOT (rc 2 keeps priority, mirrors old fetch-first order)", () => {
  const world = makeWorld("drift-5");
  try {
    const r = watch(["--json"], fakeEnv(world, inspectJson({ "cache-version": "CANNOT", "spec-freshness": "CANNOT" }, { "cache-version": "NOT-CACHED: x", "spec-freshness": "registry down" })));
    assert.equal(r.status, 2);
    assert.equal(r.json?.verdict, "CANNOT-ANSWER");
  } finally {
    removeWorld(world);
  }
});

test("identity-handshake FAIL is OUT of the purge trigger: mapped aspects PASS -> rc 0 FRESH", () => {
  const world = makeWorld("drift-6");
  try {
    const r = watch(["--json"], fakeEnv(world, inspectJson({ "identity-handshake": "FAIL" }, { "identity-handshake": "impostor shape" })));
    assert.equal(r.status, 0, `an identity FAIL must never trigger the cron purge guard: ${r.stdout}`);
    assert.equal(r.json?.verdict, "FRESH");
  } finally {
    removeWorld(world);
  }
});

test("--purge on DRIFT removes the cache dirs locally and exits 0 (inspect never deletes anything)", () => {
  const world = makeWorld("drift-7");
  plantCacheDir(world, "latest", { version: "0.7.1", marker: "0.7.1" });
  const dir = join(world.cacheRoot, "border-customs@latest");
  try {
    const r = watch(["--json", "--purge"], fakeEnv(world, inspectJson({ "spec-freshness": "FAIL" })));
    assert.equal(r.status, 0, r.stdout);
    assert.equal(r.json?.verdict, "PURGED (cold start will re-fetch)");
    assert.ok(!existsSync(dir), "the shell must have rmSync'd the cache dir");
  } finally {
    removeWorld(world);
  }
});

test("--purge must NOT run when inspect says CANNOT-ANSWER: rc 2 and the cache stays untouched", () => {
  const world = makeWorld("drift-8");
  plantCacheDir(world, "latest", { version: "0.7.1", marker: "0.7.1" });
  const dir = join(world.cacheRoot, "border-customs@latest");
  try {
    const r = watch(["--json", "--purge"], fakeEnv(world, inspectJson({ "spec-freshness": "CANNOT" })));
    assert.equal(r.status, 2);
    assert.ok(existsSync(dir), "rc 2 must never touch the cache (cron doctrine)");
  } finally {
    removeWorld(world);
  }
});

test("an unspawnable BORDER_BIN is CANNOT-ANSWER rc 2", () => {
  const world = makeWorld("drift-9");
  try {
    const r = watch(["--json"], { ...fakeEnv(world, "{}"), BORDER_BIN: "/nonexistent-xyz" });
    assert.equal(r.status, 2);
    assert.equal(r.json?.verdict, "CANNOT-ANSWER");
  } finally {
    removeWorld(world);
  }
});

test("a non-JSON inspect stdout is CANNOT-ANSWER rc 2 (mapping cannot be guessed)", () => {
  const world = makeWorld("drift-10");
  try {
    const r = watch(["--json"], { ...fakeEnv(world, "usage: border <command>"), FAKE_INSPECT_RC: "2" });
    assert.equal(r.status, 2);
    assert.equal(r.json?.verdict, "CANNOT-ANSWER");
  } finally {
    removeWorld(world);
  }
});

test("a foreign pkg name is rc 2 and the fake CLI is never spawned (no guessed purge target)", () => {
  const world = makeWorld("drift-11");
  const log = join(world.home, "spawn.log");
  try {
    const r = watch(["other-pkg", "--json"], { ...fakeEnv(world, inspectJson({})), FAKE_INSPECT_LOG: log });
    assert.equal(r.status, 2);
    assert.equal(r.json?.verdict, "CANNOT-ANSWER");
    assert.equal(readSafe(log), "", "inspect must not have been spawned");
  } finally {
    removeWorld(world);
  }
});

test("human mode still reports and exits per the same mapping (cron line uses either mode)", () => {
  const world = makeWorld("drift-12");
  try {
    const r = watch([], fakeEnv(world, inspectJson({ "cache-version": "FAIL" })));
    assert.equal(r.status, 1);
    assert.match(r.stdout, /plugin-drift: border-customs \(single-source: border opencode inspect --json\)/);
    assert.match(r.stdout, /verdict: DRIFT/);
  } finally {
    removeWorld(world);
  }
});
