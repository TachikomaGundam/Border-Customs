// provenance: .omo/plans/border-opencode-inspect.md T5 — CLI surface of
// `border opencode inspect`: dispatch, --json flag stripping before subcommand
// match, the exit-2 error paths, and the acceptance #2b sabotage run through
// the real process seam (BORDER_BIN fixture, XDG sandbox).
import assert from "node:assert/strict";
import { existsSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { before, test } from "node:test";

import { run, usage } from "../src/cli.ts";
import { ASPECT_IDS } from "../src/opencode/contract.ts";
import { BORDER_ROOT, HELP_RESPONDER, IMPOSTOR, chmodFixtures, makeWorld, plantRouteADrop, removeWorld, writeConfig, type World } from "./helpers/inspectWorld.ts";

before(() => {
  chmodFixtures();
});

async function cli(world: World, args: readonly string[], extraEnv: Record<string, string> = {}): Promise<{ code: number; out: string[]; err: string[] }> {
  const out: string[] = [];
  const err: string[] = [];
  const code = await run(["opencode", ...args], (l) => out.push(l), (l) => err.push(l), { cwd: world.cwd, env: { ...world.env, ...extraEnv } });
  return { code, out, err };
}

const AS_ENV = (world: World): Record<string, string> => ({ BORDER_BIN: HELP_RESPONDER, ...world.env }) as Record<string, string>;

test("opencode inspect on a clean sandbox world: exit 0 with all six PASS aspects via the real process", async () => {
  const world = makeWorld("inspect-cli-pass");
  try {
    const r = await cli(world, ["inspect", "--json"], AS_ENV(world));
    assert.equal(r.code, 0, r.out.join("\n") + r.err.join("\n"));
    const report = JSON.parse(r.out[0] ?? "{}") as { schemaVersion: number; scope: string; verdict: string; aspects: { id: string; verdict: string }[] };
    assert.equal(report.schemaVersion, 1);
    assert.equal(report.scope, "v1");
    assert.equal(report.verdict, "PASS");
    assert.deepEqual(report.aspects.map((x) => x.id), [...ASPECT_IDS]);
    assert.ok(report.aspects.every((x) => x.verdict === "PASS"), JSON.stringify(report.aspects));
  } finally {
    removeWorld(world);
  }
});

test("--json before and after the subcommand is consumed identically (flag stripped pre-dispatch)", async () => {
  const world = makeWorld("inspect-cli-flagpos");
  try {
    const after = await cli(world, ["inspect", "--json"], AS_ENV(world));
    const before = await cli(world, ["--json", "inspect"], AS_ENV(world));
    assert.equal(after.code, 0);
    assert.equal(before.code, 0, before.out.join("\n") + before.err.join("\n"));
    assert.deepEqual(JSON.parse(before.out[0] ?? "{}"), JSON.parse(after.out[0] ?? "{}"));
  } finally {
    removeWorld(world);
  }
});

test("existing subs are unbroken by the --json strip: install --json still installs", async () => {
  const world = makeWorld("inspect-cli-install");
  try {
    const r = await cli(world, ["install", "--json"], world.env);
    assert.equal(r.code, 0, r.err.join("\n"));
    assert.ok(existsSync(world.routeADrop), "install must still drop the plugin file");
    assert.ok(r.out.some((l) => l.includes("installed")), r.out.join("\n"));
  } finally {
    removeWorld(world);
  }
});

test("stray positional after inspect exits 2 naming the argument", async () => {
  const world = makeWorld("inspect-cli-stray");
  try {
    const r = await cli(world, ["inspect", "stray", "--json"], AS_ENV(world));
    assert.equal(r.code, 2);
    assert.ok(r.err.join("\n").includes("unexpected argument 'stray'"), r.err.join("\n"));
  } finally {
    removeWorld(world);
  }
});

test("unknown opencode subcommand exits 2 and the usage names inspect", async () => {
  const world = makeWorld("inspect-cli-unknown");
  try {
    const r = await cli(world, ["bogus"], world.env);
    assert.equal(r.code, 2);
    assert.ok(r.err.join("\n").includes("usage: border opencode install | status | uninstall | inspect"), r.err.join("\n"));
    assert.ok(usage().includes("install|status|uninstall|inspect"), "the border --help table must list the fourth verb");
  } finally {
    removeWorld(world);
  }
});

test("SABOTAGE (acceptance #2b end-to-end): BORDER_BIN impostor -> exit 1, identity-handshake FAIL, and the impostor only ever saw --help", async () => {
  const world = makeWorld("inspect-cli-impostor");
  const log = join(world.home, "impostor-calls.log");
  rmSync(log, { force: true });
  process.env["IMPOSTOR_LOG"] = log;
  try {
    const r = await cli(world, ["inspect"], { BORDER_BIN: IMPOSTOR, ...world.env });
    assert.equal(r.code, 1, r.out.join("\n"));
    assert.ok(r.out.some((l) => l.startsWith("  FAIL") && l.includes("identity-handshake")), r.out.join("\n"));
    const calls = readFileSync(log, "utf8").split("\n").filter((l) => l.length > 0);
    assert.deepEqual(calls, ["--help"], "inspect must only ever probe the candidate with --help, never hand it user argv");
  } finally {
    delete process.env["IMPOSTOR_LOG"];
    removeWorld(world);
  }
});

test("SABOTAGE (acceptance #2c end-to-end): dual registration on disk -> exit 1 dual-route FAIL", async () => {
  const world = makeWorld("inspect-cli-dual");
  writeConfig(world.globalConfig, ["border-customs@0.7.1"]);
  plantRouteADrop(world, readFileSync(join(BORDER_ROOT, "plugin", "border.ts")));
  try {
    const r = await cli(world, ["inspect", "--json"], AS_ENV(world));
    assert.equal(r.code, 1, r.out.join("\n"));
    const report = JSON.parse(r.out[0] ?? "{}") as { aspects: { id: string; verdict: string }[] };
    assert.equal(report.aspects.find((x) => x.id === "dual-route")?.verdict, "FAIL");
  } finally {
    removeWorld(world);
  }
});
