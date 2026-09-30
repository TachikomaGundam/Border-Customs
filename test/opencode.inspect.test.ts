// provenance: .omo/plans/border-opencode-inspect.md T5 — `border opencode inspect`
// core suite: per-aspect units, the aggregation priority matrix, the --json
// surface, the T2 handshake mirror pin, and the import-audit guard. Every side
// channel is an injected seam (M2 ruler-injury discipline: no async log-line
// counting, no real spawn, no real network, no real HOME/XDG).
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { before, test } from "node:test";

import { usage } from "../src/cli.ts";
import { EXIT_BLOCKED, EXIT_ERROR, EXIT_PASS } from "../src/cli/exit.ts";
import { runInspectCore, aggregateVerdict, gatherFacts, inspectExit, type InspectDeps } from "../src/opencode/inspect.ts";
import { verifyCacheVersion } from "../src/opencode/aspects/cacheVersion.ts";
import { verifySpecFreshness } from "../src/opencode/aspects/specFreshness.ts";
import { verifyIdentity } from "../src/opencode/aspects/identity.ts";
import { verifyRouteAParity } from "../src/opencode/aspects/routeA.ts";
import { verifyDualRoute } from "../src/opencode/aspects/dualRoute.ts";
import { verifyScope, SCOPE_UNCOVERED } from "../src/opencode/aspects/scope.ts";
import { HANDSHAKE_ARGV, HANDSHAKE_BANNER_PREFIX, HANDSHAKE_TIMEOUT_MS, HANDSHAKE_USAGE_NEEDLE, identityCandidates, passesHandshake } from "../src/opencode/aspects/identity.ts";
import { ASPECT_IDS, PLUGIN_MARKER, type AspectResult, type Env } from "../src/opencode/contract.ts";
import { listCacheDirs, splitNpmSpec } from "../src/opencode/jsonconfig.ts";
import {
  BORDER_ROOT,
  cacheDir,
  chmodFixtures,
  configSource,
  factsOver,
  fakeRegistry,
  inspectCtx,
  makeWorld,
  plantCacheDir,
  plantRouteADrop,
  registryForbidsCalls,
  removeWorld,
  scriptedRunner,
  SPAWNED_OK,
  writeConfig,
} from "./helpers/inspectWorld.ts";

const PACKAGED_PLUGIN = readFileSync(join(BORDER_ROOT, "plugin", "border.ts"));

before(() => {
  chmodFixtures();
});

function core(env: Env, cwd: string, deps: InspectDeps, json = false) {
  const cap = inspectCtx(env, cwd, json);
  return { ...cap, run: () => runInspectCore(cap.ctx, deps) };
}

const OFFLINE = (runner = scriptedRunner(() => SPAWNED_OK)): { deps: InspectDeps; runner: typeof runner } => ({ deps: { runner: runner.runner, registryFetcher: registryForbidsCalls.fetcher, distEntry: "/nonexistent-border" }, runner });

// ---------------------------------------------------------------- aspect 1: cache-version

test("cache-version PASS when no dirs exist and nothing is declared", () => {
  const r = verifyCacheVersion(factsOver({}));
  assert.equal(r.verdict, "PASS");
});

test("cache-version NOT-CACHED CANNOT when config declares the plugin but the cache is empty", () => {
  const r = verifyCacheVersion(factsOver({ configs: [configSource("/g", "ok", ["border-customs@latest"]), configSource("/p", "absent")] }));
  assert.equal(r.verdict, "CANNOT");
  assert.ok(r.detail.startsWith("NOT-CACHED:"), `B2 shell contract needs the NOT-CACHED token prefix, got: ${r.detail}`);
});

test("cache-version CANNOT when the cache is empty and the config is unreadable", () => {
  const r = verifyCacheVersion(factsOver({ configs: [configSource("/g", "error"), configSource("/p", "absent")] }));
  assert.equal(r.verdict, "CANNOT");
  assert.match(r.detail, /unreadable/);
});

test("cache-version PASS on a self-consistent dir (package.json == marker)", () => {
  const r = verifyCacheVersion(factsOver({ cacheDirs: [cacheDir("latest", "0.7.1", "0.7.1")] }));
  assert.equal(r.verdict, "PASS");
  assert.match(r.detail, /latest->0\.7\.1/);
});

test("cache-version FAIL on marker/package.json version disagreement", () => {
  const r = verifyCacheVersion(factsOver({ cacheDirs: [cacheDir("latest", "0.7.1", "0.5.0")] }));
  assert.equal(r.verdict, "FAIL");
  assert.ok(r.detail.includes("marker says 0.5.0") && r.detail.includes("package.json says 0.7.1"), r.detail);
});

test("cache-version FAIL when a dir cached under an exact pin reports another version", () => {
  const r = verifyCacheVersion(factsOver({
    cacheDirs: [cacheDir("0.7.0", "0.7.0", "0.7.0")],
    configs: [configSource("/g", "ok", ["border-customs@0.7.0"]), configSource("/p", "absent")],
  }));
  // tag matches pin and version matches tag -> consistent; break it:
  const broken = verifyCacheVersion(factsOver({
    cacheDirs: [cacheDir("0.7.0", "0.7.1", "0.7.1")],
    configs: [configSource("/g", "ok", ["border-customs@0.7.0"]), configSource("/p", "absent")],
  }));
  assert.equal(r.verdict, "PASS");
  assert.equal(broken.verdict, "FAIL");
  assert.ok(broken.detail.includes("cached under exact spec '0.7.0'"), broken.detail);
});

test("cache-version FAIL on unreadable package.json and on a marker-less plugin first line", () => {
  const noPkg = verifyCacheVersion(factsOver({ cacheDirs: [cacheDir("latest", null, null, "// border-opencode-plugin v0.7.1")] }));
  assert.equal(noPkg.verdict, "FAIL");
  assert.ok(noPkg.detail.includes("package.json missing or unreadable"), noPkg.detail);
  const noMarker = verifyCacheVersion(factsOver({ cacheDirs: [cacheDir("latest", "0.7.1", null, "// someone else's plugin")] }));
  assert.equal(noMarker.verdict, "FAIL");
  assert.ok(noMarker.detail.includes(PLUGIN_MARKER), noMarker.detail);
});

// ---------------------------------------------------------------- aspect 2: spec-freshness

test("spec-freshness PASS when nothing is declared (no registry call)", async () => {
  const r = await verifySpecFreshness(factsOver({}), { fetcher: registryForbidsCalls.fetcher });
  assert.equal(r.verdict, "PASS");
});

test("spec-freshness CANNOT when the config is unreadable", async () => {
  const r = await verifySpecFreshness(factsOver({ configs: [configSource("/g", "error"), configSource("/p", "absent")] }), { fetcher: registryForbidsCalls.fetcher });
  assert.equal(r.verdict, "CANNOT");
});

test("spec-freshness exact pin is judged OFFLINE: FAIL on stale cache, no registry call", async () => {
  const facts = factsOver({
    configs: [configSource("/g", "ok", ["border-customs@0.8.0"]), configSource("/p", "absent")],
    cacheDirs: [cacheDir("0.8.0", "0.7.1", "0.7.1")],
  });
  const r = await verifySpecFreshness(facts, { fetcher: registryForbidsCalls.fetcher });
  assert.equal(r.verdict, "FAIL");
  assert.ok(r.detail.includes("cache holds 0.8.0->0.7.1"), r.detail);
  assert.ok(r.detail.includes("spec expects 0.8.0"), r.detail);
  assert.equal(registryForbidsCalls.calls.length, 0);
});

test("spec-freshness exact pin PASS when the cache matches (offline)", async () => {
  const facts = factsOver({
    configs: [configSource("/g", "ok", ["border-customs@0.7.1"]), configSource("/p", "absent")],
    cacheDirs: [cacheDir("0.7.1", "0.7.1", "0.7.1")],
  });
  const r = await verifySpecFreshness(facts, { fetcher: registryForbidsCalls.fetcher });
  assert.equal(r.verdict, "PASS");
});

test("SABOTAGE (acceptance #2a): dist-tag with the registry lying about a newer version -> spec-freshness FAIL", async () => {
  const registry = fakeRegistry(() => ({ status: 200, json: { version: "0.9.0" } }));
  const facts = factsOver({
    configs: [configSource("/g", "ok", ["border-customs@latest"]), configSource("/p", "absent")],
    cacheDirs: [cacheDir("latest", "0.7.1", "0.7.1")],
  });
  const r = await verifySpecFreshness(facts, { fetcher: registry.fetcher });
  assert.equal(r.verdict, "FAIL");
  assert.ok(r.detail.includes("spec expects 0.9.0"), r.detail);
  assert.deepEqual(registry.calls, ["https://registry.npmjs.org/border-customs/latest"]);
});

test("spec-freshness dist-tag PASS when the cache holds the registry answer", async () => {
  const registry = fakeRegistry(() => ({ status: 200, json: { version: "0.7.1" } }));
  const facts = factsOver({
    configs: [configSource("/g", "ok", ["border-customs@latest"]), configSource("/p", "absent")],
    cacheDirs: [cacheDir("latest", "0.7.1", "0.7.1")],
  });
  const r = await verifySpecFreshness(facts, { fetcher: registry.fetcher });
  assert.equal(r.verdict, "PASS");
});

test("spec-freshness CANNOT on unreachable registry — border never reads silence as fresh", async () => {
  const throwing = fakeRegistry(() => ({ error: "socket hang up" }));
  const facts = factsOver({ configs: [configSource("/g", "ok", ["border-customs@latest"]), configSource("/p", "absent")] });
  const r = await verifySpecFreshness(facts, { fetcher: throwing.fetcher });
  assert.equal(r.verdict, "CANNOT");
  assert.match(r.detail, /never reads silence as fresh/);
});

test("spec-freshness CANNOT on a 404 registry answer (fail-closed, never absent-means-fresh)", async () => {
  const notFound = fakeRegistry(() => ({ status: 404 }));
  const facts = factsOver({ configs: [configSource("/g", "ok", ["border-customs@nosuchtag"]), configSource("/p", "absent")] });
  const r = await verifySpecFreshness(facts, { fetcher: notFound.fetcher });
  assert.equal(r.verdict, "CANNOT");
});

test("spec-freshness resolves the dist-tag even with an empty cache (registry error outranks NOT-CACHED, rc-2 parity)", async () => {
  const throwing = fakeRegistry(() => ({ error: "ETIMEDOUT" }));
  const facts = factsOver({ configs: [configSource("/g", "ok", ["border-customs@latest"]), configSource("/p", "absent")], cacheDirs: [] });
  const r = await verifySpecFreshness(facts, { fetcher: throwing.fetcher });
  assert.equal(r.verdict, "CANNOT");
  assert.equal(throwing.calls.length, 1);
});

test("spec-freshness PASSes the empty cache to cache-version when the registry answers", async () => {
  const registry = fakeRegistry(() => ({ status: 200, json: { version: "0.8.0" } }));
  const facts = factsOver({ configs: [configSource("/g", "ok", ["border-customs@latest"]), configSource("/p", "absent")], cacheDirs: [] });
  const r = await verifySpecFreshness(facts, { fetcher: registry.fetcher });
  assert.equal(r.verdict, "PASS");
  assert.match(r.detail, /nothing cached to compare/);
});

// ---------------------------------------------------------------- aspect 3: identity-handshake

test("SABOTAGE (acceptance #2b): BORDER_BIN impostor -> identity FAIL, override wins ALONE (never falls back)", async () => {
  const runner = scriptedRunner(() => ({ status: 0, stdout: "opencode — AI agent\nusage: opencode <command>\n", stderr: "" }));
  const r = await verifyIdentity({ runner: runner.runner, distEntry: "/whatever", env: { BORDER_BIN: "/impostor" } });
  assert.equal(r.verdict, "FAIL");
  assert.equal(runner.seen.length, 1, "BORDER_BIN wins alone — no further candidates may be probed");
  assert.deepEqual(runner.seen[0]?.argv, HANDSHAKE_ARGV);
  assert.match(r.detail, /impostor\?/);
});

test("identity PASS names the winning candidate", async () => {
  const runner = scriptedRunner(() => SPAWNED_OK);
  const r = await verifyIdentity({ runner: runner.runner, distEntry: "/d", env: {} });
  assert.equal(r.verdict, "PASS");
  assert.ok(r.detail.includes("border on PATH"), `PASS must name the winning candidate: ${r.detail}`);
});

test("identity CANNOT when no candidate is reachable (all unspawnable)", async () => {
  const runner = scriptedRunner(() => ({ status: null, stdout: "", stderr: "" }));
  const r = await verifyIdentity({ runner: runner.runner, distEntry: "/none", env: {} });
  assert.equal(r.verdict, "CANNOT");
  assert.match(r.detail, /no border binary reachable/);
});

test("identity handshake decision: exit!=0 fails, real border usage() passes, impostor banner fails", () => {
  assert.equal(passesHandshake({ status: 1, stdout: "border — gate\nusage: border x", stderr: "" }), false);
  assert.equal(passesHandshake({ status: 0, stdout: usage(), stderr: "" }), true);
  assert.equal(passesHandshake({ status: 0, stdout: "opencode\nusage: opencode", stderr: "" }), false);
});

test("identityCandidates mirrors the plugin candidate order (BORDER_BIN alone; dist pair; PATH border)", () => {
  const override = identityCandidates({ BORDER_BIN: "/x" }, "/whatever");
  assert.deepEqual(override.map((c) => c.label), ["BORDER_BIN=/x"]);
  const noDist = identityCandidates({}, "/definitely/not/here/dist.js");
  assert.deepEqual(noDist.map((c) => c.label), ["border on PATH"]);
});

// ---------------------------------------------------------------- aspects 4+5: route A / dual route

test("route-a-parity PASS-not-installed when the drop file is absent", () => {
  const r = verifyRouteAParity(factsOver({}));
  assert.equal(r.verdict, "PASS");
  assert.match(r.detail, /absent/);
});

test("route-a-parity PASS with the status-line sha shape when the drop matches the packaged bytes", () => {
  const r = verifyRouteAParity(factsOver({ routeAInstalled: true, packagedPlugin: PACKAGED_PLUGIN, routeABytes: PACKAGED_PLUGIN }));
  assert.equal(r.verdict, "PASS");
  const m = r.detail.match(/installed=([0-9a-f]{64}) packaged=([0-9a-f]{64})/);
  assert.ok(m !== null && m[1] === m[2], r.detail);
});

test("route-a-parity FAIL on a stale marker-bearing drop (outdated) and on a foreign drop", () => {
  const outdated = verifyRouteAParity(factsOver({ routeAInstalled: true, packagedPlugin: PACKAGED_PLUGIN, routeABytes: Buffer.concat([PACKAGED_PLUGIN, Buffer.from("x")]) }));
  assert.equal(outdated.verdict, "FAIL");
  assert.ok(outdated.detail.includes("outdated (marker ours, bytes differ)"), outdated.detail);
  const foreign = verifyRouteAParity(factsOver({ routeAInstalled: true, packagedPlugin: PACKAGED_PLUGIN, routeABytes: Buffer.from("// someone else's plugin, not the real bytes\n") }));
  assert.equal(foreign.verdict, "FAIL");
  assert.ok(foreign.detail.includes("foreign"), foreign.detail);
});

test("route-a-parity CANNOT on a present-but-unreadable drop and on an unreadable packaged asset", () => {
  const unreadableDrop = verifyRouteAParity(factsOver({ routeAInstalled: true, packagedPlugin: PACKAGED_PLUGIN, routeABytes: null }));
  assert.equal(unreadableDrop.verdict, "CANNOT");
  const brokenInstall = verifyRouteAParity(factsOver({ routeAInstalled: true, packagedPlugin: null, routeABytes: PACKAGED_PLUGIN }));
  assert.equal(brokenInstall.verdict, "CANNOT");
});

test("dual-route FAIL is the A∧B window; single routes and zero routes PASS", () => {
  const declared = [configSource("/g", "ok", ["border-customs@latest"]), configSource("/p", "absent")];
  const both = verifyDualRoute(factsOver({ routeAInstalled: true, configs: declared }));
  assert.equal(both.verdict, "FAIL");
  assert.match(both.detail, /blueprint §7/);
  assert.equal(verifyDualRoute(factsOver({ routeAInstalled: true })).verdict, "PASS");
  assert.equal(verifyDualRoute(factsOver({ configs: declared })).verdict, "PASS");
  assert.equal(verifyDualRoute(factsOver({})).verdict, "PASS");
});

test("dual-route CANNOT when the configuration is unreadable", () => {
  const r = verifyDualRoute(factsOver({ configs: [configSource("/g", "error"), configSource("/p", "absent")] }));
  assert.equal(r.verdict, "CANNOT");
});

// ---------------------------------------------------------------- aspect 6: scope certificate

test("scope never fails: PASS with the three declared V2 blind spots verbatim", () => {
  const r = verifyScope();
  assert.equal(r.verdict, "PASS");
  for (const blind of SCOPE_UNCOVERED) {
    assert.ok(r.detail.includes(blind), `blind spot '${blind}' must be declared verbatim`);
  }
});

// ---------------------------------------------------------------- aggregation priority matrix

function a(id: AspectResult["id"], verdict: AspectResult["verdict"]): AspectResult {
  return { id, verdict, detail: "" };
}

test("aggregate priority: FAIL outranks CANNOT outranks PASS; exit mapping 1/2/0", () => {
  assert.equal(aggregateVerdict([a("scope", "PASS"), a("dual-route", "PASS")]), "PASS");
  assert.equal(aggregateVerdict([a("scope", "PASS"), a("identity-handshake", "CANNOT")]), "CANNOT");
  assert.equal(aggregateVerdict([a("identity-handshake", "CANNOT"), a("spec-freshness", "FAIL")]), "FAIL");
  assert.equal(aggregateVerdict([a("cache-version", "FAIL"), a("spec-freshness", "FAIL"), a("identity-handshake", "CANNOT"), a("scope", "PASS")]), "FAIL");
  assert.equal(inspectExit("PASS"), EXIT_PASS);
  assert.equal(inspectExit("CANNOT"), EXIT_ERROR);
  assert.equal(inspectExit("FAIL"), EXIT_BLOCKED);
});

// ---------------------------------------------------------------- end-to-end core, injected seams

test("core end-to-end all-PASS offline: exit 0, --json surface complete", async () => {
  const world = makeWorld("inspect-core-pass");
  const { deps } = OFFLINE();
  const c = core(world.env, world.cwd, deps, true);
  try {
    const code = await c.run();
    assert.equal(code, EXIT_PASS, c.out.join("\n"));
    const report = JSON.parse(c.out[0] ?? "{}") as { schemaVersion: number; scope: string; verdict: string; aspects: { id: string; verdict: string }[] };
    assert.equal(report.schemaVersion, 1);
    assert.equal(report.scope, "v1", "the certificate bound (plan B3) must be the consumer-facing field");
    assert.equal(report.verdict, "PASS");
    assert.deepEqual(report.aspects.map((x) => x.id), [...ASPECT_IDS]);
    assert.equal(report.aspects.length, 6);
  } finally {
    removeWorld(world);
  }
});

test("core human output renders the [v1] scope line and one line per aspect", async () => {
  const world = makeWorld("inspect-core-human");
  const { deps } = OFFLINE();
  const c = core(world.env, world.cwd, deps, false);
  try {
    const code = await c.run();
    assert.equal(code, EXIT_PASS);
    assert.equal(c.out[0], "border opencode inspect [v1] PASS");
    assert.equal(c.out.length, 7);
    for (const id of ASPECT_IDS) {
      assert.ok(c.out.some((l) => l.includes(id)), `aspect ${id} missing from human render`);
    }
  } finally {
    removeWorld(world);
  }
});

test("core: declared pin without cache -> NOT-CACHED CANNOT -> exit 2 (never a fake FAIL, never a clean 0)", async () => {
  const world = makeWorld("inspect-core-notcached");
  writeConfig(world.globalConfig, ["border-customs@0.7.1"]);
  const { deps } = OFFLINE();
  const c = core(world.env, world.cwd, deps, true);
  try {
    const code = await c.run();
    assert.equal(code, EXIT_ERROR);
    const report = JSON.parse(c.out[0] ?? "{}") as { verdict: string; aspects: { id: string; verdict: string; detail: string }[] };
    const cache = report.aspects.find((x) => x.id === "cache-version");
    assert.equal(cache?.verdict, "CANNOT");
    assert.ok(cache !== undefined && cache.detail.startsWith("NOT-CACHED:"), cache?.detail);
  } finally {
    removeWorld(world);
  }
});

test("SABOTAGE (acceptance #2c, filesystem world): config declaration + Route A drop = dual-route FAIL -> exit 1", async () => {
  const world = makeWorld("inspect-core-dual");
  writeConfig(world.globalConfig, ["border-customs@0.7.1"]);
  plantRouteADrop(world, PACKAGED_PLUGIN);
  const { deps } = OFFLINE();
  const c = core(world.env, world.cwd, deps, true);
  try {
    const code = await c.run();
    assert.equal(code, EXIT_BLOCKED);
    const report = JSON.parse(c.out[0] ?? "{}") as { aspects: { id: string; verdict: string }[] };
    assert.equal(report.aspects.find((x) => x.id === "dual-route")?.verdict, "FAIL");
  } finally {
    removeWorld(world);
  }
});

test("core reads the world through XDG seams: planted cache + jsonc config with URL/comment/trailing-comma", async () => {
  const world = makeWorld("inspect-core-world");
  writeConfig(world.globalConfig, ["opencode-wiki-historian@0.5.1", "border-customs@latest"]);
  plantCacheDir(world, "latest", { version: "0.7.1", marker: "0.7.1" });
  mkdirSync(join(world.cacheRoot, "opencode-wiki-historian@0.5.1", "node_modules"), { recursive: true });
  const registry = fakeRegistry((url) => (url.endsWith("/latest") && url.includes("border-customs") ? { status: 200, json: { version: "0.7.1" } } : { status: 200, json: { version: "9.9.9" } }));
  const runner = scriptedRunner(() => SPAWNED_OK);
  const c = core(world.env, world.cwd, { registryFetcher: registry.fetcher, runner: runner.runner, distEntry: "/d" }, true);
  try {
    const code = await c.run();
    assert.equal(code, EXIT_PASS, c.out.join("\n"));
    const report = JSON.parse(c.out[0] ?? "{}") as { aspects: { id: string; verdict: string; detail: string }[] };
    assert.ok(report.aspects.find((x) => x.id === "cache-version")?.detail.includes("latest->0.7.1"));
    assert.ok(!report.aspects.some((x) => x.detail.includes("wiki-historian")), "other packages' cache/config entries must not leak into the border audit");
  } finally {
    removeWorld(world);
  }
});

test("gatherFacts: jsonc reader survives https:// double-slash and trailing commas; specs filtered to the package", async () => {
  const world = makeWorld("inspect-gather");
  writeConfig(world.globalConfig, ["border-customs@0.7.1"]);
  plantCacheDir(world, "0.7.1", { version: "0.7.1", marker: "0.7.1" });
  const facts = gatherFacts(world.env, world.cwd, { globalConfigPath: world.globalConfig, cacheRoot: world.cacheRoot });
  try {
    assert.equal(facts.configs[0]?.status, "ok");
    assert.deepEqual(facts.configs[0]?.specs, ["border-customs@0.7.1"]);
    assert.equal(facts.configs[1]?.status, "absent", "no project opencode.jsonc in the world");
    assert.equal(facts.cacheDirs.length, 1);
    assert.equal(facts.cacheDirs[0]?.packageVersion, "0.7.1");
    assert.equal(facts.cacheDirs[0]?.markerVersion, "0.7.1");
    assert.equal(facts.routeAInstalled, false);
    assert.ok(facts.packagedPlugin !== null && PACKAGED_PLUGIN.equals(facts.packagedPlugin as Buffer));
  } finally {
    removeWorld(world);
  }
});

test("listCacheDirs enumerates only <pkg>@* dirs, sorted, tolerating an unreadable payload", () => {
  const world = makeWorld("inspect-list");
  plantCacheDir(world, "latest", { version: "0.7.1", marker: "0.7.1" });
  plantCacheDir(world, "alpha", { version: null, marker: null, noPackageJson: true });
  mkdirSync(join(world.cacheRoot, "some-other-pkg@1.0.0"), { recursive: true });
  try {
    const dirs = listCacheDirs(world.cacheRoot, "border-customs");
    assert.deepEqual(dirs.map((d) => d.tag), ["alpha", "latest"]);
    assert.equal(dirs[0]?.packageVersion, null);
    const alpha = dirs.find((d) => d.tag === "alpha");
    assert.ok(alpha !== undefined && alpha.packageVersion === null);
  } finally {
    removeWorld(world);
  }
});

// splitNpmSpec unit
test("splitNpmSpec: scoped names split at the LAST @; bare names carry no spec", () => {
  assert.deepEqual(splitNpmSpec("@scope/pkg@1.2.3"), { name: "@scope/pkg", spec: "1.2.3" });
  assert.deepEqual(splitNpmSpec("border-customs@latest"), { name: "border-customs", spec: "latest" });
  assert.deepEqual(splitNpmSpec("border-customs"), { name: "border-customs", spec: null });
});

// ---------------------------------------------------------------- T2 mirror pin (plan: 镜像钉死)

test("T2 mirror: the inspect handshake decision is the plugin's decision — banner, needle, argv, cap, labels", () => {
  const pluginSource = readFileSync(join(BORDER_ROOT, "plugin", "border.ts"), "utf8");
  const helpBody = pluginSource.slice(pluginSource.indexOf("function isBorderHelp"), pluginSource.indexOf("type Resolution"));
  const banner = /startsWith\("([^"]+)"\)/.exec(helpBody)?.[1];
  const needle = /includes\("([^"]+)"\)/.exec(helpBody)?.[1];
  assert.equal(banner, HANDSHAKE_BANNER_PREFIX, "plugin banner prefix drifted from the inspect constant");
  assert.equal(needle, HANDSHAKE_USAGE_NEEDLE, "plugin usage needle drifted from the inspect constant");
  assert.match(helpBody, /result\.status !== 0/, "both sides must reject a non-zero --help exit");

  const probeCap = /const PROBE_TIMEOUT_MS = (\d[\d_]*)/.exec(pluginSource)?.[1]?.replace(/_/g, "");
  assert.equal(Number(probeCap), HANDSHAKE_TIMEOUT_MS, "the 20 s probe cap must stay identical on both sides");
  assert.ok(pluginSource.includes('runCli(candidate, ["--help"]'), "the plugin probes with exactly --help — the inspect HANDSHAKE_ARGV twin");
  assert.deepEqual(HANDSHAKE_ARGV, ["--help"]);

  // candidate order + labels mirrored verbatim:
  const listBody = pluginSource.slice(pluginSource.indexOf("function candidateList"), pluginSource.indexOf("interface CliResult"));
  assert.ok(listBody.includes("BORDER_BIN") && listBody.includes("../dist/index.js") && listBody.includes('bin: "node"') && listBody.includes('bin: "border"'), "plugin candidate order: BORDER_BIN -> dist -> node dist -> PATH border");
  assert.equal(identityCandidates({}, "does-not-exist")[0]?.label, "border on PATH");
});

test("T2 mirror: identityCandidates builds the same three-way dist pair with the plugin's labels", () => {
  const cands = identityCandidates({}, join(BORDER_ROOT, "package.json")); // any existing file stands in for dist
  assert.deepEqual(cands.map((c) => c.label), [
    "packaged dist/index.js (shebang exec)",
    "packaged dist/index.js under PATH node",
    "border on PATH",
  ]);
  assert.deepEqual(cands[1]?.prefix, [join(BORDER_ROOT, "package.json")], "the PATH-node candidate carries the dist path as script prefix");
});

// ---------------------------------------------------------------- import-audit guard (scan doctrine)

test("inspect path never imports the ledger or the check pipeline (zero-side-effect constraint)", () => {
  const hits = spawnSync("grep", ["-rEn", 'from "[^"]*(ledger/|/check\\.ts)', "src/opencode", "src/commands/opencode.ts"], {
    cwd: BORDER_ROOT,
    encoding: "utf8",
  });
  assert.equal(hits.stdout.trim(), "", `inspect path must stay ledger-/check-free, got: ${hits.stdout}`);
});

// ---------------------------------------------------------------- opt-in network E2E

test("E2E against the public npm registry (opt-in: BORDER_INSPECT_NETWORK_E2E=1)", async (t) => {
  if (process.env.BORDER_INSPECT_NETWORK_E2E !== "1") {
    t.skip("network E2E is opt-in — offline suite stays green");
    return;
  }
  const world = makeWorld("inspect-live");
  writeConfig(world.globalConfig, ["border-customs@latest"]);
  plantCacheDir(world, "latest", { version: "0.0.1", marker: "0.0.1" });
  const runner = scriptedRunner(() => SPAWNED_OK);
  const c = core(world.env, world.cwd, { runner: runner.runner, distEntry: "/d" }, true);
  try {
    const code = await c.run();
    assert.equal(code, EXIT_BLOCKED, "the live registry's @latest cannot be 0.0.1 — the planted cache must come back DRIFT");
    const report = JSON.parse(c.out[0] ?? "{}") as { aspects: { id: string; verdict: string; detail: string }[] };
    const fresh = report.aspects.find((x) => x.id === "spec-freshness");
    assert.equal(fresh?.verdict, "FAIL");
    assert.match(fresh?.detail ?? /x/, /spec expects 0\.[1-9]/, `live @latest resolved version missing in: ${fresh?.detail}`);
  } finally {
    removeWorld(world);
  }
});
