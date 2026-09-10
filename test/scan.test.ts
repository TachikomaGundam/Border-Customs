// provenance: border-inspect-roadmap.md W1.2/W1.3 — `border scan` end-to-end.
//
// Offline by default: every AC drives runScanCore through the injected
// ScanFetcher seam with RUNTIME-GENERATED npm-pack-shaped tarballs, so the
// suite exercises the REAL npm channel stage() (npm pack → lifecycle/residue
// → gitleaks/secretlint → publint) without touching the public network.
// Public-registry legs are opt-in via BORDER_SCAN_NETWORK_E2E=1
// (verdaccio-leg doctrine). The no-ledger/no-check-pipeline ban is pinned by
// a grep guard, mirroring the zero-dep guard in cli.test.ts.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";

import { UnknownArgError, EXIT_BLOCKED, EXIT_ERROR, EXIT_PASS } from "../src/cli/exit.ts";
import { handlers, setHandler } from "../src/commands/index.ts";
import { ConfigError, parseConfig } from "../src/config.ts";
import { run, usage } from "../src/cli.ts";
import { NPM_LIFECYCLE_RULE } from "../src/artifacts/npm.ts";
import { SUBCOMMANDS, type Ctx, type Flags } from "../src/cli/types.ts";
import type { Report } from "../src/findings.ts";
import { buildScanConfigYaml, synthesizeScanConfig } from "../src/scan/config.ts";
import { type ScanFetcher, type ScanResponse } from "../src/scan/fetch.ts";
import { runScanCore } from "../src/scan/scan.ts";
import { BORDER_ROOT, makeFixtureDir, removeDir } from "./helpers/fixtures.ts";
import { requireGitleaks } from "./helpers/require-engines.ts";

requireGitleaks();

const roots: string[] = [];
after(() => {
  for (const d of roots) removeDir(d);
});

function makeCtx(positionals: readonly string[], flags: Partial<Flags> = {}): Ctx & { out: string[]; err: string[] } {
  const out: string[] = [];
  const err: string[] = [];
  const base: Flags = { force: false, yes: false, llm: false, json: false, ...flags };
  return {
    out,
    err,
    command: "scan",
    flags: base,
    positionals,
    cwd: tmpdir(),
    env: { ...process.env },
    stdout: (line) => out.push(line),
    stderr: (line) => err.push(line),
    handlers,
  };
}

/** Scripted npm registry: GET /<name>/<ver> metadata, GET the tarball bytes. */
function npmStubBytes(name: string, version: string, tgzPath: string): { fetcher: ScanFetcher; requested: string[] } {
  const bytes = readFileSync(tgzPath);
  const tarballUrl = `https://registry.npmjs.org/${name}/-/${name}-${version}.tgz`;
  const requested: string[] = [];
  const fetcher: ScanFetcher = async (url): Promise<ScanResponse> => {
    requested.push(url);
    const body =
      url === `https://registry.npmjs.org/${name}/${version}`
        ? new TextEncoder().encode(JSON.stringify({ name, version, dist: { tarball: tarballUrl } }))
        : url === tarballUrl
          ? new Uint8Array(bytes)
          : (() => {
              throw new Error(`npmStubBytes got unscripted URL: ${url}`);
            })();
    return { status: 200, contentLength: body.byteLength, async *chunks() { yield body; } };
  };
  return { fetcher, requested };
}

function stagePackage(dir: string, manifest: unknown, extra: Record<string, string>): void {
  mkdirSync(join(dir, "package", "bin"), { recursive: true });
  writeFileSync(join(dir, "package", "package.json"), JSON.stringify(manifest, null, 2) + "\n");
  for (const [rel, body] of Object.entries(extra)) writeFileSync(join(dir, "package", rel), body);
}

/** `tar -czf` of a staging dir in npm pack layout (package/ wrapper included). */
function packLike(tgzPath: string, srcDir: string): void {
  const r = spawnSync("tar", ["-czf", tgzPath, "-C", srcDir, "package"], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
}

// ---------------------------------------------------------------- W1.2: config synthesis

test("scan config synthesis goes through the REAL zod schema path with exactly one enabled target", () => {
  for (const eco of ["npm", "pypi", "crates", "rubygems"] as const) {
    const cfg = synthesizeScanConfig(eco);
    assert.equal(cfg.version, 1);
    assert.deepEqual(cfg.targets.git, { remotes: [] });
    assert.notEqual(cfg.targets[eco], undefined, `targets.${eco} must be configured`);
    for (const other of ["npm", "pypi", "crates", "rubygems"] as const) {
      if (other !== eco) assert.equal(cfg.targets[other], undefined, `only ${eco} enabled`);
    }
    assert.equal(cfg.residue?.enabled, true, "residue defaults ON for scan");
    assert.deepEqual(cfg.engines.require, ["gitleaks", "secretlint"]);
    assert.equal(cfg.rules.maxFileKB, 500);
  }
});

test("synthesized YAML is what parseConfig validates — unknown shapes are caught by zod", () => {
  const yaml = buildScanConfigYaml("npm");
  assert.ok(parseConfig(yaml).targets.npm !== undefined, "round-trips through the real path");
  assert.throws(() => parseConfig(`${yaml}checks:\n  bogus: true\n`), (err: unknown) => {
    assert.ok(err instanceof ConfigError);
    assert.equal((err as ConfigError).kind, "unknown-key");
    return true;
  });
});

// ---------------------------------------------------------------- W1.2: stage-wired integration

test("scan of a planted-residue npm package exits 1 with lifecycle-script + residue-persistence-primitive, artifact-attributed paths", async () => {
  const stage = makeFixtureDir("scan-evil");
  roots.push(stage);
  const src = join(stage, "src");
  // Benign-shaped marker: an echo'd docs string; the classifier keys on the
  // literal `crontab` — nothing executes, and npm pack runs --ignore-scripts.
  stagePackage(src, { name: "eviltwin", version: "1.0.0", bin: { evil: "bin/evil.sh" }, scripts: { postinstall: "echo install-step" } }, {
    "bin/evil.sh": '#!/bin/sh\necho "upstream docs mention crontab for scheduling"\n',
  });
  const tgz = join(stage, "eviltwin-1.0.0.tgz");
  packLike(tgz, src);

  const { fetcher, requested } = npmStubBytes("eviltwin", "1.0.0", tgz);
  const ctx = makeCtx(["eviltwin@1.0.0"]);
  const code = await runScanCore(ctx, { fetcher });

  assert.equal(code, EXIT_BLOCKED, "planted residue ⇒ exit 1");
  assert.equal(requested[0], "https://registry.npmjs.org/eviltwin/1.0.0");
  const text = ctx.out.join("\n");
  assert.match(text, /border scan npm:eviltwin@1\.0\.0 FAIL/);
  assert.match(text, new RegExp(NPM_LIFECYCLE_RULE));
  assert.match(text, /residue-persistence-primitive/);
  assert.ok(ctx.out.some((l) => l.includes("eviltwin-1.0.0.tgz!bin/evil.sh")), "findings carry the artifact-attributed path");
});

test("scan --json prints exactly the Report contract (schemaVersion 1, counts, verdict FAIL)", async () => {
  const stage = makeFixtureDir("scan-json");
  roots.push(stage);
  const src = join(stage, "src");
  stagePackage(src, { name: "jsontwin", version: "1.0.0", bin: { evil: "bin/evil.sh" }, scripts: { preinstall: "echo pre" } }, {
    "bin/evil.sh": 'echo "crontab docs reference"\n',
  });
  const tgz = join(stage, "jsontwin-1.0.0.tgz");
  packLike(tgz, src);
  const { fetcher } = npmStubBytes("jsontwin", "1.0.0", tgz);
  const ctx = makeCtx(["jsontwin@1.0.0"], { json: true });
  const code = await runScanCore(ctx, { fetcher });
  assert.equal(code, EXIT_BLOCKED);
  const report = JSON.parse(ctx.out.join("\n")) as Report;
  assert.equal(report.schemaVersion, 1);
  assert.equal(report.verdict, "FAIL");
  assert.equal(report.counts.total, report.findings.length);
  assert.ok(report.counts.blocking >= 2, "lifecycle CRITICAL + residue CRITICAL");
  assert.equal(report.dirty, false);
  assert.equal(report.key.length, 64);
  assert.equal(report.rulesHash.length, 64);
  assert.match(report.ts, /^\d{4}-\d{2}-\d{2}T/);
  assert.ok(report.findings.some((f) => f.rule === "residue-persistence-primitive" && f.severity === "CRITICAL"));
});

test("benign package ⇒ verdict PASS, exit 0, never a fabricated finding", async () => {
  const stage = makeFixtureDir("scan-benign");
  roots.push(stage);
  const src = join(stage, "src");
  stagePackage(src, { name: "benignpkg", version: "1.0.0" }, { "README.md": "a calm readme\n" });
  const tgz = join(stage, "benignpkg-1.0.0.tgz");
  packLike(tgz, src);
  const { fetcher } = npmStubBytes("benignpkg", "1.0.0", tgz);
  const ctx = makeCtx(["benignpkg@1.0.0"]);
  const code = await runScanCore(ctx, { fetcher });
  assert.equal(code, EXIT_PASS);
  assert.match(ctx.out.join("\n"), /border scan npm:benignpkg@1\.0\.0 PASS/);
});

// ---------------------------------------------------------------- fail-closed doctrine

test("fail-closed: bad input and crashing fetch both reject upward to the exit-2 translator, leaving no border-scan temp dirs", async () => {
  const ctx = makeCtx(["totally bad input"]);
  await assert.rejects(
    runScanCore(ctx, {
      fetcher: async () => {
        throw new Error("must not be reached");
      },
    }),
    UnknownArgError,
  );

  const crashing: ScanFetcher = async () => {
    throw new Error("ECONNREFUSED fetch failed");
  };
  const ctx2 = makeCtx(["crasher@1.0.0"]);
  await assert.rejects(runScanCore(ctx2, { fetcher: crashing }), /ECONNREFUSED/);

  const leaked = readdirSync(tmpdir()).filter((d) => d.startsWith("border-scan-"));
  assert.deepEqual(leaked, [], "finally-removeSandbox must clean success AND failure paths");
});

test("corrupt tarball bytes are exit-2 fail-closed, NEVER a zero-findings clean", async () => {
  const { fetcher } = npmStubBytes("rotten", "1.0.0", join(BORDER_ROOT, "package.json")); // a NON-tarball "tarball"
  const ctx = makeCtx(["rotten@1.0.0"]);
  await assert.rejects(runScanCore(ctx, { fetcher }), (err: unknown) => {
    assert.ok(err instanceof Error);
    assert.equal((err as Error).message.includes("\n"), false, "one-line cause survives to the CLI translator");
    return true;
  });
});

// ---------------------------------------------------------------- CLI surface

test("scan is a first-class subcommand: registry, SUBCOMMANDS, usage table", () => {
  assert.ok((SUBCOMMANDS as readonly string[]).includes("scan"));
  assert.equal(typeof handlers.scan, "function");
  const help = usage();
  assert.match(help, /^ {2}scan\s+inspect/m);
  assert.ok(help.includes("subcommands: check, push, status, llm-request, llm-ingest, scan"));
});

test("`border scan` with zero/multiple positionals exits 2 with the actionable usage line", async () => {
  for (const argv of [["scan"], ["scan", "a@1.0.0", "b@2.0.0"]]) {
    const out: string[] = [];
    const err: string[] = [];
    const code = await run(argv, (l) => out.push(l), (l) => err.push(l), { env: { ...process.env } });
    assert.equal(code, EXIT_ERROR, argv.join(" "));
    assert.match(err.join("\n"), /usage: border scan <\[ecosystem:\]name@version>/);
  }
});

test("bad spec text is exit 2 before any network touch", async () => {
  const out: string[] = [];
  const err: string[] = [];
  const code = await run(["scan", "docker:nginx@1.0"], (l) => out.push(l), (l) => err.push(l));
  assert.equal(code, EXIT_ERROR);
  assert.match(err.join("\n"), /unknown ecosystem/);
});

test("run() dispatches scan with its positional to the registry handler (spy)", async () => {
  let seen: Ctx | undefined;
  const restore = setHandler("scan", (ctx) => {
    seen = ctx;
    return EXIT_PASS;
  });
  try {
    const r = await run(["scan", "puppeteer@23.11.1", "--json"], (l) => void l, () => {});
    assert.equal(r, EXIT_PASS);
  } finally {
    restore();
  }
  assert.ok(seen);
  assert.deepEqual(seen.positionals, ["puppeteer@23.11.1"]);
  assert.equal(seen.flags.json, true);
});

// ---------------------------------------------------------------- import audit guard

test("scan path never imports the ledger or the check pipeline (zero-side-effect constraint)", () => {
  const hits = spawnSync("grep", ["-rEn", 'from "[^"]*(ledger/|/check\\.ts)', "src/scan", "src/commands/scan.ts"], {
    cwd: BORDER_ROOT,
    encoding: "utf8",
  });
  assert.equal(hits.stdout.trim(), "", `scan path must stay ledger-/check-free, got: ${hits.stdout}`);
});

// ---------------------------------------------------------------- opt-in network E2E

test("E2E against the public npm registry (opt-in: BORDER_SCAN_NETWORK_E2E=1)", async (t) => {
  if (process.env.BORDER_SCAN_NETWORK_E2E !== "1") {
    t.skip("network E2E is opt-in — offline suite stays green");
    return;
  }
  const ctx = makeCtx(["left-pad@1.3.0"]);
  const code = await runScanCore(ctx);
  assert.ok(code === EXIT_PASS || code === EXIT_BLOCKED, `real registry scan must reach a verdict, got ${String(code)}`);
});

test("E2E crates.io fetch reaches a verdict with the mandatory UA (opt-in: BORDER_SCAN_NETWORK_E2E=1)", async (t) => {
  if (process.env.BORDER_SCAN_NETWORK_E2E !== "1") {
    t.skip("network E2E is opt-in");
    return;
  }
  const ctx = makeCtx(["crates:rand_core@0.6.4"]);
  const code = await runScanCore(ctx);
  assert.ok(code === EXIT_PASS || code === EXIT_BLOCKED, `crates.io scan must reach a verdict, got ${String(code)}`);
  const leaked = readdirSync(tmpdir()).filter((d) => d.startsWith("border-scan-"));
  assert.deepEqual(leaked, []);
});
