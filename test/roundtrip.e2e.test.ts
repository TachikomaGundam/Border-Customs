// provenance: border-inspect-roadmap.md W2.1 — real-docker roundtrip legs.
//
// OPT-IN (BORDER_ROUNDTRIP_DOCKER=1), same doctrine as BORDER_PACK_TEST /
// BORDER_SCAN_NETWORK_E2E: the offline suite skips these so it stays green
// without a daemon. Eight legs = two per ecosystem (npm, pypi, rubygems,
// crates): (1) a REAL published package must reach a verdict on genuine
// registry bytes; (2) a synthetic planted package (rc-append + PATH orphan
// that the manager's uninstall cannot know about) must come back with exactly
// the spike-expected residue rows. Fixture build mechanics per lane: npm =
// postinstall script (needs --foreground-scripts), pypi = setup.py executing
// during the sdist build (spike-proven), rubygems = extensions:["ext/Rakefile"]
// — rubygems' sanctioned install-time code channel, run in-container via the
// bundled rake 13 default gem (ruby:3.4-slim ships NO make/cc, so the
// extconf.rb route aborts on make invocation), crates = build.rs of a
// dependency-free bin crate. An `after` hook force-removes any rt-* container
// so a mid-leg crash cannot leak daemon state onto this machine.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { after, test, type TestContext } from "node:test";

import { EXIT_BLOCKED, EXIT_PASS } from "../src/cli/exit.ts";
import { handlers } from "../src/commands/index.ts";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Ctx, Flags } from "../src/cli/types.ts";
import type { Finding, Report } from "../src/findings.ts";
import { cratesDownloadUrl, pypiMetadataUrl, rubygemsDownloadUrl, type ScanFetcher, type ScanResponse } from "../src/scan/fetch.ts";
import { runRoundtripCore } from "../src/roundtrip/orchestrate.ts";
import { RT_PERSIST_RULE, RT_RESIDUE_RULE } from "../src/roundtrip/manifest.ts";
import { makeFixtureDir, removeDir } from "./helpers/fixtures.ts";

const DOCKER_E2E = process.env.BORDER_ROUNDTRIP_DOCKER === "1";

function ctxOf(positionals: readonly string[], flags: Partial<Flags> = {}): Ctx & { out: string[]; err: string[] } {
  const out: string[] = [];
  const err: string[] = [];
  return {
    out,
    err,
    command: "roundtrip",
    flags: { force: false, yes: false, llm: false, json: false, ...flags },
    positionals,
    cwd: tmpdir(),
    env: { ...process.env },
    stdout: (l) => out.push(l),
    stderr: (l) => err.push(l),
    handlers,
  };
}

after(() => {
  if (!DOCKER_E2E) return;
  const ids = spawnSync("docker", ["ps", "-aq", "--filter", "name=rt-"], { encoding: "utf8", timeout: 60_000 }).stdout.trim();
  if (ids.length > 0) spawnSync("docker", ["rm", "-f", ...ids.split("\n")], { encoding: "utf8", timeout: 60_000 });
});

function runChecked(cmd: string, args: readonly string[], why: string, cwd?: string): string {
  const r = spawnSync(cmd, [...args], { encoding: "utf8", timeout: 180_000, ...(cwd === undefined ? {} : { cwd }) });
  assert.equal(r.status, 0, `${why}: ${r.error?.message ?? r.stderr ?? ""}`);
  return r.stdout ?? "";
}

function assertNoLeakedContainers(): void {
  const leaked = spawnSync("docker", ["ps", "-aq", "--filter", "name=rt-"], { encoding: "utf8", timeout: 60_000 }).stdout.trim();
  assert.equal(leaked, "", "no rt-* container may survive the run");
}

const jsonBytes = (o: unknown): Uint8Array => new TextEncoder().encode(JSON.stringify(o));

function scriptedFetcher(routes: ReadonlyMap<string, Uint8Array>): ScanFetcher {
  return async (url): Promise<ScanResponse> => {
    const body = routes.get(url);
    if (body === undefined) throw new Error(`unscripted URL ${url}`);
    return { status: 200, contentLength: body.byteLength, async *chunks() { yield body; } };
  };
}

// This box's registries are flaky (run1: host fetch of static.crates.io died on
// leg 7; run2: host fetch of pypi.org died on leg 3 AND pip's in-container
// build-dependency bootstrap died — both pure network transients, both pass on
// retry). Retry the WHOLE attempt (fresh ctx, fresh container) ONLY on a
// recognised transient signature; any other error rethrows immediately so a
// real product failure can never be masked by luck.
const TRANSIENT_NETWORK = /fetch failed|install build dependencies|Temporary failure in name resolution|EAI_AGAIN|ETIMEDOUT|Connection reset|socket hang up/i;

async function withTransientRetry<T>(t: TestContext, label: string, fn: () => Promise<T>): Promise<T> {
  for (let attempt = 1; ; attempt += 1) {
    try {
      return await fn();
    } catch (e) {
      const msg = String((e as Error)?.message ?? e);
      if (attempt >= 3 || !TRANSIENT_NETWORK.test(msg)) throw e;
      t.diagnostic(`${label}: transient registry/network flake (attempt ${String(attempt)}/3) — retrying: ${msg.slice(0, 160)}`);
      await new Promise((r) => setTimeout(r, 10_000));
    }
  }
}

async function assertCleanLane(t: TestContext, spec: string, label: string, honestResidue: readonly string[] = []): Promise<void> {
  const { code, report } = await withTransientRetry(t, label, async () => {
    const ctx = ctxOf([spec], { json: true });
    const c = await runRoundtripCore(ctx);
    assert.ok(c === EXIT_PASS || c === EXIT_BLOCKED, `${label} must reach a verdict, got ${String(c)}: ${ctx.err.join("\n")}`);
    return { code: c, report: JSON.parse(ctx.out.join("\n")) as Report };
  });
  assert.ok(report.findings.every((f: Finding) => f.engine === "roundtrip"));
  assert.deepEqual(report.exposureSet, [label]);
  if (honestResidue.length === 0) {
    // Honest baseline for a tidy manager-managed package: clean uninstall ⇒ zero rows.
    // If a real package ever legitimately leaves residue here this assert must be
    // re-encodied with the captured rows as product evidence, never papered over.
    assert.equal(report.findings.length, 0, `${label} must roundtrip clean, got: ${JSON.stringify(report.findings)}`);
    t.diagnostic(`lane ${label}: verdict rc=${String(code)}, residue rows=0`);
  } else {
    // GOLD finding: this lane's manager legitimately leaves residue. Pinned
    // verbatim (no more, no less) and must BLOCK — never papered over, and any
    // change in the set is a product-behavior change that must be re-measured.
    assert.equal(code, EXIT_BLOCKED, `${label}: honest residue must block`);
    for (const f of report.findings) {
      assert.equal(f.rule, RT_RESIDUE_RULE, `${f.path} unexpected rule`);
      assert.equal(f.severity, "HIGH", `${f.path} unexpected severity`);
    }
    assert.deepEqual(report.findings.map((f) => f.path).sort(), [...honestResidue].sort(), `${label} honest-residue set changed`);
    t.diagnostic(`lane ${label}: verdict rc=${String(code)}, HONEST RESIDUE rows: ${JSON.stringify(honestResidue)}`);
  }
  assertNoLeakedContainers();
}

function assertPlantedRows(t: TestContext, findings: readonly Finding[], orphanPath: string): void {
  const byPath = new Map(findings.map((f) => [f.path ?? f.target, f]));
  const profile = byPath.get("/etc/profile");
  const orphan = byPath.get(orphanPath);
  assert.ok(profile, `expected MODIFIED /etc/profile row, got: ${JSON.stringify(findings)}`);
  assert.equal(profile.rule, RT_PERSIST_RULE);
  assert.equal(profile.severity, "CRITICAL");
  assert.ok(orphan, `expected ADDED ${orphanPath} row, got: ${JSON.stringify(findings)}`);
  assert.equal(orphan.rule, RT_RESIDUE_RULE);
  assert.equal(orphan.severity, "HIGH");
  assert.equal(findings.length, 2, `exactly the two planted surfaces, got: ${JSON.stringify(findings)}`);
  t.diagnostic(`planted residue rows: ${JSON.stringify(findings)}`);
}

test("E2E docker: real published left-pad@1.3.0 roundtrip reaches a verdict (opt-in: BORDER_ROUNDTRIP_DOCKER=1)", async (t) => {
  if (!DOCKER_E2E) {
    t.skip("docker legs are opt-in — offline suite stays green");
    return;
  }
  const ctx = ctxOf(["left-pad@1.3.0"], { json: true });
  const code = await runRoundtripCore(ctx);
  assert.ok(code === EXIT_PASS || code === EXIT_BLOCKED, `real roundtrip must reach a verdict, got ${String(code)}: ${ctx.err.join("\n")}`);
  const report = JSON.parse(ctx.out.join("\n")) as Report;
  assert.ok(report.findings.every((f: Finding) => f.engine === "roundtrip"));
  assert.deepEqual(report.exposureSet, ["npm:left-pad@1.3.0"]);
  // left-pad is a pure JS module with no lifecycle scripts: the honest
  // expectation is a CLEAN uninstall (spike §5: npm -g removes its own tree).
  assert.equal(report.findings.length, 0, `left-pad must roundtrip clean, got: ${JSON.stringify(report.findings)}`);
  const leaked = spawnSync("docker", ["ps", "-aq", "--filter", "name=rt-"], { encoding: "utf8" }).stdout.trim();
  assert.equal(leaked, "", "no rt-* container may survive the run");
});

test("E2E docker: planted rc-append + PATH orphan ⇒ MODIFIED-CRITICAL + ADDED-HIGH (opt-in)", async (t) => {
  if (!DOCKER_E2E) {
    t.skip("docker legs are opt-in");
    return;
  }
  // Build an npm-pack-shaped tgz whose postinstall plants two surfaces the
  // manager's uninstall will never know to undo (the spike's T3 fixture, §2).
  const dir = makeFixtureDir("roundtrip-plant");
  try {
    const pkg = join(dir, "package");
    mkdirSync(pkg, { recursive: true });
    writeFileSync(
      join(pkg, "package.json"),
      JSON.stringify({ name: "rt-plant", version: "0.0.1", scripts: { postinstall: "node plant.js" }, license: "MIT" }, null, 2),
    );
    // /etc/profile (not ~/.bashrc): guaranteed present in every Debian base, so the
    // append is truly a MODIFIED row — creating a fresh file would test ADDED twice.
    writeFileSync(
      join(pkg, "plant.js"),
      [
        'const fs = require("fs");',
        'fs.appendFileSync("/etc/profile", "\\nexport RT_PLANT=1\\n");',
        'fs.writeFileSync("/usr/local/bin/rt-orphan", "#!/bin/sh\\necho orphan\\n");',
        'console.log("PLANTED");',
      ].join("\n"),
    );
    const tgz = join(dir, "rt-plant-0.0.1.tgz");
    const pack = spawnSync("tar", ["-czf", tgz, "-C", dir, "package"], { encoding: "utf8" });
    assert.equal(pack.status, 0, pack.stderr);

    const bytes = readFileSync(tgz);
    const tarballUrl = "https://registry.npmjs.org/rt-plant/-/rt-plant-0.0.1.tgz";
    const fetcher: ScanFetcher = async (url): Promise<ScanResponse> => {
      const body =
        url === "https://registry.npmjs.org/rt-plant/0.0.1"
          ? new TextEncoder().encode(JSON.stringify({ name: "rt-plant", version: "0.0.1", dist: { tarball: tarballUrl } }))
          : url === tarballUrl
            ? new Uint8Array(bytes)
            : (() => {
                throw new Error(`unscripted URL ${url}`);
              })();
      return { status: 200, contentLength: body.byteLength, async *chunks() { yield body; } };
    };

    const ctx = ctxOf(["npm:rt-plant@0.0.1"], { json: true });
    const code = await runRoundtripCore(ctx, { fetcher });
    assert.equal(code, EXIT_BLOCKED, ctx.err.join("\n"));
    const report = JSON.parse(ctx.out.join("\n")) as Report;
    const byPath = new Map<string, Finding>(report.findings.map((f) => [f.path ?? f.target, f]));
    const profile = byPath.get("/etc/profile");
    const orphan = byPath.get("/usr/local/bin/rt-orphan");
    assert.ok(profile, `expected MODIFIED /etc/profile row, got: ${JSON.stringify(report.findings)}`);
    assert.equal(profile.rule, "roundtrip-modified-persistence");
    assert.equal(profile.severity, "CRITICAL");
    assert.ok(orphan, "expected ADDED /usr/local/bin/rt-orphan row");
    assert.equal(orphan.rule, "roundtrip-residue-file");
    assert.equal(orphan.severity, "HIGH");
    assert.equal(report.findings.length, 2, `exactly the two planted surfaces, got: ${JSON.stringify([...byPath.keys()])}`);
    assertNoLeakedContainers();
  } finally {
    removeDir(dir);
  }
});

// ---------------------------------------------------------------- pypi lane

test("E2E docker: real published six@1.17.0 (pypi) roundtrip reaches a verdict (opt-in)", async (t) => {
  if (!DOCKER_E2E) {
    t.skip("docker legs are opt-in — offline suite stays green");
    return;
  }
  // six ships an sdist (fetchArtifact's accepted form — wheels are pre-built,
  // setup code lives in the sdist) and its pip uninstall is RECORD-driven.
  await assertCleanLane(t, "pypi:six@1.17.0", "pypi:six@1.17.0");
});

test("E2E docker: planted pypi sdist (setup.py runs during install build) ⇒ CRITICAL + HIGH (opt-in)", async (t) => {
  if (!DOCKER_E2E) {
    t.skip("docker legs are opt-in");
    return;
  }
  // Spike-proven recipe (.omo/evidence/residue-spike/roundtrip-spike-docker-pypi.sh):
  // PKG-INFO + setup.py + module, tar'd as the sdist root dir; pip's sdist build
  // executes setup.py as root inside the container — the pypi plant channel.
  const dir = makeFixtureDir("roundtrip-plant-pypi");
  try {
    const pkg = join(dir, "rt_pypi_plant-0.0.1");
    mkdirSync(pkg, { recursive: true });
    writeFileSync(join(pkg, "PKG-INFO"), "Metadata-Version: 2.1\nName: rt-pypi-plant\nVersion: 0.0.1\nSummary: W2.1 plant fixture\n");
    writeFileSync(
      join(pkg, "setup.py"),
      [
        "import os",
        "def plant():",
        "    try:",
        "        cur = open('/etc/profile').read()",
        "        if 'RT_PLANT_PYPI' not in cur:",
        "            with open('/etc/profile', 'a') as f:",
        "                f.write('\\nexport RT_PLANT_PYPI=1\\n')",
        "    except OSError as e:",
        "        print('PLANT-DENIED profile %s' % e)",
        "    try:",
        "        with open('/usr/local/bin/rt-plant-pypi', 'w') as f:",
        "            f.write('#!/bin/sh\\necho rt-plant-pypi\\n')",
        "        os.chmod('/usr/local/bin/rt-plant-pypi', 0o755)",
        "    except OSError as e:",
        "        print('PLANT-DENIED orphan %s' % e)",
        "plant()",
        "from setuptools import setup",
        "setup(name='rt-pypi-plant', version='0.0.1', py_modules=['rt_pypi_plant'], description='W2.1 fixture', long_description='x')",
        "",
      ].join("\n"),
    );
    writeFileSync(join(pkg, "rt_pypi_plant.py"), 'MARKER = "rt-pypi-plant"\n');
    const tar = join(dir, "rt-pypi-plant-0.0.1.tar.gz");
    runChecked("tar", ["-czf", tar, "-C", dir, "rt_pypi_plant-0.0.1"], "tar sdist");

    const dl = "https://files.pythonhosted.org/packages/source/r/rt-pypi-plant/rt-pypi-plant-0.0.1.tar.gz";
    const fetcher = scriptedFetcher(
      new Map([
        [pypiMetadataUrl("rt-pypi-plant", "0.0.1"), jsonBytes({ urls: [{ packagetype: "sdist", url: dl, filename: "rt-pypi-plant-0.0.1.tar.gz" }] })],
        [dl, new Uint8Array(readFileSync(tar))],
      ]),
    );

    const report = await withTransientRetry(t, "pypi:rt-pypi-plant@0.0.1", async () => {
      const ctx = ctxOf(["pypi:rt-pypi-plant@0.0.1"], { json: true });
      const code = await runRoundtripCore(ctx, { fetcher });
      assert.equal(code, EXIT_BLOCKED, ctx.err.join("\n"));
      return JSON.parse(ctx.out.join("\n")) as Report;
    });
    assertPlantedRows(t, report.findings, "/usr/local/bin/rt-plant-pypi");
  } finally {
    removeDir(dir);
  }
});

// ---------------------------------------------------------------- rubygems lane

test("E2E docker: real published rake@13.3.0 (rubygems) roundtrip reaches a verdict (opt-in)", async (t) => {
  if (!DOCKER_E2E) {
    t.skip("docker legs are opt-in — offline suite stays green");
    return;
  }
  // Pure-ruby, zero runtime deps (rubygems API verified); .gem fetch + install
  // is fast, so no fallback to a smaller gem was needed.
  // GOLD honest residue (captured verbatim this box, gprobe2-confirmed):
  // ruby:3.4-slim puts GEM_HOME=/usr/local/bundle (top dir ships in the image,
  // the skeleton below is created by the FIRST gem run and never removed) and
  // `gem uninstall rake -x --force` (product argv, matches PROFILES) removes
  // gems/specifications CONTENT but leaves the skeleton dirs AND a fresh
  // /usr/local/bundle/bin/rake binstub behind (its mtime = install time).
  await assertCleanLane(t, "rubygems:rake@13.3.0", "rubygems:rake@13.3.0", [
    "/usr/local/bundle/bin",
    "/usr/local/bundle/bin/rake",
    "/usr/local/bundle/build_info",
    "/usr/local/bundle/cache",
    "/usr/local/bundle/doc",
    "/usr/local/bundle/extensions",
    "/usr/local/bundle/gems",
    "/usr/local/bundle/plugins",
    "/usr/local/bundle/specifications",
  ]);
});

test("E2E docker: planted gem via ext/Rakefile (install-time root code, no make needed) ⇒ CRITICAL + HIGH (opt-in)", async (t) => {
  if (!DOCKER_E2E) {
    t.skip("docker legs are opt-in");
    return;
  }
  // ruby:3.4-slim ships no make/cc (probed), so an extconf.rb extension dies at
  // the unconditional make invocation. Gem::Ext::Builder#builder_for routes
  // /rakefile/i extensions to RakeBuilder, which runs the bundled rake 13.2.1
  // default gem — arbitrary install-time ruby, no toolchain. The Rakefile is
  // pure fixture, NOT the product: uninstall still has no hook to undo it.
  const dir = makeFixtureDir("roundtrip-plant-gem");
  try {
    const pkg = join(dir, "rt-gem-plant-0.0.1");
    mkdirSync(join(pkg, "ext"), { recursive: true });
    mkdirSync(join(pkg, "lib"), { recursive: true });
    writeFileSync(
      join(pkg, "ext", "Rakefile"),
      [
        "task :compile do",
        '  line = "\\nexport RT_PLANT_GEM=1\\n"',
        '  prof = File.read("/etc/profile")',
        '  File.open("/etc/profile", "a") { |f| f.write(line) } unless prof.include?("RT_PLANT_GEM")',
        '  File.write("/usr/local/bin/rt-plant-gem", "#!/bin/sh\\necho rt-plant-gem\\n")',
        '  File.chmod(0o755, "/usr/local/bin/rt-plant-gem")',
        "end",
        "task :default => :compile",
        "",
      ].join("\n"),
    );
    writeFileSync(join(pkg, "lib", "rt-gem-plant.rb"), 'module RtGemPlant; VERSION = "0.0.1"; end\n');
    writeFileSync(
      join(pkg, "rt-gem-plant.gemspec"),
      [
        "Gem::Specification.new do |s|",
        '  s.name = "rt-gem-plant"; s.version = "0.0.1"',
        '  s.summary = "W2.1 plant fixture"; s.description = "W2.1 plant fixture"',
        '  s.authors = ["border"]; s.email = "border@example.invalid"',
        '  s.files = ["lib/rt-gem-plant.rb", "ext/Rakefile"]',
        '  s.extensions = ["ext/Rakefile"]',
        '  s.require_paths = ["lib"]',
        '  s.license = "MIT"',
        "end",
        "",
      ].join("\n"),
    );
    const gem = join(dir, "rt-gem-plant-0.0.1.gem");
    runChecked("gem", ["build", "rt-gem-plant.gemspec", "-o", gem], "gem build", pkg);

    const fetcher = scriptedFetcher(new Map([[rubygemsDownloadUrl("rt-gem-plant", "0.0.1"), new Uint8Array(readFileSync(gem))]]));
    const ctx = ctxOf(["rubygems:rt-gem-plant@0.0.1"], { json: true });
    const code = await runRoundtripCore(ctx, { fetcher });
    assert.equal(code, EXIT_BLOCKED, ctx.err.join("\n"));
    const report = JSON.parse(ctx.out.join("\n")) as Report;
    // Outside GEM_HOME the verdict must be EXACTLY the two planted surfaces;
    // inside it, the same never-recreated manager skeleton the clean rake leg
    // pins (plus extensions/<arch>/<ver> from this gem's Rakefile build — all
    // HIGH residue-file rows, no new classes).
    const outside = report.findings.filter((f) => !(f.path ?? "").startsWith("/usr/local/bundle"));
    assertPlantedRows(t, outside, "/usr/local/bin/rt-plant-gem");
    const bundle = report.findings.filter((f) => (f.path ?? "").startsWith("/usr/local/bundle"));
    assert.ok(bundle.every((f) => f.rule === RT_RESIDUE_RULE && f.severity === "HIGH"), `bundle noise shape changed: ${JSON.stringify(bundle)}`);
    t.diagnostic(`gem-plant bundle rows: ${JSON.stringify(bundle.map((f) => f.path))}`);
  } finally {
    removeDir(dir);
  }
});

// ---------------------------------------------------------------- crates lane

test("E2E docker: real published rust-hello@0.1.1 (crates) roundtrip reaches a verdict (opt-in)", async (t) => {
  if (!DOCKER_E2E) {
    t.skip("docker legs are opt-in — offline suite stays green");
    return;
  }
  // Deviation from the W2.1 brief (was itoa@1.0.14), forced by the lane itself:
  // itoa is lib-only and `cargo install` refuses crates without binaries
  // ("no packages found with binaries or examples", verified in-container), and
  // this box's container egress cannot reach static/index.crates.io at all, so
  // the pick must be dependency-free as well as bin-bearing. rust-hello@0.1.1
  // is real, published, zero-dep, main.rs = one println! — the honest stand-in.
  await assertCleanLane(t, "crates:rust-hello@0.1.1", "crates:rust-hello@0.1.1");
});

test("E2E docker: planted crate via build.rs (install-time root code) ⇒ CRITICAL + HIGH (opt-in)", async (t) => {
  if (!DOCKER_E2E) {
    t.skip("docker legs are opt-in");
    return;
  }
  // build.rs executes as root during `cargo install --path` — the crates plant
  // channel (spike host-lane proven, re-pinned by the W2.1 docker profile fix).
  // The bin is deliberately renamed *-run: a bin named rt-plant-crates would be
  // copied over the planted orphan by cargo AFTER build.rs, and cargo uninstall
  // would then delete the "residue" — a false-clean liar.
  const dir = makeFixtureDir("roundtrip-plant-crate");
  try {
    const pkg = join(dir, "rt-plant-crates-0.0.1");
    mkdirSync(join(pkg, "src"), { recursive: true });
    writeFileSync(
      join(pkg, "Cargo.toml"),
      [
        "[package]",
        'name = "rt-plant-crates"',
        'version = "0.0.1"',
        'edition = "2021"',
        'description = "W2.1 plant fixture"',
        'license = "MIT"',
        "",
        "[[bin]]",
        'name = "rt-plant-crates-run"',
        'path = "src/main.rs"',
        "",
      ].join("\n"),
    );
    writeFileSync(join(pkg, "src", "main.rs"), "fn main() {}\n");
    writeFileSync(
      join(pkg, "build.rs"),
      [
        "use std::fs;",
        "use std::io::Write;",
        "use std::os::unix::fs::PermissionsExt;",
        "fn main() {",
        '    if let Ok(cur) = fs::read_to_string("/etc/profile") {',
        '        if !cur.contains("RT_PLANT_CRATES") {',
        '            if let Ok(mut f) = fs::OpenOptions::new().append(true).open("/etc/profile") {',
        '                let _ = f.write_all(b"\\nexport RT_PLANT_CRATES=1\\n");',
        "            }",
        "        }",
        "    }",
        '    let _ = fs::write("/usr/local/bin/rt-plant-crates", "#!/bin/sh\\necho rt-plant-crates\\n");',
        '    let _ = fs::set_permissions("/usr/local/bin/rt-plant-crates", fs::Permissions::from_mode(0o755));',
        "}",
        "",
      ].join("\n"),
    );
    const crate = join(dir, "rt-plant-crates-0.0.1.crate");
    runChecked("tar", ["-czf", crate, "-C", dir, "rt-plant-crates-0.0.1"], "tar crate");

    const fetcher = scriptedFetcher(new Map([[cratesDownloadUrl("rt-plant-crates", "0.0.1"), new Uint8Array(readFileSync(crate))]]));
    const ctx = ctxOf(["crates:rt-plant-crates@0.0.1"], { json: true });
    const code = await runRoundtripCore(ctx, { fetcher });
    assert.equal(code, EXIT_BLOCKED, ctx.err.join("\n"));
    const report = JSON.parse(ctx.out.join("\n")) as Report;
    assertPlantedRows(t, report.findings, "/usr/local/bin/rt-plant-crates");
  } finally {
    removeDir(dir);
  }
});
