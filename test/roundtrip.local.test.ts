// provenance: border-inspect-roadmap.md W2.4(b) — G-LOCAL: `border roundtrip`
// accepts a LOCAL ARTIFACT FILE, not only a registry spec.
//
// Doctrine pinned by these tests (all of it fail-closed):
//   * Existence decides mode: an argument that resolves to an EXISTING FILE is
//     local; a missing path that looks like a path exits 2 WITHOUT any fetch
//     attempt (a typo must never silently downgrade into a registry pull of
//     different bytes). Directory arguments exit 2.
//   * Ecosystem comes from the EXTENSION ONLY, a closed four-row table
//     (.whl→pypi, .tgz→npm, .crate→crates, .gem→rubygems). No content
//     sniffing: sniffing is guessing, and a guessed ecosystem would grade the
//     artifact through the wrong manager's semantics.
//   * The digest IS the identity: the ledger proof and the report's
//     artifactSha256 are the streaming sha256 of the exact local bytes; the
//     requireProof valve consumes a local proof by digest unchanged.
//   * Provenance honesty: human + JSON output carry source:"local:<abs-path>";
//     a local run is never phrased as registry-verified.
//   * argv discipline: the user's path never reaches a docker argv or a shell
//     string — the bytes are staged to a temp file (registry-mode style) and
//     the container only ever sees a fixed /root/p.<ext> name (wheels: the
//     sanitized PEP 427 basename, because pip grades a wheel by its filename).
//   * Wheel-lane honesty (VERIFIER-REPORT-W24B-SHADOW, live 2026-09-11 on pip
//     24.0 AND 25.0.1): the LOCAL pypi-wheel lane is residue-INERT by
//     construction — pip records its installs and prunes its dirs, so a planted
//     wheel leaves zero survivors. The fake-manifest units here pin row-
//     EMISSION mechanics given a manifest; they are NOT a claim that real pip
//     leaves wheel residue. Planted-detection demos belong to the hook lanes
//     (npm postinstall, gem extconf, crates build.rs) — see the doctrine unit.
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { BORDER_ROOT } from "./helpers/fixtures.ts";

import { createHash } from "node:crypto";

import { EXIT_BLOCKED, EXIT_ERROR, EXIT_PASS, UnknownArgError } from "../src/cli/exit.ts";
import { handlers } from "../src/commands/index.ts";
import type { Ctx, Flags } from "../src/cli/types.ts";
import type { Report } from "../src/findings.ts";
import { sha256Hex, type ScanFetcher } from "../src/scan/fetch.ts";
import { buildRoundtripRecord, type LedgerRecord } from "../src/ledger/records.ts";
import { proofFindings, ROUNDTRIP_PROOF_MISSING_RULE, ROUNDTRIP_PROOF_STALE_RULE } from "../src/check/proofValve.ts";
import {
  classifyLocalInput,
  readLocalArtifact,
  type LocalArtifactInput,
} from "../src/roundtrip/localArtifact.ts";
import { runRoundtripCore, type DockerExec, type ExecResult } from "../src/roundtrip/orchestrate.ts";

// ---------------------------------------------------------------- fixtures

const base = mkdtempSync(join(tmpdir(), "border-local-test-"));

function fixture(rel: string, content: string): string {
  const p = join(base, rel);
  mkdirSync(join(p, ".."), { recursive: true });
  writeFileSync(p, content);
  return p;
}

const WHEEL = fixture("dist/jupyter_core-5.8.1-py3-none-any.whl", "fake-wheel-bytes");
const TGZ = fixture("dist/node-fetch-2.6.1.tgz", "fake-tgz-bytes");
const GEM = fixture("dist/rt-gem-1.0.0.gem", "fake-gem-bytes");
const CRATE = fixture("dist/rt-crate-1.0.0.crate", "fake-crate-bytes");
const UNKNOWN = fixture("dist/thing-1.0.tar.gz", "no-ext-in-table");
const BAD_WHEEL = fixture("dist/not-a-valid-wheel.whl", "too-few-segments");

/** The zero-fetch proof: ANY call into this fetcher is a test failure. */
const explodingFetcher: ScanFetcher = async (url) => {
  throw new Error(`network must not be touched in local mode, got fetch(${url})`);
};

function makeCtx(positionals: readonly string[], cwd = base, flags: Partial<Flags> = {}): Ctx & { out: string[]; err: string[] } {
  const out: string[] = [];
  const err: string[] = [];
  return {
    out,
    err,
    command: "roundtrip",
    flags: { force: false, yes: false, llm: false, json: false, record: false, ...flags },
    positionals,
    cwd,
    env: { ...process.env },
    stdout: (line) => out.push(line),
    stderr: (line) => err.push(line),
    handlers,
  };
}

const F = (p: string, d: string): string => `F\t${p}\t${d}`;
const D = (p: string): string => `D\t${p}\t-`;
const man = (...lines: readonly string[]): string => lines.join("\n") + "\n";
const H = (c: string): string => c.repeat(64);

const SP = "/usr/local/lib/python3.12/site-packages";
const PRISTINE = [D("/"), D("/etc"), D("/usr"), D("/usr/local"), F("/etc/resolv.conf", H("a")), F("/root/.bashrc", H("b"))].sort();
const INSTALLED_WHEEL = [...PRISTINE, F(`${SP}/jupyter_core/__init__.py`, H("c")), D(`${SP}/jupyter_core`)].sort();

/** pypi-aware fake docker (calibrate-test ordering doctrine: specific matchers first). */
type Script = { manifests: readonly string[]; closureReport?: string; installStatus?: number };
type LocalRecorder = { calls: string[][]; cpPaths: Array<{ host: string; ctr: string }>; rmCalls: number };

function fakeExec(script: Script): { exec: DockerExec; rec: LocalRecorder } {
  const rec: LocalRecorder = { calls: [], cpPaths: [], rmCalls: 0 };
  let snapshotIdx = 0;
  const exec: DockerExec = (args): ExecResult => {
    rec.calls.push([...args]);
    const joined = args.join(" ");
    if (args[0] === "--version") return { status: 0, stdout: "Docker version 27.0.0, build fake", stderr: "" };
    if (args[0] === "run") return { status: 0, stdout: "deadbeef\n", stderr: "" };
    if (args[0] === "cp") {
      rec.cpPaths.push({ host: String(args[1]), ctr: String(args[2]) });
      return { status: 0, stdout: "", stderr: "" };
    }
    if (args[0] === "rm") {
      rec.rmCalls += 1;
      return { status: 0, stdout: "", stderr: "" };
    }
    if (args[0] === "exec") {
      if (joined.includes("--dry-run --report")) return { status: 0, stdout: "", stderr: "" };
      if (joined.includes("cat /dev/shm/rt-report.json")) {
        if (script.closureReport === undefined) return { status: 1, stdout: "", stderr: "cat: no such file" };
        return { status: 0, stdout: script.closureReport, stderr: "" };
      }
      if (joined.includes("python3")) return { status: 0, stdout: "", stderr: "" };
      if (joined.includes("find / -xdev")) return { status: 0, stdout: script.manifests[snapshotIdx++] ?? "", stderr: "" };
      if (joined.includes("install")) return { status: script.installStatus ?? 0, stdout: "installed", stderr: "" };
      if (joined.includes("uninstall")) return { status: 0, stdout: "", stderr: "" };
    }
    throw new Error(`fakeExec: unmatched docker argv: ${joined}`);
  };
  return { exec, rec };
}

const WHEEL_CLOSURE = JSON.stringify({
  version: 1,
  install: [{ download_info: { url: "file:///root/jupyter_core-5.8.1-py3-none-any.whl" }, metadata: { metadata_version: "2.4", name: "jupyter_core", version: "5.8.1" } }],
});

async function runLocal(pathArg: string, script: Script, flags: Partial<Flags> = {}) {
  const ctx = makeCtx([pathArg], base, flags);
  const { exec, rec } = fakeExec(script);
  const code = await runRoundtripCore(ctx, { fetcher: explodingFetcher, exec });
  return { code, ctx, rec };
}

// ---------------------------------------------------------------- detection table (pure)

test("G-LOCAL detection: each supported extension routes to exactly one ecosystem, closed table", () => {
  const cases: Array<[string, string, "pypi" | "npm" | "crates" | "rubygems", string]> = [
    [WHEEL, "jupyter_core", "pypi", "5.8.1"],
    [TGZ, "node-fetch", "npm", "2.6.1"],
    [GEM, "rt-gem", "rubygems", "1.0.0"],
    [CRATE, "rt-crate", "crates", "1.0.0"],
  ];
  for (const [file, name, eco, version] of cases) {
    const input = classifyLocalInput(file, base, () => false) as LocalArtifactInput;
    assert.equal(input.ecosystem, eco, `${file} → ${eco}`);
    assert.equal(input.name, name);
    assert.equal(input.version, version);
    assert.equal(input.source, `local:${file}`);
    assert.equal(input.absPath, file);
  }
  // container paths: fixed names derived from the closed table, NEVER the user path.
  // Wheels are the single exception: pip refuses any filename that is not PEP 427
  // shaped (live proof: "ERROR: p.whl is not a valid wheel filename"), so the
  // wheel lane carries its own basename in — sanitized to the argv whitelist.
  assert.equal(classifyLocalInput(WHEEL, base, () => false)?.containerPath, "/root/jupyter_core-5.8.1-py3-none-any.whl");
  assert.equal(classifyLocalInput(TGZ, base, () => false)?.containerPath, "/root/p.tgz");
  assert.equal(classifyLocalInput(GEM, base, () => false)?.containerPath, "/root/p.gem");
  assert.equal(classifyLocalInput(CRATE, base, () => false)?.containerPath, "/root/p.crate");
});

test("G-LOCAL wheel container name: charset-sanitized, never directory-escaping (PEP 440 '!' local epoch → '_')", () => {
  const legacy = fixture("dist/legacy-1!2.0-py3-none-any.whl", "epoch-wheel");
  const input = classifyLocalInput(legacy, base, () => false) as LocalArtifactInput;
  assert.equal(input.version, "1!2.0");
  assert.equal(input.containerPath, "/root/legacy-1_2.0-py3-none-any.whl");
  assert.ok(!input.containerPath.includes("!"), "sanitized name stays inside the [A-Za-z0-9._+-] whitelist");
});

test("G-LOCAL detection: unknown extension ⇒ exit-2 UnknownArgError listing the closed table (no sniffing)", () => {
  assert.throws(
    () => classifyLocalInput(UNKNOWN, base, () => false),
    (err: unknown) =>
      err instanceof UnknownArgError &&
      err.exitCode === 2 &&
      /\.whl/.test(err.message) &&
      /\.tgz/.test(err.message) &&
      /\.crate/.test(err.message) &&
      /\.gem/.test(err.message),
  );
});

test("G-LOCAL detection: wheel filename grammar is enforced (no '@' in names, >=5 dash fields)", () => {
  assert.throws(() => classifyLocalInput(BAD_WHEEL, base, () => false), (err: unknown) => err instanceof UnknownArgError && /jupyter_core-5\.8\.1-py3-none-any\.whl/.test(err.message));
});

test("G-LOCAL detection: a directory exits 2 before any docker touch", async () => {
  mkdirSync(join(base, "adir"), { recursive: true });
  const { code, ctx } = await settle(makeCtx(["adir"], base), { fetcher: explodingFetcher, exec: () => { throw new Error("docker must not be probed for a directory"); } });
  assert.equal(code, EXIT_ERROR);
  assert.match(ctx.err.join("\n") + ctx.out.join("\n"), /directory/i);
});

/** runRoundtripCore throws typed errors (cli.run maps them to exit 2); settle mirrors that translation for direct-core tests. */
async function settle(ctx: Ctx, deps: { fetcher: ScanFetcher; exec: DockerExec }): Promise<{ code: number; ctx: Ctx & { out: string[]; err: string[] } }> {
  try {
    const code = await runRoundtripCore(ctx, deps);
    return { code, ctx: ctx as Ctx & { out: string[]; err: string[] } };
  } catch (err) {
    const e = err as Error & { exitCode?: number };
    (ctx as Ctx & { err: string[] }).stderr(`${e.name}: ${e.message}`);
    return { code: e.exitCode ?? EXIT_ERROR, ctx: ctx as Ctx & { out: string[]; err: string[] } };
  }
}

test("G-LOCAL detection: a missing path that looks like a path exits 2 WITHOUT any fetch or docker attempt", async () => {
  const ctx = makeCtx(["./dist/nope-1.0.0.whl"], base);
  const code = await settleWithGuard(ctx);
  assert.equal(code, EXIT_ERROR);
  assert.match(ctx.err.join("\n"), /not an existing file/i);
});

test("G-LOCAL detection: a missing bare '.tgz' name exits 2 (local grammar wins over spec error text)", async () => {
  const ctx = makeCtx(["gone-1.0.0.tgz"], base);
  const code = await settleWithGuard(ctx);
  assert.equal(code, EXIT_ERROR);
  assert.match(ctx.err.join("\n"), /not an existing file/i);
});

/** exec throws if TOUCHED at all (neither probe nor container ops may run pre-detection); fetcher explodes on use. */
async function settleWithGuard(ctx: Ctx & { out: string[]; err: string[] }): Promise<number> {
  const boom: DockerExec = () => {
    throw new Error("docker must not be touched before input detection");
  };
  return (await settle(ctx, { fetcher: explodingFetcher, exec: boom })).code;
}

test("registry specs keep byte-identical routing: a slash-bearing spec that misses on disk is still a SPEC, not a path error", async () => {
  const ctx = makeCtx(["@scope/pkg@1.2.3"], base);
  // neither file nor docker will answer here; what we pin is the ERROR CLASS:
  // a scoped spec must reach the registry lane (fetch attempted), never the
  // missing-local-path typed error. The exploding fetcher proves the lane.
  const boom: DockerExec = (args) => {
    if (args[0] === "--version") return { status: 0, stdout: "Docker version 27.0.0, build fake", stderr: "" };
    throw new Error("no container ops in this test");
  };
  await assert.rejects(() => runRoundtripCore(ctx, { fetcher: explodingFetcher, exec: boom }), /network must not be touched/);
});

// ---------------------------------------------------------------- streaming digest

test("readLocalArtifact: streaming digest equals one-shot createHash; bytes are the exact file bytes; cap fails closed", async () => {
  const big = "x".repeat(3_000_000);
  const p = fixture("big-1.0.0.tgz", big);
  const { bytes, sha256 } = await readLocalArtifact(p);
  assert.equal(sha256, createHash("sha256").update(Buffer.from(big)).digest("hex"));
  assert.equal(sha256, sha256Hex(Buffer.from(big)));
  assert.deepEqual([...bytes], [...Buffer.from(big)]);
  await assert.rejects(() => readLocalArtifact(p, 1_000_000), /cap|too large/i);
});

// ---------------------------------------------------------------- pipeline wiring (fake docker, zero network)

test("local pypi wheel: clean verdict, exit 0, provenance lines, closure leg installs the CONTAINER path", async () => {
  const { code, ctx, rec } = await runLocal("./dist/jupyter_core-5.8.1-py3-none-any.whl", {
    manifests: [man(...PRISTINE), man(...INSTALLED_WHEEL), man(...PRISTINE)],
    closureReport: WHEEL_CLOSURE,
  });
  assert.equal(code, EXIT_PASS);
  assert.ok(ctx.out.some((l) => /source local:.*jupyter_core-5\.8\.1-py3-none-any\.whl/.test(l)), ctx.out.join("\n"));
  const wantSha = sha256Hex(readFileSync(WHEEL));
  assert.ok(ctx.out.some((l) => l.includes(wantSha)), `expected artifact sha256 ${wantSha} in:\n${ctx.out.join("\n")}`);
  assert.ok(ctx.out.some((l) => /roundtrip: 0 residue row\(s\)/.test(l)), ctx.out.join("\n"));
  // cp: staged temp copy (resolver leg + measurement leg, registry-style),
  // container side is the sanitized wheel basename — never the user's file path.
  assert.equal(rec.cpPaths.length, 2, "closure resolver + measurement container each cp the staged bytes");
  for (const cp of rec.cpPaths) {
    assert.match(cp.ctr, /:\/root\/jupyter_core-5\.8\.1-py3-none-any\.whl$/);
    assert.notEqual(cp.host, WHEEL, "the user's own file must never be the cp source (staging doctrine)");
  }
  // every docker argv is argv-clean: no user path, no shell string for install legs
  const all = JSON.stringify(rec.calls);
  assert.ok(!all.includes(base), `user path leaked into docker argv: ${all}`);
  const installCall = rec.calls.find((c) => c.join(" ").includes("pip install") && !c.join(" ").includes("--dry-run"));
  assert.deepEqual(installCall?.slice(2), ["pip", "install", "--no-input", "--root-user-action=ignore", "/root/jupyter_core-5.8.1-py3-none-any.whl"]);
});

test("local npm/crates/gem lanes: install argv built from the closed table, path never interpolated", async () => {
  const { rec: npmRec } = await runLocal("./dist/node-fetch-2.6.1.tgz", { manifests: [man(...PRISTINE), man(...PRISTINE, F("/usr/local/lib/node_modules/node-fetch/index.js", H("c"))), man(...PRISTINE)] });
  const npmInstall = npmRec.calls.find((c) => c.join(" ").includes("npm install"));
  assert.deepEqual(npmInstall?.slice(2), ["npm", "install", "-g", "--foreground-scripts", "--no-audit", "--no-fund", "/root/p.tgz"]);

  const { rec: gemRec } = await runLocal("./dist/rt-gem-1.0.0.gem", { manifests: [man(...PRISTINE), man(...PRISTINE, F("/usr/local/share/gems/gems/rt-gem-1.0.0/lib/x.rb", H("d"))), man(...PRISTINE)] });
  const gemInstall = gemRec.calls.find((c) => c.join(" ").includes("gem install"));
  assert.deepEqual(gemInstall?.slice(2), ["gem", "install", "--no-document", "/root/p.gem"]);

  const { rec: crateRec } = await runLocal("./dist/rt-crate-1.0.0.crate", { manifests: [man(...PRISTINE), man(...PRISTINE, F("/usr/local/bin/rt-crate", H("e"))), man(...PRISTINE)] });
  const crateInstall = crateRec.calls.find((c) => c.join(" ").includes("tar xf"));
  assert.ok(crateInstall?.[3] === "-c", "sh -c script uses ONLY the fixed /root/p.crate name");
  assert.match(String(crateInstall?.[4]), /^tar xf \/root\/p\.crate -C \/opt && cargo install --root \/usr\/local --path "?\/opt\/rt-crate-1\.0\.0"? && rm -rf "?\/opt\/rt-crate-1\.0\.0"?$/);
  assert.ok(!JSON.stringify(crateInstall).includes(base));
});

// Pins border's row-EMISSION mechanics for a manifest that (in this FAKE m3)
// still lists a survivor — NOT a claim that real pip leaves wheel residue: the
// local wheel lane is residue-INERT (see header; live pip 24.0/25.0.1,
// 2026-09-11). The hostile shape stays inside site-packages, where pip's own
// RECORD pruning actually operates.
test("local wheel: fake survivor manifest ⇒ exit 1, rows target the derived label, provenance still local (emission mechanics only)", async () => {
  const dirty = [...PRISTINE, F(`${SP}/jupyter_core/evil.py`, H("f"))];
  const { code, ctx } = await runLocal(WHEEL, {
    manifests: [man(...PRISTINE), man(...INSTALLED_WHEEL), man(...dirty)],
    closureReport: WHEEL_CLOSURE,
  });
  assert.equal(code, EXIT_BLOCKED);
  assert.ok(ctx.out.some((l) => /HIGH.*roundtrip.*evil\.py/.test(l)), ctx.out.join("\n"));
  assert.ok(ctx.out.some((l) => l.includes("1 residue row(s)")));
  assert.ok(ctx.out.some((l) => /source local:/.test(l)));
});

test("--json local mode: Report carries source + artifactSha256; registry mode's Report keys stay unchanged", async () => {
  const { code, ctx } = await runLocal(WHEEL, { manifests: [man(...PRISTINE), man(...INSTALLED_WHEEL), man(...PRISTINE)], closureReport: WHEEL_CLOSURE }, { json: true });
  assert.equal(code, EXIT_PASS);
  const report = JSON.parse(ctx.out.join("\n")) as Report & { source?: string; artifactSha256?: string };
  assert.equal(report.source, `local:${WHEEL}`);
  assert.equal(report.artifactSha256, sha256Hex(readFileSync(WHEEL)));
  assert.match(report.key, /^[0-9a-f]{64}$/);
  assert.equal(report.verdict, "PASS");
  assert.deepEqual(report.exposureSet, ["pypi:jupyter_core@5.8.1"]);

  // registry lane untouched: npm spec via stub fetcher carries NO source keys.
  const tarballUrl = "https://registry.npmjs.org/rt-fake/-/rt-fake-1.0.0.tgz";
  const stub: ScanFetcher = async (url) => {
    const body =
      url === "https://registry.npmjs.org/rt-fake/1.0.0"
        ? new TextEncoder().encode(JSON.stringify({ name: "rt-fake", version: "1.0.0", dist: { tarball: tarballUrl } }))
        : url === tarballUrl
          ? new Uint8Array(Buffer.from("fake-tgz-bytes"))
          : (() => { throw new Error(`unscripted ${url}`); })();
    return { status: 200, contentLength: body.byteLength, async *chunks() { yield body; } };
  };
  const rctx = makeCtx(["rt-fake@1.0.0"], base, { json: true });
  const { exec } = fakeExec({ manifests: [man(...PRISTINE), man(...PRISTINE, F("/usr/local/lib/node_modules/rt-fake/index.js", H("c"))), man(...PRISTINE)] });
  const rcode = await runRoundtripCore(rctx, { fetcher: stub, exec });
  assert.equal(rcode, EXIT_PASS);
  const rreport = JSON.parse(rctx.out.join("\n")) as Report & { source?: string; artifactSha256?: string };
  assert.ok(!("source" in rreport), JSON.stringify(Object.keys(rreport)));
  assert.ok(!("artifactSha256" in rreport));
  assert.deepEqual(rreport.exposureSet, ["npm:rt-fake@1.0.0"]);
});

test("local mode never calls the fetcher (zero-network) — exploding seam proves absence of fetch, not its absence from output", async () => {
  // explodingFetcher throws on ANY use; a green run below IS the zero-fetch proof.
  const { code } = await runLocal(TGZ, { manifests: [man(...PRISTINE), man(...PRISTINE, F("/usr/local/lib/node_modules/node-fetch/i.js", H("c"))), man(...PRISTINE)] });
  assert.equal(code, EXIT_PASS);
});

// ---------------------------------------------------------------- valve integration (digest-is-identity)

test("proof valve consumes a local-mode roundtrip proof by digest, unchanged", () => {
  const { sha256 } = { sha256: sha256Hex(readFileSync(WHEEL)) };
  const rulesHash = sha256Hex("rules");
  const rec = buildRoundtripRecord({ artifactSha256: sha256, verdict: "clean", rulesHash, rows: 0 });
  const artifacts = [{ file: "dist/jupyter_core-5.8.1-py3-none-any.whl", sha256 }];
  // fresh proof for exactly these bytes ⇒ no findings, regardless of the spec form staged
  assert.deepEqual(proofFindings({ artifacts, records: [rec] as LedgerRecord[], rulesHash }), []);
  // same digest, rotated rules ⇒ stale (unchanged invalidation semantics)
  const stale = proofFindings({ artifacts, records: [rec] as LedgerRecord[], rulesHash: sha256Hex("other") });
  assert.equal(stale[0]?.rule, ROUNDTRIP_PROOF_STALE_RULE);
  // bytes nobody roundtripped ⇒ missing
  const stranger = [{ file: "dist/other.whl", sha256: sha256Hex("other-bytes") }];
  const missing = proofFindings({ artifacts: stranger, records: [rec] as LedgerRecord[], rulesHash });
  assert.equal(missing[0]?.rule, ROUNDTRIP_PROOF_MISSING_RULE);
});

test("local directory input is rejected even when --json is on (no partial JSON on stderr paths)", async () => {
  const ctx = makeCtx(["adir"], base, { json: true });
  const code = await settleWithGuard(ctx);
  assert.equal(code, EXIT_ERROR);
  assert.equal(ctx.out.length, 0);
});

// ---------------------------------------------------------------- doctrine (docs boundary)

test("doctrine: README states the local PyPI-wheel lane is residue-inert — en paragraph + zh mirror, no disproven mechanism restated", () => {
  const readme = readFileSync(join(BORDER_ROOT, "README.md"), "utf8");
  const zhIdx = readme.indexOf("## 中文概要");
  assert.ok(zhIdx > 0, "zh mirror section must exist (RC-DOC pattern)");
  const en = readme.slice(0, zhIdx);
  const zh = readme.slice(zhIdx);
  // The boundary VERIFIER-REPORT-W24B-SHADOW forced into the docs: planted wheels
  // are residue-INERT under pip (live 24.0 AND 25.0.1, 2026-09-11) — the README
  // must say so, cite both pip versions, and point plant demos at the hook lanes.
  assert.ok(en.includes("is residue-INERT"), "en local-mode paragraph must state the inert-wheel boundary");
  assert.ok(en.includes("pip 25.0.1 AND 24.0"), "en boundary sentence cites both live-verified pip versions");
  assert.ok(en.includes("npm install -g --foreground-scripts"), "en names the executing-hook lane where plant demos belong");
  assert.ok(zh.includes("残留惰性"), "zh mirror states the inert-wheel boundary");
  assert.ok(zh.includes("pip 25.0.1 与 24.0"), "zh mirror cites both live-verified pip versions");
  assert.ok(zh.includes("种植检测演示属于会执行安装钩子的通道"), "zh mirror points plant demos at the hook lanes");
  // The disproven fabricated survivor path must appear nowhere in the doctrine docs.
  assert.ok(!readme.includes("/usr/local/.config"), "disproven planted-wheel survivor path must not be restated");
});

process.on("exit", () => rmSync(base, { recursive: true, force: true }));
