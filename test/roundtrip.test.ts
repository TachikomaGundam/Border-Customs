// provenance: border-inspect-roadmap.md W2.1 — `border roundtrip` orchestrator.
//
// Offline by default: every classification leg drives runRoundtripCore through
// the injected DockerExec seam with scripted manifests, so the residue matrix
// (ADDED→HIGH, MODIFIED→persistence?CRITICAL:HIGH, no-op install→exit 2,
// exec failure→exit 2 never clean, trap-cleanup on every path incl throw) is
// pinned without the daemon. Real-docker legs are opt-in via
// BORDER_ROUNDTRIP_DOCKER=1 (test/roundtrip.e2e.test.ts, BORDER_PACK_TEST /
// BORDER_SCAN_NETWORK_E2E doctrine). Mechanics mirror the proven W2.0 spike
// (.omo/evidence/residue-spike/ROUNDTRIP-SPIKE.md + roundtrip-spike-lib.sh).
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { EXIT_BLOCKED, EXIT_ERROR, EXIT_PASS } from "../src/cli/exit.ts";
import { handlers } from "../src/commands/index.ts";
import { run } from "../src/cli.ts";
import type { Ctx, Flags } from "../src/cli/types.ts";
import { EngineMissingError, EngineRunError } from "../src/engines/support.ts";
import type { Report } from "../src/findings.ts";
import type { ScanFetcher, ScanResponse } from "../src/scan/fetch.ts";
import {
  isPersistenceSurface,
  parseManifest,
  diffManifests,
  classifyResidue,
  RT_RESIDUE_RULE,
  RT_MODIFY_RULE,
  RT_PERSIST_RULE,
} from "../src/roundtrip/manifest.ts";
import { snapshotScript, BASE_EXCLUDES, PYTHON_EXCLUDES } from "../src/roundtrip/docker.ts";
import { profileFor, runRoundtripCore, containerNameFor, type DockerExec, type ExecResult } from "../src/roundtrip/orchestrate.ts";

// ---------------------------------------------------------------- fixtures

function makeCtx(positionals: readonly string[], flags: Partial<Flags> = {}): Ctx & { out: string[]; err: string[] } {
  const out: string[] = [];
  const err: string[] = [];
  const base: Flags = { force: false, yes: false, llm: false, json: false, ...flags };
  return {
    out,
    err,
    command: "roundtrip",
    flags: base,
    positionals,
    cwd: tmpdir(),
    env: { ...process.env },
    stdout: (line) => out.push(line),
    stderr: (line) => err.push(line),
    handlers,
  };
}

/** Minimal npm-registry stub: metadata JSON + arbitrary tgz bytes (fetch seam only). */
function stubFetcher(tgz: Buffer): ScanFetcher {
  const tarballUrl = "https://registry.npmjs.org/rt-fake/-/rt-fake-1.0.0.tgz";
  return async (url: string): Promise<ScanResponse> => {
    const body =
      url === "https://registry.npmjs.org/rt-fake/1.0.0"
        ? new TextEncoder().encode(JSON.stringify({ name: "rt-fake", version: "1.0.0", dist: { tarball: tarballUrl } }))
        : url === tarballUrl
          ? new Uint8Array(tgz)
          : (() => {
              throw new Error(`stubFetcher got unscripted URL: ${url}`);
            })();
    return { status: 200, contentLength: body.byteLength, async *chunks() { yield body; } };
  };
}

const F = (p: string, d: string): string => `F\t${p}\t${d}`;
const L = (p: string, t: string): string => `L\t${p}\t${t}`;
const D = (p: string): string => `D\t${p}\t-`;
const man = (...lines: readonly string[]): string => lines.join("\n") + "\n";

const H1 = "a".repeat(64);
const H2 = "b".repeat(64);
const H3 = "c".repeat(64);

// Baseline "pristine" container: /root/.bashrc + a system lib + dirs + a symlink.
const PRISTINE = [
  D("/"),
  D("/etc"),
  F("/etc/resolv.conf", H1),
  L("/lib/x", "usr/lib/x"),
  F("/root/.bashrc", H1),
  F("/usr/lib/x", H2),
].sort();

/** install delta of one package file — proves the install was NOT a no-op. */
const INSTALLED = [...PRISTINE, F("/usr/local/lib/node_modules/rt-fake/index.js", H3), D("/usr/local/lib/node_modules/rt-fake")].sort();

type Script = {
  /** manifest handed back per snapshot call, in order (m1, m2, m3). */
  manifests?: readonly string[];
  installStatus?: number;
  uninstallStatus?: number;
  snapshotError?: Error;
};

type Recorder = {
  calls: string[][];
  cpPaths: Array<{ host: string; ctr: string }>;
  rmCalls: number;
  timeouts: number[];
};

/** Fake DockerExec: pattern-matches the docker argv like the real daemon would. */
function fakeExec(script: Script): { exec: DockerExec; rec: Recorder } {
  const rec: Recorder = { calls: [], cpPaths: [], rmCalls: 0, timeouts: [] };
  let snapshotIdx = 0;
  const exec: DockerExec = (args, timeoutMs): ExecResult => {
    rec.calls.push([...args]);
    rec.timeouts.push(timeoutMs);
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
      const body = args.slice(2).join(" ");
      if (body.includes("find / -xdev")) {
        if (script.snapshotError !== undefined) throw script.snapshotError;
        const text = (script.manifests ?? [man(...PRISTINE), man(...INSTALLED), man(...PRISTINE)])[snapshotIdx] ?? "";
        snapshotIdx += 1;
        return { status: 0, stdout: text, stderr: "" };
      }
      if (body.includes("npm install") || body.includes("pip install") || body.includes("gem install") || body.includes("cargo install")) {
        return { status: script.installStatus ?? 0, stdout: "added 1 package", stderr: "" };
      }
      if (body.includes("uninstall")) return { status: script.uninstallStatus ?? 0, stdout: "", stderr: "" };
    }
    throw new Error(`fakeExec: unmatched docker argv: ${joined}`);
  };
  return { exec, rec };
}

const SPEC = "rt-fake@1.0.0";
const tgz = Buffer.from("fake-tgz-bytes");

async function core(script: Script, ctx = makeCtx([SPEC])) {
  const { exec, rec } = fakeExec(script);
  const code = await runRoundtripCore(ctx, { fetcher: stubFetcher(tgz), exec });
  return { code, ctx, rec, exec };
}

// ---------------------------------------------------------------- manifest model

test("parseManifest + diffManifests implement the spike key model (type+path, value=sha/target/absent)", () => {
  const before = parseManifest(man(...PRISTINE));
  const after = parseManifest(
    man(
      ...PRISTINE.map((l) => (l === F("/root/.bashrc", H1) ? F("/root/.bashrc", H2) : l)).filter((l) => l !== F("/usr/lib/x", H2)),
      F("/tmp/orphan", H3),
    ),
  );
  const diff = diffManifests(before, after);
  assert.deepEqual(diff.added.map((e) => e.path), ["/tmp/orphan"]);
  assert.deepEqual(diff.removed.map((e) => e.path), ["/usr/lib/x"]);
  assert.deepEqual(diff.modified.map((e) => e.path), ["/root/.bashrc"]);
});

test("parseManifest tolerates trailing newline + empty text", () => {
  assert.equal(parseManifest("").size, 0);
  assert.equal(parseManifest(man(D("/"), F("/f", H1))).size, 2);
});

// ---------------------------------------------------------------- classification matrix

test("planted-then-cleanly-removed ⇒ zero findings (install delta is not residue)", () => {
  const diff = diffManifests(parseManifest(man(...INSTALLED)), parseManifest(man(...PRISTINE)));
  // m1→m3 comparison is what classifies; here identical ⇒ nothing.
  assert.deepEqual(classifyResidue("npm:rt-fake@1.0.0", diffManifests(parseManifest(man(...PRISTINE)), parseManifest(man(...PRISTINE)))), []);
  assert.ok(diff.removed.length > 0); // install DID touch the fs (sanity of the fixture itself)
});

test("surviving added file ⇒ ADDED residue, HIGH", () => {
  const findings = classifyResidue("npm:rt-fake@1.0.0", diffManifests(parseManifest(man(...PRISTINE)), parseManifest(man(...PRISTINE, F("/var/tmp/planted", H3)))));
  assert.equal(findings.length, 1);
  assert.equal(findings[0]?.severity, "HIGH");
  assert.equal(findings[0]?.rule, RT_RESIDUE_RULE);
  assert.equal(findings[0]?.engine, "roundtrip");
  assert.equal(findings[0]?.path, "/var/tmp/planted");
  assert.match(findings[0]?.valueDigest ?? "", /^[0-9a-f]{64}$/);
});

test("modified persistence surface (rc/profile.d/systemd/cron/PATH) ⇒ CRITICAL; plain file ⇒ HIGH", () => {
  assert.ok(isPersistenceSurface("/root/.bashrc"));
  assert.ok(isPersistenceSurface("/etc/profile.d/rt.sh"));
  assert.ok(isPersistenceSurface("/etc/systemd/system/x.service"));
  assert.ok(isPersistenceSurface("/etc/cron.d/rt"));
  assert.ok(isPersistenceSurface("/usr/local/bin/rt"));
  assert.ok(isPersistenceSurface("/root/.config/fish/config.fish"));
  assert.ok(!isPersistenceSurface("/usr/lib/python3/os.py"));
  assert.ok(!isPersistenceSurface("/tmp/scratch"));

  const mk = (p: string) => diffManifests(parseManifest(man(F(p, H1))), parseManifest(man(F(p, H2))));
  const persist = classifyResidue("l", mk("/root/.bashrc"));
  assert.equal(persist[0]?.severity, "CRITICAL");
  assert.equal(persist[0]?.rule, RT_PERSIST_RULE);
  const plain = classifyResidue("l", mk("/usr/lib/python3/os.py"));
  assert.equal(plain[0]?.severity, "HIGH");
  assert.equal(plain[0]?.rule, RT_MODIFY_RULE);
});

test("REMOVED rows are manager-internal noise ⇒ ignored by classifyResidue", () => {
  const diff = diffManifests(parseManifest(man(...PRISTINE)), parseManifest(man(...PRISTINE.filter((l) => l !== F("/etc/resolv.conf", H1)))));
  assert.equal(diff.removed.length, 1);
  assert.deepEqual(classifyResidue("l", diff), []);
});

test("modified symlink target counts as MODIFIED", () => {
  const diff = diffManifests(parseManifest(man(L("/lib/x", "usr/lib/x"))), parseManifest(man(L("/lib/x", "evil"))));
  assert.deepEqual(diff.modified.map((e) => e.path), ["/lib/x"]);
});

// ---------------------------------------------------------------- per-ecosystem profiles

test("profileFor pins the spike-proven image + install/uninstall pairs per ecosystem", () => {
  const spec = (eco: "npm" | "pypi" | "rubygems" | "crates", name: string) => ({ ecosystem: eco, name, version: "1.0.0" }) as const;

  const npm = profileFor("npm");
  assert.equal(npm.image, "node:24-slim");
  assert.match(npm.install(npm.artifactPath, spec("npm", "rt-fake")).join(" "), /npm install -g --foreground-scripts --no-audit --no-fund \/root\/p\.tgz/);
  assert.deepEqual(npm.uninstall(spec("npm", "rt-fake")), ["npm", "uninstall", "-g", "rt-fake"]);

  const pypi = profileFor("pypi");
  assert.equal(pypi.image, "python:3.12-slim");
  assert.match(pypi.install(pypi.artifactPath, spec("pypi", "rt-pypi")).join(" "), /pip install --no-input --root-user-action=ignore \/root\/p\.tar\.gz/);
  assert.deepEqual(pypi.uninstall(spec("pypi", "rt-pypi")), ["pip", "uninstall", "-y", "rt-pypi"]);
  for (const extra of ["/root/.cache", "/var/log", "/var/lib/apt/lists"]) {
    assert.ok(PYTHON_EXCLUDES.includes(extra), `pypi lane must exclude ${extra} (spike §3 noise table)`);
  }

  const gem = profileFor("rubygems");
  assert.equal(gem.image, "ruby:3.4-slim");
  assert.match(gem.install(gem.artifactPath, spec("rubygems", "rt-gem")).join(" "), /gem install --no-document \/root\/p\.gem/);
  assert.deepEqual(gem.uninstall(spec("rubygems", "rt-gem")), ["gem", "uninstall", "rt-gem", "-x", "--force"]);

  const cargo = profileFor("crates");
  assert.equal(cargo.image, "rust:1-slim");
  const cInstall = cargo.install(cargo.artifactPath, spec("crates", "rt-crate")).join(" ");
  assert.match(cInstall, /tar xf \/root\/p\.crate -C \/opt/);
  // E2E-verified on rust:1-slim/cargo 1.98 (W2.1 docker legs, this box):
  // (a) modern cargo parses a bare positional as a CRATE@VER spec — a local
  //     directory MUST go through --path or install dies on "invalid character
  //     `/` in package name"; (b) --no-track SKIPS the $ROOT/.crates2.json
  //     install record, which is the only thing `cargo uninstall` reads —
  //     --no-track therefore makes every crates uninstall a guaranteed
  //     "package ID specification did not match" failure (spike omitted it,
  //     which is why the host lane passed); (c) border's own /opt/<dir> staging
  //     tree survives cargo uninstall (cargo never created it), so the profile
  //     that tar-copies it in is the one that must clean it in its own chain —
  //     after cargo install succeeded, so an install failure still fails closed.
  assert.match(cInstall, /cargo install --root \/usr\/local --path "?\/opt\/rt-crate-1\.0\.0"?/);
  assert.ok(!cInstall.includes("--no-track"), "--no-track suppresses the crates2 record cargo uninstall needs");
  assert.match(cInstall, /&& rm -rf "?\/opt\/rt-crate-1\.0\.0"?$/);
  assert.deepEqual(cargo.uninstall(spec("crates", "rt-crate")), ["cargo", "uninstall", "--root", "/usr/local", "rt-crate"]);

  // The rust image ships CARGO_HOME=/usr/local/cargo (not /root/.cargo) and
  // writes its install record at $ROOT/.crates2.json — both are manager
  // bookkeeping of the /root/.npm class and must be excluded or every crates
  // verdict carries phantom ADDED rows (.package-cache / registry CACHEDIR.TAG
  // churn observed on this box's first docker runs).
  const cargoEx = profileFor("crates").excludes;
  assert.ok(cargoEx.includes("/usr/local/cargo"), "image CARGO_HOME must be excluded");
  assert.ok(cargoEx.includes("/usr/local/.crates2.json"), "install-record file must be excluded");
  // cargo 1.98 additionally writes the LEGACY v1 record /usr/local/.crates.toml
  // and leaves it behind (trimmed) after cargo uninstall — proven on the W2.1
  // docker leg, where it surfaced as a phantom ADDED HIGH row beside the two
  // planted ones. Same bookkeeping class as .crates2.json.
  assert.ok(cargoEx.includes("/usr/local/.crates.toml"), "legacy v1 install-record file must be excluded");
});

test("pypi lane prunes interpreter bytecode caches: pip's first run compiles ~470 stdlib __pycache__/*.pyc (W2.1 docker legs)", () => {
  // Observed on the real six@1.17.0 leg: python:3.12-slim ships the stdlib
  // WITHOUT .pyc, so the first pip invocation writes /usr/local/lib/python3.12/
  // **/__pycache__/*.cpython-312.pyc after m1 and never removes them — 470+
  // phantom ADDED rows that have nothing to do with the package under test.
  // Doctrine: interpreter/manager bookkeeping is hidden by design (cf.
  // /root/.cache, /tmp/node-compile-cache). find -path globs across '/'.
  assert.ok(PYTHON_EXCLUDES.includes("*/__pycache__"), "stdlib pycache noise must be pruned on the pypi lane");
  const sh = snapshotScript([...BASE_EXCLUDES, ...PYTHON_EXCLUDES]);
  assert.ok(sh.includes('-path "*/__pycache__"'), "prune clause must reach the snapshot script verbatim");
  // The prune must be on the pypi lane's script and NOT leak into the npm one
  // (each lane carries only its measured noise set).
  assert.ok(!snapshotScript([...BASE_EXCLUDES]).includes("__pycache__"));
});

// ---------------------------------------------------------------- snapshot script mechanics

test("snapshotScript keeps spike mechanics: -xdev, pruned excludes, /dev/shm scratch, sha256sum, C-locale sort", () => {
  const sh = snapshotScript([...BASE_EXCLUDES, ...PYTHON_EXCLUDES]);
  assert.ok(sh.includes("find / -xdev"));
  for (const ex of ["/proc", "/sys", "/dev", "/root/.npm", "/tmp/node-compile-cache", "/etc/hostname", "/etc/resolv.conf", "/etc/hosts", "/root/.cache"]) {
    assert.ok(sh.includes(`-path "${ex}"`), `prune must carry ${ex}`);
  }
  assert.ok(sh.includes("/dev/shm/rt-snap."), "scratch lives in /dev/shm, never /tmp (scanner self-noise trap)");
  assert.ok(sh.includes("sha256sum"));
  assert.ok(sh.includes("xargs -0 -r"));
  assert.ok(sh.includes("LC_ALL=C sort"));
  // /tmp, /var/tmp, /etc, /usr/local stay OBSERVABLE — no blanket prune for them.
  assert.ok(!/-path "\/tmp"/.test(sh));
  assert.ok(!/-path "\/var\/tmp"/.test(sh));
});

test("containerNameFor: rt-<sha8>-<rand> shape, deterministic prefix", () => {
  const a = containerNameFor("npm:rt-fake@1.0.0", "ff00aa");
  assert.match(a, /^rt-[0-9a-f]{8}-ff00aa$/);
  assert.equal(a, containerNameFor("npm:rt-fake@1.0.0", "ff00aa"));
});

// ---------------------------------------------------------------- pipeline behavior (fake docker)

test("clean roundtrip ⇒ exit 0 + scan-shaped rows + summary line with install-delta", async () => {
  const { code, ctx, rec } = await core({ manifests: [man(...PRISTINE), man(...INSTALLED), man(...PRISTINE)] });
  assert.equal(code, EXIT_PASS);
  assert.ok(ctx.out.some((l) => l.includes("roundtrip: 0 residue row(s); install-delta 2 files")), ctx.out.join("\n"));
  // trap-cleanup ran even on the happy path
  assert.equal(rec.rmCalls, 1);
  assert.equal(rec.calls[0]?.[0], "--version", "the docker probe is the first daemon touch");
  assert.equal(rec.calls[1]?.[0], "run");
  assert.ok(rec.cpPaths.length === 1 && /:\/root\/p\.tgz$/.test(rec.cpPaths[0]?.ctr ?? ""), JSON.stringify(rec.cpPaths));
});

test("residue survives uninstall ⇒ exit 1 (HIGH blocks) + residue row listed", async () => {
  const dirty = [...PRISTINE, F("/tmp/rt-orphan", H3)];
  const { code, ctx, rec } = await core({ manifests: [man(...PRISTINE), man(...INSTALLED), man(...dirty)] });
  assert.equal(code, EXIT_BLOCKED);
  assert.ok(ctx.out.some((l) => /HIGH.*roundtrip.*\/tmp\/rt-orphan/.test(l)), ctx.out.join("\n"));
  assert.ok(ctx.out.some((l) => l.includes("roundtrip: 1 residue row(s)")));
  assert.equal(rec.rmCalls, 1);
});

test("rc-line mutated ⇒ MODIFIED CRITICAL row", async () => {
  const mutated = PRISTINE.map((l) => (l === F("/root/.bashrc", H1) ? F("/root/.bashrc", H2) : l));
  const { code, ctx } = await core({ manifests: [man(...PRISTINE), man(...INSTALLED), man(...mutated)] });
  assert.equal(code, EXIT_BLOCKED);
  assert.ok(ctx.out.some((l) => /CRITICAL.*roundtrip.*\/root\/\.bashrc/.test(l)), ctx.out.join("\n"));
});

test("--json routes through the SAME renderer path as scan: parsable Report, engine='roundtrip'", async () => {
  const dirty = [...PRISTINE, F("/var/tmp/x", H3)];
  const { code, ctx } = await core({ manifests: [man(...PRISTINE), man(...INSTALLED), man(...dirty)] }, makeCtx([SPEC], { json: true }));
  assert.equal(code, EXIT_BLOCKED);
  const report = JSON.parse(ctx.out.join("\n")) as Report;
  assert.equal(report.schemaVersion, 1);
  assert.equal(report.verdict, "FAIL");
  assert.equal(report.findings.length, 1);
  assert.equal(report.findings[0]?.engine, "roundtrip");
  assert.deepEqual(report.exposureSet, ["npm:rt-fake@1.0.0"]);
  assert.match(report.key, /^[0-9a-f]{64}$/);
});

test("no-op install (empty m1→m2 delta) ⇒ exit 2 cannot-verify, NEVER clean (hr vacuous-pass trap)", async () => {
  await assert.rejects(
    () => core({ manifests: [man(...PRISTINE), man(...PRISTINE), man(...PRISTINE)] }).then(({ code }) => code),
    (err: unknown) => err instanceof EngineRunError && /no-op|cannot verify/i.test((err as Error).message),
  );
});

test("install exec failure ⇒ EngineRunError (CLI maps to exit 2), trap still removes container", async () => {
  const { exec, rec } = fakeExec({ installStatus: 1 });
  await assert.rejects(
    () => runRoundtripCore(makeCtx([SPEC]), { fetcher: stubFetcher(tgz), exec }),
    (err: unknown) => err instanceof EngineRunError && /install/i.test((err as Error).message),
  );
  assert.equal(rec.rmCalls, 1, "trap cleanup runs on the install-failure path too");
});

test("exec throw midway (snapshot dies) ⇒ error propagates, rm called — trap-cleanup on throw path", async () => {
  const { exec, rec } = fakeExec({ manifests: [man(...PRISTINE)], snapshotError: new EngineRunError("boom", null) });
  await assert.rejects(() => runRoundtripCore(makeCtx([SPEC]), { fetcher: stubFetcher(tgz), exec }), /boom/);
  assert.equal(rec.rmCalls, 1, "docker rm -f must run even when a phase throws");
});

test("uninstall failure ⇒ exit 2 fail-closed, never a partial clean verdict", async () => {
  await assert.rejects(
    () => core({ manifests: [man(...PRISTINE), man(...INSTALLED), man(...PRISTINE)], uninstallStatus: 17 }).then(({ code }) => code),
    (err: unknown) => err instanceof EngineRunError && /uninstall/i.test((err as Error).message),
  );
});

test("phase timeouts are bounded: snapshots ≤ 120s, install/uninstall ≤ 600s", async () => {
  const { rec } = await core({ manifests: [man(...PRISTINE), man(...INSTALLED), man(...PRISTINE)] });
  const execTimeouts = rec.calls.map((c, i) => ({ c, t: rec.timeouts[i] as number })).filter((x) => x.c[0] === "exec");
  for (const { c, t } of execTimeouts) {
    if (c.join(" ").includes("find / -xdev")) assert.ok(t <= 120_000);
    else assert.ok(t <= 600_000);
  }
});

// ---------------------------------------------------------------- CLI surface

test("docker absent ⇒ exit 2 'roundtrip: docker unavailable — cannot verify', no container ops", async () => {
  const ctx = makeCtx([SPEC]);
  const exec: DockerExec = () => {
    throw new EngineMissingError("docker not installed");
  };
  const code = await runRoundtripCore(ctx, { fetcher: stubFetcher(tgz), exec });
  assert.equal(code, EXIT_ERROR);
  assert.deepEqual(ctx.err, ["roundtrip: docker unavailable — cannot verify"]);
  assert.deepEqual(ctx.out, []);
});

test("run() dispatches roundtrip with its positional (registry seam) + bad spec is exit 2 pre-docker", async () => {
  const out: string[] = [];
  const err: string[] = [];
  const code = await run(["roundtrip", "docker:nginx@1.0"], (l) => out.push(l), (l) => err.push(l));
  assert.equal(code, EXIT_ERROR);
  assert.match(err.join("\n"), /unknown ecosystem/);

  const code2 = await run(["roundtrip"], (l) => void l, (l) => void l);
  assert.equal(code2, EXIT_ERROR);
});

test("roundtrip path never imports the ledger or the check pipeline (zero-side-effect grep guard)", () => {
  const hits = spawnSync("grep", ["-rEn", 'from "[^"]*(ledger/|/check\\.ts)', "src/roundtrip", "src/commands/roundtrip.ts"], {
    cwd: join(import.meta.dirname, ".."),
    encoding: "utf8",
  });
  assert.equal(hits.stdout.trim(), "");
});
