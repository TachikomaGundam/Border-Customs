// provenance: border-inspect-roadmap.md W2.4(a) — G-CALIB pypi lane (target-only diff).
//
// The W2.3 founding run graded a real pypi package at 2211 residue rows of which
// 2210 were pip's left-behind transitive-dep files and exactly 1 was a GENUINE
// orphan dir (/usr/local/share/aihr). The dep-storm drowned the signal. The valve
// here: resolve the dependency closure BEFORE install (`pip install --dry-run
// --report` in a throwaway resolver container — the measurement container's m1
// baseline must stay pristine: running the dry-run inside it would let a
// setup.py-planting sdist poison the baseline, cf. the e2e rt-pypi-plant leg),
// then at m3 ask the MEASUREMENT container which surviving paths a still-installed
// closure dist still accounts for (dist-info walk + RECORD, site-packages subtree
// only). Claimed ADDED rows demote to LOW `residue-roundtrip-dep-owned`
// (non-blocking, owner named in the message); everything else keeps W2.1 grades
// byte-for-byte. Fail-closed discipline: closure resolution failure ⇒ typed error
// ⇒ exit 2 (cannot-verify ≠ clean); ambiguous/missing attribution ⇒ stays HIGH
// (over-report tolerated, silent-clean is not). The npm/cargo/gem lanes are
// pypi-gated off: closure=null ⇒ zero new docker legs, classifier unchanged.
import assert from "node:assert/strict";
import { tmpdir } from "node:os";
import { test } from "node:test";

import { isBlocking } from "../src/findings.ts";
import type { Ctx, Flags } from "../src/cli/types.ts";
import { handlers } from "../src/commands/index.ts";
import { EngineRunError } from "../src/engines/support.ts";
import type { ScanFetcher, ScanResponse } from "../src/scan/fetch.ts";
import { pypiMetadataUrl } from "../src/scan/fetch.ts";
import { EXIT_BLOCKED, EXIT_PASS } from "../src/cli/exit.ts";
import { RT_DEP_RULE, buildAttribution, normalizePipName, ownerOf, parsePipReport } from "../src/roundtrip/calibrate.ts";
import { classifyResidue, diffManifests, parseManifest, RT_MODIFY_RULE, RT_PERSIST_RULE, RT_RESIDUE_RULE } from "../src/roundtrip/manifest.ts";
import { runRoundtripCore, type DockerExec, type ExecResult } from "../src/roundtrip/orchestrate.ts";

// ---------------------------------------------------------------- fixtures (closed tables)

const SP = "/usr/local/lib/python3.12/site-packages";
const H = (c: string): string => c.repeat(64);

const F = (p: string, d: string): string => `F\t${p}\t${d}`;
const D = (p: string): string => `D\t${p}\t-`;
const man = (...lines: readonly string[]): string => lines.join("\n") + "\n";

const PRISTINE = [D("/"), D("/etc"), D("/usr"), D("/usr/local"), F("/etc/resolv.conf", H("a")), F("/root/.bashrc", H("b"))].sort();

/** jupyter-core's own files — uninstall removes them; survivors are GENUINE orphans. */
const TARGET_INSTALLED = [D(`${SP}/jupyter_core`), F(`${SP}/jupyter_core/__init__.py`, H("c")), D(`${SP}/jupyter_core-5.8.1.dist-info`), F(`${SP}/jupyter_core-5.8.1.dist-info/RECORD`, H("d"))].sort();

/** The dep storm: still-installed closure dists' files, exactly what pip leaves behind. */
const DEP_ROWS = [
  D(`${SP}/traitlets`),
  F(`${SP}/traitlets/__init__.py`, H("e")),
  D(`${SP}/traitlets/config`),
  F(`${SP}/traitlets/config/base.py`, H("f")),
  D(`${SP}/traitlets-5.16.1.dist-info`),
  F(`${SP}/traitlets-5.16.1.dist-info/METADATA`, H("1")),
  F(`${SP}/traitlets-5.16.1.dist-info/RECORD`, H("2")),
  D(`${SP}/platformdirs`),
  F(`${SP}/platformdirs/api.py`, H("3")),
  D(`${SP}/platformdirs-4.11.8.dist-info`),
  F(`${SP}/platformdirs-4.11.8.dist-info/METADATA`, H("4")),
].sort();

/** Rows the in-container claim scanner emits: one canonical claimant meta
 *  (`@\towner\tnorm\tver\tdi\tdirName\tdirVer`) per honored dist-info, then its
 *  claim lines (owner\tpath TSV). platformdirs' RECORD is deliberately ABSENT
 *  from the claims — the test-(d) shape: a closure dist whose RECORD cannot be
 *  read claims only its dist-info subtree, so its package files stay blocking. */
const CLAIM_ROWS = [
  `@\ttraitlets==5.16.1\ttraitlets\t5.16.1\t${SP}/traitlets-5.16.1.dist-info\ttraitlets\t5.16.1`,
  `traitlets==5.16.1\t${SP}/traitlets-5.16.1.dist-info`,
  `traitlets==5.16.1\t${SP}/traitlets-5.16.1.dist-info/METADATA`,
  `traitlets==5.16.1\t${SP}/traitlets-5.16.1.dist-info/RECORD`,
  `traitlets==5.16.1\t${SP}/traitlets/__init__.py`,
  `traitlets==5.16.1\t${SP}/traitlets/config/base.py`,
  `@\tplatformdirs==4.11.8\tplatformdirs\t4.11.8\t${SP}/platformdirs-4.11.8.dist-info\tplatformdirs\t4.11.8`,
  `platformdirs==4.11.8\t${SP}/platformdirs-4.11.8.dist-info`,
  `platformdirs==4.11.8\t${SP}/platformdirs-4.11.8.dist-info/METADATA`,
].join("\n") + "\n";

/** Every DEP_ROWS path claimed (platformdirs RECORD present as a normal entry). */
const CLAIM_ROWS_FULL = CLAIM_ROWS + `platformdirs==4.11.8\t${SP}/platformdirs/api.py\n`;

/** Genuine residue the valve must NEVER demote. */
const ORPHAN_ROWS = [
  D("/usr/local/share/aihr"), // the W2.3 founding-run signal: ownerless dir outside any RECORD
  F("/usr/local/bin/rt-plant", H("5")),
  F(`${SP}/jupyter_core/evil.py`, H("6")), // target's own survivor — its dist-info is gone
].sort();

const CLOSURE_REPORT = JSON.stringify({
  version: 1,
  install: [
    { download_info: { url: "file:///root/p.tar.gz" }, metadata: { metadata_version: "2.4", name: "jupyter_core", version: "5.8.1" } },
    { download_info: { url: "https://files.pythonhosted.org/packages/ad/66/traitlets-5.16.1-py3-none-any.whl" }, metadata: { metadata_version: "2.4", name: "traitlets", version: "5.16.1" } },
    { download_info: { url: "https://files.pythonhosted.org/packages/f4/e1/platformdirs-4.11.8-py3-none-any.whl" }, metadata: { metadata_version: "2.4", name: "platformdirs", version: "4.11.8" } },
  ],
});

// ---------------------------------------------------------------- fake docker (pypi-aware)

type Script = {
  manifests: readonly string[]; // m1, m2, m3 for the MEASUREMENT container
  closureReport?: string; // stdout of the resolver's `cat` leg
  dryRunStatus?: number;
  claimRows?: string; // stdout of the m3-time claim scan
  claimStatus?: number;
};

type Recorder = { calls: string[][]; timeouts: number[]; rmCalls: number; runNames: string[] };

function fakeExec(script: Script): { exec: DockerExec; rec: Recorder } {
  const rec: Recorder = { calls: [], timeouts: [], rmCalls: 0, runNames: [] };
  let snapshotIdx = 0;
  const exec: DockerExec = (args, timeoutMs): ExecResult => {
    rec.calls.push([...args]);
    rec.timeouts.push(timeoutMs);
    const joined = args.join(" ");
    if (args[0] === "--version") return { status: 0, stdout: "Docker version 27.0.0, build fake", stderr: "" };
    if (args[0] === "run") {
      rec.runNames.push(String(args[3]));
      return { status: 0, stdout: "deadbeef\n", stderr: "" };
    }
    if (args[0] === "cp") return { status: 0, stdout: "", stderr: "" };
    if (args[0] === "rm") {
      rec.rmCalls += 1;
      return { status: 0, stdout: "", stderr: "" };
    }
    if (args[0] === "exec") {
      // Order matters: the dry-run leg ALSO contains "pip install"; the specific
      // matchers must be checked first or they would be swallowed by it.
      if (joined.includes("--dry-run --report")) return { status: script.dryRunStatus ?? 0, stdout: "", stderr: script.dryRunStatus ? "resolution exploded" : "" };
      if (joined.includes("cat /dev/shm/rt-report.json")) {
        if (script.closureReport === undefined) return { status: 1, stdout: "", stderr: "cat: no such file" };
        return { status: 0, stdout: script.closureReport, stderr: "" };
      }
      if (joined.includes("python3")) return { status: script.claimStatus ?? 0, stdout: script.claimRows ?? "", stderr: script.claimStatus ? "scan died" : "" };
      if (joined.includes("find / -xdev")) return { status: 0, stdout: script.manifests[snapshotIdx++] ?? "", stderr: "" };
      if (joined.includes("pip install") || joined.includes("npm install")) return { status: 0, stdout: "Successfully installed", stderr: "" };
      if (joined.includes("uninstall")) return { status: 0, stdout: "", stderr: "" };
    }
    throw new Error(`fakeExec: unmatched docker argv: ${joined}`);
  };
  return { exec, rec };
}

function makeCtx(positionals: readonly string[], flags: Partial<Flags> = {}): Ctx & { out: string[]; err: string[] } {
  const out: string[] = [];
  const err: string[] = [];
  return {
    out,
    err,
    command: "roundtrip",
    flags: { force: false, yes: false, llm: false, json: false, record: false, ...flags },
    positionals,
    cwd: tmpdir(),
    env: { ...process.env },
    stdout: (line) => out.push(line),
    stderr: (line) => err.push(line),
    handlers,
  };
}

/** pypi-shaped fetcher: metadata JSON + sdist bytes (the lane's accepted form). */
function pypiFetcher(name: string, version: string): ScanFetcher {
  const meta = pypiMetadataUrl(name, version);
  const dl = `https://files.pythonhosted.org/packages/source/${name[0]}/${name}/${name.replace(/-/g, "_")}-${version}.tar.gz`;
  return async (url: string): Promise<ScanResponse> => {
    const body =
      url === meta
        ? new TextEncoder().encode(JSON.stringify({ urls: [{ packagetype: "sdist", url: dl, filename: "pkg.tar.gz" }] }))
        : url === dl
          ? new TextEncoder().encode("fake-sdist-bytes")
          : (() => {
              throw new Error(`pypiFetcher got unscripted URL: ${url}`);
            })();
    return { status: 200, contentLength: body.byteLength, async *chunks() { yield body; } };
  };
}

const PYPI_SPEC = "pypi:jupyter-core@5.8.1";

async function core(script: Script, spec = PYPI_SPEC) {
  const ctx = makeCtx([spec]);
  const { exec, rec } = fakeExec(script);
  let code = -1;
  let thrown: unknown = null;
  try {
    code = await runRoundtripCore(ctx, { fetcher: pypiFetcher("jupyter-core", "5.8.1"), exec });
  } catch (err) {
    thrown = err;
  }
  return { code, ctx, rec, thrown };
}

const M_STORM_ORPHAN = [
  man(...PRISTINE),
  man(...PRISTINE, ...TARGET_INSTALLED, ...DEP_ROWS),
  man(...PRISTINE, ...DEP_ROWS, ...ORPHAN_ROWS),
];

// ---------------------------------------------------------------- parsePipReport

test("parsePipReport: v1 report maps PEP503-normalized names to versions (target + deps)", () => {
  const closure = parsePipReport(CLOSURE_REPORT);
  assert.deepEqual(
    [...closure.entries()].sort(),
    [
      ["jupyter-core", "5.8.1"],
      ["platformdirs", "4.11.8"],
      ["traitlets", "5.16.1"],
    ],
  );
  assert.equal(normalizePipName("Jupyter_Core"), "jupyter-core");
  assert.equal(normalizePipName("zope.interface"), "zope-interface");
  assert.equal(normalizePipName("Twisted.Web"), "twisted-web");
});

test('parsePipReport: version spelled as string "1" is accepted (live pip 25.0.1 emits "version": "1", found in-container 2026-09-11)', () => {
  const stringly = CLOSURE_REPORT.replace('"version":1', '"version":"1"');
  assert.notEqual(stringly, CLOSURE_REPORT, "fixture must actually carry the string spelling");
  const closure = parsePipReport(stringly);
  assert.deepEqual([...closure.keys()].sort(), ["jupyter-core", "platformdirs", "traitlets"]);
});

test("parsePipReport fail-closed (cannot-verify ≠ clean): garbage / wrong version / empty install / nameless entry / non-array ⇒ typed error", () => {
  const bad = [
    "not json at all",
    JSON.stringify({ version: 99, install: [{ metadata: { name: "x", version: "1" } }] }),
    JSON.stringify({ version: "99", install: [{ metadata: { name: "x", version: "1" } }] }),
    JSON.stringify({ version: 1, install: [] }),
    JSON.stringify({ version: 1, install: [{ metadata: { version: "1.0" } }] }),
    JSON.stringify({ version: 1, install: { metadata: { name: "x", version: "1" } } }),
    JSON.stringify({ install: [{ metadata: { name: "x", version: "1" } }] }),
  ];
  for (const text of bad) {
    assert.throws(() => parsePipReport(text), (err: unknown) => err instanceof EngineRunError && /cannot verify/i.test((err as Error).message), `must reject: ${text.slice(0, 40)}`);
  }
});

// ---------------------------------------------------------------- attribution model

test("buildAttribution/ownerOf: exact file+dir claims, ancestor dirs for package trees, garbage & relative paths ignored", () => {
  const attr = buildAttribution(CLAIM_ROWS_FULL);
  assert.equal(ownerOf({ kind: "F", path: `${SP}/traitlets/__init__.py` }, attr), "traitlets==5.16.1");
  assert.equal(ownerOf({ kind: "D", path: `${SP}/traitlets-5.16.1.dist-info` }, attr), "traitlets==5.16.1"); // exact dist-info dir claim
  assert.equal(ownerOf({ kind: "D", path: `${SP}/traitlets` }, attr), "traitlets==5.16.1"); // ancestor of a RECORD file
  assert.equal(ownerOf({ kind: "D", path: `${SP}/traitlets/config` }, attr), "traitlets==5.16.1");
  assert.equal(ownerOf({ kind: "F", path: "/usr/local/share/aihr/config.json" }, attr), undefined);
  assert.equal(ownerOf({ kind: "D", path: "/usr/local/share/aihr" }, attr), undefined);
  assert.equal(ownerOf({ kind: "F", path: "/etc/passwd" }, attr), undefined);
  // malformed rows claim nothing (fail-closed): missing tab, relative path, empty line
  const junk = buildAttribution(`${SP}/no-owner-line\nrelative/path\towner\n\nx==1\trelative/p\n`);
  assert.equal(ownerOf({ kind: "F", path: `${SP}/no-owner-line` }, junk), undefined);
  assert.equal(ownerOf({ kind: "F", path: "relative/p" }, junk), undefined);
});

test("ambiguous attribution (two owners claim one path) stays BLOCKING — over-report tolerated, silent-clean is not", () => {
  const attr = buildAttribution([`traitlets==5.16.1\t${SP}/shared/mod.py`, `platformdirs==4.11.8\t${SP}/shared/mod.py`].join("\n"));
  assert.equal(ownerOf({ kind: "F", path: `${SP}/shared/mod.py` }, attr), undefined);
  assert.equal(ownerOf({ kind: "D", path: `${SP}/shared` }, attr), undefined);
});

// ---------------------------------------------------------------- classifier (unit level)

test("classifyResidue: claimed ADDED rows ⇒ LOW residue-roundtrip-dep-owned naming the owner; unclaimed keep W2.1 grades; npm-shape call unchanged", () => {
  const diff = diffManifests(parseManifest(man(...PRISTINE)), parseManifest(man(...PRISTINE, ...DEP_ROWS, ...ORPHAN_ROWS)));
  const withAttr = classifyResidue(PYPI_SPEC, diff, buildAttribution(CLAIM_ROWS));
  const lows = withAttr.filter((f) => f.rule === RT_DEP_RULE);
  const highs = withAttr.filter((f) => f.rule === RT_RESIDUE_RULE);
  // 7 exact claims + the two ancestor dirs (traitlets/, traitlets/config/) that
  // the RECORD files sit under — dirs under a claimed subtree demote too.
  assert.equal(lows.length, 9);
  assert.ok(lows.every((f) => f.severity === "LOW" && !isBlocking(f.severity) && f.engine === "roundtrip"));
  assert.ok(lows.some((f) => f.message.includes("traitlets==5.16.1")), "message must name the owning dep");
  // test (b): the genuine orphan dir survives demotion at HIGH, exactly as W2.1 graded it
  const aihr = highs.find((f) => f.path === "/usr/local/share/aihr");
  assert.ok(aihr && aihr.severity === "HIGH");
  // test (d) shape: platformdirs' RECORD-less package files stay blocking
  assert.ok(highs.some((f) => f.path === `${SP}/platformdirs/api.py`));
  assert.ok(highs.some((f) => f.path === `${SP}/jupyter_core/evil.py`), "target's own survivor is never dep-owned");
  // without attribution the classifier is byte-for-byte the W2.1 machine (npm/cargo/gem lanes)
  const plain = classifyResidue("npm:rt-fake@1.0.0", diff);
  assert.equal(plain.length, DEP_ROWS.length + ORPHAN_ROWS.length);
  assert.ok(plain.every((f) => f.severity === "HIGH" && f.rule === RT_RESIDUE_RULE));
});

test("demotion applies to ADDED only: a MODIFIED persistence surface claimed by a dep stays CRITICAL", () => {
  const diff = diffManifests(parseManifest(man(F("/etc/profile", H("a")))), parseManifest(man(F("/etc/profile", H("b")))));
  const attr = buildAttribution(`traitlets==5.16.1\t/etc/profile\n`);
  const findings = classifyResidue(PYPI_SPEC, diff, attr);
  assert.equal(findings[0]?.rule, RT_PERSIST_RULE);
  assert.equal(findings[0]?.severity, "CRITICAL");
  const mod = diffManifests(parseManifest(man(F(`${SP}/traitlets/__init__.py`, H("a")))), parseManifest(man(F(`${SP}/traitlets/__init__.py`, H("b")))));
  assert.equal(classifyResidue(PYPI_SPEC, mod, buildAttribution(CLAIM_ROWS))[0]?.rule, RT_MODIFY_RULE);
});

// ---------------------------------------------------------------- pipeline (fake docker, pypi lane)

test("pypi lane opens a SEPARATE resolver container for the dry-run and removes it — the measurement container's m1 stays pristine", async () => {
  const { code, rec } = await core({ manifests: M_STORM_ORPHAN, closureReport: CLOSURE_REPORT, claimRows: CLAIM_ROWS });
  assert.equal(code, EXIT_BLOCKED);
  assert.equal(rec.runNames.length, 2, "exactly two containers: resolver + measurement");
  assert.notEqual(rec.runNames[0], rec.runNames[1], "resolver is its own container (setup.py side-effects cannot poison m1)");
  assert.ok(rec.runNames.every((n) => /^rt-[0-9a-f]{8}-[0-9a-f]{6}$/.test(n)));
  assert.equal(rec.rmCalls, 2, "trap-cleanup on both containers");
  const dryRun = rec.calls.find((c) => c.join(" ").includes("--dry-run --report"));
  assert.ok(dryRun, "the dry-run leg ran");
  assert.ok(dryRun?.includes("/root/p.tar.gz"), "resolution runs against the copied artifact path");
  assert.ok(dryRun?.includes("pip"), JSON.stringify(dryRun));
  // the resolver container only ever sees cp/dry-run/cat — never the real install/snapshot
  const resolverId = dryRun?.[1];
  assert.ok(!rec.calls.some((c) => c[2] === resolverId && (c.join(" ").includes("find / -xdev") || (c.join(" ").includes("pip install") && !c.join(" ").includes("--dry-run")))));
});

test("dep-storm + genuine orphan (the W2.3 founding run shape): storm demoted LOW, aihr-style orphan keeps HIGH ⇒ exit 1", async () => {
  const { code, ctx } = await core({ manifests: M_STORM_ORPHAN, closureReport: CLOSURE_REPORT, claimRows: CLAIM_ROWS });
  assert.equal(code, EXIT_BLOCKED);
  const blocking = ctx.out.filter((l) => /^HIGH roundtrip-residue-file /.test(l));
  // unclaimed DEP rows (platformdirs D + api.py F — RECORD absent) + 3 genuine orphans = 5 HIGH
  assert.equal(blocking.length, 5, ctx.out.join("\n"));
  assert.ok(blocking.some((l) => l.includes("/usr/local/share/aihr")));
  assert.ok(blocking.some((l) => l.includes(`${SP}/platformdirs/api.py`)), "RECORD-less dist files stay blocking");
  assert.ok(ctx.out.filter((l) => /^LOW residue-roundtrip-dep-owned /.test(l)).length === 9);
  assert.ok(ctx.out.some((l) => l.includes("traitlets==5.16.1")));
});

test("storm fully pip-accountable ⇒ exit 0, 0 blocking, LOW rows visible + demotion note", async () => {
  const m3 = man(...PRISTINE, ...DEP_ROWS); // uninstall removed the target cleanly; only dep files remain
  const { code, ctx, rec } = await core({ manifests: [man(...PRISTINE), man(...PRISTINE, ...TARGET_INSTALLED, ...DEP_ROWS), m3], closureReport: CLOSURE_REPORT, claimRows: CLAIM_ROWS_FULL });
  assert.equal(code, EXIT_PASS);
  assert.ok(!ctx.out.some((l) => /^HIGH |^CRITICAL /.test(l)));
  assert.ok(ctx.out.some((l) => /^LOW residue-roundtrip-dep-owned /.test(l)));
  assert.ok(ctx.out.some((l) => /dep-owned|attributed/i.test(l) && !l.startsWith("  ")), `demotion must be called out in the summary, got: ${ctx.out.join("\n")}`);
  // install-delta guard still fires on this lane (delta here is 15 rows, not 0)
  assert.ok(ctx.out.some((l) => l.includes("install-delta")));
  assert.equal(rec.rmCalls, 2);
});

test("test (c): unparseable closure report ⇒ typed EngineRunError, exit-2 path, resolver removed, measurement container NEVER starts", async () => {
  for (const report of [undefined, "}{ not json", JSON.stringify({ version: 1, install: [] })]) {
    const { code, rec, thrown } = await core({ manifests: M_STORM_ORPHAN, ...(report === undefined ? {} : { closureReport: report }) });
    assert.ok(thrown instanceof EngineRunError, `expected typed error for report ${String(report)?.slice(0, 20)}`);
    assert.match((thrown as Error).message, /closure|report/i);
    assert.equal(code, -1, "runRoundtripCore throws; the CLI maps EngineRunError to exit 2");
    assert.equal(rec.runNames.length, 1, "only the resolver container was ever created");
    assert.equal(rec.rmCalls, 1, "resolver cleaned in finally even on the failure path");
  }
});

test("dry-run exec failure + closure missing the target ⇒ typed error (cannot-verify ≠ clean)", async () => {
  const { thrown } = await core({ manifests: M_STORM_ORPHAN, closureReport: CLOSURE_REPORT, dryRunStatus: 2 });
  assert.ok(thrown instanceof EngineRunError && /dry-run|resolution/i.test(thrown.message), String(thrown));
  const other = JSON.stringify({ version: 1, install: [{ metadata: { name: "traitlets", version: "5.16.1" } }] });
  const r2 = await core({ manifests: M_STORM_ORPHAN, closureReport: other });
  assert.ok(r2.thrown instanceof EngineRunError && /target/i.test((r2.thrown as Error).message), "a closure without the target contradicts the dry-run's own contract");
});

test("claim-scan failure degrades to today's full-blocking behavior (over-report), with a stderr note", async () => {
  const { code, ctx } = await core({ manifests: M_STORM_ORPHAN, closureReport: CLOSURE_REPORT, claimStatus: 1 });
  assert.equal(code, EXIT_BLOCKED);
  assert.ok(!ctx.out.some((l) => /^LOW /.test(l)), "nothing demotes when the scan dies");
  assert.ok(ctx.out.some((l) => /^HIGH roundtrip-residue-file .*traitlets/i.test(l)));
  assert.ok(ctx.err.some((l) => /attribut|claim/i.test(l)), "the degradation is announced, never silent");
});

test("pypi npm-spec sanity — non-pypi lanes spawn ZERO closure/scan legs and keep byte-identical grades", async () => {
  const ctx = makeCtx(["npm:rt-fake@1.0.0"]);
  const { exec, rec } = fakeExec({ manifests: [man(...PRISTINE), man(...PRISTINE, ...TARGET_INSTALLED), man(...PRISTINE, ...DEP_ROWS, ...ORPHAN_ROWS)] });
  const code = await runRoundtripCore(ctx, {
    fetcher: (async (url: string): Promise<ScanResponse> => {
      const body =
        url === "https://registry.npmjs.org/rt-fake/1.0.0"
          ? new TextEncoder().encode(JSON.stringify({ name: "rt-fake", version: "1.0.0", dist: { tarball: "https://registry.npmjs.org/rt-fake/-/rt-fake-1.0.0.tgz" } }))
          : new TextEncoder().encode("fake-tgz");
      return { status: 200, contentLength: body.byteLength, async *chunks() { yield body; } };
    }) as ScanFetcher,
    exec,
  });
  assert.equal(code, EXIT_BLOCKED);
  assert.equal(rec.runNames.length, 1, "npm lane: no resolver container");
  assert.ok(!rec.calls.some((c) => c.join(" ").includes("--dry-run")), "npm lane never touches pip");
  assert.ok(!rec.calls.some((c) => c.join(" ").includes("python3")), "npm lane never runs the claim scanner");
  assert.ok(!ctx.out.some((l) => /^LOW /.test(l)), "storm rows stay HIGH in the npm lane — demotion is pypi-gated");
  assert.equal(ctx.out.filter((l) => /^HIGH roundtrip-residue-file /.test(l)).length, DEP_ROWS.length + ORPHAN_ROWS.length);
});

test("every new pypi leg carries an explicit timeout (dry-run ≤600s, cat/scan/snapshot ≤120s)", async () => {
  const { rec } = await core({ manifests: M_STORM_ORPHAN, closureReport: CLOSURE_REPORT, claimRows: CLAIM_ROWS });
  for (const [i, c] of rec.calls.entries()) {
    const t = rec.timeouts[i] as number;
    assert.ok(Number.isFinite(t) && t > 0, `leg ${c.join(" ").slice(0, 60)} must carry a timeout`);
    const joined = c.join(" ");
    if (joined.includes("--dry-run")) assert.ok(t <= 600_000);
    else if (joined.includes("find / -xdev") || joined.includes("python3") || joined.includes("cat /dev/shm")) assert.ok(t <= 120_000);
    else assert.ok(t <= 600_000);
  }
});

// ---------------------------------------------------------------- fix-round: shadow dist-info self-certification
// VERIFIER-REPORT-W24-W4 probes.shadow_dist_info_blocker: a surviving fake
// dist-info whose METADATA Name is in the closure (version ignored) used to
// self-certify and launder ARBITRARY residue rows to LOW. Claimant legitimacy
// is now adjudicated TS-side against the resolver report.

const PINS = parsePipReport(CLOSURE_REPORT);
const GUARD = { pins: PINS, target: normalizePipName("jupyter_core") };

function claimedBy(text: string, guard: { pins: ReadonlyMap<string, string>; target: string } | undefined, path: string): string | undefined {
  return ownerOf({ kind: "F", path }, guard === undefined ? buildAttribution(text) : buildAttribution(text, guard));
}

test("shadow claimant for the TARGET name is rejected — its payload rows stay blocking (fix a)", () => {
  const shadow = CLAIM_ROWS + [
    `@\tjupyter-core==9.9\tjupyter-core\t9.9\t${SP}/jupyter_core-9.9.dist-info\tjupyter_core\t9.9`,
    `jupyter-core==9.9\t${SP}/payload/backdoor.py`,
    `jupyter-core==9.9\t${SP}/jupyter_core/__init__.py`,
    `jupyter-core==9.9\t${SP}/jupyter_core-9.9.dist-info`,
  ].join("\n") + "\n";
  assert.equal(claimedBy(shadow, GUARD, `${SP}/payload/backdoor.py`), undefined);
  assert.equal(claimedBy(shadow, GUARD, `${SP}/jupyter_core/__init__.py`), undefined);
  assert.equal(claimedBy(shadow, GUARD, `${SP}/jupyter_core-9.9.dist-info`), undefined);
  assert.equal(claimedBy(shadow, GUARD, `${SP}/traitlets/__init__.py`), "traitlets==5.16.1", "legit claimants unaffected");
});

test("claimant version must EQUAL the resolver pin — Name-in-closure with 'jc==9.9'-style drift rejected (fix b)", () => {
  const text = [
    `@\ttraitlets==9.9\ttraitlets\t9.9\t${SP}/traitlets-9.9.dist-info\ttraitlets\t9.9`,
    `traitlets==9.9\t${SP}/traitlets-9.9.dist-info/METADATA`,
    `traitlets==9.9\t${SP}/traitlets/__init__.py`,
  ].join("\n") + "\n";
  assert.equal(claimedBy(text, GUARD, `${SP}/traitlets/__init__.py`), undefined);
  assert.equal(claimedBy(text, GUARD, `${SP}/traitlets-9.9.dist-info/METADATA`), undefined);
});

test("non-canonical dist-info dir name is rejected (shadow-evil.dist-info impersonating a pinned name)", () => {
  const text = [
    `@\ttraitlets==5.16.1\ttraitlets\t5.16.1\t${SP}/shadow-evil.dist-info\tshadow-evil\t5.16.1`,
    `traitlets==5.16.1\t${SP}/traitlets/__init__.py`,
  ].join("\n") + "\n";
  assert.equal(claimedBy(text, GUARD, `${SP}/traitlets/__init__.py`), undefined);
});

test("duplicate claimants for one closure name are ALL rejected (shadow alongside the real dist-info ⇒ over-report, never launder)", () => {
  const text = CLAIM_ROWS + [
    `@\ttraitlets==5.16.1\ttraitlets\t5.16.1\t${SP}/traitlets-extra-5.16.1.dist-info\ttraitlets\t5.16.1`,
    `traitlets==5.16.1\t${SP}/payload/backdoor.py`,
  ].join("\n") + "\n";
  assert.equal(claimedBy(text, GUARD, `${SP}/payload/backdoor.py`), undefined);
  assert.equal(claimedBy(text, GUARD, `${SP}/traitlets/__init__.py`), undefined);
  assert.equal(claimedBy(text, GUARD, `${SP}/platformdirs-4.11.8.dist-info/METADATA`), "platformdirs==4.11.8", "unrelated claimants unaffected");
});

test("claims outside the claimant's site-packages root stay blocking (/usr/local/bin/backdoor via forged RECORD)", () => {
  const text = CLAIM_ROWS + `traitlets==5.16.1\t/usr/local/bin/backdoor\n`;
  assert.equal(claimedBy(text, GUARD, "/usr/local/bin/backdoor"), undefined);
  assert.equal(claimedBy(text, GUARD, `${SP}/traitlets/__init__.py`), "traitlets==5.16.1");
});

test("claim lines without a claimant meta are rejected under guard; legacy guard-less parse unchanged (byte-compatible)", () => {
  assert.equal(claimedBy(CLAIM_ROWS, GUARD, `${SP}/traitlets/__init__.py`), "traitlets==5.16.1", "benign parity: canonical metas demote exactly as before");
  assert.equal(claimedBy(CLAIM_ROWS, undefined, `${SP}/traitlets/__init__.py`), "traitlets==5.16.1", "guard-less mode ignores meta lines");
  const orphanClaims = CLAIM_ROWS.split("\n").filter((l) => !l.startsWith("@")).join("\n") + "\n";
  assert.equal(claimedBy(orphanClaims, GUARD, `${SP}/traitlets/__init__.py`), undefined, "forged claims w/o meta ⇒ no demotion");
});

test("shadow e2e through the full pipeline: payload row HIGH, dep-storm rows LOW, run still blocks (fix c via classifyResidue)", async () => {
  const shadowClaim = CLAIM_ROWS + [
    `@\tjupyter-core==9.9\tjupyter-core\t9.9\t${SP}/jupyter_core-9.9.dist-info\tjupyter_core\t9.9`,
    `jupyter-core==9.9\t${SP}/payload/backdoor.py`,
  ].join("\n") + "\n";
  const m3 = man(...PRISTINE, ...TARGET_INSTALLED, ...DEP_ROWS, D(`${SP}/payload`), F(`${SP}/payload/backdoor.py`, H("9")), D(`${SP}/jupyter_core-9.9.dist-info`));
  const { code, ctx } = await core({ manifests: [man(...PRISTINE), man(...PRISTINE, ...TARGET_INSTALLED, ...DEP_ROWS), m3], closureReport: CLOSURE_REPORT, claimRows: shadowClaim });
  assert.equal(code, EXIT_BLOCKED, "laundering attempt must still block");
  assert.ok(ctx.out.some((l) => /^HIGH roundtrip-residue-file .*\/payload\/backdoor\.py/.test(l)), `payload stays HIGH:\n${ctx.out.join("\n")}`);
  assert.ok(ctx.out.some((l) => /^LOW residue-roundtrip-dep-owned /.test(l)), "legit dep rows still demote");
});

test("scanner env carries the FULL pin map (name→version dict), not closure keys", async () => {
  const { rec } = await core({ manifests: M_STORM_ORPHAN, closureReport: CLOSURE_REPORT, claimRows: CLAIM_ROWS });
  const scan = rec.calls.find((c) => c.includes("python3"));
  assert.ok(scan !== undefined, "scanner leg present");
  const env = scan?.[2] as string;
  assert.ok(env.startsWith("BORDER_CLOSURE="), env.slice(0, 30));
  assert.deepEqual(JSON.parse(env.slice("BORDER_CLOSURE=".length)), { "jupyter-core": "5.8.1", traitlets: "5.16.1", platformdirs: "4.11.8" });
});
