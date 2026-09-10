// provenance: border-inspect-roadmap.md W2.2 — `border roundtrip` mints the ledger proof.
//
// The check-side valve is fail-closed-by-absence; THIS command is the only
// writer of the fact it consumes. Doctrine pins of this suite: recording is
// DEFAULT ON (the record is the feature's whole point — an unrecorded roundtrip
// is invisible to the gate), opt-out is --no-record; clean AND residue runs are
// BOTH recorded (the FACT is the record, not the verdict); the record leg NEVER
// changes the run's exit code and NEVER touches stdout when --json is on; a run
// outside a border repo warns loudly that the proof was NOT recorded — it does
// not silently pretend a record exists.
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";

import { run } from "../src/cli.ts";
import { EXIT_BLOCKED, EXIT_ERROR, EXIT_PASS } from "../src/cli/exit.ts";
import type { Ctx, CommandHandler, Flags, Subcommand } from "../src/cli/types.ts";
import { ledgerPath, readLedger } from "../src/ledger.ts";
import { handlers } from "../src/commands/index.ts";
import type { Report } from "../src/findings.ts";
import type { ScanFetcher, ScanResponse } from "../src/scan/fetch.ts";
import { sha256Hex } from "../src/scan/fetch.ts";
import { runRoundtripCore, type DockerExec, type ExecResult } from "../src/roundtrip/orchestrate.ts";
import { requireGitleaks } from "./helpers/require-engines.ts";
import { gitInit, removeDir } from "./helpers/fixtures.ts";

requireGitleaks();

const roots: string[] = [];
after(() => {
  for (const d of roots) removeDir(d);
});

const tgz = Buffer.from("fake-tgz-bytes");

function repoFixture(): string {
  const dir = mkdtempSync(join(tmpdir(), "w22-rec-"));
  gitInit(dir);
  writeFileSync(
    join(dir, "border.yaml"),
    [
      "version: 1",
      "targets:",
      "  git:",
      "    remotes:",
      "      - name: origin",
      "        url: origin.example:widgets.git",
      "rules:",
      "  authors:",
      "    emails:",
      "      - wiki@sumteclab.com",
      "    names:",
      "      - Wiki.js",
      "  hosts: []",
      "  ips: []",
      "  pathPatterns: []",
      "",
    ].join("\n"),
  );
  roots.push(dir);
  return dir;
}

function makeCtx(cwd: string, positionals: readonly string[], flags: Partial<Flags> = {}): Ctx & { out: string[]; err: string[] } {
  const out: string[] = [];
  const err: string[] = [];
  const base: Flags = { force: false, yes: false, llm: false, json: false, ...flags };
  return {
    out,
    err,
    command: "roundtrip",
    flags: base,
    positionals,
    cwd,
    env: { ...process.env },
    stdout: (line) => out.push(line),
    stderr: (line) => err.push(line),
    handlers,
  };
}

function stubFetcher(): ScanFetcher {
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
const man = (...lines: readonly string[]): string => lines.join("\n") + "\n";
const H1 = "a".repeat(64);
const PRISTINE = [F("/etc/resolv.conf", H1), F("/root/.bashrc", H1)].sort();
const INSTALLED = [...PRISTINE, F("/usr/local/lib/node_modules/rt-fake/index.js", "c".repeat(64))].sort();

function fakeExec(manifests: readonly string[]): DockerExec {
  let idx = 0;
  return (args, _timeoutMs): ExecResult => {
    const joined = args.join(" ");
    if (args[0] === "--version") return { status: 0, stdout: "Docker version 27.0.0, build fake", stderr: "" };
    if (args[0] === "run") return { status: 0, stdout: "deadbeef\n", stderr: "" };
    if (args[0] === "cp" || args[0] === "rm") return { status: 0, stdout: "", stderr: "" };
    if (args[0] === "exec") {
      const body = args.slice(2).join(" ");
      if (body.includes("find / -xdev")) return { status: 0, stdout: manifests[idx++] ?? "", stderr: "" };
      if (body.includes("npm install")) return { status: 0, stdout: "added 1 package", stderr: "" };
      if (body.includes("uninstall")) return { status: 0, stdout: "", stderr: "" };
    }
    throw new Error(`fakeExec: unmatched docker argv: ${joined}`);
  };
}

const CLEAN_RUN = [man(...PRISTINE), man(...INSTALLED), man(...PRISTINE)];

test("W2.2-record: default ON — a clean roundtrip appends the t:\"roundtrip\" fact keyed by artifact sha256", async () => {
  const dir = repoFixture();
  const ctx = makeCtx(dir, ["rt-fake@1.0.0"]);
  const code = await runRoundtripCore(ctx, { fetcher: stubFetcher(), exec: fakeExec(CLEAN_RUN) });
  assert.equal(code, EXIT_PASS);
  const { records, warnings } = readLedger(dir);
  assert.deepEqual(warnings, []);
  const rt = records.filter((r) => r.t === "roundtrip");
  assert.equal(rt.length, 1, "recording is DEFAULT — a bare `border roundtrip` is what mints the gate's proof");
  const rec = rt[0];
  assert.ok(rec?.t === "roundtrip");
  assert.equal(rec.artifactSha256, sha256Hex(tgz), "the valve's key: sha256 of the exact artifact bytes");
  assert.equal(rec.verdict, "clean");
  assert.equal(rec.rows, 0);
  assert.match(rec.rulesHash, /^[0-9a-f]{64}$/, "check computes the SAME rulesHash → freshness = equality");
  assert.ok(!Number.isNaN(Date.parse(rec.ts)));
  assert.ok(ctx.err.some((l) => /recorded/i.test(l)), "the mint is announced on stderr (stdout stays pure under --json)");
});

test("W2.2-record: a residue run is recorded too — the FACT is the record, not the verdict", async () => {
  const dir = repoFixture();
  const ctx = makeCtx(dir, ["rt-fake@1.0.0"]);
  const leaked = [...PRISTINE, F("/root/.bashrc", "b".repeat(64))];
  const code = await runRoundtripCore(ctx, {
    fetcher: stubFetcher(),
    exec: fakeExec([man(...PRISTINE), man(...INSTALLED), man(...leaked)]),
  });
  assert.equal(code, EXIT_BLOCKED, "the residue verdict still blocks the roundtrip itself");
  const rt = readLedger(dir).records.filter((r) => r.t === "roundtrip");
  assert.equal(rt.length, 1);
  assert.ok(rt[0]?.t === "roundtrip");
  assert.equal(rt[0].verdict, "residue");
  assert.ok(rt[0].rows > 0);
});

test("W2.2-record: --no-record opts out — the ledger is not even created", async () => {
  const dir = repoFixture();
  const ctx = makeCtx(dir, ["rt-fake@1.0.0"], { record: false });
  const code = await runRoundtripCore(ctx, { fetcher: stubFetcher(), exec: fakeExec(CLEAN_RUN) });
  assert.equal(code, EXIT_PASS);
  assert.equal(existsSync(ledgerPath(dir)), false, "opt-out writes NOTHING — no line, no empty file");
  assert.ok(!ctx.err.some((l) => /recorded/i.test(l)), "and claims nothing on stderr");
});

test("W2.2-record: outside a border repo the proof is NOT recorded and the run says so loudly (exit code untouched)", async () => {
  const ctx = makeCtx(tmpdir(), ["rt-fake@1.0.0"]);
  const code = await runRoundtripCore(ctx, { fetcher: stubFetcher(), exec: fakeExec(CLEAN_RUN) });
  assert.equal(code, EXIT_PASS, "the roundtrip verdict is honest on its own legs; the record leg is additive");
  assert.ok(ctx.err.some((l) => /NOT recorded/i.test(l)), "silence here would fake a proof that does not exist");
});

test("W2.2-record: --json stdout stays the pure report — record notices ride stderr only", async () => {
  const dir = repoFixture();
  const ctx = makeCtx(dir, ["rt-fake@1.0.0"], { json: true });
  const code = await runRoundtripCore(ctx, { fetcher: stubFetcher(), exec: fakeExec(CLEAN_RUN) });
  assert.equal(code, EXIT_PASS);
  assert.equal(ctx.out.length, 1);
  const report = JSON.parse(ctx.out[0] as string) as Report;
  assert.equal(report.verdict, "PASS");
  assert.ok(readLedger(dir).records.some((r) => r.t === "roundtrip"));
});

test("W2.2-cli: --record / --no-record parse into Flags.record (both together is an argument error)", async () => {
  const seen: Array<Ctx["flags"]> = [];
  const cap: CommandHandler = (ctx) => {
    seen.push(ctx.flags);
    return EXIT_PASS;
  };
  const registry = Object.fromEntries(
    (["check", "push", "status", "llm-request", "llm-ingest", "scan", "roundtrip"] as Subcommand[]).map((c) => [c, cap]),
  ) as Record<Subcommand, CommandHandler>;
  const call = async (argv: string[]): Promise<number> =>
    (await run(argv, () => {}, () => {}, { cwd: process.cwd(), env: { ...process.env }, handlers: registry })) as number;

  seen.length = 0;
  assert.equal(await call(["roundtrip", "x@1.0.0", "--no-record"]), EXIT_PASS);
  assert.equal(seen[0]?.record, false);
  assert.equal(await call(["roundtrip", "x@1.0.0", "--record"]), EXIT_PASS);
  assert.equal(seen[1]?.record, true);
  assert.equal(await call(["roundtrip", "x@1.0.0"]), EXIT_PASS);
  assert.equal(seen[2]?.record, undefined, "unset means the command's default (ON) applies — parser stays silent");
  const errs: string[] = [];
  const bothCode = (await run(["roundtrip", "x@1.0.0", "--record", "--no-record"], () => {}, (l) => errs.push(l), { handlers: registry })) as number;
  assert.equal(bothCode, EXIT_ERROR);
  assert.ok(errs.some((l) => /border:/.test(l)) && seen.length === 3, "contradictory pair is exit 2 with one stderr line, the handler never runs");
});
