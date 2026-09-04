// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 14
//
// End-to-end skip-ledger lifecycle through the REAL CLI (real gitleaks, real
// git, real npm): PASS ⇒ SKIP, then EVERY plan AC re-trigger cause, cached-FAIL
// honesty, degraded-never-certifies, corruption tolerance at the CLI seam, and
// the round-1 M8 gitignored-but-packed dist hole closed via repack proof.
// Sub-second SKIP is asserted with a generous 2s budget (shared workstation
// noise; the <1s contract itself is timed literally in the manual QA evidence).
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { after, test } from "node:test";

import { run } from "../src/cli.ts";
import { EXIT_BLOCKED, EXIT_ERROR, EXIT_PASS } from "../src/cli/exit.ts";
import { readLedger, type CheckRecord } from "../src/ledger.ts";
import { requireGitleaks } from "./helpers/require-engines.ts";
import { gitAddCommit, gitInit, makeFixtureDir, randAwsPair, removeDir, writeRel } from "./helpers/fixtures.ts";

requireGitleaks();

const fixtureRoots: string[] = [];
after(() => {
  for (const d of fixtureRoots) removeDir(d);
});

function fixture(name: string): string {
  const root = makeFixtureDir(`ledcli-${name}`);
  fixtureRoots.push(root);
  return root;
}

function borderYaml(remoteUrl = "origin.example:widgets.git", withNpm = false): string {
  return [
    "version: 1",
    "targets:",
    "  git:",
    "    remotes:",
    "      - name: origin",
    `        url: ${remoteUrl}`,
    ...(withNpm ? ["  npm: {}"] : []),
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
  ].join("\n");
}

function checkRepo(name: string): string {
  const dir = fixture(name);
  gitInit(dir);
  writeRel(dir, "border.yaml", borderYaml());
  writeRel(dir, "notes.txt", "clean\n");
  gitAddCommit(dir, "init");
  return dir;
}

type Cli = { readonly code: number; readonly out: readonly string[]; readonly err: readonly string[]; readonly ms: number };

async function cli(dir: string, extra: readonly string[] = [], env?: Record<string, string>): Promise<Cli> {
  const out: string[] = [];
  const err: string[] = [];
  const t0 = performance.now();
  const code = (await run(["check", ...extra], (l) => out.push(l), (l) => err.push(l), {
    cwd: dir,
    ...(env === undefined ? {} : { env: { ...process.env, ...env } }),
  })) as number;
  return { code, out, err, ms: performance.now() - t0 };
}

const SKIP_RE = /^SKIP ([0-9a-f]{8}) — PASS (\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z) report \.border\/runs\/(\S+)\/report\.json$/;
const skipLine = (c: Cli): string | undefined => c.out.find((l) => SKIP_RE.test(l));

function ledger(dir: string): readonly CheckRecord[] {
  return readLedger(dir).records.filter((r): r is CheckRecord => r.t === "check");
}

function nthCheck(dir: string, i: number): CheckRecord {
  const all = ledger(dir);
  const r = all[i] ?? (i < 0 ? all.at(i) : undefined);
  if (r === undefined) throw new Error(`ledger has no check record at index ${String(i)}`);
  return r;
}

function git(dir: string, args: readonly string[]): void {
  const r = spawnSync("git", args, {
    cwd: dir,
    encoding: "utf8",
    env: { ...process.env, GIT_CEILING_DIRECTORIES: join(dir, "..") },
  });
  if (r.status !== 0) throw new Error(`git ${args.join(" ")}: ${r.stderr}`);
}

test("CLI lifecycle: PASS records, SKIPs, and every plan cause re-triggers a full check", { timeout: 120_000 }, async () => {
  const dir = checkRepo("lifecycle");

  const r1 = await cli(dir);
  assert.equal(r1.code, EXIT_PASS, `run1 must pass: ${r1.out.join("\n")} / ${r1.err.join("\n")}`);
  assert.equal(skipLine(r1), undefined, "run1 never prints SKIP");
  const recs1 = ledger(dir);
  assert.equal(recs1.length, 1);
  const rec = nthCheck(dir, 0);
  assert.equal(rec.verdict, "PASS");
  assert.equal(rec.degraded, false);
  assert.equal(rec.llm, false);
  assert.deepEqual([...rec.effectiveTargets], ["git"]);
  assert.match(rec.key, /^[0-9a-f]{64}$/);
  assert.match(rec.head, /^[0-9a-f]{40}$/);
  assert.equal(rec.key8, rec.key.slice(0, 8));
  assert.equal(rec.artifacts, null, "git-only runs carry no artifact digests");
  assert.ok(existsSync(join(dir, rec.reportPath)), `archived report at ${rec.reportPath} must exist`);
  const key1 = rec.key;

  const r2 = await cli(dir);
  assert.equal(r2.code, EXIT_PASS);
  const skip = SKIP_RE.exec(skipLine(r2) ?? "");
  assert.ok(skip !== null, `run2 must print the D6 SKIP line, got: ${r2.out.join(" | ")}`);
  assert.equal(skip[1], rec.key8);
  assert.equal(skip[2], rec.ts, "SKIP provenance cites the CERTIFYING run's timestamp");
  assert.equal(ledger(dir).length, 1, "SKIP appends nothing");
  assert.ok(r2.ms < 2000, `SKIP fast-path must stay sub-second-class, took ${String(Math.round(r2.ms))}ms`);

  // corruption tolerance AT THE CLI: hand-mangle a line, the skip decision survives + warns.
  writeFileSync(join(dir, ".border", "ledger.jsonl"), "!!!torn by an interrupted write\n\n", { flag: "a" });
  const r2b = await cli(dir);
  assert.equal(skipLine(r2b) !== undefined, true, "SKIP still honored around the corrupt line");
  assert.ok(r2b.err.some((l) => l.includes("WARNING") && l.includes("unreadable")), `expected corruption WARNING, got: ${r2b.err.join(" | ")}`);
  assert.equal(ledger(dir).length, 1);

  // --force bypasses the lookup entirely.
  const forced = await cli(dir, ["--force"]);
  assert.equal(skipLine(forced), undefined, "--force never skips");
  assert.equal(ledger(dir).length, 2, "--force re-certifies with a fresh record");
  assert.equal(nthCheck(dir, 1).key, key1);

  // cause 1 (refSet): new tag.
  git(dir, ["tag", "v1.0.0"]);
  assert.equal(skipLine(await cli(dir)), undefined, "refSet change re-checks");

  // cause 2 (head): new commit.
  writeRel(dir, "more.txt", "work\n");
  gitAddCommit(dir, "second");
  assert.equal(skipLine(await cli(dir)), undefined, "HEAD change re-checks");

  // cause 3 (porcelain): dirty tree; and the dirty run itself certifies.
  writeRel(dir, "scratch.tmp", "untracked dirt\n");
  assert.equal(skipLine(await cli(dir)), undefined, "dirty-tree change re-checks");
  rmSync(join(dir, "scratch.tmp"));

  // cause 4 (exposureSet via overlay): second remote in an UNTRACKED overlay —
  // border.yaml bytes AND git state untouched, only effective config moves.
  writeRel(dir, ".border/config.local.yaml", [
    "targets:",
    "  git:",
    "    remotes:",
    "      - name: origin",
    "        url: origin.example:widgets.git",
    "      - name: backup",
    "        url: backup.example:widgets.git",
    "",
  ].join("\n"));
  assert.equal(skipLine(await cli(dir)), undefined, "added remote (overlay) re-checks");
  rmSync(join(dir, ".border", "config.local.yaml"));

  // cause 5 (rulesHash): gitleaks engineVersion bump via PATH shim — same repo state, different engine.
  const shimDir = fixture("gitleaks-shim");
  writeFileSync(
    join(shimDir, "gitleaks"),
    '#!/bin/sh\nif [ "$1" = "--version" ]; then echo "gitleaks version 99.99.99"; exit 0; fi\nexec "$HOME/.local/bin/gitleaks" "$@"\n',
    { mode: 0o755 },
  );
  const shimmed = await cli(dir, [], { PATH: `${shimDir}:${process.env.PATH as string}` });
  assert.equal(skipLine(shimmed), undefined, "engineVersion change re-checks (G21)");
  assert.equal(shimmed.code, EXIT_PASS, "shim forwards the real scan legs");
  assert.ok(shimmed.ms < 15000, `shimmed run must really scan (<15s), took ${String(Math.round(shimmed.ms))}ms`);

  // back to the certified state: the newest record for key1 still holds.
  assert.notEqual(skipLine(await cli(dir)), undefined, "reverting the cause restores the skip");

  // degraded NEVER certifies and NEVER skips: exit 2, no new record.
  const before = ledger(dir).length;
  const deg = await cli(dir, ["--require-engine", "trufflehog"]);
  assert.equal(deg.code, EXIT_ERROR, "degraded probe ⇒ exit 2 regardless of the cached PASS");
  assert.equal(skipLine(deg), undefined, "a degraded lookup never skips");
  assert.equal(ledger(dir).length, before, "degraded runs append nothing");

  // cached FAIL honesty (plan lookup: verdict PASS only ⇒ FAILs are NEVER skipped):
  const planted = randAwsPair();
  writeRel(dir, "config.env", planted.text);
  gitAddCommit(dir, "oops: planted credentials");
  const fail1 = await cli(dir);
  assert.equal(fail1.code, EXIT_BLOCKED);
  const failRec = nthCheck(dir, -1);
  assert.equal(failRec.verdict, "FAIL");
  const fail2 = await cli(dir);
  assert.equal(skipLine(fail2), undefined, "FAIL is never a skip candidate — re-verify every time");
  assert.equal(fail2.code, EXIT_BLOCKED, "the blocked verdict is re-derived, not replayed");
  assert.equal(ledger(dir).length, before + 2, "both FAIL runs appended audit records; the degraded run and the restored SKIP appended nothing");
});

test("CLI exposure cause: env-expanded remote URL moves the key with IDENTICAL config bytes (G21)", async () => {
  const dir = fixture("envurl");
  gitInit(dir);
  writeRel(dir, "border.yaml", borderYaml("git@${BORDER_QA_HOST}:org/repo.git"));
  writeRel(dir, "notes.txt", "clean\n");
  gitAddCommit(dir, "init");

  const a1 = await cli(dir, [], { BORDER_QA_HOST: "a.example" });
  assert.equal(a1.code, EXIT_PASS);
  const a2 = await cli(dir, [], { BORDER_QA_HOST: "a.example" });
  assert.notEqual(skipLine(a2), undefined, "same env ⇒ same exposureSet ⇒ SKIP");

  const b = await cli(dir, [], { BORDER_QA_HOST: "b.example" });
  assert.equal(skipLine(b), undefined, "env-expanded remote change MUST re-check even though border.yaml bytes are identical");
  assert.equal(b.code, EXIT_PASS);
  const recs = ledger(dir);
  assert.equal(recs.length, 2);
  assert.notEqual(recs[0]?.key, recs[1]?.key, "exposureSet is a key input, not just the config digest");
});

test("CLI --llm + push-scope: non-LLM PASS never certifies an --llm run; git-scope never covers npm", async () => {
  const dir = checkRepo("llmscope");
  assert.equal((await cli(dir)).code, EXIT_PASS);
  assert.notEqual(skipLine(await cli(dir)), undefined);

  const llm = await cli(dir, ["--llm"]);
  assert.equal(skipLine(llm), undefined, "round-1 m7: --llm run cannot consume a non-LLM PASS");
  assert.equal((nthCheck(dir, -1)).llm, true);
  assert.notEqual(skipLine(await cli(dir, ["--llm"])), undefined, "LLM PASS certifies the next --llm run");

  // widen the scope: git+npm (plan AC5's ledger half — push --yes over npm must exit 1).
  writeRel(dir, "package.json", JSON.stringify({ name: "widgets", version: "1.0.0", files: ["dist/"] }) + "\n");
  writeRel(dir, "dist/index.js", "export const w = 1;\n");
  writeRel(dir, "border.yaml", borderYaml("origin.example:widgets.git", true));
  gitAddCommit(dir, "add npm target");
  const full = await cli(dir);
  assert.equal(full.code, EXIT_PASS, `npm-scoped run must pass: ${full.out.join(" | ")} ${full.err.join(" | ")}`);
  const wide = nthCheck(dir, -1);
  assert.deepEqual([...wide.effectiveTargets], ["git", "npm"]);
  assert.ok(wide.artifacts !== null && wide.artifacts.length === 1, "clean npm PASS archives repackable artifact digests (M8 groundwork)");

  // the git-only key from run1 cannot authorize an npm push — and the wide run skips next time.
  assert.notEqual(skipLine(await cli(dir)), undefined);
});

test("CLI M8: gitignored-but-packed dist change defeats SKIP despite unchanged head+porcelain", { timeout: 120_000 }, async () => {
  const dir = fixture("m8");
  gitInit(dir);
  writeRel(dir, "package.json", JSON.stringify({ name: "widgets", version: "1.0.0", files: ["dist/"] }) + "\n");
  writeRel(dir, "dist/index.js", "export const w = 1;\n");
  writeRel(dir, ".gitignore", "dist/built.js\n");
  writeRel(dir, "border.yaml", [
    "version: 1",
    "targets:",
    "  git:",
    "    remotes:",
    "      - name: origin",
    "        url: origin.example:widgets.git",
    "  npm: {}",
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
  ].join("\n"));
  gitAddCommit(dir, "init");

  assert.equal((await cli(dir)).code, EXIT_PASS);
  assert.notEqual(skipLine(await cli(dir)), undefined, "steady state skips");

  writeRel(dir, "dist/built.js", "rebuilt payload with new bytes\n"); // gitignored ⇒ git NEVER sees this
  const stale = await cli(dir);
  assert.equal(skipLine(stale), undefined, "repack digest mismatch must reject the stale PASS (round-1 M8)");
  assert.equal(stale.code, EXIT_PASS);
  const rec = nthCheck(dir, -1);
  assert.ok(rec.artifacts !== null);
  assert.notDeepEqual(rec.artifacts, (nthCheck(dir, -2)).artifacts, "the new record captured the changed tarball digest");

  assert.notEqual(skipLine(await cli(dir)), undefined, "fresh certificate ⇒ skip again");
});
