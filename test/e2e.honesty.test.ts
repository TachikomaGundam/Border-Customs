// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 20
//
// Cross-cutting honesty suite: ONE fixture, the 8-step plan sequence verbatim.
// A planted AWS key lives ONLY in git history (commit + revert at HEAD), the
// working tree is dirtied, and a STALE PASS ledger record for a DIFFERENT head
// is pre-seeded. The suite proves end-to-end: the history FAIL exits 1 with the
// leak commit sha and cannot be skipped or gate-bypassed by the stale PASS;
// push --yes refuses with zero mutations (bare shas unchanged, no push
// records); and the planted literal NEVER appears in any captured stream or in
// .border/** — only the redacted `AKIA…7X2Q` snippet form does, closing
// G22/G23 behaviorally including the gitleaks-stdout path. Step 8 is the
// honest recovery: leak-free branch ⇒ fresh PASS (not a stale skip), PUSHED
// record confirmedVia ls-remote, rerun ⇒ SKIP + push no-op. Real gitleaks
// (require-engines guard), local bare remote only — zero public-registry
// network, zero sleeps.
import assert from "node:assert/strict";
import { existsSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { after, test } from "node:test";

import { run } from "../src/cli.ts";
import { EXIT_BLOCKED, EXIT_PASS } from "../src/cli/exit.ts";
import { computeCheckKey } from "../src/check/rulesHash.ts";
import { appendRecord, lookupSkipRecord, readLedger, type CheckRecord } from "../src/ledger.ts";
import { requireGitleaks } from "./helpers/require-engines.ts";
import {
  BORDER_ROOT,
  gitAddCommit,
  gitInit,
  gitRevParseHead,
  gitRmCommit,
  makeFixtureDir,
  removeDir,
  walkFiles,
  writeRel,
} from "./helpers/fixtures.ts";
import { gitIn } from "./helpers/cli-fixtures.ts";

requireGitleaks();

// Exactly AKIA + 16 chars of [A-Z2-7] — matches the vendored gitleaks 8.30.1
// aws-access-token detector; an entropy-rule-only key could be silently missed
// and weaken the whole suite (round-1 finding). redact() maps 20 code points >
// 12 to first4…last4, so the acceptable trace form is `AKIA…7X2Q`; the grep
// target is the 8-char literal prefix `AKIAI4Q3`.
const LEAK_KEY_ID = "AKIAI4Q3EXAMPL3K7X2Q";
const LITERAL = "AKIAI4Q3";
const SNIPPET = "AKIA\u20267X2Q";
const SKIP_RE = /^SKIP [0-9a-f]{8} — PASS \S+ report \.border\/runs\/\S+\/report\.json$/;

const roots: string[] = [];
after(() => {
  for (const d of roots) removeDir(d);
});

function borderYaml(): string {
  return [
    "version: 1",
    "targets:",
    "  git:",
    "    remotes:",
    "      - name: origin",
    "        url: ../remote.git",
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

type CliResult = { readonly step: string; readonly code: number; readonly out: readonly string[]; readonly err: readonly string[] };
const streams: CliResult[] = [];

/** One CLI step through the run() seam, stdout+stderr captured as strings. */
async function cli(work: string, step: string, args: readonly string[]): Promise<CliResult> {
  const out: string[] = [];
  const err: string[] = [];
  const code = (await run(args, (l) => out.push(l), (l) => err.push(l), { cwd: work, env: { ...process.env } })) as number;
  const result: CliResult = { step, code, out, err };
  streams.push(result);
  return result;
}

function checkRecords(work: string): CheckRecord[] {
  return readLedger(work).records.filter((r): r is CheckRecord => r.t === "check");
}
function pushRecordCount(work: string): number {
  return readLedger(work).records.filter((r) => r.t === "push").length;
}

function countOccurrences(haystack: string, needle: string): number {
  let n = 0;
  for (let i = haystack.indexOf(needle); i !== -1; i = haystack.indexOf(needle, i + 1)) n += 1;
  return n;
}

/** Every step's stdout+stderr plus every byte of every file under .border/**. */
function corpus(work: string): string {
  const parts = streams.map((s) => `${s.out.join("\n")}\n${s.err.join("\n")}`);
  for (const file of walkFiles(join(work, ".border"))) parts.push(readFileSync(file, "utf8"));
  return parts.join("\n");
}

test("e2e honesty: history leak + stale ledger ⇒ blocked push, zero literal exposure, honest recovery", { timeout: 150_000 }, async () => {
  const t0 = performance.now();
  // Plan regression precondition: verdaccio devDep present in node_modules — assert only, never install.
  assert.ok(existsSync(join(BORDER_ROOT, "node_modules", "verdaccio")), "verdaccio devDep must be installed before this suite runs");

  const root = makeFixtureDir("e2e-honesty");
  roots.push(root);
  const bare = join(root, "remote.git");
  const work = join(root, "work");
  mkdirSync(bare);
  mkdirSync(work);
  gitIn(root, bare, ["init", "-q", "--bare", "-b", "main"]);
  gitInit(work);
  gitIn(work, work, ["remote", "add", "origin", "../remote.git"]);
  writeRel(work, ".gitignore", ".border/\n");
  writeRel(work, "border.yaml", borderYaml());
  writeRel(work, "notes.txt", "clean content\n");
  gitAddCommit(work, "init");
  const sha0 = gitRevParseHead(work);

  // (1) clean tree ⇒ check PASS, record written.
  const c1 = await cli(work, "1 check PASS", ["check"]);
  assert.equal(c1.code, EXIT_PASS, `step 1 must pass: ${c1.out.join("\n")} / ${c1.err.join("\n")}`);
  assert.ok(c1.out.some((l) => l.includes("PASS")), "step 1 summary must report PASS");
  const rec1 = checkRecords(work)[0] as CheckRecord;
  assert.equal(rec1.verdict, "PASS");
  assert.equal(rec1.head, sha0);

  // (2) leak lives only in history: commit the key, then revert at HEAD.
  writeRel(work, "config/aws.conf", `aws_access_key_id = ${LEAK_KEY_ID}\n`);
  gitAddCommit(work, "add aws config");
  const leakSha = gitRevParseHead(work);
  gitRmCommit(work, "config/aws.conf", "revert aws config");
  const headSha = gitRevParseHead(work);
  assert.notEqual(headSha, leakSha);

  // (3) dirty the working tree (leak-free content).
  writeRel(work, "scratch.txt", "work in progress\n");

  // (4) stale PASS for a DIFFERENT head — schema-exact (it must PARSE), key
  // honestly derived for leakSha, so the only reason it cannot skip is the
  // head/fingerprint mismatch.
  const staleKey = computeCheckKey({
    headSha: leakSha,
    porcelainDigest: rec1.dirtyDigest,
    rulesHash: rec1.rulesHash,
    exposureSet: rec1.exposureSet,
    refSet: ["refs/heads/main"],
    effectiveTargets: rec1.effectiveTargets,
  });
  const stale: CheckRecord = {
    ...rec1,
    key: staleKey,
    key8: staleKey.slice(0, 8),
    head: leakSha,
    verdict: "PASS",
    ts: new Date().toISOString(),
  };
  appendRecord(work, stale);
  const seeded = readLedger(work);
  assert.deepEqual(seeded.warnings, [], "stale seed must parse — a schema failure would skip for the wrong reason");
  assert.equal(seeded.records.length, 2);
  assert.notEqual(staleKey, rec1.key);
  // The record IS a live skip candidate under its own fingerprint…
  assert.ok(lookupSkipRecord(seeded.records, staleKey, false) !== null, "stale seed must be skippable for its own key (not inert garbage)");

  // (5) check --force ⇒ exit 1, CRITICAL carrying the leak commit sha (history leg).
  const c5 = await cli(work, "5 check --force FAIL", ["check", "--force"]);
  assert.equal(c5.code, EXIT_BLOCKED, `step 5 must block: ${c5.out.join("\n")} / ${c5.err.join("\n")}`);
  assert.ok(
    c5.out.some((l) => l.includes("CRITICAL") && l.includes("gitleaks") && l.includes(leakSha)),
    `a CRITICAL gitleaks finding naming the leak commit ${leakSha} must surface:\n${c5.out.join("\n")}`,
  );
  const recs5 = readLedger(work).records;
  const failRec = checkRecords(work).at(-1) as CheckRecord; // newest check record = this run's FAIL
  assert.equal(failRec.verdict, "FAIL");
  assert.equal(failRec.head, headSha);
  // …and under the LIVE key it is not a skip: the head mismatch is what refutes it.
  assert.equal(lookupSkipRecord(recs5, failRec.key, false), null, "stale PASS must NOT skip the live fingerprint");
  assert.notEqual(staleKey, failRec.key);

  // (6) push --yes ⇒ exit 1 BLOCKED; nothing touched: bare shas identical, zero push records.
  const lsBefore = gitIn(work, work, ["ls-remote", "../remote.git"]);
  const pushBlocks = await cli(work, "6 push --yes blocked", ["push", "--yes"]);
  assert.equal(pushBlocks.code, EXIT_BLOCKED);
  assert.ok(pushBlocks.out.some((l) => l.includes("BLOCKED")), `push must print BLOCKED:\n${pushBlocks.out.join("\n")}`);
  assert.ok(pushBlocks.err.some((l) => l.includes("nothing was pushed")), "refusal line must state nothing was pushed");
  assert.equal(gitIn(work, work, ["ls-remote", "../remote.git"]), lsBefore, "remote refs must be byte-identical after the refused push");
  assert.equal(pushRecordCount(work), 0, "refused push must append zero push records");

  // (7) THE GREP: the literal never appears in any stream or under .border/**; the redacted snippet form must.
  const all = corpus(work);
  const hits = countOccurrences(all, LITERAL);
  console.log(`${LITERAL} literal matches: ${String(hits)}`);
  console.log(`covered streams: ${streams.map((s) => `${s.step}(out+err)`).join(", ")} + .border/** files`);
  assert.equal(hits, 0, "the planted literal must never surface — G22/G23 honesty violation");
  assert.ok(countOccurrences(all, SNIPPET) > 0, "the AKIA…7X2Q snippet form must appear — proves the finding really flowed through redact()");

  // (8) honest recovery: leak-free branch ⇒ fresh PASS, push lands, reruns skip/no-op.
  rmSync(join(work, "scratch.txt"));
  gitIn(work, work, ["checkout", "-q", "-b", "clean", sha0]);
  const c8 = await cli(work, "8 check clean-branch", ["check"]);
  assert.equal(c8.code, EXIT_PASS, `clean branch must PASS: ${c8.out.join("\n")} / ${c8.err.join("\n")}`);
  assert.ok(!c8.out.some((l) => SKIP_RE.test(l)), "must be a FRESH PASS, not a skip of the stale seed");
  const checks = checkRecords(work);
  assert.equal(checks.length, 4, "step-8 check must record a new PASS");
  const rec3 = checks.at(-1) as CheckRecord;
  assert.equal(rec3.verdict, "PASS");
  assert.equal(rec3.head, sha0);
  assert.notEqual(rec3.key, rec1.key, "clean-branch key differs from step-1 (refSet changed)");
  assert.notEqual(rec3.key, staleKey);

  const p8 = await cli(work, "8 push --yes", ["push", "--yes"]);
  assert.equal(p8.code, EXIT_PASS, `push must land: ${p8.out.join("\n")} / ${p8.err.join("\n")}`);
  assert.ok(p8.out.some((l) => l.includes("pushed git:origin") && l.includes("confirmed via ls-remote")), `landing line expected:\n${p8.out.join("\n")}`);
  const lsAfter = gitIn(work, work, ["ls-remote", "../remote.git"]);
  assert.ok(lsAfter.includes(sha0) && lsAfter.includes("refs/heads/clean"), `remote must carry refs/heads/clean@${sha0}:\n${lsAfter}`);
  const pushRec = readLedger(work).records.find((r) => r.t === "push");
  assert.ok(
    pushRec !== undefined && pushRec.t === "push" && pushRec.confirmedVia === "ls-remote" &&
      pushRec.remoteSha === sha0 && pushRec.localSha === sha0 && pushRec.target === "git:origin" && pushRec.remoteName === "origin",
    `push record must be a ls-remote-confirmed proof: ${JSON.stringify(pushRec)}`,
  );

  const c8b = await cli(work, "8 rerun check", ["check"]);
  assert.equal(c8b.code, EXIT_PASS);
  assert.ok(c8b.out.some((l) => SKIP_RE.test(l)), `rerun must SKIP:\n${c8b.out.join("\n")}`);
  const p8b = await cli(work, "8 rerun push", ["push", "--yes"]);
  assert.equal(p8b.code, EXIT_PASS);
  assert.ok(p8b.out.some((l) => l.includes("nothing pending — every target is already PUSHED (no-op)")), `no-op line expected:\n${p8b.out.join("\n")}`);
  assert.equal(checkRecords(work).length, 4, "SKIP + no-op append nothing");
  assert.equal(pushRecordCount(work), 1);

  // Final integrity sweep over the FULL corpus (all 9 steps + every .border byte written since).
  const finalHits = countOccurrences(corpus(work), LITERAL);
  console.log(`${LITERAL} literal matches (final): ${String(finalHits)}`);
  assert.equal(finalHits, 0);
  console.log(`honesty suite wall: ${String(Math.round(performance.now() - t0))} ms`);
});
