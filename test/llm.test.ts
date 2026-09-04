// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 18
//
// LLM bundle contract: `border llm-request` writes the review bundle (masked
// diff patches, deterministic summary, prompt template ref); `border
// llm-ingest` validates agent findings against the C1 schema + the bundle's
// file list, forces engine:'agent', and persists an {llm:true} ledger record
// + report.json via the todo-14 seam. border NEVER calls an LLM API — every
// check/ingest pair here spawns the real CLI over real fixture repos with real
// gitleaks masking (fail-closed if the binary is absent, hence the guard).
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { test } from "node:test";

import { EXIT_BLOCKED, EXIT_ERROR, EXIT_PASS } from "../src/cli/exit.ts";
import type { CheckRecord } from "../src/ledger/records.ts";
import { readLedger } from "../src/ledger/records.ts";
import type { LlmRequestBundle } from "../src/llm.ts";
import { DATA_BOUNDARY } from "../src/llm.ts";
import { BORDER_ROOT, makeFixtureDir, randAwsPair, removeDir, writeRel, gitInit, gitAddCommit } from "./helpers/fixtures.ts";
import { gitIn, makeRemoteFixture } from "./helpers/cli-fixtures.ts";
import { requireGitleaks } from "./helpers/require-engines.ts";

requireGitleaks();

const gitleaksPresent = spawnSync("gitleaks", ["version"], { encoding: "utf8" }).status === 0;

/**
 * border.yaml for the fixtures: the remote URL is the RELATIVE `../remote.git`
 * (a real git-accepted path from work/) because an absolute /home path inside
 * a tracked file trips secretlint's built-in homedir rule — the fixture must
 * PASS the deterministic gate for the round-trip tests, and the rules.authors
 * allow-list covers the fixture committer identity (Wiki.js) the identity rule
 * would otherwise CRITICAL on.
 */
function cleanBorderYaml(): string {
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

type Run = { readonly code: number; readonly out: string; readonly err: string };

function border(args: readonly string[], cwd: string, env: Readonly<Record<string, string>> = {}): Run {
  const r = spawnSync(
    process.execPath,
    ["--import", join(BORDER_ROOT, "tools", "register-ts.mjs"), join(BORDER_ROOT, "src", "index.ts"), ...args],
    { cwd, encoding: "utf8", env: { ...process.env, GIT_CEILING_DIRECTORIES: dirname(cwd), ...env } },
  );
  return { code: r.status ?? -1, out: r.stdout ?? "", err: r.stderr ?? "" };
}

/** bare remote + clean commit pushed + border.yaml + one LOCAL commit (tip behind). */
function fixtureTipBehind(): { readonly root: string; readonly work: string; readonly bare: string } {
  const fx = makeRemoteFixture();
  gitIn(fx.root, fx.work, ["remote", "set-url", "origin", "../remote.git"]);
  writeRel(fx.work, "border.yaml", cleanBorderYaml());
  writeRel(fx.work, "feature.txt", "feature work\nsecond line\n");
  gitIn(fx.work, fx.work, ["add", "-A"]);
  gitIn(fx.work, fx.work, ["-c", "user.name=Wiki.js", "-c", "user.email=wiki@sumteclab.com", "commit", "-q", "-m", "add feature"]);
  return { root: fx.root, work: fx.work, bare: fx.bare };
}

function readBundle(work: string): LlmRequestBundle {
  const runs = join(work, ".border", "runs");
  const dirs = readdirSync(runs).sort().reverse();
  for (const d of dirs) {
    const p = join(runs, d, "llm-request.json");
    if (existsSync(p)) return JSON.parse(readFileSync(p, "utf8")) as LlmRequestBundle;
  }
  throw new Error("no llm-request.json under any run dir");
}

function lastCheckRecord(work: string): CheckRecord {
  const { records } = readLedger(work);
  for (let i = records.length - 1; i >= 0; i -= 1) {
    const r = records[i];
    if (r !== undefined && r.t === "check") return r;
  }
  throw new Error("no check record");
}

if (!gitleaksPresent) {
  test("llm contract tests skipped: gitleaks binary absent (masking is fail-closed)", () => {});
} else {
  test("llm-request requires a prior check record (no record ⇒ exit 2, instruct check)", () => {
    const fx = makeRemoteFixture();
    try {
      gitIn(fx.root, fx.work, ["remote", "set-url", "origin", "../remote.git"]);
      writeRel(fx.work, "border.yaml", cleanBorderYaml());
      const r = border(["llm-request"], fx.work);
      assert.equal(r.code, EXIT_ERROR);
      assert.match(r.err, /run ['"]?border check['"]?/);
      assert.equal(r.out.length, 0, "no success payload without a record");
    } finally {
      removeDir(fx.root);
    }
  });

  test("bundle round-trip: remote-tip base + llm-ingest CRITICAL flips PASS⇒FAIL (agent provenance, exit 1)", () => {
    const fx = fixtureTipBehind();
    try {
      const checked = border(["check"], fx.work);
      assert.equal(checked.code, EXIT_PASS, checked.err);
      const tip = gitIn(fx.root, fx.work, ["rev-parse", "origin/main"]).trim();
      const head = gitIn(fx.root, fx.work, ["rev-parse", "HEAD"]).trim();
      assert.notEqual(tip, head, "fixture must have local commits ahead of the remote tip");

      const req = border(["llm-request"], fx.work);
      assert.equal(req.code, EXIT_PASS, req.err);
      assert.match(req.out, /llm-request: wrote .+llm-request\.json/);
      const bundle = readBundle(fx.work);
      const record = lastCheckRecord(fx.work);
      assert.equal(bundle.key, record.key);
      assert.equal(bundle.head, head);
      assert.equal(bundle.base.mode, "remote-tip");
      assert.equal(bundle.base.sha, tip);
      assert.equal(bundle.rulesHash, record.rulesHash);
      assert.ok(bundle.exposureSet.length >= 1, "exposureSet carried from the recorded ctx");
      assert.ok(bundle.refSet.includes("refs/heads/main"), `refSet: ${String(bundle.refSet)}`);
      assert.equal(bundle.dataBoundary, DATA_BOUNDARY);
      const delta = bundle.fileDeltas.find((d) => d.path === "feature.txt");
      assert.ok(delta !== undefined, `feature.txt missing from ${String(bundle.fileDeltas.map((d) => d.path))}`);
      assert.ok(delta.patch.includes("+feature work"), "patch carries the real added line (reviewable source)");
      assert.equal(bundle.deterministic.counts.total, 0);
      assert.equal(bundle.promptTemplate.sha256, createHash("sha256").update(readFileSync(join(BORDER_ROOT, "assets", "prompts", "llm-review.md"))).digest("hex"));

      writeRel(fx.root, "findings.json", JSON.stringify([
        { rule: "llm-suspicious-todo", severity: "CRITICAL", target: "git", path: "feature.txt", line: 1, message: "hard-coded follow-up hints at unfinished auth code" },
      ]));
      const ing = border(["llm-ingest", join(fx.root, "findings.json")], fx.work);
      assert.match(ing.out + ing.err, /verdict FAIL/);
      assert.equal(ing.code, EXIT_BLOCKED, "CRITICAL agent finding flips the verdict ⇒ exit 1");
      const rec = lastCheckRecord(fx.work);
      assert.equal(rec.llm, true);
      assert.equal(rec.verdict, "FAIL");
      assert.equal(rec.key, bundle.key, "ingest record keys on the reviewed bundle state");
      const report = JSON.parse(readFileSync(join(fx.work, rec.reportPath), "utf8")) as { findings: { engine: string; valueDigest: string }[] };
      assert.equal(report.findings.length, 1);
      assert.equal(report.findings[0]?.engine, "agent");
      assert.match(String(report.findings[0]?.valueDigest), /^[0-9a-f]{64}$/);

      // {llm:true} FAIL record must not skip; a plain re-check re-runs fully.
      const plain = border(["check"], fx.work);
      assert.doesNotMatch(plain.out, /^SKIP/m, "llm FAIL record must not produce a SKIP line");
    } finally {
      removeDir(fx.root);
    }
  });

  test("masking proof: deterministic-flagged secret value appears NOWHERE raw in the bundle, only [REDACTED:<sha8>]", () => {
    const fx = fixtureTipBehind();
    try {
      const leak = randAwsPair();
      writeRel(fx.work, "config.ini", leak.text);
      gitIn(fx.work, fx.work, ["add", "-A"]);
      gitIn(fx.work, fx.work, ["-c", "user.name=Wiki.js", "-c", "user.email=wiki@sumteclab.com", "commit", "-q", "-m", "wire aws"]);
      const checked = border(["check"], fx.work);
      assert.equal(checked.code, EXIT_BLOCKED, "planted secret must FAIL the deterministic gate");
      const req = border(["llm-request"], fx.work);
      assert.equal(req.code, EXIT_PASS, req.err);
      const bundle = readBundle(fx.work);
      const bundleText = JSON.stringify(bundle);
      assert.equal(bundleText.includes(leak.key), false, "raw AWS key literal must not appear in the bundle");
      assert.equal(bundleText.includes(leak.secret), false, "raw secret literal must not appear in the bundle");
      const det = bundle.deterministic.findings.find((f) => f.engine === "gitleaks");
      assert.ok(det !== undefined, "gitleaks deterministic finding expected in summary");
      const token = `[REDACTED:${det.valueDigest.slice(0, 8)}]`;
      const delta = bundle.fileDeltas.find((d) => d.path === "config.ini");
      assert.ok(delta !== undefined && delta.patch.includes(token), `patch must carry ${token}, got: ${String(delta?.patch.slice(0, 200))}`);
      assert.ok(delta.patch.includes("aws_access_key_id = "), "non-secret diff context survives masking");
      assert.ok(delta.patch.includes("[REDACTED:") && !delta.patch.includes(leak.key));
    } finally {
      removeDir(fx.root);
    }
  });

  test("ingest rejects unknown path / malformed items with exit 2 naming the item index; malformed bundle inputs stay honest", () => {
    const fx = fixtureTipBehind();
    try {
      assert.equal(border(["check"], fx.work).code, EXIT_PASS);
      assert.equal(border(["llm-request"], fx.work).code, EXIT_PASS);
      const ledgerLines = (): number => readFileSync(join(fx.work, ".border", "ledger.jsonl"), "utf8").split("\n").filter((l) => l !== "").length;
      const before = ledgerLines();
      const cases: [string, string, RegExp][] = [
        ["unknown path", JSON.stringify([{ rule: "x", severity: "CRITICAL", target: "git", path: "nowhere.txt", message: "m" }]), /item 0.*finding-unknown-location/s],
        ["bad rule", JSON.stringify([{ rule: "Bad_Rule!", severity: "LOW", target: "git", message: "m" }]), /item 0/],
        ["bad severity", JSON.stringify([{ rule: "x", severity: "BLOCKER", target: "git", message: "m" }]), /item 0/],
        ["extra key", JSON.stringify([{ rule: "x", severity: "LOW", target: "git", message: "m", payload: 1 }]), /item 0.*unknown key/s],
        ["second item", JSON.stringify([{ rule: "x", severity: "LOW", target: "git", message: "ok" }, { rule: "y", severity: "NOPE", target: "git", message: "bad" }]), /item 1/],
        ["not root array", JSON.stringify({ findings: [] }), /not a JSON array/],
        ["truncated json", "[{rule:", /not valid JSON/],
      ];
      for (const [name, body, expect] of cases) {
        writeRel(fx.root, "bad.json", body);
        const r = border(["llm-ingest", join(fx.root, "bad.json")], fx.work);
        assert.equal(r.code, EXIT_ERROR, `${name}: stderr ${r.err}`);
        assert.match(r.err, expect, name);
        assert.equal(r.out.length, 0, `${name}: must print no success payload`);
      }
      const missing = border(["llm-ingest", "definitely-absent.json"], fx.work);
      assert.equal(missing.code, EXIT_ERROR);
      assert.equal(border(["llm-ingest"], fx.work).code, EXIT_ERROR, "no positional ⇒ usage error");
      assert.equal(ledgerLines(), before, "rejected ingests persist nothing");
    } finally {
      removeDir(fx.root);
    }
  });

  test("agent message carrying a secret value is masked on ingest (prompt-injection class)", () => {
    const fx = fixtureTipBehind();
    try {
      const leak = randAwsPair();
      writeRel(fx.work, "config.ini", leak.text);
      gitIn(fx.work, fx.work, ["add", "-A"]);
      gitIn(fx.work, fx.work, ["-c", "user.name=Wiki.js", "-c", "user.email=wiki@sumteclab.com", "commit", "-q", "-m", "wire aws"]);
      assert.equal(border(["check"], fx.work).code, EXIT_BLOCKED);
      assert.equal(border(["llm-request"], fx.work).code, EXIT_PASS);
      writeRel(fx.root, "findings.json", JSON.stringify([
        { rule: "aws-key-pinned", severity: "HIGH", target: "git", message: `agent pasted the key it saw: ${leak.key}` },
      ]));
      const ing = border(["llm-ingest", join(fx.root, "findings.json")], fx.work);
      assert.equal(ing.code, EXIT_BLOCKED, ing.out + ing.err);
      const rec = lastCheckRecord(fx.work);
      const reportText = readFileSync(join(fx.work, rec.reportPath), "utf8");
      assert.equal(reportText.includes(leak.key), false, "raw key echoed by the agent must be masked in the persisted report");
      assert.match(reportText, /\[REDACTED:[0-9a-f]{8}\]/);
    } finally {
      removeDir(fx.root);
    }
  });

  test("empty findings array is ingested honestly: llm:true PASS record, no plain-check SKIP leak, --llm skips, stale after head move", () => {
    const fx = fixtureTipBehind();
    try {
      assert.equal(border(["check"], fx.work).code, EXIT_PASS);
      assert.equal(border(["llm-request"], fx.work).code, EXIT_PASS);
      writeRel(fx.root, "findings.json", "[]");
      const ing = border(["llm-ingest", join(fx.root, "findings.json")], fx.work);
      assert.equal(ing.code, EXIT_PASS, ing.out + ing.err);
      assert.match(ing.out, /verdict PASS/);
      const rec = lastCheckRecord(fx.work);
      assert.deepEqual({ llm: rec.llm, verdict: rec.verdict }, { llm: true, verdict: "PASS" });
      // newest-record authority: the llm PASS satisfies the --llm skip...
      const llmCheck = border(["check", "--llm"], fx.work);
      assert.match(llmCheck.out, /^SKIP /m, llmCheck.out + llmCheck.err);
      // ...but a plain check must NOT ride an llm record (and now re-records
      // llm:false itself — which in turn must not satisfy a --llm skip).
      const plain = border(["check"], fx.work);
      assert.doesNotMatch(plain.out, /^SKIP/m, "llm:true PASS must never satisfy a plain-check skip");
      const llmAgain = border(["check", "--llm"], fx.work);
      assert.doesNotMatch(llmAgain.out, /^SKIP/m, "plain llm:false PASS must never satisfy a --llm skip");
      // head moves ⇒ no stale reuse of either record
      writeRel(fx.work, "more.txt", "new work\n");
      gitIn(fx.work, fx.work, ["add", "-A"]);
      gitIn(fx.work, fx.work, ["-c", "user.name=Wiki.js", "-c", "user.email=wiki@sumteclab.com", "commit", "-q", "-m", "more"]);
      const afterMove = border(["check", "--llm"], fx.work);
      assert.doesNotMatch(afterMove.out, /^SKIP/m, "moved head must never reuse the old llm PASS");
    } finally {
      removeDir(fx.root);
    }
  });

  test("stale bundle: llm-ingest refuses when HEAD moved since llm-request", () => {
    const fx = fixtureTipBehind();
    try {
      assert.equal(border(["check"], fx.work).code, EXIT_PASS);
      assert.equal(border(["llm-request"], fx.work).code, EXIT_PASS);
      writeRel(fx.work, "late.txt", "commit after request\n");
      gitIn(fx.work, fx.work, ["add", "-A"]);
      gitIn(fx.work, fx.work, ["-c", "user.name=Wiki.js", "-c", "user.email=wiki@sumteclab.com", "commit", "-q", "-m", "late"]);
      writeRel(fx.root, "findings.json", JSON.stringify([{ rule: "x", severity: "LOW", target: "git", message: "m" }]));
      const ing = border(["llm-ingest", join(fx.root, "findings.json")], fx.work);
      assert.equal(ing.code, EXIT_ERROR);
      assert.match(ing.err, /moved since llm-request/);
      assert.equal(ing.out.length, 0);
    } finally {
      removeDir(fx.root);
    }
  });

  test("oversized diff (>10MiB) truncates the patch with an explicit marker", () => {
    const fx = fixtureTipBehind();
    try {
      const big = Array.from({ length: 220_000 }, (_, i) => `line ${String(i)} ${"x".repeat(40)}`).join("\n");
      writeRel(fx.work, "big.txt", `${big}\n`);
      gitIn(fx.work, fx.work, ["add", "-A"]);
      gitIn(fx.work, fx.work, ["-c", "user.name=Wiki.js", "-c", "user.email=wiki@sumteclab.com", "commit", "-q", "-m", "big file"]);
      const checked = border(["check"], fx.work);
      assert.ok(checked.code === EXIT_PASS || checked.code === EXIT_BLOCKED, checked.err);
      const req = border(["llm-request"], fx.work);
      assert.equal(req.code, EXIT_PASS, req.err);
      const bundle = readBundle(fx.work);
      const delta = bundle.fileDeltas.find((d) => d.path === "big.txt");
      assert.ok(delta !== undefined);
      assert.equal(delta.truncated, true);
      assert.ok(delta.patch.includes("[border: patch truncated at 10 MiB"), delta.patch.slice(-120));
      assert.ok(Buffer.byteLength(delta.patch, "utf8") <= 10 * 1024 * 1024 + 512, `patchBytes ${String(delta.patchBytes)}`);
    } finally {
      removeDir(fx.root);
    }
  });

  test("first-push (no remote-tracking tip) ⇒ full-tree mode stated in the bundle", () => {
    const root = makeFixtureDir("llm-firstpush");
    const bare = join(root, "remote.git");
    const work = join(root, "work");
    try {
      mkdirSync(bare);
      gitIn(root, bare, ["init", "-q", "--bare", "-b", "main"]);
      mkdirSync(work);
      gitInit(work);
      writeRel(work, "hello.txt", "first tree\n");
      writeRel(work, "border.yaml", cleanBorderYaml());
      gitAddCommit(work, "seed");
      gitIn(root, work, ["remote", "add", "origin", "../remote.git"]);
      assert.equal(border(["check"], work).code, EXIT_PASS);
      const req = border(["llm-request"], work);
      assert.equal(req.code, EXIT_PASS, req.err);
      const bundle = readBundle(work);
      assert.equal(bundle.base.mode, "full-tree");
      assert.match(bundle.base.note, /first push|no remote-tracking/i);
      const paths = bundle.fileDeltas.map((d) => d.path);
      assert.ok(paths.includes("hello.txt") && paths.includes("border.yaml"), `full tree expected, got ${String(paths)}`);
      const hello = bundle.fileDeltas.find((d) => d.path === "hello.txt");
      assert.ok(hello !== undefined && hello.patch.includes("+first tree"), "added-file patch shows the full content as additions");
    } finally {
      removeDir(root);
    }
  });

  test("prompt template edit invalidates the cached PASS (digest feeds rulesHash)", () => {
    const fx = fixtureTipBehind();
    const tpl = join(fx.root, "tpl.md");
    try {
      writeFileSync(tpl, readFileSync(join(BORDER_ROOT, "assets", "prompts", "llm-review.md"), "utf8"));
      const env = { BORDER_PROMPT_TEMPLATE_PATH: tpl };
      assert.equal(border(["check"], fx.work, env).code, EXIT_PASS);
      const skip = border(["check"], fx.work, env);
      assert.match(skip.out, /^SKIP /m, "unchanged state must SKIP before the template edit");
      writeFileSync(tpl, `${readFileSync(tpl, "utf8")}\n<!-- tightened review wording -->\n`);
      const rerun = border(["check"], fx.work, env);
      assert.doesNotMatch(rerun.out, /^SKIP/m, "template edit must invalidate the fingerprint — no SKIP");
      assert.equal(rerun.code, EXIT_PASS);
    } finally {
      removeDir(fx.root);
    }
  });
}
