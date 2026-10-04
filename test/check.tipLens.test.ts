// provenance: check-tip-lens regression suite (2026-10-04 incident).
//
// The incident: `border check` PASSed (0 blocking) and `border push --yes` landed,
// then the POST-PUSH landing scan (scanTipTree over the whole remote tip tree)
// reported 20 blocking CRITICALs. Root cause, evidence-backed (Abathur ledger +
// archived report.json 579dcc27-2026-10-04T04-36-59-231Z): a DOUBLE STANDARD —
//   (a) check suppressed the exact landing-reported findings through owner-authored
//       allow pins while landing's scanTipTree never applied the allow list at all;
//   (b) the range/disk-oriented check lens can be blind to bytes that ARE in the
//       pushed tip tree (merge-commit additions invisible to `git log -p`, files
//       deleted from disk but tracked in HEAD) while landing scans the whole tip.
// Green-before-push had no predictive power over landing. These tests pin the fix:
//   T1 the check pipeline runs the landing-grade tip lens (same machinery);
//   T2 allow pins exempt matching TIP findings in BOTH faces (never silent — the
//      suppression is echoed at landing; unpinned findings still block — the
//      detects-and-never-erases doctrine is untouched);
//   T3 the skip-ledger key gains the lens identity, so pre-fix range-only PASS
//      records can never certify a push under the tip-augmented lens, while the
//      post-fix record still self-skips;
//   T4 a failed tip leg is loud (exit 2 territory, never a silent clean); a broken
//      twin engine skips only its own sub-leg of the tip scan (existing degraded
//      semantics, never a crash of the whole gate).
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { appendFileSync, chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { tmpdir } from "node:os";
import { after, test } from "node:test";

import { run } from "../src/cli.ts";
import { EXIT_BLOCKED, EXIT_ERROR, EXIT_PASS } from "../src/cli/exit.ts";
import { scanTipTree } from "../src/commands/exfil.ts";
import { makeGit } from "../src/commands/exfilGit.ts";
import { scanTipTreeLens } from "../src/check/tipTreeLens.ts";
import { computeCheckKey, stableStringify, type CheckKeyInput } from "../src/check/rulesHash.ts";
import { runLandingVerification, type LandingLeg } from "../src/push/landing.ts";
import { ledgerPath, type LandingRecord } from "../src/ledger/records.ts";
import type { Finding, Report } from "../src/findings.ts";
import { assembleOctet, gitAddCommit, gitInit, makeFixtureDir, removeDir, writeRel } from "./helpers/fixtures.ts";

const roots: string[] = [];
after(() => {
  for (const d of roots) removeDir(d);
});

function fixture(name: string): string {
  const dir = makeFixtureDir(`tiplens-${name}`);
  roots.push(dir);
  return dir;
}

// F3 doctrine: the full dotted quad is assembled at runtime — this source file
// never carries one. The literal below exists only in process memory + fixtures.
const RFC = assembleOctet("10.42.7", "99");
const RFC_SHA = createHash("sha256").update(RFC, "utf8").digest("hex");

function yaml(remoteUrl: string, allow: string): string {
  return [
    "version: 1",
    "targets:",
    "  git:",
    "    remotes:",
    "    - name: origin",
    `      url: ${remoteUrl}`,
    "rules:",
    "  authors:",
    "    emails: [bot@gate-corp.com]",
    "    names: [Wiki.js]",
    "  hosts: []",
    "  ips: []",
    "  pathPatterns: []",
    `allow: ${allow}`,
  ].join("\n") + "\n";
}

const ALLOW_PIN = [
  "- rule: exfil-rfc1918",
  `  match: ${RFC_SHA}`,
  "  file: leaky.txt",
].join("\n");

/** repo + bare remote + border.yaml, mirroring exfil.landing.test.ts's fixtureRepo. */
function fixtureRepo(name: string): { repo: string; bare: string } {
  const repo = fixture(`${name}-repo`);
  const bare = fixture(`${name}-bare`);
  spawnSync("git", ["init", "--bare", "-b", "main", bare], { encoding: "utf8" });
  gitInit(repo);
  return { repo, bare };
}

function gsp(cwd: string, args: readonly string[]): { status: number | null; stdout: string; stderr: string } {
  const r = spawnSync("git", args, { cwd, encoding: "utf8", env: { ...process.env, GIT_CEILING_DIRECTORIES: dirname(cwd) } });
  return { status: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
}

async function cli(argv: readonly string[], cwd: string): Promise<{ code: number; out: string[]; err: string[] }> {
  const out: string[] = [];
  const err: string[] = [];
  const code = await run(argv, (l) => out.push(l), (l) => err.push(l), { cwd, env: { ...process.env } });
  return { code, out, err };
}

function parseReport(out: readonly string[]): Report {
  return JSON.parse(out.join("\n")) as Report;
}

// -------------------------------------------------------------------------- T1
// The blindspot fixture: leaky.txt exists ONLY in the HEAD tree — introduced by a
// merge commit (invisible to the `git log -p` history lens; proven below) and
// deleted from disk uncommitted (invisible to the disk lens). Pre-fix check
// certified this tip PASS 0 blocking; landing's scanTipTree reports it CRITICAL.
function blindspotRepo(name: string, allow: string): { repo: string; bare: string } {
  const { repo, bare } = fixtureRepo(name);
  writeRel(repo, "base.txt", "benign base\n");
  gitAddCommit(repo, "init");
  gsp(repo, ["checkout", "-qb", "side"]);
  writeRel(repo, "notes.txt", "side version\n");
  gitAddCommit(repo, "side notes");
  gsp(repo, ["checkout", "-q", "main"]);
  writeRel(repo, "notes.txt", "main version\n");
  gitAddCommit(repo, "main notes");
  // conflict on notes.txt ⇒ hand-resolved merge that ALSO adds leaky.txt: the
  // literal never appears in any non-merge diff.
  const merge = gsp(repo, ["merge", "--no-ff", "side", "-m", "x"]);
  assert.notEqual(merge.status, 0, "fixture requires an add/add conflict");
  writeRel(repo, "notes.txt", "resolved\n");
  writeRel(repo, "leaky.txt", `mirror = ${RFC}\n`);
  writeRel(repo, "border.yaml", yaml(relative(repo, bare), allow));
  gsp(repo, ["add", "notes.txt", "leaky.txt", "border.yaml"]);
  gsp(repo, ["commit", "-q", "-m", "merge side into main"]);
  rmSync(join(repo, "leaky.txt")); // tip-only bytes: uncommitted disk deletion
  // fixture self-check: the history lens really is blind to the literal.
  const log = gsp(repo, ["log", "-p"]);
  assert.ok(!log.stdout.includes(RFC), "git log -p must not contain the literal (merge-only addition)");
  return { repo, bare };
}

test("T1 tip lens in check: bytes visible ONLY in the HEAD tree now block the gate (landing-grade parity)", async () => {
  const { repo } = blindspotRepo("t1", "[]");
  const res = await cli(["check", "--force", "--json", "--config", join(repo, "border.yaml")], repo);
  assert.equal(res.code, EXIT_BLOCKED, `check must FAIL on tip-only leak bytes: ${res.out.join("\n")} / ${res.err.join("\n")}`);
  const report = parseReport(res.out);
  assert.ok(report.counts.blocking >= 1, "at least the secretlint twin fires in-process; gitleaks adds its copy when installed");
  const tipFindings = report.findings.filter((f) => f.path === "leaky.txt" && f.rule === "exfil-rfc1918");
  assert.ok(tipFindings.length >= 1, `tip-lens findings on leaky.txt missing: ${JSON.stringify(report.findings.map((f) => [f.rule, f.path, f.engine]))}`);
  for (const f of tipFindings) {
    assert.equal(f.severity, "CRITICAL", "twin severity mapping on the tip lens is CRITICAL — identical to landing/exfil");
    assert.ok(["gitleaks", "secretlint"].includes(f.engine));
  }
});

// -------------------------------------------------------------------------- T2
test("T2 allow-pin parity: the same rule+file+digest pin exempts matching tip findings in check AND in landing (loud, never silent)", async () => {
  const { repo, bare } = blindspotRepo("t2", `\n${ALLOW_PIN}`);
  const res = await cli(["check", "--force", "--json", "--config", join(repo, "border.yaml")], repo);
  assert.equal(res.code, EXIT_PASS, `pinned tip bytes must PASS the gate — pins are the one sanctioned waiver surface: ${res.out.join("\n")}`);
  const report = parseReport(res.out);
  assert.equal(report.counts.blocking, 0, "check: pinned tip findings must not block");
  assert.ok((report.allowHits ?? []).some((h) => h.rule === "exfil-rfc1918" && h.count >= 1), "every suppression is enumerated — exit 0 never hides what it hid");

  // ---- landing side: scanTipTree findings flow through the SAME pins.
  const KEY = "a".repeat(64);
  const RULES = "c".repeat(64);
  const leg: LandingLeg = { target: { target: "git:origin", url: relative(repo, bare) }, branch: "main" };
  const seedPass = (dir: string) => {
    mkdirSync(dirname(ledgerPath(dir)), { recursive: true });
    appendFileSync(
      ledgerPath(dir),
      `${JSON.stringify({
        t: "check", key: KEY, key8: KEY.slice(0, 8), head: "e".repeat(40), dirtyDigest: "f".repeat(64),
        refSetHash: "0".repeat(64), exposureSet: [], effectiveTargets: ["git"], rulesHash: RULES,
        artifacts: null, llm: false, verdict: "PASS",
        counts: { INFO: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0, total: 0, blocking: 0, warnings: 0 },
        reportPath: ".border/runs/x/report.json", degraded: false, ts: "2026-10-04T00:00:00.000Z",
      })}\n`,
    );
  };
  const twinFinding = (engine: Finding["engine"]): Finding => ({
    rule: "exfil-rfc1918", severity: "CRITICAL", target: "tree", path: "leaky.txt", line: 1,
    engine, message: "x", valueDigest: RFC_SHA, snippet: "▮▮▮▮",
  });
  const otherFinding = (): Finding => ({ ...twinFinding("gitleaks"), valueDigest: "9".repeat(64) });
  const landingOpts = (allow: readonly { rule: string; match: string; file: string }[]) => {
    const out: string[] = [];
    const err: string[] = [];
    const rows: { verdict: string; blocking: number }[] = [];
    return {
      out, err, rows,
      opts: {
        repoDir: repo, key: KEY, legs: [leg], env: { ...process.env },
        allow,
        out: (l: string) => out.push(l), err: (l: string) => err.push(l),
        record: (r: LandingRecord) => rows.push(r),
        observeRemoteTip: () => "b".repeat(40),
        scanRemoteTip: async () => [twinFinding("secretlint"), twinFinding("gitleaks")],
      },
    };
  };
  seedPass(repo);
  const pinned = landingOpts([{ rule: "exfil-rfc1918", match: RFC_SHA, file: "leaky.txt" }]);
  const exitPinned = await runLandingVerification(pinned.opts);
  assert.equal(exitPinned, null, "a landing hit fully covered by the owner's pins is clean — the double standard is gone");
  assert.equal(pinned.rows.length, 1, `landing must mint exactly one fact row; out=${JSON.stringify(pinned.out)} err=${JSON.stringify(pinned.err)}`);
  assert.equal(pinned.rows[0]?.blocking, 0, "pinned landing reports zero blocking");
  assert.match([...pinned.out, ...pinned.err].join("\n"), /allow/, "the suppression is ECHOED LOUD — never silent");

  const unpinned = landingOpts([]);
  // a finding NOT covered by any pin must still block landing exactly as before (detects, never erases):
  const failOpts = { ...unpinned.opts, scanRemoteTip: async () => [otherFinding(), otherFinding()] };
  const exitBlocked = await runLandingVerification(failOpts);
  assert.equal(exitBlocked, EXIT_BLOCKED, "unpinned landing hits still gate — no doctrine weakened");
  assert.match([...unpinned.out, ...unpinned.err].join("\n"), /ALREADY PUBLIC; border detects, never erases/);
});

// -------------------------------------------------------------------------- T3
test("T3 skip-ledger lens identity: pre-fix range-only keys can never certify the tip-augmented lens; post-fix records self-skip", async () => {
  const input: CheckKeyInput = {
    headSha: "1".repeat(40),
    porcelainDigest: "2".repeat(64),
    rulesHash: "3".repeat(64),
    exposureSet: ["origin.example"],
    refSet: ["refs/heads/main"],
    effectiveTargets: ["git"],
  };
  // The pre-fix derivation was exactly sha256(stableStringify({...input})) with NO
  // lens discriminator (frozen here from src/check/rulesHash.ts computeCheckKey).
  const legacyKey = createHash("sha256").update(stableStringify({ ...input }), "utf8").digest("hex");
  assert.notEqual(computeCheckKey(input), legacyKey, "a tip-lens-augmented check record key must differ from an old range-only record");

  const { repo, bare } = fixtureRepo("t3");
  writeRel(repo, "base.txt", "benign base\n");
  writeRel(repo, "border.yaml", yaml(relative(repo, bare), "[]"));
  gitAddCommit(repo, "init");
  const first = await cli(["check", "--force", "--config", join(repo, "border.yaml")], repo);
  assert.equal(first.code, EXIT_PASS, `clean fixture must PASS: ${first.out.join("\n")} / ${first.err.join("\n")}`);
  const second = await cli(["check", "--config", join(repo, "border.yaml")], repo);
  assert.equal(second.code, EXIT_PASS);
  assert.ok(second.out.some((l) => l.startsWith("SKIP ")), `post-fix records must still self-skip: ${second.out.join("\n")}`);
});

// -------------------------------------------------------------------------- T4
test("T4 degraded tip leg fails loud; broken twin engines skip only their own tip sub-leg (existing degraded semantics preserved)", async () => {
  const { repo, bare } = fixtureRepo("t4");
  writeRel(repo, "base.txt", "benign base\n");
  writeRel(repo, "border.yaml", yaml(relative(repo, bare), "[]"));
  gitAddCommit(repo, "init");

  // (a) unreadable rev ⇒ the shared tip helper THROWS (never returns a silent []):
  //     the check pipeline lets ConfigError ride to the CLI's exit-2 mapping.
  await assert.rejects(
    () => scanTipTreeLens({ repoDir: repo, rev: "f".repeat(40), env: { ...process.env } }),
    /git/,
    "a failing git leg must raise loudly — absence of evidence is never evidence of clean",
  );

  // (b) pipeline-level: a broken git object store ⇒ exit 2, never 0 and never 1.
  const rootTree = gsp(repo, ["rev-parse", "HEAD^{tree}"]).stdout.trim();
  const loose = join(repo, ".git", "objects", rootTree.slice(0, 2), rootTree.slice(2));
  assert.ok(existsSync(loose), "fixture requires the root tree as a loose object");
  chmodSync(loose, 0o000);
  try {
    const res = await cli(["check", "--force", "--config", join(repo, "border.yaml")], repo);
    assert.equal(res.code, EXIT_ERROR, `git corruption must map to exit 2: ${res.out.join("\n")} / ${res.err.join("\n")}`);
  } finally {
    chmodSync(loose, 0o444);
  }

  // (c) skip flags on the shared machinery: the tip scan runs without the gitleaks
  // sub-leg and finds nothing extra; the secretlint twin still runs.
  const { repo: repo2 } = blindspotRepo("t4c", "[]");
  const treeRoot = mkdtempSync(join(tmpdir(), "tiplens-tree-"));
  try {
    const git = makeGit(repo2, { ...process.env });
    const noGitleaks = await scanTipTree(git, treeRoot, "HEAD", { ...process.env }, { skipGitleaks: true });
    assert.ok(noGitleaks.every((f) => f.engine !== "gitleaks"), "skipGitleaks must silence exactly the gitleaks sub-leg");
    assert.ok(noGitleaks.some((f) => f.engine === "secretlint" && f.path === "leaky.txt"), "the secretlint twin still sees tip-only bytes");
    const nativeOnly = await scanTipTree(git, treeRoot, "HEAD", { ...process.env }, { skipGitleaks: true, skipSecretlint: true });
    assert.ok(!nativeOnly.some((f) => f.path === "leaky.txt"), "the rfc1918 HIGH family is twin-only on the tree facet — native-only scan stays silent on it");
  } finally {
    rmSync(treeRoot, { recursive: true, force: true });
  }
});
