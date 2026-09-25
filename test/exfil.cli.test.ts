// provenance: .omo/plans/border-exfil-lens.md T4 — `border exfil` surface and
// exit tri-state: SUBCOMMANDS/usage/registry, bad-args & unresolvable-ref ⇒ 2,
// clean ref ⇒ 0, MEDIUM-tree ⇒ printed & released (0), planted commit message
// red only under --deep (:message rides deep, lead ruling), URL mode via an
// offline file:// remote with guaranteed temp-repo destruction, and the plan
// boundary pin: "exfil" is NOT added to the plugin command allowlist.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";

import { run, usage } from "../src/cli.ts";
import { handlers } from "../src/commands/index.ts";
import { SUBCOMMANDS } from "../src/cli/types.ts";
import { EXIT_BLOCKED, EXIT_ERROR, EXIT_PASS } from "../src/cli/exit.ts";
import type { Report } from "../src/findings.ts";
import { BORDER_ROOT, assembleOctet, gitAddCommit, gitInit, makeFixtureDir, removeDir, writeRel } from "./helpers/fixtures.ts";
import { requireGitleaks } from "./helpers/require-engines.ts";

requireGitleaks(); // the fast face's twin channel is the vendored-gitleaks leg — CI provisions it (README posture)

const roots: string[] = [];
after(() => {
  for (const d of roots) removeDir(d);
});

function fixture(name: string): string {
  const dir = makeFixtureDir(`excli-${name}`);
  roots.push(dir);
  return dir;
}

async function cli(argv: readonly string[], cwd: string) {
  const out: string[] = [];
  const err: string[] = [];
  const code = await run(argv, (l) => out.push(l), (l) => err.push(l), { cwd });
  return { code, out, err };
}

/** repo: one benign commit; messageIp adds the second commit whose MESSAGE carries the synthetic IP. */
function exfilRepo(name: string, treeText = "benign project notes\n"): string {
  const dir = fixture(name);
  gitInit(dir);
  writeRel(dir, "README.md", treeText);
  gitAddCommit(dir, "init");
  return dir;
}

test("surface: SUBCOMMANDS closed set + usage table + registry all name exfil", () => {
  assert.ok((SUBCOMMANDS as readonly string[]).includes("exfil"), "SUBCOMMANDS gained exfil");
  const u = usage();
  assert.match(u, /^ {2}exfil {2,}\S/m, "usage lists the command");
  assert.match(u, /subcommands: [^\n]*\bexfil\b/, "footer enumerates it");
  assert.equal(typeof handlers.exfil, "function");
});

test("no arguments is a bad-args tool error: exit 2 with usage, never a scan of nothing", async () => {
  const dir = exfilRepo("noargs");
  const r = await cli(["exfil"], dir);
  assert.equal(r.code, EXIT_ERROR);
  assert.match(r.err.join("\n"), /expects <ref\|url>/);
  assert.ok(r.out.join("\n").includes("usage: border <command>"), "argument mistakes earn the usage table");
});

test("unresolvable ref ⇒ exit 2 loud cannot-answer", async () => {
  const dir = exfilRepo("badref");
  const r = await cli(["exfil", "refs/heads/no-such-branch"], dir);
  assert.equal(r.code, EXIT_ERROR);
  assert.equal(r.err.length, 1, "one sanitized stderr line");
});

test("clean ref exits 0; MEDIUM tree findings are printed and released (0, not 1)", async () => {
  const clean = exfilRepo("clean");
  const c = await cli(["exfil", "refs/heads/main"], clean);
  assert.equal(c.code, EXIT_PASS);
  assert.match(c.out.join("\n"), /PASS: 0 finding\(s\)/);

  const leaky = exfilRepo("medium");
  writeRel(leaky, "notes.md", "copy from /home/synthuser/.ssh/config and rotate staging.env\n");
  gitAddCommit(leaky, "notes");
  const m = await cli(["exfil", "refs/heads/main"], leaky);
  assert.equal(m.code, EXIT_PASS, "MEDIUM prints and passes (plan §S2 exit contract)");
  const lines = m.out.join("\n");
  assert.match(lines, /MEDIUM exfil-home-path/);
  assert.match(lines, /MEDIUM exfil-cred-location/);
  assert.match(lines, /notes\.md:1/, "file:line attribution on the human face");
});

test("--deep rides the :message family: tree-clean + message-red ⇒ fast 0, deep 1", async () => {
  const dir = fixture("deep");
  gitInit(dir);
  writeRel(dir, "README.md", "benign project notes\n");
  gitAddCommit(dir, "sync the mirror 10.200.30.40 nightly");

  const fast = await cli(["exfil", "refs/heads/main", "--json"], dir);
  assert.equal(fast.code, EXIT_PASS, "commit messages are NOT the fast face's business (lead ruling: :message rides deep)");
  const fastReport = JSON.parse(fast.out.join("")) as Report;
  assert.equal(fastReport.findings.length, 0);
  assert.equal(fastReport.verdict, "PASS");

  const deep = await cli(["exfil", "refs/heads/main", "--deep", "--json"], dir);
  assert.equal(deep.code, EXIT_BLOCKED, "a message-only leak blocks the fast face exactly once --deep admits the facet");
  const report = JSON.parse(deep.out.join("")) as Report;
  assert.equal(report.verdict, "FAIL");
  assert.equal(report.counts.blocking, 1);
  const f = report.findings.find((x) => x.rule === "exfil-rfc1918:message");
  assert.ok(f, "the :message finding is present");
  assert.equal(f?.severity, "HIGH");
  assert.match(f?.path ?? "", /^[0-9a-f]{40}$/, "sha attribution in the JSON report");
  assert.ok(!JSON.stringify(report).includes("10.200.30.40"), "G23: the report never echoes the raw address");
  assert.match(report.rulesHash, /^[0-9a-f]{64}$/, "fast-face rule identity is present");
});

test("URL mode: offline file:// remote is fetched, scanned --deep, and the temp repo is destroyed", async () => {
  const seed = exfilRepo("urlseed");
  const bare = mkdtempSync(join(tmpdir(), "exfil-bare-"));
  roots.push(bare);
  const g = (args: readonly string[], cwd: string) => {
    const r = spawnSync("git", args, { cwd, encoding: "utf8" });
    if (r.status !== 0) throw new Error(`git ${args.join(" ")}: ${r.stderr}`);
  };
  g(["init", "--bare", "-b", "main"], bare);
  g(["-C", seed, "remote", "add", "origin", bare], seed);
  g(["-C", seed, "push", "-q", "origin", "refs/heads/main:refs/heads/main"], seed);

  const outside = await cli(["exfil", `file://${bare}`, "refs/heads/main"], seed);
  assert.equal(outside.code, EXIT_PASS);

  writeRel(seed, "leak.md", `peer ${assembleOctet("172.20.5", "6")} pingback\n`);
  g(["-C", seed, "add", "leak.md"], seed);
  g(["-C", seed, "-c", "user.name=Wiki.js", "-c", "user.email=bot@gate-corp.com", "commit", "-m", "add node list"], seed);
  g(["-C", seed, "push", "-q", "origin", "refs/heads/main:refs/heads/main"], seed);
  const cwdScratch = fixture("urlcwd"); // run from a dir that is NOT the fetched repo
  const hit = await cli(["exfil", `file://${bare}`, "refs/heads/main", "--deep", "--json"], cwdScratch);
  assert.equal(hit.code, EXIT_BLOCKED, "history blob (172.20/12) reddens the deep face over URL");
  const report = JSON.parse(hit.out.join("")) as Report;
  assert.ok(report.findings.some((x) => x.rule === "exfil-rfc1918" && x.target === "tree"));
  assert.ok(report.exposureSet[0]?.endsWith(bare) && report.exposureSet[0]?.startsWith("file:"), `sanitized file:// exposure recorded, got ${JSON.stringify(report.exposureSet)}`);
  const leftovers = readdirSync(tmpdir()).filter((d) => d.startsWith("border-exfil-"));
  assert.deepEqual(leftovers, [], "every fetched sandbox is destroyed even on a FAIL verdict");
});

test("plugin boundary (plan §S2): 'exfil' is NOT added to the opencode adapter's command allowlist", () => {
  const plugin = readFileSync(join(BORDER_ROOT, "plugin", "border.ts"), "utf8");
  const m = /const ALLOWED_COMMANDS: readonly string\[\] = \[([\s\S]*?)\];/.exec(plugin);
  assert.ok(m, "the closed allowlist block exists");
  assert.ok(!m[1]?.includes('"exfil"'), "ledger follow-up wave decides plugin surface — not this one");
});
