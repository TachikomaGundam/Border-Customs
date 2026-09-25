// provenance: .omo/plans/border-exfil-lens.md T6 — golden regression, synthetic
// and CI-in (acceptance 2): every leak CLASS reddens through the REAL pipeline
// (executeCheck = the gate posture), fixtures are runtime-generated so no red
// bytes ever land in git (F3/F4.1 doctrine), and the fixture-band asymmetry
// (tree green / :message red) is asserted exactly. The opt-in truth lane
// (BORDER_EXFIL_TRUTH=1) runs the URL mode against the public AIHR red anchors
// and the purged hr green anchor — skipped in the default suite like the other
// network legs.
import assert from "node:assert/strict";
import { tmpdir } from "node:os";
import { after, test } from "node:test";

import { executeCheck } from "../src/check.ts";
import type { BorderConfig } from "../src/config.ts";
import type { Finding } from "../src/findings.ts";
import { runExfilCore } from "../src/commands/exfil.ts";
import type { Ctx, Subcommand, CommandHandler } from "../src/cli/types.ts";
import { EXFIL_HIGH_FAMILY } from "../src/exfil/severity.ts";
import { requireGitleaks } from "./helpers/require-engines.ts";
import { assembleHost, assembleOctet, gitAddCommit, gitInit, gitRevParseHead, makeFixtureDir, removeDir, writeRel } from "./helpers/fixtures.ts";

requireGitleaks();

const roots: string[] = [];
after(() => {
  for (const d of roots) removeDir(d);
});

function fixture(name: string): string {
  const dir = makeFixtureDir(`exgold-${name}`);
  roots.push(dir);
  return dir;
}

const CFG: BorderConfig = {
  version: 1,
  targets: { git: { remotes: [] } },
  rules: { authors: { emails: ["wiki@sumteclab.com"], names: ["Wiki.js"] }, hosts: [], ips: [], pathPatterns: [], maxFileKB: 500 },
  allow: [],
  engines: { require: ["gitleaks", "secretlint"], trufflehog: false },
};

async function goldenCheck(name: string, files: Record<string, string>, message: string): Promise<readonly Finding[]> {
  const dir = fixture(name);
  gitInit(dir);
  for (const [rel, content] of Object.entries(files)) writeRel(dir, rel, content);
  gitAddCommit(dir, message);
  const outcome = await executeCheck({ repoDir: dir, cfg: CFG, configDigest: "a".repeat(64), effectiveTargets: ["git"] });
  assert.equal(outcome.degraded, false, `${name}: engines must be healthy for a golden assertion`);
  return outcome.report.findings;
}

test("GOLDEN-RED: every class fires through the gate — twins CRITICAL on the tree, native MEDIUM family, :message red with sha attribution", async () => {
  const REAL_1918 = assembleOctet("10.31.4", "5");
  const SSH = assembleHost("synthuser", "synthdb", "internal");
  const findings = await goldenCheck(
    "red",
    {
      "infra/notes.md":
        `mirror ${REAL_1918} reachable as ${SSH}\n` +
        `key copied from /home/synthuser/.ssh/id_ed25519\n` +
        `rotate prod.env and upload with ~/.pypirc\n` +
        "The build box runs Ubuntu 22.04 and there is no docker installed.\n",
    },
    "docs: ship the infra notes",
  );
  const byRule = new Map(findings.filter((f) => f.rule.startsWith("exfil-")).map((f) => [f.rule, f]));
  const gl = findings.filter((f) => f.rule === "exfil-rfc1918" && f.engine === "gitleaks");
  const lint = findings.filter((f) => f.rule === "exfil-rfc1918" && f.engine === "secretlint");
  assert.ok(gl.length > 0 && lint.length > 0, "twin pair both flag the real-shape literal on the tree");
  assert.equal(gl[0]?.severity, "CRITICAL");
  assert.ok(findings.some((f) => f.rule === "exfil-ssh-target" && f.severity === "CRITICAL"));
  for (const rule of ["exfil-home-path", "exfil-cred-location", "exfil-host-profile"]) {
    const f = byRule.get(rule);
    assert.ok(f && f.severity === "MEDIUM" && f.engine === "border-exfil", `native MEDIUM family补发: ${rule}`);
  }
  assert.ok(!findings.some((f) => f.rule === "exfil-rfc1918" && f.engine === "border-exfil"), "native never double-emits the HIGH family on tree");
  assert.ok(!findings.some((f) => f.rule.endsWith(":message")), "benign message ⇒ no :message ids here (the message story is GOLDEN-MSG's job)");
});

test("GOLDEN-MSG: synthetic IP in the commit MESSAGE reddens :message with sha attribution (incident exhibit class)", async () => {
  const findings = await goldenCheck(
    "msg",
    { "README.md": "benign project notes\n" },
    `sync the mirror ${assembleOctet("10.31.4", "5")} nightly`,
  );
  const m = findings.filter((f) => f.rule === "exfil-rfc1918:message");
  assert.equal(m.length, 1);
  assert.equal(m[0]?.severity, "HIGH");
  assert.match(m[0]?.path ?? "", /^[0-9a-f]{40}$/);
  assert.equal(m[0]?.path, gitRevParseHead(roots[roots.length - 1] ?? ""), "attribution names the offending commit");
  assert.equal(m[0]?.line, 1);
  assert.ok(!findings.some((f) => (f.rule === "exfil-rfc1918" || f.rule === "exfil-ssh-target") && !f.rule.endsWith(":message")), "tree facet stays clean — the message is the only leak (plan: 树干净 ⇒ message 必红)");
});

test("GOLDEN-GREEN: benign repo lights no exfil id at all", async () => {
  const findings = await goldenCheck("green", { "README.md": "# project\ntotally benign content here\n" }, "docs: init");
  assert.deepEqual(findings.filter((f) => f.rule.startsWith("exfil-")), []);
});

test("GOLDEN-BAND: 10.200/16 tree shapes are green on EVERY channel while the same literals fire :message (matrix asymmetry)", async () => {
  const findings = await goldenCheck(
    "band",
    { "docs/fixture-refs.md": "golden anchor 10.200.30.40 and ssh synthuser@10.200.30.40 live in the fixture band — hostname shapes stay armed (GOLDEN-RED covers those)\n" },
    "deploy mirror 10.200.30.40 via synthuser@10.200.30.40 nightly",
  );
  assert.ok(!findings.some((f) => f.rule === "exfil-rfc1918"), "band literal green on twins + native");
  assert.ok(!findings.some((f) => f.rule === "exfil-ssh-target"), "band ssh host green on twins (F2 parity)");
  const msgRules = new Set(findings.filter((f) => f.rule.endsWith(":message")).map((f) => f.rule));
  assert.ok(msgRules.has("exfil-rfc1918:message"), "band fires on the message facet (golden red anchor rides :message)");
  assert.ok(msgRules.has("exfil-ssh-target:message"), "band ssh host fires the message facet too (message facet ignores bands — both tokens in the message)");
  assert.ok(!findings.some((f) => f.rule === "exfil-ssh-target" && f.severity === "CRITICAL"), "…while identical tree bytes are green on the twins (per-rule band allowlists + negative classes)");
});

// ---------------------------------------------------------------- opt-in truth lane (plan §真值腿, R3)

function truthCtx(argv: readonly string[]): Ctx & { out: string[] } {
  const out: string[] = [];
  return {
    command: "exfil",
    flags: { force: false, yes: false, llm: false, json: true },
    positionals: argv,
    cwd: tmpdir(),
    env: { ...process.env },
    stdout: (l) => out.push(l),
    stderr: () => {},
    handlers: {} as Record<Subcommand, CommandHandler>,
    out,
  };
}

test("TRUTH-LANE (opt-in BORDER_EXFIL_TRUTH=1): public AIHR main + v0.4.0 red-anchor the three incident files; purged hr green", async (t) => {
  const mode = process.env.BORDER_EXFIL_TRUTH;
  if (mode !== "1" && mode !== "2") {
    t.skip("truth lane is opt-in (BORDER_EXFIL_TRUTH=1 live anchors, =2 post-H-1 archive mode) — the default CI suite stays offline");
    return;
  }
  const HIGH_IDS = new Set<string>(EXFIL_HIGH_FAMILY);
  async function lens(url: string, ref: string): Promise<{ findings: Finding[] }> {
    const ctx = truthCtx([url, ref]);
    await runExfilCore(ctx); // the URL sandbox is created and destroyed inside the handler (finally-rm)
    return { findings: (JSON.parse(ctx.out.join("")) as { findings: Finding[] }).findings };
  }
  // presence check first: proves the lane fetched the RIGHT repo regardless of anchor state.
  const INCIDENT_FILES = ["docs/PUSH.md", "scripts/README-build.md", "opencode_plugin/install-cli.js"];
  const red = await lens("https://github.com/TachikomaGundam/AIHR.git", "main");
  const allPaths = new Set(red.findings.map((f) => f.path ?? ""));
  assert.ok(INCIDENT_FILES.some((f) => allPaths.has(f)), "fetched tree must still contain the incident files (any finding class proves it) — otherwise the lane scanned the wrong repo/ref");
  const redHits = new Set(red.findings.filter((f) => HIGH_IDS.has(f.rule)).map((f) => f.path ?? ""));
  if (redHits.size === 0) {
    // Lifetime clause (plan §真值腿): the red-anchor expectation is alive only until
    // H-1 lands. Public main going identity-clean = landed (the F-L4 live-rewrite
    // observation recorded the owner's purge racing the audit) — the flip to green is
    // BY DESIGN and not a suite failure; the lane degrades to evidence-archive-backed
    // (.omo/evidence/F-L4-2026-09-25-aihr-exfil-incident.md keeps the red record).
    console.log("truth lane: red anchors EXPIRED (public AIHR main identity-clean — H-1 landed); archive-backed per plan lifetime clause");
  } else {
    for (const file of INCIDENT_FILES) {
      assert.ok(red.findings.some((f) => HIGH_IDS.has(f.rule) && f.path === file), `red anchor must hit ${file} while the leak is public (F-L4 §公开面 table)`);
    }
    assert.ok(red.findings.some((f) => HIGH_IDS.has(f.rule) && f.rule === "exfil-rfc1918"), "pre-landing main must carry RFC1918 reds");
  }
  const tag = await lens("https://github.com/TachikomaGundam/AIHR.git", "v0.4.0");
  if (redHits.size > 0) {
    for (const file of INCIDENT_FILES) {
      assert.ok(tag.findings.some((f) => HIGH_IDS.has(f.rule) && f.path === file), "v0.4.0 tag tree must anchor red alongside main (H-2 pending)");
    }
  } else {
    console.log(`truth lane: v0.4.0 identity-class findings = ${String(tag.findings.filter((f) => HIGH_IDS.has(f.rule)).length)} (archive-backed while H-2 tag disposition is pending)`);
  }

  const green = await lens("file:///home/lab/workspace/harness/hr", "refs/heads/main");
  assert.deepEqual(green.findings.filter((f) => HIGH_IDS.has(f.rule)), [], "purged hr HEAD carries no identifier-class leak");
    console.log(`truth lane green-anchor residue (non-blocking MEDIUM, informational): ${String(green.findings.length)}`);
});
