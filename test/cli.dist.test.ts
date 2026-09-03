// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 7
//
// AC2: child_process tests against the REAL dist bundle (`npm run build` in
// before()), incl. findings-spy wrappers that plant a gate verdict through the
// run(ctx) registry across a process boundary — proving dry-run exits with
// the verdict the gate would produce (m-R5-a) without todo 10's engine
// pipeline existing yet. Every push assertion pins that the bare remote sha
// is unchanged afterwards: dry-run performed ZERO mutations.
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { before, test } from "node:test";

import { EXIT_BLOCKED, EXIT_ERROR, EXIT_PASS } from "../src/cli/exit.ts";
import { usage } from "../src/cli.ts";
import { GIT_PUSH_DRY_RUN } from "../src/commands/push.ts";
import type { Finding } from "../src/findings.ts";
import { BORDER_ROOT, removeDir, writeRel } from "./helpers/fixtures.ts";
import { borderYaml, gitIn, makeRemoteFixture } from "./helpers/cli-fixtures.ts";

// child-process AC2 runs the freshly built dist bundle
before(() => {
  execFileSync("npm", ["run", "build"], { cwd: BORDER_ROOT, stdio: "pipe" });
});

function distBin(): string {
  return join(BORDER_ROOT, "dist", "index.js");
}

function runDist(args: readonly string[], cwd: string): { code: number | null; stdout: string; stderr: string } {
  const r = spawnSync(process.execPath, [distBin(), ...args], { cwd, encoding: "utf8" });
  return { code: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
}

/**
 * Findings-spy across a process boundary: the wrapper replaces the registry's
 * check handler with a spy that plants a verdict via exitCodeFromFindings,
 * then drives the real push dry-run through the real cli.ts dispatch.
 */
function runGateSpy(mode: "clean" | "blocked", work: string, root: string): { code: number; out: string } {
  const wrapper = join(root, "gate-spy-wrapper.mjs");
  const findingsPath = join(root, "planted-findings.json");
  writeFileSync(
    wrapper,
    `import { writeFileSync } from "node:fs";
process.chdir(${JSON.stringify(work)});
const BORDER = ${JSON.stringify(BORDER_ROOT)};
const { run } = await import(\`file://\${BORDER}/src/cli.ts\`);
const { setHandler } = await import(\`file://\${BORDER}/src/commands/index.ts\`);
const { exitCodeFromFindings } = await import(\`file://\${BORDER}/src/cli/exit.ts\`);
const FINDING = {
  rule: "aws-access-token",
  severity: "CRITICAL",
  target: "git",
  engine: "unit-spy",
  message: "planted by cli.test gate spy",
  valueDigest: "a".repeat(64),
  snippet: "\\u25ae\\u25ae\\u25ae\\u25ae",
};
setHandler("check", () => {
  if (process.argv[2] === "blocked") {
    writeFileSync(process.argv[3], JSON.stringify([FINDING], null, 2));
    return exitCodeFromFindings([FINDING]);
  }
  return exitCodeFromFindings([]);
});
const lines = [];
const code = await run(["push"], (l) => lines.push(l), (l) => lines.push(l));
process.stdout.write(JSON.stringify({ code, out: lines.join("\\n") }));
`,
  );
  const r = spawnSync(
    process.execPath,
    ["--import", join(BORDER_ROOT, "tools/register-ts.mjs"), wrapper, mode, findingsPath],
    { cwd: work, encoding: "utf8" },
  );
  assert.equal(r.status, 0, `wrapper must exit cleanly: ${r.stderr}`);
  return JSON.parse(r.stdout ?? "{}") as { code: number; out: string };
}

test("--help exits 0 and prints the full G9 flag table + subcommands + exit-code contract", () => {
  const r = runDist(["--help"], BORDER_ROOT);
  assert.equal(r.code, EXIT_PASS);
  assert.equal(r.stdout, `${usage()}\n`);
  const help = usage();
  for (const flag of ["--config <path>", "--targets <git,npm,pypi>", "--force", "--yes", "--require-engine <list>", "--llm", "--json"]) {
    assert.ok(help.includes(flag), `flag table missing ${flag}`);
  }
  for (const cmd of ["check", "push", "status", "llm-request", "llm-ingest"]) {
    assert.ok(help.includes(cmd), `help missing subcommand ${cmd}`);
  }
  assert.match(help, /0 pass/);
  assert.match(help, /1 gate-blocked/);
  assert.match(help, /2 config\/tool error/);
});

test("unknown subcommand ⇒ exit 2 + usage on stdout + one stderr line", () => {
  const r = runDist(["frobnicate"], BORDER_ROOT);
  assert.equal(r.code, EXIT_ERROR);
  assert.match(r.stderr, /unknown command/i);
  assert.equal(r.stderr.trim().split("\n").length, 1);
  assert.match(r.stdout, /usage: border <command>/);
});

test("bad flag ⇒ exit 2 + usage; bare invocation ⇒ exit 2", () => {
  const bad = runDist(["push", "--bogus"], BORDER_ROOT);
  assert.equal(bad.code, EXIT_ERROR);
  assert.match(bad.stderr, /--bogus/);
  assert.match(bad.stdout, /usage: border <command>/);
  const bare = runDist([], BORDER_ROOT);
  assert.equal(bare.code, EXIT_ERROR);
  assert.match(bare.stderr, /unknown command/i);
});

test("push on a clean fixture: stdout carries DRY-RUN + git push --dry-run, bare sha unchanged", () => {
  const fx = makeRemoteFixture();
  try {
    writeRel(fx.work, "border.yaml", borderYaml([{ name: "origin", url: fx.bare }]));
    const before = gitIn(fx.root, fx.bare, ["rev-parse", "main"]);
    const r = runDist(["push"], fx.work);
    assert.match(r.stdout, /DRY-RUN/);
    assert.ok(r.stdout.includes(GIT_PUSH_DRY_RUN), "grep-guard string must survive bundling");
    assert.ok(r.stdout.includes("origin"));
    // post todo-10 the dist bundle wires the REAL check; dist cannot resolve
    // the vendored gitleaks assets yet (files:["dist"] packaging is todo 20/21),
    // so the gate fails CLOSED — exactly the "never a fake 0" contract:
    assert.match(r.stderr, /engine run error|not implemented/i, "unwired gate ⇒ fail-closed 2, never a fake 0");
    assert.equal(r.code, EXIT_ERROR);
    assert.equal(gitIn(fx.root, fx.bare, ["rev-parse", "main"]), before);
  } finally {
    removeDir(fx.root);
  }
});

test("gate-blocked fixture (findings spy): dry-run exits 1, bare sha unchanged, CRITICAL planted", () => {
  const fx = makeRemoteFixture();
  try {
    writeRel(fx.work, "border.yaml", borderYaml([{ name: "origin", url: fx.bare }]));
    const before = gitIn(fx.root, fx.bare, ["rev-parse", "main"]);
    const spy = runGateSpy("blocked", fx.work, fx.root);
    assert.equal(spy.code, EXIT_BLOCKED);
    assert.match(spy.out, /DRY-RUN/);
    assert.ok(spy.out.includes(GIT_PUSH_DRY_RUN));
    assert.equal(gitIn(fx.root, fx.bare, ["rev-parse", "main"]), before);
    const planted = JSON.parse(readFileSync(join(fx.root, "planted-findings.json"), "utf8")) as Finding[];
    assert.equal(planted[0]?.severity, "CRITICAL");
  } finally {
    removeDir(fx.root);
  }
});

test("clean gate (findings spy over a leak-free repo): dry-run exits 0, sha unchanged", () => {
  const fx = makeRemoteFixture();
  try {
    writeRel(fx.work, "border.yaml", borderYaml([{ name: "origin", url: fx.bare }]));
    const before = gitIn(fx.root, fx.bare, ["rev-parse", "main"]);
    const spy = runGateSpy("clean", fx.work, fx.root);
    assert.equal(spy.code, EXIT_PASS);
    assert.match(spy.out, /DRY-RUN/);
    assert.equal(gitIn(fx.root, fx.bare, ["rev-parse", "main"]), before);
  } finally {
    removeDir(fx.root);
  }
});

test("dist status/llm stubs exit 2 without touching the repo", () => {
  for (const cmd of ["status", "llm-request", "llm-ingest"] as const) {
    const r = runDist([cmd], BORDER_ROOT);
    assert.equal(r.code, EXIT_ERROR, cmd);
    assert.match(r.stderr, /not implemented/i, cmd);
  }
});
