// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 7
//
// CLI surface + exit-code contract (G9/G10/G11), in-process layers:
//  1. AC1 translation matrix — every row of src/cli/exit.ts, unit-level.
//  2. run(ctx) registry seam — flags reach handlers, push dry-run propagates
//     the gate verdict (clean⇒0, gate-blocked⇒1, gate-unavailable⇒2), --yes
//     never mutates before todos 15/16 land.
// Child-process tests on the real dist bundle live in cli.dist.test.ts.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { test } from "node:test";

import {
  ENGINE_EXIT_TABLE,
  EXIT_BLOCKED,
  EXIT_ERROR,
  EXIT_PASS,
  UnknownArgError,
  exitCodeFromFindings,
  translateEngineCode,
  translateError,
} from "../src/cli/exit.ts";
import { run, usage } from "../src/cli.ts";
import { handlers, setHandler } from "../src/commands/index.ts";
import { DRY_RUN_PREFIX, GIT_PUSH_DRY_RUN } from "../src/commands/push.ts";
import { ConfigError } from "../src/config.ts";
import { EnginePolicyError } from "../src/engines/policy.ts";
import { EngineMissingError, EngineRunError } from "../src/engines/support.ts";
import { InvalidFindingError, type Finding, type Severity, type Verdict } from "../src/findings.ts";
import { BORDER_ROOT, gitRevParseHead, makeFixtureDir, removeDir, writeRel } from "./helpers/fixtures.ts";
import { borderYaml, gitIn, makeRemoteFixture } from "./helpers/cli-fixtures.ts";
import type { CommandHandler, Ctx, Subcommand } from "../src/cli/types.ts";

function sevFinding(severity: Severity): Finding {
  return {
    rule: "test-rule",
    severity,
    target: "git",
    engine: "unit",
    message: "planted",
    valueDigest: "a".repeat(64),
    snippet: "\u25ae\u25ae\u25ae\u25ae",
  };
}

type RunResult = { readonly code: number; readonly out: readonly string[]; readonly err: readonly string[] };

async function runCli(argv: readonly string[], overrides: Parameters<typeof run>[3] = {}): Promise<RunResult> {
  const out: string[] = [];
  const err: string[] = [];
  const code = await run(
    argv,
    (line) => {
      out.push(line);
    },
    (line) => {
      err.push(line);
    },
    overrides,
  );
  return { code, out, err };
}

// ------------------------------------------------- AC1: exit-code matrix (unit)

test("AC1 G11 table: gitleaks 0⇒0 clean, 1⇒findings, 126 and any other native code⇒2", () => {
  assert.equal(translateEngineCode("gitleaks", 0), EXIT_PASS);
  assert.equal(translateEngineCode("gitleaks", 1), "findings");
  assert.equal(translateEngineCode("gitleaks", 126), EXIT_ERROR, "126 is a usage error, NEVER 'clean'");
  assert.equal(translateEngineCode("gitleaks", 2), EXIT_ERROR);
});

test("AC1 G11 table: trufflehog 183⇒findings(1), secretlint 1⇒findings and 2⇒2", () => {
  assert.equal(translateEngineCode("trufflehog", 183), "findings");
  assert.equal(translateEngineCode("trufflehog", 0), EXIT_PASS);
  assert.equal(translateEngineCode("secretlint", 1), "findings");
  assert.equal(translateEngineCode("secretlint", 2), EXIT_ERROR);
  assert.equal(translateEngineCode("secretlint", 3), EXIT_ERROR);
});

test("AC1 G11 table: unknown engine or unmapped code fails closed to 2; table rows are consistent", () => {
  assert.equal(translateEngineCode("mystery-engine", 0), EXIT_ERROR);
  assert.equal(translateEngineCode("mystery-engine", 1), EXIT_ERROR);
  assert.ok(ENGINE_EXIT_TABLE.length >= 8);
  for (const row of ENGINE_EXIT_TABLE) {
    assert.ok(
      row.border === EXIT_PASS || row.border === EXIT_BLOCKED || row.border === EXIT_ERROR || row.border === "findings",
      `bad border column for ${row.engine} ${row.code}`,
    );
    assert.equal(translateEngineCode(row.engine, row.code), row.border, `table row must match translator: ${row.engine} ${row.code}`);
  }
  assert.deepEqual(ENGINE_EXIT_TABLE.find((r) => r.engine === "gitleaks" && r.code === 126)?.border, EXIT_ERROR);
});

test("AC1 findings→exit: CRITICAL⇒1, HIGH⇒1, MEDIUM/LOW/INFO-only⇒0, empty⇒0", () => {
  assert.equal(exitCodeFromFindings([sevFinding("CRITICAL")]), EXIT_BLOCKED);
  assert.equal(exitCodeFromFindings([sevFinding("HIGH")]), EXIT_BLOCKED);
  assert.equal(exitCodeFromFindings([sevFinding("MEDIUM")]), EXIT_PASS);
  assert.equal(exitCodeFromFindings([sevFinding("LOW"), sevFinding("INFO"), sevFinding("MEDIUM")]), EXIT_PASS);
  assert.equal(exitCodeFromFindings([]), EXIT_PASS);
});

test("AC1 verdict→exit: PASS⇒0, FAIL⇒1 (never a misleading 0 for a blocking verdict)", () => {
  const verdict = (v: Verdict): number => exitCodeFromFindings(v === "FAIL" ? [sevFinding("HIGH")] : []);
  assert.equal(verdict("PASS"), EXIT_PASS);
  assert.equal(verdict("FAIL"), EXIT_BLOCKED);
});

function errno(code: string, message: string): Error {
  return Object.assign(new Error(message), { code });
}

test("AC1 translateError: every typed config/tool error maps to exit 2", () => {
  const rows: readonly [string, Error][] = [
    ["ConfigError unreadable", new ConfigError("unreadable", "config file not found: /x/border.yaml")],
    ["ConfigError malformed-yaml", new ConfigError("malformed-yaml", "bad yaml at line 3")],
    ["EnginePolicyError", new EnginePolicyError("required engine 'trufflehog' disabled by require-override")],
    ["EngineRunError gitleaks 126", new EngineRunError("gitleaks exited 126; only 0 (clean) and 1 (findings) are translatable — any other code (incl. 126 usage error) is a border exit-2 tool failure. stderr: bad flag", 126)],
    ["EngineMissingError", new EngineMissingError("engine binary 'gitleaks' not found; border fails closed — install it or pass binPath")],
    ["UnknownArgError", new UnknownArgError("unknown option '--bogus'")],
    ["InvalidFindingError", new InvalidFindingError("finding[0]: valueDigest is not 64-hex")],
    ["spawn EACCES", errno("EACCES", "spawn secretlint EACCES")],
    ["spawn ENOENT", errno("ENOENT", "spawn gitleaks ENOENT")],
    ["bare Error", new Error("something else went wrong")],
  ];
  for (const [label, err] of rows) {
    const t = translateError(err);
    assert.equal(t.code, EXIT_ERROR, `row: ${label}`);
    assert.equal(t.message.includes("\n"), false, `one-line stderr, row: ${label}`);
    assert.ok(t.message.length <= 600, `capped, row: ${label}`);
    assert.ok(t.message.length > label.length, `non-empty, row: ${label}`);
  }
});

test("AC1 translateError: gitleaks exit 126 message keeps its translated detail", () => {
  const t = translateError(new EngineRunError("gitleaks exited 126; only 0 (clean) and 1 (findings) are translatable", 126));
  assert.match(t.message, /engine run error/);
  assert.match(t.message, /126/);
});

test("AC1 translateError: multi-line collapsed, credential-bearing URLs sanitized, length capped", () => {
  const multi = translateError(new Error("first line\nsecond  line\r\nthird"));
  assert.equal(multi.message, "unexpected error: first line second line third");
  const url = translateError(new ConfigError("unreadable", "cannot reach https://user:pass@github.com/x?token=***"));
  assert.equal(url.message.includes("user:pass"), false, "credentials must not echo");
  assert.equal(url.message.includes("token="), false, "sensitive query must not echo");
  assert.match(url.message, /github\.com/);
  const long = translateError(new Error("z".repeat(5000)));
  assert.ok(long.message.length <= 600);
});

// ------------------------------------------------- run(ctx) registry seam

test("--yes reaches the handler as a parsed boolean flag (registry spy)", async () => {
  let seen: Ctx | undefined;
  const restore = setHandler("push", (ctx) => {
    seen = ctx;
    return EXIT_PASS;
  });
  try {
    const r = await runCli(["push", "--yes"]);
    assert.equal(r.code, EXIT_PASS);
  } finally {
    restore();
  }
  assert.ok(seen);
  assert.equal(seen.command, "push");
  assert.equal(seen.flags.yes, true);
});

test("full G9 flag table parses into ctx.flags with typed values", async () => {
  let seen: Ctx | undefined;
  const restore = setHandler("check", (ctx) => {
    seen = ctx;
    return EXIT_PASS;
  });
  try {
    const r = await runCli([
      "check",
      "--config", "custom.yaml",
      "--targets", "git, npm ,pypi",
      "--force",
      "--require-engine", "gitleaks,secretlint",
      "--llm",
      "--json",
    ]);
    assert.equal(r.code, EXIT_PASS);
  } finally {
    restore();
  }
  assert.ok(seen);
  assert.equal(seen.flags.config, "custom.yaml");
  assert.deepEqual(seen.flags.targets, ["git", "npm", "pypi"]);
  assert.equal(seen.flags.force, true);
  assert.deepEqual(seen.flags.requireEngine, ["gitleaks", "secretlint"]);
  assert.equal(seen.flags.llm, true);
  assert.equal(seen.flags.json, true);
  assert.equal(seen.flags.yes, false);
});

test("invalid --targets value is rejected as a tool error (exit 2 + usage)", async () => {
  const r = await runCli(["check", "--targets", "docker"]);
  assert.equal(r.code, EXIT_ERROR);
  assert.match(r.err.join("\n"), /unknown target 'docker'/i);
});

test("every subcommand dispatches to its registry handler; llm-ingest keeps positional", async () => {
  const seen: Subcommand[] = [];
  const spies: [Subcommand, CommandHandler][] = (Object.keys(handlers) as Subcommand[]).map((name) => [
    name,
    (ctx) => {
      seen.push(ctx.command);
      assert.equal(typeof ctx.cwd, "string");
      return EXIT_PASS;
    },
  ]);
  const restores = spies.map(([name, fn]) => setHandler(name, fn));
  try {
    for (const [name] of spies) {
      const r = await runCli(name === "llm-ingest" ? [name, "findings.json"] : [name]);
      assert.equal(r.code, EXIT_PASS, name);
    }
  } finally {
    for (const restore of restores) restore();
  }
  assert.equal(seen.filter((s) => s === "push").length, 1);
  assert.equal(seen.filter((s) => s === "llm-ingest").length, 1);
});

test("handlers swap is visible to run() without touching cli.ts (registry IS the seam)", () => {
  const original = handlers.check;
  const restore = setHandler("check", () => EXIT_PASS);
  try {
    assert.notEqual(handlers.check, original);
  } finally {
    restore();
  }
  assert.equal(handlers.check, original);
});

test("push ctx seen by a handler carries env + writers + live registry", async () => {
  let seen: Ctx | undefined;
  const restore = setHandler("push", (ctx) => {
    seen = ctx;
    return EXIT_PASS;
  });
  try {
    await runCli(["push", "--yes"]);
  } finally {
    restore();
  }
  assert.ok(seen);
  assert.equal(typeof seen.env, "object");
  assert.equal(seen.handlers, handlers);
  assert.ok(Array.isArray(seen.positionals));
});

// ------------------------------------------------- push dry-run contract (in-process)

test("push dry-run prints the per-remote plan and propagates a clean gate verdict (0)", async () => {
  const fx = makeRemoteFixture();
  try {
    writeRel(fx.work, "border.yaml", borderYaml([{ name: "origin", url: fx.bare }]));
    const restore = setHandler("check", () => EXIT_PASS);
    try {
      const r = await runCli(["push"], { cwd: fx.work });
      assert.equal(r.code, EXIT_PASS, "clean⇒0 — never a misleading 0 for a blocked gate");
      assert.ok(r.out.some((l) => l.includes(DRY_RUN_PREFIX) && l.includes(GIT_PUSH_DRY_RUN) && l.includes("origin")));
    } finally {
      restore();
    }
    assert.equal(gitIn(fx.root, fx.bare, ["rev-parse", "main"]).trim(), gitRevParseHead(fx.work));
  } finally {
    removeDir(fx.root);
  }
});

test("push dry-run exits 1 when the gate would block, and exits 2 fail-closed when the gate errors out", async () => {
  const fx = makeRemoteFixture();
  try {
    writeRel(fx.work, "border.yaml", borderYaml([{ name: "origin", url: fx.bare }]));
    const restore = setHandler("check", () => EXIT_BLOCKED);
    try {
      const blocked = await runCli(["push"], { cwd: fx.work });
      assert.equal(blocked.code, EXIT_BLOCKED);
      assert.ok(blocked.out.some((l) => l.includes(DRY_RUN_PREFIX)));
    } finally {
      restore();
    }
    // todo 10 wired the real check; the fail-closed contract now covers ANY
    // gate failure (engine crash, config error, …) — never a misleading 0.
    const broken = setHandler("check", () => {
      throw new EngineRunError("gitleaks exited 99", 99);
    });
    try {
      const unwired = await runCli(["push"], { cwd: fx.work });
      assert.equal(unwired.code, EXIT_ERROR, "gate unavailable must never fake 0");
      assert.match(unwired.err.join("\n"), /engine run error/i);
    } finally {
      broken();
    }
  } finally {
    removeDir(fx.root);
  }
});

test("push dry-run lists one plan line per git remote and zero-mutates on NO-OP config", async () => {
  const fx = makeRemoteFixture();
  const root2 = makeFixtureDir("cli-noop");
  try {
    writeRel(fx.work, "border.yaml", borderYaml([
      { name: "origin", url: fx.bare },
      { name: "backup", url: `${fx.bare}-backup` },
    ]));
    const restore = setHandler("check", () => EXIT_PASS);
    try {
      const r = await runCli(["push"], { cwd: fx.work });
      assert.equal(r.code, EXIT_PASS);
      assert.equal(r.out.filter((l) => l.includes(GIT_PUSH_DRY_RUN)).length, 2);
    } finally {
      restore();
    }
    writeRel(root2, "border.yaml", borderYaml([]));
    const noop = await runCli(["push"], { cwd: root2 });
    assert.equal(noop.code, EXIT_PASS);
    assert.match(noop.out.join("\n"), /no targets/i);
  } finally {
    removeDir(fx.root);
    removeDir(root2);
  }
});

test("push --yes refuses to execute until todo 15/16 land (no mutation path today)", async () => {
  const r = await runCli(["push", "--yes"]);
  assert.equal(r.code, EXIT_ERROR);
  assert.equal(r.out.length, 0, "refusal prints no success payload");
  assert.match(r.err.join("\n"), /--yes.*not implemented/i);
});

test("push reports sanitized remote URLs in the dry-run plan", async () => {
  const root = makeFixtureDir("cli-sanitize");
  try {
    writeRel(root, "border.yaml", borderYaml([{ name: "origin", url: "https://user:pass@github.com/acme/thing.git" }]));
    const restore = setHandler("check", () => EXIT_PASS);
    try {
      const r = await runCli(["push"], { cwd: root });
      assert.equal(r.code, EXIT_PASS);
      assert.ok(r.out.some((l) => l.includes("github.com/acme/thing.git")));
      assert.equal(r.out.join("\n").includes("user:pass"), false);
    } finally {
      restore();
    }
  } finally {
    removeDir(root);
  }
});

// ------------------------------------------------- stub honesty (todo 7 contract)

// Deliberate todo-19 update: status left the "not implemented" stub for the
// real ledger view, so it now runs INFORMATIONALLY over this repo's live
// state (table or "no check runs recorded yet" — both exit 0, stdout-only).
// llm-request/llm-ingest stay precondition-honest failures: the dogfood
// border.yaml has targets.git.remotes: [] ⇒ loadConfig kind is still "no-op"
// (only `check` promotes explicit-empty), so exit 2 with no stdout survives.
test("status is informational over the live repo (exit 0, stdout-only); wired llm commands still fail honestly", async () => {
  const stub = await runCli(["status"]);
  assert.equal(stub.code, EXIT_PASS);
  assert.ok(stub.out.length > 0, "status must print a table or the empty-ledger note");
  assert.ok(!stub.err.join("\n").includes("not implemented"));
  const req = await runCli(["llm-request"]);
  assert.equal(req.code, EXIT_ERROR);
  assert.equal(req.out.length, 0, "llm-request must not print a success payload");
  assert.match(req.err.join("\n"), /no scan targets.*run 'border check' first/i);
  const ing = await runCli(["llm-ingest"]);
  assert.equal(ing.code, EXIT_ERROR);
  assert.equal(ing.out.length, 0, "llm-ingest must not print a success payload");
  assert.match(ing.err.join("\n"), /usage: border llm-ingest <findings\.json>/);
});

test("bad config is a tool error: exit 2, one sanitized line, no stack", async () => {
  const r = await runCli(["push", "--config", "/definitely/not/here/border.yaml"]);
  assert.equal(r.code, EXIT_ERROR);
  assert.equal(r.err.length, 1);
  assert.match(r.err[0] as string, /not found/i);
  assert.equal((r.err[0] as string).includes(" at "), false, "no stack frames echoed");
});

test("--help / -h / `help` all print the usage table and exit 0; `push --help` too", async () => {
  for (const argv of [["--help"], ["-h"], ["help"], ["push", "--help"]]) {
    const r = await runCli(argv);
    assert.equal(r.code, EXIT_PASS, argv.join(" "));
    assert.equal(r.out.join("\n"), usage(), argv.join(" "));
    assert.equal(r.err.length, 0);
  }
});

test("unknown subcommand is one stderr line + usage on stdout + exit 2", async () => {
  const r = await runCli(["frobnicate"]);
  assert.equal(r.code, EXIT_ERROR);
  assert.equal(r.err.length, 1);
  assert.match(r.err[0] as string, /unknown command/i);
  assert.match(r.out.join("\n"), /usage: border <command>/);
});

test("a throwing handler is translated to one sanitized stderr line, exit 2", async () => {
  const restore = setHandler("check", () => {
    throw new EnginePolicyError("engine 'gitleaks' binary missing at https://tok:en@download.example/x");
  });
  try {
    const r = await runCli(["check"]);
    assert.equal(r.code, EXIT_ERROR);
    assert.equal(r.err.length, 1);
    assert.match(r.err[0] as string, /engine policy error/);
    assert.equal((r.err[0] as string).includes("tok:en"), false);
  } finally {
    restore();
  }
});

test("no command framework in src (zero-dep G9 constraint guard)", () => {
  const hits = spawnSync("grep", ["-rEl", "commander|yargs|minimist", "src"], { cwd: BORDER_ROOT, encoding: "utf8" });
  assert.equal(hits.stdout.trim(), "");
});
