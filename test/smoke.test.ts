import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { run, usage } from "../src/index.ts";

const SUBCOMMANDS = ["check", "push", "status", "llm-request", "llm-ingest"] as const;

test("--help exits 0 and its output lists all five subcommands", () => {
  const lines: string[] = [];
  const log = (s: unknown): void => {
    lines.push(String(s));
  };
  const code = run(["--help"], log, () => {});
  assert.equal(code, 0);
  const out = lines.join("\n");
  for (const cmd of SUBCOMMANDS) {
    assert.ok(out.includes(cmd), `usage output missing subcommand: ${cmd}`);
  }
  assert.ok(usage().includes(SUBCOMMANDS.join(", ")));
});

test("unknown command exits 2 and prints an error line to stderr", () => {
  const err: string[] = [];
  const code = run(["bogus-cmd"], () => {}, (s) => {
    err.push(String(s));
  });
  assert.equal(code, 2);
  assert.equal(err.length, 1, "exactly one error line expected");
  assert.match(err[0] as string, /unknown command/i);
});

test("absent command (no args) exits 2 and prints an error line to stderr", () => {
  const err: string[] = [];
  const code = run([], () => {}, (s) => {
    err.push(String(s));
  });
  assert.equal(code, 2);
  assert.equal(err.length, 1);
  assert.match(err[0] as string, /unknown command/i);
});

// Deliberate todo-19 update: 'status' left the wired-stub surface for the real
// ledger view; this pins the LAST stub is gone and the failure path stays
// loud (exit 2, zero stdout) when the cwd is not a git repository.
test("status is fully wired: no stub remains, and it fails loudly outside a git repo", () => {
  const dir = mkdtempSync(join(tmpdir(), "border-smoke-"));
  try {
    const err: string[] = [];
    const out: string[] = [];
    const code = run(["status"], (s) => {
      out.push(String(s));
    }, (s) => {
      err.push(String(s));
    }, { cwd: dir });
    assert.equal(code, 2);
    assert.equal(out.length, 0, "failing status must not print a success payload");
    assert.match(err.join("\n"), /status/i);
    assert.doesNotMatch(err.join("\n"), /not implemented/i);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
