import assert from "node:assert/strict";
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

test("recognized-but-unwired subcommand fails loudly instead of faking success", () => {
  const err: string[] = [];
  const out: string[] = [];
  const code = run(["check"], (s) => {
    out.push(String(s));
  }, (s) => {
    err.push(String(s));
  });
  assert.equal(code, 2);
  assert.equal(out.length, 0, "unwired command must not print a success payload");
  assert.match(err[0] as string, /not implemented/i);
});
