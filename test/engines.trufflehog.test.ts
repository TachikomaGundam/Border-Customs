// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 6
//
// Acceptance tests for the optional trufflehog adapter. trufflehog is NOT
// provisioned here (and must never be vendored — G41), so every test drives a
// generated PATH-stub / binPath-stub shell script under test/tmp/ (gitignored)
// that replays canned `--json` JSON-lines and scripted exit codes. Fixture
// choice documented: stubs are GENERATED per test, not checked into
// test/fixtures/bin — keeps executable shell fixtures out of git history and
// makes each test hermetic (no cross-test script reuse). No network, ever.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmodSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

import { validateFinding, type Finding } from "../src/findings.ts";
import { TextSanitizer } from "../src/redact.ts";
import { EngineMissingError, EngineRunError } from "../src/engines/support.ts";
import { scanTrufflehog, TRUFFLEHOG_ENGINE, trufflehogVersion } from "../src/engines/trufflehog.ts";
import { makeFixtureDir, removeDir, writeRel } from "./helpers/fixtures.ts";

/** Canned values — AKIA-prefixed but NOT the AWS docs example keys (engine builtin allows). */
const RAW = "AKIAI4Q3EXAMPL3K7X2Q";
const SECRET2 = "sk_live_51H8xQrVb3mNp2wZ9yT4cD7eF0gH1iJ2";
const COMMIT = "3f7a2b9c4d5e6f708192a3b4c5d6e7f8091a2b3c";

function cannedResultAws() {
  return {
    SourceMetadata: { Data: { Git: { Commit: COMMIT, File: "config/aws.py", Line: 42 } } },
    DetectorName: "AWS",
    DetectorID: 1,
    SourceType: 0,
    DecoderName: "Plain",
    Raw: RAW,
    Redacted: "AKIA[REDACTED]",
    Verified: true,
  };
}
function cannedResultPrivateKey() {
  return {
    DetectorName: "Private Key",
    DetectorID: 2,
    SourceType: 0,
    DecoderName: "Plain",
    Raw: SECRET2,
    Verified: true,
  };
}

/** Stub binary: echoes the canned file and exits with the scripted code; rejects unexpected argv. */
function trufflehogStub(dir: string, cannedRel: string, exitCode: number): string {
  writeRel(
    dir,
    "bin/trufflehog",
    [
      "#!/bin/sh",
      `CANNED='${join(dir, cannedRel)}'`,
      'if [ "$1" = "--version" ]; then echo "version: v3.88.0"; exit 0; fi',
      // invocation contract: exactly the plan's command shape
      'if [ "$1" = "git" ] && [ "${2#file://}" != "$2" ] && [ "$3" = "--only-verified" ] && [ "$4" = "--fail" ] && [ "$5" = "--no-update" ] && [ "$6" = "--json" ]; then',
      '  cat "$CANNED"',
      `  exit ${String(exitCode)}`,
      "fi",
      "echo 'stub: unexpected argv' >&2",
      "exit 64",
      "",
    ].join("\n"),
  );
  const p = join(dir, "bin", "trufflehog");
  chmodSync(p, 0o755);
  return p;
}

test("AC2: canned exit-183 stub ⇒ verified findings ingested as CRITICAL, masked, rules conform to validateFinding", () => {
  const fx = makeFixtureDir("th-183");
  try {
    writeRel(fx, "canned.jsonl", `${JSON.stringify(cannedResultAws())}\n${JSON.stringify(cannedResultPrivateKey())}\n`);
    const bin = trufflehogStub(fx, "canned.jsonl", 183);
    const sanitizer = new TextSanitizer();
    const findings = scanTrufflehog({ repoDir: "/repo/ignored-by-stub", binPath: bin, sanitizer });

    assert.equal(findings.length, 2);
    for (const f of findings) {
      validateFinding(f); // rule/target/engine/message/snippet strings, digest 64-hex, line integer
      assert.equal(f.engine, TRUFFLEHOG_ENGINE);
      assert.equal(f.severity, "CRITICAL");
      assert.equal(f.target, "git");
      assert.match(f.rule, /^trufflehog\/[a-z0-9][a-z0-9-]*$/);
    }
    const [aws, key] = findings as [Finding, Finding];
    assert.equal(aws.rule, "trufflehog/aws");
    assert.equal(aws.path, "config/aws.py");
    assert.equal(aws.line, 42);
    assert.equal(aws.commit, COMMIT);
    // detector name in the message (plan: 'detector name in message')
    assert.ok(aws.message.includes("AWS"));
    // lowercase-dash normalization of a multi-word detector name
    assert.equal(key.rule, "trufflehog/private-key");

    // G23: raw values NEVER appear in any serialized Finding field…
    const serialized = JSON.stringify(findings);
    assert.equal(serialized.includes(RAW), false);
    assert.equal(serialized.includes(SECRET2), false);
    // …only their digests and redaction snippets
    assert.equal(aws.valueDigest, createHash("sha256").update(RAW, "utf8").digest("hex"));
    assert.equal(key.valueDigest, createHash("sha256").update(SECRET2, "utf8").digest("hex"));
    const pts = [...RAW];
    assert.equal(aws.snippet, `${pts.slice(0, 4).join("")}\u2026${pts.slice(-4).join("")}`);
    // sanitizer received the raw values for free-text scrubbing
    const scrubbed = sanitizer.sanitize(`leaked ${RAW} in log`);
    assert.equal(scrubbed.includes(RAW), false);
    assert.match(scrubbed, /\[REDACTED:[0-9a-f]{8}\]/);
  } finally {
    removeDir(fx);
  }
});

test("AC3: exit 0 with no JSON lines ⇒ clean (0 findings)", () => {
  const fx = makeFixtureDir("th-clean");
  try {
    writeRel(fx, "canned.jsonl", "");
    const bin = trufflehogStub(fx, "canned.jsonl", 0);
    assert.deepEqual(scanTrufflehog({ repoDir: "/repo", binPath: bin }), []);
  } finally {
    removeDir(fx);
  }
});

test("AC3: exit codes other than 0/183 (1, 7, 64) ⇒ EngineRunError carrying the code (border exit 2), never 'clean'", () => {
  const fx = makeFixtureDir("th-exit");
  try {
    writeRel(fx, "canned.jsonl", "");
    for (const code of [1, 7]) {
      const bin = trufflehogStub(fx, "canned.jsonl", code);
      assert.throws(
        () => scanTrufflehog({ repoDir: "/repo", binPath: bin }),
        (err: unknown) => {
          assert.ok(err instanceof EngineRunError, `exit ${String(code)} must map to EngineRunError`);
          assert.equal((err as EngineRunError).exitCode, code);
          return true;
        },
      );
    }
    // command-shape proof is implicit: trufflehogStub exits 64 (⇒ EngineRunError)
    // unless border spawns EXACTLY `git file://<repo> --only-verified --fail --no-update --json`,
    // which the AC2 test's successful 183-parse demonstrates.
  } finally {
    removeDir(fx);
  }
});

test("AC3: unparseable --json stdout line ⇒ EngineRunError (fail closed, never partial trust)", () => {
  const fx = makeFixtureDir("th-garbage");
  try {
    writeRel(fx, "canned.jsonl", "this is not json\n");
    const bin = trufflehogStub(fx, "canned.jsonl", 183);
    assert.throws(() => scanTrufflehog({ repoDir: "/repo", binPath: bin }), EngineRunError);
  } finally {
    removeDir(fx);
  }
});

test("AC3: result object without SourceMetadata git block ⇒ path/line/commit simply absent (still a valid finding)", () => {
  const fx = makeFixtureDir("th-nometa");
  try {
    writeRel(fx, "canned.jsonl", `${JSON.stringify(cannedResultPrivateKey())}\n`);
    const bin = trufflehogStub(fx, "canned.jsonl", 183);
    const findings = scanTrufflehog({ repoDir: "/repo", binPath: bin });
    assert.equal(findings.length, 1);
    const f = findings[0] as Finding;
    validateFinding(f);
    assert.equal(f.path, undefined);
    assert.equal(f.line, undefined);
    assert.equal(f.commit, undefined);
  } finally {
    removeDir(fx);
  }
});

test("missing binary ⇒ EngineMissingError from both entry points (PATH-stripped, empty fake HOME)", () => {
  const fx = makeFixtureDir("th-missing");
  try {
    const env = { PATH: "", HOME: join(fx, "fakehome") };
    assert.throws(() => scanTrufflehog({ repoDir: "/repo", env }), EngineMissingError);
    assert.throws(() => trufflehogVersion({ env }), EngineMissingError);
  } finally {
    removeDir(fx);
  }
});

test("trufflehogVersion: `trufflehog --version` output collected for the rulesHash engineVersions map", () => {
  const fx = makeFixtureDir("th-version");
  try {
    writeRel(fx, "canned.jsonl", "");
    const bin = trufflehogStub(fx, "canned.jsonl", 0);
    assert.match(trufflehogVersion({ binPath: bin }), /3\.88\.0/);
  } finally {
    removeDir(fx);
  }
});
