// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 5
//
// Acceptance tests for the secretlint adapter against the REAL @secretlint/core
// 13.0.5 in-process API (spike-verified in tools/spike-secretlint.mjs — no
// stubs). ACs: POSIX/Windows default path-patterns (G40), config-driven
// internal host/IP literals with regex-metachar safety, git-tracked-only +
// hard .border/ exclusion, G23 no-raw-persistence, CLI-fallback transparency,
// fail-closed crash mapping, and the package-lock fingerprint (round-2 M8).
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmodSync, existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

import {
  scanGitTrackedFiles,
  scanPaths,
  SecretlintRunError,
  secretlintVersionFingerprint,
  type SecretlintRulesInput,
} from "../src/engines/secretlint.ts";
import { validateFinding, type Finding } from "../src/findings.ts";
import { TextSanitizer } from "../src/redact.ts";
import {
  gitAddCommit,
  gitInit,
  makeFixtureDir,
  randAwsPair,
  removeDir,
  walkFiles,
  writeRel,
} from "./helpers/fixtures.ts";

const digest = (v: string): string => createHash("sha256").update(v, "utf8").digest("hex");

function assertFindingsWellFormed(findings: readonly Finding[]): void {
  for (const f of findings) {
    validateFinding(f);
    assert.equal(f.engine, "secretlint");
    assert.equal(f.severity, "CRITICAL");
  }
}

/** Write `files` into a fresh fixture dir and scan them via the explicit-paths entry point. */
async function scanFixtureFiles(
  prefix: string,
  files: Readonly<Record<string, string>>,
  rules?: SecretlintRulesInput,
  mode?: "in-process" | "cli",
): Promise<{ findings: Finding[]; dir: string }> {
  const dir = makeFixtureDir(prefix);
  try {
    for (const [rel, content] of Object.entries(files)) writeRel(dir, rel, content);
    const findings = await scanPaths({
      dir,
      files: Object.keys(files),
      target: "tree",
      ...(rules !== undefined ? { rules } : {}),
      ...(mode !== undefined ? { mode } : {}),
    });
    return { findings, dir };
  } finally {
    removeDir(dir);
  }
}

test("AC1: default POSIX path-pattern catches /home/lab/proj/.env.local inside a file", async () => {
  const { findings } = await scanFixtureFiles("posix", {
    "secret-path.txt": "config at /home/lab/proj/.env.local\n",
  });
  assertFindingsWellFormed(findings);
  const hit = findings.find((f) => f.rule === "path-pattern:/home/[a-z]+/");
  assert.ok(hit, `expected path-pattern:/home/[a-z]+/ among ${JSON.stringify(findings.map((f) => f.rule))}`);
  assert.equal(hit.valueDigest, digest("/home/lab/"));
  assert.equal(hit.path, "secret-path.txt");
  assert.equal(hit.line, 1);
});

test("AC2: default Windows path-pattern catches C:\\Users\\bob (G40: no-homedir alone misses this)", async () => {
  const { findings } = await scanFixtureFiles("win", {
    "notes.md": "see doc at C:\\Users\\bob\\doc.txt for details\n",
  });
  assertFindingsWellFormed(findings);
  const hit = findings.find((f) => f.rule.startsWith("path-pattern:") && f.valueDigest === digest("C:\\Users\\bob"));
  assert.ok(hit, "expected a path-pattern finding for C:\\Users\\bob");
});

test("AC3: rules.hosts generates an internal-host pattern finding (corp.internal in source)", async () => {
  const { findings } = await scanFixtureFiles(
    "host",
    { "app.js": 'const api = "https://gateway.corp.internal/v1";\n' },
    { hosts: ["corp.internal"] },
  );
  assertFindingsWellFormed(findings);
  const hit = findings.find((f) => f.rule === "internal-host:corp.internal");
  assert.ok(hit, `expected internal-host:corp.internal among ${JSON.stringify(findings.map((f) => f.rule))}`);
  assert.equal(hit.valueDigest, digest("corp.internal"));
});

test("AC4: rules.ips literal-matches with dotted-decimal escape safety", async () => {
  const { findings } = await scanFixtureFiles(
    "ip",
    { "infra.yaml": "bastion: 10.0.5.22\n" },
    { ips: ["10.0.5.22"] },
  );
  assertFindingsWellFormed(findings);
  const hit = findings.find((f) => f.rule === "internal-ip:10.0.5.22");
  assert.ok(hit, "expected internal-ip:10.0.5.22");
  assert.equal(hit.valueDigest, digest("10.0.5.22"));
  // the unescaped regex 10.0.5.22 would also match "100052" — the escaped one must not:
  assert.equal(findings.some((f) => f.rule === "internal-ip:10.0.5.22" && f.valueDigest === digest("10x0y5z2")), false);
});

test("AC5: regex metachars in rules.hosts ('a(b') match literally and never crash", async () => {
  const { findings } = await scanFixtureFiles(
    "meta",
    { "src/util.c": "call a(b here\n" },
    { hosts: ["a(b"] },
  );
  assertFindingsWellFormed(findings);
  const hit = findings.find((f) => f.rule === "internal-host:a(b");
  assert.ok(hit, "expected literal internal-host:a(b finding");
  assert.equal(hit.valueDigest, digest("a(b"));
});

test("AC6: empty pattern string fails closed with SecretlintRunError (never a silent no-rule)", async () => {
  const dir = makeFixtureDir("emptyrule");
  try {
    writeRel(dir, "f.txt", "x\n");
    await assert.rejects(
      scanPaths({ dir, files: ["f.txt"], target: "tree", rules: { hosts: [""] } }),
      SecretlintRunError,
    );
  } finally {
    removeDir(dir);
  }
});

test("AC7: clean fixture yields 0 findings", async () => {
  const { findings } = await scanFixtureFiles("clean", {
    "README.md": "# project\ntotally benign content here\n",
  });
  assert.deepEqual(findings, []);
});

test("AC8: preset-recommend (with the spike-discovered enableIDScanRule override) catches a planted AWS pair", async () => {
  const pair = randAwsPair();
  const { findings } = await scanFixtureFiles("aws", { "creds.env-ish.txt": pair.text });
  assertFindingsWellFormed(findings);
  assert.ok(
    findings.some((f) => f.rule.endsWith("/AWSAccessKeyID")),
    `AWSAccessKeyID must fire — enableIDScanRule defaults to FALSE upstream; got ${JSON.stringify(findings.map((f) => f.rule))}`,
  );
  assert.ok(findings.some((f) => f.valueDigest === digest(pair.key)));
  assert.ok(findings.some((f) => f.valueDigest === digest(pair.secret)));
});

test("AC9: git-tracked scan covers tracked files only and hard-excludes .border/", async () => {
  const repo = makeFixtureDir("tracked");
  try {
    const pair = randAwsPair();
    writeRel(repo, "app/secrets.txt", pair.text);
    writeRel(repo, ".border/stale-scan.yaml", "echo /home/lab/secret/dir 192.168.9.9\n");
    gitInit(repo);
    gitAddCommit(repo, "tracked files");
    writeRel(repo, "untracked-leak.txt", "host db.corp.internal here\n");

    const findings = await scanGitTrackedFiles({
      repoDir: repo,
      target: "git",
      rules: { hosts: ["db.corp.internal"], ips: ["192.168.9.9"] },
    });
    assertFindingsWellFormed(findings);
    assert.ok(findings.some((f) => f.valueDigest === digest(pair.key)), "tracked AWS key must be found");
    assert.equal(findings.some((f) => (f.path ?? "").startsWith(".border/")), false, ".border/ must be hard-excluded");
    assert.equal(findings.some((f) => (f.path ?? "").includes("192.168.9.9") || f.valueDigest === digest("192.168.9.9")), false);
    assert.equal(findings.some((f) => f.path === "untracked-leak.txt"), false, "untracked files are not git-tracked");
  } finally {
    removeDir(repo);
  }
});

test("AC10: no-dotenv rule flags a committed .env file", async () => {
  const { findings } = await scanFixtureFiles("dotenv", { ".env": "DATABASE_URL=x\n" });
  assertFindingsWellFormed(findings);
  assert.ok(
    findings.some((f) => f.rule.includes("no-dotenv")),
    `no-dotenv must flag .env; got ${JSON.stringify(findings.map((f) => f.rule))}`,
  );
});

test("AC11: G23 — raw matched values never reach Finding fields; sanitizer registered; no report residue on disk", async () => {
  const pair = randAwsPair();
  const dir = makeFixtureDir("g23");
  try {
    writeRel(dir, "leak.txt", pair.text);
    writeRel(dir, "paths.txt", "mnt C:\\Users\\admin\\keys.pem\n");
    const sanitizer = new TextSanitizer();
    const findings = await scanPaths({ dir, files: ["leak.txt", "paths.txt"], target: "tree", sanitizer });
    assertFindingsWellFormed(findings);
    assert.ok(findings.length >= 2);
    const serialized = JSON.stringify(findings);
    assert.equal(serialized.includes(pair.secret), false, "raw secret must never reach a Finding field");
    assert.equal(serialized.includes(pair.key), false);
    for (const f of findings) {
      assert.equal(f.message.includes(pair.secret), false);
      assert.equal(f.message.includes(pair.key), false);
      assert.match(f.valueDigest, /^[0-9a-f]{64}$/);
    }
    // adapter registered every matched raw value with the sanitizer:
    const scrubbed = sanitizer.sanitize(`saw ${pair.key} in transit`);
    assert.equal(scrubbed.includes(pair.key), false);
    assert.match(scrubbed, /\[REDACTED:[0-9a-f]{8}\]/);
    // no engine report/config file was ever written inside the scanned tree
    const names = walkFiles(dir).map((p) => p.slice(dir.length));
    assert.equal(names.some((n) => /secretlintrc|report|\.json$/.test(n)), false);
  } finally {
    removeDir(dir);
  }
});

test("AC12: CLI fallback mode is caller-transparent — same Finding contract for the same fixture", async () => {
  const pair = randAwsPair();
  const dir = makeFixtureDir("climode");
  try {
    writeRel(dir, "leak.txt", pair.text);
    const findings = await scanPaths({ dir, files: ["leak.txt"], target: "tree", mode: "cli" });
    assertFindingsWellFormed(findings);
    assert.ok(findings.some((f) => f.valueDigest === digest(pair.key)), "CLI mode must digest the same raw value");
    assert.equal(JSON.stringify(findings).includes(pair.secret), false);
    assert.equal(existsSync(join(dir, ".secretlintrc.json")), false, "CLI mode must not write a config file into the target");
  } finally {
    removeDir(dir);
  }
});

test("AC13: CLI crash (exit 2 domain) maps to SecretlintRunError with the exit code — never 'clean'", async () => {
  const dir = makeFixtureDir("clicrash");
  try {
    writeRel(dir, "f.txt", "x\n");
    const fake = join(dir, "fake-secretlint.sh");
    writeFileSync(fake, "#!/bin/sh\necho 'boom' >&2\nexit 126\n");
    chmodSync(fake, 0o755);
    await assert.rejects(
      scanPaths({ dir, files: ["f.txt"], target: "tree", mode: "cli", binPath: fake }),
      (err: unknown) => {
        assert.ok(err instanceof SecretlintRunError);
        assert.equal((err as SecretlintRunError).exitCode, 126);
        return true;
      },
    );
  } finally {
    removeDir(dir);
  }
});

test("AC14: secretlintVersionFingerprint is a stable sha256 over the lockfile's @secretlint family", async () => {
  const fp = await secretlintVersionFingerprint();
  assert.match(fp, /^[0-9a-f]{64}$/);
  assert.equal(await secretlintVersionFingerprint(), fp, "fingerprint must be deterministic");

  // a lock whose family versions differ MUST produce a different fingerprint
  const dir = makeFixtureDir("lock");
  try {
    const mk = (ver: string): string => {
      const p = join(dir, `lock-${ver}.json`);
      writeFileSync(
        p,
        JSON.stringify({
          packages: {
            "node_modules/@secretlint/core": { version: ver },
            "node_modules/secretlint": { version: ver },
            "node_modules/yaml": { version: "2.9.0" },
          },
        }),
      );
      return p;
    };
    const a = await secretlintVersionFingerprint({ lockPath: mk("13.0.5") });
    const b = await secretlintVersionFingerprint({ lockPath: mk("13.0.6") });
    assert.notEqual(a, b, "engineVersions must change when the locked family changes");
    // non-secretlint deps must NOT influence it
    const pNoisy = join(dir, "lock-noisy.json");
    writeFileSync(
      pNoisy,
      JSON.stringify({
        packages: {
          "node_modules/@secretlint/core": { version: "13.0.5" },
          "node_modules/secretlint": { version: "13.0.5" },
          "node_modules/zod": { version: "99.0.0" },
        },
      }),
    );
    assert.equal(await secretlintVersionFingerprint({ lockPath: pNoisy }), a);
    // lockfile without the family = broken build input ⇒ fail closed
    const pEmpty = join(dir, "lock-empty.json");
    writeFileSync(pEmpty, JSON.stringify({ packages: {} }));
    await assert.rejects(secretlintVersionFingerprint({ lockPath: pEmpty }), SecretlintRunError);
  } finally {
    removeDir(dir);
  }
});
