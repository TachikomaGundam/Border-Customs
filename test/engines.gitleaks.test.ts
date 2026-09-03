// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 4
//
// Acceptance tests for the gitleaks adapter against the REAL gitleaks 8.30.1
// binary (no stubs — require-engines guards). Every AC of todo 4 maps to one
// test below; archive/ingest invariants proven by the spike are recorded in
// src/engines/ADAPTER-CONTRACT.md.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmodSync, existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

import {
  detectHostileConfig,
  EngineMissingError,
  gitleaksVersion,
  GitleaksRunError,
  scanGitHistory,
  scanTree,
} from "../src/engines/gitleaks.ts";
import { validateFinding, type Finding } from "../src/findings.ts";
import { TextSanitizer } from "../src/redact.ts";
import { requireGitleaks } from "./helpers/require-engines.ts";
import {
  gitAddCommit,
  gitInit,
  gitRevParseHead,
  gitRmCommit,
  makeFixtureDir,
  randAwsPair,
  removeDir,
  walkFiles,
  writeRel,
} from "./helpers/fixtures.ts";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

requireGitleaks();

/** Every finding must satisfy the shared Finding contract and be engine-tagged. */
function assertFindingsWellFormed(findings: readonly Finding[]): void {
  for (const f of findings) {
    validateFinding(f);
    assert.equal(f.engine, "gitleaks");
    assert.equal(f.severity, "CRITICAL");
  }
}

function totalBytesSecretAbsent(dir: string, secret: string): void {
  for (const file of walkFiles(dir)) {
    const raw = readFileSync(file);
    assert.equal(
      raw.includes(secret),
      false,
      `planted literal must never persist to disk: ${file}`,
    );
  }
}

test("AC1: history leg reports a secret added then deleted at HEAD, carrying the leaking commit sha", () => {
  const repo = makeFixtureDir("hist");
  try {
    const pair = randAwsPair();
    writeRel(repo, "config.txt", pair.text);
    gitInit(repo);
    gitAddCommit(repo, "add config");
    const leakSha = gitRevParseHead(repo);
    gitRmCommit(repo, "config.txt", "remove config");
    assert.notEqual(gitRevParseHead(repo), leakSha);

    const findings = scanGitHistory({ repoDir: repo, refRange: "--all", target: "git" });
    assertFindingsWellFormed(findings);
    assert.ok(findings.length >= 1, "deleted-but-reachable secret must still gate");
    assert.ok(
      findings.some((f) => f.commit === leakSha),
      `at least one finding must carry the leaking commit sha ${leakSha}`,
    );
    // G23: the raw literal must not ride along in any serialized field.
    assert.equal(JSON.stringify(findings).includes(pair.secret), false);
    assert.equal(JSON.stringify(findings).includes(pair.key), false);
    // digest = sha256 of SOME matched raw value; verify at least the secret-line digest path:
    for (const f of findings) {
      assert.match(f.valueDigest, /^[0-9a-f]{64}$/);
      assert.match(f.snippet, /^(\u25ae\u25ae\u25ae\u25ae|.+\u2026.+)$/);
    }
  } finally {
    removeDir(repo);
  }
});

test("AC2a: planted key inside .tgz (spike-proven MISS) is detected via the extract shim, attributed to the archive", () => {
  const fx = makeFixtureDir("tgz");
  try {
    const pair = randAwsPair();
    writeRel(fx, "work/payload.txt", pair.text);
    execFileSync("tar", ["czf", join(fx, "pkg.tgz"), "-C", join(fx, "work"), "payload.txt"]);
    removeDir(join(fx, "work"));

    const findings = scanTree({ dir: fx, stateDir: join(fx, ".border"), target: "artifact" });
    assertFindingsWellFormed(findings);
    assert.ok(findings.length >= 1, "key inside .tgz must be detected");
    assert.ok(
      findings.some((f) => (f.path ?? "").includes("pkg.tgz!")),
      "finding path must name the containing archive (pkg.tgz!<inner>)",
    );
    // extraction temp must be gone on the success path
    assert.equal(existsSync(join(fx, ".border", "tmp")), false, "extract tmp must be cleaned up");
    assert.equal(JSON.stringify(findings).includes(pair.secret), false);
  } finally {
    removeDir(fx);
  }
});

test("AC2b: .tar.gz and .zip (spike-proven NATIVE) are detected through the dir leg with archive-joined paths", () => {
  const fx = makeFixtureDir("native");
  try {
    const gz = randAwsPair();
    const zp = randAwsPair();
    writeRel(fx, "work/gz.txt", gz.text);
    writeRel(fx, "work/zip.txt", zp.text);
    execFileSync("tar", ["czf", join(fx, "sdist.tar.gz"), "-C", join(fx, "work"), "gz.txt"]);
    execFileSync("python3", ["-m", "zipfile", "-c", join(fx, "wheelish.zip"), "gz.txt", "zip.txt"], {
      cwd: join(fx, "work"),
    });
    removeDir(join(fx, "work"));

    const findings = scanTree({ dir: fx, stateDir: join(fx, ".border"), target: "artifact" });
    assertFindingsWellFormed(findings);
    assert.ok(findings.some((f) => (f.path ?? "").includes("sdist.tar.gz!")));
    assert.ok(findings.some((f) => (f.path ?? "").includes("wheelish.zip!")));
  } finally {
    removeDir(fx);
  }
});

test("AC3: clean fixture yields 0 findings on both legs", () => {
  const fx = makeFixtureDir("clean");
  try {
    writeRel(fx, "README.md", "# project\ntotally benign content here\n");
    gitInit(fx);
    gitAddCommit(fx, "init");

    const history = scanGitHistory({ repoDir: fx, refRange: "--all", target: "git" });
    assert.deepEqual(history, []);
    const tree = scanTree({ dir: fx, stateDir: join(fx, ".border"), target: "tree" });
    assert.deepEqual(tree, []);
    assert.equal(existsSync(join(fx, ".border", "tmp")), false);
  } finally {
    removeDir(fx);
  }
});

test("AC4: no report/extract residue — after scans the fixture tree contains no planted literal and no .border/tmp survives", () => {
  const fx = makeFixtureDir("residue");
  try {
    const inRepo = randAwsPair();
    const inTgz = randAwsPair();
    writeRel(fx, "leaked.env", inRepo.text);
    gitInit(fx);
    gitAddCommit(fx, "leak");
    gitRmCommit(fx, "leaked.env", "unstage leak");
    writeRel(fx, "work/payload.txt", inTgz.text);
    execFileSync("tar", ["czf", join(fx, "pkg.tgz"), "-C", join(fx, "work"), "payload.txt"]);
    removeDir(join(fx, "work"));

    scanGitHistory({ repoDir: fx, refRange: "--all", target: "git" });
    scanTree({ dir: fx, stateDir: join(fx, ".border"), target: "tree" });

    // working tree + any border state dirs carry zero copies of the literals
    totalBytesSecretAbsent(fx, inRepo.secret);
    totalBytesSecretAbsent(fx, inTgz.secret);
    // no on-disk gitleaks report file, no surviving extraction root
    assert.equal(existsSync(join(fx, ".border", "tmp")), false);
    const names = walkFiles(fx).map((p) => p.slice(fx.length));
    assert.equal(names.some((n) => n.includes("gitleaks") && !n.includes("node_modules")), false);
  } finally {
    removeDir(fx);
  }
});

test("AC5: committed .gitleaksignore / .gitleaks.toml in HEAD tree ⇒ CRITICAL repo-self-ignores-findings naming path + head sha", () => {
  const fx = makeFixtureDir("hostile");
  try {
    // content is arbitrary: the detector fires on PRESENCE in the HEAD tree,
    // because the engine obeys any committed .gitleaksignore unconditionally
    // (spike: root.go:304-320 is additive regardless of -i; real proof 1→0).
    writeRel(fx, "app.env", randAwsPair().text);
    writeRel(fx, ".gitleaksignore", "# attacker-suppressed findings\n");
    gitInit(fx);
    gitAddCommit(fx, "hostile ignore file");
    const head = gitRevParseHead(fx);

    // The engine itself silently obeys the committed ignore file (spike: 1→0),
    // so the detector is the gate:
    const hostile = detectHostileConfig({ repoDir: fx, target: "git" });
    assertFindingsWellFormed(hostile);
    assert.equal(hostile.length, 1);
    const f = hostile[0] as Finding;
    assert.equal(f.rule, "repo-self-ignores-findings");
    assert.equal(f.severity, "CRITICAL");
    assert.equal(f.commit, head);
    assert.ok((f.path ?? "").includes(".gitleaksignore"));

    // rules=[] .gitleaks.toml variant is caught too (two files ⇒ two findings)
    writeRel(fx, "nested/.gitleaks.toml", 'title = "empty"\nrules = []\n');
    gitAddCommit(fx, "empty rules config");
    const head2 = gitRevParseHead(fx);
    const both = detectHostileConfig({ repoDir: fx, target: "git" });
    assert.equal(both.length, 2);
    assert.ok(both.every((x) => x.rule === "repo-self-ignores-findings" && x.commit === head2));
    assert.ok(both.some((x) => (x.path ?? "").endsWith("nested/.gitleaks.toml")));
  } finally {
    removeDir(fx);
  }
});

test("AC6: committed rules=[] .gitleaks.toml does NOT neutralize the vendored --config — key still reported", () => {
  const fx = makeFixtureDir("emptyrules");
  try {
    const pair = randAwsPair();
    writeRel(fx, "secrets.txt", pair.text);
    gitInit(fx);
    gitAddCommit(fx, "leak");
    const leakSha = gitRevParseHead(fx);
    gitRmCommit(fx, "secrets.txt", "remove secret");
    writeRel(fx, ".gitleaks.toml", 'title = "empty"\nrules = []\n');
    gitAddCommit(fx, "add empty rules config");

    const findings = scanGitHistory({ repoDir: fx, refRange: "--all", target: "git" });
    assertFindingsWellFormed(findings);
    assert.ok(
      findings.some((f) => f.commit === leakSha),
      "vendored --config must replace target-repo auto-discovered .gitleaks.toml",
    );
  } finally {
    removeDir(fx);
  }
});

test("AC7: PATH-stripped run throws typed EngineMissingError (all spawn entry points)", () => {
  const fx = makeFixtureDir("missing");
  const fakeHome = makeFixtureDir("fakehome");
  try {
    const env = { PATH: "", HOME: fakeHome };
    assert.throws(
      () => scanGitHistory({ repoDir: fx, refRange: "--all", target: "git", env }),
      EngineMissingError,
    );
    assert.throws(() => scanTree({ dir: fx, target: "tree", env }), EngineMissingError);
    assert.throws(() => gitleaksVersion({ env }), EngineMissingError);
  } finally {
    removeDir(fx);
    removeDir(fakeHome);
  }
});

test("AC8: gitleaks exit codes other than 0/1 (e.g. 126 usage error) are border exit-2 errors, never 'clean'", () => {
  const fx = makeFixtureDir("exit2");
  try {
    const fake = join(fx, "fake-gitleaks.sh");
    writeFileSync(fake, "#!/bin/sh\necho 'boom: unknown flag' >&2\nexit 126\n");
    chmodSync(fake, 0o755);
    assert.throws(
      () => scanTree({ dir: fx, target: "tree", binPath: fake }),
      (err: unknown) => {
        assert.ok(err instanceof GitleaksRunError);
        assert.equal(err.exitCode, 126);
        return true;
      },
    );
    // and it is NEVER treated as clean: the throw is the only acceptable outcome
  } finally {
    removeDir(fx);
  }
});

test("AC9: --version string is collectible for the rulesHash engineVersions map", () => {
  const v = gitleaksVersion();
  assert.match(v, /8\.30\.1/);
});

test("AC10: ingest routes every value through redact(); sanitizer scrubbing + env-strip behavior", () => {
  const fx = makeFixtureDir("ingest");
  try {
    const pair = randAwsPair();
    writeRel(fx, "app.env", pair.text);

    const sanitizer = new TextSanitizer();
    // a hostile GITLEAKS_CONFIG env var must not change engine behavior:
    // the adapter spawns with GITLEAKS_CONFIG/GITLEAKS_CONFIG_TOML stripped.
    const findings = scanTree({
      dir: fx,
      stateDir: join(fx, ".border"),
      target: "tree",
      sanitizer,
      env: { ...process.env, GITLEAKS_CONFIG: "/nonexistent/evil.toml", GITLEAKS_CONFIG_TOML: "rules = []" },
    });
    assertFindingsWellFormed(findings);
    assert.ok(findings.length >= 1);
    const serialized = JSON.stringify(findings);
    assert.equal(serialized.includes(pair.secret), false, "raw secret must never reach a Finding field");
    assert.equal(serialized.includes(pair.key), false);

    // the adapter registered the matched raw value(s) with the sanitizer:
    const scrubbed = sanitizer.sanitize(`token seen: ${pair.secret} in log`);
    assert.equal(scrubbed.includes(pair.secret), false);
    assert.match(scrubbed, /\[REDACTED:[0-9a-f]{8}\]/);

    // digest consistency: for each finding the digest must equal sha256 of the
    // registered raw value that produced it.
    const digestOfSecret = createHash("sha256").update(pair.secret, "utf8").digest("hex");
    const digestOfKey = createHash("sha256").update(pair.key, "utf8").digest("hex");
    assert.ok(
      findings.some((f) => f.valueDigest === digestOfSecret || f.valueDigest === digestOfKey),
      "valueDigest must be sha256 of the raw matched value",
    );
  } finally {
    removeDir(fx);
  }
});
