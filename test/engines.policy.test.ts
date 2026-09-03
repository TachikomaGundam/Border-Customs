// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 6
//
// Acceptance tests for the fail-closed engine policy. gitleaks/trufflehog are
// driven through GENERATED shell stubs placed on a private PATH under
// test/tmp/ (gitignored) — stubs are created per test, never checked in, so
// each case is hermetic and the runner machine's real binaries are invisible
// (PATH + HOME are both overridden; ~/.local/bin fallback is fenced off by
// the empty fake HOME). secretlint has no --version: its probe is the
// in-process package-lock fingerprint, so its failure is injected via a stub
// lockPath that lacks the @secretlint/* family.
import assert from "node:assert/strict";
import { chmodSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

import { parseConfig, type BorderConfig } from "../src/config.ts";
import { computeVerdict, validateFinding } from "../src/findings.ts";
import { DEGRADED_ENGINE_RULE, EnginePolicyError, probeEngines } from "../src/engines/policy.ts";
import { makeFixtureDir, removeDir, writeRel } from "./helpers/fixtures.ts";

function testCfg(enginesYaml = ""): BorderConfig {
  return parseConfig(
    [
      "version: 1",
      "targets:",
      "  git:",
      "    remotes:",
      "      - name: origin",
      "        url: git@github.com:acme/widgets.git",
      "rules:",
      "  authors: { emails: [], names: [] }",
      "  hosts: []",
      "  ips: []",
      "  pathPatterns: []",
      enginesYaml,
      "",
    ].join("\n"),
  );
}

/** Executable PATH stub printing a canned version line. */
function versionStub(dir: string, name: string, versionLine: string): void {
  writeRel(dir, `bin/${name}`, `#!/bin/sh\necho '${versionLine}'\n`);
  chmodSync(join(dir, "bin", name), 0o755);
}

function sandboxEnv(stubDir: string): Record<string, string> {
  return { PATH: join(stubDir, "bin"), HOME: join(stubDir, "fakehome") };
}

/** A package-lock that parses but carries no @secretlint/* family entries. */
function stubLockWithoutSecretlint(dir: string): string {
  writeRel(
    dir,
    "package-lock.json",
    JSON.stringify({ name: "x", lockfileVersion: 3, packages: { "node_modules/yaml": { version: "2.9.0" } } }),
  );
  return join(dir, "package-lock.json");
}

test("AC1: PATH-stub WITHOUT gitleaks ⇒ degraded:true + DEGRADED-ENGINE CRITICAL (engine field names it) + blocking verdict (the flag todo 14 uses to forbid ledger writes)", async () => {
  const fx = makeFixtureDir("pol-no-gitleaks");
  try {
    const result = await probeEngines(testCfg(), { env: sandboxEnv(fx) });
    assert.equal(result.degraded, true);
    assert.equal(result.findings.length, 1, "one DEGRADED-ENGINE finding per missing engine");
    const f = result.findings[0] as ReturnType<typeof validateFinding>;
    validateFinding(f);
    assert.equal(f.rule, DEGRADED_ENGINE_RULE);
    assert.equal(f.severity, "CRITICAL");
    assert.equal(f.engine, "gitleaks");
    assert.ok(f.message.includes("run border's engine provisioning or install manually"));
    // contract the ledger layer (todo 14) rides on: a degraded run can never
    // be a writable PASS — the CRITICAL finding blocks the verdict too.
    assert.equal(computeVerdict(result.findings), "FAIL");
    assert.equal(result.engineVersions["gitleaks"], undefined);
    assert.match(result.engineVersions["secretlint"] ?? "", /^[0-9a-f]{64}$/, "real lock fingerprints fine");
  } finally {
    removeDir(fx);
  }
});

test("AC1: gitleaks present but secretlint lock family absent ⇒ same degraded posture naming secretlint", async () => {
  const fx = makeFixtureDir("pol-badlock");
  try {
    versionStub(fx, "gitleaks", "gitleaks version 8.30.1");
    const result = await probeEngines(testCfg(), { env: sandboxEnv(fx), secretlintLockPath: stubLockWithoutSecretlint(fx) });
    assert.equal(result.degraded, true);
    assert.equal(result.findings.length, 1);
    const f = result.findings[0] as ReturnType<typeof validateFinding>;
    validateFinding(f);
    assert.equal(f.rule, DEGRADED_ENGINE_RULE);
    assert.equal(f.engine, "secretlint");
    assert.equal(result.engineVersions["gitleaks"], "8.30.1");
  } finally {
    removeDir(fx);
  }
});

test("healthy engines ⇒ degraded:false, no findings, engineVersions map for rulesHash", async () => {
  const fx = makeFixtureDir("pol-healthy");
  try {
    versionStub(fx, "gitleaks", "gitleaks version 8.30.1");
    const result = await probeEngines(testCfg(), { env: sandboxEnv(fx) });
    assert.equal(result.degraded, false);
    assert.deepEqual(result.findings, []);
    assert.equal(result.engineVersions["gitleaks"], "8.30.1");
    assert.match(result.engineVersions["secretlint"] ?? "", /^[0-9a-f]{64}$/);
  } finally {
    removeDir(fx);
  }
});

test("--require-engine override replaces cfg.engines.require (secretlint dropped from required set ⇒ its broken lock no longer degrades)", async () => {
  const fx = makeFixtureDir("pol-override");
  try {
    versionStub(fx, "gitleaks", "gitleaks version 8.30.1");
    const result = await probeEngines(testCfg(), {
      env: sandboxEnv(fx),
      requireOverride: ["gitleaks"],
      secretlintLockPath: stubLockWithoutSecretlint(fx),
    });
    assert.equal(result.degraded, false);
    assert.deepEqual(result.findings, []);
    assert.equal(result.engineVersions["secretlint"], undefined, "non-required engine is not probed");
  } finally {
    removeDir(fx);
  }
});

test("trufflehog is probed ONLY when engines.trufflehog:true — absent binary when enabled ⇒ DEGRADED-ENGINE trufflehog", async () => {
  const fxOff = makeFixtureDir("pol-th-off");
  const fxOn = makeFixtureDir("pol-th-on");
  try {
    versionStub(fxOff, "gitleaks", "gitleaks version 8.30.1");
    versionStub(fxOn, "gitleaks", "gitleaks version 8.30.1");

    const off = await probeEngines(testCfg(), { env: sandboxEnv(fxOff) });
    assert.equal(off.degraded, false, "disabled trufflehog must never degrade the run");
    assert.equal(off.engineVersions["trufflehog"], undefined);

    const on = await probeEngines(testCfg("engines:\n  trufflehog: true"), { env: sandboxEnv(fxOn) });
    assert.equal(on.degraded, true);
    assert.equal(on.findings.length, 1);
    const f = on.findings[0] as ReturnType<typeof validateFinding>;
    validateFinding(f);
    assert.equal(f.rule, DEGRADED_ENGINE_RULE);
    assert.equal(f.engine, "trufflehog");
  } finally {
    removeDir(fxOff);
    removeDir(fxOn);
  }
});

test("trufflehog enabled + working stub ⇒ version joins the engineVersions map", async () => {
  const fx = makeFixtureDir("pol-th-ok");
  try {
    versionStub(fx, "gitleaks", "gitleaks version 8.30.1");
    versionStub(fx, "trufflehog", "version: v3.88.0");
    const result = await probeEngines(testCfg("engines:\n  trufflehog: true"), { env: sandboxEnv(fx) });
    assert.equal(result.degraded, false);
    assert.equal(result.engineVersions["trufflehog"], "3.88.0");
  } finally {
    removeDir(fx);
  }
});

test("AC3: unparseable --version output ⇒ EnginePolicyError naming the engine (exit 2, never assume current)", async () => {
  const fx = makeFixtureDir("pol-badver");
  try {
    versionStub(fx, "gitleaks", "gitleaks version banana");
    await assert.rejects(
      probeEngines(testCfg(), { env: sandboxEnv(fx) }),
      (err: unknown) => {
        assert.ok(err instanceof EnginePolicyError);
        assert.equal(err.exitCode, 2);
        assert.ok(err.message.includes("gitleaks"), "error must name the engine");
        assert.ok(err.message.includes("banana") || err.message.includes("unparseable"));
        return true;
      },
    );
  } finally {
    removeDir(fx);
  }
});

test("AC3: unparseable trufflehog version names trufflehog", async () => {
  const fx = makeFixtureDir("pol-badthver");
  try {
    versionStub(fx, "gitleaks", "gitleaks version 8.30.1");
    versionStub(fx, "trufflehog", "trufflehog: command garbled");
    await assert.rejects(
      probeEngines(testCfg("engines:\n  trufflehog: true"), { env: sandboxEnv(fx) }),
      (err: unknown) => err instanceof EnginePolicyError && err.message.includes("trufflehog"),
    );
  } finally {
    removeDir(fx);
  }
});

test("unknown name in required set ⇒ fail-closed DEGRADED-ENGINE (a probeable-by-default engine can never be silently skipped)", async () => {
  const fx = makeFixtureDir("pol-unknown");
  try {
    const result = await probeEngines(testCfg("engines:\n  require: [nosuchengine]"), { env: sandboxEnv(fx) });
    assert.equal(result.degraded, true);
    const f = result.findings[0] as ReturnType<typeof validateFinding>;
    validateFinding(f);
    assert.equal(f.engine, "nosuchengine");
    assert.equal(f.rule, DEGRADED_ENGINE_RULE);
  } finally {
    removeDir(fx);
  }
});
