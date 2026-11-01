// provenance: security advisory 2026-10-17 / handoff B0. Regression guard for
// the npm <=10 `prepare`-executes-during-pack defect reproduced 2026-10-19 on
// npm 10.9.7. The fake-npm shims make the version boundary deterministic on
// every machine (npm 11 is clean, npm 10 is not); packOnce must refuse BEFORE
// spawning `pack`, so the marker the fake would touch can never appear.
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

import { packOnce } from "../src/artifacts/npmPack.ts";
import { npmPackSafety, readNpmPackScripts } from "../src/artifacts/npmPackSafety.ts";
import { EngineRunError } from "../src/engines/support.ts";
import { makeFixtureDir, removeDir, writeRel } from "./helpers/fixtures.ts";

function fakeNpm(dir: string, version: string, marker: string): string {
  const bin = join(dir, "npm");
  writeFileSync(
    bin,
    [
      "#!/bin/sh",
      'if [ "$1" = "--version" ]; then',
      `  printf '%s\\n' '${version}'`,
      "  exit 0",
      "fi",
      `touch '${marker}'`,
      "exit 1",
      "",
    ].join("\n"),
  );
  chmodSync(bin, 0o755);
  return bin;
}

function repoWith(prefix: string, manifest: Record<string, unknown>): string {
  const repo = makeFixtureDir(prefix);
  writeRel(repo, "package.json", JSON.stringify(manifest));
  return repo;
}

test("npm 10 + prepare: safety probe refuses and the pack hook marker never appears", () => {
  const repo = repoWith("npmsafety10", {
    name: "hooky",
    version: "1.0.0",
    scripts: { prepare: "node -e \"require('fs').writeFileSync('PWNED','x')\"" },
  });
  const shimDir = makeFixtureDir("npmsafety10-bin");
  const marker = join(shimDir, "PACK-RAN");
  const npmBinPath = fakeNpm(shimDir, "10.9.7", marker);
  try {
    const safety = npmPackSafety({ repoDir: repo, npmBinPath });
    assert.equal(safety.ok, false);
    if (!safety.ok) {
      assert.equal(safety.major, 10);
      assert.match(safety.reason, /npm 10\.9\.7/);
      assert.match(safety.reason, /'prepare'/);
    }
    const dist = join(repo, ".border", "dist");
    mkdirSync(dist, { recursive: true });
    assert.throws(
      () => packOnce({ repoDir: repo, distDir: dist, npmBinPath }),
      (err: unknown) => err instanceof EngineRunError && /npm 10\.9\.7/.test(err.message),
    );
    assert.equal(existsSync(marker), false, "pack must never be spawned under npm 10 with a prepare hook");
  } finally {
    removeDir(repo);
    removeDir(shimDir);
  }
});

test("npm 10 without pack-phase hooks stays scannable (nothing for npm to execute)", () => {
  const repo = repoWith("npmsafety10clean", { name: "plain", version: "1.0.0", scripts: { test: "x" } });
  const shimDir = makeFixtureDir("npmsafety10clean-bin");
  const npmBinPath = fakeNpm(shimDir, "10.9.7", join(shimDir, "PACK-RAN"));
  try {
    const safety = npmPackSafety({ repoDir: repo, npmBinPath });
    assert.equal(safety.ok, true);
  } finally {
    removeDir(repo);
    removeDir(shimDir);
  }
});

test("npm 11 + prepare is allowed (the flag is trustworthy on that line)", () => {
  const repo = repoWith("npmsafety11", { name: "hooky", version: "1.0.0", scripts: { prepare: "true" } });
  const shimDir = makeFixtureDir("npmsafety11-bin");
  const npmBinPath = fakeNpm(shimDir, "11.19.1", join(shimDir, "PACK-RAN"));
  try {
    const safety = npmPackSafety({ repoDir: repo, npmBinPath });
    assert.equal(safety.ok, true);
    if (safety.ok) assert.equal(safety.major, 11);
  } finally {
    removeDir(repo);
    removeDir(shimDir);
  }
});

test("unparseable npm version fails closed", () => {
  const repo = repoWith("npmsafetybadversion", { name: "plain", version: "1.0.0" });
  const shimDir = makeFixtureDir("npmsafetybadversion-bin");
  const npmBinPath = fakeNpm(shimDir, "not-a-version", join(shimDir, "PACK-RAN"));
  try {
    const safety = npmPackSafety({ repoDir: repo, npmBinPath });
    assert.equal(safety.ok, false);
    if (!safety.ok) assert.match(safety.reason, /cannot determine npm version/);
  } finally {
    removeDir(repo);
    removeDir(shimDir);
  }
});

test("readNpmPackScripts sees prepack/prepare/postpack only when non-empty", () => {
  const repo = repoWith("npmsafetyread", {
    name: "plain",
    version: "1.0.0",
    scripts: { prepack: "x", prepare: "   ", postpack: "y", postinstall: "z" },
  });
  try {
    assert.deepEqual(readNpmPackScripts(repo), ["prepack", "postpack"]);
  } finally {
    removeDir(repo);
  }
});

// sibyl must_fix 2026-10-23: the original guard read the root manifest only,
// so a workspaces monorepo could hide `prepare` in a child package.json.

test("workspaces: a child package's prepare refuses on npm 10 and names its manifest", () => {
  const repo = repoWith("npmsafetyws", {
    name: "root",
    version: "1.0.0",
    workspaces: ["packages/*"],
    scripts: { test: "x" },
  });
  writeRel(repo, "packages/child/package.json", JSON.stringify({ name: "child", version: "1.0.0", scripts: { prepare: "evil" } }));
  const shimDir = makeFixtureDir("npmsafetyws-bin");
  const marker = join(shimDir, "PACK-RAN");
  const npmBinPath = fakeNpm(shimDir, "10.9.7", marker);
  try {
    assert.deepEqual(readNpmPackScripts(repo), ["prepare (packages/child/package.json)"]);
    const safety = npmPackSafety({ repoDir: repo, npmBinPath });
    assert.equal(safety.ok, false);
    if (!safety.ok) assert.match(safety.reason, /prepare \(packages\/child\/package\.json\)/);
    assert.equal(existsSync(marker), false);
  } finally {
    removeDir(repo);
    removeDir(shimDir);
  }
});

test("node_modules dependency manifests are out of pack scope (and never walked)", () => {
  const repo = repoWith("npmsafetyNM", { name: "plain", version: "1.0.0" });
  writeRel(repo, "node_modules/dep/package.json", JSON.stringify({ name: "dep", version: "1.0.0", scripts: { prepare: "evil" } }));
  try {
    assert.deepEqual(readNpmPackScripts(repo), []);
  } finally {
    removeDir(repo);
  }
});

test("an unreadable nested manifest counts as a hook (unknown is never safe)", () => {
  const repo = repoWith("npmsafetyUnreadable", { name: "plain", version: "1.0.0" });
  writeRel(repo, "pkg-broken/package.json", "{not json");
  const shimDir = makeFixtureDir("npmsafetyUnreadable-bin");
  const npmBinPath = fakeNpm(shimDir, "10.9.7", join(shimDir, "PACK-RAN"));
  try {
    assert.deepEqual(readNpmPackScripts(repo), ["pkg-broken/package.json: unreadable or unparseable"]);
    const safety = npmPackSafety({ repoDir: repo, npmBinPath });
    assert.equal(safety.ok, false);
    if (!safety.ok) assert.match(safety.reason, /unreadable or unparseable/);
  } finally {
    removeDir(repo);
    removeDir(shimDir);
  }
});
