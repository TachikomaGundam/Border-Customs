// provenance: sibyl Q1 chain W4b — loadConfig-level security-tier tests on the
// §3⁗ honor matrix. Logic runs through the qualify seam; the fd-chain itself
// is tested for real in tier.test.ts.
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { loadConfig } from "../src/config.ts";

/** valid border.yaml with an npm target; extra = lines appended INSIDE the
 *  npm mapping (4-space indent) or top-level (0-indent) sections. */
function cfg(npmExtra: readonly string[] = [], topExtra: readonly string[] = []): string {
  return [
    "version: 1",
    "targets:",
    "  git:",
    "    remotes: []",
    "  npm:",
    "    registry: https://x.invalid",
    ...npmExtra,
    ...topExtra,
    "rules:",
    "  authors:",
    "    emails: [bot@example.invalid]",
    "    names: [bot]",
    "  hosts: []",
    "  ips: []",
    "  pathPatterns: []",
  ].join("\n");
}
const BASE = cfg();

function dir(): string {
  return mkdtempSync(join(tmpdir(), "cfgsec-"));
}

function write(p: string, text: string): void {
  writeFileSync(p, text, "utf8");
}

const OK = () => ({ ok: true });
const NO = () => ({ ok: false });

test("repo border.yaml sandboxImage is NEVER honored (present-unqualified ⇒ exit-2 ConfigError)", () => {
  const d = dir();
  try {
    write(join(d, "border.yaml"), cfg([`    sandboxImage: node@sha256:${"a".repeat(64)}`]));
    assert.throws(
      () => loadConfig({ cwd: d, securityQualify: OK, securityQualifyDir: OK }),
      (e: unknown) => e instanceof Error && /sandboxImage/.test(e.message) && /UNQUALIFIED/.test(e.message),
    );
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

test("overlay .border/config.local.yaml is repo-tier too", () => {
  const d = dir();
  try {
    write(join(d, "border.yaml"), BASE);
    mkdirSync(join(d, ".border"));
    write(join(d, ".border", "config.local.yaml"), `targets:\n  npm:\n    sandboxImage: node@sha256:${"b".repeat(64)}\n`);
    assert.throws(
      () => loadConfig({ cwd: d, securityQualify: OK, securityQualifyDir: OK }),
      (e: unknown) => e instanceof Error && /sandboxImage/.test(e.message),
    );
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

test("qualified --config outside the repo IS honored (value flows to config + security)", () => {
  const d = dir();
  const outside = dir();
  try {
    const img = `node@sha256:${"c".repeat(64)}`;
    write(join(outside, "gate.yaml"), cfg([`    sandboxImage: ${img}`]));
    const load = loadConfig({ cwd: d, configPath: join(outside, "gate.yaml"), securityQualify: OK, securityQualifyDir: OK });
    assert.equal(load.kind, "loaded");
    if (load.kind !== "loaded") return;
    assert.equal(load.security.sandbox.npm, img);
    assert.equal((load.config.targets.npm as { sandboxImage?: string })?.sandboxImage, img);
  } finally {
    rmSync(d, { recursive: true, force: true });
    rmSync(outside, { recursive: true, force: true });
  }
});

test("--config file INSIDE the repo is repo-tier even with perfect modes (authorship rule)", () => {
  const d = dir();
  try {
    const img = `node@sha256:${"d".repeat(64)}`;
    write(join(d, "gate.yaml"), cfg([`    sandboxImage: ${img}`]));
    assert.throws(
      () => loadConfig({ cwd: d, configPath: join(d, "gate.yaml"), securityQualify: OK, securityQualifyDir: OK }),
      (e: unknown) => e instanceof Error && /UNQUALIFIED/.test(e.message),
    );
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

test("SHADOWED: qualified --config plus a repo declaration of the same lane ⇒ named exit 2", () => {
  const d = dir();
  const outside = dir();
  try {
    write(join(outside, "gate.yaml"), cfg([`    sandboxImage: node@sha256:${"e".repeat(64)}`]));
    write(join(d, "border.yaml"), cfg([`    sandboxImage: node@sha256:${"f".repeat(64)}`]));
    assert.throws(
      () => loadConfig({ cwd: d, configPath: join(outside, "gate.yaml"), securityQualify: OK, securityQualifyDir: OK }),
      (e: unknown) => e instanceof Error && /CONFLICTING/.test(e.message),
    );
  } finally {
    rmSync(d, { recursive: true, force: true });
    rmSync(outside, { recursive: true, force: true });
  }
});

test("AMBIGUOUS: two qualified sources (argv + qualified overlay-outside…via two argv-declared lanes is impossible; use identical double-decl) — argv file declaring both allowBuilds twice is one file; assert the pure-matrix path via two qualified files is refused", () => {
  // loadConfig has ONE argv config; AMBIGUOUS arises between argv + machine
  // store. Simulate the machine file by pointing BORDER_CONFIG_DIR at a dir
  // with a matching remote key? That needs git remotes — covered instead by
  // tier.test.ts honor-level AMBIGUOUS test. Here assert the SEAM wiring:
  // two lanes honored independently do not collide (npm+pypi digests coexist).
  const d = dir();
  const outside = dir();
  try {
    write(
      join(outside, "gate.yaml"),
      [
        "version: 1",
        "targets:",
        "  git:",
        "    remotes: []",
        "  npm:",
        `    sandboxImage: node@sha256:${"1".repeat(64)}`,
        "  pypi:",
        `    sandboxImage: python@sha256:${"2".repeat(64)}`,
        "rules:",
        "  authors:",
        "    emails: [bot@example.invalid]",
        "    names: [bot]",
        "  hosts: []",
        "  ips: []",
        "  pathPatterns: []",
      ].join("\n"),
    );
    const load = loadConfig({ cwd: d, configPath: join(outside, "gate.yaml"), securityQualify: OK, securityQualifyDir: OK });
    assert.equal(load.kind, "loaded");
    if (load.kind !== "loaded") return;
    assert.equal(Object.keys(load.security.sandbox).length, 2);
  } finally {
    rmSync(d, { recursive: true, force: true });
    rmSync(outside, { recursive: true, force: true });
  }
});

test("unqualified XDG override ⇒ shadowed exit 2 for an argv-honored value (fixtures a/b)", () => {
  const d = dir();
  const outside = dir();
  try {
    const img = `node@sha256:${"a".repeat(64)}`;
    write(join(outside, "gate.yaml"), cfg([`    sandboxImage: ${img}`]));
    for (const xdg of ["/tmp/xdg-cfgsec-empty", "/nonexistent-cfgsec"]) {
      assert.throws(
        () => loadConfig({ cwd: d, configPath: join(outside, "gate.yaml"), env: { XDG_CONFIG_HOME: xdg }, securityQualify: OK, securityQualifyDir: NO }),
        (e: unknown) => e instanceof Error && /CONFLICTING/.test(e.message),
        xdg,
      );
    }
  } finally {
    rmSync(d, { recursive: true, force: true });
    rmSync(outside, { recursive: true, force: true });
  }
});

test("allowBuilds withheld (not refused) when only unqualified sources declare it", () => {
  const d = dir();
  try {
    write(join(d, "border.yaml"), cfg([], ["allowBuilds: true"]));
    const load = loadConfig({ cwd: d, securityQualify: OK, securityQualifyDir: OK });
    assert.equal(load.kind, "loaded");
    if (load.kind !== "loaded") return;
    assert.equal(load.security.allowBuilds, false);
    assert.ok(load.warnings.some((w) => /allowBuilds.*withheld/.test(w)), load.warnings.join("|"));
    assert.equal((load.config as { allowBuilds?: boolean }).allowBuilds, undefined, "false stays absent — old digests must not rotate");
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
});

test("$BORDER_CONFIG is NOT a security tier: its sandboxImage declares but never honors", () => {
  const d = dir();
  const outside = dir();
  try {
    const img = `node@sha256:${"9".repeat(64)}`;
    write(join(outside, "cfgenv.yaml"), cfg([`    sandboxImage: ${img}`]));
    assert.throws(
      () => loadConfig({ cwd: d, env: { BORDER_CONFIG: join(outside, "cfgenv.yaml") }, securityQualify: OK, securityQualifyDir: OK }),
      (e: unknown) => e instanceof Error && /UNQUALIFIED/.test(e.message),
    );
  } finally {
    rmSync(d, { recursive: true, force: true });
    rmSync(outside, { recursive: true, force: true });
  }
});
