// provenance: sibyl Q1 chain (c5e7/2739/62cf/5d41/1008/f9dc) — W4b hardening.
// Tier tests per proposal §3⁗/§3⁖/§3‡ (v6/v7 canonical): every fixture the
// council required for the honor-state semantics and the anchor-split fd chain.
import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { canonicalStoreRoot, honorSecurityKey, passwdHome, qualifyDir, qualifyRead, type SecurityDecl } from "../src/tier.ts";

function withSecureDir(fn: (dir: string) => void): void {
  const base = mkdtempSync(join(tmpdir(), "tier-"));
  try {
    fn(base);
  } finally {
    chmodSync(base, 0o700);
    rmSync(base, { recursive: true, force: true });
  }
}

function qualifiedFile(dir: string, name = "store.yaml"): string {
  const p = join(dir, name);
  writeFileSync(p, "sandboxImage: node@sha256:aaa\n");
  chmodSync(p, 0o600);
  return p;
}

const decl = (path: string, source: SecurityDecl["source"]): SecurityDecl => ({
  key: "sandboxImage",
  lane: "npm",
  value: "node@sha256:aaa",
  source,
  path,
});

const OK = () => ({ ok: true });
const NO = () => ({ ok: false });

test("§3⁗ ABSENT when nothing declares the key", () => {
  assert.deepEqual(honorSecurityKey([]), { kind: "absent" });
});

test("§3⁗ HONORED only reads the qualified fd value", () => {
  withSecureDir((d) => {
    const p = qualifiedFile(d);
    assert.deepEqual(honorSecurityKey([decl(p, "machine")], [], OK), { kind: "honored", value: "node@sha256:aaa" });
  });
});

test("§3⁗ lax-mode (0644) file alone ⇒ PRESENT-UNQUALIFIED (not silently absent)", () => {
  withSecureDir((d) => {
    const p = join(d, "lax.yaml");
    writeFileSync(p, "x: 1\n");
    chmodSync(p, 0o644);
    assert.equal(honorSecurityKey([decl(p, "machine")], [], NO).kind, "present-unqualified");
  });
});

test("§3⁗ foreign value at unqualified repo ⇒ PRESENT-UNQUALIFIED even when its modes are perfect", () => {
  withSecureDir((d) => {
    const p = qualifiedFile(d, "border.yaml");
    assert.equal(honorSecurityKey([decl(p, "repo")], [], OK).kind, "present-unqualified");
  });
});

test("§3⁗ fixture c/d: qualified value + repo declaration ⇒ SHADOWED regardless of value equality", () => {
  withSecureDir((d) => {
    const m = qualifiedFile(d);
    const r = qualifiedFile(d, "border.yaml");
    const state = honorSecurityKey([decl(m, "machine"), decl(r, "repo")], [], OK);
    assert.equal(state.kind, "shadowed");
    if (state.kind === "shadowed") assert.ok(state.shadowedBy.some((s) => s.endsWith("border.yaml")));
  });
});

test("§3⁗ fixtures a/b: active unqualified XDG override shadows BY PRESENCE, files or not", () => {
  withSecureDir((d) => {
    const m = qualifiedFile(d);
    for (const override of ["/tmp/xdg-empty-tier-test", "/nonexistent-xyz-tier-test"]) {
      assert.equal(honorSecurityKey([decl(m, "machine")], [override], OK).kind, "shadowed");
    }
  });
});

test("§3⁗ two QUALIFIED sources for one key ⇒ AMBIGUOUS, no precedence", () => {
  withSecureDir((d) => {
    const a = qualifiedFile(d, "a.yaml");
    const b = qualifiedFile(d, "b.yaml");
    assert.equal(honorSecurityKey([decl(a, "machine"), decl(b, "argv")], [], OK).kind, "ambiguous");
  });
});

test("§3⁖ fixture i: standard layout — 0755 root-owned above, euid 0755 anchor, 0700 chain, 0600 file", () => {
  const home = passwdHome();
  assert.notEqual(home, undefined);
  const chain = join(home!, ".border-tier-probe");
  mkdirSync(chain, { recursive: true });
  chmodSync(chain, 0o700);
  const p = join(chain, "probe.yaml");
  writeFileSync(p, "probe: 1\n");
  chmodSync(p, 0o600);
  try {
    const q = qualifyRead(p);
    assert.equal(q.ok, true, q.ok ? "" : q.reason);
    // and the closed tmp-root set rejects its own turf:
    const t = mkdtempSync(join(tmpdir(), "tier-"));
    const tp = join(t, "x.yaml");
    writeFileSync(tp, "x: 1\n");
    chmodSync(tp, 0o600);
    assert.equal(qualifyRead(tp).ok, false);
    chmodSync(t, 0o700);
    rmSync(t, { recursive: true, force: true });
  } finally {
    rmSync(p, { force: true });
    rmSync(chain, { recursive: true, force: true });
  }
});

test("§3⁖ file mode 0600 and euid ownership are fd-bound (0640 fails)", () => {
  const home = passwdHome()!;
  const p = join(home, ".config", "border", "machines", "tierprobe2.yaml");
  mkdirSync(join(home, ".config", "border", "machines"), { recursive: true });
  writeFileSync(p, "x: 1\n");
  chmodSync(p, 0o640);
  try {
    assert.equal(qualifyRead(p).ok, false);
  } finally {
    rmSync(p, { force: true });
  }
});

test("§3⁖ symlink anywhere in the chain ⇒ qualification failure", () => {
  const home = passwdHome()!;
  mkdirSync(join(home, ".config", "border", "machines"), { recursive: true });
  const link = join(home, ".config", "border", "machines", "tierlink.yaml");
  const target = qualifiedFile(mkdtempSync(join(home, ".config", "border", "tmp-")));
  try {
    symlinkSync(target, link);
    assert.equal(qualifyRead(link).ok, false);
  } finally {
    rmSync(link, { force: true });
    rmSync(target, { force: true });
  }
});

test("§3⁖ qualifyDir judges the anchor by ownership, tolerating 0755 (f9dc must_fix 1)", () => {
  const home = passwdHome()!;
  const st = qualifyDir(join(home, ".config"));
  assert.equal(st.ok, true, st.ok ? "" : st.reason);
  assert.equal(qualifyDir("/tmp").ok, false);
});

test("§3‡ canonical store root derives from passwd, never $HOME", () => {
  const saved = process.env["HOME"];
  process.env["HOME"] = "/tmp/evil-home";
  try {
    const root = canonicalStoreRoot();
    assert.ok(root !== undefined && !root.startsWith("/tmp/evil-home"));
    assert.ok(root !== undefined && root.endsWith("/.config/border/machines"));
  } finally {
    if (saved === undefined) delete process.env["HOME"];
    else process.env["HOME"] = saved;
  }
});

test("§3‡ getent failure falls back to os.homedir, never to $HOME", () => {
  const saved = process.env["HOME"];
  process.env["HOME"] = "/tmp/evil-home-2";
  try {
    const h = passwdHome(
      () => {
        throw new Error("simulated getent absence");
      },
      () => {
        throw new Error("simulated passwd DB unreadable");
      },
    );
    assert.equal(h, undefined, "both passwd sources failing must yield UNDEFINED, never $HOME");
  } finally {
    if (saved === undefined) delete process.env["HOME"];
    else process.env["HOME"] = saved;
  }
});
