// provenance: .omo/plans/border-exfil-lens.md T2 — pipeline guards for the
// exfil lens: TWIN-ID-EQUALITY (parse the REAL artifacts: the vendored TOML
// bytes + the live secretlint emission), FULL-MATRIX-GUARD (the pipeline's
// observed emissions against severity.ts), ALLOW-ISOLATION-BIDIRECTIONAL
// (production applyAllowList), RULESHASH-TOML-ROTATION (the new TOML rides
// the fingerprint), plus the engine-health exemption proof for the native
// legs (degraded gitleaks never silences them).
import assert from "node:assert/strict";
import { copyFileSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { after, test } from "node:test";

import { executeCheck } from "../src/check.ts";
import { scanExfilTree } from "../src/check/exfilTreeScan.ts";
import { applyAllowList } from "../src/check/allow.ts";
import { computeCheckRulesHash } from "../src/check/rulesHash.ts";
import type { BorderConfig } from "../src/config.ts";
import type { Finding } from "../src/findings.ts";
import { computeRulesHash, TextSanitizer } from "../src/redact.ts";
import { scanTree } from "../src/engines/gitleaks.ts";
import { scanPaths } from "../src/engines/secretlint.ts";
import {
  EXFIL_CHANNELS,
  EXFIL_HIGH_FAMILY,
  EXFIL_MATRIX,
  EXFIL_MEDIUM_FAMILY,
  EXFIL_RULE_IDS,
  emitRulesFor,
  observedSeverity,
} from "../src/exfil/severity.ts";
import { DEFAULT_EXEMPT_BANDS, EXFIL_TWIN_PATTERNS, matchRfc1918, matchSshTarget } from "../src/exfil/rules.ts";
import { scanMessageText, scanTreeText } from "../src/exfil/scan.ts";
import { GITLEAKS_VENDORED_CONFIG } from "../src/engines/gitleaks.ts";
import { requireGitleaks } from "./helpers/require-engines.ts";
import { BORDER_ROOT, assembleHost, assembleOctet, gitAddCommit, gitInit, makeFixtureDir, removeDir, writeRel } from "./helpers/fixtures.ts";

requireGitleaks();

const roots: string[] = [];
after(() => {
  for (const d of roots) removeDir(d);
});

function fixture(name: string): string {
  const dir = makeFixtureDir(`expip-${name}`);
  roots.push(dir);
  return dir;
}

/** The same planted text drives every channel fixture: one hit per matrix family. */
const PROBE_TEXT = `peer ${assembleOctet("10.31.4", "5")} joined\nssh ${assembleHost("synthuser", "synthdb", "internal")} now\ncopy /home/synthuser/x done\nrotate staging.env nightly\n`;

// ---------------------------------------------------------------- TWIN-ID-EQUALITY (real artifacts)

test("TWIN-ID-EQUALITY: the vendored TOML carries both HIGH-family ids verbatim, exactly once", () => {
  const toml = readFileSync(join(BORDER_ROOT, "assets", "gitleaks-defaults-v8.30.1.toml"), "utf8");
  for (const rule of EXFIL_HIGH_FAMILY) {
    const hits = toml.split("\n").filter((l) => /^id = ".+"$/.test(l) && l.includes(`"${rule}"`));
    assert.equal(hits.length, 1, `TOML must define id "${rule}" exactly once, got ${String(hits.length)}`);
  }
  for (const rule of EXFIL_MEDIUM_FAMILY) {
    assert.ok(!toml.includes(`id = "${rule}"`), `MEDIUM family never rides the gitleaks channel: ${rule}`);
  }
  assert.deepEqual(EXFIL_TWIN_PATTERNS.map((p) => p.name), [...EXFIL_HIGH_FAMILY], "secretlint twin ids = pattern names = rule ids");
});

test("TWIN-ID-EQUALITY: the LIVE engines emit the ids verbatim at the matrix severity (CRITICAL)", async () => {
  const dir = fixture("twin-emit");
  writeRel(dir, "notes.txt", PROBE_TEXT);
  const lint = await scanPaths({ dir, files: ["notes.txt"], target: "tree" });
  const exfilLint = lint.filter((f) => f.rule.startsWith("exfil-"));
  assert.deepEqual([...new Set(exfilLint.map((f) => f.rule))].sort(), [...EXFIL_HIGH_FAMILY].sort(), "secretlint emits exactly the HIGH family under verbatim ids");
  for (const f of exfilLint) {
    assert.equal(f.severity, "CRITICAL", "secretlint has no HIGH rung — error→CRITICAL is the honest observed severity");
    assert.equal(f.engine, "secretlint");
  }
  const gl = scanTree({ dir, stateDir: join(dir, ".border-state"), target: "tree" });
  const exfilGl = new Set(gl.filter((f) => f.rule.startsWith("exfil-")).map((f) => f.rule));
  assert.ok(exfilGl.has("exfil-rfc1918") && exfilGl.has("exfil-ssh-target"), `gitleaks emits both ids, got ${JSON.stringify([...exfilGl])}`);
  for (const f of gl) if (f.rule.startsWith("exfil-")) assert.equal(f.severity, "CRITICAL");
});

// ---------------------------------------------------------------- FULL-MATRIX-GUARD

test("FULL-MATRIX-GUARD: every pipeline emission sits on a declared matrix cell; forbidden cells never emit", async () => {
  // exhaustive cell shape
  for (const facet of ["tree", "message", "tagNote"] as const) {
    for (const channel of EXFIL_CHANNELS) {
      for (const rule of EXFIL_RULE_IDS) {
        const cell = observedSeverity(rule, facet, channel);
        assert.equal(cell, EXFIL_MATRIX[facet][channel][rule]);
        assert.ok(cell === null || (["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"] as readonly string[]).includes(cell), `cell ${rule}/${facet}/${channel} typed`);
      }
    }
  }
  // native tree leg (real repo fixture): MEDIUM family only, HIGH family unemittable
  const dir = fixture("matrix-tree");
  gitInit(dir);
  writeRel(dir, "notes.txt", PROBE_TEXT);
  gitAddCommit(dir, "seed");
  const tree = scanExfilTree({ repoDir: dir });
  const rules = new Set(tree.map((f) => f.rule));
  assert.ok(rules.has("exfil-home-path") && rules.has("exfil-cred-location"), "tree cells emit their MEDIUM severities");
  for (const f of tree) {
    assert.ok(!EXFIL_HIGH_FAMILY.includes(f.rule as (typeof EXFIL_HIGH_FAMILY)[number]), `native tree must never emit ${f.rule}`);
    assert.equal(f.severity, observedSeverity(f.rule as (typeof EXFIL_RULE_IDS)[number], "tree", "native"));
    assert.equal(f.engine, "border-exfil");
  }
  // the twins never scan messages, and no channel scans tag notes with exfil ids
  assert.deepEqual([...emitRulesFor("message", "gitleaks-twin")], []);
  for (const channel of EXFIL_CHANNELS) assert.deepEqual([...emitRulesFor("tagNote", channel)], []);
  // scanTreeText (the native surface itself) cannot emit forbidden ids
  for (const f of scanTreeText({ text: PROBE_TEXT, source: "x.txt" })) {
    assert.notEqual(observedSeverity(f.rule, "tree", "native"), null);
  }
});

// ---------------------------------------------------------------- ALLOW-ISOLATION-BIDIRECTIONAL

function mkFinding(rule: string, path: string): Finding {
  return { rule, severity: "HIGH", target: "git", path, line: 1, engine: "border-exfil", message: "isolated?", valueDigest: "a".repeat(64), snippet: "▮▮▮▮" };
}

test("ALLOW-ISOLATION-BIDIRECTIONAL: blob-face exemptions never pierce the :message family, nor vice versa (applyAllowList semantics)", () => {
  const SHA = "b".repeat(40);
  const blob = mkFinding("exfil-rfc1918", "docs/x.md");
  const msg = mkFinding("exfil-rfc1918:message", SHA);
  const entryBlob = { rule: "exfil-rfc1918", match: "*", file: "docs/x.md" } as const;
  const keptByBlob = applyAllowList([blob, msg], [entryBlob], "/repo");
  assert.deepEqual(keptByBlob.kept.map((f) => f.rule), ["exfil-rfc1918:message"], "blob exemption does not swallow the :message finding");
  assert.equal(keptByBlob.allowHits[0]?.count, 1);

  const entryMsg = { rule: "exfil-rfc1918:message", match: "*", file: SHA } as const;
  const keptByMsg = applyAllowList([blob, msg], [entryMsg], "/repo");
  assert.deepEqual(keptByMsg.kept.map((f) => f.rule), ["exfil-rfc1918"], ":message exemption does not swallow the blob finding");
  assert.equal(keptByMsg.allowHits[0]?.count, 1, "per-commit sha allow rows work (path=sha passes toRepoRelative verbatim)");

  const any = applyAllowList([blob, msg], [], "/repo");
  assert.equal(any.kept.length, 2);
});

// ---------------------------------------------------------------- RULESHASH / TOML rotation

test("RULESHASH-TOML-ROTATION: live hash deterministic; a one-byte vendored-TOML edit rotates it", async () => {
  const base = { engineVersions: {}, configDigest: "c".repeat(64) };
  const h1 = await computeCheckRulesHash({ ...base });
  assert.equal(h1, await computeCheckRulesHash({ ...base }), "deterministic across runs");

  const dir = fixture("toml-rot");
  const a = join(dir, "tomlA.toml");
  const b = join(dir, "tomlB.toml");
  copyFileSync(GITLEAKS_VENDORED_CONFIG, a);
  writeFileSync(b, `${readFileSync(a, "utf8")}\n# +1 byte\n`, "utf8");
  const shared = { configDigest: "c".repeat(64), engineVersions: {}, promptTemplatePaths: [] };
  const ha = await computeRulesHash({ ...shared, bundledRulePaths: [a] });
  const hb = await computeRulesHash({ ...shared, bundledRulePaths: [b] });
  assert.notEqual(ha, hb, "a TOML rule-table edit must invalidate every cached PASS (plan R1)");
});

// ---------------------------------------------------------------- native legs eat NO engine degradation

function stubBrokenGitleaks(): NodeJS.ProcessEnv {
  const dir = mkdtempSync(join(BORDER_ROOT, "test", "tmp", "expip-stub-"));
  roots.push(dir);
  writeFileSync(join(dir, "gitleaks"), "#!/bin/sh\nexit 99\n", { mode: 0o755 });
  return { ...process.env, PATH: `${dir}:${process.env.PATH ?? ""}` } as NodeJS.ProcessEnv;
}

test("ENGINE-NOT-GATED: with gitleaks degraded, the native exfil tree leg AND the message leg still fire", async () => {
  const dir = fixture("degraded-native");
  gitInit(dir);
  writeRel(dir, "border.yaml", "version: 1\ntargets:\n  git:\n    remotes: []\nrules:\n  authors:\n    emails: [bot@gate-corp.com]\n    names: [Wiki.js]\n  hosts: []\n  ips: []\n  pathPatterns: []\n");
  writeRel(dir, "notes.txt", PROBE_TEXT);
  gitAddCommit(dir, "sync the mirror 10.200.30.40 nightly");
  const cfg: BorderConfig = {
    version: 1,
    targets: { git: { remotes: [] } },
    rules: { authors: { emails: ["bot@gate-corp.com"], names: ["Wiki.js"] }, hosts: [], ips: [], pathPatterns: [], maxFileKB: 500 },
    allow: [],
    engines: { require: ["gitleaks", "secretlint"], trufflehog: false },
  };
  const outcome = await executeCheck({ repoDir: dir, cfg, configDigest: "e".repeat(64), effectiveTargets: ["git"], env: stubBrokenGitleaks() });
  assert.equal(outcome.degraded, true, "the stub must have degraded the run — that is the point of the fixture");
  assert.ok(outcome.report.findings.some((f) => f.rule === "DEGRADED-ENGINE" && f.engine === "gitleaks"));
  const rules = new Set(outcome.report.findings.map((f) => f.rule));
  assert.ok(rules.has("exfil-home-path"), "native tree leg survived the broken gitleaks (broken.has never gates it)");
  assert.ok(rules.has("exfil-cred-location"));
  assert.ok(rules.has("exfil-rfc1918:message"), "message leg survived: the planted commit message still reads HIGH on the public face");
  const msg = outcome.report.findings.find((f) => f.rule === "exfil-rfc1918:message");
  assert.equal(msg?.severity, "HIGH");
  assert.match(msg?.path ?? "", /^[0-9a-f]{40}$/, "sha attribution survives into the report path");
  const gitleaksExfil = outcome.report.findings.filter((f) => f.rule === "exfil-rfc1918" && f.engine === "gitleaks");
  assert.deepEqual(gitleaksExfil, [], "the broken gitleaks twin leg was (correctly) skipped — and only it was skipped");
});

// ---------------------------------------------------------------- F2 VERDICT PARITY (the twins' real contract)

const sha = (v: string): string => createHash("sha256").update(v, "utf8").digest("hex");

/**
 * The SAME line-set must read the SAME on every channel at the tree facet:
 * fixture band / loopback / RFC5737 green everywhere, real-shape RFC1918 red
 * everywhere (id-equality without verdict parity was the round-2 hole).
 * Real-shape literals are assembled at runtime per the F3 fixture doctrine —
 * the checked-out bytes carry only 10.200/16 band quads and prefixes.
 */
test("VERDICT-PARITY: native tree policy, secretlint twin and gitleaks twin agree red/green line-by-line", async () => {
  const REAL_10 = assembleOctet("10.31.4", "5");
  const REAL_172 = assembleOctet("172.20.30", "40");
  const REAL_192 = assembleOctet("192.168.13", "37");
  const corpus = [
    "band one 10.200.30.40",
    "band two 10.200.13.37",
    "loop 127.0.0.1",
    "doc one 192.0.2.1",
    "doc two 198.51.100.7",
    "doc three 203.0.113.9",
    `real ten ${REAL_10}`,
    `real one-seven-two ${REAL_172}`,
    `real one-nine-two ${REAL_192}`,
    "ssh band synthuser@10.200.30.40",
    `ssh real synthuser@${REAL_172}`,
    `ssh suffix ${assembleHost("deploy", "synth-one", "lan")}`,
    "mail synthuser@example.com",
    `version string 1.${REAL_10} no-match`,
  ];
  const text = `${corpus.join("\n")}\n`;

  const expected = new Set([sha(REAL_10), sha(REAL_172), sha(REAL_192), sha(`synthuser@${REAL_172}`), sha(assembleHost("deploy", "synth-one", "lan"))]);
  for (const band of ["10.200.30.40", "10.200.13.37", "synthuser@10.200.30.40"]) {
    assert.ok(!expected.has(sha(band)), `band member ${band} must be green on every channel`);
  }

  const native = new Set<string>();
  for (const f of [...matchRfc1918(text, { facet: "tree" }), ...matchSshTarget(text, { facet: "tree" })]) native.add(sha(f.matched));

  const dir = fixture("parity");
  writeRel(dir, "corpus.txt", text);
  const lint = new Set((await scanPaths({ dir, files: ["corpus.txt"], target: "tree" })).filter((f) => f.rule.startsWith("exfil-")).map((f) => f.valueDigest));
  const gl = new Set(scanTree({ dir, stateDir: join(dir, ".border-state"), target: "tree" }).filter((f) => f.rule.startsWith("exfil-")).map((f) => f.valueDigest));

  assert.deepEqual([...native].sort(), [...expected].sort(), "native tree predicate = expected verdict set");
  assert.deepEqual([...lint].sort(), [...expected].sort(), "secretlint twin verdicts match the native tree policy exactly");
  assert.deepEqual([...gl].sort(), [...expected].sort(), "gitleaks twin verdicts match (named-secret extraction + per-rule band allowlists)");

  // the exemption list is the closed contract both twins mirror:
  assert.deepEqual(DEFAULT_EXEMPT_BANDS, ["127", "192.0.2", "198.51.100", "203.0.113", "10.200"]);
});

// ---------------------------------------------------------------- F4 legibility (location class never registers)

test("F4-LEGIBILITY: location-class matches never enter the sanitizer; identifier-class matches do", () => {
  const dir = fixture("legible-unit");
  gitInit(dir);
  writeRel(dir, "notes.txt", "copied config from /home/synthuser\nupload with ~/.pypirc\n");
  gitAddCommit(dir, "docs: benign note");
  const san = new TextSanitizer();
  const findings = scanExfilTree({ repoDir: dir, sanitizer: san });
  assert.ok(findings.some((f) => f.rule === "exfil-home-path") && findings.some((f) => f.rule === "exfil-cred-location"), "fixture must light the location class");
  const probe = "copied config from /home/synthuser and ~/.pypirc as usual";
  assert.equal(san.sanitize(probe), probe, "F4: location strings survive every later render — registration is identifier-class only");

  const san2 = new TextSanitizer();
  const msg = scanMessageText({
    text: `mirror 10.200.30.40 pinged`,
    source: "f".repeat(40),
    onMatch: (raw, digest) => san2.register(digest, raw),
  });
  assert.ok(msg.some((m) => m.rule === "exfil-rfc1918"), "identifier-class control fires");
  assert.match(san2.sanitize("mirror 10.200.30.40 pinged"), /\[REDACTED:[0-9a-f]{8}\]/, "identifier class still registers (the value must not resurface)");
});

test("F4-LEGIBILITY (end-to-end): a healthy executeCheck renders home-path lines verbatim", async () => {
  const dir = fixture("legible-check");
  gitInit(dir);
  writeRel(dir, "border.yaml", "version: 1\ntargets:\n  git:\n    remotes: []\nrules:\n  authors:\n    emails: [bot@gate-corp.com]\n    names: [Wiki.js]\n  hosts: []\n  ips: []\n  pathPatterns: []\n");
  writeRel(dir, "notes.txt", "copied config from /home/synthuser\nupload with ~/.pypirc\n");
  gitAddCommit(dir, "docs: benign note");
  const cfg: BorderConfig = {
    version: 1,
    targets: { git: { remotes: [] } },
    rules: { authors: { emails: ["bot@gate-corp.com"], names: ["Wiki.js"] }, hosts: [], ips: [], pathPatterns: [], maxFileKB: 500 },
    allow: [],
    engines: { require: ["gitleaks", "secretlint"], trufflehog: false },
  };
  const outcome = await executeCheck({ repoDir: dir, cfg, configDigest: "d".repeat(64), effectiveTargets: ["git"] });
  assert.equal(outcome.degraded, false, "healthy-engine leg of the legibility proof");
  assert.match(outcome.sanitizedSummary, /MEDIUM exfil-home-path border-exfil notes\.txt Home-directory path/, "both location findings render as their own legible line");
  assert.match(outcome.sanitizedSummary, /MEDIUM exfil-cred-location border-exfil notes\.txt/);
  assert.ok(!outcome.sanitizedSummary.includes("[REDACTED"), "no redaction storm on location-class output (the round-2 unreadability regression stays dead)");
});
