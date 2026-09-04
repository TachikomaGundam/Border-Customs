// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 19
//
// G14 allow post-filter. The allow-list is the ONLY sanctioned suppression
// path: a finding is dropped iff an explicit {rule, match, file?} entry matches
// it, and every drop is ENUMERATED in report.allowHits (nothing hidden
// silently — plan AC "exit 0 with every suppressed finding enumerated").
// These units pin: match semantics (rule glob, valueDigest/snippet glob,
// file scoping incl. absolute paths and archive `!<inner>` attribution),
// first-entry-wins, hit aggregation, the blanket-shape config guards, the
// allow∈configDigest fingerprint proof (stale_state ultraqa), and the
// explicit-empty-config no-op predicate (red-first characterization).
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { after, test } from "node:test";

import { loadConfig, parseConfig, ConfigError } from "../src/config.ts";
import { computeConfigDigest } from "../src/check/rulesHash.ts";
import { applyAllowList } from "../src/check/allow.ts";
import type { AllowHit, Finding } from "../src/findings.ts";
import { run } from "../src/cli.ts";
import { EXIT_PASS } from "../src/cli/exit.ts";
import { readLedger } from "../src/ledger.ts";
import { requireGitleaks } from "./helpers/require-engines.ts";
import { gitAddCommit, gitInit, makeFixtureDir, removeDir, writeRel } from "./helpers/fixtures.ts";

const roots: string[] = [];
after(() => {
  for (const d of roots) removeDir(d);
});

function fixture(name: string): string {
  const root = makeFixtureDir(`allow-${name}`);
  roots.push(root);
  return root;
}

const DIGEST_A = "a".repeat(64);
const DIGEST_B = "b".repeat(64);

function finding(over: Partial<Finding> & Pick<Finding, "rule">): Finding {
  return {
    severity: "CRITICAL",
    target: "git",
    engine: "unit",
    message: "planted",
    valueDigest: DIGEST_A,
    snippet: "\u25ae\u25ae\u25ae\u25ae",
    ...over,
  };
}

// ---------------------------------------------------------------- filtering

test("entry matches on rule glob + valueDigest: suppression recorded with count and sample", () => {
  const { kept, allowHits } = applyAllowList(
    [finding({ rule: "aws-access-token", path: "test/a.test.ts" })],
    [{ rule: "aws-*", match: DIGEST_A, file: "test/**" }],
    "/repo",
  );
  assert.deepEqual(kept, []);
  assert.equal(allowHits.length, 1);
  const hit = allowHits[0] as AllowHit;
  assert.equal(hit.rule, "aws-*");
  assert.equal(hit.count, 1);
  assert.equal(hit.sample, "test/a.test.ts");
  assert.equal(hit.entryIndex, 0);
});

test("entry also matches on masked snippet glob (≤12-char values share ▮▮▮▮; digest stays the precise seam)", () => {
  const f = finding({ rule: "@secretlint/secretlint-rule-aws/AWSAccessKeyId", snippet: "AKIA…FAKE", valueDigest: DIGEST_B });
  const bySnippet = applyAllowList([f], [{ rule: f.rule, match: "AKIA…*", file: undefined }], "/repo");
  assert.deepEqual(bySnippet.kept, []);
  // A snippet-glob that does not match leaves the finding in place.
  const miss = applyAllowList([f], [{ rule: f.rule, match: "ghp_*", file: undefined }], "/repo");
  assert.equal(miss.kept.length, 1);
  assert.equal(miss.allowHits.length, 0);
});

test("file scoping: entry without file hits path-less findings; entry with file never suppresses them", () => {
  const noPath = finding({ rule: "identity-not-allowlisted" });
  const withPath = finding({ rule: "identity-not-allowlisted", path: "docs/x.md" });
  const scoped = applyAllowList([noPath, withPath], [{ rule: "identity-*", match: DIGEST_A, file: "notes/**" }], "/repo");
  assert.deepEqual(scoped.kept.map((f) => f.path), [undefined, "docs/x.md"]);
  assert.equal(scoped.allowHits.length, 0);
  const unscoped = applyAllowList([noPath], [{ rule: "identity-*", match: DIGEST_A }], "/repo");
  assert.deepEqual(unscoped.kept, []);
  assert.equal(unscoped.allowHits[0]?.count, 1);
});

test("file scoping normalizes absolute paths and strips archive `!<inner>` attribution", () => {
  const repo = "/repo";
  const abs = finding({ rule: "aws-access-token", path: "/repo/dist/pkg.tgz!lib/leak.js" });
  const out = finding({ rule: "aws-access-token", path: "/elsewhere/dist/pkg.tgz!lib/leak.js" });
  const r1 = applyAllowList([abs], [{ rule: "aws-*", match: DIGEST_A, file: "dist/**" }], repo);
  assert.equal(r1.allowHits[0]?.count, 1, "abs path under repoDir + archive tail must scope-match dist/**");
  const r2 = applyAllowList([out], [{ rule: "aws-*", match: DIGEST_A, file: "dist/**" }], repo);
  assert.equal(r2.kept.length, 1, "paths outside the repo never match a file scope");
});

test("first matching entry wins; hits aggregate per entry in config order", () => {
  const findings = [
    finding({ rule: "aws-access-token", path: ".omo/evidence/a.txt" }),
    finding({ rule: "aws-access-token", path: ".omo/plans/b.md" }),
    finding({ rule: "aws-access-token", path: "test/c.test.ts" }),
  ];
  const allow = [
    { rule: "aws-access-token", match: DIGEST_A, file: "test/**" },
    { rule: "aws-access-token", match: DIGEST_A, file: ".omo/**" },
  ];
  const { kept, allowHits } = applyAllowList(findings, allow, "/repo");
  assert.equal(kept.length, 0);
  assert.equal(allowHits.length, 2);
  const byIndex = new Map(allowHits.map((h) => [h.entryIndex, h]));
  assert.equal((byIndex.get(1) as AllowHit).count, 2);
  assert.equal((byIndex.get(1) as AllowHit).sample, ".omo/evidence/a.txt");
  assert.equal((byIndex.get(0) as AllowHit).count, 1);
});

test("no allow entries ⇒ identity pass-through (report shape untouched)", () => {
  const findings = [finding({ rule: "x" })];
  const r = applyAllowList(findings, [], "/repo");
  assert.deepEqual(r.kept, findings);
  assert.deepEqual(r.allowHits, []);
});

// ---------------------------------------------------------------- config guards

const BASE_YAML = `version: 1
targets:
  git:
    remotes:
      - name: origin
        url: origin.example:widgets.git
rules:
  authors:
    emails: []
    names: []
  hosts: []
  ips: []
  pathPatterns: []
`;

function parseWith(allowBlock: string): unknown {
  return parseConfig(`${BASE_YAML}\nallow:\n${allowBlock}\n`);
}

// The plan's Must-NOT targets the BLANKET shape — wildcard suppression with
// no scoping at all. Concrete-value or concrete-rule wildcards stay legal,
// and a wildcard pair bound to a file glob is legal too (that is precisely
// how the sanctioned dogfood categories (a) .omo/** / (b) test/** read).
test("blanket unscoped `{rule: \"*\", match: \"*\"}` is rejected; scoped wildcards and concrete patterns parse (plan Must-NOT)", () => {
  assert.throws(() => parseWith(`  - {rule: "*", match: "*"}`), (e: unknown) => e instanceof ConfigError && e.kind === "invalid-value");
  const ok = parseWith(
    `  - {rule: "*", match: "${DIGEST_A}"}\n  - {rule: "aws-access-token", match: "*"}\n  - {rule: "*", match: "*", file: "test/**"}`,
  ) as { allow: unknown[] };
  assert.equal(ok.allow.length, 3);
});

test("malformed allow entries fail typed at load: empty strings, absolute or escaping file globs (malformed_input ultraqa)", () => {
  for (const block of [
    `  - {rule: "", match: "x"}`,
    `  - {rule: "r", match: ""}`,
    `  - {rule: "r", match: "x", file: "/etc/**"}`,
    `  - {rule: "r", match: "x", file: "../escape/**"}`,
    `  - {rule: "r", match: "x", file: "a/../b"}`,
  ]) {
    assert.throws(() => parseWith(block), (e: unknown) => e instanceof ConfigError && e.kind === "invalid-value", `must reject: ${block}`);
  }
  // A well-formed entry still parses untouched.
  const ok = parseWith(`  - {rule: "aws-access-token", match: "${DIGEST_A}", file: "test/**"}`) as { allow: unknown[] };
  assert.equal(ok.allow.length, 1);
});

// ---------------------------------------------------------------- fingerprint

test("stale_state guard: allow[] rides in configDigest ⇒ editing an entry invalidates the skip fingerprint", async () => {
  const dir = fixture("digest");
  gitInit(dir);
  writeRel(dir, "border.yaml", `${BASE_YAML}\nallow: []\n`);
  gitAddCommit(dir, "cfg a");
  const loadA = loadConfig({ cwd: dir, env: {} });
  assert.ok(loadA.kind === "loaded");
  writeRel(
    dir,
    "border.yaml",
    `${BASE_YAML}\nallow:\n  - {rule: "aws-access-token", match: "${DIGEST_A}", file: "test/**"}\n`,
  );
  gitAddCommit(dir, "cfg b");
  const loadB = loadConfig({ cwd: dir, env: {} });
  assert.ok(loadB.kind === "loaded");
  assert.notEqual(computeConfigDigest(loadA), computeConfigDigest(loadB));
  // configDigest folds into rulesHash which folds into the ledger key
  // (computeCheckKey), so any allow[] edit invalidates a recorded PASS —
  // the full-chain live proof is the dogfood run in the evidence file.
});

// ---------------------------------------------------------------- no-op predicate

function dogfoodYaml(remotesBlock: string): string {
  return `version: 1
targets:
  git:
    remotes:${remotesBlock}
rules:
  authors:
    emails: ["wiki@sumteclab.com"]
    names: ["Wiki.js"]
  hosts: []
  ips: []
  pathPatterns: []
`;
}

test("explicit-but-empty config keeps kind 'no-op' but carries the parsed config (payload for the check predicate)", (t) => {
  void t;
  const dir = fixture("noop-payload");
  gitInit(dir);
  writeRel(dir, "border.yaml", dogfoodYaml(" []"));
  gitAddCommit(dir, "seed");
  const res = loadConfig({ cwd: dir, env: {} });
  assert.ok(res.kind === "no-op");
  assert.ok(res.explicit !== undefined, "explicit-file no-op must carry the parsed config for the check flow");
  assert.equal(res.explicit.config.targets.git.remotes.length, 0);
  assert.ok(res.explicit.source.endsWith("border.yaml"));
});

test("undiscovered config ⇒ no-op with NO explicit payload (todo-2 contract intact)", (t) => {
  void t;
  const dir = fixture("noop-discovery");
  gitInit(dir);
  writeRel(dir, "f.txt", "x");
  gitAddCommit(dir, "seed");
  const res = loadConfig({ cwd: dir, env: {} });
  assert.ok(res.kind === "no-op");
  assert.equal(res.explicit, undefined);
});

test("live pipeline: explicit-empty config RUNS repo-local scans (never the vacuous no-op) and ledgers a PASS", async (t) => {
  requireGitleaks();
  void t;
  const dir = fixture("explicit-run");
  gitInit(dir);
  writeRel(dir, "border.yaml", dogfoodYaml(" []"));
  writeRel(dir, "notes.txt", "clean\n");
  gitAddCommit(dir, "seed");
  const out: string[] = [];
  const err: string[] = [];
  const code = (await run(["check"], (l) => out.push(l), (l) => err.push(l), { cwd: dir, env: { ...process.env, HOME: process.env["HOME"] ?? "" } })) as number;
  assert.equal(code, EXIT_PASS, `expected PASS run, got ${String(code)}; out=${out.join("|")} err=${err.join("|")}`);
  assert.ok(!out.join("\n").includes("no-op"), "must not collapse to the discovery no-op");
  const read = readLedger(dir);
  const checks = read.records.filter((r) => r.t === "check");
  assert.equal(checks.length, 1, "the run must be ledgered (no-ops never are)");
  const rec = checks[0];
  assert.ok(rec !== undefined && rec.t === "check");
  assert.deepEqual([...rec.effectiveTargets], [], "no publish targets configured");
  assert.deepEqual([...rec.exposureSet], [], "exposureSet is empty for an explicit-empty config");
  // report.json really exists next to the record
  const raw = JSON.parse(readFileSync(join(dir, rec.reportPath), "utf8")) as { verdict: string };
  assert.equal(raw.verdict, "PASS");
  assert.ok(existsSync(join(dir, rec.reportPath)));
});

test("border.yaml self suppresses the todo-19b config-path findings, never another file", () => {
  const cfg = parseConfig(readFileSync(new URL("../border.yaml", import.meta.url), "utf8"));
  const mk = (rule: string, path: string): Finding => finding({ rule, path });
  const selfTriggers = [
    mk("@secretlint/secretlint-rule-no-homedir/HOMEDIR", "border.yaml"),
    mk("path-pattern:/home/[a-z]+/", "border.yaml"),
  ];
  const elsewhere = [
    mk("@secretlint/secretlint-rule-no-homedir/HOMEDIR", "notes.md"),
    mk("path-pattern:/home/[a-z]+/", "notes.md"),
  ];
  const { kept, allowHits } = applyAllowList([...selfTriggers, ...elsewhere], cfg.allow, "/repo");
  assert.deepEqual(kept.map((f) => f.path), ["notes.md", "notes.md"]);
  assert.deepEqual(
    allowHits.map((h) => [h.rule, h.count, h.sample]),
    [
      ["@secretlint/secretlint-rule-no-homedir/*", 1, "border.yaml"],
      ["path-pattern:*", 1, "border.yaml"],
    ],
  );
});
