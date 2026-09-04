// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 9
//
// Identity-allowlist rule tests. Fixtures are throwaway git repos under
// test/tmp (gitignored) with FORGED author/committer/tagger idents via
// GIT_AUTHOR_*/GIT_COMMITTER_* env overrides — the only honest way to plant
// a "foreign" identity without touching the real user config.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { test } from "node:test";

import { parseConfig, type BorderConfig } from "../src/config.ts";
import { validateFinding } from "../src/findings.ts";
import { TextSanitizer } from "../src/redact.ts";
import { IDENTITY_RULE, matchGlob, scanIdentity } from "../src/rules/identity.ts";
import { gitInit, makeFixtureDir, removeDir, writeRel } from "./helpers/fixtures.ts";

const WIKI = { name: "Wiki.js", email: "wiki@sumteclab.com" };
const EVIL = { name: "Joe Evil", email: "evil@personal.example" };
const DEPENDABOT = { name: "dependabot[bot]", email: "4999333+dependabot[bot]@users.noreply.github.com" };

let fileCounter = 0;

function gitRun(dir: string, args: readonly string[], env: Record<string, string> = {}): string {
  const r = spawnSync("git", args, {
    cwd: dir,
    encoding: "utf8",
    env: { ...process.env, GIT_CEILING_DIRECTORIES: dirname(dir), ...env },
  });
  if (r.status !== 0) {
    throw new Error(`git ${args.join(" ")} failed (${String(r.status)}): ${r.stderr}`);
  }
  return r.stdout ?? "";
}

type Ident = { name: string; email: string };

function identEnv(who: Ident): Record<string, string> {
  return {
    GIT_AUTHOR_NAME: who.name,
    GIT_AUTHOR_EMAIL: who.email,
    GIT_COMMITTER_NAME: who.name,
    GIT_COMMITTER_EMAIL: who.email,
  };
}

function commitAs(dir: string, who: Ident): string {
  fileCounter += 1;
  writeRel(dir, `f${String(fileCounter)}.txt`, `x${String(fileCounter)}\n`);
  gitRun(dir, ["add", "-A"]);
  gitRun(dir, ["commit", "-q", "--no-gpg-sign", "-m", `c${String(fileCounter)}`], identEnv(who));
  return gitRun(dir, ["rev-parse", "HEAD"]).trim();
}

function mergeAs(dir: string, branch: string, author: Ident, committer: Ident): string {
  gitRun(dir, ["merge", "--no-ff", "-m", "merge", branch], { ...identEnv(author), ...identEnv(committer) });
  return gitRun(dir, ["rev-parse", "HEAD"]).trim();
}

function tagAs(dir: string, tag: string, tagger: Ident): void {
  gitRun(dir, ["tag", "-a", tag, "-m", `release ${tag}`], identEnv(tagger));
}

function cfgWith(opts: {
  emails: readonly string[];
  names: readonly string[];
  allowBots?: boolean;
}): BorderConfig {
  const botsLine = opts.allowBots === undefined ? "" : `    allowBots: ${String(opts.allowBots)}\n`;
  return parseConfig(
    `version: 1
targets:
  git:
    remotes: []
rules:
  authors:
    emails: [${opts.emails.map((e) => JSON.stringify(e)).join(", ")}]
    names: [${opts.names.map((n) => JSON.stringify(n)).join(", ")}]
${botsLine}  hosts: []
  ips: []
  pathPatterns: []
`,
  );
}

const CLEAN_CFG = cfgWith({ emails: ["wiki@sumteclab.com", "*@company.example"], names: ["Wiki.js", "*"] });

function newRepo(): string {
  const dir = makeFixtureDir("identity");
  gitInit(dir);
  return dir;
}

function scan(dir: string, refSet: readonly string[], cfg: BorderConfig) {
  return scanIdentity({ repoDir: dir, refSet, cfg });
}

// ---------------------------------------------------------------- glob matcher

test("matchGlob: * spans anything, ? is exactly one char, anchors at both ends", () => {
  assert.equal(matchGlob("*", "anything"), true);
  assert.equal(matchGlob("*.example", "foo.example"), true);
  assert.equal(matchGlob("*.example", "foo.example.evil"), false, "trailing suffix must anchor at end");
  assert.equal(matchGlob("foo", "foobar"), false, "no implicit substring");
  assert.equal(matchGlob("foo", "barfoo"), false);
  assert.equal(matchGlob("a?c", "abc"), true);
  assert.equal(matchGlob("a?c", "ac"), false, "? consumes exactly one character");
  assert.equal(matchGlob("a?c", "abcd"), false);
  assert.equal(matchGlob("?*?", "ab"), true);
  assert.equal(matchGlob("?*?", "a"), false);
  assert.equal(matchGlob("a*b*c", "abbbc"), true);
  assert.equal(matchGlob("", ""), true);
  assert.equal(matchGlob("", "x"), false);
});

test("matchGlob: [ ] are literals (dependabot shape), matching is case-sensitive", () => {
  assert.equal(
    matchGlob("*[bot]@users.noreply.github.com", "4999333+dependabot[bot]@users.noreply.github.com"),
    true,
  );
  assert.equal(matchGlob("ABC", "abc"), false, "case-insensitivity is applied by the CALLER, not the matcher");
});

// ---------------------------------------------------------------- AC1: basic violation

test("AC1: one commit authored by a non-allowlisted identity yields exactly one CRITICAL listing its sha", () => {
  const dir = newRepo();
  try {
    const evilSha = commitAs(dir, EVIL);
    const findings = scan(dir, ["main"], CLEAN_CFG);
    assert.equal(findings.length, 1, `expected exactly 1 finding, got ${String(findings.length)}`);
    const f = findings[0] as ReturnType<typeof validateFinding>;
    validateFinding(f);
    assert.equal(f.rule, IDENTITY_RULE);
    assert.equal(f.severity, "CRITICAL");
    assert.equal(f.commit, evilSha);
    assert.ok(f.message.includes("evil@personal.example"), f.message);
    assert.ok(f.message.includes("Joe Evil"), f.message);
    assert.ok(f.message.includes(evilSha), "message must list the offending commit sha");
    assert.match(f.valueDigest, /^[0-9a-f]{64}$/);
  } finally {
    removeDir(dir);
  }
});

test("clean fixture: allowlisted author+committer and no tags yields no findings", () => {
  const dir = newRepo();
  try {
    commitAs(dir, WIKI);
    commitAs(dir, { name: "someone", email: "ops@company.example" });
    assert.deepEqual(scan(dir, ["main"], CLEAN_CFG), []);
  } finally {
    removeDir(dir);
  }
});

// ---------------------------------------------------------------- AC2: bots

test("AC2: allowBots lets the dependabot noreply-[bot] identity pass while evil still fires", () => {
  const dir = newRepo();
  try {
    commitAs(dir, WIKI);
    const evilSha = commitAs(dir, EVIL);
    commitAs(dir, DEPENDABOT);
    const bots = cfgWith({ emails: ["wiki@sumteclab.com"], names: ["Wiki.js"], allowBots: true });
    const findings = scan(dir, ["main"], bots);
    assert.equal(findings.length, 1);
    assert.ok(findings[0]?.message.includes(evilSha));
    assert.ok(!findings.some((f) => f.message.includes("dependabot")), "dependabot must pass under allowBots");
  } finally {
    removeDir(dir);
  }
});

test("allowBots false (and unset) makes the bot identity fire like any other", () => {
  const dir = newRepo();
  try {
    commitAs(dir, DEPENDABOT);
    const sha = commitAs(dir, { name: "github-actions[bot]", email: "41898282+github-actions[bot]@users.noreply.github.com" });
    const off = cfgWith({ emails: ["wiki@sumteclab.com"], names: ["Wiki.js"], allowBots: false });
    assert.equal(scan(dir, ["main"], off).length, 2, "both bot commits fire when allowBots:false");
    const unset = cfgWith({ emails: ["wiki@sumteclab.com"], names: ["Wiki.js"] });
    const findings = scan(dir, ["main"], unset);
    assert.equal(findings.length, 2);
    assert.ok(findings.some((f) => f.message.includes(sha)));
  } finally {
    removeDir(dir);
  }
});

// ---------------------------------------------------------------- AC3: tags

test("AC3: annotated tag with violating tagger fires CRITICAL naming the refname; lightweight tags are skipped", () => {
  const dir = newRepo();
  try {
    commitAs(dir, WIKI);
    gitRun(dir, ["tag", "v-light"]);
    tagAs(dir, "v1.0.0", EVIL);
    const findings = scan(dir, ["main"], CLEAN_CFG);
    assert.equal(findings.length, 1);
    const f = findings[0];
    assert.ok(f?.message.includes("refs/tags/v1.0.0"), f?.message);
    assert.ok(f?.message.includes("evil@personal.example"));
    assert.ok(f?.message.includes("tagger"), "role label must say tagger");
  } finally {
    removeDir(dir);
  }
});

// ---------------------------------------------------------------- AC4: merges

test("AC4: merge commits check the committer only (bad author passes, bad committer fires)", () => {
  const dir = newRepo();
  try {
    commitAs(dir, WIKI); // c1
    gitRun(dir, ["branch", "feature"]);
    commitAs(dir, WIKI); // c2 on main
    gitRun(dir, ["checkout", "-q", "feature"]);
    commitAs(dir, WIKI); // c3 on feature
    gitRun(dir, ["checkout", "-q", "main"]);
    // merge authored by evil but committed by wiki ⇒ must NOT fire
    mergeAs(dir, "feature", EVIL, WIKI);
    assert.deepEqual(scan(dir, ["main"], CLEAN_CFG), [], "evil merge AUTHOR must be exempt (committer-only check)");

    // second merge: wiki author, evil committer ⇒ must fire as committer
    gitRun(dir, ["checkout", "-q", "-b", "feature2"]);
    commitAs(dir, WIKI);
    gitRun(dir, ["checkout", "-q", "main"]);
    const mergeSha = mergeAs(dir, "feature2", WIKI, EVIL);
    const findings = scan(dir, ["main"], CLEAN_CFG);
    assert.equal(findings.length, 1);
    assert.ok(findings[0]?.message.includes(mergeSha));
    assert.ok(findings[0]?.message.includes("committer of"), findings[0]?.message);
    assert.ok(!findings[0]?.message.includes("author of"), "evil must appear as committer of the merge only");
  } finally {
    removeDir(dir);
  }
});

// ---------------------------------------------------------------- aggregation & scoping

test("one identity across many commits ⇒ ONE finding listing every sha; >50 truncates with (+N more)", () => {
  const dir = newRepo();
  try {
    commitAs(dir, WIKI);
    const shas: string[] = [];
    for (let i = 0; i < 51; i += 1) shas.push(commitAs(dir, EVIL));
    const findings = scan(dir, ["main"], CLEAN_CFG);
    assert.equal(findings.length, 1, "one distinct identity ⇒ one finding");
    const msg = findings[0]?.message ?? "";
    assert.ok(msg.includes(shas[50] as string), "newest commits are listed first (git log order)");
    assert.ok(!msg.includes(shas[0] as string), "the 51st (oldest) sha must be dropped behind the marker");
    assert.ok(msg.includes("(+1 more)"), msg.slice(-120));
    const listed = shas.filter((s) => msg.includes(s)).length;
    assert.equal(listed, 50, "exactly 50 shas listed before the truncation marker");
  } finally {
    removeDir(dir);
  }
});

test("distinct identities get separate findings", () => {
  const dir = newRepo();
  try {
    commitAs(dir, EVIL);
    commitAs(dir, { name: "Joe Evil", email: "other@personal.example" });
    commitAs(dir, { name: "Mallory", email: "evil@personal.example" });
    assert.equal(scan(dir, ["main"], CLEAN_CFG).length, 3);
  } finally {
    removeDir(dir);
  }
});

test("scan is scoped to refSet: evil commit on an unlisted branch is invisible", () => {
  const dir = newRepo();
  try {
    commitAs(dir, WIKI);
    gitRun(dir, ["checkout", "-q", "-b", "feature"]);
    const evilSha = commitAs(dir, EVIL);
    gitRun(dir, ["checkout", "-q", "main"]);
    assert.deepEqual(scan(dir, ["main"], CLEAN_CFG), []);
    assert.equal(scan(dir, ["main", "feature"], CLEAN_CFG).length, 1);
    const findings = scan(dir, ["main..feature"], CLEAN_CFG);
    assert.equal(findings.length, 1);
    assert.ok(findings[0]?.message.includes(evilSha));
  } finally {
    removeDir(dir);
  }
});

test("empty refSet scans no commits (tag leg still runs)", () => {
  const dir = newRepo();
  try {
    commitAs(dir, EVIL);
    assert.deepEqual(scan(dir, [], CLEAN_CFG), []);
    assert.equal(scanIdentity({ repoDir: dir, refSet: [], cfg: CLEAN_CFG }).length, 0);
  } finally {
    removeDir(dir);
  }
});

// ---------------------------------------------------------------- matching semantics

test("email patterns match case-insensitively; names are case-sensitive by design", () => {
  const dir = newRepo();
  try {
    commitAs(dir, { name: "Wiki.js", email: "Wiki@Sumteclab.com" });
    const lc = cfgWith({ emails: ["WIKI@SUMTECLAB.COM"], names: ["Wiki.js"] });
    assert.deepEqual(scan(dir, ["main"], lc), [], "mixed-case commit email must match lowercase-normalized pattern");

    commitAs(dir, { name: "wiki.js", email: "wiki@sumteclab.com" }); // wrong-case NAME
    const findings = scan(dir, ["main"], lc);
    assert.equal(findings.length, 1, "names are compared case-sensitively");
    assert.ok(findings[0]?.message.includes("wiki.js"), findings[0]?.message);
  } finally {
    removeDir(dir);
  }
});

test("name must match too: allowlisted email with unlisted name fires", () => {
  const dir = newRepo();
  try {
    commitAs(dir, { name: "Random Alias", email: "wiki@sumteclab.com" });
    const strict = cfgWith({ emails: ["wiki@sumteclab.com"], names: ["Wiki.js"] });
    const findings = scan(dir, ["main"], strict);
    assert.equal(findings.length, 1);
    assert.ok(findings[0]?.message.includes("Random Alias"));
  } finally {
    removeDir(dir);
  }
});

test("empty author/committer email fails closed (no glob pattern was intended to allow '' except '*')", () => {
  const dir = newRepo();
  try {
    writeRel(dir, "e.txt", "e\n");
    gitRun(dir, ["add", "-A"]);
    gitRun(dir, ["commit", "-q", "--no-gpg-sign", "-m", "no-email"], {
      GIT_AUTHOR_NAME: "Ghost",
      GIT_AUTHOR_EMAIL: "",
      GIT_COMMITTER_NAME: "Ghost",
      GIT_COMMITTER_EMAIL: "",
    });
    const findings = scan(dir, ["main"], cfgWith({ emails: ["*@example.org"], names: ["Ghost"] }));
    assert.equal(findings.length, 1);
    assert.ok(findings[0]?.message.includes("Ghost"));
  } finally {
    removeDir(dir);
  }
});

// ---------------------------------------------------------------- plumbing contract

test("message carries the remediation doc string and border never suggests a rewrite", () => {
  const dir = newRepo();
  try {
    commitAs(dir, EVIL);
    const msg = scan(dir, ["main"], CLEAN_CFG)[0]?.message ?? "";
    assert.ok(msg.includes("git filter-repo"), msg);
    assert.ok(msg.includes("out of scope"), msg);
  } finally {
    removeDir(dir);
  }
});

test("sanitizer option is honored without crashing and findings are valid", () => {
  const dir = newRepo();
  try {
    commitAs(dir, EVIL);
    const sanitizer = new TextSanitizer();
    const findings = scanIdentity({ repoDir: dir, refSet: ["main"], cfg: CLEAN_CFG, sanitizer });
    assert.equal(findings.length, 1);
    for (const f of findings) validateFinding(f);
    assert.ok(findings[0]?.message.includes("evil@personal.example"), "identity must stay visible in its own finding");
  } finally {
    removeDir(dir);
  }
});

test("bad refSet entry fails closed (git error propagates, no silent empty scan)", () => {
  const dir = newRepo();
  try {
    commitAs(dir, WIKI);
    assert.throws(() => scan(dir, ["no-such-ref-xyz"], CLEAN_CFG), /no-such-ref-xyz|exited/);
  } finally {
    removeDir(dir);
  }
});

// ---------------------------------------------------------------- transmitted-object leg (first push)
//
// The first-push gap: a `border push` transmits every OBJECT of a ref the
// remote has never had (no remote-tracking ref, or a restored deleted tag),
// so identities carried only by those objects must still be allow-listed.
// The scan unions the history leg (git log over the ref set) with a
// per-remote `git rev-list <remote>/<ref>..<ref>` leg; refs whose remote
// endpoint is unresolvable skip the leg silently (whole ref transmitted ⇒
// history leg already covers it). These tests pin the operator-visible
// contract plus the zero-false-positive regressions.

const EVE_FP = { name: "evil Eve", email: "eve@evil.test" };

function cfgWithRemote(opts: {
  emails: readonly string[];
  names: readonly string[];
  remotes: readonly { name?: string; url: string }[];
}): BorderConfig {
  const remoteLines = opts.remotes
    .map((r) => `    - { ${r.name === undefined ? "" : `name: ${JSON.stringify(r.name)}, `}url: ${JSON.stringify(r.url)} }`)
    .join("\n");
  return parseConfig(`version: 1
targets:
  git:
    remotes:
${remoteLines}
rules:
  authors:
    emails: [${opts.emails.map((e) => JSON.stringify(e)).join(", ")}]
    names: [${opts.names.map((n) => JSON.stringify(n)).join(", ")}]
  hosts: []
  ips: []
  pathPatterns: []
`);
}

/** Bare remote `a.git` seeded with one Wiki.js commit `main`. */
function wikiSeededRemote(): { top: string; a: string } {
  const top = makeFixtureDir("identity-fp");
  const a = join(top, "a.git");
  gitRun(top, ["init", "-q", "--bare", "-b", "main", a]);
  const seed = join(top, "seed");
  gitRun(top, ["init", "-q", "-b", "main", seed]);
  writeRel(seed, "x.txt", "x\n");
  gitRun(seed, ["add", "-A"]);
  gitRun(seed, ["commit", "-q", "--no-gpg-sign", "-m", "x"], identEnv(WIKI));
  gitRun(seed, ["push", "-q", a, "main"]);
  return { top, a };
}

function cloneOf(top: string, a: string): string {
  gitRun(top, ["clone", "-q", a, "b"]);
  return join(top, "b");
}

test("first push: evil commit on a ref the remote never had is reported (eve@evil.test scenario)", () => {
  const { top, a } = wikiSeededRemote();
  try {
    const b = cloneOf(top, a);
    const evilSha = commitAs(b, EVE_FP);
    const cfg = cfgWithRemote({ emails: ["wiki@sumteclab.com"], names: ["Wiki.js"], remotes: [{ name: "origin", url: `file://${a}` }] });
    const findings = scanIdentity({ repoDir: b, refSet: ["refs/heads/main"], cfg });
    assert.equal(findings.length, 1, `expected exactly 1 finding, got ${JSON.stringify(findings.map((f) => f.message))}`);
    const msg = findings[0]?.message ?? "";
    assert.ok(msg.includes("eve@evil.test"), msg);
    assert.ok(msg.includes("evil Eve"), msg);
    assert.ok(msg.includes(evilSha), "message must name the transmitted commit sha");
  } finally {
    removeDir(top);
  }
});

test("regression: allow-listed first-push adds ZERO new findings", () => {
  const { top, a } = wikiSeededRemote();
  try {
    const b = cloneOf(top, a);
    commitAs(b, WIKI);
    const cfg = cfgWithRemote({ emails: ["wiki@sumteclab.com"], names: ["Wiki.js"], remotes: [{ name: "origin", url: `file://${a}` }] });
    assert.deepEqual(scanIdentity({ repoDir: b, refSet: ["refs/heads/main"], cfg }), []);
  } finally {
    removeDir(top);
  }
});

test("regression: remote already fully has the ref adds no duplicate findings (sha listed exactly once)", () => {
  const { top, a } = wikiSeededRemote();
  try {
    const b = cloneOf(top, a);
    const evilSha = commitAs(b, EVE_FP);
    gitRun(b, ["push", "-q", "origin", "main"]);
    gitRun(b, ["fetch", "-q", "origin"]); // origin/main == main ⇒ rev-list leg is empty
    const cfg = cfgWithRemote({ emails: ["wiki@sumteclab.com"], names: ["Wiki.js"], remotes: [{ name: "origin", url: `file://${a}` }] });
    const findings = scanIdentity({ repoDir: b, refSet: ["refs/heads/main"], cfg });
    assert.equal(findings.length, 1);
    const msg = findings[0]?.message ?? "";
    assert.equal(msg.split(evilSha).length - 1, 1, `sha must appear exactly once, got: ${msg}`);
  } finally {
    removeDir(top);
  }
});

test("unresolvable remote endpoint (named remote never fetched) skips the rev-list leg silently — full history still scanned", () => {
  const { top, a } = wikiSeededRemote();
  try {
    const b = cloneOf(top, a); // tracking refs exist only under `origin`, never under `a`
    const evilSha = commitAs(b, EVE_FP);
    const cfg = cfgWithRemote({ emails: ["wiki@sumteclab.com"], names: ["Wiki.js"], remotes: [{ name: "a", url: `file://${a}` }] });
    const findings = scanIdentity({ repoDir: b, refSet: ["refs/heads/main"], cfg });
    assert.equal(findings.length, 1);
    assert.ok(findings[0]?.message.includes(evilSha));
  } finally {
    removeDir(top);
  }
});

test("range-style refSet entries skip the rev-list leg without throwing", () => {
  const dir = newRepo();
  try {
    commitAs(dir, WIKI);
    gitRun(dir, ["checkout", "-q", "-b", "feature"]);
    const evilSha = commitAs(dir, EVE_FP);
    const cfg = cfgWithRemote({ emails: ["wiki@sumteclab.com"], names: ["Wiki.js"], remotes: [{ name: "origin", url: "file:///does-not-exist.git" }] });
    const findings = scan(dir, ["main..feature"], cfg);
    assert.equal(findings.length, 1);
    assert.ok(findings[0]?.message.includes(evilSha));
  } finally {
    removeDir(dir);
  }
});

test("bad refSet entry still fails closed when remotes are configured", () => {
  const dir = newRepo();
  try {
    commitAs(dir, WIKI);
    const cfg = cfgWithRemote({ emails: ["wiki@sumteclab.com"], names: ["Wiki.js"], remotes: [{ name: "origin", url: "file:///does-not-exist.git" }] });
    assert.throws(() => scan(dir, ["no-such-ref-xyz"], cfg), /no-such-ref-xyz|exited/);
  } finally {
    removeDir(dir);
  }
});
