// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 2
//
// TDD suite for the border.yaml schema + loader + target inference.
// Gate: node --import ./tools/register-ts.mjs --test test/config.test.ts
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, realpathSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";

import {
  ConfigError,
  FALLBACK_WARNING,
  NO_OP_MESSAGE,
  exposureSet,
  loadConfig,
  parseConfig,
  type BorderConfig,
} from "../src/config.ts";

// ---------------------------------------------------------------- fixtures

const GIT_ENV: NodeJS.ProcessEnv = {
  ...process.env,
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_CONFIG_SYSTEM: "/dev/null",
  GIT_AUTHOR_NAME: "fixture",
  GIT_AUTHOR_EMAIL: "fixture@example.invalid",
  GIT_COMMITTER_NAME: "fixture",
  GIT_COMMITTER_EMAIL: "fixture@example.invalid",
  GIT_AUTHOR_DATE: "2020-01-01T00:00:00Z",
  GIT_COMMITTER_DATE: "2020-01-01T00:00:00Z",
};

/** Run git inside a fixture dir, asserting the toplevel IS the fixture
 *  before any operation (never escape into the outer repo). */
function git(cwd: string, args: readonly string[]): string {
  if (existsSync(join(cwd, ".git"))) {
    const top = execFileSync("git", ["rev-parse", "--show-toplevel"], {
      cwd,
      encoding: "utf8",
      env: GIT_ENV,
    }).trim();
    assert.equal(realpathSync(top), realpathSync(cwd), `git toplevel escaped fixture: ${top}`);
  }
  return execFileSync("git", [...args], { cwd, encoding: "utf8", env: GIT_ENV });
}

function makeRepo(t: { after: (fn: () => void) => void }): string {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "border-cfg-")));
  git(dir, ["init", "-b", "main"]);
  t.after(() => {
    rmSync(dir, { recursive: true, force: true });
  });
  return dir;
}

function write(dir: string, rel: string, text: string): void {
  const p = join(dir, rel);
  mkdirSync(dirname(p), { recursive: true });
  writeFileSync(p, text);
}

function commitAll(dir: string, msg: string): void {
  git(dir, ["add", "-A"]);
  git(dir, ["commit", "-m", msg]);
}

const MINIMAL_YAML = `version: 1
targets:
  git:
    remotes:
      - name: origin
        url: git@github.com:acme/widget.git
rules:
  authors:
    emails: ["dev@acme.test"]
    names: ["Acme Dev"]
  hosts: []
  ips: []
  pathPatterns: []
`;

function fullConfig(overrides?: Partial<BorderConfig["targets"]>): BorderConfig {
  return {
    version: 1,
    targets: {
      git: { remotes: [] },
      ...overrides,
    },
    rules: {
      authors: { emails: ["a@b.test"], names: [] },
      hosts: [],
      ips: [],
      pathPatterns: [],
      maxFileKB: 500,
    },
    allow: [],
    engines: { require: ["gitleaks", "secretlint"], trufflehog: false },
  };
}

// ---------------------------------------------------------------- schema

test("valid minimal config applies defaults: maxFileKB=500, engines require/trufflehog", () => {
  const cfg = parseConfig(MINIMAL_YAML, "border.yaml");
  assert.equal(cfg.version, 1);
  assert.equal(cfg.rules.maxFileKB, 500);
  assert.deepEqual(cfg.allow, []);
  assert.deepEqual(cfg.engines.require, ["gitleaks", "secretlint"]);
  assert.equal(cfg.engines.trufflehog, false);
  assert.equal(cfg.targets.git.remotes[0]?.url, "git@github.com:acme/widget.git");
});

test("explicit maxFileKB overrides the 500 default", () => {
  const cfg = parseConfig(MINIMAL_YAML.replace("pathPatterns: []", "pathPatterns: []\n  maxFileKB: 100"), "border.yaml");
  assert.equal(cfg.rules.maxFileKB, 100);
});

test("strict schema rejects unknown top-level key and names it", () => {
  assert.throws(
    () => parseConfig(`bogusTop: hi\n${MINIMAL_YAML}`, "border.yaml"),
    (err: unknown) => {
      assert.ok(err instanceof ConfigError, `expected ConfigError, got ${String(err)}`);
      assert.match(err.message, /bogusTop/);
      assert.equal(err.exitCode, 2);
      return true;
    },
  );
});

test("strict schema rejects unknown nested key and names it", () => {
  assert.throws(
    () => parseConfig(MINIMAL_YAML.replace("ips: []", "ips: []\n  sneaky: 1"), "border.yaml"),
    (err: unknown) => {
      assert.ok(err instanceof ConfigError);
      assert.match(err.message, /sneaky/);
      return true;
    },
  );
});

test("missing rules.authors.emails when targets present errors naming the field", () => {
  const yaml = MINIMAL_YAML.replace('    emails: ["dev@acme.test"]\n', "");
  assert.throws(
    () => parseConfig(yaml, "border.yaml"),
    (err: unknown) => {
      assert.ok(err instanceof ConfigError);
      assert.match(err.message, /rules\.authors\.emails/);
      return true;
    },
  );
});

test("version must be exactly 1 (2 rejected, no auto-migration)", () => {
  assert.throws(
    () => parseConfig(MINIMAL_YAML.replace("version: 1", "version: 2"), "border.yaml"),
    (err: unknown) => err instanceof ConfigError,
  );
});

test("wrong type for rules.hosts errors instead of coercing", () => {
  assert.throws(
    () => parseConfig(MINIMAL_YAML.replace("hosts: []", "hosts: 42"), "border.yaml"),
    (err: unknown) => {
      assert.ok(err instanceof ConfigError);
      assert.match(err.message, /rules\.hosts/);
      return true;
    },
  );
});

// ---------------------------------------------------------------- remote names

test("duplicate git remote names rejected: names the dup, kind invalid-value, exit 2", () => {
  const yaml = `version: 1
targets:
  git:
    remotes:
      - name: origin
        url: https://a.example/x.git
      - name: origin
        url: git@b.example:acme/y.git
rules:
  authors:
    emails: ["a@b.test"]
    names: []
  hosts: []
  ips: []
  pathPatterns: []
`;
  assert.throws(
    () => parseConfig(yaml, "border.yaml"),
    (err: unknown) => {
      assert.ok(err instanceof ConfigError, `expected ConfigError, got ${String(err)}`);
      assert.equal(err.kind, "invalid-value");
      assert.equal(err.exitCode, 2);
      assert.match(err.message, /duplicate/i);
      assert.match(err.message, /origin/);
      assert.match(err.message, /remotes/);
      return true;
    },
  );
});

test("multiple unnamed remotes stay valid (index-keyed git:#N ids, no dup to compare)", () => {
  const yaml = `version: 1
targets:
  git:
    remotes:
      - url: https://a.example/x.git
      - url: https://b.example/y.git
rules:
  authors:
    emails: ["a@b.test"]
    names: []
  hosts: []
  ips: []
  pathPatterns: []
`;
  const cfg = parseConfig(yaml, "border.yaml");
  assert.equal(cfg.targets.git.remotes.length, 2);
});

// ---------------------------------------------------------------- env expansion

test("${VAR} expands in url/registry/repository but nowhere else", () => {
  const yaml = `version: 1
targets:
  git:
    remotes:
      - url: "\${BORDER_TEST_REG}/repo.git"
  npm:
    name: "\${BORDER_TEST_REG}"
    registry: "\${BORDER_TEST_REG}/npm"
  pypi:
    repository: "\${BORDER_TEST_REG}/pypi"
rules:
  authors:
    emails: ["\${BORDER_TEST_REG}"]
    names: []
  hosts: ["\${BORDER_TEST_REG}"]
  ips: []
  pathPatterns: []
`;
  const cfg = parseConfig(yaml, "border.yaml", {
    env: { BORDER_TEST_REG: "https://corp.example" },
  });
  assert.equal(cfg.targets.git.remotes[0]?.url, "https://corp.example/repo.git");
  assert.equal(cfg.targets.npm?.registry, "https://corp.example/npm");
  assert.equal(cfg.targets.pypi?.repository, "https://corp.example/pypi");
  // non-URL fields stay literal — no .env expansion elsewhere
  assert.equal(cfg.targets.npm?.name, "${BORDER_TEST_REG}");
  assert.deepEqual(cfg.rules.hosts, ["${BORDER_TEST_REG}"]);
  assert.deepEqual(cfg.rules.authors.emails, ["${BORDER_TEST_REG}"]);
});

test("missing env var referenced by a url fails loudly naming the var", () => {
  const yaml = MINIMAL_YAML.replace(
    "url: git@github.com:acme/widget.git",
    "url: ${BORDER_TEST_UNSET_VAR}/x.git",
  );
  assert.throws(
    () => parseConfig(yaml, "border.yaml", { env: {} }),
    (err: unknown) => {
      assert.ok(err instanceof ConfigError);
      assert.match(err.message, /BORDER_TEST_UNSET_VAR/);
      return true;
    },
  );
});

test("prompt-injection safety: $, {, $( ) literals pass through untouched (no eval)", () => {
  const weird = "https://x.example/a$b/{c}/$/${ j : $(id) }";
  const yaml = MINIMAL_YAML.replace("url: git@github.com:acme/widget.git", `url: "${weird}"`);
  const cfg = parseConfig(yaml, "border.yaml", { env: { j: "SHOULD-NOT-APPEAR" } });
  assert.equal(cfg.targets.git.remotes[0]?.url, weird);
});

// ---------------------------------------------------------------- malformed input

test("malformed YAML (unclosed flow) yields ConfigError carrying line info", () => {
  assert.throws(
    () => parseConfig("version: 1\nrules:\n  hosts: [\n", "border.yaml"),
    (err: unknown) => {
      assert.ok(err instanceof ConfigError, `expected ConfigError, got ${String(err)}`);
      assert.equal(err.kind, "malformed-yaml");
      assert.equal(typeof err.line, "number");
      assert.ok((err.line ?? 0) >= 3, `expected line >= 3, got ${String(err.line)}`);
      assert.match(err.message, /line \d+/);
      assert.match(err.message, /border\.yaml/);
      return true;
    },
  );
});

test("tab-indented YAML yields a named-line ConfigError, not a stack trace", () => {
  assert.throws(
    () => parseConfig("version: 1\n\trules: x", "border.yaml"),
    (err: unknown) => {
      assert.ok(err instanceof ConfigError);
      assert.equal(err.kind, "malformed-yaml");
      assert.equal(err.line, 2);
      return true;
    },
  );
});

test("YAML anchors/aliases are resolved by the parser, never evaluated", () => {
  const yaml = `version: 1
targets:
  git:
    remotes:
      - url: &link https://a.example/x.git
      - name: mirror
        url: *link
rules:
  authors:
    emails: ["e@f.test"]
    names: []
  hosts: []
  ips: []
  pathPatterns: []
`;
  const cfg = parseConfig(yaml, "border.yaml", { env: {} });
  assert.equal(cfg.targets.git.remotes[0]?.url, "https://a.example/x.git");
  assert.equal(cfg.targets.git.remotes[1]?.url, "https://a.example/x.git");
  assert.equal(cfg.targets.git.remotes[1]?.name, "mirror");
});

test("YAML merge keys (<<) are not a schema escape hatch: rejected by name", () => {
  const yaml = `version: 1
<<: {engines: {trufflehog: 999}}
targets:
  git:
    remotes: []
rules:
  authors:
    emails: ["e@f.test"]
    names: []
  hosts: []
  ips: []
  pathPatterns: []
`;
  assert.throws(
    () => parseConfig(yaml, "border.yaml", { env: {} }),
    (err: unknown) => {
      assert.ok(err instanceof ConfigError, `expected ConfigError, got ${String(err)}`);
      assert.match(err.message, /<</);
      return true;
    },
  );
});

test("empty YAML document is a named invalid-config error, not a crash", () => {
  assert.throws(
    () => parseConfig("", "border.yaml"),
    (err: unknown) => err instanceof ConfigError && err.kind !== "malformed-yaml",
  );
});

// ---------------------------------------------------------------- discovery

test("discovery order: --config > ./border.yaml > git-toplevel border.yaml", (t) => {
  const dir = makeRepo(t);
  write(dir, "border.yaml", MINIMAL_YAML);
  git(dir, ["add", "border.yaml"]);
  git(dir, ["commit", "-m", "cfg"]);
  write(dir, "sub/border.yaml", MINIMAL_YAML.replace("widget.git", "from-cwd.git"));
  write(dir, "explicit.yaml", MINIMAL_YAML.replace("widget.git", "from-flag.git"));

  // 1. --config wins over everything
  const byFlag = loadConfig({ configPath: join(dir, "explicit.yaml"), cwd: join(dir, "sub"), env: {} });
  assert.ok(byFlag.kind === "loaded", `expected loaded, got ${byFlag.kind}`);
  assert.match(byFlag.config.targets.git.remotes[0]?.url ?? "", /from-flag/);
  assert.deepEqual([...byFlag.warnings], []);

  // 2. ./border.yaml (cwd) wins over toplevel
  const byCwd = loadConfig({ cwd: join(dir, "sub"), env: {} });
  assert.ok(byCwd.kind === "loaded");
  assert.match(byCwd.config.targets.git.remotes[0]?.url ?? "", /from-cwd/);

  // 3. falls back to git toplevel when cwd has none
  rmSync(join(dir, "sub/border.yaml"));
  const byTop = loadConfig({ cwd: join(dir, "sub"), env: {} });
  assert.ok(byTop.kind === "loaded");
  assert.match(byTop.config.targets.git.remotes[0]?.url ?? "", /widget/);
  assert.deepEqual([...byTop.warnings], []);
});

test("--config pointing at a missing file is a ConfigError, not an auto-fallback", () => {
  assert.throws(
    () => loadConfig({ configPath: "/nonexistent/border.yaml", cwd: tmpdir(), env: {} }),
    (err: unknown) => {
      assert.ok(err instanceof ConfigError);
      assert.match(err.message, /nonexistent\/border\.yaml/);
      return true;
    },
  );
});

// ---------------------------------------------------------------- overlay

test("private overlay .border/config.local.yaml deep-merges over the base config", (t) => {
  const dir = makeRepo(t);
  write(dir, "border.yaml", MINIMAL_YAML);
  write(
    dir,
    ".border/config.local.yaml",
    `rules:
  authors:
    emails: ["private@corp.internal"]
  hosts: ["git.corp.internal"]
targets:
  npm:
    registry: "https://npm.corp.internal"
`,
  );
  const res = loadConfig({ cwd: dir, env: {} });
  assert.ok(res.kind === "loaded");
  const cfg = res.config;
  // overlay wins for arrays it defines
  assert.deepEqual(cfg.rules.authors.emails, ["private@corp.internal"]);
  assert.deepEqual(cfg.rules.hosts, ["git.corp.internal"]);
  // base survives keys the overlay does not touch (deep, not shallow)
  assert.deepEqual(cfg.rules.authors.names, ["Acme Dev"]);
  assert.equal(cfg.rules.maxFileKB, 500);
  assert.equal(cfg.targets.git.remotes[0]?.url, "git@github.com:acme/widget.git");
  assert.equal(cfg.targets.npm?.registry, "https://npm.corp.internal");
});

test("overlay unknown key is rejected naming the key", (t) => {
  const dir = makeRepo(t);
  write(dir, "border.yaml", MINIMAL_YAML);
  write(dir, ".border/config.local.yaml", "bogusOverlay: 1\n");
  assert.throws(
    () => loadConfig({ cwd: dir, env: {} }),
    (err: unknown) => {
      assert.ok(err instanceof ConfigError);
      assert.match(err.message, /bogusOverlay/);
      return true;
    },
  );
});

// ---------------------------------------------------------------- inference / no-op

test("2-remote repo with NO border.yaml ⇒ inferred git targets + fallback warning", (t) => {
  const dir = makeRepo(t);
  write(dir, "f.txt", "x");
  commitAll(dir, "seed");
  git(dir, ["remote", "add", "origin", "https://user:tok@h/r.git"]);
  git(dir, ["remote", "add", "backup", "git@example.com:acme/x.git"]);

  const res = loadConfig({ cwd: dir, env: {} });
  assert.ok(res.kind === "loaded", `expected loaded, got ${res.kind}`);
  assert.ok(
    res.warnings.includes(FALLBACK_WARNING),
    `expected fallback warning among ${JSON.stringify(res.warnings)}`,
  );
  assert.deepEqual(
    res.config.targets.git.remotes.map((r) => [r.name, r.url]),
    [
      ["backup", "git@example.com:acme/x.git"],
      ["origin", "https://user:tok@h/r.git"],
    ],
  );
  assert.equal(res.config.version, 1);
  assert.equal(res.config.rules.maxFileKB, 500);
});

test("repo with no remotes and no border.yaml ⇒ NO-OP verdict", (t) => {
  const dir = makeRepo(t);
  write(dir, "f.txt", "x");
  commitAll(dir, "seed");
  const res = loadConfig({ cwd: dir, env: {} });
  assert.ok(res.kind === "no-op");
  assert.equal(NO_OP_MESSAGE, "no targets discovered; check is a no-op");
});

test("config that declares zero targets ⇒ NO-OP too (empty remotes, no npm/pypi)", (t) => {
  const dir = makeRepo(t);
  write(
    dir,
    "border.yaml",
    `version: 1
targets:
  git:
    remotes: []
rules:
  authors:
    emails: ["a@b.test"]
    names: []
  hosts: []
  ips: []
  pathPatterns: []
`,
  );
  const res = loadConfig({ cwd: dir, env: {} });
  assert.ok(res.kind === "no-op", `expected no-op, got ${res.kind}`);
});

test("loader is deterministic across repeated runs (stale_state probe)", (t) => {
  const dir = makeRepo(t);
  write(dir, "border.yaml", MINIMAL_YAML);
  git(dir, ["add", "-A"]);
  git(dir, ["commit", "-m", "cfg"]);
  const a = loadConfig({ cwd: dir, env: {} });
  const b = loadConfig({ cwd: dir, env: {} });
  assert.deepEqual(a, b);
});

// ---------------------------------------------------------------- exposureSet

test("exposureSet: sanitized remotes + npm/pypi versions read at HEAD, not worktree", (t) => {
  const dir = makeRepo(t);
  write(dir, "package.json", '{ "name": "pkgname", "version": "1.2.3" }');
  write(dir, "pyproject.toml", '[project]\nname = "widge"\nversion = "0.4.2"\n');
  commitAll(dir, "seeds");
  // mutate the working tree — HEAD must still win
  write(dir, "package.json", '{ "name": "pkgname", "version": "9.9.9" }');
  write(dir, "pyproject.toml", '[project]\nname = "widge"\nversion = "9.9.9"\n');

  const cfg = fullConfig({
    git: { remotes: [{ name: "origin", url: "https://user:tok@h/r.git" }] },
    npm: {},
    pypi: {},
  });
  const set = exposureSet(cfg, { cwd: dir });
  assert.ok(set.includes("https://h/r.git"), `sanitized remote missing from ${JSON.stringify(set)}`);
  assert.ok(!set.some((s) => s.includes("tok@")), "raw credential must never enter the set");
  assert.ok(set.includes("npm:pkgname@1.2.3"), `npm HEAD version missing from ${JSON.stringify(set)}`);
  assert.ok(set.includes("pypi:widge@0.4.2"), `pypi HEAD version missing from ${JSON.stringify(set)}`);
  assert.deepEqual(set, [...set].sort(), "exposureSet must be sorted");
});
