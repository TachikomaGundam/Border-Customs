// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 13
//
// Registry pre-flight suite — ALL traffic is loopback (plan: "no real network in
// the suite"). Covers the plan's full classification table:
//   npm:  exit-0-WITH-JSON ⇒ version PRESENT ⇒ CRITICAL `version-exists`
//         (exact message `bump version required`, NEVER silent-skip);
//         stderr `code E404`/`404 Not Found` ⇒ absent ⇒ proceed;
//         ANYTHING else (ECONNREFUSED/FETCH_ERROR/timeout/empty-stdout) ⇒
//         EngineRunError ⇒ CLI exit 2 (fail-closed, no warn-and-proceed).
//   owner: claimed+foreign ⇒ CRITICAL `name-foreign-owner`; claimed but no
//         comparable owner signal ⇒ FAIL loud (same rule, ambiguous wording);
//         unclaimed ⇒ INFO `name-available`, check still PASS (plan AC).
//   PyPI: 200/404 JSON API polarity, 5xx/timeout/malformed ⇒ exit 2.
import assert from "node:assert/strict";
import { after, test } from "node:test";

import {
  BUMP_VERSION_MESSAGE,
  FOREIGN_OWNER_RULE,
  NAME_AVAILABLE_RULE,
  VERSION_EXISTS_RULE,
  classifyNpmVersionView,
  normalizeGitLocation,
  runRegistryProbes,
} from "../src/registry.ts";
import { EngineRunError } from "../src/engines/support.ts";
import type { BorderConfig } from "../src/config.ts";
import type { Report } from "../src/findings.ts";
import { run } from "../src/cli.ts";
import { EXIT_BLOCKED, EXIT_ERROR, EXIT_PASS } from "../src/cli/exit.ts";
import { executeCheck } from "../src/check.ts";
import { requireGitleaks } from "./helpers/require-engines.ts";
import { gitAddCommit, gitInit, makeFixtureDir, removeDir, writeRel } from "./helpers/fixtures.ts";
import { PACKUMENT_WIDGETS_100, closedEphemeralPort, startHangingStub, startRegistryStub, type RegistryStub } from "./helpers/registry-stub.ts";

const openStubs: RegistryStub[] = [];
const fixtureRoots: string[] = [];

async function stub(routes: Parameters<typeof startRegistryStub>[0]): Promise<RegistryStub> {
  const s = await startRegistryStub(routes);
  openStubs.push(s);
  return s;
}

function trackedRepo(name: string, files: Record<string, string>): string {
  const dir = makeFixtureDir(`reg-${name}`);
  fixtureRoots.push(dir);
  gitInit(dir);
  for (const [rel, content] of Object.entries(files)) writeRel(dir, rel, content);
  gitAddCommit(dir, "init");
  return dir;
}

after(async () => {
  for (const s of openStubs) await s.close();
  for (const d of fixtureRoots) removeDir(d);
});

function cfgFor(o: {
  readonly npmRegistry?: string;
  readonly pypiRepository?: string;
  readonly emails?: readonly string[];
  readonly remotes?: readonly string[];
}): BorderConfig {
  return {
    version: 1,
    targets: {
      git: { remotes: (o.remotes ?? ["origin.example:widgets.git"]).map((url) => ({ url })) },
      ...(o.npmRegistry === undefined ? {} : { npm: { registry: o.npmRegistry } }),
      ...(o.pypiRepository === undefined ? {} : { pypi: { repository: o.pypiRepository } }),
    },
    rules: {
      authors: { emails: [...(o.emails ?? [])], names: [] },
      hosts: [],
      ips: [],
      pathPatterns: [],
      maxFileKB: 500,
    },
    allow: [],
    engines: { require: [], trufflehog: false },
  };
}

const PKG_JSON = JSON.stringify({ name: "widgets", version: "1.0.0", files: ["dist/"] }) + "\n";
const PYPROJECT = '[project]\nname = "widgets"\nversion = "1.0.0"\n';
const GIT_TARGETS = ["git"] as const;

// ---------------------------------------------------------------- classifier (pure, plan polarity table)

test("classifyNpmVersionView: exit 0 WITH JSON body ⇒ present (round-3 B1/mB1 polarity)", () => {
  assert.equal(classifyNpmVersionView({ status: 0, stdout: '{"name":"widgets"}', stderr: "" }), "present");
});

test("classifyNpmVersionView: non-zero + stderr code E404 / 404 Not Found ⇒ absent", () => {
  assert.equal(classifyNpmVersionView({ status: 1, stdout: "", stderr: "npm error code E404" }), "absent");
  assert.equal(classifyNpmVersionView({ status: 1, stdout: "", stderr: "npm error 404 Not Found - GET https://x" }), "absent");
});

test("classifyNpmVersionView: exit 0 + EMPTY stdout throws — silence is never 'absent'", () => {
  assert.throws(
    () => classifyNpmVersionView({ status: 0, stdout: "  \n", stderr: "npm warn whatever" }),
    (err: unknown) => err instanceof EngineRunError && /empty stdout/.test(err.message),
  );
});

test("classifyNpmVersionView: exit 0 + malformed or null JSON throws (typed parse error)", () => {
  assert.throws(() => classifyNpmVersionView({ status: 0, stdout: '{"name": "broke', stderr: "" }), EngineRunError);
  assert.throws(() => classifyNpmVersionView({ status: 0, stdout: "null", stderr: "" }), EngineRunError);
  assert.throws(() => classifyNpmVersionView({ status: 0, stdout: '"a string"', stderr: "" }), EngineRunError);
});

test("classifyNpmVersionView: non-404 failure codes throw (ECONNREFUSED / FETCH_ERROR / timeout-null)", () => {
  assert.throws(() => classifyNpmVersionView({ status: 1, stdout: "", stderr: "npm error code ECONNREFUSED" }), EngineRunError);
  assert.throws(() => classifyNpmVersionView({ status: 1, stdout: "", stderr: "npm error code FETCH_ERROR invalid json response body" }), EngineRunError);
  assert.throws(() => classifyNpmVersionView({ status: 1, stdout: "", stderr: "npm error code EAI_AGAIN" }), EngineRunError);
  assert.throws(() => classifyNpmVersionView({ status: -1, stdout: "", stderr: "" }), EngineRunError);
});

// ---------------------------------------------------------------- npm probes (real npm CLI vs loopback stub)

test("npm version PRESENT on stub ⇒ CRITICAL version-exists, exact message, never silent-ok", async () => {
  const s = await stub([{ path: "/widgets", body: PACKUMENT_WIDGETS_100 }]);
  const dir = trackedRepo("present", { "package.json": PKG_JSON });
  const findings = await runRegistryProbes({
    repoDir: dir,
    cfg: cfgFor({ npmRegistry: s.url, emails: ["alice@self.example"] }),
    effectiveTargets: [...GIT_TARGETS, "npm"],
  });
  const vf = findings.filter((f) => f.rule === VERSION_EXISTS_RULE);
  assert.equal(vf.length, 1);
  assert.equal(vf[0]?.severity, "CRITICAL");
  assert.equal(vf[0]?.message, BUMP_VERSION_MESSAGE);
  assert.equal(vf[0]?.message, "bump version required", "plan AC pins the literal string");
  assert.equal(vf[0]?.target, "npm");
  assert.equal(vf[0]?.engine, "registry");
});

test("npm 404 name ⇒ INFO name-available and no version finding", async () => {
  const s = await stub([]); // unknown paths ⇒ 404
  const dir = trackedRepo("unclaimed", { "package.json": PKG_JSON });
  const findings = await runRegistryProbes({
    repoDir: dir,
    cfg: cfgFor({ npmRegistry: s.url }),
    effectiveTargets: [...GIT_TARGETS, "npm"],
  });
  assert.equal(findings.filter((f) => f.rule === VERSION_EXISTS_RULE).length, 0, "404 version must never surface as present");
  const nf = findings.filter((f) => f.rule === NAME_AVAILABLE_RULE);
  assert.equal(nf.length, 1);
  assert.equal(nf[0]?.severity, "INFO");
});

test("npm claimed + self maintainer email ⇒ no npm findings at all", async () => {
  const s = await stub([{ path: "/widgets", body: { ...PACKUMENT_WIDGETS_100, "dist-tags": { latest: "0.9.0" }, versions: { "0.9.0": { name: "widgets", version: "0.9.0" } } } }]); // name present, 1.0.0 absent
  const dir = trackedRepo("selfowner", { "package.json": PKG_JSON });
  const findings = await runRegistryProbes({
    repoDir: dir,
    cfg: cfgFor({ npmRegistry: s.url, emails: ["alice@self.example"] }),
    effectiveTargets: [...GIT_TARGETS, "npm"],
  });
  assert.deepEqual(findings, [], "self-owned name + unpublished version is the clean case");
});

test("npm claimed by FOREIGN owner ⇒ CRITICAL name-foreign-owner", async () => {
  const s = await stub([{ path: "/widgets", body: { ...PACKUMENT_WIDGETS_100, "dist-tags": { latest: "0.9.0" }, versions: { "0.9.0": { name: "widgets", version: "0.9.0" } }, maintainers: [{ name: "bob", email: "bob@other.example" }], repository: { url: "https://git.other.example/bob/widgets.git" } } }]);
  const dir = trackedRepo("foreign", { "package.json": PKG_JSON });
  const findings = await runRegistryProbes({
    repoDir: dir,
    cfg: cfgFor({ npmRegistry: s.url, emails: ["alice@self.example"] }),
    effectiveTargets: [...GIT_TARGETS, "npm"],
  });
  const ff = findings.filter((f) => f.rule === FOREIGN_OWNER_RULE);
  assert.equal(ff.length, 1);
  assert.equal(ff[0]?.severity, "CRITICAL");
});

test("npm claimed + only repo-URL proves ownership (git+https scheme, foreign email) ⇒ silent", async () => {
  // Regression: normalizeGitLocation must strip `git+https://` (colon before //).
  // A live CLI run caught this: config remote origin.example:widgets.git vs packument
  // git+https://origin.example/widgets.git were normalized to different strings and a
  // self-owned name surfaced as CRITICAL name-foreign-owner.
  const s = await stub([{ path: "/widgets", body: { ...PACKUMENT_WIDGETS_100, "dist-tags": { latest: "0.9.0" }, versions: { "0.9.0": { name: "widgets", version: "0.9.0" } } } }]);
  const dir = trackedRepo("urlmatch", { "package.json": PKG_JSON });
  const findings = await runRegistryProbes({
    repoDir: dir,
    cfg: cfgFor({ npmRegistry: s.url, emails: [] }), // NO email overlap — repo URL is the only self-signal
    effectiveTargets: [...GIT_TARGETS, "npm"],
  });
  assert.deepEqual(findings, [], "repository.url matching a configured git remote ⇒ self-owned, silent");
});

test("normalizeGitLocation: scheme + scp + colon paths collapse to host/path", () => {
  assert.equal(normalizeGitLocation("git+https://origin.example/widgets.git"), "origin.example/widgets");
  assert.equal(normalizeGitLocation("https://origin.example/widgets.git"), "origin.example/widgets");
  assert.equal(normalizeGitLocation("origin.example:widgets.git"), "origin.example/widgets");
  assert.equal(normalizeGitLocation("git@github.com:acme/widgets.git"), "github.com/acme/widgets");
});

test("npm claimed but ZERO owner signals (empty-stdout field query) ⇒ FAIL loud, never absent", async () => {
  const s = await stub([{ path: "/widgets", body: { name: "widgets", "dist-tags": { latest: "1.0.0" }, versions: { "1.0.0": { name: "widgets", version: "1.0.0" } } } }]);
  const dir = trackedRepo("bare", { "package.json": PKG_JSON });
  const findings = await runRegistryProbes({
    repoDir: dir,
    cfg: cfgFor({ npmRegistry: s.url, emails: ["alice@self.example"] }),
    effectiveTargets: [...GIT_TARGETS, "npm"],
  });
  const ff = findings.filter((f) => f.rule === FOREIGN_OWNER_RULE);
  assert.equal(ff.length, 1, "ambiguous ownership must fail loud");
  assert.equal(ff[0]?.severity, "CRITICAL");
  assert.match(ff[0]?.message ?? "", /ambiguous/i);
  assert.equal(findings.filter((f) => f.rule === NAME_AVAILABLE_RULE).length, 0, "claimed name is never 'available'");
});

test("npm registry REFUSED port ⇒ EngineRunError (plan AC: unreachable ⇒ exit 2)", async () => {
  await stub([]);
  const refused = `http://127.0.0.1:${String(await closedEphemeralPort())}`;
  const dir = trackedRepo("refused", { "package.json": PKG_JSON });
  await assert.rejects(
    runRegistryProbes({ repoDir: dir, cfg: cfgFor({ npmRegistry: refused }), effectiveTargets: [...GIT_TARGETS, "npm"] }),
    EngineRunError,
  );
});

test("npm malformed-JSON body ⇒ EngineRunError, NOT absent-present confusion (QA failure case)", async () => {
  const s = await stub([{ path: "/widgets", raw: '{"name": "broke' }]);
  const dir = trackedRepo("malformed", { "package.json": PKG_JSON });
  await assert.rejects(
    runRegistryProbes({ repoDir: dir, cfg: cfgFor({ npmRegistry: s.url }), effectiveTargets: [...GIT_TARGETS, "npm"] }),
    EngineRunError,
  );
});

test("npm HUNG registry (accepts, never answers) ⇒ EngineRunError via per-attempt timeout", async () => {
  const hang = await startHangingStub();
  openStubs.push(hang);
  const dir = trackedRepo("hung", { "package.json": PKG_JSON });
  const t0 = performance.now();
  await assert.rejects(
    runRegistryProbes({ repoDir: dir, cfg: cfgFor({ npmRegistry: hang.url }), effectiveTargets: [...GIT_TARGETS, "npm"], timeoutMs: 1500 }),
    (err: unknown) => err instanceof EngineRunError && /timed out|killed/i.test(err.message),
  );
  assert.ok(performance.now() - t0 < 10_000, "timeout must bound the probe, not npm's own 5min default");
});

// ---------------------------------------------------------------- PyPI probes (fetch vs loopback stub)

const PYPI_TARGETS = [...GIT_TARGETS, "pypi"];

async function pypiProbes(s: RegistryStub, extra: { emails?: readonly string[] } = {}, dir?: string) {
  const repo = dir ?? trackedRepo(`pypi-${String(s.port)}`, { "pyproject.toml": PYPROJECT });
  return runRegistryProbes({ repoDir: repo, cfg: cfgFor({ pypiRepository: s.url, ...extra }), effectiveTargets: PYPI_TARGETS });
}

test("pypi 200 on version json ⇒ CRITICAL version-exists exact message", async () => {
  const s = await stub([{ path: "/pypi/widgets/1.0.0/json", body: { info: { version: "1.0.0" } } }]);
  const findings = await pypiProbes(s);
  const vf = findings.filter((f) => f.rule === VERSION_EXISTS_RULE);
  assert.equal(vf.length, 1);
  assert.equal(vf[0]?.message, "bump version required");
  assert.equal(vf[0]?.target, "pypi");
});

test("pypi 404 version + 404 name ⇒ INFO name-available only", async () => {
  const s = await stub([]);
  const findings = await pypiProbes(s);
  assert.equal(findings.filter((f) => f.rule === VERSION_EXISTS_RULE).length, 0);
  assert.equal(findings.filter((f) => f.rule === NAME_AVAILABLE_RULE).length, 1);
});

test("pypi name owned by foreign author ⇒ CRITICAL name-foreign-owner; self author ⇒ silent", async () => {
  const foreign = await stub([{ path: "/pypi/widgets/json", body: { info: { author: "Mallory <mallory@other.example>", project_urls: { Homepage: "https://other.example/widgets" } } } }]);
  const ff = (await pypiProbes(foreign, { emails: ["alice@self.example"] })).filter((f) => f.rule === FOREIGN_OWNER_RULE);
  assert.equal(ff.length, 1);
  assert.equal(ff[0]?.severity, "CRITICAL");

  const self = await stub([{ path: "/pypi/widgets/json", body: { info: { maintainer: "Alice <alice@self.example>" } } }]);
  const clean = await pypiProbes(self, { emails: ["alice@self.example"] });
  assert.deepEqual(clean.filter((f) => f.rule !== NAME_AVAILABLE_RULE || f.severity === "CRITICAL"), []);
});

test("pypi 5xx ⇒ EngineRunError (fail-closed, never warn-and-proceed)", async () => {
  const s = await stub([{ path: "/pypi/widgets/1.0.0/json", status: 500, body: { error: "boom" } }]);
  await assert.rejects(pypiProbes(s), EngineRunError);
});

test("pypi 200 malformed JSON ⇒ typed EngineRunError, not crash", async () => {
  const s = await stub([{ path: "/pypi/widgets/1.0.0/json", raw: "<html>not json</html>" }]);
  await assert.rejects(
    pypiProbes(s),
    (err: unknown) => err instanceof EngineRunError && /malformed|parse/i.test(err.message),
  );
});

test("pypi HUNG stub ⇒ AbortSignal timeout surfaces as EngineRunError", async () => {
  const hang = await startHangingStub();
  openStubs.push(hang);
  await assert.rejects(
    runRegistryProbes({
      repoDir: trackedRepo("pypi-hang", { "pyproject.toml": PYPROJECT }),
      cfg: cfgFor({ pypiRepository: hang.url }),
      effectiveTargets: PYPI_TARGETS,
      timeoutMs: 1500,
    }),
    (err: unknown) => err instanceof EngineRunError && /timed out/i.test(err.message),
  );
});

test("git-only effectiveTargets ⇒ registry NEVER probed (refused port stays silent)", async () => {
  const dir = trackedRepo("gitonly", { "package.json": PKG_JSON });
  const findings = await runRegistryProbes({
    repoDir: dir,
    cfg: cfgFor({ npmRegistry: "http://127.0.0.1:1" }),
    effectiveTargets: [...GIT_TARGETS],
  });
  assert.deepEqual(findings, []);
});

// ---------------------------------------------------------------- check-pipeline + CLI wiring (plan ACs)

requireGitleaks();

function cliYaml(registry: string): string {
  return [
    "version: 1",
    "targets:",
    "  git:",
    "    remotes:",
    "      - name: origin",
    "        url: origin.example:widgets.git",
    "  npm:",
    `    registry: ${registry}`,
    "rules:",
    "  authors:",
    "    emails:",
    "      - wiki@sumteclab.com",
    "      - alice@self.example",
    "    names:",
    "      - Wiki.js",
    "  hosts: []",
    "  ips: []",
    "  pathPatterns: []",
    "",
  ].join("\n");
}

test("executeCheck: npm target configured ⇒ probes join the report; present version ⇒ verdict FAIL", async () => {
  const s = await stub([{ path: "/widgets", body: PACKUMENT_WIDGETS_100 }]);
  const dir = trackedRepo("pipeline", { "package.json": PKG_JSON, "border.yaml": cliYaml(s.url) });
  const cfg = cfgFor({ npmRegistry: s.url, emails: ["alice@self.example"] });
  const { report } = await executeCheck({
    repoDir: dir,
    cfg,
    configDigest: "0".repeat(64),
    effectiveTargets: [...GIT_TARGETS, "npm"],
  });
  const vf = report.findings.filter((f) => f.rule === VERSION_EXISTS_RULE);
  assert.equal(vf.length, 1, `report must carry the probe finding, got: ${JSON.stringify(report.findings.map((f) => f.rule))}`);
  assert.equal(report.verdict, "FAIL");
});

async function cliCheck(dir: string, extra: readonly string[] = []): Promise<{ code: number; out: string[]; err: string[]; report?: Report }> {
  const out: string[] = [];
  const err: string[] = [];
  const code = (await run(["check", "--force", ...extra], (l) => out.push(l), (l) => err.push(l), { cwd: dir })) as number;
  const report = code === EXIT_PASS || code === EXIT_BLOCKED ? (JSON.parse(out.join("\n")) as Report) : undefined;
  return { code, out, err, ...(report === undefined ? {} : { report }) };
}

test("CLI AC: unclaimed-name stub ⇒ INFO name-available and check still PASS (exit 0)", async () => {
  const s = await stub([]);
  const dir = trackedRepo("cli-pass", { "package.json": PKG_JSON, "border.yaml": cliYaml(s.url) });
  const r = await cliCheck(dir, ["--json"]);
  assert.equal(r.code, EXIT_PASS, `stdout=${r.out.join("|")} stderr=${r.err.join("|")}`);
  const infos = (r.report?.findings ?? []).filter((f) => f.rule === NAME_AVAILABLE_RULE);
  assert.equal(infos.length, 1);
  assert.equal(infos[0]?.severity, "INFO");
  assert.equal(r.report?.verdict, "PASS");
});

test("CLI AC: present version on stub ⇒ CRITICAL bump + exit 1 (gate blocked, not exit 2)", async () => {
  const s = await stub([{ path: "/widgets", body: PACKUMENT_WIDGETS_100 }]);
  const dir = trackedRepo("cli-block", { "package.json": PKG_JSON, "border.yaml": cliYaml(s.url) });
  const r = await cliCheck(dir, ["--json"]);
  assert.equal(r.code, EXIT_BLOCKED);
  const vf = (r.report?.findings ?? []).filter((f) => f.rule === VERSION_EXISTS_RULE);
  assert.equal(vf.length, 1);
  assert.equal(vf[0]?.message, "bump version required");
});

test("CLI AC: refused registry port ⇒ exit 2 with engine-run-error line, never exit 0/1", async () => {
  const dir = trackedRepo("cli-refused", { "package.json": PKG_JSON, "border.yaml": cliYaml(`http://127.0.0.1:${String(await closedEphemeralPort())}`) });
  const r = await cliCheck(dir);
  assert.equal(r.code, EXIT_ERROR, `stdout=${r.out.join("|")}`);
  assert.match(r.err.join("|"), /engine run error/i);
});
