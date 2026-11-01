// W4 sandbox contract tests (sibyl ruling 2026-10-23): docker argv is the
// containment proof, so it is asserted token by token; probe/marker exit codes
// must surface as named errors; the digest-pin schema gate is load-bearing.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  SANDBOX_IMAGE_RE,
  runSandboxedBuild,
  sandboxBindingJoin,
  sandboxDockerArgs,
  sandboxRun,
  shQuote,
} from "../src/artifacts/sandbox.ts";
import { sandboxPackOnce } from "../src/artifacts/npmPack.ts";
import { ConfigError, loadConfig } from "../src/config.ts";
import { EngineRunError } from "../src/engines/support.ts";
import type { DockerExec, ExecResult } from "../src/roundtrip/docker.ts";
import { makeFixtureDir, removeDir, writeRel } from "./helpers/fixtures.ts";

const PINNED = "node@sha256:" + "a".repeat(64);

function scriptDocker(respond: (args: readonly string[]) => ExecResult): { exec: DockerExec; calls: string[][] } {
  const calls: string[][] = [];
  return {
    calls,
    exec: (args) => {
      calls.push([...args]);
      return respond(args);
    },
  };
}

test("docker argv pins the mechanical contract: net none, read-only, ro repo, drops, sh -eu", () => {
  const args = sandboxDockerArgs({
    spec: { image: PINNED, docker: () => ({ status: 0, stdout: "", stderr: "" }) },
    repoDir: "/repo",
    outDir: "/out",
    script: "echo hi",
  });
  const s = args.join("\u0000");
  for (const needle of [
    "--network", "none",
    "--read-only",
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges",
    "/repo:/audit/repo:ro",
    "/out:/audit/out",
    "--user", "0",
    "--tmpfs", "/work:exec",
  ]) {
    assert.ok(args.includes(needle), `argv must contain ${needle}`);
  }
  assert.ok(s.includes("--volume\u0000/repo:/audit/repo:ro"), "repo mount is ro");
  assert.equal(args.at(-5), PINNED);
  assert.deepEqual(args.slice(-4, -1), ["sh", "-eu", "-c"]);
  assert.equal(args.at(-1), "echo hi");
  // no host env rides in beyond the fixed pair
  const envs = args.flatMap((a, i) => (a === "--env" ? [args[i + 1] ?? ""] : []));
  assert.deepEqual(envs.sort(), ["HOME=/tmp", "LANG=C.UTF-8"]);
});

test("cargo lane adds the rw cache bind + CARGO_HOME, other lanes do not", () => {
  const base = {
    spec: { image: PINNED, docker: () => ({ status: 0, stdout: "", stderr: "" }) },
    repoDir: "/repo",
    outDir: "/out",
    script: "x",
  };
  const plain = sandboxDockerArgs(base).join(" ");
  assert.ok(!plain.includes("/audit/cache"));
  const cargo = sandboxDockerArgs({ ...base, cargoCacheHostDir: "/repo/.border/cache" }).join(" ");
  assert.ok(cargo.includes("/repo/.border/cache:/audit/cache "));
  assert.ok(cargo.includes("CARGO_HOME=/audit/cache/cargo-home"));
});

test("probe/marker exit codes surface as named EngineRunErrors (86 DNS, 87 TCP, 88 no-tool, 85 old npm)", () => {
  const dir = makeFixtureDir("sbx-markers");
  const out = join(dir, "out");
  mkdirSync(out, { recursive: true });
  const run = (status: number, stderr = "") =>
    runSandboxedBuild({ spec: { image: PINNED, docker: () => ({ status, stdout: "", stderr }) }, repoDir: dir, outDir: out, laneScript: "true" });
  assert.throws(() => run(86), (e: unknown) => e instanceof EngineRunError && /DNS resolved inside/.test(e.message));
  assert.throws(() => run(87), (e: unknown) => e instanceof EngineRunError && /TCP connect succeeded/.test(e.message));
  assert.throws(() => run(88), (e: unknown) => e instanceof EngineRunError && /no probe tool/.test(e.message));
  assert.throws(() => run(85, "BORDER-SANDBOX-NPM-OLD: npm 10.9.7 ..."), (e: unknown) => e instanceof EngineRunError && /NPM-OLD|npm too old|10\.9\.7/.test(e.message));
  assert.throws(() => run(1, "boom"), (e: unknown) => e instanceof EngineRunError && /sandboxed build failed \(exit 1\)/.test(e.message));
  removeDir(dir);
});

test("sandboxRun demands toolchain.txt back (unbound record is fail-closed)", () => {
  const dir = makeFixtureDir("sbx-toolchain");
  const out = join(dir, "out");
  mkdirSync(out, { recursive: true });
  const docker = scriptDocker(() => ({ status: 0, stdout: "", stderr: "" }));
  assert.throws(
    () => sandboxRun({ spec: { image: PINNED, docker: docker.exec }, repoDir: dir, outDir: out, laneProbes: ["npm"], laneScript: "true" }),
    (e: unknown) => e instanceof EngineRunError && /no toolchain\.txt/.test(e.message),
  );
  const script = docker.calls[0]?.[docker.calls[0].length - 1] ?? "";
  assert.ok(script.includes("> /audit/out/toolchain.txt"), "probe writes the binding first");
  assert.ok(script.includes("getent hosts registry.npmjs.org"), "DNS leg present");
  assert.ok(script.includes("192.0.2.119"), "TCP leg targets TEST-NET-1");
  removeDir(dir);
});

test("sandboxPackOnce builds inside the container and verifies the report against landed bytes", () => {
  const repo = makeFixtureDir("sbx-pack");
  writeRel(repo, "package.json", JSON.stringify({ name: "widgets", version: "1.0.0" }));
  const dist = join(repo, ".border", "dist");
  mkdirSync(dist, { recursive: true });
  const tarbytes = Buffer.from("fake-tarball-bytes");
  const shasum = createHash("sha1").update(tarbytes).digest("hex");
  const docker = scriptDocker(() => {
    writeFileSync(join(dist, "toolchain.txt"), "npm 11.19.1\nnode v22.22.2\n");
    writeFileSync(join(dist, "widgets-1.0.0.tgz"), tarbytes);
    return {
      status: 0,
      stdout: JSON.stringify([{ name: "widgets", version: "1.0.0", filename: "widgets-1.0.0.tgz", shasum, size: tarbytes.byteLength }]),
      stderr: "",
    };
  });
  const { outcome, toolchain } = sandboxPackOnce({ repoDir: repo, distDir: dist, spec: { image: PINNED, docker: docker.exec } });
  assert.equal(outcome.filename, "widgets-1.0.0.tgz");
  assert.equal(outcome.sha256, createHash("sha256").update(tarbytes).digest("hex"));
  assert.equal(toolchain, "npm 11.19.1\nnode v22.22.2");
  const argv = docker.calls[0] as string[];
  const script = argv[argv.length - 1] ?? "";
  assert.ok(script.includes("npm pack --ignore-scripts --json --pack-destination /audit/out"));
  assert.ok(!script.includes("NPM-OLD"), "no prepare hooks ⇒ the in-image version guard stays disarmed");
  assert.ok(argv.includes(`${repo}:/audit/repo:ro`), "this repo mounted ro");
  removeDir(repo);
});

test("report↔bytes mismatch still fails closed on the sandbox path", () => {
  const repo = makeFixtureDir("sbx-pack-bad");
  writeRel(repo, "package.json", JSON.stringify({ name: "widgets", version: "1.0.0" }));
  const dist = join(repo, ".border", "dist");
  mkdirSync(dist, { recursive: true });
  const docker: DockerExec = () => {
    writeFileSync(join(dist, "toolchain.txt"), "npm 11.19.1");
    writeFileSync(join(dist, "widgets-1.0.0.tgz"), "different-bytes");
    return {
      status: 0,
      stdout: JSON.stringify([{ name: "widgets", version: "1.0.0", filename: "widgets-1.0.0.tgz", shasum: "0".repeat(40), size: 999 }]),
      stderr: "",
    };
  };
  assert.throws(
    () => sandboxPackOnce({ repoDir: repo, distDir: dist, spec: { image: PINNED, docker } }),
    (e: unknown) => e instanceof EngineRunError && /report disagrees with the tarball bytes/.test(e.message),
  );
  removeDir(repo);
});

test("sandboxImage schema gate via loadConfig: tags fail closed typed, digests load", () => {
  assert.ok(SANDBOX_IMAGE_RE.test(PINNED));
  assert.ok(!SANDBOX_IMAGE_RE.test("ubuntu:latest"));
  const dir = makeFixtureDir("sbx-config");
  let outsideBase: string | undefined;
  const yaml = (img: string) => [
    "version: 1",
    "targets:",
    "  git:",
    "    remotes: []",
    "  npm:",
    `    sandboxImage: ${img}`,
    "rules:",
    "  authors:",
    "    emails: [bot@gate-corp.com]",
    "    names: [Wiki.js]",
    "  hosts: []",
    "  ips: []",
    "  pathPatterns: []",
    "",
  ].join("\n");
  try {
    // schema gate is source-independent: a malformed value (mutable tag) dies
    // typed at parse, in any file, before any tier question is asked.
    writeRel(dir, "border.yaml", yaml("node:22"));
    assert.throws(() => loadConfig({ cwd: dir }), (e: unknown) => e instanceof ConfigError && /digest-pinned/.test((e as Error).message));
    // schema gate on a QUALIFIED source: a mutable tag dies typed at parse.
    // (fixtures live under os.tmpdir here ON PURPOSE: makeFixtureDir nests them
    // inside the enclosing git repo, where insideRepo() would — correctly —
    // demote the "outside" --config to repo tier.)
    outsideBase = mkdtempSync(join(tmpdir(), "sbx-outside-"));
    const tagDir = join(outsideBase, "repo-tag");
    writeRel(tagDir, "border.yaml", "version: 1\ntargets:\n  git:\n    remotes: []\n");
    const tagFile = join(outsideBase, "outside-tag.yaml");
    writeFileSync(tagFile, yaml("ubuntu:latest"), "utf8");
    assert.throws(
      () => loadConfig({ cwd: tagDir, configPath: tagFile, securityQualify: () => ({ ok: true }), securityQualifyDir: () => ({ ok: true }) }),
      (e: unknown) => e instanceof ConfigError && /digest-pinned/.test((e as Error).message),
    );
    // security tier (sibyl §3): a digest in the REPO's own config is refused by provenance,
    // schema pass or not — the two gates are independent by design.
    writeRel(dir, "border.yaml", yaml(PINNED));
    assert.throws(() => loadConfig({ cwd: dir }), (e: unknown) => e instanceof ConfigError && /UNQUALIFIED/.test((e as Error).message));
    // the acceptance path: out-of-repo --config (fd-chain-qualified source).
    const repo2 = join(outsideBase, "repo");
    writeRel(repo2, "border.yaml", "version: 1\ntargets:\n  git:\n    remotes: []\n");
    const outside = join(outsideBase, "outside.yaml");
    writeFileSync(outside, yaml(PINNED), "utf8");
    const load = loadConfig({
      cwd: repo2,
      configPath: outside,
      // this test pins the SCHEMA gate; the real fd-chain qualification is
      // tier.test.ts's domain — inject the seam and assert the plumbing only.
      securityQualify: () => ({ ok: true }),
      securityQualifyDir: () => ({ ok: true }),
    });
    assert.equal(load.kind, "loaded");
    if (load.kind === "loaded") assert.equal(load.config.targets.npm?.sandboxImage, PINNED);
  } finally {
    removeDir(dir);
    if (outsideBase !== undefined) removeDir(outsideBase);
  }
});

test("binding join: sorted, unique, host builds join to empty string", () => {
  assert.equal(sandboxBindingJoin([`b@sha256:${"b".repeat(64)}`, `a@sha256:${"a".repeat(64)}`, `b@sha256:${"b".repeat(64)}`]), `a@sha256:${"a".repeat(64)}\nb@sha256:${"b".repeat(64)}`);
  assert.equal(sandboxBindingJoin([]), "");
});

test("shQuote survives paths containing single quotes", () => {
  assert.equal(shQuote("it's a gem"), `'it'\\''s a gem'`);
  assert.equal(shQuote("plain.gemspec"), `'plain.gemspec'`);
});
