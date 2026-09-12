// provenance: original clean-room implementation per .omo/plans/border-opencode-plugin.md
//
// Byte-pins, plugin-behaviour, and installer-lifecycle coverage for the
// official opencode plugin adapter (plugin/border.ts + src/commands/opencode.ts).
// Plugin spawns are faked with test/fixtures/opencode/echo-argv.mjs via
// BORDER_BIN; installer destinations live in test/tmp sandboxes whose HOME and
// XDG_CONFIG_HOME never touch the real user profile.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmodSync, existsSync, lstatSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { test } from "node:test";
import { join } from "node:path";
import type { Config, ToolContext } from "@opencode-ai/plugin";
import { run } from "../src/cli.ts";
import { COMMAND_MARKER } from "../src/commands/opencode.ts";
import borderPlugin, { COMMAND_TEMPLATE } from "../plugin/border.ts";
import { BORDER_ROOT, makeFixtureDir, removeDir } from "./helpers/fixtures.ts";

const PLUGIN_PATH = join(BORDER_ROOT, "plugin", "border.ts");
const MD_PATH = join(BORDER_ROOT, "plugin", "border-command.md");
const DIST_INDEX = join(BORDER_ROOT, "dist", "index.js");
const FIXTURE = join(BORDER_ROOT, "test", "fixtures", "opencode", "echo-argv.mjs");

test.before(() => {
  // fake-CLI fixture is spawned via shebang: needs the exec bit (mode bits are
  // not preserved when the file is created by machine, no git commit here)
  chmodSync(FIXTURE, 0o755);
});

interface PkgShape {
  version?: string;
  exports?: { [subpath: string]: unknown };
  dependencies?: { [name: string]: unknown };
  files?: unknown;
}

function readPkg(): PkgShape {
  return JSON.parse(readFileSync(join(BORDER_ROOT, "package.json"), "utf8")) as PkgShape;
}

function makeToolContext(): ToolContext {
  return {
    sessionID: "test-session",
    messageID: "test-message",
    agent: "test-agent",
    directory: "/tmp",
    worktree: "/tmp",
    abort: new AbortController().signal,
    metadata: () => {},
    ask: async () => {},
  };
}

function resultText(result: string | { output: string }): string {
  return typeof result === "string" ? result : result.output;
}

function packageJsonPluginsEnv(home: string): { HOME: string; XDG_CONFIG_HOME: string } {
  return { HOME: home, XDG_CONFIG_HOME: join(home, ".config") };
}

async function opencode(
  args: readonly string[],
  env: Record<string, string>,
): Promise<{ code: number; out: string[]; err: string[] }> {
  const out: string[] = [];
  const err: string[] = [];
  const code = await run(["opencode", ...args], (l) => out.push(l), (l) => err.push(l), { cwd: BORDER_ROOT, env });
  return { code, out, err };
}

function shaOf(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}

test("hygiene: packaged assets carry the pinned markers and the plugin template byte-mirrors the command file", () => {
  const pkg = readPkg();
  const version = pkg.version ?? "";
  assert.notEqual(version, "", "package.json must carry a version");
  const exportsMap = pkg.exports ?? {};
  assert.equal(exportsMap["./server"], "./plugin/border.ts");
  assert.equal(typeof exportsMap["./package.json"], "string");
  const deps = pkg.dependencies ?? {};
  assert.equal(typeof deps["@opencode-ai/plugin"], "string", "the plugin adapter dependency must be declared");
  const files = pkg.files ?? [];
  assert.ok(Array.isArray(files) && files.includes("plugin"), 'package.json files must ship the "plugin" dir');

  const pluginSource = readFileSync(PLUGIN_PATH, "utf8");
  const pluginLines = pluginSource.split("\n");
  const markerLine = pluginLines[0] ?? "";
  assert.ok(markerLine.startsWith("// border-opencode-plugin v"), "plugin line 1 must carry the version marker");
  assert.equal(
    markerLine,
    `// border-opencode-plugin v${version}`,
    "plugin marker version must equal the package.json version",
  );

  const mdSource = readFileSync(MD_PATH, "utf8");
  const mdLines = mdSource.split("\n");
  assert.equal(mdLines[0], COMMAND_MARKER, "command file line 1 (byte 0 onward) must be exactly the marker");
  assert.ok(mdSource.startsWith(COMMAND_MARKER), "command file must start with the marker at byte 0");

  // byte-mirror: lines 2.. of the command file === the runtime COMMAND_TEMPLATE verbatim
  assert.equal(mdSource, `${COMMAND_MARKER}\n${COMMAND_TEMPLATE}`, "command file must be marker + newline + COMMAND_TEMPLATE");
});

test("plugin: server() exposes config + tool hooks and the config hook self-registers the /border command", async () => {
  const hooks = await borderPlugin.server();
  assert.equal(typeof hooks.config, "function");
  assert.equal(typeof hooks.tool, "object");

  const fresh: Config = {};
  await hooks.config(fresh);
  const border = fresh.command?.border;
  assert.ok(border !== undefined, "config hook must create command.border on a fresh config");
  assert.equal(border.template, COMMAND_TEMPLATE);
  assert.equal(border.description, "Drive the border push gate (usage: /border <command> [args...])");

  // ??= pin: a pre-existing sentinel must survive untouched
  const preSet: Config = { command: { border: { template: "sentinel", description: "mine" } } };
  await hooks.config(preSet);
  assert.equal(preSet.command?.border?.template, "sentinel");
});

test("plugin: execute spawns the configured CLI with command + extra argv and renders sections", async (t) => {
  const hooks = await borderPlugin.server();
  const execute = hooks.tool["border"].execute;
  const ctx = makeToolContext();

  process.env["BORDER_BIN"] = FIXTURE;
  delete process.env["FAKE_EXIT"];
  t.after(() => {
    delete process.env["BORDER_BIN"];
    delete process.env["FAKE_EXIT"];
  });

  const res = resultText(await execute({ command: "check", extra: ["--verbose", "x"] }, ctx));
  assert.ok(res.includes("$ border check --verbose x"), `shell line missing in:\n${res}`);
  assert.ok(res.includes("exit: 0"), `exit line missing in:\n${res}`);
  assert.ok(res.includes("--- stdout ---"), "stdout section header missing");
  const stdoutSection = res.slice(res.indexOf("--- stdout ---"), res.indexOf("--- stderr ---"));
  assert.ok(stdoutSection.includes("argv: check"), "fixture did not echo the command token into the stdout section");
  assert.ok(stdoutSection.includes("argv: --verbose"), "fixture did not echo extra token 1");
  assert.ok(stdoutSection.includes("argv: x"), "fixture did not echo extra token 2");
});

test("plugin: unknown command is refused locally and the CLI is never spawned", async (t) => {
  const hooks = await borderPlugin.server();
  const execute = hooks.tool["border"].execute;
  const ctx = makeToolContext();

  process.env["BORDER_BIN"] = FIXTURE;
  t.after(() => {
    delete process.env["BORDER_BIN"];
    delete process.env["FAKE_EXIT"];
  });

  const res = resultText(await execute({ command: "promote" }, ctx));
  assert.ok(res.includes("refused"), `refusal wording missing in:\n${res}`);
  assert.ok(res.includes("Allowed:"), "refusal must name the allowed list");
  assert.ok(res.includes("scan"), "refusal must list the allowed commands");
  assert.ok(!res.includes("argv:"), "fixture must not have been spawned (no echo)");
});

test("plugin: --yes anywhere in argv is refused as the human gate", async (t) => {
  const hooks = await borderPlugin.server();
  const execute = hooks.tool["border"].execute;
  const ctx = makeToolContext();

  process.env["BORDER_BIN"] = FIXTURE;
  t.after(() => {
    delete process.env["BORDER_BIN"];
    delete process.env["FAKE_EXIT"];
  });

  const res = resultText(await execute({ command: "push", extra: ["--yes"] }, ctx));
  assert.ok(/terminal|human gate/i.test(res), `--yes refusal must point at the terminal/human gate:\n${res}`);
  assert.ok(!res.includes("argv:"), "fixture must not have been spawned (no echo)");
});

test("plugin: the CLI exit code becomes the reported exit code", async (t) => {
  const hooks = await borderPlugin.server();
  const execute = hooks.tool["border"].execute;
  const ctx = makeToolContext();

  process.env["BORDER_BIN"] = FIXTURE;
  process.env["FAKE_EXIT"] = "2";
  t.after(() => {
    delete process.env["BORDER_BIN"];
    delete process.env["FAKE_EXIT"];
  });

  const res = resultText(await execute({ command: "status" }, ctx));
  assert.ok(res.includes("exit: 2"), `FAKE_EXIT=2 must surface as exit: 2:\n${res}`);
});

test("plugin: ENOENT maps to 127 with a note naming the remedies", async (t) => {
  const hooks = await borderPlugin.server();
  const execute = hooks.tool["border"].execute;
  const ctx = makeToolContext();

  process.env["BORDER_BIN"] = "/nonexistent-xyz";
  t.after(() => {
    delete process.env["BORDER_BIN"];
    delete process.env["FAKE_EXIT"];
  });

  const res = resultText(await execute({ command: "status" }, ctx));
  assert.ok(res.includes("exit: 127"), `ENOENT must map to 127:\n${res}`);
  assert.ok(res.includes("BORDER_BIN"), "ENOENT note must name the BORDER_BIN remedy");
  assert.ok(res.includes("opencode install"), "ENOENT note must name the opencode install remedy");
});

test("plugin: --help with the packaged dist resolves via the dist self-spawn", async (t) => {
  const hooks = await borderPlugin.server();
  const execute = hooks.tool["border"].execute;
  const ctx = makeToolContext();

  if (!existsSync(DIST_INDEX)) {
    t.skip(`dist/index.js is not built on this checkout (gitignored); build it (npm run build) and rerun to exercise the dist self-spawn path`);
    return;
  }

  delete process.env["BORDER_BIN"];
  t.after(() => {
    delete process.env["BORDER_BIN"];
    delete process.env["FAKE_EXIT"];
  });

  const res = resultText(await execute({ command: "--help" }, ctx));
  assert.ok(res.includes("usage: border"), `dist --help must print the border usage:\n${res}`);
  assert.ok(res.includes("exit: 0"), `dist --help must exit 0:\n${res}`);
});

test("installer: fresh install copies both packaged assets byte-for-byte", async (t) => {
  const home = makeFixtureDir("opencode-install");
  t.after(() => removeDir(home));
  const xdg = join(home, ".config");

  const packagedPlug = readFileSync(PLUGIN_PATH);
  const packagedMd = readFileSync(MD_PATH);

  const { code, out, err } = await opencode(["install"], packageJsonPluginsEnv(home));
  assert.equal(code, 0, `install failed:\n${err.join("\n")}`);
  const borderPlug = join(xdg, "opencode", "plugins", "border.ts");
  const borderMd = join(xdg, "opencode", "commands", "border.md");
  assert.ok(out.includes(`${borderPlug}: installed`), `missing install line:\n${out.join("\n")}`);
  assert.ok(out.includes(`${borderMd}: installed`), `missing install line:\n${out.join("\n")}`);
  assert.ok(out.includes("note: restart opencode to load the plugin — tools and commands are scanned at startup."));
  assert.ok(readFileSync(borderPlug).equals(packagedPlug), "plugin file must be a byte-copy of the packaged asset");
  assert.ok(readFileSync(borderMd).equals(packagedMd), "command file must be a byte-copy of the packaged asset");

  // second install: idempotent
  const again = await opencode(["install"], packageJsonPluginsEnv(home));
  assert.equal(again.code, 0);
  assert.ok(again.out.includes(`${borderPlug}: up to date`));
  assert.ok(again.out.includes(`${borderMd}: up to date`));
  assert.ok(readFileSync(borderPlug).equals(packagedPlug), "idempotent install must not rewrite bytes");
});

test("installer: a stale marked file is updated and foreign/awkward destinations are refused atomically", async (t) => {
  const home = makeFixtureDir("opencode-refuse");
  t.after(() => removeDir(home));
  const xdg = join(home, ".config");
  const env = packageJsonPluginsEnv(home);
  const borderPlug = join(xdg, "opencode", "plugins", "border.ts");
  const borderMd = join(xdg, "opencode", "commands", "border.md");
  const packagedPlug = readFileSync(PLUGIN_PATH);
  const packagedMd = readFileSync(MD_PATH);

  await opencode(["install"], env);

  // 1. stale marked file => updated, bytes restored
  writeFileSync(borderPlug, Buffer.concat([packagedPlug, Buffer.from("x")]));
  let r = await opencode(["install"], env);
  assert.equal(r.code, 0);
  assert.ok(r.out.includes(`${borderPlug}: updated`), `expected updated line:\n${r.out.join("\n")}`);
  assert.ok(readFileSync(borderPlug).equals(packagedPlug), "stale file must be restored to the packaged bytes");

  // 2. directory at a destination => exit 2, nothing else touched
  rmSync(borderPlug);
  mkdirSync(borderPlug);
  r = await opencode(["install"], env);
  assert.equal(r.code, 2, `directory at destination must refuse (exit 2), got ${r.code}`);
  assert.ok(r.err.some((l) => l.includes(borderPlug)), `refusal must name the path:\n${r.err.join("\n")}`);
  assert.ok(lstatSync(borderPlug).isDirectory(), "directory must be left alone");
  assert.ok(readFileSync(borderMd).equals(packagedMd), "sibling target must be untouched by the refusal");
  rmSync(borderPlug, { recursive: true });

  // 3. symlink at a destination => exit 2, never followed
  const fence = join(home, "outside-file.txt");
  writeFileSync(fence, "not ours, do not destroy");
  symlinkSync(fence, borderPlug);
  r = await opencode(["install"], env);
  assert.equal(r.code, 2, `symlink at destination must refuse (exit 2), got ${r.code}`);
  assert.ok(lstatSync(borderPlug).isSymbolicLink(), "symlink must not be followed or replaced");
  assert.equal(readFileSync(fence, "utf8"), "not ours, do not destroy", "symlink target content must survive");
  rmSync(borderPlug);
  writeFileSync(borderPlug, packagedPlug);

  // 4. foreign file => exit 2, named, bytes intact, sibling untouched (atomicity)
  writeFileSync(borderMd, "some other tool's command file\n");
  r = await opencode(["install"], env);
  assert.equal(r.code, 2, `foreign file must refuse (exit 2), got ${r.code}`);
  assert.ok(r.err.some((l) => l.includes(borderMd)), `refusal must name the foreign path:\n${r.err.join("\n")}`);
  assert.equal(readFileSync(borderMd, "utf8"), "some other tool's command file\n", "foreign bytes must survive");
  assert.ok(readFileSync(borderPlug).equals(packagedPlug), "marked sibling must not be rewritten when a foreign file blocks");
});

test("installer: status reports states and sha256 for absent and up-to-date targets", async (t) => {
  const home = makeFixtureDir("opencode-status");
  t.after(() => removeDir(home));
  const env = packageJsonPluginsEnv(home);
  const borderPlug = join(home, ".config", "opencode", "plugins", "border.ts");
  const borderMd = join(home, ".config", "opencode", "commands", "border.md");
  const packagedPlug = readFileSync(PLUGIN_PATH);
  const packagedMd = readFileSync(MD_PATH);

  const absent = await opencode(["status"], env);
  assert.equal(absent.code, 0);
  assert.ok(absent.out.includes(`${borderPlug}: absent  installed=-  packaged=${shaOf(packagedPlug)}`));
  assert.ok(absent.out.includes(`${borderMd}: absent  installed=-  packaged=${shaOf(packagedMd)}`));

  await opencode(["install"], env);
  const upToDate = await opencode(["status"], env);
  assert.equal(upToDate.code, 0);
  assert.ok(upToDate.out.includes(`${borderPlug}: up-to-date  installed=${shaOf(packagedPlug)}  packaged=${shaOf(packagedPlug)}`));
  assert.ok(upToDate.out.includes(`${borderMd}: up-to-date  installed=${shaOf(packagedMd)}  packaged=${shaOf(packagedMd)}`));
});

test("installer: uninstall removes marked files only, is absent-safe, and refuses foreign files", async (t) => {
  const home = makeFixtureDir("opencode-uninstall");
  t.after(() => removeDir(home));
  const xdg = join(home, ".config");
  const env = packageJsonPluginsEnv(home);
  const borderPlug = join(xdg, "opencode", "plugins", "border.ts");
  const borderMd = join(xdg, "opencode", "commands", "border.md");

  await opencode(["install"], env);
  const gone = await opencode(["uninstall"], env);
  assert.equal(gone.code, 0);
  assert.ok(gone.out.includes(`${borderPlug}: removed`));
  assert.ok(gone.out.includes(`${borderMd}: removed`));
  assert.ok(gone.out.includes("note: restart opencode for the tool and command to disappear."));
  assert.ok(!existsSync(borderPlug) && !existsSync(borderMd), "marked files must be removed");

  const absentSafe = await opencode(["uninstall"], env);
  assert.equal(absentSafe.code, 0);
  assert.ok(absentSafe.out.includes(`${borderPlug}: absent (nothing to remove)`));
  assert.ok(absentSafe.out.includes(`${borderMd}: absent (nothing to remove)`));
});

test("installer: uninstall refuses foreign files and removes nothing", async (t) => {
  const home = makeFixtureDir("opencode-uninstall-foreign");
  t.after(() => removeDir(home));
  const env = packageJsonPluginsEnv(home);
  const borderPlug = join(home, ".config", "opencode", "plugins", "border.ts");

  mkdirSync(join(home, ".config", "opencode", "plugins"), { recursive: true });
  writeFileSync(borderPlug, "someone else's plugin\n");
  const r = await opencode(["uninstall"], env);
  assert.equal(r.code, 2, `foreign uninstall must refuse (exit 2), got ${r.code}`);
  assert.ok(r.err.some((l) => l.includes(borderPlug)), `refusal must name the path:\n${r.err.join("\n")}`);
  assert.equal(readFileSync(borderPlug, "utf8"), "someone else's plugin\n", "foreign file must survive");
});

test("installer: bad subcommands and stray arguments exit 2 with usage", async () => {
  const env = packageJsonPluginsEnv(makeFixtureDir("opencode-usage"));
  for (const args of [[], ["bogus"], ["install", "extra"]] as const) {
    const { code, err } = await opencode([...args], env);
    assert.equal(code, 2, `["opencode", ...${args.map((a) => JSON.stringify(a)).join(",")}] must exit 2, got ${code}`);
    assert.ok(err.join("\n").includes("usage: border opencode install | status | uninstall"), `usage missing:\n${err.join("\n")}`);
  }
});