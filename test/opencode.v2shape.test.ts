// provenance: original implementation per .omo/plans/border-opencode-v2-plugin.md (plan T2)
//
// Invariant-core coverage for the dual-shape default export of plugin/border.ts:
// the V2 loader surface ({id, setup}) structurally, byte-exact V1↔V2 execute
// parity against the echo-argv fake CLI, and the pre-spawn gates on the V2
// edge. The V1 frozen shadow is test/opencode.test.ts, which must keep
// passing unmodified (plan T2 item (e) runs it separately, not from here).
//
// Same-env cache note (plan D2): the verified handshake cache is keyed by
// BORDER_BIN, so in the parity tests the second edge eats the first edge's
// cache — that is intentional here (parity is about the render); V2-side
// coverage of the handshake resolution itself belongs to the T3 live probe.
import assert from "node:assert/strict";
import { chmodSync, readFileSync } from "node:fs";
import { test, type TestContext } from "node:test";
import { join } from "node:path";
import type { ToolContext } from "@opencode-ai/plugin";
import borderPlugin from "../plugin/border.ts";
import type { V2PluginContext, V2ToolEditor, V2ToolInfo } from "../plugin/border.ts";
import { BORDER_ROOT } from "./helpers/fixtures.ts";

const PLUGIN_PATH = join(BORDER_ROOT, "plugin", "border.ts");
const FIXTURE = join(BORDER_ROOT, "test", "fixtures", "opencode", "echo-argv.mjs");

test.before(() => {
  // the fake CLI is spawned via shebang: needs the exec bit (same reason and
  // same mode as test/opencode.test.ts sets it up)
  chmodSync(FIXTURE, 0o755);
});

/** Mirror of the stub in test/opencode.test.ts: V1 execute uses metadata(). */
function makeToolContext(): ToolContext {
  return {
    sessionID: "v2shape-session",
    messageID: "v2shape-message",
    agent: "v2shape-agent",
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

function useBorderBin(t: TestContext, value: string): void {
  process.env["BORDER_BIN"] = value;
  delete process.env["FAKE_EXIT"];
  t.after(() => {
    delete process.env["BORDER_BIN"];
    delete process.env["FAKE_EXIT"];
  });
}

/**
 * Drive setup() through a fake V2 ctx shaped exactly like the loader seam
 * (transform hands a synchronous editor to the callback and returns the
 * registration) and capture the Info handed to editor.add.
 */
async function captureV2ToolInfo(): Promise<V2ToolInfo> {
  let added: V2ToolInfo | null = null;
  const ctx: V2PluginContext = {
    tool: {
      transform: async (callback: (editor: V2ToolEditor) => void): Promise<unknown> => {
        callback({
          add: (info: V2ToolInfo): void => {
            added = info;
          },
        });
        return added;
      },
    },
  };
  await borderPlugin.setup(ctx);
  assert.ok(added !== null, "setup must add exactly one tool through the editor");
  return added;
}

test("v2 shape: default export carries {id, setup} alongside server, and the loader's minimum schema accepts it", () => {
  const keys = Object.keys(borderPlugin);
  assert.ok(keys.includes("id"), "default export must carry id");
  assert.ok(keys.includes("setup"), "default export must carry setup");
  assert.ok(keys.includes("server"), "default export must keep the V1 server entry");
  assert.equal(borderPlugin.id, "border", "the id is shared by both loaders");
  assert.equal(borderPlugin.setup.length, 1, "setup must take exactly one ctx argument");

  // five-line mirror of the beta-19271 loader gate Schema.Struct({id, setup}):
  function v2LoaderShapeAccepts(mod: Record<string, unknown>): boolean {
    return typeof mod["id"] === "string" && typeof mod["setup"] === "function";
  }
  assert.ok(v2LoaderShapeAccepts(borderPlugin), "the loader schema mirror must accept the default export");
});

test("v2 execute parity: happy path renders byte-identically on both edges", async (t) => {
  useBorderBin(t, FIXTURE);

  const info = await captureV2ToolInfo();
  const v1 = await borderPlugin.server();

  const v1Text = resultText(await v1.tool["border"].execute({ command: "status", extra: [] }, makeToolContext()));
  const v2 = await info.execute({ command: "status", extra: [] }, {});
  assert.equal(v2.content, v1Text, "V2 content must be byte-equal to the V1 render");
  // …and the render must be the real fixture round-trip, not two equal empties
  assert.ok(v1Text.includes("$ border status"), `shell line missing in:\n${v1Text}`);
  assert.ok(v1Text.includes("exit: 0"), `exit line missing in:\n${v1Text}`);
  assert.ok(v1Text.includes("argv: status"), "fixture must have echoed the argv token");
});

test("v2 execute parity: cannot-answer path renders byte-identically on both edges", async (t) => {
  useBorderBin(t, "/nonexistent-v2shape");

  const info = await captureV2ToolInfo();
  const v1 = await borderPlugin.server();

  const v1Text = resultText(await v1.tool["border"].execute({ command: "status", extra: [] }, makeToolContext()));
  const v2 = await info.execute({ command: "status", extra: [] }, {});
  assert.equal(v2.content, v1Text, "cannot-answer render must be byte-equal across edges");
  assert.ok(v1Text.includes("exit: 2"), `unspawnable override must map to 2:\n${v1Text}`);
  assert.ok(v1Text.includes("cannot-answer"), "note must name the cannot-answer class");
  assert.ok(v1Text.includes("BORDER_BIN"), "note must name the failing candidate");
});

test("v2 gates: allowlist and --yes refusals fire before any spawn, byte-equal to V1", async (t) => {
  useBorderBin(t, FIXTURE);

  const info = await captureV2ToolInfo();
  const v1 = await borderPlugin.server();

  const refusals: ReadonlyArray<{ command: string; extra?: string[] }> = [
    { command: "promote" },
    { command: "push", extra: ["--yes"] },
  ];
  for (const args of refusals) {
    const v1Text = resultText(await v1.tool["border"].execute({ ...args }, makeToolContext()));
    const v2Text = (await info.execute({ ...args }, {})).content;
    assert.ok(v1Text.includes("refused"), `refusal wording missing in:\n${v1Text}`);
    assert.equal(v2Text, v1Text, `refusal must be byte-equal across edges for '${args.command}'`);
    assert.ok(!v2Text.includes("argv:"), "fixture must not have been spawned on a refusal");
    assert.ok(!v2Text.includes("--- stdout ---"), "a refusal must not render CLI sections");
  }
});

test("v2 sync discipline: no await between tool.transform( and editor.add( in the stripped source", () => {
  // comment-stripped exactly like the execPath pin in test/opencode.test.ts,
  // so the contract prose may name the identifiers freely
  const code = readFileSync(PLUGIN_PATH, "utf8")
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/\/\/[^\n]*/g, "");
  const callAt = code.indexOf("tool.transform(");
  assert.ok(callAt >= 0, "setup must call ctx.tool.transform");
  const addAt = code.indexOf("editor.add(", callAt);
  assert.ok(addAt > callAt, "the transform callback must call editor.add");
  const between = code.slice(callAt, addAt);
  assert.ok(
    !between.includes("await"),
    "the transform callback body must stay synchronous (only editor.add inside; async work belongs in execute) — found an await in:\n" + between,
  );
});
