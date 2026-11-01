// provenance: sibyl Q1 ruling 2026-10-23 option B+ — `border sandbox` helper behavior pins.
import assert from "node:assert/strict";
import { test } from "node:test";

import { run, usage } from "../src/cli.ts";
import { makeSandboxHandler, type Io } from "../src/commands/sandbox.ts";
import { machineStoreKey } from "../src/config/machineStore.ts";
import type { Ctx } from "../src/cli/types.ts";

const PIN = `node@sha256:${"a".repeat(64)}`;
const STORE = "/store";
const KEY = machineStoreKey("github.com/acme/widgets");
const PATH = `${STORE}/${KEY}.yaml`;

function fakeIo(files: Map<string, string>, o: { fileOk?: boolean; dirOk?: boolean } = {}): Io & { calls: string[] } {
  const calls: string[] = [];
  return {
    calls,
    read: (p) => {
      const v = files.get(p);
      if (v === undefined) throw new Error(`ENOENT ${p}`);
      return v;
    },
    writeAtomic0600: (p, text) => {
      calls.push(`write:${p}`);
      files.set(p, text);
    },
    mkdir0700: (p) => calls.push(`mkdir:${p}`),
    exists: (p) => files.has(p),
    remove: (p) => {
      calls.push(`remove:${p}`);
      files.delete(p);
    },
    remotes: () => [{ name: "origin", url: "https://github.com/acme/widgets.git" }],
    qualifyFile: () => o.fileOk !== false,
    qualifyDirFn: () => o.dirOk !== false,
    storeDirOverride: STORE,
  };
}

function ctx(sub: readonly string[], flags: Partial<Ctx["flags"]>): Ctx {
  const out: string[] = [];
  const err: string[] = [];
  const base: Ctx = {
    command: "sandbox",
    // eslint note: fixture shorthand — optional-key spread under exactOptionalPropertyTypes
    flags: { force: false, yes: false, ...flags } as Ctx["flags"],
    positionals: sub,
    cwd: "/repo",
    env: {},
    stdout: (l) => out.push(String(l)),
    stderr: (l) => err.push(String(l)),
    handlers: {} as Ctx["handlers"],
  };
  return base;
}

test("init writes a valid machine-store fragment with the pinned image, remote-derived key", async () => {
  const files = new Map<string, string>();
  const io = fakeIo(files);
  const handler = makeSandboxHandler(io);
  const c = ctx(["init"], { lane: "npm", image: PIN });
  assert.equal(await handler(c), 0);
  const doc = (await import("yaml")).parse(files.get(PATH) ?? "") as {
    version: number;
    targets: { git: { remotes: unknown[] }; npm: { sandboxImage?: string } };
    rules: unknown;
  };
  assert.equal(doc.version, 1);
  assert.equal(doc.targets.npm.sandboxImage, PIN);
  assert.ok(Array.isArray(doc.targets.git.remotes) && doc.targets.git.remotes.length === 1);
  assert.ok(doc.rules !== undefined);
  assert.ok(io.calls.includes(`mkdir:${STORE}`));
});

test("a mutable tag is refused and nothing is written", async () => {
  const files = new Map<string, string>();
  const io = fakeIo(files);
  const handler = makeSandboxHandler(io);
  assert.equal(await handler(ctx(["init"], { lane: "npm", image: "node:22" })), 2);
  assert.equal(files.size, 0);
});

test("§3 self-verification: a written file failing qualification is REMOVED and refused", async () => {
  const files = new Map<string, string>();
  const io = fakeIo(files, { fileOk: false });
  const handler = makeSandboxHandler(io);
  assert.equal(await handler(ctx(["pin"], { lane: "npm,pypi", image: PIN })), 2);
  assert.equal(files.has(PATH), false);
  assert.ok(io.calls.some((c) => c.startsWith(`remove:${PATH}`)));
});

test("existing store content is merged, not clobbered; unpin removes only the sandbox keys", async () => {
  const yaml = (await import("yaml")).stringify({
    version: 1,
    targets: { git: { remotes: [{ url: "https://github.com/acme/widgets.git" }] }, npm: { registry: "http://localhost:4873" } },
    rules: { authors: { emails: ["a@b.c"], names: [] }, hosts: [], ips: [], pathPatterns: [] },
  });
  const files = new Map<string, string>([[PATH, yaml]]);
  const io = fakeIo(files);
  const handler = makeSandboxHandler(io);
  assert.equal(await handler(ctx(["init"], { lane: "npm", image: PIN })), 0);
  let doc = (await import("yaml")).parse(files.get(PATH) ?? "") as { targets: { npm: Record<string, unknown> } };
  assert.equal(doc.targets.npm.sandboxImage, PIN);
  assert.equal(doc.targets.npm.registry, "http://localhost:4873");
  assert.equal(await handler(ctx(["unpin"], { lane: "npm" })), 0);
  doc = (await import("yaml")).parse(files.get(PATH) ?? "") as { targets: { npm: Record<string, unknown> } };
  assert.equal("sandboxImage" in doc.targets.npm, false);
  assert.equal(doc.targets.npm.registry, "http://localhost:4873");
});

test("unknown --lane is a typed refusal", async () => {
  const handler = makeSandboxHandler(fakeIo(new Map()));
  await assert.rejects(
    async () => handler(ctx(["init"], { lane: "gems", image: PIN })),
    (e: unknown) => e instanceof Error && /--lane/.test((e as Error).message),
  );
});

test("status renders the store state without a config present", async () => {
  const files = new Map<string, string>();
  const handler = makeSandboxHandler(fakeIo(files));
  assert.equal(await handler(ctx(["status"], {})), 0);
});

// ------------------------------------------------- CLI wiring (real dispatch)

test("usage lists sandbox; bare sandbox and bogus lane reach typed exits through the real CLI", async () => {
  assert.match(usage(), /sandbox\s+init\|pin\|status\|unpin/);
  const lines: string[] = [];
  const errs: string[] = [];
  assert.equal(await run(["sandbox"], (l) => lines.push(String(l)), (l) => errs.push(String(l))), 2);
  assert.ok(errs.some((l) => l.includes("border sandbox init|pin")));
  const code = await run(["sandbox", "init", "--lane", "gems", "--image", PIN], () => {}, (l) => errs.push(String(l)), { cwd: "/repo" });
  assert.equal(code, 2);
  assert.ok(errs.some((l) => l.includes("--lane")));
});
