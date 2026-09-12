// provenance: original clean-room implementation per .omo/plans/border-opencode-plugin.md
//
// OPT-IN end-to-end probe: BORDER_OPENCODE_PROBE=1 turns it on, otherwise the
// whole file is a single skip. When on, it drives the REAL opencode binary:
// sandbox HOME + XDG_CONFIG_HOME, `node dist/index.js opencode install`, a
// plugin-less opencode.jsonc, `opencode serve` on a free port, HTTP polls for
// the /command registry and the tool ids. Mirrors handoff §4: abort flows are
// observed on the wire, not via exit codes (plugin load failures are silent).
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { test } from "node:test";
import { join } from "node:path";
import { BORDER_ROOT, makeFixtureDir, removeDir } from "./helpers/fixtures.ts";

const POLL_INTERVAL_MS = 500;
const POLL_DEADLINE_MS = 60_000;

function pathHasOpenCode(): string {
  const paths = (process.env["PATH"] ?? "").split(":").filter((p) => p.length > 0);
  for (const dir of paths) {
    for (const name of ["opencode", "opencode.cmd"]) {
      const candidate = join(dir, name);
      if (existsSync(candidate)) return candidate;
    }
  }
  return "";
}

/** Reserve a free TCP port on loopback (connect race is acceptable for this test). */
async function freePort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (address === null || typeof address === "string") {
    server.close();
    throw new Error("listen(0) did not yield a TCP port");
  }
  const port = address.port;
  server.close();
  return port;
}

async function waitFor(
  poll: () => Promise<boolean>,
  deadlineMs: number,
): Promise<boolean> {
  const deadline = Date.now() + deadlineMs;
  for (;;) {
    if (await poll()) return true;
    if (Date.now() >= deadline) return false;
    await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
  }
}

test("probe: installed plugin registers exactly one border command and the border tool on a live serve", async (t) => {
  if (process.env["BORDER_OPENCODE_PROBE"] !== "1") {
    t.skip("BORDER_OPENCODE_PROBE=1 turns this end-to-end probe on (needs the real opencode binary and a built dist)");
    return;
  }

  const opencodeBin = pathHasOpenCode();
  if (opencodeBin.length === 0) {
    t.skip("no `opencode` binary found on PATH — build the probe environment and rerun");
    return;
  }
  const distIndex = join(BORDER_ROOT, "dist", "index.js");
  if (!existsSync(distIndex)) {
    t.skip(`dist/index.js is not built (gitignored); run npm run build first`);
    return;
  }

  const sandbox = makeFixtureDir("probe-opencode");
  t.after(() => removeDir(sandbox));
  // Full inherited env + HOME/XDG overrides — empirically REQUIRED: the
  // bun-built opencode binary never starts its HTTP server when spawned with a
  // trimmed {HOME,XDG_CONFIG_HOME,PATH}-only environment (verified 2026-09-12).
  const env = { ...process.env, HOME: sandbox, XDG_CONFIG_HOME: join(sandbox, ".config") };

  const installed = spawnSync(process.execPath, [distIndex, "opencode", "install"], {
    cwd: BORDER_ROOT,
    env,
    encoding: "utf8",
  });
  assert.equal(
    installed.status,
    0,
    `border opencode install failed (${String(installed.status)}): ${installed.stderr ?? ""}`,
  );

  // plugin-less config: the install-free route B must not be required here —
  // this probe exercises route A (file drop), so no plugin[] entries at all.
  mkdirSync(join(env.XDG_CONFIG_HOME, "opencode"), { recursive: true });
  writeFileSync(join(env.XDG_CONFIG_HOME, "opencode", "opencode.jsonc"), '{\n  "autoupdate": false\n}\n', "utf8");

  const port = await freePort();
  const server = spawn(opencodeBin, ["serve", "--port", String(port)], {
    cwd: sandbox,
    env,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let serveLog = "";
  server.stdout?.on("data", (chunk: Buffer) => {
    serveLog += chunk.toString("utf8");
  });
  server.stderr?.on("data", (chunk: Buffer) => {
    serveLog += chunk.toString("utf8");
  });
  const exited = new Promise<number | null>((resolve) => {
    server.once("exit", (code) => resolve(code));
  });
  t.after(async () => {
    if (server.exitCode === null && server.signalCode === null) {
      server.kill("SIGTERM");
      const done = await Promise.race([exited, new Promise((resolve) => setTimeout(resolve, 3_000))]);
      if (done === undefined && server.exitCode === null && server.signalCode === null) {
        server.kill("SIGKILL");
      }
    }
  });

  const base = `http://127.0.0.1:${port}`;
  const ready = await waitFor(async () => {
    // AbortSignal.timeout guards the undici connect/headers stall (a dead
    // socket otherwise keeps fetch pending for the default 300s headersTimeout)
    try {
      const res = await fetch(`${base}/command`, { signal: AbortSignal.timeout(3_000) });
      return res.ok;
    } catch {
      return false;
    }
  }, POLL_DEADLINE_MS);
  assert.ok(ready, `opencode serve did not answer within ${POLL_DEADLINE_MS / 1000}s. serve log:\n${serveLog}`);

  const commandRes = await fetch(`${base}/command`);
  assert.ok(commandRes.ok, `GET /command failed: ${commandRes.status}. serve log:\n${serveLog}`);
  const commands: unknown = await commandRes.json();
  assert.ok(Array.isArray(commands), `GET /command must return a JSON array. serve log:\n${serveLog}`);
  const borders = (commands as unknown[]).filter(
    (row) => typeof row === "object" && row !== null && "name" in row && row.name === "border",
  );
  assert.equal(
    borders.length,
    1,
    `expected EXACTLY one /command entry named "border" (duplicate registration is abnormal), got ${borders.length}. serve log:\n${serveLog}`,
  );

  const toolsRes = await fetch(`${base}/experimental/tool/ids`);
  assert.ok(toolsRes.ok, `GET /experimental/tool/ids failed: ${toolsRes.status}. serve log:\n${serveLog}`);
  const toolIds: unknown = await toolsRes.json();
  assert.ok(Array.isArray(toolIds), `tool ids must be a JSON array. serve log:\n${serveLog}`);
  assert.ok(
    (toolIds as unknown[]).includes("border"),
    `the "border" tool must be registered. serve log:\n${serveLog}`,
  );
});