// provenance: sibyl ruling 2026-10-23 (Q1 chain, run sibyl-20261023T184627Z-1b47) option B+.
//
// `border sandbox init|pin|status|unpin` — the opt-in helper the ruling approved for
// configuring sandboxImage. Design lines the council drew, encoded here:
//   * writes ONLY the machine store (canonical passwd root or a qualified
//     $XDG_CONFIG_HOME/border/machines) — never the audited repo;
//   * refuses to write wherever the §3 security tier would refuse to READ
//     (real fd-chain qualification of dir + file; a tmp-rooted XDG is
//     fail-closed rejected rather than silently seeded);
//   * every created file lands 0600 under a 0700 directory, written via a
//     same-dir temp + rename (L-STATE-ATOMIC);
//   * images must be digest-pinned (schema regex shared with the config gate);
//   * the file it writes is a full machine-store config fragment — existing
//     content is preserved field-wise, never clobbered.
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { parse, stringify } from "yaml";

import { canonicalStoreRoot, qualifyDir, qualifyRead } from "../tier.ts";
import { ConfigError, loadConfig, SANDBOX_LANES, type SandboxLane } from "../config.ts";
import { SANDBOX_IMAGE_RE } from "../artifacts/sandbox.ts";
import { canonicalRemoteUrl, machineStoreKey } from "../config/machineStore.ts";
import type { CommandHandler, Ctx } from "../cli/types.ts";
import { EXIT_ERROR, EXIT_PASS, type BorderExit } from "../cli/exit.ts";

export type Io = {
  read: (p: string) => string;
  writeAtomic0600: (p: string, text: string) => void;
  mkdir0700: (p: string) => void;
  exists: (p: string) => boolean;
  remove: (p: string) => void;
  remotes: (cwd: string) => { name?: string; url: string }[];
  qualifyFile: (p: string) => boolean;
  qualifyDirFn: (p: string) => boolean;
  storeDirOverride?: string;
};

const realIo: Io = {
  read: (p) => readFileSync(p, "utf8"),
  writeAtomic0600: (p, text) => {
    const tmp = `${p}.tmp-${String(process.pid)}`;
    writeFileSync(tmp, text, { mode: 0o600 });
    renameSync(tmp, p);
  },
  mkdir0700: (p) => {
    // recursive mkdir with explicit 0700 on the leaf AND every created level —
    // the walk chain refuses 0o022-writable parents, so umask defaults (0755)
    // are fine above but the leaf dirs are ours: tighten them.
    let cur = p;
    const stack: string[] = [];
    while (!existsSync(cur) && cur !== "/" && cur !== ".") {
      stack.push(cur);
      cur = dirname(cur);
    }
    for (const dir of stack.reverse()) {
      mkdirSync(dir, { mode: 0o700 });
    }
  },
  exists: (p) => existsSync(p),
  remove: (p) => unlinkSync(p),
  remotes: (cwd) => {
    const r = spawnSync("git", ["-C", cwd, "remote", "-v"], { encoding: "utf8" });
    if (r.error !== undefined || r.status !== 0) return [];
    const seen = new Map<string, { name?: string; url: string }>();
    for (const line of r.stdout.split("\n")) {
      const m = /^(\S+)\s+(\S+)\s+\(fetch\)$/.exec(line);
      if (m?.[1] !== undefined && m[2] !== undefined && !seen.has(m[1])) {
        seen.set(m[1], { name: m[1], url: m[2] });
      }
    }
    return [...seen.values()];
  },
  qualifyFile: (p) => qualifyRead(p).ok,
  qualifyDirFn: (p) => qualifyDir(p).ok,
};

function sandboxIo(ctx: Ctx, io: Io): { io: Io; err: (m: string) => void; out: (m: string) => void } {
  return { io, err: (m) => ctx.stderr(`border: ${m}`), out: (m) => ctx.stdout(m) };
}

function resolveStore(ctx: Ctx, io: Io): { dir: string; path: string; canonical: string } | string {
  const env = ctx.env as Record<string, string | undefined>;
  let dir: string | undefined;
  if (io.storeDirOverride !== undefined) dir = io.storeDirOverride;
  else if (env.XDG_CONFIG_HOME !== undefined && env.XDG_CONFIG_HOME !== "") {
    dir = join(env.XDG_CONFIG_HOME, "border", "machines");
  } else dir = canonicalStoreRoot();
  if (dir === undefined) return "cannot resolve a canonical home from passwd — refusing to place a security-tier file (sibyl §3‡)";
  const remotes = io.remotes(ctx.cwd);
  for (const remote of remotes) {
    const canonical = canonicalRemoteUrl(remote.url);
    if (canonical === undefined) continue;
    return { dir, path: join(dir, `${machineStoreKey(canonical)}.yaml`), canonical };
  }
  return "no canonical git remote in this repository — the machine store keys on remote URL; add an origin first";
}

function loadFragment(io: Io, path: string, remotes: { name?: string; url: string }[]): Record<string, unknown> {
  if (io.exists(path)) {
    const doc = parse(io.read(path)) as unknown;
    if (typeof doc === "object" && doc !== null && !Array.isArray(doc)) return doc as Record<string, unknown>;
    throw new ConfigError("invalid-value", `machine store ${path} is not a config object — refusing to merge`, { key: "machine-store" });
  }
  return {
    version: 1,
    targets: { git: { remotes: remotes.map((r) => ({ ...(r.name !== undefined ? { name: r.name } : {}), url: r.url })) } },
    rules: { authors: { emails: [], names: [] }, hosts: [], ips: [], pathPatterns: [] },
  };
}

function writeLaneImages(ctx: Ctx, images: Map<SandboxLane, string>, io0: Io): BorderExit {
  const { io, err, out } = sandboxIo(ctx, io0);
  const store = resolveStore(ctx, io);
  if (typeof store === "string") return err(store), EXIT_ERROR;
  if (!io.qualifyDirFn(store.dir) && io.exists(store.dir)) {
    return err(`machine store dir ${store.dir} fails the security-tier ownership check — refusing to write where border would refuse to read (sibyl §3⁗)`), EXIT_ERROR;
  }
  const doc = loadFragment(io, store.path, io.remotes(ctx.cwd));
  const targets = (doc.targets ??= {}) as Record<string, unknown>;
  for (const [lane, image] of images) {
    if (!SANDBOX_IMAGE_RE.test(image)) {
      return err(`sandboxImage for ${lane} must be digest-pinned ('<name>@sha256:<64hex>') — tags are rejected (sibyl §3)`), EXIT_ERROR;
    }
    const laneTarget = (targets[lane] ??= {}) as Record<string, unknown>;
    if (typeof laneTarget !== "object" || laneTarget === null) {
      return err(`targets.${lane} in the store file is not a mapping — refusing to merge`), EXIT_ERROR;
    }
    laneTarget.sandboxImage = image;
  }
  io.mkdir0700(store.dir);
  io.writeAtomic0600(store.path, stringify(doc));
  if (!io.qualifyFile(store.path)) {
    io.remove(store.path);
    return err(`wrote ${store.path} but it fails the §3 qualification (modes/ownership) — removed again; fix the store dir ownership`), EXIT_ERROR;
  }
  out(`border: sandbox pins written to ${store.path} (0600) for ${[...images.keys()].join(", ")} — canonical remote ${store.canonical}`);
  out("border: NOTE the pin applies only when border resolves config from the machine store; a repo border.yaml still cannot declare sandboxImage (sibyl §3)");
  return EXIT_PASS;
}

function lanesFromFlag(ctx: Ctx): SandboxLane[] | undefined {
  if (ctx.flags.lane === undefined) return undefined;
  const list = ctx.flags.lane.split(",").map((s) => s.trim()).filter((s) => s !== "");
  const bad = list.filter((l) => !(SANDBOX_LANES as readonly string[]).includes(l));
  if (bad.length > 0) throw new ConfigError("invalid-value", `--lane accepts ${SANDBOX_LANES.join("|")} (got '${bad.join(",")}')`, { key: "--lane" });
  return list as SandboxLane[];
}

export function makeSandboxHandler(injected: Io = realIo): CommandHandler {
  return async (ctx): Promise<BorderExit> => runSandboxWith(ctx, injected);
}

export const runSandbox: CommandHandler = makeSandboxHandler();

async function runSandboxWith(ctx: Ctx, realIoOrInjected: Io): Promise<BorderExit> {
  const sub = ctx.positionals[0];
  const injectedIo = realIoOrInjected;
  if (sub === "init" || sub === "pin") {
    const image = ctx.flags.image;
    if (image === undefined) return ctx.stderr("border: sandbox init/pin needs --image <name@sha256:<64hex>>"), EXIT_ERROR;
    const lanes = lanesFromFlag(ctx);
    if (lanes === undefined) return ctx.stderr("border: sandbox init/pin needs --lane <npm|pypi|crates|rubygems[,...]>"), EXIT_ERROR;
    return writeLaneImages(ctx, new Map(lanes.map((l) => [l, image])), injectedIo);
  }
  if (sub === "unpin") {
    const { io, err, out } = sandboxIo(ctx, injectedIo);
    const store = resolveStore(ctx, io);
    if (typeof store === "string") return err(store), EXIT_ERROR;
    if (!io.exists(store.path)) return out("border: no machine-store file for this remote — nothing pinned"), EXIT_PASS;
    const doc = loadFragment(io, store.path, io.remotes(ctx.cwd));
    const targets = (doc.targets ?? {}) as Record<string, unknown>;
    const lanes = lanesFromFlag(ctx) ?? [...SANDBOX_LANES];
    let removed = 0;
    for (const lane of lanes) {
      const t = targets[lane];
      if (typeof t === "object" && t !== null && "sandboxImage" in t) {
        delete (t as Record<string, unknown>).sandboxImage;
        removed += 1;
      }
    }
    io.writeAtomic0600(store.path, stringify(doc));
    out(`border: removed ${String(removed)} sandboxImage entr${removed === 1 ? "y" : "ies"} from ${store.path}`);
    return EXIT_PASS;
  }
  if (sub === "status") {
    const { io, out } = sandboxIo(ctx, injectedIo);
    const store = resolveStore(ctx, io);
    if (typeof store === "string") return out(`border: ${store}`), EXIT_PASS;
    out(`border: machine store for this remote: ${store.path} (${io.exists(store.path) ? "present" : "absent"})`);
    if (io.exists(store.path)) {
      out(`border: store file qualification: ${io.qualifyFile(store.path) ? "OK (0600 under qualified chain)" : "FAILS §3 — border will refuse to honor sandbox keys from it"}`);
    }
    try {
      const load = loadConfig({ cwd: ctx.cwd, env: ctx.env as Record<string, string | undefined>, ...(ctx.flags.config !== undefined ? { configPath: ctx.flags.config } : {}) });
      if (load.kind !== "no-op") {
        const sec = load.security;
        for (const lane of SANDBOX_LANES) {
          out(`border: sandbox[${lane}] = ${sec.sandbox[lane] ?? "(none — host builds, consent still required)"}`);
        }
        out(`border: allowBuilds (machine-side consent) = ${String(sec.allowBuilds)}`);
      }
    } catch (err) {
      out(`border: config resolution REFUSED: ${err instanceof Error ? err.message : String(err)}`);
    }
    return EXIT_PASS;
  }
  ctx.stderr("border: usage: border sandbox init|pin --lane <lanes> --image <name@sha256:...> | unpin [--lane ...] | status");
  return EXIT_ERROR;
};
