// provenance: sibyl ruling 2026-10-23 (run sibyl-20261023T112953Z-7ada) wave W4 —
// OS-level containment for registry artifact builds of operator-consented repos.
//
// What this is: every build that consumes repo input (npm pack, python -m build,
// gem build, cargo package — check stages AND freshness re-packs) can run inside
// `docker run` with the mechanical contract the ruling enumerated:
//   * image pinned by sha256 digest (config schema refuses anything else),
//   * --network none with an IN-CONTAINER probe (DNS + TCP) that fails the build
//     closed — a flag alone is a promise, the probe is the proof,
//   * repo mounted read-only, build runs on a tmpfs copy, artifacts come back
//     through one mounted out dir (also kills the live-tree TOCTOU race for the
//     bytes that get digested),
//   * container env = image defaults + the fixed pairs below; no host env rides
//     in (no ~/.npmrc, no *_TOKEN — the bind list IS the env),
//   * --cap-drop ALL + --security-opt no-new-privileges + --read-only rootfs.
// What this is NOT: a VM. Kernel CVE escapes stay in the residual-risk sentence
// in README/SECURITY — this module's docs must never promise unconditional
// isolation.
// Docker absence is a NAMED EngineMissingError (exit 2 with the remedy). There
// is deliberately no silent host fallback: "sandbox configured" means the
// operator asked for containment, and quietly building on the host anyway would
// re-admit exactly the class this wave closes.
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { z } from "zod";

import { EngineMissingError, EngineRunError } from "../engines/support.ts";
import type { DockerExec, ExecResult } from "../roundtrip/docker.ts";

/** Config gate for targets.<ch>.sandboxImage: digest pinning is mandatory. */
export const SANDBOX_IMAGE_RE = /@sha256:[0-9a-f]{64}$/;

export const sandboxImageSchema = z
  .string()
  .regex(
    SANDBOX_IMAGE_RE,
    "sandboxImage must be digest-pinned ('<name>@sha256:<64hex>') — a mutable tag would let check and freshness rebuild different bytes",
  );

/** Build-phase default budget; the npm/pypi/gem lanes measured minutes-scale host-side. */
export const SANDBOX_BUILD_TIMEOUT_MS = 600_000;
export const SANDBOX_PROBE_TIMEOUT_MS = 60_000;

export type SandboxSpec = {
  readonly image: string;
  readonly docker: DockerExec;
  readonly timeoutMs?: number;
};

let sandboxSeq = 0;

/**
 * The dash-safe in-container preamble: network proof, then the repo snapshot.
 * Probe legs run whenever the image ships their tool; zero legs = inconclusive
 * = exit 88 (never "assume --network none worked"). Reachability markers exit
 * 86 (DNS) / 87 (TCP) and surface as named EngineRunErrors host-side.
 */
export function sandboxPreamble(o: { npmMajorGuard: boolean }): string {
  const legs = [
    // DNS leg: with --network none resolution cannot reach any nameserver.
    `if command -v getent >/dev/null 2>&1; then`,
    `  if getent hosts registry.npmjs.org >/dev/null 2>&1; then echo BORDER-SANDBOX-DNS-REACHABLE >&2; exit 86; fi`,
    `  PROBE_LEGS=1`,
    `else PROBE_LEGS=0; fi`,
    // TCP legs, first available tool wins; 192.0.2.119 is TEST-NET-1 (RFC 5737),
    // unroutable by reservation, so a connect only succeeds through a live netns.
    `if command -v curl >/dev/null 2>&1; then PROBE_LEGS=1`,
    `  curl -sS -m 3 -o /dev/null http://192.0.2.119/ >/dev/null 2>&1 && { echo BORDER-SANDBOX-TCP-REACHABLE >&2; exit 87; }; :`,
    `elif command -v python3 >/dev/null 2>&1; then PROBE_LEGS=1`,
    `  python3 -c 'import socket,sys
try:
    s = socket.create_connection(("192.0.2.119", 443), timeout=3)
    s.close()
except Exception:
    sys.exit(0)
sys.exit(1)' && { echo BORDER-SANDBOX-TCP-REACHABLE >&2; exit 87; }; :`,
    `elif command -v node >/dev/null 2>&1; then PROBE_LEGS=1`,
    `  node -e 'const net=require("net");const s=net.connect({host:"192.0.2.119",port:443,timeout:3000},()=>{s.destroy();process.exit(1)});s.on("error",()=>process.exit(0));s.on("timeout",()=>{s.destroy();process.exit(0)})' && { echo BORDER-SANDBOX-TCP-REACHABLE >&2; exit 87; }; :`,
    `elif command -v ruby >/dev/null 2>&1; then PROBE_LEGS=1`,
    `  ruby -rsocket -e 'begin; TCPSocket.new("192.0.2.119", 443).close; exit 1; rescue StandardError; exit 0; end' && { echo BORDER-SANDBOX-TCP-REACHABLE >&2; exit 87; }; :`,
    `fi`,
    `if [ "$PROBE_LEGS" = 0 ]; then echo BORDER-SANDBOX-NO-PROBE-TOOL >&2; exit 88; fi`,
  ];
  const guard = o.npmMajorGuard
    ? [
        `NPM_MAJOR=$(npm --version 2>/dev/null | cut -d. -f1)`,
        `if [ -z "$NPM_MAJOR" ] || [ "$NPM_MAJOR" -lt 11 ]; then echo "BORDER-SANDBOX-NPM-OLD: npm $(npm --version 2>/dev/null || echo missing) executes pack-phase hooks; image needs npm >= 11 while the repo declares them" >&2; exit 85; fi`,
      ]
    : [];
  return [
    "set -eu",
    ...legs,
    ...guard,
    `mkdir -p /work/repo /audit/out`,
    `cp -a /audit/repo/. /work/repo/`,
    `cd /work/repo`,
  ].join("\n");
}

/** Pure argv builder — unit tests script docker through these exact tokens. */
export function sandboxDockerArgs(o: {
  spec: SandboxSpec;
  repoDir: string;
  outDir: string;
  script: string;
  cargoCacheHostDir?: string;
  runName?: string;
}): string[] {
  sandboxSeq += 1;
  const name = o.runName ?? `border-sbx-${String(process.pid)}-${String(sandboxSeq)}`;
  const args = [
    "run",
    "--rm",
    "--name",
    name,
    "--network",
    "none",
    "--cap-drop",
    "ALL",
    "--security-opt",
    "no-new-privileges",
    "--read-only",
    "--user",
    "0",
    "--tmpfs",
    "/tmp",
    "--tmpfs",
    "/work:exec",
    "--volume",
    `${o.repoDir}:/audit/repo:ro`,
    "--volume",
    `${o.outDir}:/audit/out`,
    "--env",
    "HOME=/tmp",
    "--env",
    "LANG=C.UTF-8",
  ];
  if (o.cargoCacheHostDir !== undefined) {
    args.push(
      "--volume",
      `${o.cargoCacheHostDir}:/audit/cache`,
      "--env",
      "CARGO_HOME=/audit/cache/cargo-home",
    );
  }
  args.push(o.spec.image, "sh", "-eu", "-c", o.script);
  return args;
}

/** Run one sandboxed build; every failure mode is a named error, never a pass. */
export function runSandboxedBuild(o: {
  spec: SandboxSpec;
  repoDir: string;
  outDir: string;
  laneScript: string;
  npmMajorGuard?: boolean;
  cargoCacheHostDir?: string;
}): ExecResult {
  const script = `${sandboxPreamble({ npmMajorGuard: o.npmMajorGuard === true })}\n${o.laneScript}`;
  let r: ExecResult;
  try {
    r = o.spec.docker(sandboxDockerArgs({ spec: o.spec, repoDir: o.repoDir, outDir: o.outDir, script, ...(o.cargoCacheHostDir !== undefined ? { cargoCacheHostDir: o.cargoCacheHostDir } : {}) }), o.spec.timeoutMs ?? SANDBOX_BUILD_TIMEOUT_MS);
  } catch (e) {
    if (e instanceof EngineMissingError) {
      throw new EngineMissingError(
        "targets.*.sandboxImage is configured but docker is not available — install docker, or remove sandboxImage to accept host builds; border fails closed",
      );
    }
    throw e;
  }
  const err = r.stderr.trim();
  if (r.status === 86) throw new EngineRunError(`sandbox network probe: DNS resolved inside the container — --network none is not in effect (${o.spec.image}) — failing closed`, r.status);
  if (r.status === 87) throw new EngineRunError(`sandbox network probe: TCP connect succeeded inside the container — --network none is not in effect (${o.spec.image}) — failing closed`, r.status);
  if (r.status === 88) throw new EngineRunError(`sandbox network probe: the image ships no probe tool (getent/curl/python3/node/ruby) — cannot prove the containment (${o.spec.image}); add one or drop sandboxImage — failing closed`, r.status);
  if (r.status === 85) throw new EngineRunError(err === "" ? "sandbox npm too old for pack-phase hooks (exit 85)" : err, r.status);
  if (r.status !== 0) {
    throw new EngineRunError(`sandboxed build failed (exit ${String(r.status)}) in ${o.spec.image}: ${(err === "" ? r.stdout.trim() : err).slice(0, 600)}`, r.status);
  }
  return r;
}

/** Observed toolchain versions inside the pinned image (record binding). A
 *  failed probe returns null — the record then simply carries no binding, and
 *  freshness parity against a bound record fails closed. */
export function sandboxToolchainVersions(spec: SandboxSpec, probesScript: string): string | null {
  try {
    const r = spec.docker(["run", "--rm", "--network", "none", "--entrypoint", "sh", spec.image, "-c", probesScript], SANDBOX_PROBE_TIMEOUT_MS);
    if (r.status !== 0) return null;
    return r.stdout.trim().slice(0, 400);
  } catch {
    return null;
  }
}

/** POSIX single-quote shell escaping for paths interpolated into lane scripts. */
export function shQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

/** Canonical join of the sandbox images the CURRENT config resolves for the
 *  needed channels — the parity string records and freshness compare on.
 *  Sorted unique, one per line; "" means "no sandbox in play" (host builds). */
export function sandboxBindingJoin(images: Iterable<string>): string {
  return [...new Set(images)].sort().join("\n");
}

export type SandboxRunResult = { readonly stdout: string; readonly toolchain: string };

/**
 * Run one lane end-to-end: toolchain probe + preamble + lane build, then read
 * the binding file back off the out mount. Missing toolchain.txt is a NAMED
 * fail-closed: the record would carry an unbound build environment.
 */
export function sandboxRun(o: {
  spec: SandboxSpec;
  repoDir: string;
  outDir: string;
  laneProbes: readonly string[];
  laneScript: string;
  npmMajorGuard?: boolean;
  cargoCacheHostDir?: string;
}): SandboxRunResult {
  const probe = o.laneProbes.map((p) => `{ printf '%s ' '${p}'; ${p} --version 2>&1 | head -n 1; }`).join("\n");
  const script = `${probe} > /audit/out/toolchain.txt\n${o.laneScript}`;
  const r = runSandboxedBuild({
    spec: o.spec,
    repoDir: o.repoDir,
    outDir: o.outDir,
    laneScript: script,
    ...(o.npmMajorGuard !== undefined ? { npmMajorGuard: o.npmMajorGuard } : {}),
    ...(o.cargoCacheHostDir !== undefined ? { cargoCacheHostDir: o.cargoCacheHostDir } : {}),
  });
  const binding = readToolchain(o.outDir, o.spec.image);
  return { stdout: r.stdout, toolchain: binding };
}

function readToolchain(outDir: string, image: string): string {
  let text: string;
  try {
    text = readFileSync(join(outDir, "toolchain.txt"), "utf8");
  } catch {
    throw new EngineRunError(`sandboxed build left no toolchain.txt in the out dir (${image}) — the image entrypoint shadowed /audit/out or the probe failed; failing closed`, null);
  }
  return text.trim().slice(0, 400);
}
