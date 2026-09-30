// provenance: .omo/plans/border-opencode-inspect.md T1/T2 — aspect 3: identity-handshake.
//
// Mirror of plugin/border.ts's binary resolution + identity handshake, kept
// byte-honest by test/opencode.inspect.test.ts (T2 mirror pin): the candidate
// order (BORDER_BIN wins alone -> packaged dist shebang exec -> packaged dist
// under PATH node -> border on PATH), the 20 s probe cap, and the decision
// (exit 0, first line starts with `border`, stdout contains `usage: border`).
// The runner is an injected seam (M2): unit tests script the handshake
// without ever spawning the impostor shapes they describe.
// Honest boundary (same as 0.5.1): this catches mistaken identity, not a
// forged banner.
import { execFile } from "node:child_process";
import { existsSync } from "node:fs";

import type { AspectResult, Env, InspectRunner, SpawnOutcome, SpawnTarget } from "../contract.ts";

export const HANDSHAKE_ARGV: readonly string[] = ["--help"];
export const HANDSHAKE_BANNER_PREFIX = "border";
export const HANDSHAKE_USAGE_NEEDLE = "usage: border";
/** Identity-handshake cap — a `--help` needing longer than this is not a border CLI (plugin PROBE_TIMEOUT_MS). */
export const HANDSHAKE_TIMEOUT_MS = 20_000;
/** Per-stream cap fed back from the probe (plugin MAX_OUTPUT_BYTES parity). */
const MAX_OUTPUT_BYTES = 64 * 1024;

/** Spawn-and-run default for the runner seam; never rejects (null status = unspawnable). */
export const defaultInspectRunner: InspectRunner = (target, argv) =>
  new Promise<SpawnOutcome>((resolve) => {
    execFile(
      target.bin,
      [...target.prefix, ...argv],
      { timeout: HANDSHAKE_TIMEOUT_MS, maxBuffer: MAX_OUTPUT_BYTES, shell: false },
      (error, stdout, stderr) => {
        const out = stdout.slice(0, MAX_OUTPUT_BYTES);
        const err = stderr.slice(0, MAX_OUTPUT_BYTES);
        if (error === null) {
          resolve({ status: 0, stdout: out, stderr: err });
          return;
        }
        const failure = error as Error & { code?: string | number | null; killed?: boolean; signal?: string | null };
        if (failure.code === "ENOENT" || failure.code === "EACCES" || failure.code === "ENOEXEC") {
          resolve({ status: null, stdout: out, stderr: err });
          return;
        }
        const status = typeof failure.code === "number" ? failure.code : failure.killed === true || failure.signal != null ? 124 : -1;
        resolve({ status, stdout: out, stderr: err });
      },
    );
  });

/** The border --help contract check — the decision plugin/border.ts's isBorderHelp applies. */
export function passesHandshake(outcome: SpawnOutcome): boolean {
  if (outcome.status !== 0) return false;
  const firstLine = (outcome.stdout.match(/^\s*(.*)/) ?? ["", ""])[1] ?? "";
  return firstLine.startsWith(HANDSHAKE_BANNER_PREFIX) && outcome.stdout.includes(HANDSHAKE_USAGE_NEEDLE);
}

/** Candidate order mirrored verbatim from plugin/border.ts candidateList(). */
export function identityCandidates(env: Env, distEntry: string): readonly SpawnTarget[] {
  const configured = env["BORDER_BIN"];
  if (configured !== undefined && configured.length > 0) {
    return [{ bin: configured, prefix: [], label: `BORDER_BIN=${configured}` }];
  }
  const candidates: SpawnTarget[] = [];
  if (existsSync(distEntry)) {
    candidates.push({ bin: distEntry, prefix: [], label: "packaged dist/index.js (shebang exec)" });
    candidates.push({ bin: "node", prefix: [distEntry], label: "packaged dist/index.js under PATH node" });
  }
  candidates.push({ bin: "border", prefix: [], label: "border on PATH" });
  return candidates;
}

export type IdentityDeps = {
  readonly runner?: InspectRunner;
  readonly distEntry: string;
  readonly env: Env;
};

export async function verifyIdentity(deps: IdentityDeps): Promise<AspectResult> {
  const id = "identity-handshake" as const;
  const runner = deps.runner ?? defaultInspectRunner;
  const candidates = identityCandidates(deps.env, deps.distEntry);
  const reasons: string[] = [];
  let anySpawned = false;
  for (const candidate of candidates) {
    const probe = await runner(candidate, HANDSHAKE_ARGV);
    if (passesHandshake(probe)) {
      return { id, verdict: "PASS", detail: `${candidate.label} passed the identity handshake` };
    }
    if (probe.status !== null) {
      anySpawned = true;
      reasons.push(`${candidate.label}: spawned but --help did not answer as border (impostor?)`);
    } else {
      reasons.push(`${candidate.label}: unspawnable (ENOENT/EACCES/ENOEXEC)`);
    }
  }
  if (anySpawned) {
    return { id, verdict: "FAIL", detail: `a border binary was reachable but failed the identity handshake — impersonation shape: ${reasons.join("; ")}` };
  }
  return { id, verdict: "CANNOT", detail: `no border binary reachable — tried: ${reasons.join("; ")}` };
}
