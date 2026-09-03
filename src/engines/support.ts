// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 4
//
// Shared plumbing for external engine adapters: typed spawn-failure classes
// and a candidate-fallback spawner (PATH binary first, ~/.local/bin fallback
// the engines were provisioned into per todo 1). Library layer never calls
// process.exit — every failure is a typed error the CLI (todo 7) maps to
// exit 2 (EngineMissing / engine crash) or exit 1 (findings).
import { spawnSync } from "node:child_process";

/** Engine binary absent/unrunnable — border fails closed (todo 6 probeEngines consumes this). */
export class EngineMissingError extends Error {
  override readonly name = "EngineMissingError";
}

/** Engine ran but not with a translatable exit code / produced an unusable report. */
export class EngineRunError extends Error {
  override readonly name = "EngineRunError";
  readonly exitCode: number | null;

  constructor(message: string, exitCode: number | null) {
    super(message);
    this.exitCode = exitCode;
  }
}

export type EngineOptions = {
  /** Environment override (tests: PATH-stripped runs). Default: process.env. */
  env?: Readonly<Record<string, string | undefined>>;
  /** Exact binary path; when set, no PATH/HOME fallback candidates are tried. */
  binPath?: string;
  timeoutMs?: number;
  maxBufferBytes?: number;
};

export type SpawnOutcome = {
  status: number;
  stdout: string;
  stderr: string;
};

function isEnoent(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    (error as NodeJS.ErrnoException).code === "ENOENT"
  );
}

export function engineErrorFromSpawn(error: unknown, bin: string): Error {
  if (isEnoent(error)) {
    return new EngineMissingError(`engine binary '${bin}' not found; border fails closed — install it or pass binPath`);
  }
  return error instanceof Error ? error : new Error(String(error));
}

/**
 * Run `args` against the first candidate binary that exists. Every candidate
 * failing with ENOENT ⇒ EngineMissingError; any other spawn-level failure is
 * rethrown typed. Signal-killed children (incl. timeout) ⇒ EngineRunError.
 */
export function spawnEngine(
  candidates: readonly string[],
  args: readonly string[],
  opts: EngineOptions = {},
): SpawnOutcome {
  let lastError: unknown;
  for (const bin of candidates) {
    const r = spawnSync(bin, [...args], {
      encoding: "utf8",
      timeout: opts.timeoutMs ?? 300_000,
      maxBuffer: opts.maxBufferBytes ?? 32 * 1024 * 1024,
      ...(opts.env !== undefined ? { env: { ...opts.env } } : {}),
    });
    if (r.error !== undefined) {
      if (isEnoent(r.error)) {
        lastError = r.error;
        continue;
      }
      throw engineErrorFromSpawn(r.error, bin);
    }
    if (r.status === null) {
      throw new EngineRunError(
        `${bin} was killed by signal ${String(r.signal)} (timeout?)`,
        null,
      );
    }
    return { status: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
  }
  throw engineErrorFromSpawn(lastError ?? new Error("no candidate binaries"), candidates[0] ?? "engine");
}

/** Binary candidates: explicit binPath, else PATH, else ~/.local/bin (todo 1 provisioning). */
export function binaryCandidates(binName: string, opts: EngineOptions): string[] {
  if (opts.binPath !== undefined) return [opts.binPath];
  const home = (opts.env ?? process.env).HOME;
  return home === undefined || home === ""
    ? [binName]
    : [binName, `${home}/.local/bin/${binName}`];
}

/** Copy of `env` with every variable whose name starts with `GITLEAKS_` removed. */
export function stripEngineEnv(env: Readonly<Record<string, string | undefined>>): Record<string, string | undefined> {
  const out: Record<string, string | undefined> = {};
  for (const [name, value] of Object.entries(env)) {
    if (!name.startsWith("GITLEAKS_")) out[name] = value;
  }
  return out;
}
