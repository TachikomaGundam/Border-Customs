// Engine presence guards for border's real-engine acceptance tests.
// Contract (border-push-gate plan todo 1): a missing external engine must
// FAIL the test loudly — never a silent skip — so stubs can never satisfy a
// real-engine AC. Each guard probes PATH first, then the ~/.local/bin
// fallback provisioned in todo 1 (PATH may not carry it in every runner).
import { spawnSync } from "node:child_process";
import { homedir } from "node:os";
import { join } from "node:path";

export class EngineMissingError extends Error {
  override readonly name = "EngineMissingError";
}

interface EngineProbe {
  readonly label: string;
  readonly command: string;
  readonly args: readonly string[];
  readonly fallbackPath?: string;
  readonly versionHint: RegExp;
  readonly provisioning: string;
}

function isEnoent(error: unknown): boolean {
  return (
    error instanceof Error &&
    "code" in error &&
    (error as NodeJS.ErrnoException).code === "ENOENT"
  );
}

function probe(engine: EngineProbe): string {
  const attempts: (readonly string[])[] = [[engine.command, ...engine.args]];
  if (engine.fallbackPath !== undefined) {
    attempts.push([engine.fallbackPath, ...engine.args.slice(1)]);
  }
  for (const attempt of attempts) {
    const [bin, ...rest] = attempt;
    if (bin === undefined) {
      continue;
    }
    const result = spawnSync(bin, [...rest], { encoding: "utf8" });
    if (result.error !== undefined && !isEnoent(result.error)) {
      throw new EngineMissingError(
        `ENGINE BROKEN: '${bin}' could not be executed: ${String(result.error)}`,
      );
    }
    if (result.error === undefined) {
      if (result.status !== 0) {
        throw new EngineMissingError(
          `ENGINE BROKEN: '${bin} ${rest.join(" ")}' exited ${String(result.status)}: ${result.stderr.trim()}`,
        );
      }
      const version = `${result.stdout}\n${result.stderr}`.trim();
      if (!engine.versionHint.test(version)) {
        throw new EngineMissingError(
          `ENGINE VERSION MISMATCH (${engine.label}): expected ${String(engine.versionHint)}, got: ${version}`,
        );
      }
      return version;
    }
  }
  throw new EngineMissingError(
    `ENGINE MISSING: ${engine.label} not found. border fails closed — tests must never skip a missing engine.\nProvision it per todo 1: ${engine.provisioning}`,
  );
}

export function requireGitleaks(): string {
  return probe({
    label: "gitleaks",
    command: "gitleaks",
    args: ["--version"],
    fallbackPath: join(homedir(), ".local", "bin", "gitleaks"),
    versionHint: /\b8\.30\.1\b/,
    provisioning:
      "download the gitleaks v8.30.1 linux_x64 release binary to ~/.local/bin/gitleaks and chmod +x",
  });
}

export function requirePythonBuild(): string {
  return probe({
    label: "python 'build' module",
    command: "python3",
    args: ["-m", "build", "--version"],
    versionHint: /\bbuild\b/,
    provisioning:
      "python3 -m pip install --user --break-system-packages build",
  });
}

export function requireTwine(): string {
  return probe({
    label: "python 'twine' module",
    command: "python3",
    args: ["-m", "twine", "--version"],
    versionHint: /\btwine version\b/,
    provisioning:
      "python3 -m pip install --user --break-system-packages twine",
  });
}
