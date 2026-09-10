// provenance: border-inspect-roadmap.md W2.1 — docker lane plumbing.
//
// Every daemon touch goes through ONE injectable DockerExec seam (ScanFetcher
// doctrine): unit tests script docker argv, production spawns the real binary
// via engines/support.ts spawnEngine (timeout-killed children become
// EngineRunError — silence is never "clean"). The snapshot script reproduces
// the W2.0 spike mechanics (.omo/evidence/residue-spike/roundtrip-spike-lib.sh):
// find -xdev over '/' with a measured prune set, in-container sha256sum,
// /dev/shm scratch (a /tmp scratch dir would be scanned by the snapshot
// itself), LC_ALL=C sort for byte-stable manifests. No mtime/inode/mode:
// content and identity only, so overlayfs copy-up cannot pollute a diff.
import { binaryCandidates, spawnEngine } from "../engines/support.ts";

export type ExecResult = { readonly status: number; readonly stdout: string; readonly stderr: string };
export type DockerExec = (args: readonly string[], timeoutMs: number) => ExecResult;

export const DOCKER_PROBE_TIMEOUT_MS = 15_000;
export const DOCKER_RUN_TIMEOUT_MS = 120_000;
export const DOCKER_CP_TIMEOUT_MS = 120_000;
/** Spike measured 1-2s for a full-root manifest; 120s is the hard cap per manifest. */
export const SNAPSHOT_TIMEOUT_MS = 120_000;
/** Plan W2.1: install / uninstall legs get a 600s phase budget each. */
export const PHASE_TIMEOUT_MS = 600_000;
export const DOCKER_RM_TIMEOUT_MS = 60_000;
/** Container TTL backstop: a crashed orchestrator still cannot leak a runner. */
export const CONTAINER_TTL_SEC = 900;

// Spike §2/§4: exactly these paths produced noise on the npm docker lane;
// everything else (/tmp, /var/tmp, /etc, /usr/local, $HOME) stays observable.
export const BASE_EXCLUDES: readonly string[] = [
  "/proc",
  "/sys",
  "/dev",
  "/root/.npm",
  "/tmp/node-compile-cache",
  "/etc/hostname",
  "/etc/resolv.conf",
  "/etc/hosts",
];
// Spike §3 python lane: pip's wheel/http cache + apt/log bookkeeping are the
// pypi analogue of /root/.npm — hidden by design, never flagged as residue.
// "*/__pycache__" (find -path glob, matches across '/'): python:3.12-slim ships
// the stdlib without .pyc, so the FIRST pip run compiles ~470
// /usr/local/lib/python3.12/**/__pycache__/*.cpython-312.pyc files after m1 and
// no uninstall ever removes them — measured on the W2.1 six@1.17.0 docker leg,
// where they out-numbered real findings 235:1. Interpreter bookkeeping, same
// class as /tmp/node-compile-cache above.
export const PYTHON_EXCLUDES: readonly string[] = ["/root/.cache", "/var/log", "/var/lib/apt/lists", "*/__pycache__"];
// cargo's registry/cache + install-record tree is manager-internal on the crates
// lane. W2.1 docker legs: the rust image ships CARGO_HOME=/usr/local/cargo (not
// /root/.cargo — kept for PATH-independence) and cargo records installs in
// $ROOT/.crates2.json plus the legacy v1 $ROOT/.crates.toml, files cargo
// deliberately keeps (trimmed) after uninstall; all are the /root/.npm class —
// bookkeeping, never package residue.
export const CARGO_EXCLUDES: readonly string[] = ["/root/.cargo", "/usr/local/cargo", "/usr/local/.crates2.json", "/usr/local/.crates.toml"];

/**
 * POSIX-sh manifest script (dash-safe: the slim images ship no bash).
 * Row kinds: `F path sha` | `L path target` | `D path -`.
 */
export function snapshotScript(excludes: readonly string[]): string {
  // Parens quoted for dash: unquoted they are shell metacharacters, not find args.
  const prune = `"(" ${excludes.map((p) => `-path "${p}"`).join(" -o ")} ")" -prune -o`;
  return [
    "set -e",
    'T=/dev/shm/rt-snap.$$; mkdir -p "$T"',
    `find / -xdev ${prune} -type f -print0 > "$T/f0"`,
    // || true: a file can vanish between find passes (package managers churn
    // temp state); the missing row is consistent noise, not a false residue.
    `xargs -0 -r sha256sum < "$T/f0" 2>/dev/null > "$T/hashes" || true`,
    // sha256sum text mode = 64 hex + 2 spaces + path; substr keeps spaced paths whole.
    `awk '{ printf "F\\t%s\\t%s\\n", substr($0,67), substr($0,1,64) }' "$T/hashes" > "$T/files"`,
    `find / -xdev ${prune} -type l -printf 'L\\t%p\\t%l\\n' > "$T/links"`,
    `find / -xdev ${prune} -type d -printf 'D\\t%p\\t-\\n' > "$T/dirs"`,
    'LC_ALL=C sort "$T/files" "$T/links" "$T/dirs"',
    'rm -rf "$T"',
  ].join("\n");
}

/** Real docker via PATH (then ~/.local/bin), every leg hard-timed. */
export function realDockerExec(): DockerExec {
  return (args, timeoutMs) => {
    const r = spawnEngine(binaryCandidates("docker", {}), [...args], { timeoutMs });
    return { status: r.status, stdout: r.stdout, stderr: r.stderr };
  };
}

