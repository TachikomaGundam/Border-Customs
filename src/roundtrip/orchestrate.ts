// provenance: border-inspect-roadmap.md W2.1 — `border roundtrip` orchestrator.
//
// Pipeline per run (spike-proven mechanics, ROUNDTRIP-SPIKE.md §2/§4):
//   docker run -d pinned-image sleep 900 → docker cp of the REAL registry
//   artifact bytes (W1 fetch layer, never a registry call from inside the
//   container) → manifest m1 → install → m2 → uninstall → m3 → classify
//   m1-vs-m3. The m1→m2 install delta MUST be non-empty: an install that
//   touched nothing proves nothing, and a verdict minted on it would be the
//   hr vacuous-pass trap wearing a fresh coat (plan: cannot-verify ⇒ exit 2).
//   ANY pipeline failure — spawn, exec status, timeout — propagates typed and
//   the CLI maps it to exit 2; this command NEVER prints clean on top of a
//   broken leg. The container is removed in a finally block on every path,
//   with the sleep-TTL as the daemon-side backstop.
//
// Egress posture: only the host fetches registries (metadata + tarball, the
// exact W1 fetchArtifact surface). The container installs from a local file;
// package DEPENDENCIES of a real-world artifact may still pull from the
// registry inside the container (default bridge network, same as the spike) —
// documented decision, README ships in W2.2.
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { EXIT_ERROR, exitCodeFromVerdict, UnknownArgError, type BorderExit } from "../cli/exit.ts";
import type { Ctx } from "../cli/types.ts";
import { loadConfig } from "../config.ts";
import { resolveRepoDir } from "../check/context.ts";
import { computeCheckRulesHash, computeConfigDigest, type LoadedConfig } from "../check/rulesHash.ts";
import { probeEngines } from "../engines/policy.ts";
import { EngineRunError, type EngineOptions } from "../engines/support.ts";
import { appendRecord, buildRoundtripRecord } from "../ledger/records.ts";
import { computeVerdict, countFindings, type Finding, type Report } from "../findings.ts";
import { TextSanitizer } from "../redact.ts";
import { renderReportJson } from "../report.ts";
import { defaultScanFetcher, fetchArtifact, sha256Hex, type ScanFetcher } from "../scan/fetch.ts";
import { parseScanSpec, SCAN_SPEC_USAGE, type ScanEcosystem, type ScanSpec } from "../scan/spec.ts";
import {
  BASE_EXCLUDES,
  CARGO_EXCLUDES,
  CONTAINER_TTL_SEC,
  DOCKER_CP_TIMEOUT_MS,
  DOCKER_PROBE_TIMEOUT_MS,
  DOCKER_RM_TIMEOUT_MS,
  DOCKER_RUN_TIMEOUT_MS,
  PHASE_TIMEOUT_MS,
  SNAPSHOT_TIMEOUT_MS,
  PYTHON_EXCLUDES,
  realDockerExec,
  snapshotScript,
  type DockerExec,
  type ExecResult,
} from "./docker.ts";
import { classifyResidue, diffManifests, parseManifest } from "./manifest.ts";

export type { DockerExec, ExecResult } from "./docker.ts";

/** rt-<sha8 of label>-<rand6>: collision-free concurrent runs, greppable for cleanup. */
export function containerNameFor(label: string, rand: string = randomBytes(3).toString("hex")): string {
  return `rt-${sha256Hex(label).slice(0, 8)}-${rand}`;
}

/** One pinned image + command pair set per ecosystem (spike script set, generalized). */
export type EcoProfile = {
  readonly image: string;
  readonly artifactPath: string;
  readonly excludes: readonly string[];
  install(artifactPath: string, spec: ScanSpec): readonly string[];
  uninstall(spec: ScanSpec): readonly string[];
};

// The artifact always lands on a fixed in-container path (never the registry's
// filename), so profiles stay static arrays and hostile names cannot escape
// /root/. sh -c is used ONLY where the leg is a compound command (crates).
const shArgv = (name: string): string[] => {
  if (!/^[A-Za-z0-9@._+/-]+$/.test(name)) {
    throw new EngineRunError(`roundtrip: package name '${name}' rejected for shell composition`, null);
  }
  return [name];
};

const PROFILES: Record<ScanEcosystem, EcoProfile> = {
  npm: {
    image: "node:24-slim",
    artifactPath: "/root/p.tgz",
    excludes: BASE_EXCLUDES,
    install: (p) => ["npm", "install", "-g", "--foreground-scripts", "--no-audit", "--no-fund", p],
    uninstall: (s) => ["npm", "uninstall", "-g", shArgv(s.name)[0] as string],
  },
  pypi: {
    image: "python:3.12-slim",
    artifactPath: "/root/p.tar.gz",
    excludes: [...BASE_EXCLUDES, ...PYTHON_EXCLUDES],
    install: (p) => ["pip", "install", "--no-input", "--root-user-action=ignore", p],
    uninstall: (s) => ["pip", "uninstall", "-y", shArgv(s.name)[0] as string],
  },
  rubygems: {
    image: "ruby:3.4-slim",
    artifactPath: "/root/p.gem",
    excludes: BASE_EXCLUDES,
    install: (p) => ["gem", "install", "--no-document", p],
    uninstall: (s) => ["gem", "uninstall", shArgv(s.name)[0] as string, "-x", "--force"],
  },
  crates: {
    image: "rust:1-slim",
    artifactPath: "/root/p.crate",
    excludes: [...BASE_EXCLUDES, ...CARGO_EXCLUDES],
    // W2.1 docker legs, verified on rust:1-slim / cargo 1.98: a bare positional
    // is parsed as a CRATE@VER spec (a directory 400s on "invalid character `/`"),
    // so the unpacked staging dir goes through --path; --no-track must NOT be
    // used because it suppresses the $ROOT/.crates2.json install record, which is
    // the only thing `cargo uninstall` reads (with it, every uninstall dies on
    // "package ID specification did not match"); and border's own /opt/<dir>
    // staging tree is never owned by cargo, so the chain that creates it removes
    // it — after `cargo install` succeeded, keeping install failure fail-closed.
    install: (p, s) => {
      const name = shArgv(s.name)[0] as string;
      const dir = `${name}-${s.version}`;
      return ["sh", "-c", `tar xf ${p} -C /opt && cargo install --root /usr/local --path "/opt/${dir}" && rm -rf "/opt/${dir}"`];
    },
    uninstall: (s) => ["cargo", "uninstall", "--root", "/usr/local", shArgv(s.name)[0] as string],
  },
};

export function profileFor(eco: ScanEcosystem): EcoProfile {
  return PROFILES[eco];
}

export type RoundtripDeps = {
  readonly fetcher?: ScanFetcher;
  readonly exec?: DockerExec;
};

function execChecked(
  exec: DockerExec,
  args: readonly string[],
  timeoutMs: number,
  what: string,
): ExecResult {
  const r = exec(args, timeoutMs);
  if (r.status !== 0) {
    const tail = r.stderr.replace(/\s+/g, " ").slice(-240);
    throw new EngineRunError(`roundtrip: ${what} failed (exit ${String(r.status)})${tail ? `: ${tail}` : ""} — cannot verify (fail-closed)`, r.status);
  }
  return r;
}

type PipelineResult = { readonly findings: Finding[]; readonly installDelta: number; readonly baselineDigest: string };

function runPipeline(
  exec: DockerExec,
  profile: EcoProfile,
  spec: ScanSpec,
  label: string,
  hostPath: string,
  container: string,
): PipelineResult {
  execChecked(exec, ["run", "-d", "--name", container, profile.image, "sleep", String(CONTAINER_TTL_SEC)], DOCKER_RUN_TIMEOUT_MS, "container start");
  try {
    execChecked(exec, ["cp", hostPath, `${container}:${profile.artifactPath}`], DOCKER_CP_TIMEOUT_MS, "artifact copy");
    const m1 = parseManifest(takeSnapshot(exec, container, profile.excludes));
    execChecked(exec, ["exec", container, ...profile.install(profile.artifactPath, spec)], PHASE_TIMEOUT_MS, `install ${label}`);
    const m2 = parseManifest(takeSnapshot(exec, container, profile.excludes));
    const installDiff = diffManifests(m1, m2);
    const installDelta = installDiff.added.length + installDiff.removed.length + installDiff.modified.length;
    // Vacuous-pass guard: an install that touched nothing proves nothing.
    if (installDelta === 0) {
      throw new EngineRunError(
        `roundtrip: install of ${label} produced an empty filesystem delta — cannot verify it ran, refusing to grade a no-op`,
        null,
      );
    }
    execChecked(exec, ["exec", container, ...profile.uninstall(spec)], PHASE_TIMEOUT_MS, `uninstall ${label}`);
    const m3 = parseManifest(takeSnapshot(exec, container, profile.excludes));
    return {
      findings: classifyResidue(label, diffManifests(m1, m3)),
      installDelta,
      baselineDigest: sha256Hex([...m1.keys()].join("\n")),
    };
  } finally {
    // Trap-cleanup on EVERY path; a failed rm still dies with the sleep-TTL.
    try {
      exec(["rm", "-f", container], DOCKER_RM_TIMEOUT_MS);
    } catch {
      /* daemon unreachable mid-cleanup: the 900s TTL is the backstop */
    }
  }
}

function takeSnapshot(exec: DockerExec, container: string, excludes: readonly string[]): string {
  return execChecked(
    exec,
    ["exec", container, "sh", "-c", snapshotScript(excludes)],
    SNAPSHOT_TIMEOUT_MS,
    "manifest snapshot",
  ).stdout;
}

export async function runRoundtripCore(ctx: Ctx, deps: RoundtripDeps = {}): Promise<BorderExit> {
  const raw = ctx.positionals[0];
  if (ctx.positionals.length !== 1 || raw === undefined) {
    throw new UnknownArgError(
      `border roundtrip expects exactly one <spec> argument (got ${String(ctx.positionals.length)}); ${SCAN_SPEC_USAGE}`,
    );
  }
  const spec = parseScanSpec(raw);
  const profile = profileFor(spec.ecosystem);
  const label = `${spec.ecosystem}:${spec.name}@${spec.version}`;

  const exec = deps.exec ?? realDockerExec();
  if (!dockerAvailableGuard(exec)) {
    ctx.stderr("roundtrip: docker unavailable — cannot verify");
    return EXIT_ERROR;
  }

  const baseDir = mkdtempSync(join(tmpdir(), "border-roundtrip-"));
  try {
    const { bytes } = await fetchArtifact(spec, { fetcher: deps.fetcher ?? defaultScanFetcher });
    const hostPath = join(baseDir, "artifact");
    writeFileSync(hostPath, bytes);

    const container = containerNameFor(label);
    const { findings, installDelta, baselineDigest } = runPipeline(exec, profile, spec, label, hostPath, container);

    const verdict = computeVerdict(findings);
    const report: Report = {
      schemaVersion: 1,
      key: sha256Hex(`roundtrip:${label}:${baselineDigest}:${verdict}`),
      head: baselineDigest.slice(0, 40),
      dirty: false,
      exposureSet: [label],
      refSet: [],
      rulesHash: sha256Hex(`${profile.image}|${profile.install(profile.artifactPath, spec).join(" ")}|${profile.uninstall(spec).join(" ")}`),
      verdict,
      counts: countFindings(findings),
      findings,
      ts: new Date().toISOString(),
    };

    const sanitizer = new TextSanitizer();
    const line = (text: string): string => sanitizer.sanitize(text).replace(/\s+/g, " ").trim();
    if (ctx.flags.json) {
      ctx.stdout(renderReportJson(report));
    } else {
      for (const f of report.findings) {
        ctx.stdout(line(`  ${f.severity} ${f.rule} [${f.engine}] ${f.path ?? f.target} ${f.message}`));
      }
      ctx.stdout(line(`roundtrip: ${String(report.findings.length)} residue row(s); install-delta ${String(installDelta)} files`));
    }
    // Default-ON proof leg (W2.2): the roundtrip VERDICT decides the exit code;
    // the ledger RECORD is the portable fact `border check` consumes under
    // residue.requireProof. Both outcomes are recorded — clean and residue
    // alike; the existence of the fact, not its content, is the proof.
    if (ctx.flags.record !== false) {
      await recordRoundtripProof(ctx, sha256Hex(bytes), report.findings.length, report.findings.length === 0 ? "clean" : "residue");
    }
    return exitCodeFromVerdict(verdict);
  } finally {
    rmSync(baseDir, { recursive: true, force: true });
  }
}

// Fail-closed-by-absence, writer side: any problem minting the proof (no
// config, not a repo, probe degraded, disk error) degrades to a stderr notice
// and NO record — the valve then blocks on absence rather than trusting a
// half-minted one. Never changes the roundtrip exit code.
async function recordRoundtripProof(ctx: Ctx, artifactSha256: string, rows: number, verdict: "clean" | "residue"): Promise<void> {
  const notice = (msg: string): void => ctx.stderr(`roundtrip: ${msg}`);
  try {
    const env: EngineOptions["env"] = ctx.env;
    const load = loadConfig({
      cwd: ctx.cwd,
      ...(ctx.flags.config !== undefined ? { configPath: ctx.flags.config } : {}),
      ...(env !== undefined ? { env } : {}),
    });
    let effective: LoadedConfig | null = null;
    if (load.kind === "loaded") effective = load;
    else if (load.explicit !== undefined) effective = { kind: "loaded", config: load.explicit.config, warnings: [], source: load.explicit.source };
    if (effective === null) {
      notice("no border.yaml here — proof NOT recorded");
      return;
    }
    const repoDir = resolveRepoDir(ctx.cwd, { ...(env !== undefined ? { env } : {}) });
    const probe = await probeEngines(effective.config, { ...(env !== undefined ? { env } : {}) });
    if (probe.degraded) {
      notice("engine probe degraded — cannot mint the rulesHash this proof must match; proof NOT recorded");
      return;
    }
    const rulesHash = await computeCheckRulesHash({
      engineVersions: probe.engineVersions,
      configDigest: computeConfigDigest(effective),
      ...(env !== undefined ? { env } : {}),
    });
    appendRecord(repoDir, buildRoundtripRecord({ artifactSha256, verdict, rulesHash, rows }));
    notice(`proof recorded for ${artifactSha256.slice(0, 12)}… (verdict ${verdict}, ${String(rows)} residue row(s))`);
  } catch (err) {
    notice(`proof NOT recorded (${err instanceof Error ? err.message : String(err)}) — 'border check' with residue.requireProof will treat this artifact as unproven`);
  }
}

// Probe is deliberately catch-all: `docker --version` hanging or erroring is
// the same operator fact as the binary being gone — roundtrip cannot verify.
function dockerAvailableGuard(exec: DockerExec): boolean {
  try {
    return exec(["--version"], DOCKER_PROBE_TIMEOUT_MS).status === 0;
  } catch {
    return false;
  }
}
