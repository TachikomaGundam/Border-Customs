// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 17
//
// Same-bytes npm publish executor — AND the shared publish core the PyPI leg
// imports from here (src/push/pypi.ts). Plan contract, in force order:
//
//   1. GATE   the caller's fingerprint key (push.ts derives it once via
//             todo-15 derivePushState — this executor never re-probes engines)
//             must match a NON-DEGRADED PASSED check record in the ledger that
//             covers this target; anything else ⇒ exit 1 `run border check first`.
//   2. RE-HASH every CheckRecord.artifacts entry in this target's dist
//             convention (.tgz for npm; .whl/.tar.gz for pypi) must still hash
//             to its recorded sha256 at .border/dist/<file> — mismatch ⇒ exit 2
//             `artifact changed since check`, strictly BEFORE any network.
//   3. DRY-RUN prints the exact `npm publish <file.tgz> --registry <url?>`
//             command (space-joined argv, one line per recorded tarball) and
//             performs ZERO registry requests. --yes re-probes version-exists
//             immediately pre-publish (race safety; unreachable registry lets
//             runRegistryProbes throw EngineRunError ⇒ the CLI boundary exits 2,
//             fail-closed), hard-FAILs exit 1 on any blocking finding, then
//             executes via spawn stdio:'inherit' so interactive OTP/credential
//             prompts pass straight through — border never handles tokens (G28).
//   4. RECORD   success appends a t:"push" record through the todo-15 writer.
//
// MUST NOT (plan): no --access flag at all (the config schema carries no
// npm.access — the executor adds no opinionated flags beyond it), no dist-tag
// logic, no retry loop. Execution ORDER (git remotes → npm → PyPI) and the
// all-or-nothing pre-flight of EVERY remote before ANY publish belong to
// src/commands/push.ts (todo 16); it enforces the order by awaiting every
// git leg and the full derivePushState pre-flight before ever calling
// runNpmPublish, and awaits runNpmPublish before calling runPypiPublish —
// these executors are single-target by construction, so interleaving cannot
// happen inside them.
//
// Published-version immutability — verified against OFFICIAL docs 2026-09-04
// (round-2 G37 close-out; the PUBLISH_WARNING below paraphrases exactly this):
//   * npm Unpublish Policy — https://docs.npmjs.com/policies/unpublish/
//     "Registry data is immutable, meaning once published, a package cannot
//     change. [...] Once `package@version` has been used, you can never use it
//     again. You must publish a new version even if you unpublished the old
//     one." Unpublish itself is allowed only inside 72h (or under the
//     no-dependents/<300-downloads/single-owner criteria); a fully unpublished
//     name is re-publish-locked for 24h.
//   * PyPI Yanking — https://docs.pypi.org/project-management/yanking/
//     "PyPI currently only supports yanking of entire releases, not individual
//     files. PyPI supports yanking as a non-destructive alternative to
//     deletion." (Deletion windows differ from npm's: yank is the supported
//     post-hoc remedy, which is why the warning tells operators to check the
//     per-registry policy before burning a version number.)
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { basename, join } from "node:path";

import { BORDER_STATE_DIR } from "../check/lock.ts";
import { EXIT_BLOCKED, EXIT_ERROR, EXIT_PASS, type BorderExit } from "../cli/exit.ts";
import type { BorderConfig } from "../config.ts";
import { EngineRunError } from "../engines/support.ts";
import { isBlocking, type Finding } from "../findings.ts";
import { latestPassCoveringTargets, readLedger, type CheckRecord } from "../ledger.ts";
import { NPM_DEFAULT_REGISTRY, readNpmCoords, runRegistryProbes } from "../registry.ts";
import { recordPushSuccess } from "../pushstate.ts";

/** Immutability notice emitted BEFORE any irreversible publish spawn. */
export const PUBLISH_WARNING =
  "WARNING: published versions cannot be re-uploaded unchanged; deletion windows differ per registry — verify version bump policy";

export type LineWriter = (line: string) => void;

/** Shared publish context. `key` is the live fingerprint key — identical to
 *  derivePushState().key (both are computeFingerprint outputs), which is what
 *  makes the ledger gate in requirePassedRecord meaningful. */
export type PublishInput = {
  readonly repoDir: string;
  readonly cfg: BorderConfig;
  readonly key: string;
  /** false ⇒ dry-run (print, zero network); true ⇒ execute irreversibly. */
  readonly yes: boolean;
  /** Environment handed to probes and the publish spawn (stdio:inherit). */
  readonly env?: NodeJS.ProcessEnv;
  readonly out?: LineWriter;
  readonly err?: LineWriter;
  /** Probe timeout override; default REGISTRY_TIMEOUT_MS inside registry.ts. */
  readonly timeoutMs?: number;
};

export type NpmPublishInput = PublishInput & {
  /** Exact npm binary seam (tests / pinned toolchains); default "npm" on PATH. */
  readonly npmBinPath?: string;
};

export type PublishTarget = "npm" | "pypi";

const DIST_DIR = join(BORDER_STATE_DIR, "dist");

const defaultOut: LineWriter = (line) => void process.stdout.write(`${line}\n`);
const defaultErr: LineWriter = (line) => void process.stderr.write(`${line}\n`);

export function writers(i: PublishInput): { out: LineWriter; err: LineWriter } {
  return { out: i.out ?? defaultOut, err: i.err ?? defaultErr };
}

type Gate = { readonly ok: true; readonly record: CheckRecord } | { readonly ok: false; readonly exit: BorderExit; readonly message: string };

/** Step 1 — ledger gate. latestPassCoveringTargets enforces ALL of: newest
 *  record for the key (a later FAIL revokes an earlier PASS), verdict PASS,
 *  degraded=false (structurally impossible for ledgered records, asserted by
 *  the todo-14 parser), and effectiveTargets covering this kind. */
export function requirePassedRecord(kind: PublishTarget, i: PublishInput): Gate {
  const { records } = readLedger(i.repoDir);
  const record = latestPassCoveringTargets(records, i.key, [kind]);
  if (record === null) {
    return {
      ok: false,
      exit: EXIT_BLOCKED,
      message: `border publish '${kind}' blocked: no non-degraded PASSED check record matches the current fingerprint key — run border check first`,
    };
  }
  return { ok: true, record };
}

type Rehash = { readonly ok: true; readonly files: readonly string[] } | { readonly ok: false; readonly message: string };

/** Step 2 — same-bytes proof (G38): re-hash every recorded artifact of this
 *  target's dist convention against .border/dist. An empty convention match
 *  fails closed too: nothing recorded ⇒ nothing provably unchanged. */
export function rehashRecordedArtifacts(kind: PublishTarget, record: CheckRecord, repoDir: string): Rehash {
  const conventions: readonly string[] = kind === "npm" ? [".tgz"] : [".whl", ".tar.gz"];
  const entries = (record.artifacts ?? []).filter((a) => conventions.some((ext) => a.file.endsWith(ext)));
  const fail = (detail: string): Rehash => ({ ok: false, message: `artifact changed since check — ${detail}` });
  if (entries.length === 0) {
    return fail(`the PASSED check recorded no ${kind} artifacts (${conventions.join("/")}) to re-verify`);
  }
  const files: string[] = [];
  for (const a of entries) {
    const rel = join(DIST_DIR, basename(a.file));
    const abs = join(repoDir, rel);
    if (!existsSync(abs)) return fail(`${rel} is missing from the working tree`);
    const digest = createHash("sha256").update(readFileSync(abs)).digest("hex");
    if (digest !== a.sha256) return fail(`${rel} no longer hashes to the digest recorded by the check`);
    files.push(rel);
  }
  return { ok: true, files: files.sort() };
}

/** Step 3 precondition — immediate pre-publish re-probe (race safety).
 *  EngineRunError from an unreachable registry PROPAGATES: the gate cannot be
 *  bypassed by a dead registry (the CLI maps it to exit 2, fail-closed). */
export async function blockingProbeFindings(i: PublishInput, kind: PublishTarget): Promise<readonly Finding[]> {
  const findings = await runRegistryProbes({
    repoDir: i.repoDir,
    cfg: i.cfg,
    effectiveTargets: [kind],
    ...(i.env === undefined ? {} : { env: i.env }),
    ...(i.timeoutMs === undefined ? {} : { timeoutMs: i.timeoutMs }),
  });
  return findings.filter((f) => isBlocking(f.severity));
}

/** stdio:'inherit' spawn — interactive OTP/credential prompts reach the
 *  operator untouched; border sees only the exit code (G28 by construction). */
export function spawnInherit(bin: string, args: readonly string[], cwd: string, env?: NodeJS.ProcessEnv): Promise<number> {
  return new Promise<number>((resolveP, rejectP) => {
    const child = spawn(bin, [...args], { cwd, stdio: "inherit", ...(env === undefined ? {} : { env }) });
    child.on("error", (err) => rejectP(new EngineRunError(`failed to spawn ${bin}: ${String(err)}`, null)));
    child.on("close", (code) => resolveP(code ?? -1));
  });
}

function npmArgv(file: string, registry: string | undefined): readonly string[] {
  // Exactly `npm publish <file.tgz> --registry <url?>` — --registry only when
  // configured; NO --access, NO --tag, nothing else (plan MUST NOT list).
  return ["publish", file, ...(registry === undefined ? [] : ["--registry", registry])];
}

/**
 * npm leg entry point (todo 16 orchestrates; see file header for the
 * gate → re-hash → probe → warn → spawn → record pipeline and dry-run
 * semantics: dry-run prints the exact command with ZERO registry hits).
 */
export async function runNpmPublish(i: NpmPublishInput): Promise<BorderExit> {
  const { out, err } = writers(i);
  const gate = requirePassedRecord("npm", i);
  if (!gate.ok) {
    err(gate.message);
    return gate.exit;
  }
  const rehash = rehashRecordedArtifacts("npm", gate.record, i.repoDir);
  if (!rehash.ok) {
    err(rehash.message);
    return EXIT_ERROR;
  }
  const registry = i.cfg.targets.npm?.registry;
  if (!i.yes) {
    for (const f of rehash.files) out(`npm ${npmArgv(f, registry).join(" ")}`);
    return EXIT_PASS;
  }
  const blockers = await blockingProbeFindings(i, "npm");
  if (blockers.length > 0) {
    for (const f of blockers) err(`${f.rule}: ${f.message}`);
    return EXIT_BLOCKED;
  }
  out(PUBLISH_WARNING);
  const bin = i.npmBinPath ?? "npm";
  for (const f of rehash.files) {
    const code = await spawnInherit(bin, npmArgv(f, registry), i.repoDir, i.env);
    if (code !== 0) {
      err(`npm publish failed for ${f} (exit ${String(code)}) — no retry loop; inspect the registry state before running again`);
      return EXIT_BLOCKED;
    }
  }
  const coords = readNpmCoords(i.repoDir, i.cfg, i.env);
  recordPushSuccess(i.repoDir, {
    key: i.key,
    target: "npm",
    remoteName: "npm",
    url: registry ?? NPM_DEFAULT_REGISTRY,
    localSha: gate.record.head,
    version: `${coords.name}@${coords.version}`,
    confirmedVia: "npm-view",
  });
  out(`published ${coords.name}@${coords.version}; push-record appended`);
  return EXIT_PASS;
}
