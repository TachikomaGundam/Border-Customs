// provenance: original clean-room implementation per .omo/plans/border-push-gate.md todo 17,
//   extended per .omo/plans/border-push-channels.md todo C2 (shared publish core)
//
// Same-bytes publish core — the git/npm/pypi legs' shared pipeline, extracted
// from src/push/npm.ts (C2) and parameterized by channel descriptor:
// what differs between platforms (artifactExtensions, argv source, binary
// seams, record fields) arrives via PublishCoreHooks, never via a switch on
// kind. Plan contract, in force order:
//
//   1. GATE   the caller's fingerprint key (push.ts derives it once via
//             todo-15 derivePushState — this executor never re-probes engines)
//             must match a NON-DEGRADED PASSED check record in the ledger that
//             covers this target; anything else ⇒ exit 1 `run border check first`.
//   2. RE-HASH every CheckRecord.artifacts entry in this target's dist
//             convention (.tgz for npm; .whl/.tar.gz for pypi) must still hash
//             to its recorded sha256 at .border/dist/<file> — mismatch ⇒ exit 2
//             `artifact changed since check`, strictly BEFORE any network.
//   3. DRY-RUN prints the exact publish command (space-joined argv, one line
//             per argv row from the channel's publishArgv) and performs ZERO
//             registry requests. --yes re-probes version-exists immediately
//             pre-publish (race safety; unreachable registry lets
//             runRegistryProbes throw EngineRunError ⇒ the CLI boundary exits 2,
//             fail-closed), hard-FAILs exit 1 on any blocking finding, then
//             executes via spawn stdio:'inherit' so interactive OTP/credential
//             prompts pass straight through — border never handles tokens (G28).
//   4. RECORD   success appends a t:"push" record through the todo-15 writer.
//
// MUST NOT (plan): no --access flag at all, no dist-tag logic, no retry loop.
// Execution ORDER (git remotes → npm → PyPI) and the all-or-nothing pre-flight
// of EVERY remote before ANY publish belong to src/commands/push.ts (todo 16);
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
import { runRegistryProbes } from "../registry.ts";
import type { PublishChannelId } from "../channels/registry.ts";

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
export function requirePassedRecord(kind: PublishChannelId, i: PublishInput): Gate {
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
export function rehashRecordedArtifacts(kind: PublishChannelId, extensions: readonly string[], record: CheckRecord, repoDir: string): Rehash {
  const conventions: readonly string[] = extensions;
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
export async function blockingProbeFindings(i: PublishInput, kind: PublishChannelId): Promise<readonly Finding[]> {
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

export type PublishSpawnCommand = {
  readonly bin: string;
  readonly prefix: readonly string[];
  readonly args: readonly string[];
  /** Human label for the failure message (npm: the published file). */
  readonly what?: string;
};

/** One spawn command — the real publish argv for this channel's records. */
export function publishSpawnCommand(bin: string, argv: readonly string[], what?: string): PublishSpawnCommand {
  return { bin, prefix: [], args: argv, ...(what === undefined ? {} : { what }) };
}

/** Channel hooks the shared pipeline needs (C2): the JOB of this channel is to
 *  say what differs (argv source, binary seam, pre-publish gate, ledger record
 *  fields) — the ORDER is fixed here and cannot diverge between legs. */
export type PublishCoreHooks = {
  readonly kind: PublishChannelId;
  /** Dry-run print prefix, e.g. "npm" / "twine". */
  readonly label: string;
  /** Dist-convention extensions (artifactExtensions on the descriptor). */
  readonly artifactExtensions: readonly string[];
  /** ONE argv source: the DRY-RUN print and the real spawn both render what
   *  this returns (per-file argv rows). */
  readonly argvFor: (files: readonly string[], cfg: BorderConfig) => readonly string[][];
  /** Optional pre-spawn gate (pypi: twine availability) — runs BEFORE the
   *  pre-publish registry re-probe, exactly like the pre-C2 leg did. */
  readonly prePublishGate?: (i: PublishInput) => { readonly ok: true } | { readonly ok: false; readonly message: string; readonly exit: BorderExit };
  /** Spawn plan: one entry per process border starts (npm: one per file;
   *  pypi: a single twine upload for every file). */
  readonly spawnCommands: (i: PublishInput, files: readonly string[], argvRows: readonly string[][]) => readonly PublishSpawnCommand[];
  /** HEAD coordinate reader (descriptor.coords). */
  readonly coords: (i: PublishInput) => { readonly name: string; readonly version: string };
  /** Ledger record on success (channel's confirmedVia + remote name). */
  readonly recordPush: (i: PublishInput, record: CheckRecord, version: string) => void;
  readonly successLine: (version: string) => string;
  readonly failureMessage: (code: number, what: string | undefined) => string;
};

/** Shared same-bytes publish pipeline (C2): gate → re-hash → dry-run print /
 *  yes: pre-publish gate → blocking re-probe → immutability warning → spawn
 *  stdio:inherit → push-record. Returns the BorderExit code; the CLI maps
 *  every non-PASS path without ambiguity. */
export async function runPublishCore(ch: PublishCoreHooks, i: PublishInput): Promise<BorderExit> {
  const { out, err } = writers(i);
  const gate = requirePassedRecord(ch.kind, i);
  if (!gate.ok) {
    err(gate.message);
    return gate.exit;
  }
  const rehash = rehashRecordedArtifacts(ch.kind, ch.artifactExtensions, gate.record, i.repoDir);
  if (!rehash.ok) {
    err(rehash.message);
    return EXIT_ERROR;
  }
  const argvRows = ch.argvFor(rehash.files, i.cfg);
  if (!i.yes) {
    for (const argv of argvRows) out(`${ch.label} ${argv.join(" ")}`);
    return EXIT_PASS;
  }
  if (ch.prePublishGate !== undefined) {
    const gateStep = ch.prePublishGate(i);
    if (!gateStep.ok) {
      err(gateStep.message);
      return gateStep.exit;
    }
  }
  const blockers = await blockingProbeFindings(i, ch.kind);
  if (blockers.length > 0) {
    for (const f of blockers) err(`${f.rule}: ${f.message}`);
    return EXIT_BLOCKED;
  }
  out(PUBLISH_WARNING);
  for (const cmd of ch.spawnCommands(i, rehash.files, argvRows)) {
    const code = await spawnInherit(cmd.bin, [...cmd.prefix, ...cmd.args], i.repoDir, i.env);
    if (code !== 0) {
      err(ch.failureMessage(code, cmd.what));
      return EXIT_BLOCKED;
    }
  }
  const coords = ch.coords(i);
  ch.recordPush(i, gate.record, `${coords.name}@${coords.version}`);
  out(ch.successLine(`${coords.name}@${coords.version}`));
  return EXIT_PASS;
}